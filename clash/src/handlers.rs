//! Pre-built hook handlers for Claude Code integration.
//!
//! These handlers wire together permission evaluation, notifications, and
//! session validation into ready-to-use functions that process Claude Code
//! hook events.

use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, HookSpecificOutput, SessionStartHookInput, ToolUseHookInput};
use crate::notifications;
use crate::permissions::check_permission;
use crate::settings::ClashSettings;

use claude_settings::PermissionRule;

/// Handle a permission request — decide whether to approve or deny on behalf of user.
///
/// When the policy evaluates to "ask" and a Zulip bot is configured, the request
/// is forwarded to Zulip and we poll for a human response. If no Zulip config is
/// present or the poll times out, we fall through to let the terminal user decide.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn handle_permission_request(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    let pre_tool_result = check_permission(input, settings)?;

    // Convert PreToolUse decision to PermissionRequest format.
    // Claude Code validates that hookEventName matches the event type.
    Ok(match pre_tool_result.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(ref pre)) => match pre.permission_decision {
            Some(PermissionRule::Allow) => HookOutput::approve_permission(None),
            Some(PermissionRule::Deny) => {
                let reason = pre
                    .permission_decision_reason
                    .clone()
                    .unwrap_or_else(|| "denied by policy".into());
                HookOutput::deny_permission(reason, false)
            }
            // Ask or no decision: try interactive desktop prompt first,
            // then fall through to Zulip / terminal.
            _ => resolve_via_desktop_or_zulip(input, settings),
        },
        _ => pre_tool_result,
    })
}

/// Build a human-readable summary of the permission request for notifications.
fn permission_summary(input: &ToolUseHookInput) -> String {
    match input.tool_name.as_str() {
        "Bash" => {
            let cmd = input.tool_input["command"].as_str().unwrap_or("(unknown)");
            format!("Bash: {}", cmd)
        }
        _ => input.tool_name.to_string(),
    }
}

/// Try to resolve a permission ask via desktop notification and/or Zulip.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn resolve_via_desktop_or_zulip(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> HookOutput {
    let has_desktop = settings.notifications.desktop;
    let has_zulip = settings.notifications.zulip.is_some();

    if has_zulip && has_desktop {
        start_zulip_background(input, settings);
        return resolve_via_desktop_then_continue(input, settings);
    }

    if has_desktop {
        return resolve_via_desktop_then_continue(input, settings);
    }

    if has_zulip {
        return resolve_via_zulip_or_continue(input, settings);
    }

    HookOutput::continue_execution()
}

fn resolve_via_desktop_then_continue(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> HookOutput {
    let summary = permission_summary(input);
    let timeout = std::time::Duration::from_secs(settings.notifications.desktop_timeout_secs);
    let response = clash_notify::prompt("Clash: Permission Request", &summary, timeout);

    match response {
        clash_notify::PromptResponse::Approved => {
            info!("Permission approved via desktop notification");
            HookOutput::approve_permission(None)
        }
        clash_notify::PromptResponse::Denied => {
            info!("Permission denied via desktop notification");
            HookOutput::deny_permission("denied via desktop notification".into(), false)
        }
        clash_notify::PromptResponse::TimedOut => {
            info!("Desktop notification timed out, falling through to terminal");
            HookOutput::continue_execution()
        }
        clash_notify::PromptResponse::Unavailable => {
            info!("Interactive desktop notifications unavailable, falling through to terminal");
            HookOutput::continue_execution()
        }
    }
}

fn start_zulip_background(input: &ToolUseHookInput, settings: &ClashSettings) {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return;
    };

    let request = notifications::PermissionRequest {
        tool_name: input.tool_name.clone(),
        tool_input: input.tool_input.clone(),
        session_id: input.session_id.clone(),
        cwd: input.cwd.clone(),
    };

    let config = zulip_config.clone();

    std::thread::spawn(move || {
        let client = notifications::ZulipClient::new(&config);
        match client.resolve_permission(&request) {
            Ok(Some(notifications::PermissionResponse::Approve)) => {
                info!("Permission approved via Zulip (background), exiting hook");
                let output = HookOutput::approve_permission(None);
                if output.write_stdout().is_ok() {
                    std::process::exit(0);
                }
            }
            Ok(Some(notifications::PermissionResponse::Deny(reason))) => {
                info!("Permission denied via Zulip (background), exiting hook");
                let output = HookOutput::deny_permission(reason, false);
                if output.write_stdout().is_ok() {
                    std::process::exit(0);
                }
            }
            Ok(None) => {
                info!("Zulip resolution timed out (background)");
            }
            Err(e) => {
                warn!(error = %e, "Zulip resolution failed (background)");
            }
        }
    });
}

#[instrument(level = Level::TRACE, skip(input, settings))]
fn resolve_via_zulip_or_continue(input: &ToolUseHookInput, settings: &ClashSettings) -> HookOutput {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return HookOutput::continue_execution();
    };

    let request = notifications::PermissionRequest {
        tool_name: input.tool_name.clone(),
        tool_input: input.tool_input.clone(),
        session_id: input.session_id.clone(),
        cwd: input.cwd.clone(),
    };

    let client = notifications::ZulipClient::new(zulip_config);
    match client.resolve_permission(&request) {
        Ok(Some(notifications::PermissionResponse::Approve)) => {
            HookOutput::approve_permission(None)
        }
        Ok(Some(notifications::PermissionResponse::Deny(reason))) => {
            HookOutput::deny_permission(reason, false)
        }
        Ok(None) => {
            info!("Zulip resolution timed out, falling through to terminal");
            HookOutput::continue_execution()
        }
        Err(e) => {
            warn!(error = %e, "Zulip resolution failed, falling through to terminal");
            HookOutput::continue_execution()
        }
    }
}

/// Handle a session start event — validate policy/settings and report status to Claude.
#[instrument(level = Level::TRACE, skip(input))]
pub fn handle_session_start(input: &SessionStartHookInput) -> anyhow::Result<HookOutput> {
    // Ensure the user has a policy file — create one with safe defaults if not.
    let created_policy = ClashSettings::ensure_user_policy_exists()?;

    let _settings = ClashSettings::load_or_create_with_session(Some(&input.session_id))?;

    let mut lines = Vec::new();

    if let Some(path) = created_policy {
        lines.push(format!(
            "Welcome to Clash! A default policy has been created at {}. \
             It starts with deny-all and allows reading files in your project. \
             Use /clash:status to see what's allowed, or /clash:edit to customize.",
            path.display()
        ));
    }

    // Inject clash usage context so Claude understands how to use skills and policies.
    lines.push(clash_session_context().into());

    // Check if user is running without skip-permissions (default mode).
    let is_skip_permissions = input
        .permission_mode
        .as_deref()
        .is_some_and(|m| m == "dangerously-skip-permissions");

    if is_skip_permissions {
        lines.push(
            "NOTE: policy enforcement is DISABLED (--dangerously-skip-permissions). \
             Filesystem sandboxing is still active for exec rules."
                .into(),
        );
    } else {
        lines.push(
            "NOTE: Clash is managing permissions. For full enforcement, run with \
             --dangerously-skip-permissions so Clash is the sole decision-maker."
                .into(),
        );
    }

    check_sandbox_and_session(&mut lines, input);

    finish_session_start(lines)
}

/// Generate comprehensive context about clash for injection into Claude's session.
///
/// This text is returned as `additional_context` in the SessionStart hook response,
/// giving Claude the knowledge it needs to use clash skills and manage policies.
fn clash_session_context() -> &'static str {
    r#"## Clash — Command Line Agent Safety Harness

Clash enforces permission policies on Claude Code tool usage. It intercepts every tool call
and evaluates it against a policy before allowing, denying, or prompting the user.

### Available Skills

Use these slash commands to manage clash policies during a session:

- `/clash:status` — Show current permission enforcement status and what Claude can/cannot do
- `/clash:describe` — Full human-readable breakdown of the active policy with analysis
- `/clash:edit` — Guided editing of the policy (add/remove/change rules)
- `/clash:allow` — Add an allow rule (e.g., after a denial)
- `/clash:deny` — Add a deny rule to block a specific action
- `/clash:explain` — Explain which policy rule matches a specific tool invocation
- `/clash:test` — Test hypothetical tool uses against the policy
- `/clash:onboard` — Create a policy from scratch (directs to `clash edit` wizard)
- `/clash:audit` — View recent permission decisions from the audit log
- `/clash:bug-report` — File a bug report to the clash issue tracker
- `/clash:dogfood` — Initialize clash with safe defaults

### Policy Basics

Policies use s-expression syntax with three effects and four capability domains:

**Effects:** `allow` (permit silently), `deny` (block), `ask` (prompt user)
**Domains:** `exec` (commands), `fs` (filesystem), `net` (network), `tool` (agent tools)
**Precedence:** deny always wins over allow; more specific rules beat less specific ones

### Policy File Structure

```
(default deny "main")           ; default effect + entry policy name

(policy "helpers"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "helpers")            ; inline another policy's rules
  (allow (exec "git" *))         ; allow all git commands
  (deny  (exec "git" "push" *)) ; but block git push
  (allow (net "github.com")))    ; allow github.com network access
```

**Policy layers** (higher shadows lower): Session > Project > User
- User: `~/.clash/policy.sexpr`
- Project: `<project>/.clash/policy.sexpr`
- Session: created via `clash edit --session`

### Rule Syntax Quick Reference

**Exec (commands):**
```
(allow (exec "git" *))                    ; all git commands
(deny  (exec "git" "push" *))            ; git push with any args
(allow (exec "cargo" "test" *))           ; cargo test
(deny  (exec "git" :has "--force"))       ; git commands containing --force
```

**Fs (filesystem):**
```
(allow (fs read (subpath (env PWD))))     ; read files under working directory
(allow (fs (or read write) (subpath (env PWD))))  ; read+write under cwd
(deny  (fs write ".env"))                 ; block writing .env
```

**Net (network):**
```
(allow (net "github.com"))                ; allow github.com
(allow (net (or "github.com" "crates.io")))  ; allow multiple domains
```

**Patterns:** `*` (wildcard), `"literal"` (exact), `/regex/` (regex), `(or ...)` (any of), `(not ...)` (negate)

### CLI Commands for Policy Management

Always run clash as an installed binary (`clash`), never via `cargo run`.

**Viewing:**
- `clash status` — overview of layers, rules, and issues
- `clash policy list` — list all rules with level tags
- `clash policy explain bash "git push"` — check which rule matches

**Modifying (always dry-run first):**
- `clash policy allow '(exec "git" *)'` — add an allow rule
- `clash policy deny '(exec "rm" "-rf" *)'` — add a deny rule
- `clash policy remove '(allow (exec "git" *))'` — remove a rule
- Add `--dry-run` to any modification command to preview without applying

**Bare verb shortcuts:**
- `clash policy allow edit` — allow editing files in the project
- `clash policy allow bash` — allow running commands in the project
- `clash policy allow web` — allow web search and fetch
- `clash policy allow read` — allow reading files in the project

### Tool-to-Capability Mapping

| Tool | Capability |
|------|-----------|
| Bash | exec (bin = first word, args = rest) |
| Read, Glob, Grep | fs read |
| Write, Edit | fs write |
| WebFetch | net (domain from URL) |
| WebSearch | net (wildcard domain) |
| Skill, Task, etc. | tool |

### Session-Scoped Rules

When a user approves a permission prompt, Clash will suggest a session rule via PostToolUse context.
You should offer this to the user — but ALWAYS confirm before adding:

1. After a permission is approved, you may receive advisory context suggesting a `clash policy allow --scope session` command
2. Ask the user: "Would you like me to allow this for the rest of the session?"
3. If yes, dry-run first, then apply:
   ```
   clash policy allow '(exec "git" *)' --scope session --dry-run
   clash policy allow '(exec "git" *)' --scope session
   ```
4. Session rules are temporary — they only last for the current session

**Crafting precise rules:**
- Use the suggested rule from the advisory context as a starting point
- Prefer specific rules: `(exec "git" *)` over `(exec *)`
- For filesystem access, scope to the relevant directory
- For network access, scope to the specific domain

### Important Behaviors

- Deny rules ALWAYS take precedence over allow rules, regardless of specificity
- When the user asks to allow something currently denied, they must remove the deny rule first
- Always use `--dry-run` before applying policy changes
- Summarize command output in plain English — never paste raw terminal output to the user"#
}

/// Check sandbox support, init session, and symlink — shared by both paths.
fn check_sandbox_and_session(lines: &mut Vec<String>, input: &SessionStartHookInput) {
    // 3. Check sandbox support
    let support = crate::sandbox::check_support();
    match support {
        crate::sandbox::SupportLevel::Full => {
            lines.push("sandbox: fully supported".into());
        }
        crate::sandbox::SupportLevel::Partial { ref missing } => {
            lines.push(format!(
                "sandbox: partial (missing: {})",
                missing.join(", ")
            ));
        }
        crate::sandbox::SupportLevel::Unsupported { ref reason } => {
            lines.push(format!("sandbox: unsupported ({})", reason));
        }
    }

    // 4. Initialize per-session history directory
    match crate::audit::init_session(
        &input.session_id,
        &input.cwd,
        input.source.as_deref(),
        input.model.as_deref(),
    ) {
        Ok(session_dir) => {
            lines.push(format!("session history: {}", session_dir.display()));
        }
        Err(e) => {
            warn!(error = %e, "Failed to create session history directory");
        }
    }

    // 4b. Write active session marker so CLI commands can find this session.
    if let Err(e) = ClashSettings::set_active_session(&input.session_id) {
        warn!(error = %e, "Failed to write active session marker");
    }

    // 5. Session metadata
    if let Some(ref source) = input.source {
        lines.push(format!("session source: {}", source));
    }
    if let Some(ref model) = input.model {
        lines.push(format!("model: {}", model));
    }
}

fn finish_session_start(lines: Vec<String>) -> anyhow::Result<HookOutput> {
    info!(context = %lines.join("; "), "SessionStart validation");

    let context = if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    };

    Ok(HookOutput::session_start(context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_session_start_input() -> SessionStartHookInput {
        SessionStartHookInput {
            session_id: "test-session".into(),
            transcript_path: "/tmp/transcript.jsonl".into(),
            cwd: "/tmp".into(),
            permission_mode: Some("default".into()),
            hook_event_name: "SessionStart".into(),
            source: Some("startup".into()),
            model: Some("claude-sonnet-4-20250514".into()),
        }
    }

    #[test]
    fn test_session_start_reports_sandbox_support() {
        let input = default_session_start_input();
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(
            ctx.contains("sandbox:"),
            "should report sandbox status, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_session_metadata() {
        let input = default_session_start_input();
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(ctx.contains("session source: startup"), "got: {ctx}");
        assert!(
            ctx.contains("model: claude-sonnet-4-20250514"),
            "got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_recommends_skip_permissions_in_default_mode() {
        let input = default_session_start_input();
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(
            ctx.contains("--dangerously-skip-permissions"),
            "should recommend --dangerously-skip-permissions when not in skip mode, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_no_recommendation_when_skip_permissions() {
        let mut input = default_session_start_input();
        input.permission_mode = Some("dangerously-skip-permissions".into());
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(
            !ctx.contains("NOTE: Clash is managing permissions"),
            "should NOT recommend when already in skip mode, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_injects_instructions_when_skip_permissions() {
        let mut input = default_session_start_input();
        input.permission_mode = Some("dangerously-skip-permissions".into());
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(ctx.contains("policy enforcement is DISABLED"), "got: {ctx}");
        assert!(ctx.contains("Filesystem sandboxing"), "got: {ctx}");
    }
}
