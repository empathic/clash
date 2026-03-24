use crate::policy::Effect;
use crate::policy_decision::PolicyDecision;
use tracing::{Level, info, instrument, warn};

use clash_hooks::ToolEvent;

use crate::settings::ClashSettings;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level = Level::TRACE, ret, skip(input, settings), fields(tool = input.tool_name()))]
pub fn check_permission(
    input: &impl ToolEvent,
    settings: &ClashSettings,
) -> anyhow::Result<PolicyDecision> {
    let tool_name = input.tool_name();
    let tool_input = input.tool_input_raw();

    let tree = match settings.policy_tree() {
        Some(t) => t,
        None => {
            let (reason, context) = match settings.policy_error() {
                Some(err) => {
                    let reason = format!(
                        "Policy failed to compile: {}. All actions are blocked until the policy is fixed.",
                        err
                    );
                    let context = "POLICY ERROR: clash cannot enforce permissions because the policy failed to compile.\n\
                         The user's policy file has a syntax or compilation error.\n\n\
                         Agent instructions:\n\
                         - Tell the user their clash policy has an error and all actions are blocked\n\
                         - Suggest running: clash policy validate\n\
                         - Do NOT retry the tool call — it will be blocked until the policy is fixed\n\
                         - Do NOT attempt workarounds".to_string();
                    (reason, context)
                }
                None => {
                    let reason = "No policy configured. All actions are blocked. Run `clash init` to create a policy.".to_string();
                    let context = "POLICY ERROR: clash has no compiled policy available.\n\
                         All actions are blocked because there is no valid policy to evaluate.\n\n\
                         Agent instructions:\n\
                         - Tell the user clash has no policy configured\n\
                         - Suggest running: clash init\n\
                         - Do NOT retry the tool call"
                        .to_string();
                    (reason, context)
                }
            };

            // Print distinctive error to stderr
            eprintln!(
                "{} {}",
                crate::style::err_red_bold("clash policy error:"),
                &reason
            );
            eprintln!(
                "  {} {}",
                crate::style::err_dim("To diagnose:"),
                crate::style::err_yellow("clash policy validate")
            );

            warn!("{}", reason);
            return Ok(PolicyDecision::Deny {
                reason,
                context: Some(context),
            });
        }
    };

    let decision = tree.evaluate(tool_name, tool_input);
    let noun = extract_noun(tool_name, tool_input);

    info!(
        tool = %tool_name,
        noun = %noun,
        effect = %decision.effect,
        reason = ?decision.reason,
        trace = ?decision.trace,
        "Policy decision"
    );

    // Write audit log entry (global + session).
    crate::audit::log_decision(
        &settings.audit,
        input.session_id(),
        tool_name,
        tool_input,
        decision.effect,
        decision.reason.as_deref(),
        &decision.trace,
    );

    let explanation = decision.human_explanation();
    let additional_context = if explanation.is_empty() {
        None
    } else {
        Some(explanation.join("\n"))
    };

    // Print a concise denial message to stderr so the user sees it in the terminal.
    if decision.effect == Effect::Deny {
        let verb_str = tool_to_verb_str(tool_name);
        let noun_summary = truncate_noun(&noun, 60);

        eprintln!(
            "{} blocked {} on {}",
            crate::style::err_red_bold("clash:"),
            verb_str,
            noun_summary
        );

        let is_explicit_deny = decision
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("denied") || r.contains("deny"));

        if is_explicit_deny {
            eprintln!(
                "  {}",
                crate::style::err_dim("This action is explicitly denied by your policy.")
            );
        } else {
            eprintln!("  {}", crate::style::err_dim(denial_explanation(&verb_str)));
        }

        eprintln!(
            "  {} {}",
            crate::style::err_dim("To allow this:"),
            crate::style::err_yellow(&suggest_allow_command(&verb_str))
        );
        eprintln!(
            "  {}",
            crate::style::err_dim("(run \"clash allow --help\" for more options)")
        );
    }

    let verb_str = tool_to_verb_str(tool_name);

    Ok(match decision.effect {
        Effect::Allow => {
            // If the policy decision includes a per-command sandbox, rewrite the
            // command to run through `clash sandbox exec`.
            let updated_input = if let Some(ref sandbox_policy) = decision.sandbox {
                wrap_bash_with_sandbox(input, sandbox_policy).inspect(|_| {
                    info!("Rewrote Bash command to run under sandbox");
                })
            } else {
                None
            };
            PolicyDecision::Allow {
                reason: decision.reason.or(Some("policy: allowed".into())),
                context: additional_context,
                updated_input,
            }
        }
        Effect::Deny => {
            let denial_count = count_session_denials(input.session_id());
            let deny_context = build_deny_context(
                tool_name,
                &verb_str,
                &noun,
                decision.reason.as_deref(),
                denial_count,
            );
            PolicyDecision::Deny {
                reason: decision.reason.unwrap_or_else(|| "policy: denied".into()),
                context: Some(deny_context),
            }
        }
        Effect::Ask => PolicyDecision::Ask {
            reason: decision.reason.or(Some("policy: ask".into())),
            context: additional_context,
        },
    })
}

/// Map a tool name to a short verb string for user-facing messages.
///
/// Verbs align with the bare verb shortcuts in `clash allow <verb>`:
/// bash, edit, read, web.
fn tool_to_verb_str(tool_name: &str) -> String {
    match tool_name {
        "Bash" => "bash".into(),
        "Read" | "Glob" | "Grep" => "read".into(),
        "Write" | "Edit" => "edit".into(),
        "WebFetch" | "WebSearch" => "web".into(),
        "Skill" | "Task" | "TaskCreate" | "TaskUpdate" | "TaskList" | "TaskGet" | "TaskStop"
        | "TaskOutput" | "AskUserQuestion" | "EnterPlanMode" | "ExitPlanMode" | "NotebookEdit" => {
            "tool".into()
        }
        _ => tool_name.to_lowercase(),
    }
}

/// If the tool input is a Bash command and a sandbox policy exists,
/// rewrite the command to run through `clash sandbox exec`.
///
/// Returns the updated `tool_input` JSON if rewriting is applicable, or None.
#[instrument(level = Level::TRACE, skip(input, sandbox_policy))]
fn wrap_bash_with_sandbox(
    input: &impl ToolEvent,
    sandbox_policy: &crate::policy::sandbox_types::SandboxPolicy,
) -> Option<serde_json::Value> {
    let bash_input = input.bash()?;

    let clash_bin = std::env::current_exe().ok()?;
    let policy_json = serde_json::to_string(sandbox_policy).ok()?;

    // Pass session and tool_use_id so `clash sandbox exec` can log violations
    // to the audit trail after the sandboxed process exits.
    let mut extra_args = String::new();
    let session_id = input.session_id();
    if !session_id.is_empty() {
        extra_args += &format!(" --session-id {}", shell_escape(session_id));
        if let Some(tuid) = input.tool_use_id() {
            extra_args += &format!(" --tool-use-id {}", shell_escape(tuid));
        }
    }

    let sandboxed_command = format!(
        "{} sandbox exec --policy {} --cwd {}{} -- bash -c {}",
        shell_escape(&clash_bin.to_string_lossy()),
        shell_escape(&policy_json),
        shell_escape(input.cwd()),
        extra_args,
        shell_escape(&bash_input.command),
    );

    let mut updated = input.tool_input_raw().clone();
    if let Some(obj) = updated.as_object_mut() {
        obj.insert(
            "command".into(),
            serde_json::Value::String(sandboxed_command),
        );
    }

    Some(updated)
}

/// Simple shell escaping: wrap in single quotes, escaping embedded single quotes.
#[instrument(level = Level::TRACE)]
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Count the number of deny decisions in the current session's audit log.
fn count_session_denials(session_id: &str) -> usize {
    let log_path = crate::audit::session_dir(session_id).join("audit.jsonl");
    let content = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    content
        .lines()
        .filter(|line| line.contains("\"decision\":\"deny\""))
        .count()
}

/// Suggest a `clash allow` command for a denied verb.
fn suggest_allow_command(verb_str: &str) -> String {
    match verb_str {
        "edit" | "bash" | "read" | "web" | "tool" => format!("clash allow {verb_str}"),
        _ => format!("clash allow '{verb_str}'"),
    }
}

/// Return a plain-English explanation for why a verb was denied.
fn denial_explanation(verb_str: &str) -> &'static str {
    match verb_str {
        "edit" => "File editing is not allowed by your current policy.",
        "bash" => "Command execution is not allowed by your current policy.",
        "web" => "Web access is not allowed by your current policy.",
        "read" => "File reading outside the project is not allowed by your current policy.",
        _ => "This action is not allowed by your current policy.",
    }
}

/// Truncate a noun string to approximately `max_len` characters, appending "..." if truncated.
fn truncate_noun(noun: &str, max_len: usize) -> String {
    if noun.len() <= max_len {
        noun.to_string()
    } else {
        format!("{}...", &noun[..max_len])
    }
}

/// Build structured agent context for a Deny decision.
fn build_deny_context(
    tool_name: &str,
    verb_str: &str,
    noun: &str,
    reason: Option<&str>,
    denial_count: usize,
) -> String {
    let truncated_noun = truncate_noun(noun, 80);

    let is_explicit_deny = reason.is_some_and(|r| r.contains("denied") || r.contains("deny"));
    let reason_code = if is_explicit_deny {
        "explicit-deny"
    } else {
        "default-deny"
    };

    let suggested = suggest_allow_command(verb_str);

    let mut lines = vec![format!(
        "BLOCKED: {reason_code} tool={tool_name} input={truncated_noun}"
    )];

    if is_explicit_deny {
        lines.push("This action is explicitly blocked by the user's clash policy.".into());
    } else {
        lines.push(format!(
            "{} Suggested action: {}",
            denial_explanation(verb_str),
            suggested,
        ));
    }

    lines.push(String::new());
    lines.push("Agent instructions:".into());
    lines.push(format!(
        "- Tell the user this was blocked by clash and suggest: {suggested}"
    ));
    lines.push("- Do NOT retry the same tool call".into());
    lines.push("- Do NOT attempt workarounds (e.g., curl instead of WebFetch)".into());
    if denial_count <= 2 && !is_explicit_deny {
        lines.push("- The user may be new to clash — be brief and reassuring".into());
    }

    lines.join("\n")
}

/// Extract the noun (resource identifier) from tool input JSON.
pub fn extract_noun(tool_name: &str, tool_input: &serde_json::Value) -> String {
    let fields = [
        "command",   // Bash
        "file_path", // Read, Write, Edit, NotebookEdit
        "pattern",   // Glob, Grep
        "query",     // WebSearch
        "url",       // WebFetch
        "path",      // Glob, Grep (secondary field)
        "prompt",    // Task
        "skill",     // Skill
    ];
    for field in &fields {
        if let Some(val) = tool_input.get(*field).and_then(|v| v.as_str()) {
            return val.to_string();
        }
    }
    tool_name.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use clash_hooks::HookEvent;
    use serde_json::json;

    fn make_pre_tool_use(tool_name: &str, tool_input: serde_json::Value) -> clash_hooks::event::PreToolUse {
        let json = serde_json::json!({
            "session_id": "",
            "transcript_path": "",
            "cwd": "",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
        });
        let event = clash_hooks::recv_from(serde_json::to_vec(&json).unwrap().as_slice()).unwrap();
        match event {
            HookEvent::PreToolUse(e) => e,
            _ => panic!("expected PreToolUse"),
        }
    }

    fn bash_input(command: &str) -> clash_hooks::event::PreToolUse {
        make_pre_tool_use("Bash", json!({"command": command}))
    }

    fn settings_with_policy(source: &str) -> ClashSettings {
        let mut settings = ClashSettings::default();
        settings.set_policy_source(source);
        settings
    }

    // --- policy engine tests ---

    /// V5 policy: allow Bash when positional_arg(0) matches `bin`.
    fn v5_allow_exec(bin: &str) -> String {
        format!(
            r#"{{"schema_version":5,"default_effect":"deny","sandboxes":{{}},"tree":[
            {{"condition":{{"observe":"tool_name","pattern":{{"literal":{{"literal":"Bash"}}}},"children":[
                {{"condition":{{"observe":{{"positional_arg":0}},"pattern":{{"literal":{{"literal":"{bin}"}}}},"children":[
                    {{"decision":{{"allow":null}}}}
                ]}}}}
            ]}}}}
        ]}}"#
        )
    }

    #[test]
    fn test_policy_allow_git_status() -> Result<()> {
        let settings = settings_with_policy(&v5_allow_exec("git"));
        let result = check_permission(&bash_input("git status"), &settings)?;
        assert!(matches!(result, PolicyDecision::Allow { ref reason, .. } if reason.as_deref() == Some("result: allow")));
        Ok(())
    }

    #[test]
    fn test_policy_deny_git_push() -> Result<()> {
        // deny git push, allow git *
        let source = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
                {"condition":{"observe":{"positional_arg":0},"pattern":{"literal":{"literal":"git"}},"children":[
                    {"condition":{"observe":{"positional_arg":1},"pattern":{"literal":{"literal":"push"}},"children":[
                        {"decision":"deny"}
                    ]}},
                    {"decision":{"allow":null}}
                ]}}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let result = check_permission(&bash_input("git push origin main"), &settings)?;
        assert!(result.is_deny());
        Ok(())
    }

    #[test]
    fn test_policy_default_deny() -> Result<()> {
        let settings = settings_with_policy(&v5_allow_exec("git"));
        // ls doesn't match any rule
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert!(result.is_deny());
        Ok(())
    }

    #[test]
    fn test_policy_read_under_cwd() -> Result<()> {
        let source = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"fs_op","pattern":{"literal":{"literal":"read"}},"children":[
                {"condition":{"observe":"fs_path","pattern":{"prefix":{"literal":"/home/user/project"}},"children":[
                    {"decision":{"allow":null}}
                ]}}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let input = make_pre_tool_use("Read", json!({"file_path": "/home/user/project/src/main.rs"}));
        let result = check_permission(&input, &settings)?;
        assert!(matches!(result, PolicyDecision::Allow { ref reason, .. } if reason.as_deref() == Some("result: allow")));
        Ok(())
    }

    #[test]
    fn test_policy_read_outside_cwd_denied() -> Result<()> {
        let source = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"fs_op","pattern":{"literal":{"literal":"read"}},"children":[
                {"condition":{"observe":"fs_path","pattern":{"prefix":{"literal":"/home/user/project"}},"children":[
                    {"decision":{"allow":null}}
                ]}}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let input = make_pre_tool_use("Read", json!({"file_path": "/etc/passwd"}));
        let result = check_permission(&input, &settings)?;
        assert!(result.is_deny());
        Ok(())
    }

    #[test]
    fn test_no_compiled_policy_denies() -> Result<()> {
        let settings = ClashSettings::default();
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert!(result.is_deny());
        Ok(())
    }

    // --- Explanation tests ---

    #[test]
    fn test_explanation_contains_matched_rule() -> Result<()> {
        let settings = settings_with_policy(&v5_allow_exec("git"));
        let result = check_permission(&bash_input("git status"), &settings)?;
        let ctx = match &result {
            PolicyDecision::Allow { context, .. } => context.as_deref(),
            _ => panic!("expected Allow"),
        };
        let ctx = ctx.expect("should have context");
        assert!(
            ctx.contains("matched"),
            "explanation should contain 'matched' but got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_explanation_no_rules_matched() -> Result<()> {
        // default=ask so that unmatched tools get ask, not deny
        let source = r#"{"schema_version":5,"default_effect":"ask","sandboxes":{},"tree":[
            {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
                {"condition":{"observe":{"positional_arg":0},"pattern":{"literal":{"literal":"git"}},"children":[
                    {"decision":{"allow":null}}
                ]}}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let result = check_permission(&bash_input("ls"), &settings)?;
        let ctx = match &result {
            PolicyDecision::Ask { context, .. } => context.as_deref(),
            _ => panic!("expected Ask, got {:?}", result),
        };
        let ctx = ctx.expect("should have context");
        assert!(
            ctx.contains("No rules matched"),
            "explanation should say 'No rules matched' but got: {ctx}"
        );
        Ok(())
    }

    // --- interactive tool (AskUserQuestion) policy tests ---

    #[test]
    fn test_ask_user_question_allowed_by_blanket_tool_rule() -> Result<()> {
        // Blanket allow all tools: wildcard on tool_name
        let source = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"tool_name","pattern":"wildcard","children":[
                {"decision":{"allow":null}}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let input = make_pre_tool_use(
            "AskUserQuestion",
            json!({"questions": [{"question": "Which approach?", "options": []}]}),
        );
        let result = check_permission(&input, &settings)?;
        assert!(matches!(result, PolicyDecision::Allow { ref reason, .. } if reason.as_deref() == Some("result: allow")));
        Ok(())
    }

    #[test]
    fn test_ask_user_question_denied_by_explicit_deny() -> Result<()> {
        // Deny AskUserQuestion, allow everything else
        let source = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"AskUserQuestion"}},"children":[
                {"decision":"deny"}
            ]}},
            {"condition":{"observe":"tool_name","pattern":"wildcard","children":[
                {"decision":{"allow":null}}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let input = make_pre_tool_use("AskUserQuestion", json!({"questions": []}));
        let result = check_permission(&input, &settings)?;
        assert!(result.is_deny());
        Ok(())
    }

    // --- shell_escape tests ---

    #[test]
    fn test_shell_escape_simple_string() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn test_shell_escape_string_with_spaces() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_escape_empty_string() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_embedded_single_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_multiple_single_quotes() {
        assert_eq!(shell_escape("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn test_shell_escape_special_characters() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("`whoami`"), "'`whoami`'");
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("say \"hi\""), "'say \"hi\"'");
    }

    // --- wrap_bash_with_sandbox tests ---

    fn test_sandbox_policy() -> crate::policy::sandbox_types::SandboxPolicy {
        use crate::policy::sandbox_types::{Cap, NetworkPolicy};
        crate::policy::sandbox_types::SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        }
    }

    fn bash_input_for_sandbox(command: &str, cwd: &str) -> clash_hooks::event::PreToolUse {
        let json = serde_json::json!({
            "session_id": "",
            "transcript_path": "",
            "cwd": cwd,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        });
        match clash_hooks::recv_from(serde_json::to_vec(&json).unwrap().as_slice()).unwrap() {
            HookEvent::PreToolUse(e) => e,
            _ => panic!("expected PreToolUse"),
        }
    }

    fn extract_wrapped_command(result: &serde_json::Value) -> &str {
        result
            .get("command")
            .and_then(|v| v.as_str())
            .expect("wrapped result should have a 'command' string field")
    }

    #[test]
    fn test_wrap_bash_basic_command() {
        let input = bash_input_for_sandbox("ls -la", "/home/user/project");
        let policy = test_sandbox_policy();
        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(result.is_some());
        let wrapped = result.unwrap();
        let cmd = extract_wrapped_command(&wrapped);
        assert!(cmd.contains("sandbox exec"));
        assert!(cmd.contains("--policy"));
        assert!(cmd.contains("--cwd"));
        assert!(cmd.contains("-- bash -c 'ls -la'"));
    }

    #[test]
    fn test_wrap_bash_returns_none_for_read_tool() {
        let input = make_pre_tool_use("Read", json!({"file_path": "/tmp/test.txt"}));
        let policy = test_sandbox_policy();
        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(result.is_none());
    }

    // --- suggest/deny tests ---

    #[test]
    fn test_suggest_allow_command_edit() {
        assert_eq!(suggest_allow_command("edit"), "clash allow edit");
    }

    #[test]
    fn test_suggest_allow_command_bash() {
        assert_eq!(suggest_allow_command("bash"), "clash allow bash");
    }

    #[test]
    fn test_suggest_allow_command_web() {
        assert_eq!(suggest_allow_command("web"), "clash allow web");
    }

    #[test]
    fn test_truncate_noun_short() {
        assert_eq!(truncate_noun("hello", 60), "hello");
    }

    #[test]
    fn test_truncate_noun_long() {
        let s = "a".repeat(100);
        let result = truncate_noun(&s, 60);
        assert_eq!(result.len(), 63);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_build_deny_context_contains_tool_name() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(ctx.contains("Bash"));
        assert!(ctx.contains("BLOCKED:"));
        assert!(ctx.contains("Agent instructions"));
    }

    #[test]
    fn test_deny_decision_includes_agent_context() -> Result<()> {
        // Deny all Bash commands
        let source = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
                {"decision":"deny"}
            ]}}
        ]}"#;
        let settings = settings_with_policy(source);
        let result = check_permission(&bash_input("ls -la"), &settings)?;
        assert!(result.is_deny());
        let ctx = match &result {
            PolicyDecision::Deny { context, .. } => context.as_deref(),
            _ => panic!("expected Deny"),
        };
        let ctx = ctx.expect("deny should have context");
        assert!(ctx.contains("BLOCKED:"), "got: {ctx}");
        Ok(())
    }
}
