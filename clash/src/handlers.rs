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
    include_str!("../docs/session-context.md")
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
