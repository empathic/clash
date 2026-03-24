//! Pre-built hook handlers for Claude Code integration.
//!
//! These handlers wire together permission evaluation, notifications, and
//! session validation into ready-to-use functions that process Claude Code
//! hook events.

use clash_hooks::event::{PermissionRequest, SessionStart};
use clash_hooks::{HookEventCommon, Response, ToolEvent};
use tracing::{Level, info, instrument, warn};

use crate::notifications;
use crate::permissions::check_permission;
use crate::policy_decision::PolicyDecision;
use crate::settings::ClashSettings;

/// Handle a permission request — decide whether to approve or deny on behalf of user.
///
/// When the policy evaluates to "ask" and a Zulip bot is configured, the request
/// is forwarded to Zulip and we poll for a human response. If no Zulip config is
/// present or the poll times out, we fall through to let the terminal user decide.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn handle_permission_request(
    input: &PermissionRequest,
    settings: &ClashSettings,
) -> anyhow::Result<Response> {
    // Interactive tools (AskUserQuestion, EnterPlanMode, ExitPlanMode) must be
    // handled by Claude Code's native UI. If the policy doesn't deny them,
    // pass through so the user sees the native prompt / plan review screen.
    if input.is_interactive_tool() {
        let decision = check_permission(input, settings)?;
        if decision.is_deny() {
            let reason = match &decision {
                PolicyDecision::Deny { reason, .. } => reason.clone(),
                _ => "denied by policy".into(),
            };
            return Ok(input.deny(reason));
        }
        info!(tool = %input.tool_name(), "Passthrough: interactive tool deferred to Claude Code");
        return Ok(input.pass());
    }

    let decision = check_permission(input, settings)?;

    // Convert policy decision to PermissionRequest format.
    Ok(match decision {
        PolicyDecision::Allow { .. } => input.approve(),
        PolicyDecision::Deny { reason, .. } => input.deny(reason),
        // Ask or no decision: try interactive desktop prompt first,
        // then fall through to Zulip / terminal.
        PolicyDecision::Ask { .. } | PolicyDecision::Pass => {
            resolve_via_desktop_or_zulip(input, settings)
        }
    })
}

/// Build a human-readable summary of the permission request for notifications.
fn permission_summary(input: &PermissionRequest) -> String {
    match input.tool_name() {
        "Bash" => {
            let cmd = input.tool_input_raw()["command"]
                .as_str()
                .unwrap_or("(unknown)");
            format!("Bash: {}", cmd)
        }
        _ => input.tool_name().to_string(),
    }
}

/// Try to resolve a permission ask via desktop notification and/or Zulip.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn resolve_via_desktop_or_zulip(
    input: &PermissionRequest,
    settings: &ClashSettings,
) -> Response {
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

    input.pass()
}

fn resolve_via_desktop_then_continue(
    input: &PermissionRequest,
    settings: &ClashSettings,
) -> Response {
    let summary = permission_summary(input);
    let timeout = std::time::Duration::from_secs(settings.notifications.desktop_timeout_secs);
    let response = clash_notify::prompt("Clash: Permission Request", &summary, timeout);

    match response {
        clash_notify::PromptResponse::Approved => {
            info!("Permission approved via desktop notification");
            input.approve()
        }
        clash_notify::PromptResponse::Denied => {
            info!("Permission denied via desktop notification");
            input.deny("denied via desktop notification")
        }
        clash_notify::PromptResponse::TimedOut => {
            info!("Desktop notification timed out, falling through to terminal");
            input.pass()
        }
        clash_notify::PromptResponse::Unavailable => {
            info!("Interactive desktop notifications unavailable, falling through to terminal");
            input.pass()
        }
    }
}

fn start_zulip_background(input: &PermissionRequest, settings: &ClashSettings) {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return;
    };

    let request = notifications::PermissionRequest {
        tool_name: input.tool_name().to_string(),
        tool_input: input.tool_input_raw().clone(),
        session_id: input.session_id().to_string(),
        cwd: input.cwd().to_string(),
    };

    let config = zulip_config.clone();

    std::thread::spawn(move || {
        let client = notifications::ZulipClient::new(&config);
        match client.resolve_permission(&request) {
            Ok(Some(notifications::PermissionResponse::Approve)) => {
                info!("Permission approved via Zulip (background), exiting hook");
                let resp = clash_hooks::pass();
                let _ = clash_hooks::send(&resp);
                std::process::exit(0);
            }
            Ok(Some(notifications::PermissionResponse::Deny(reason))) => {
                info!("Permission denied via Zulip (background), exiting hook");
                // We can't call input.deny() from this thread since input is not Send,
                // but we need to exit the process, so use a raw pass + exit approach.
                // The Zulip deny is best-effort in the background thread.
                eprintln!("clash: Zulip denied permission: {reason}");
                std::process::exit(clash_hooks::exit_code::BLOCKING_ERROR);
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
fn resolve_via_zulip_or_continue(
    input: &PermissionRequest,
    settings: &ClashSettings,
) -> Response {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return input.pass();
    };

    let request = notifications::PermissionRequest {
        tool_name: input.tool_name().to_string(),
        tool_input: input.tool_input_raw().clone(),
        session_id: input.session_id().to_string(),
        cwd: input.cwd().to_string(),
    };

    let client = notifications::ZulipClient::new(zulip_config);
    match client.resolve_permission(&request) {
        Ok(Some(notifications::PermissionResponse::Approve)) => input.approve(),
        Ok(Some(notifications::PermissionResponse::Deny(reason))) => input.deny(reason),
        Ok(None) => {
            info!("Zulip resolution timed out, falling through to terminal");
            input.pass()
        }
        Err(e) => {
            warn!(error = %e, "Zulip resolution failed, falling through to terminal");
            input.pass()
        }
    }
}

/// Handle a session start event — validate policy/settings and report status to Claude.
#[instrument(level = Level::TRACE, skip(input))]
pub fn handle_session_start(input: &SessionStart) -> anyhow::Result<Response> {
    // Ensure the user has a policy file — create one with safe defaults if not.
    let created_policy = ClashSettings::ensure_user_policy_exists()?;

    let hook_ctx = crate::settings::HookContext::from_transcript_path(input.transcript_path());
    let _settings =
        ClashSettings::load_or_create_with_session(Some(input.session_id()), Some(&hook_ctx))?;

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
        .permission_mode()
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

    finish_session_start(input, lines)
}

/// Generate comprehensive context about clash for injection into Claude's session.
///
/// This text is returned as `additional_context` in the SessionStart hook response,
/// giving Claude the knowledge it needs to use clash skills and manage policies.
fn clash_session_context() -> &'static str {
    include_str!("../docs/session-context.md")
}

/// Check sandbox support, init session, and symlink — shared by both paths.
fn check_sandbox_and_session(lines: &mut Vec<String>, input: &SessionStart) {
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
        input.session_id(),
        input.cwd(),
        input.source(),
        input.model(),
    ) {
        Ok(session_dir) => {
            lines.push(format!("session history: {}", session_dir.display()));
        }
        Err(e) => {
            warn!(error = %e, "Failed to create session history directory");
        }
    }

    // 4b. Write active session marker so CLI commands can find this session.
    if let Err(e) = ClashSettings::set_active_session(input.session_id()) {
        warn!(error = %e, "Failed to write active session marker");
    }

    // 5. Session metadata
    if let Some(source) = input.source() {
        lines.push(format!("session source: {}", source));
    }
    if let Some(model) = input.model() {
        lines.push(format!("model: {}", model));
    }
}

fn finish_session_start(input: &SessionStart, lines: Vec<String>) -> anyhow::Result<Response> {
    info!(context = %lines.join("; "), "SessionStart validation");

    let response = if lines.is_empty() {
        input.pass()
    } else {
        input.context(lines.join("\n"))
    };

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_hooks::HookEvent;

    fn make_session_start_event() -> SessionStart {
        let json = serde_json::json!({
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-sonnet-4-20250514",
        });
        match clash_hooks::recv_from(serde_json::to_vec(&json).unwrap().as_slice()).unwrap() {
            HookEvent::SessionStart(e) => e,
            _ => panic!("expected SessionStart"),
        }
    }

    fn get_context(response: &Response) -> Option<String> {
        let mut buf = Vec::new();
        clash_hooks::send_to(response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        json["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .map(|s| s.to_string())
    }

    #[test]
    fn test_session_start_reports_sandbox_support() {
        let input = make_session_start_event();
        let output = handle_session_start(&input).unwrap();
        let ctx = get_context(&output).expect("should have context");
        assert!(
            ctx.contains("sandbox:"),
            "should report sandbox status, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_session_metadata() {
        let input = make_session_start_event();
        let output = handle_session_start(&input).unwrap();
        let ctx = get_context(&output).expect("should have context");
        assert!(ctx.contains("session source: startup"), "got: {ctx}");
        assert!(
            ctx.contains("model: claude-sonnet-4-20250514"),
            "got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_recommends_skip_permissions_in_default_mode() {
        let input = make_session_start_event();
        let output = handle_session_start(&input).unwrap();
        let ctx = get_context(&output).expect("should have context");
        assert!(
            ctx.contains("--dangerously-skip-permissions"),
            "should recommend --dangerously-skip-permissions when not in skip mode, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_no_recommendation_when_skip_permissions() {
        let json = serde_json::json!({
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/tmp",
            "permission_mode": "dangerously-skip-permissions",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-sonnet-4-20250514",
        });
        let input = match clash_hooks::recv_from(serde_json::to_vec(&json).unwrap().as_slice()).unwrap() {
            HookEvent::SessionStart(e) => e,
            _ => panic!("expected SessionStart"),
        };
        let output = handle_session_start(&input).unwrap();
        let ctx = get_context(&output).expect("should have context");
        assert!(
            !ctx.contains("NOTE: Clash is managing permissions"),
            "should NOT recommend when already in skip mode, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_injects_instructions_when_skip_permissions() {
        let json = serde_json::json!({
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/tmp",
            "permission_mode": "dangerously-skip-permissions",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-sonnet-4-20250514",
        });
        let input = match clash_hooks::recv_from(serde_json::to_vec(&json).unwrap().as_slice()).unwrap() {
            HookEvent::SessionStart(e) => e,
            _ => panic!("expected SessionStart"),
        };
        let output = handle_session_start(&input).unwrap();
        let ctx = get_context(&output).expect("should have context");
        assert!(ctx.contains("policy enforcement is DISABLED"), "got: {ctx}");
        assert!(ctx.contains("Filesystem sandboxing"), "got: {ctx}");
    }
}
