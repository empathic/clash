//! Pre-built hook handlers for Claude Code integration.
//!
//! These handlers wire together permission evaluation, notifications, and
//! session validation into ready-to-use functions that process Claude Code
//! hook events.

use tracing::{Level, info, instrument, warn};

use crate::hooks::{
    HookOutput, HookSpecificOutput, SessionStartHookInput, ToolUseHookInput, is_interactive_tool,
};
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
    // Interactive tools (AskUserQuestion, EnterPlanMode, ExitPlanMode):
    // When the policy says "ask", pass through to CC's native UI so the
    // user sees the prompt. When the policy explicitly allows or denies,
    // enforce it — this enables mode-aware automation.
    if is_interactive_tool(&input.tool_name) {
        let pre_tool_result = check_permission(input, settings)?;
        let is_deny = matches!(
            pre_tool_result.hook_specific_output,
            Some(HookSpecificOutput::PreToolUse(ref pre))
                if matches!(pre.permission_decision, Some(PermissionRule::Deny))
        );
        let is_allow = matches!(
            pre_tool_result.hook_specific_output,
            Some(HookSpecificOutput::PreToolUse(ref pre))
                if matches!(pre.permission_decision, Some(PermissionRule::Allow))
        );
        if is_deny {
            let reason = match &pre_tool_result.hook_specific_output {
                Some(HookSpecificOutput::PreToolUse(pre)) => pre
                    .permission_decision_reason
                    .clone()
                    .unwrap_or_else(|| "denied by policy".into()),
                _ => "denied by policy".into(),
            };
            return Ok(HookOutput::deny_permission(reason, false));
        }
        if is_allow {
            info!(tool = %input.tool_name, "Policy allows interactive tool");
            return Ok(HookOutput::approve_permission(None));
        }
        info!(tool = %input.tool_name, "Passthrough: interactive tool deferred to Claude Code");
        return Ok(HookOutput::continue_execution());
    }

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
    let display = crate::agents::display_name(&input.tool_name);
    match input.tool_name.as_str() {
        "Bash" => {
            let cmd = input.tool_input["command"].as_str().unwrap_or("(unknown)");
            format!("{}: {}", display, cmd)
        }
        _ => display.to_string(),
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

/// Build a [`notifications::PermissionRequest`] from a tool use hook input.
fn build_permission_request(input: &ToolUseHookInput) -> notifications::PermissionRequest {
    notifications::PermissionRequest {
        tool_name: input.tool_name.clone(),
        tool_input: input.tool_input.clone(),
        session_id: input.session_id.clone(),
        cwd: input.cwd.clone(),
    }
}

/// Map a Zulip resolution result to a [`HookOutput`].
///
/// Returns `Some(output)` for a definitive approve/deny, or `None` when the
/// resolution timed out or failed (caller should fall through to the next strategy).
fn zulip_result_to_output(
    result: anyhow::Result<Option<notifications::PermissionResponse>>,
) -> Option<HookOutput> {
    match result {
        Ok(Some(notifications::PermissionResponse::Approve)) => {
            Some(HookOutput::approve_permission(None))
        }
        Ok(Some(notifications::PermissionResponse::Deny(reason))) => {
            Some(HookOutput::deny_permission(reason, false))
        }
        Ok(None) => None,
        Err(_) => None,
    }
}

fn start_zulip_background(input: &ToolUseHookInput, settings: &ClashSettings) {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return;
    };

    let request = build_permission_request(input);
    let config = zulip_config.clone();

    std::thread::spawn(move || {
        let client = notifications::ZulipClient::new(&config);
        let result = client.resolve_permission(&request);
        match &result {
            Ok(Some(notifications::PermissionResponse::Approve)) => {
                info!("Permission approved via Zulip (background), exiting hook");
            }
            Ok(Some(notifications::PermissionResponse::Deny(_))) => {
                info!("Permission denied via Zulip (background), exiting hook");
            }
            Ok(None) => info!("Zulip resolution timed out (background)"),
            Err(e) => warn!(error = %e, "Zulip resolution failed (background)"),
        }
        if let Some(output) = zulip_result_to_output(result)
            && output.write_stdout().is_ok()
        {
            std::process::exit(0);
        }
    });
}

#[instrument(level = Level::TRACE, skip(input, settings))]
fn resolve_via_zulip_or_continue(input: &ToolUseHookInput, settings: &ClashSettings) -> HookOutput {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return HookOutput::continue_execution();
    };

    let client = notifications::ZulipClient::new(zulip_config);
    let result = client.resolve_permission(&build_permission_request(input));

    if result.is_err() || matches!(result, Ok(None)) {
        info!("Zulip resolution timed out or failed, falling through to terminal");
    }

    zulip_result_to_output(result).unwrap_or_else(HookOutput::continue_execution)
}

/// Handle a session start event — validate policy/settings and report status to Claude.
#[instrument(level = Level::TRACE, skip(input))]
pub fn handle_session_start(input: &SessionStartHookInput) -> anyhow::Result<HookOutput> {
    // Ensure the user has a policy file — create one with safe defaults if not.
    let created_policy = ClashSettings::ensure_user_policy_exists()?;

    let hook_ctx = crate::settings::HookContext::from_transcript_path(&input.transcript_path);
    let _settings =
        ClashSettings::load_or_create_with_session(Some(&input.session_id), Some(&hook_ctx))?;

    let mut lines = Vec::new();

    if let Some(path) = created_policy {
        lines.push(format!(
            "Welcome to Clash! A default policy has been created at {}. \
             It starts with deny-all and allows reading files in your project. \
             Run `clash status` to see what's allowed, or edit the policy file to customize.",
            path.display()
        ));
    }

    // Inject clash usage context so Claude understands how to use skills and policies.
    lines.push(clash_session_context().into());

    lines.push("Clash is managing permissions via hooks.".into());

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

    // 4c. Initialize toolpath tracing for this session.
    if let Err(e) = crate::trace::init_trace(
        &input.session_id,
        &input.transcript_path,
        &input.cwd,
        input.model.as_deref(),
        input.source.as_deref(),
    ) {
        warn!(error = %e, "Failed to initialize session trace");
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

    fn session_start_context(input: &SessionStartHookInput) -> String {
        let output = handle_session_start(input).expect("session start should succeed");
        match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => {
                s.additional_context.clone().expect("should have context")
            }
            _ => panic!("expected SessionStart output"),
        }
    }

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
        let ctx = session_start_context(&default_session_start_input());
        assert!(
            ctx.contains("sandbox:"),
            "should report sandbox status, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_session_metadata() {
        let ctx = session_start_context(&default_session_start_input());
        assert!(ctx.contains("session source: startup"), "got: {ctx}");
        assert!(
            ctx.contains("model: claude-sonnet-4-20250514"),
            "got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_managing_permissions() {
        let ctx = session_start_context(&default_session_start_input());
        assert!(
            ctx.contains("Clash is managing permissions via hooks"),
            "should report clash is managing permissions, got: {ctx}"
        );
    }
}
