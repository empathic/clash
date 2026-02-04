//! Pre-built hook handlers for Claude Code integration.
//!
//! These handlers wire together permission evaluation, notifications, and
//! session validation into ready-to-use functions that process Claude Code
//! hook events.

use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, HookSpecificOutput, SessionStartHookInput, ToolUseHookInput};
use crate::notifications;
use crate::permissions::check_permission;
use crate::settings::{self, ClashSettings};

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
            // Ask or no decision: notify and try Zulip resolution.
            _ => {
                send_permission_desktop_notification(input, settings);
                resolve_via_zulip_or_continue(input, settings)
            }
        },
        _ => pre_tool_result,
    })
}

/// Send a desktop notification for a permission request, if enabled.
pub fn send_permission_desktop_notification(input: &ToolUseHookInput, settings: &ClashSettings) {
    if !settings.notifications.desktop {
        return;
    }
    let summary = match input.tool_name.as_str() {
        "Bash" => {
            let cmd = input.tool_input["command"].as_str().unwrap_or("(unknown)");
            format!("Permission needed: Bash `{}`", cmd)
        }
        _ => format!("Permission needed: {}", input.tool_name),
    };
    notifications::send_desktop_notification("Clash: Permission Request", &summary);
}

/// Attempt to resolve a permission ask via Zulip. Falls back to `continue_execution`.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn resolve_via_zulip_or_continue(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> HookOutput {
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
            // Timeout — fall through to terminal.
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
    let mut lines: Vec<String> = Vec::new();

    // 1. Check policy file
    let policy_path = ClashSettings::policy_file();
    if policy_path.exists() {
        match std::fs::read_to_string(&policy_path) {
            Ok(contents) => match claude_settings::policy::parse::parse_yaml(&contents) {
                Ok(doc) => {
                    let rule_count = doc.statements.len()
                        + doc
                            .profile_defs
                            .values()
                            .map(|p| p.rules.len())
                            .sum::<usize>();
                    let format = if doc.profile_defs.is_empty() {
                        "legacy"
                    } else {
                        "new"
                    };
                    match claude_settings::policy::CompiledPolicy::compile(&doc) {
                        Ok(_) => {
                            lines.push(format!(
                                "policy.yaml: OK ({} rules, format={}, default={})",
                                rule_count, format, doc.policy.default,
                            ));
                        }
                        Err(e) => {
                            lines.push(format!("ISSUE: policy.yaml compile error: {}", e));
                        }
                    }
                }
                Err(e) => {
                    lines.push(format!("ISSUE: policy.yaml parse error: {}", e));
                }
            },
            Err(e) => {
                lines.push(format!("ISSUE: policy.yaml read error: {}", e));
            }
        }
    } else {
        lines.push("policy.yaml: not found (using legacy permissions)".into());
    }

    // 2. Validate notification config from the same policy file
    if policy_path.exists()
        && let Ok(contents) = std::fs::read_to_string(&policy_path)
    {
        let (notif_config, notif_warning) = settings::parse_notification_config(&contents);
        if let Some(warning) = notif_warning {
            lines.push(format!("ISSUE: {}", warning));
        } else {
            let zulip_status = if notif_config.zulip.is_some() {
                "configured"
            } else {
                "not configured"
            };
            lines.push(format!(
                "notifications: OK (desktop={}, zulip={})",
                notif_config.desktop, zulip_status
            ));
        }
    }

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

    // 5. Session metadata
    if let Some(ref source) = input.source {
        lines.push(format!("session source: {}", source));
    }
    if let Some(ref model) = input.model {
        lines.push(format!("model: {}", model));
    }

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
}
