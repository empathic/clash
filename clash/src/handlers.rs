//! Pre-built hook handlers for Claude Code integration.
//!
//! These handlers wire together permission evaluation, notifications, and
//! session validation into ready-to-use functions that process Claude Code
//! hook events.

use tracing::{Level, debug, info, instrument, warn};

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
///
/// When both are configured they race concurrently — the first response wins.
/// The desktop notification blocks the main thread (macOS requirement), while
/// Zulip polls in a background thread. If the Zulip thread gets a response
/// first it writes directly to stdout and exits the process.
///
/// When only one channel is configured, it runs alone. If neither resolves
/// the request, we fall through to the terminal prompt.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn resolve_via_desktop_or_zulip(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> HookOutput {
    let has_desktop = settings.notifications.desktop;
    let has_zulip = settings.notifications.zulip.is_some();

    // If both are configured, race them concurrently.
    // If only Zulip, run it on the main thread (no macOS constraint).
    // If only desktop, run it on the main thread.
    // If neither, fall through immediately.

    if has_zulip && has_desktop {
        // Start Zulip polling in a background thread. If it wins the race,
        // it writes the hook output to stdout and exits the process directly.
        start_zulip_background(input, settings);

        // Desktop notification blocks the main thread.
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

/// Show an interactive desktop notification and return the result.
/// Falls through to `continue_execution` on timeout or unavailability.
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

/// Spawn a background thread that polls Zulip for a permission response.
///
/// If the Zulip thread receives a response before the desktop notification,
/// it writes the hook output directly to stdout and exits the process. This
/// is safe because we run inside a short-lived hook subprocess.
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

    // Clone config so the thread owns its data.
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
                // Don't exit — let the desktop notification or terminal handle it.
            }
            Err(e) => {
                warn!(error = %e, "Zulip resolution failed (background)");
            }
        }
    });
}

/// Attempt to resolve a permission ask via Zulip on the current thread.
/// Falls back to `continue_execution`.
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

/// Collect human-readable deny rule descriptions from both legacy statements and profile defs.
fn collect_deny_descriptions(doc: &crate::policy::ast::PolicyDocument) -> Vec<String> {
    let mut descriptions = Vec::new();

    // Legacy statements
    for stmt in &doc.statements {
        if stmt.effect == crate::policy::Effect::Deny {
            let noun_str = crate::policy::ast::format_pattern_str(&stmt.noun);
            let verb_str = match &stmt.verb {
                crate::policy::VerbPattern::Any => "*".to_string(),
                crate::policy::VerbPattern::Exact(v) => v.to_string(),
                crate::policy::VerbPattern::Named(s) => s.clone(),
            };
            descriptions.push(format!("deny {} {}", verb_str, noun_str));
        }
    }

    // New-format profile rules
    for profile_def in doc.profile_defs.values() {
        for rule in &profile_def.rules {
            if rule.effect == crate::policy::Effect::Deny {
                let noun_str = crate::policy::ast::format_pattern_str(&rule.noun);
                descriptions.push(format!("deny {} {}", rule.verb, noun_str));
            }
        }
    }

    descriptions
}

/// Handle a session start event — validate policy/settings and report status to Claude.
#[instrument(level = Level::TRACE, skip(input))]
pub fn handle_session_start(input: &SessionStartHookInput) -> anyhow::Result<HookOutput> {
    let mut lines: Vec<String> = Vec::new();

    // 0. Check permission mode and recommend --dangerously-skip-permissions
    let skip_permissions = input
        .permission_mode
        .as_deref()
        .is_some_and(|m| m.contains("dangerously-skip-permissions"));

    if skip_permissions {
        eprintln!(
            "\x1b[1;33mwarning\x1b[0m: clash: running with --dangerously-skip-permissions \
             — policy enforcement disabled"
        );

        lines.push(
            "IMPORTANT: This session is running with --dangerously-skip-permissions. \
             Clash's policy enforcement is DISABLED — all tool calls are auto-approved \
             without policy evaluation. Filesystem sandboxing (Landlock/Seatbelt) is \
             still active if configured, but no permission rules are being checked. \
             Exercise extra caution with destructive operations (deleting files, force-pushing, \
             modifying system files). To re-enable policy enforcement, restart Claude Code \
             without the --dangerously-skip-permissions flag."
                .into(),
        );
    } else {
        lines.push(
            "NOTE: Clash is managing permissions for this session. \
             For the best experience, run Claude Code with --dangerously-skip-permissions \
             to let Clash be the sole permission handler and avoid double prompting."
                .into(),
        );
    }

    // 1. Check policy file
    let policy_contents = match ClashSettings::policy_file() {
        Ok(policy_path) if policy_path.exists() => match std::fs::read_to_string(&policy_path) {
            Ok(contents) => Some(contents),
            Err(e) => {
                lines.push(format!("ISSUE: policy.yaml read error: {}", e));
                None
            }
        },
        Ok(_) => {
            lines.push("policy.yaml: not found (using legacy permissions)".into());
            None
        }
        Err(e) => {
            lines.push(format!("ISSUE: policy.yaml path error: {}", e));
            None
        }
    };

    if let Some(ref contents) = policy_contents {
        match crate::policy::parse::parse_yaml(contents) {
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
                match crate::policy::CompiledPolicy::compile(&doc) {
                    Ok(_) => {
                        lines.push(format!(
                            "policy.yaml: OK ({} rules, format={}, default={})",
                            rule_count, format, doc.policy.default,
                        ));

                        // Build a user-friendly summary with key denials and active profile.
                        let mut deny_descriptions = collect_deny_descriptions(&doc);
                        deny_descriptions.sort();
                        deny_descriptions.dedup();

                        let profile_name = doc
                            .default_config
                            .as_ref()
                            .map(|dc| dc.profile.as_str())
                            .unwrap_or("(none)");

                        let denials_summary = if deny_descriptions.is_empty() {
                            "no explicit denials".to_string()
                        } else if deny_descriptions.len() <= 4 {
                            deny_descriptions.join(", ")
                        } else {
                            let first_four = &deny_descriptions[..4];
                            format!(
                                "{}, +{} more",
                                first_four.join(", "),
                                deny_descriptions.len() - 4
                            )
                        };

                        lines.push(format!(
                            "Clash active: profile '{}', {} rules. Denied: {}. Use /clash:status or /clash:edit for details.",
                            profile_name, rule_count, denials_summary,
                        ));
                    }
                    Err(e) => {
                        lines.push(format!(
                            "ISSUE: policy.yaml compile error: {}. All actions will default to 'ask'.",
                            e
                        ));
                    }
                }
            }
            Err(e) => {
                lines.push(format!(
                    "ISSUE: policy.yaml parse error: {}. All actions will default to 'ask'.",
                    e
                ));
            }
        }

        // 2. Validate notification config from the same policy file
        let (notif_config, notif_warning) = settings::parse_notification_config(contents);
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

    // 4. Export CLASH_BIN via CLAUDE_ENV_FILE so skills can use $CLASH_BIN
    if let Ok(env_file) = std::env::var("CLAUDE_ENV_FILE") {
        match std::env::current_exe() {
            Ok(exe_path) => {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&env_file) {
                    let _ = writeln!(f, "CLASH_BIN={}", exe_path.display());
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to resolve clash binary path");
            }
        }
    }

    // 4b. Symlink clash binary into a user-owned PATH directory
    #[cfg(unix)]
    if let Ok(exe_path) = std::env::current_exe() {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::getuid() };
        let linked = std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .find_map(|dir| {
                let dir = std::path::Path::new(dir);
                let meta = std::fs::metadata(dir).ok()?;
                if meta.uid() != uid {
                    return None;
                }
                // Check writable by attempting a temp file
                let test_path = dir.join(".clash_write_test");
                if std::fs::write(&test_path, b"").is_ok() {
                    let _ = std::fs::remove_file(&test_path);
                } else {
                    return None;
                }
                let link_path = dir.join("clash");
                // Already correctly linked — nothing to do
                if let Ok(target) = std::fs::read_link(&link_path) {
                    if target == exe_path {
                        return Some(true);
                    }
                    // Stale symlink — replace it
                    let _ = std::fs::remove_file(&link_path);
                } else if link_path.exists() {
                    // Regular file exists — don't clobber
                    return None;
                }
                match std::os::unix::fs::symlink(&exe_path, &link_path) {
                    Ok(()) => {
                        info!(dir = %dir.display(), "symlinked clash into PATH");
                        Some(true)
                    }
                    Err(e) => {
                        debug!(error = %e, dir = %dir.display(), "failed to symlink clash");
                        None
                    }
                }
            });
        if linked.is_none() {
            debug!("no suitable user-owned PATH directory found for clash symlink");
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

    #[test]
    fn test_session_start_recommends_skip_permissions_in_default_mode() {
        let input = default_session_start_input(); // permission_mode = "default"
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
            "should NOT recommend --dangerously-skip-permissions when already in skip mode, got: {ctx}"
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
        assert!(
            ctx.contains("policy enforcement is DISABLED"),
            "should warn about disabled policy enforcement, got: {ctx}"
        );
        assert!(
            ctx.contains("Filesystem sandboxing"),
            "should mention sandbox is still active, got: {ctx}"
        );
        assert!(
            ctx.contains("restart Claude Code without"),
            "should explain how to re-enable, got: {ctx}"
        );
    }
}
