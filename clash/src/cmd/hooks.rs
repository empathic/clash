use anyhow::Result;
use clash_hooks::{HookEvent, HookEventCommon, Response, ToolEvent};
use tracing::{Level, info, instrument};

use crate::cli::HooksCmd;
use crate::permissions::check_permission;
use crate::policy_decision::PolicyDecision;
use crate::session_policy;
use crate::settings::{ClashSettings, HookContext};

impl HooksCmd {
    /// Handle hook when clash is disabled — drain stdin and return pass-through.
    fn run_disabled(&self) -> Result<()> {
        info!("Clash is disabled (CLASH_DISABLE), returning pass-through");
        // Read stdin to determine event type (avoids broken pipe).
        let event = clash_hooks::recv()?;
        let response = match event {
            HookEvent::SessionStart(e) => {
                e.context(
                    "Clash is disabled (CLASH_DISABLE is set). \
                     All hooks are pass-through — no policy enforcement is active. \
                     Unset CLASH_DISABLE to re-enable.",
                )
            }
            _ => clash_hooks::pass(),
        };
        clash_hooks::send(&response)?;
        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(self))]
    pub fn run(&self) -> Result<()> {
        if crate::settings::is_disabled() {
            return self.run_disabled();
        }

        let event = clash_hooks::recv()?;
        let response = match event {
            HookEvent::PreToolUse(ref e) => {
                let hook_ctx = HookContext::from_transcript_path(e.transcript_path());
                let settings = ClashSettings::load_or_create_with_session(
                    Some(e.session_id()),
                    Some(&hook_ctx),
                )?;
                let decision = check_permission(e, &settings)?;

                // Interactive tools (e.g., AskUserQuestion) require user input
                // via Claude Code's native UI. Returning "allow" would skip that
                // UI entirely, so we pass through for any non-deny decision.
                if e.is_interactive_tool() && !decision.is_deny() {
                    info!(tool = %e.tool_name(), "Passthrough: interactive tool deferred to Claude Code");
                    clash_hooks::pass()
                } else {
                    // Update session stats for the status line (only here, not in
                    // log_decision, to avoid double-counting PermissionRequest).
                    if let Some(effect) = decision.effect() {
                        crate::audit::update_session_stats(
                            e.session_id(),
                            e.tool_name(),
                            e.tool_input_raw(),
                            effect,
                            e.cwd(),
                        );
                    }

                    // If the decision is Ask, record it so PostToolUse can detect
                    // user approval and suggest a session policy rule.
                    if decision.is_ask()
                        && let Some(tool_use_id) = e.tool_use_id()
                    {
                        session_policy::record_pending_ask(
                            e.session_id(),
                            tool_use_id,
                            e.tool_name(),
                            e.tool_input_raw(),
                            e.cwd(),
                        );
                    }

                    policy_decision_to_pre_tool_use_response(e, decision)
                }
            }
            HookEvent::PostToolUse(ref e) => {
                // Check if this tool use was previously "ask"ed and the user
                // accepted. If so, return advisory context suggesting a session
                // rule for Claude to offer the user.
                let session_context = e.tool_use_id().and_then(|tool_use_id| {
                    let advice = session_policy::process_post_tool_use(
                        tool_use_id,
                        e.session_id(),
                        e.tool_name(),
                        e.tool_input_raw(),
                        e.cwd(),
                    )?;
                    info!(
                        rule = %advice.suggested_rule,
                        "Suggesting session rule for user approval"
                    );
                    Some(advice.as_context())
                });

                // Check if a sandboxed Bash command failed with network or
                // filesystem errors, and provide hints about sandbox restrictions.
                let (network_context, fs_context) = {
                    let hook_ctx = HookContext::from_transcript_path(e.transcript_path());
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(e.session_id()),
                        Some(&hook_ctx),
                    )
                    .ok();
                    let net = settings
                        .as_ref()
                        .and_then(|s| crate::network_hints::check_for_sandbox_network_hint(e, s));
                    let fs = settings
                        .as_ref()
                        .and_then(|s| crate::sandbox_fs_hints::check_for_sandbox_fs_hint(e, s));
                    (net, fs)
                };

                // Combine contexts (session policy advice + sandbox hints).
                let context = [session_context, network_context, fs_context]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                if context.is_empty() {
                    e.pass()
                } else {
                    e.context(context.join("\n\n"))
                }
            }
            HookEvent::PermissionRequest(ref e) => {
                let hook_ctx = HookContext::from_transcript_path(e.transcript_path());
                let settings = ClashSettings::load_or_create_with_session(
                    Some(e.session_id()),
                    Some(&hook_ctx),
                )?;
                crate::handlers::handle_permission_request(e, &settings)?
            }
            HookEvent::SessionStart(ref e) => {
                crate::handlers::handle_session_start(e)?
            }
            _ => clash_hooks::pass(),
        };

        clash_hooks::send(&response)?;
        Ok(())
    }
}

/// Convert a [`PolicyDecision`] into a [`Response`] for a PreToolUse event.
fn policy_decision_to_pre_tool_use_response(
    event: &clash_hooks::event::PreToolUse,
    decision: PolicyDecision,
) -> Response {
    match decision {
        PolicyDecision::Allow {
            reason,
            context,
            updated_input,
        } => {
            if let Some(updated) = updated_input {
                // Allow with rewritten input (sandbox wrapping).
                let mut resp = event.allow_with_modified_input(updated);
                if let Some(ctx) = context {
                    resp = resp.with_context(ctx);
                }
                resp
            } else {
                match context {
                    Some(ctx) => event.allow_with_context(reason, ctx),
                    None => event.allow_with_reason(reason),
                }
            }
        }
        PolicyDecision::Deny { reason, context } => match context {
            Some(ctx) => event.deny_with_context(reason, ctx),
            None => event.deny(reason),
        },
        PolicyDecision::Ask { reason, context } => match context {
            Some(ctx) => event.ask_with_context(reason, ctx),
            None => event.ask_with_reason(reason),
        },
        PolicyDecision::Pass => event.pass(),
    }
}
