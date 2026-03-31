use std::io::Write;

use anyhow::{Context, Result};
use tracing::{Level, info, instrument};

use crate::agents::AgentKind;
use crate::agents::protocol::get_protocol;
use crate::cli::{HookCmd, HookSubcommand};
use crate::hooks::{HookOutput, HookSpecificOutput, PermissionBehavior, is_interactive_tool};
use crate::permissions::check_permission;
use crate::policy_decision::PolicyDecision;
use crate::session_policy;
use crate::settings::{ClashSettings, HookContext};
use crate::trace;

use clash_hooks::{HookEvent, HookEventCommon, ToolEvent};

/// Generate a fallback session ID when the agent doesn't provide one.
///
/// Uses the parent PID as a stable identifier — every `clash hook` invocation
/// within the same agent session shares the same parent process.
fn fallback_session_id(agent: AgentKind) -> String {
    let ppid = std::os::unix::process::parent_id();
    format!("{agent}-{ppid}")
}

impl HookCmd {
    /// Handle hook when clash is disabled — drain stdin and return pass-through.
    fn run_disabled(&self) -> Result<()> {
        info!("Clash is disabled (CLASH_DISABLE), returning pass-through");
        let output = match self.subcommand {
            HookSubcommand::SessionStart => {
                // Still read stdin to avoid broken pipe.
                let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
                HookOutput::session_start(Some(
                    "Clash is disabled (CLASH_DISABLE is set). \
                     All hooks are pass-through — no policy enforcement is active. \
                     Unset CLASH_DISABLE to re-enable."
                        .into(),
                ))
            }
            _ => {
                // Drain stdin to avoid broken pipe, but skip parsing.
                let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
                HookOutput::continue_execution()
            }
        };
        output
            .write_stdout()
            .context("serializing disabled-mode hook response to stdout")?;
        Ok(())
    }

    /// Read a hook event from stdin, dispatching via the agent's protocol.
    fn recv_event(&self) -> Result<HookEvent> {
        let raw: serde_json::Value = serde_json::from_reader(std::io::stdin().lock())?;
        get_protocol(self.agent).parse_event(&raw)
    }

    #[instrument(level = Level::TRACE, skip(self), fields(agent = %self.agent))]
    pub fn run(&self) -> Result<()> {
        if crate::settings::is_disabled() {
            return self.run_disabled();
        }

        let passthrough = crate::settings::is_passthrough();

        // Read the event from stdin via the agent's protocol.
        let event = self.recv_event().context("parsing hook event from stdin")?;

        // Dispatch on the event type.
        match event {
            HookEvent::PreToolUse(ref e) => {
                let mut session_id = e.session_id().to_string();
                if session_id.is_empty() {
                    session_id = fallback_session_id(self.agent);
                    info!(session_id = %session_id, "Agent did not provide session_id, using fallback");
                }

                if passthrough {
                    info!(
                        tool = %e.tool_name(),
                        "CLASH_PASSTHROUGH: deferring to native permissions"
                    );
                    if let Err(err) = trace::sync_trace(&session_id, None) {
                        tracing::warn!(error = %err, "Failed to sync trace (PreToolUse/passthrough)");
                    }
                    self.write_output(&HookOutput::continue_execution())?;
                } else {
                    let hook_ctx = HookContext::from_transcript_path(e.transcript_path());
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&session_id),
                        Some(&hook_ctx),
                    )?;
                    let decision = check_permission(e, Some(self.agent), &settings)?;

                    // Interactive tools (e.g., AskUserQuestion) require user input
                    // via Claude Code's native UI.
                    if is_interactive_tool(e.tool_name())
                        && !decision.is_deny()
                        && decision.is_ask()
                    {
                        info!(tool = %e.tool_name(), "Passthrough: interactive tool deferred to Claude Code");
                        self.write_output(&HookOutput::continue_execution())?;
                    } else {
                        // Update session stats.
                        if let Some(effect) = decision.effect() {
                            crate::audit::update_session_stats(
                                &session_id,
                                e.tool_name(),
                                e.tool_input_raw(),
                                effect,
                                e.cwd(),
                            );
                        }

                        // Record Ask for session policy advice.
                        if decision.is_ask()
                            && let Some(tool_use_id) = e.tool_use_id()
                        {
                            session_policy::record_pending_ask(
                                &session_id,
                                tool_use_id,
                                e.tool_name(),
                                e.tool_input_raw(),
                                e.cwd(),
                            );
                        }

                        // Sync trace.
                        let trace_decision = e.tool_use_id().and_then(|id| {
                            let effect = decision.effect()?;
                            Some(trace::TraceDecision {
                                tool_use_id: id.to_string(),
                                tool_name: Some(e.tool_name().to_string()),
                                effect,
                                reason: None,
                            })
                        });
                        if let Err(err) = trace::sync_trace(&session_id, trace_decision) {
                            tracing::warn!(error = %err, "Failed to sync trace (PreToolUse)");
                        }

                        self.write_decision(&decision)?;
                    }
                }
            }
            HookEvent::PostToolUse(ref e) => {
                let mut session_id = e.session_id().to_string();
                if session_id.is_empty() {
                    session_id = fallback_session_id(self.agent);
                }

                // Check if this tool use was previously "ask"ed.
                let session_context = e.tool_use_id().and_then(|tool_use_id| {
                    let advice = session_policy::process_post_tool_use(
                        tool_use_id,
                        &session_id,
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

                // Check for sandbox hints.
                let (network_context, fs_context) = {
                    let hook_ctx = HookContext::from_transcript_path(e.transcript_path());
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&session_id),
                        Some(&hook_ctx),
                    )
                    .ok();
                    let net = settings
                        .as_ref()
                        .and_then(|s| crate::network_hints::check_for_sandbox_network_hint(e, s));
                    let fs = settings
                        .as_ref()
                        .and_then(|s| crate::sandbox_hints::check_for_sandbox_fs_hint(e, s));
                    (net, fs)
                };

                // Combine contexts.
                let context = [session_context, network_context, fs_context]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let context = if context.is_empty() {
                    None
                } else {
                    Some(context.join("\n\n"))
                };

                if let Err(err) = trace::sync_trace(&session_id, None) {
                    tracing::warn!(error = %err, "Failed to sync trace (PostToolUse)");
                }

                self.write_output(&HookOutput::post_tool_use(context))?;
            }
            HookEvent::PermissionRequest(ref e) => {
                let mut session_id = e.session_id().to_string();
                if session_id.is_empty() {
                    session_id = fallback_session_id(self.agent);
                }

                if passthrough {
                    info!(
                        tool = %e.tool_name(),
                        "CLASH_PASSTHROUGH: deferring permission request to native UI"
                    );
                    self.write_output(&HookOutput::continue_execution())?;
                } else {
                    let hook_ctx = HookContext::from_transcript_path(e.transcript_path());
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&session_id),
                        Some(&hook_ctx),
                    )?;
                    let output =
                        crate::handlers::handle_permission_request(e, Some(self.agent), &settings)?;
                    self.write_output(&output)?;
                }
            }
            HookEvent::SessionStart(ref e) => {
                let mut session_id = e.session_id().to_string();
                if session_id.is_empty() {
                    session_id = fallback_session_id(self.agent);
                    info!(session_id = %session_id, "Agent did not provide session_id, using fallback");
                }
                let output = crate::handlers::handle_session_start(e, &session_id)?;
                self.write_output(&output)?;
            }
            HookEvent::Stop(ref e) => {
                let mut session_id = e.session_id().to_string();
                if session_id.is_empty() {
                    session_id = fallback_session_id(self.agent);
                    info!(session_id = %session_id, "Agent did not provide session_id, using fallback");
                }

                if let Err(err) = trace::sync_trace(&session_id, None) {
                    tracing::warn!(error = %err, "Failed to sync trace (Stop)");
                }

                self.write_output(&HookOutput::continue_execution())?;
            }
            _ => {
                // Unknown or unhandled events — pass through.
                self.write_output(&HookOutput::continue_execution())?;
            }
        }

        Ok(())
    }

    /// Write a [`PolicyDecision`] directly to stdout in the agent's format.
    fn write_decision(&self, decision: &PolicyDecision) -> Result<()> {
        let json = get_protocol(self.agent).format_decision(decision);
        serde_json::to_writer(std::io::stdout().lock(), &json)
            .context("serializing hook response to stdout")?;
        writeln!(std::io::stdout().lock())?;
        Ok(())
    }

    /// Write a HookOutput to stdout, converting to agent protocol format.
    ///
    /// Used for non-PreToolUse events (PostToolUse, SessionStart, PermissionRequest, etc.)
    fn write_output(&self, output: &HookOutput) -> Result<()> {
        let protocol = get_protocol(self.agent);
        let json = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(ss)) => {
                protocol.format_session_start(ss.additional_context.as_deref())
            }
            Some(HookSpecificOutput::PostToolUse(pt)) => {
                protocol.format_post_tool_use(pt.additional_context.as_deref())
            }
            Some(HookSpecificOutput::PermissionRequest(pr)) => {
                let behavior = match pr.decision.behavior {
                    PermissionBehavior::Allow => "allow",
                    PermissionBehavior::Deny => "deny",
                };
                protocol.format_permission_response(
                    behavior,
                    pr.decision.message.as_deref(),
                    pr.decision.updated_input.as_ref(),
                    pr.decision.interrupt,
                )
            }
            _ => protocol.format_continue(),
        };
        serde_json::to_writer(std::io::stdout().lock(), &json)
            .context("serializing hook response to stdout")?;
        writeln!(std::io::stdout().lock())?;
        Ok(())
    }
}
