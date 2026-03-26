use std::io::Write;

use anyhow::{Context, Result};
use tracing::{Level, info, instrument};

use crate::agents::protocol::{HookProtocol, get_protocol};
use crate::agents::AgentKind;
use crate::cli::{HookCmd, HookSubcommand};
use crate::hooks::{HookOutput, HookSpecificOutput, ToolUseHookInput, is_interactive_tool};
use crate::permissions::check_permission;
use crate::policy::Effect;
use crate::session_policy;
use crate::settings::{ClashSettings, HookContext};
use crate::trace;

use claude_settings::PermissionRule;

impl HookCmd {
    /// Handle hook when clash is disabled — drain stdin and return pass-through.
    fn run_disabled(&self) -> Result<()> {
        info!("Clash is disabled (CLASH_DISABLE), returning pass-through");
        let output = match self.subcommand {
            HookSubcommand::SessionStart => {
                // Still read stdin to avoid broken pipe.
                let _ = crate::hooks::SessionStartHookInput::from_reader(std::io::stdin().lock());
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

    #[instrument(level = Level::TRACE, skip(self))]
    pub fn run(&self) -> Result<()> {
        if crate::settings::is_disabled() {
            return self.run_disabled();
        }

        let passthrough = crate::settings::is_passthrough();

        let output = match self.subcommand {
            HookSubcommand::PreToolUse => {
                let input = self.parse_tool_use_input()
                    .context("parsing PreToolUse hook input from stdin — expected JSON with tool_name and tool_input fields")?;

                if passthrough {
                    info!(
                        tool = %input.tool_name,
                        "CLASH_PASSTHROUGH: deferring to native permissions"
                    );
                    if let Err(e) = trace::sync_trace(&input.session_id, None) {
                        tracing::warn!(error = %e, "Failed to sync trace (PreToolUse/passthrough)");
                    }
                    HookOutput::continue_execution()
                } else {
                    let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&input.session_id),
                        Some(&hook_ctx),
                    )?;
                    let output = check_permission(&input, &settings)?;

                    // Interactive tools (e.g., AskUserQuestion) require user input
                    // via Claude Code's native UI. When the policy says "ask", pass
                    // through to CC's native prompt. When the policy explicitly allows
                    // or denies, enforce it — this enables mode-aware automation
                    // (e.g., allow ExitPlanMode in plan mode).
                    if is_interactive_tool(&input.tool_name)
                        && !is_deny_decision(&output)
                        && is_ask_decision(&output)
                    {
                        info!(tool = %input.tool_name, "Passthrough: interactive tool deferred to Claude Code");
                        HookOutput::continue_execution()
                    } else {
                        // Update session stats for the status line (only here, not in
                        // log_decision, to avoid double-counting PermissionRequest).
                        if let Some(effect) = extract_effect(&output) {
                            crate::audit::update_session_stats(
                                &input.session_id,
                                &input.tool_name,
                                &input.tool_input,
                                effect,
                                &input.cwd,
                            );
                        }

                        // If the decision is Ask, record it so PostToolUse can detect
                        // user approval and suggest a session policy rule.
                        if is_ask_decision(&output)
                            && let Some(ref tool_use_id) = input.tool_use_id
                        {
                            session_policy::record_pending_ask(
                                &input.session_id,
                                tool_use_id,
                                &input.tool_name,
                                &input.tool_input,
                                &input.cwd,
                            );
                        }

                        // Sync trace with the policy decision for this tool use.
                        let decision = input.tool_use_id.as_ref().and_then(|id| {
                            let effect = extract_effect(&output)?;
                            Some(trace::PolicyDecision {
                                tool_use_id: id.clone(),
                                tool_name: Some(input.tool_name.clone()),
                                effect,
                                reason: None,
                            })
                        });
                        if let Err(e) = trace::sync_trace(&input.session_id, decision) {
                            tracing::warn!(error = %e, "Failed to sync trace (PreToolUse)");
                        }

                        output
                    }
                }
            }
            HookSubcommand::PostToolUse => {
                let input = self.parse_tool_use_input()
                    .context("parsing PostToolUse hook input from stdin")?;

                // Check if this tool use was previously "ask"ed and the user
                // accepted. If so, return advisory context suggesting a session
                // rule for Claude to offer the user.
                let session_context = input.tool_use_id.as_deref().and_then(|tool_use_id| {
                    let advice = session_policy::process_post_tool_use(
                        tool_use_id,
                        &input.session_id,
                        &input.tool_name,
                        &input.tool_input,
                        &input.cwd,
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
                    let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&input.session_id),
                        Some(&hook_ctx),
                    )
                    .ok();
                    let net = settings.as_ref().and_then(|s| {
                        crate::network_hints::check_for_sandbox_network_hint(&input, s)
                    });
                    let fs = settings
                        .as_ref()
                        .and_then(|s| crate::sandbox_hints::check_for_sandbox_fs_hint(&input, s));
                    (net, fs)
                };

                // Combine contexts (session policy advice + sandbox hints).
                let context = [session_context, network_context, fs_context]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let context = if context.is_empty() {
                    None
                } else {
                    Some(context.join("\n\n"))
                };

                // Sync trace to pick up tool responses.
                if let Err(e) = trace::sync_trace(&input.session_id, None) {
                    tracing::warn!(error = %e, "Failed to sync trace (PostToolUse)");
                }

                HookOutput::post_tool_use(context)
            }
            HookSubcommand::PermissionRequest => {
                let input = self.parse_tool_use_input()
                    .context("parsing PermissionRequest hook input from stdin")?;
                if passthrough {
                    info!(
                        tool = %input.tool_name,
                        "CLASH_PASSTHROUGH: deferring permission request to native UI"
                    );
                    HookOutput::continue_execution()
                } else {
                    let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&input.session_id),
                        Some(&hook_ctx),
                    )?;
                    crate::handlers::handle_permission_request(&input, &settings)?
                }
            }
            HookSubcommand::SessionStart => {
                let input =
                    crate::hooks::SessionStartHookInput::from_reader(std::io::stdin().lock())
                        .context("parsing SessionStart hook input from stdin")?;
                crate::handlers::handle_session_start(&input)?
            }
            HookSubcommand::Stop => {
                // Read stdin to avoid broken pipe, extract session_id.
                let input = crate::hooks::StopHookInput::from_reader(std::io::stdin().lock())
                    .context("parsing Stop hook input from stdin")?;

                // Final catch-up sync for non-tool conversation turns.
                if let Err(e) = trace::sync_trace(&input.session_id, None) {
                    tracing::warn!(error = %e, "Failed to sync trace (Stop)");
                }

                HookOutput::continue_execution()
            }
        };

        // For Claude, write the HookOutput directly (existing format).
        // For other agents, convert the decision to their protocol format.
        if self.agent == AgentKind::Claude {
            output
                .write_stdout()
                .context("serializing hook response to stdout")?;
        } else {
            let protocol = get_protocol(self.agent);
            let json = hook_output_to_protocol(&*protocol, &output);
            serde_json::to_writer(std::io::stdout().lock(), &json)
                .context("serializing hook response to stdout")?;
            writeln!(std::io::stdout().lock())?;
        }
        Ok(())
    }

    /// Parse tool-use input from stdin, using the agent's protocol for non-Claude agents.
    fn parse_tool_use_input(&self) -> Result<ToolUseHookInput> {
        if self.agent == AgentKind::Claude {
            let mut input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
            input.agent = Some(AgentKind::Claude);
            Ok(input)
        } else {
            let protocol = get_protocol(self.agent);
            let raw: serde_json::Value = serde_json::from_reader(std::io::stdin().lock())?;
            protocol.parse_tool_use(&raw)
        }
    }
}

fn extract_effect(output: &HookOutput) -> Option<Effect> {
    match &output.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(pre)) => match pre.permission_decision {
            Some(PermissionRule::Allow) => Some(Effect::Allow),
            Some(PermissionRule::Deny) => Some(Effect::Deny),
            Some(PermissionRule::Ask) => Some(Effect::Ask),
            Some(PermissionRule::Unset) | None => None,
        },
        _ => None,
    }
}

fn is_ask_decision(output: &HookOutput) -> bool {
    matches!(extract_effect(output), Some(Effect::Ask))
}

fn is_deny_decision(output: &HookOutput) -> bool {
    matches!(extract_effect(output), Some(Effect::Deny))
}

/// Convert a Claude-format HookOutput into the agent's protocol format.
fn hook_output_to_protocol(protocol: &dyn HookProtocol, output: &HookOutput) -> serde_json::Value {
    let (reason, context, updated_input) = match &output.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(pre)) => (
            pre.permission_decision_reason.as_deref(),
            pre.additional_context.as_deref(),
            pre.updated_input.clone(),
        ),
        Some(HookSpecificOutput::SessionStart(ss)) => {
            return protocol.format_session_start(ss.additional_context.as_deref());
        }
        Some(HookSpecificOutput::PostToolUse(pt)) => {
            // PostToolUse is advisory — just continue
            return protocol.format_allow(
                Some("post-tool-use"),
                pt.additional_context.as_deref(),
                None,
            );
        }
        _ => (None, None, None),
    };

    match extract_effect(output) {
        Some(Effect::Allow) => protocol.format_allow(reason, context, updated_input),
        Some(Effect::Deny) => protocol.format_deny(
            reason.unwrap_or("policy: denied"),
            context,
        ),
        Some(Effect::Ask) => protocol.format_ask(reason, context),
        None => {
            // No decision (e.g., continue_execution) — allow passthrough
            protocol.format_allow(None, None, None)
        }
    }
}
