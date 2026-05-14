use std::io::Write;

use anyhow::{Context, Result};
use tracing::{Level, info, instrument};

use crate::agents::AgentKind;
use crate::agents::protocol::{HookProtocol, get_protocol};
use crate::cli::{HookCmd, HookSubcommand};
use crate::hooks::{HookOutput, HookSpecificOutput, ToolUseHookInput, is_interactive_tool};
use crate::permissions::check_permission;
use crate::session_policy;
use crate::settings::{ClashSettings, HookContext};
use crate::trace;

// Re-import the hook Effect (from coding-agent-hooks) and the policy Effect.
use coding_agent_hooks::output::Effect as HookEffect;

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

    #[instrument(level = Level::TRACE, skip(self), fields(agent = %self.agent))]
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
                    let env = crate::env::Env::prod();
                    if let Err(e) = env.session.sync_trace(&input.session_id, None) {
                        tracing::warn!(error = %e, "Failed to sync trace (PreToolUse/passthrough)");
                    }
                    HookOutput::continue_execution()
                } else {
                    let env = crate::env::Env::prod();
                    let mut hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    if let Some(agent) = input.agent {
                        hook_ctx = hook_ctx.with_agent(agent);
                    }
                    let settings = env.policy.load_settings(&input.session_id, &hook_ctx)?;
                    let output = check_permission(&input, &settings)?;

                    if is_interactive_tool(&input.tool_name)
                        && !is_deny_decision(&output)
                        && is_ask_decision(&output)
                    {
                        info!(tool = %input.tool_name, "Passthrough: interactive tool deferred to Claude Code");
                        HookOutput::continue_execution()
                    } else {
                        if let Some(effect) = hook_effect_to_policy(output.effect()) {
                            env.session.update_session_stats(
                                &input.session_id,
                                &input.tool_name,
                                &input.tool_input,
                                effect,
                                &input.cwd,
                            );
                        }

                        if is_ask_decision(&output)
                            && let Some(ref tool_use_id) = input.tool_use_id
                        {
                            env.session.record_pending_ask(
                                &input.session_id,
                                tool_use_id,
                                &input.tool_name,
                                &input.tool_input,
                                &input.cwd,
                            );
                        }

                        let decision = input.tool_use_id.as_ref().and_then(|id| {
                            let effect = hook_effect_to_policy(output.effect())?;
                            Some(trace::PolicyDecision {
                                tool_use_id: id.clone(),
                                tool_name: Some(input.tool_name.clone()),
                                effect,
                                reason: None,
                            })
                        });
                        if let Err(e) = env.session.sync_trace(&input.session_id, decision) {
                            tracing::warn!(error = %e, "Failed to sync trace (PreToolUse)");
                        }

                        output
                    }
                }
            }
            HookSubcommand::PostToolUse => {
                let input = self
                    .parse_tool_use_input()
                    .context("parsing PostToolUse hook input from stdin")?;
                let env = crate::env::Env::prod();

                let session_context = input.tool_use_id.as_deref().and_then(|tool_use_id| {
                    let advice = env.session.consume_pending_ask(
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

                let (network_context, fs_context) = {
                    let mut hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    if let Some(agent) = input.agent {
                        hook_ctx = hook_ctx.with_agent(agent);
                    }
                    let settings = env.policy.load_settings(&input.session_id, &hook_ctx).ok();
                    let net = settings.as_ref().and_then(|s| {
                        crate::network_hints::check_for_sandbox_network_hint(&input, s)
                    });
                    let fs = settings
                        .as_ref()
                        .and_then(|s| crate::sandbox_hints::check_for_sandbox_fs_hint(&input, s));
                    (net, fs)
                };

                let context = [session_context, network_context, fs_context]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let context = if context.is_empty() {
                    None
                } else {
                    Some(context.join("\n\n"))
                };

                if let Err(e) = env.session.sync_trace(&input.session_id, None) {
                    tracing::warn!(error = %e, "Failed to sync trace (PostToolUse)");
                }

                HookOutput::post_tool_use(context)
            }
            HookSubcommand::PermissionRequest => {
                let input = self
                    .parse_tool_use_input()
                    .context("parsing PermissionRequest hook input from stdin")?;
                if passthrough {
                    info!(
                        tool = %input.tool_name,
                        "CLASH_PASSTHROUGH: deferring permission request to native UI"
                    );
                    HookOutput::continue_execution()
                } else {
                    let mut hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    if let Some(agent) = input.agent {
                        hook_ctx = hook_ctx.with_agent(agent);
                    }
                    let settings = ClashSettings::load_or_create_with_session(
                        Some(&input.session_id),
                        Some(&hook_ctx),
                    )?;
                    crate::handlers::handle_permission_request(&input, &settings)?
                }
            }
            HookSubcommand::SessionStart => {
                let mut input = self
                    .parse_session_start_input()
                    .context("parsing SessionStart hook input from stdin")?;
                if input.session_id.is_empty() {
                    input.session_id = fallback_session_id(self.agent);
                    info!(session_id = %input.session_id, "Agent did not provide session_id, using fallback");
                }
                let env = crate::env::Env::prod();
                crate::handlers::handle_session_start(&env, &input, Some(self.agent))?
            }
            HookSubcommand::Stop => {
                let mut input = self
                    .parse_stop_input()
                    .context("parsing Stop hook input from stdin")?;
                if input.session_id.is_empty() {
                    input.session_id = fallback_session_id(self.agent);
                    info!(session_id = %input.session_id, "Agent did not provide session_id, using fallback");
                }

                // Final catch-up sync for non-tool conversation turns.
                let env = crate::env::Env::prod();
                if let Err(e) = env.session.sync_trace(&input.session_id, None) {
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

    /// Read stdin as raw JSON, then delegate to the agent's protocol.
    fn read_stdin_json(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_reader(std::io::stdin().lock())?)
    }

    /// Parse tool-use input from stdin via the agent's protocol.
    fn parse_tool_use_input(&self) -> Result<ToolUseHookInput> {
        let protocol = get_protocol(self.agent);
        let raw = self.read_stdin_json()?;
        let mut input = protocol.parse_tool_use(&raw)?;
        if input.session_id.is_empty() {
            input.session_id = fallback_session_id(self.agent);
            info!(session_id = %input.session_id, "Agent did not provide session_id, using fallback");
        }
        Ok(input)
    }

    /// Parse session-start input from stdin via the agent's protocol.
    fn parse_session_start_input(&self) -> Result<crate::hooks::SessionStartHookInput> {
        let protocol = get_protocol(self.agent);
        let raw = self.read_stdin_json()?;
        protocol.parse_session_start(&raw)
    }

    /// Parse stop input from stdin via the agent's protocol.
    fn parse_stop_input(&self) -> Result<crate::hooks::StopHookInput> {
        let protocol = get_protocol(self.agent);
        let raw = self.read_stdin_json()?;
        protocol.parse_stop(&raw)
    }
}

/// Convert a hook-level Effect to a policy-level Effect.
fn hook_effect_to_policy(effect: Option<HookEffect>) -> Option<crate::policy::Effect> {
    match effect {
        Some(HookEffect::Allow) => Some(crate::policy::Effect::Allow),
        Some(HookEffect::Deny) => Some(crate::policy::Effect::Deny),
        Some(HookEffect::Ask) => Some(crate::policy::Effect::Ask),
        None => None,
    }
}

fn is_ask_decision(output: &HookOutput) -> bool {
    matches!(output.effect(), Some(HookEffect::Ask))
}

fn is_deny_decision(output: &HookOutput) -> bool {
    matches!(output.effect(), Some(HookEffect::Deny))
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

    match output.effect() {
        Some(HookEffect::Allow) => protocol.format_allow(reason, context, updated_input),
        Some(HookEffect::Deny) => protocol.format_deny(reason.unwrap_or("policy: denied"), context),
        Some(HookEffect::Ask) => protocol.format_ask(reason, context),
        None => {
            // No decision (e.g., continue_execution) — allow passthrough
            protocol.format_allow(None, None, None)
        }
    }
}
