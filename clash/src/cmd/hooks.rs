use anyhow::Result;
use tracing::{Level, info, instrument};

use crate::cli::HooksCmd;
use crate::hooks::{HookOutput, HookSpecificOutput, ToolUseHookInput, is_interactive_tool};
use crate::permissions::check_permission;
use crate::policy::Effect;
use crate::session_policy;
use crate::settings::{ClashSettings, HookContext};

use claude_settings::PermissionRule;

impl HooksCmd {
    /// Handle hook when clash is disabled — drain stdin and return pass-through.
    fn run_disabled(&self) -> Result<()> {
        info!("Clash is disabled (CLASH_DISABLE), returning pass-through");
        let output = match self {
            Self::SessionStart => {
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
        output.write_stdout()?;
        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(self))]
    pub fn run(&self) -> Result<()> {
        if crate::settings::is_disabled() {
            return self.run_disabled();
        }

        let output = match self {
            Self::PreToolUse => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                let settings = ClashSettings::load_or_create_with_session(
                    Some(&input.session_id),
                    Some(&hook_ctx),
                )?;
                let output = check_permission(&input, &settings)?;

                // Interactive tools (e.g., AskUserQuestion) require user input
                // via Claude Code's native UI. Returning "allow" would skip that
                // UI entirely, so we pass through for any non-deny decision.
                if is_interactive_tool(&input.tool_name) && !is_deny_decision(&output) {
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

                    output
                }
            }
            Self::PostToolUse => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;

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
                    let fs = settings.as_ref().and_then(|s| {
                        crate::sandbox_fs_hints::check_for_sandbox_fs_hint(&input, s)
                    });
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

                HookOutput::post_tool_use(context)
            }
            Self::PermissionRequest => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                let settings = ClashSettings::load_or_create_with_session(
                    Some(&input.session_id),
                    Some(&hook_ctx),
                )?;
                crate::handlers::handle_permission_request(&input, &settings)?
            }
            Self::SessionStart => {
                let input =
                    crate::hooks::SessionStartHookInput::from_reader(std::io::stdin().lock())?;
                crate::handlers::handle_session_start(&input)?
            }
        };

        output.write_stdout()?;
        Ok(())
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
