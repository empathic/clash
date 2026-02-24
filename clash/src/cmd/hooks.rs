use anyhow::Result;
use tracing::{Level, info, instrument};

use crate::cli::HooksCmd;
use crate::hooks::{HookOutput, HookSpecificOutput, ToolUseHookInput};
use crate::permissions::check_permission;
use crate::session_policy;
use crate::settings::{ClashSettings, HookContext};

use claude_settings::PermissionRule;

impl HooksCmd {
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn run(&self) -> Result<()> {
        let output = match self {
            Self::PreToolUse => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                let settings = ClashSettings::load_or_create_with_session(Some(&input.session_id), Some(&hook_ctx))?;
                let output = check_permission(&input, &settings)?;

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

                // Check if a sandboxed Bash command failed with network errors
                // and provide a hint about sandbox network restrictions.
                let network_context = {
                    let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                    let settings =
                        ClashSettings::load_or_create_with_session(Some(&input.session_id), Some(&hook_ctx)).ok();
                    settings.and_then(|s| {
                        crate::network_hints::check_for_sandbox_network_hint(&input, &s)
                    })
                };

                // Combine contexts (session policy advice + network hints).
                let context = match (session_context, network_context) {
                    (Some(s), Some(n)) => Some(format!("{s}\n\n{n}")),
                    (Some(s), None) => Some(s),
                    (None, Some(n)) => Some(n),
                    (None, None) => None,
                };

                HookOutput::post_tool_use(context)
            }
            Self::PermissionRequest => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                let hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
                let settings = ClashSettings::load_or_create_with_session(Some(&input.session_id), Some(&hook_ctx))?;
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

fn is_ask_decision(output: &HookOutput) -> bool {
    matches!(
        &output.hook_specific_output,
        Some(HookSpecificOutput::PreToolUse(pre))
        if pre.permission_decision == Some(PermissionRule::Ask)
    )
}
