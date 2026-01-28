use claude_settings::PermissionRule;

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    // let tool_input = input.typed_tool_input();
    Ok(HookOutput::ask(Some(format!("{:?}", settings))))
    // match tool_input {
    //     ToolInput::Bash(bash_input) => HookOutput::allow(Some("yolo")),
    //     ToolInput::Write(write_input) => todo!(),
    //     ToolInput::Edit(edit_input) => todo!(),
    //     ToolInput::Read(read_input) => todo!(),
    //     ToolInput::Unknown(value) => todo!(),
    // }
}

// TODO: Re-enable tests when permission checking is fully implemented
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::hooks::ToolUseHookInput;
//     use claude_settings::PermissionSet;
//
//     fn make_bash_input(command: &str) -> ToolUseHookInput { ... }
//     fn make_read_input(file_path: &str) -> ToolUseHookInput { ... }
//
//     #[test]
//     fn test_bash_unset_by_default() { ... }
//     ...
// }
