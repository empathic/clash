use claude_settings::PermissionRule;
use tracing::{Level, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level=Level::INFO)]
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    // TODO(eliot): re-enable mac notifications
    match &settings.from_claude {
        Some(claude) => Ok(check_permission_claude(input, claude)),
        None => Ok(HookOutput::ask(Some("clash currently not configured".into()))),
    }
}

#[instrument(level=Level::INFO)]
pub fn check_permission_claude(
    input: &ToolUseHookInput,
    settings: &claude_settings::Settings,
) -> HookOutput {
    let perms = &settings.permissions;
    fn decide(tool: &str, arg: Option<&str>, perms: &claude_settings::PermissionSet) -> HookOutput {
        match perms.check(tool, arg) {
            PermissionRule::Allow => HookOutput::allow(Some("explicitly allowed".into())),
            PermissionRule::Deny => HookOutput::deny("explicitly denied".into()),
            _ => HookOutput::ask(Some("no applicable setting".into())),
        }
    }

    match input.typed_tool_input() {
        ToolInput::Bash(bash_input) => decide("Bash", Some(&bash_input.command), perms),
        ToolInput::Write(write_input) => decide("Write", Some(&write_input.file_path), perms),
        ToolInput::Edit(edit_input) => decide("Edit", Some(&edit_input.file_path), perms),
        ToolInput::Read(read_input) => decide("Read", Some(&read_input.file_path), perms),
        ToolInput::Unknown(value) => {
            warn!("value" = ?value, "Unknown tool type");
            HookOutput::ask(Some("Unknown tool type".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::ToolUseHookInput;
    use anyhow::Result;
    use serde_json::json;

    fn bash_input(command: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": command}),
            ..Default::default()
        }
    }
    fn read_input(file_path: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: json!({"file_path": file_path}),
            ..Default::default()
        }
    }

    #[test]
    fn test_allow_npm_exact() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": ["Bash(npm run test)"],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test"), &settings)?,
            HookOutput::allow(Some("explicitly allowed".into())),
        );
        Ok(())
    }
    #[test]
    fn test_allow_npm_glob() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": ["Bash(npm run test *)"],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::allow(Some("explicitly allowed".into())),
        );
        Ok(())
    }
    #[test]
    fn test_allow_empty() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": [],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::ask(Some("no applicable setting".into())),
        );
        Ok(())
    }
    #[test]
    fn test_deny_glob() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": [],
                "deny": ["Bash(*)"],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::deny("explicitly denied".into()),
        );
        Ok(())
    }
}
