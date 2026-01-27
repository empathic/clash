use crate::hooks::{HookInput, ToolInput};
use claude_settings::{PermissionRule, Settings};

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
pub fn check_permission(input: &HookInput, settings: &Settings) -> anyhow::Result<PermissionRule> {
    let tool_input = input.typed_tool_input();
    match tool_input {
        ToolInput::Bash(bash) => Ok(check_bash_permission(&bash.command, settings)),
        ToolInput::Write(write) => Ok(settings.permissions.check("Write", Some(&write.file_path))),
        ToolInput::Edit(edit) => Ok(settings.permissions.check("Edit", Some(&edit.file_path))),
        ToolInput::Read(read) => Ok(settings.permissions.check("Read", Some(&read.file_path))),
        ToolInput::Unknown(_) => Ok(PermissionRule::Ask),
    }
}

fn check_bash_permission(command: &str, settings: &Settings) -> PermissionRule {
    settings.permissions.check("Bash", Some(command))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookInput;
    use claude_settings::PermissionSet;

    fn make_bash_input(command: &str) -> HookInput {
        let json = format!(
            r#"{{
                "session_id": "test",
                "transcript_path": "/tmp/t.jsonl",
                "cwd": "/tmp",
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {{"command": "{}"}},
                "tool_use_id": "t1"
            }}"#,
            command
        );
        HookInput::from_reader(json.as_bytes()).unwrap()
    }

    fn make_read_input(file_path: &str) -> HookInput {
        let json = format!(
            r#"{{
                "session_id": "test",
                "transcript_path": "/tmp/t.jsonl",
                "cwd": "/tmp",
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {{"file_path": "{}"}},
                "tool_use_id": "t1"
            }}"#,
            file_path
        );
        HookInput::from_reader(json.as_bytes()).unwrap()
    }

    #[test]
    fn test_bash_unset_by_default() {
        let input = make_bash_input("git status");
        let decision = check_permission(&input, &Settings::new()).unwrap();
        assert_eq!(decision, PermissionRule::Unset);
    }

    #[test]
    fn test_bash_allowed_by_permission() {
        let input = make_bash_input("git status");
        let settings = Settings::new().with_permissions(PermissionSet::new().allow("Bash(git:*)"));
        let decision = check_permission(&input, &settings).unwrap();
        assert_eq!(decision, PermissionRule::Allow);
    }

    #[test]
    fn test_read_unset_by_default() {
        let input = make_read_input("/tmp/test.txt");
        let decision = check_permission(&input, &Settings::new()).unwrap();
        assert_eq!(decision, PermissionRule::Unset);
    }

    #[test]
    fn test_read_allowed_by_permission() {
        let input = make_read_input("/tmp/test.txt");
        let settings = Settings::new().with_permissions(PermissionSet::new().allow("Read"));
        let decision = check_permission(&input, &settings).unwrap();
        assert_eq!(decision, PermissionRule::Allow);
    }
}
