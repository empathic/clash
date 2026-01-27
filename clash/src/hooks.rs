use std::io::{Read, Write};

use claude_settings::PermissionRule;
use serde::{Deserialize, Serialize};

/// The complete hook input received from Claude Code via stdin
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub permission_mode: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_use_id: String,
}

impl HookInput {
    /// Parse from any reader (for testability)
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Parse from stdin (convenience wrapper for production)
    pub fn from_stdin() -> anyhow::Result<Self> {
        Self::from_reader(std::io::stdin().lock())
    }

    /// Get typed tool input based on tool_name
    pub fn typed_tool_input(&self) -> ToolInput {
        match self.tool_name.as_str() {
            "Bash" => serde_json::from_value(self.tool_input.clone())
                .map(ToolInput::Bash)
                .unwrap_or_else(|_| ToolInput::Unknown(self.tool_input.clone())),
            "Write" => serde_json::from_value(self.tool_input.clone())
                .map(ToolInput::Write)
                .unwrap_or_else(|_| ToolInput::Unknown(self.tool_input.clone())),
            "Edit" => serde_json::from_value(self.tool_input.clone())
                .map(ToolInput::Edit)
                .unwrap_or_else(|_| ToolInput::Unknown(self.tool_input.clone())),
            "Read" => serde_json::from_value(self.tool_input.clone())
                .map(ToolInput::Read)
                .unwrap_or_else(|_| ToolInput::Unknown(self.tool_input.clone())),
            _ => ToolInput::Unknown(self.tool_input.clone()),
        }
    }
}

/// Tool-specific input variants
#[derive(Debug, Clone)]
pub enum ToolInput {
    Bash(BashInput),
    Write(WriteInput),
    Edit(EditInput),
    Read(ReadInput),
    Unknown(serde_json::Value),
}

#[derive(Debug, Clone, Deserialize)]
pub struct BashInput {
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub run_in_background: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WriteInput {
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EditInput {
    pub file_path: String,
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReadInput {
    pub file_path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

/// Hook-specific output for PreToolUse
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<PermissionRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// The complete hook output sent to Claude Code via stdout
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(rename = "continue")]
    pub should_continue: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<PreToolUseOutput>,
}

impl HookOutput {
    /// Create an "allow" response - bypasses permission system
    pub fn allow(reason: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(PermissionRule::Allow),
                permission_decision_reason: reason,
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    /// Create a "deny" response - prevents tool execution
    pub fn deny(reason: String) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(PermissionRule::Deny),
                permission_decision_reason: Some(reason),
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    /// Create an "ask" response - prompts user for confirmation
    pub fn ask(reason: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(PermissionRule::Ask),
                permission_decision_reason: reason,
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    /// Write response to any writer (for testability)
    pub fn write_to(&self, mut writer: impl Write) -> anyhow::Result<()> {
        serde_json::to_writer(&mut writer, self)?;
        writeln!(writer)?;
        Ok(())
    }

    /// Write response to stdout (convenience wrapper for production)
    pub fn write_stdout(&self) -> anyhow::Result<()> {
        self.write_to(std::io::stdout().lock())
    }
}

/// Exit codes for hook responses
pub mod exit_code {
    /// Success - response written to stdout
    pub const SUCCESS: i32 = 0;
    /// Blocking error - stderr message fed to Claude
    pub const BLOCKING_ERROR: i32 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hook_json() -> &'static str {
        r#"{
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status", "timeout": 120000},
            "tool_use_id": "toolu_01ABC"
        }"#
    }

    #[test]
    fn test_parse_hook_input() {
        let input = HookInput::from_reader(sample_hook_json().as_bytes()).unwrap();
        assert_eq!(input.session_id, "test-session");
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.hook_event_name, "PreToolUse");
    }

    #[test]
    fn test_typed_bash_input() {
        let input = HookInput::from_reader(sample_hook_json().as_bytes()).unwrap();
        match input.typed_tool_input() {
            ToolInput::Bash(bash) => {
                assert_eq!(bash.command, "git status");
                assert_eq!(bash.timeout, Some(120000));
            }
            other => panic!("Expected Bash input, got {:?}", other),
        }
    }

    #[test]
    fn test_typed_write_input() {
        let json = r#"{
            "session_id": "test",
            "transcript_path": "/tmp/t.jsonl",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.txt", "content": "hello world"},
            "tool_use_id": "toolu_02"
        }"#;
        let input = HookInput::from_reader(json.as_bytes()).unwrap();
        match input.typed_tool_input() {
            ToolInput::Write(write) => {
                assert_eq!(write.file_path, "/tmp/test.txt");
                assert_eq!(write.content, "hello world");
            }
            other => panic!("Expected Write input, got {:?}", other),
        }
    }

    #[test]
    fn test_output_allow() {
        let output = HookOutput::allow(Some("Safe command".into()));
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Safe command"
        );
    }

    #[test]
    fn test_output_deny() {
        let output = HookOutput::deny("Dangerous command".into());
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Dangerous command"
        );
    }

    #[test]
    fn test_output_ask() {
        let output = HookOutput::ask(None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(json["hookSpecificOutput"]["permissionDecisionReason"].is_null());
    }
}
