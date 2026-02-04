use std::io::{Read, Write};

use claude_settings::PermissionRule;
use serde::{Deserialize, Serialize};
use tracing::{Level, instrument};

/// The complete hook input received from Claude Code via stdin
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HookInput {
    /// PreToolUse, PostToolUse, PermissionRequest events
    ToolUse(ToolUseHookInput),
    /// SessionStart events
    SessionStart(SessionStartHookInput),
}

/// Hook input for tool-related events (PreToolUse, PostToolUse, PermissionRequest)
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ToolUseHookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub permission_mode: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub tool_use_id: Option<String>,
    /// Present in PostToolUse events
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
}

/// Hook input for SessionStart events
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SessionStartHookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: Option<String>,
    pub hook_event_name: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

impl SessionStartHookInput {
    /// Parse from any reader (for testability)
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
}

impl HookInput {
    /// Parse from any reader (for testability)
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Parse from stdin (convenience wrapper for production)
    #[instrument(level = Level::TRACE)]
    pub fn from_stdin() -> anyhow::Result<Self> {
        Self::from_reader(std::io::stdin().lock())
    }

    /// Get the hook event name
    pub fn hook_event_name(&self) -> &str {
        match self {
            HookInput::ToolUse(input) => &input.hook_event_name,
            HookInput::SessionStart(input) => &input.hook_event_name,
        }
    }

    /// Get the session ID
    pub fn session_id(&self) -> &str {
        match self {
            HookInput::ToolUse(input) => &input.session_id,
            HookInput::SessionStart(input) => &input.session_id,
        }
    }

    /// Check if this is a tool use event
    pub fn as_tool_use(&self) -> Option<&ToolUseHookInput> {
        match self {
            HookInput::ToolUse(input) => Some(input),
            _ => None,
        }
    }

    /// Check if this is a session start event
    pub fn as_session_start(&self) -> Option<&SessionStartHookInput> {
        match self {
            HookInput::SessionStart(input) => Some(input),
            _ => None,
        }
    }
}

impl ToolUseHookInput {
    /// Parse from any reader (for testability)
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Get typed tool input based on tool_name
    #[instrument(level = Level::TRACE, skip(self))]
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
#[derive(Debug, Clone, Serialize, PartialEq)]
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

/// Decision behavior for PermissionRequest responses
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PermissionBehavior {
    Allow,
    Deny,
}

/// Decision structure for PermissionRequest responses
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDecision {
    pub behavior: PermissionBehavior,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interrupt: Option<bool>,
}

/// Hook-specific output for PermissionRequest
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestOutput {
    pub hook_event_name: &'static str,
    pub decision: PermissionDecision,
}

/// Hook-specific output for SessionStart
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output variants
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum HookSpecificOutput {
    PreToolUse(PreToolUseOutput),
    PermissionRequest(PermissionRequestOutput),
    SessionStart(SessionStartOutput),
}

/// The complete hook output sent to Claude Code via stdout
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(rename = "continue")]
    pub should_continue: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

impl HookOutput {
    /// Create an "allow" response for PreToolUse - bypasses permission system.
    #[instrument(level = Level::TRACE)]
    pub fn allow(reason: Option<String>, context: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PreToolUse(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(PermissionRule::Allow),
                permission_decision_reason: reason,
                updated_input: None,
                additional_context: context,
            })),
        }
    }

    /// Create a "deny" response for PreToolUse - prevents tool execution.
    #[instrument(level = Level::TRACE)]
    pub fn deny(reason: String, context: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PreToolUse(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(PermissionRule::Deny),
                permission_decision_reason: Some(reason),
                updated_input: None,
                additional_context: context,
            })),
        }
    }

    /// Create an "ask" response for PreToolUse - prompts user for confirmation.
    #[instrument(level = Level::TRACE)]
    pub fn ask(reason: Option<String>, context: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PreToolUse(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(PermissionRule::Ask),
                permission_decision_reason: reason,
                updated_input: None,
                additional_context: context,
            })),
        }
    }

    /// Approve a permission request on behalf of the user
    #[instrument(level = Level::TRACE)]
    pub fn approve_permission(updated_input: Option<serde_json::Value>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PermissionRequest(
                PermissionRequestOutput {
                    hook_event_name: "PermissionRequest",
                    decision: PermissionDecision {
                        behavior: PermissionBehavior::Allow,
                        updated_input,
                        message: None,
                        interrupt: None,
                    },
                },
            )),
        }
    }

    /// Deny a permission request on behalf of the user
    #[instrument(level = Level::TRACE)]
    pub fn deny_permission(message: String, interrupt: bool) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PermissionRequest(
                PermissionRequestOutput {
                    hook_event_name: "PermissionRequest",
                    decision: PermissionDecision {
                        behavior: PermissionBehavior::Deny,
                        updated_input: None,
                        message: Some(message),
                        interrupt: Some(interrupt),
                    },
                },
            )),
        }
    }

    /// Set the updated_input field on a PreToolUse response.
    /// This rewrites the tool input before Claude Code executes it.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_updated_input(&mut self, updated_input: serde_json::Value) {
        if let Some(HookSpecificOutput::PreToolUse(ref mut pre)) = self.hook_specific_output {
            pre.updated_input = Some(updated_input);
        }
    }

    /// Create a SessionStart response with optional context about the session setup.
    #[instrument(level = Level::TRACE)]
    pub fn session_start(additional_context: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::SessionStart(SessionStartOutput {
                hook_event_name: "SessionStart",
                additional_context,
            })),
        }
    }

    /// Continue execution without making a decision (for informational hooks)
    #[instrument(level = Level::TRACE)]
    pub fn continue_execution() -> Self {
        Self {
            should_continue: true,
            hook_specific_output: None,
        }
    }

    /// Write response to any writer (for testability)
    #[instrument(level = Level::TRACE, skip(self, writer))]
    pub fn write_to(&self, mut writer: impl Write) -> anyhow::Result<()> {
        serde_json::to_writer(&mut writer, self)?;
        writeln!(writer)?;
        Ok(())
    }

    /// Write response to stdout (convenience wrapper for production)
    #[instrument(level = Level::TRACE, skip(self))]
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

    fn sample_tool_use_json() -> &'static str {
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
    fn test_parse_tool_use_input() {
        let input = HookInput::from_reader(sample_tool_use_json().as_bytes()).unwrap();
        assert_eq!(input.session_id(), "test-session");
        assert_eq!(input.hook_event_name(), "PreToolUse");

        let tool_use = input.as_tool_use().expect("Should be ToolUse variant");
        assert_eq!(tool_use.tool_name, "Bash");
    }

    #[test]
    fn test_typed_bash_input() {
        let input = ToolUseHookInput::from_reader(sample_tool_use_json().as_bytes()).unwrap();
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
        let input = ToolUseHookInput::from_reader(json.as_bytes()).unwrap();
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
        let output = HookOutput::allow(Some("Safe command".into()), None);
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
        let output = HookOutput::deny("Dangerous command".into(), None);
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
        let output = HookOutput::ask(None, None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(json["hookSpecificOutput"]["permissionDecisionReason"].is_null());
    }

    #[test]
    fn test_approve_permission() {
        let output = HookOutput::approve_permission(None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");
        assert!(json["hookSpecificOutput"]["decision"]["updatedInput"].is_null());
    }

    #[test]
    fn test_approve_permission_with_updated_input() {
        let updated = serde_json::json!({"command": "ls -la"});
        let output = HookOutput::approve_permission(Some(updated.clone()));
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["decision"]["updatedInput"],
            updated
        );
    }

    #[test]
    fn test_deny_permission() {
        let output = HookOutput::deny_permission("Not allowed".into(), true);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["decision"]["message"],
            "Not allowed"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["interrupt"], true);
    }

    #[test]
    fn test_deny_permission_no_interrupt() {
        let output = HookOutput::deny_permission("Try again".into(), false);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(json["hookSpecificOutput"]["decision"]["interrupt"], false);
    }
}
