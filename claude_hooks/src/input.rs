//! Hook input types deserialized from Claude Code via stdin.
//!
//! When Claude Code fires a hook, it sends a JSON payload to the hook process's
//! stdin. The types in this module represent those payloads.

use std::io::Read;

use serde::Deserialize;

use crate::tools;

/// The complete hook input received from Claude Code via stdin.
///
/// Uses `#[serde(untagged)]` — deserialization tries `ToolUse` first (which
/// requires `tool_name`), then falls back to `SessionStart`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HookInput {
    /// PreToolUse, PostToolUse, PermissionRequest events.
    ToolUse(ToolUseHookInput),
    /// SessionStart events.
    SessionStart(SessionStartHookInput),
}

/// Hook input for tool-related events (PreToolUse, PostToolUse, PermissionRequest).
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
    /// Present in PostToolUse events.
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
}

/// Hook input for SessionStart events.
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

/// Hook input for Stop events (conversation turn ended without a tool call).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct StopHookInput {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    pub hook_event_name: String,
}

impl HookInput {
    /// Parse from any reader (for testability).
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Parse from stdin (convenience wrapper for production).
    pub fn from_stdin() -> anyhow::Result<Self> {
        Self::from_reader(std::io::stdin().lock())
    }

    /// Get the hook event name.
    pub fn hook_event_name(&self) -> &str {
        match self {
            HookInput::ToolUse(input) => &input.hook_event_name,
            HookInput::SessionStart(input) => &input.hook_event_name,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        match self {
            HookInput::ToolUse(input) => &input.session_id,
            HookInput::SessionStart(input) => &input.session_id,
        }
    }

    /// Get the inner `ToolUseHookInput` if this is a tool use event.
    pub fn as_tool_use(&self) -> Option<&ToolUseHookInput> {
        match self {
            HookInput::ToolUse(input) => Some(input),
            _ => None,
        }
    }

    /// Get the inner `SessionStartHookInput` if this is a session start event.
    pub fn as_session_start(&self) -> Option<&SessionStartHookInput> {
        match self {
            HookInput::SessionStart(input) => Some(input),
            _ => None,
        }
    }
}

impl ToolUseHookInput {
    /// Parse from any reader (for testability).
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Get typed tool input based on `tool_name`.
    ///
    /// Delegates to [`tools::ToolInput::parse`] for the canonical
    /// tool-name → typed-struct mapping.
    pub fn typed_tool_input(&self) -> tools::ToolInput {
        tools::ToolInput::parse(&self.tool_name, self.tool_input.clone())
    }
}

impl SessionStartHookInput {
    /// Parse from any reader (for testability).
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
}

impl StopHookInput {
    /// Parse from any reader (for testability).
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
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
            tools::ToolInput::Bash(bash) => {
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
            tools::ToolInput::Write(write) => {
                assert_eq!(write.file_path, "/tmp/test.txt");
                assert_eq!(write.content, "hello world");
            }
            other => panic!("Expected Write input, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_session_start() {
        let json = r#"{
            "session_id": "sess-123",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-opus-4-5-20251101"
        }"#;
        let input = HookInput::from_reader(json.as_bytes()).unwrap();
        assert_eq!(input.hook_event_name(), "SessionStart");
        let session = input.as_session_start().expect("Should be SessionStart");
        assert_eq!(session.source.as_deref(), Some("startup"));
        assert_eq!(session.model.as_deref(), Some("claude-opus-4-5-20251101"));
    }

    #[test]
    fn test_parse_stop_input() {
        let json = r#"{
            "session_id": "sess-123",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user",
            "hook_event_name": "Stop"
        }"#;
        let input = StopHookInput::from_reader(json.as_bytes()).unwrap();
        assert_eq!(input.session_id, "sess-123");
        assert_eq!(input.hook_event_name, "Stop");
    }
}
