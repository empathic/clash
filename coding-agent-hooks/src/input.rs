//! Hook input types — normalized representations of what agents send via stdin.
//!
//! These types are deserialized from JSON and represent the agent's hook event.
//! Agent-specific protocol adapters normalize native JSON into these types via
//! the [`HookProtocol`](crate::protocol::HookProtocol) trait.

use std::io::Read;

use serde::Deserialize;
use tracing::{Level, instrument};

use crate::AgentKind;

/// The complete hook input received from an agent via stdin.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum HookInput {
    /// PreToolUse, PostToolUse, PermissionRequest events
    ToolUse(ToolUseHookInput),
    /// SessionStart events
    SessionStart(SessionStartHookInput),
}

/// Hook input for tool-related events (PreToolUse, PostToolUse, PermissionRequest).
///
/// The `tool_name` field carries the internal (Claude-style) name after protocol
/// normalization. The original agent-native name is preserved in `original_tool_name`.
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

    // -- Multi-agent fields (not deserialized from JSON, set by protocol layer) --
    /// Which agent sent this hook input.
    #[serde(skip)]
    pub agent: Option<AgentKind>,
    /// The agent's original tool name before normalization (e.g. "run_shell_command").
    /// For Claude, this is the same as `tool_name`.
    #[serde(skip)]
    pub original_tool_name: Option<String>,
}

/// Hook input for SessionStart events.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SessionStartHookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: Option<String>,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

impl SessionStartHookInput {
    /// Parse from any reader (for testability).
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
}

/// Hook input for Stop events (conversation turn ended without a tool call).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct StopHookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub hook_event_name: String,
}

impl StopHookInput {
    /// Parse from any reader (for testability).
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
}

impl HookInput {
    /// Parse from any reader (for testability).
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Parse from stdin (convenience wrapper for production).
    #[instrument(level = Level::TRACE)]
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

    /// Check if this is a tool use event.
    pub fn as_tool_use(&self) -> Option<&ToolUseHookInput> {
        match self {
            HookInput::ToolUse(input) => Some(input),
            _ => None,
        }
    }

    /// Check if this is a session start event.
    pub fn as_session_start(&self) -> Option<&SessionStartHookInput> {
        match self {
            HookInput::SessionStart(input) => Some(input),
            _ => None,
        }
    }
}

impl ToolUseHookInput {
    /// Parse from any reader (for testability).
    #[instrument(level = Level::TRACE, skip(reader))]
    pub fn from_reader(reader: impl Read) -> anyhow::Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }
}

/// Exit codes for hook responses.
pub mod exit_code {
    /// Success - response written to stdout.
    pub const SUCCESS: i32 = 0;
    /// Blocking error - stderr message fed to agent.
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
}
