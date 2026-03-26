//! Hook protocol abstraction for multi-agent support.
//!
//! Each coding agent sends/receives hook JSON in a different format.
//! The [`HookProtocol`] trait encapsulates these differences so the
//! core permission logic works identically regardless of which agent
//! is calling Clash.

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use crate::hooks::{SessionStartHookInput, ToolUseHookInput};

/// Abstraction over agent-specific hook JSON formats.
///
/// Each agent (Claude Code, Gemini CLI, etc.) implements this trait to handle:
/// - Parsing its native JSON stdin into Clash's internal types
/// - Formatting Clash decisions back into the agent's expected JSON output
/// - Rewriting tool inputs for sandbox enforcement
pub trait HookProtocol {
    /// Which agent this protocol handles.
    fn agent(&self) -> AgentKind;

    /// Parse the agent's PreToolUse JSON into a `ToolUseHookInput`.
    ///
    /// The returned `tool_name` MUST be the internal (Claude-style) name,
    /// translated via [`super::resolve_tool_name`]. The original agent-native
    /// name is preserved in `original_tool_name`.
    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput>;

    /// Parse the agent's PostToolUse JSON into a `ToolUseHookInput`.
    fn parse_post_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput>;

    /// Parse the agent's SessionStart JSON.
    fn parse_session_start(&self, raw: &Value) -> Result<SessionStartHookInput>;

    /// Format an "allow" decision in the agent's expected output format.
    fn format_allow(
        &self,
        reason: Option<&str>,
        context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value;

    /// Format a "deny" decision in the agent's expected output format.
    fn format_deny(&self, reason: &str, context: Option<&str>) -> Value;

    /// Format an "ask" decision (fall through to agent's native prompt).
    fn format_ask(&self, reason: Option<&str>, context: Option<&str>) -> Value;

    /// Format a session-start response with optional context injection.
    fn format_session_start(&self, context: Option<&str>) -> Value;

    /// Rewrite a shell command's tool_input to run through `clash shell` for sandbox enforcement.
    ///
    /// Returns the modified tool_input JSON, or None if not applicable.
    fn rewrite_for_sandbox(
        &self,
        input: &ToolUseHookInput,
        sandbox_cmd: &str,
    ) -> Option<Value>;

    /// Context string injected into the agent's session at startup.
    fn session_context(&self) -> &str;
}

/// Construct the appropriate protocol implementation for an agent.
pub fn get_protocol(agent: AgentKind) -> Box<dyn HookProtocol> {
    match agent {
        AgentKind::Claude => Box::new(super::claude::ClaudeProtocol),
        AgentKind::Gemini => Box::new(super::gemini::GeminiProtocol),
        // Future agents will be added here as they are implemented.
        _ => Box::new(super::claude::ClaudeProtocol),
    }
}
