//! Hook protocol abstraction for multi-agent support.
//!
//! Each coding agent sends/receives hook JSON in a different format.
//! The [`HookProtocol`] trait encapsulates these differences so the
//! core permission logic works identically regardless of which agent
//! is calling Clash.
//!
//! Most methods have default implementations that handle the common case.
//! Adding a new agent typically requires overriding only [`HookProtocol::agent`]
//! and [`HookProtocol::parse_tool_use`]. Override format methods only if
//! the agent uses a non-standard output format.

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
///
/// # Adding a New Agent
///
/// Only two methods are required: [`agent`](HookProtocol::agent) and
/// [`parse_tool_use`](HookProtocol::parse_tool_use). All other methods
/// have sensible defaults. Override them only when your agent's protocol
/// diverges from the common JSON format.
pub trait HookProtocol {
    /// Which agent this protocol handles. **Required.**
    fn agent(&self) -> AgentKind;

    /// Parse the agent's PreToolUse JSON into a `ToolUseHookInput`. **Required.**
    ///
    /// The returned `tool_name` MUST be the internal (Claude-style) name,
    /// translated via [`super::resolve_tool_name`]. The original agent-native
    /// name is preserved in `original_tool_name`.
    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput>;

    /// Parse the agent's PostToolUse JSON into a `ToolUseHookInput`.
    ///
    /// Default: delegates to `parse_tool_use`.
    fn parse_post_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        self.parse_tool_use(raw)
    }

    /// Parse the agent's SessionStart JSON.
    ///
    /// Default: extracts common fields (session_id, cwd, source, model).
    fn parse_session_start(&self, raw: &Value) -> Result<SessionStartHookInput> {
        Ok(SessionStartHookInput {
            session_id: json_str(raw, "session_id").to_string(),
            transcript_path: json_str(raw, "transcript_path").to_string(),
            cwd: json_str(raw, "cwd").to_string(),
            permission_mode: raw.get("permission_mode").and_then(|v| v.as_str()).map(String::from),
            hook_event_name: json_str_or(raw, "hook_event_name", "SessionStart").to_string(),
            source: raw.get("source").and_then(|v| v.as_str()).map(String::from),
            model: raw.get("model").and_then(|v| v.as_str()).map(String::from),
        })
    }

    /// Format an "allow" decision in the agent's expected output format.
    ///
    /// Default: `{ "decision": "allow", "reason": "..." }`
    fn format_allow(
        &self,
        reason: Option<&str>,
        _context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({ "decision": "allow" });
        if let Some(r) = reason {
            output["reason"] = Value::String(r.to_string());
        }
        if let Some(ui) = updated_input {
            output["updated_input"] = ui;
        }
        output
    }

    /// Format a "deny" decision in the agent's expected output format.
    ///
    /// Default: `{ "decision": "deny", "reason": "..." }`
    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({
            "decision": "deny",
            "reason": reason
        })
    }

    /// Format an "ask" decision (fall through to agent's native prompt).
    ///
    /// Default: `{ "continue": true }` (passthrough to agent's native UI).
    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        serde_json::json!({ "continue": true })
    }

    /// Format a session-start response with optional context injection.
    ///
    /// Default: `{ "decision": "allow", "additional_context": "..." }`
    fn format_session_start(&self, context: Option<&str>) -> Value {
        let mut output = serde_json::json!({ "decision": "allow" });
        if let Some(ctx) = context {
            output["additional_context"] = Value::String(ctx.to_string());
        }
        output
    }

    /// Rewrite a shell command's tool_input to run through `clash shell`.
    ///
    /// Default: rewrites the `command` field for tools with internal name "Bash".
    fn rewrite_for_sandbox(
        &self,
        input: &ToolUseHookInput,
        sandbox_cmd: &str,
    ) -> Option<Value> {
        if input.tool_name != "Bash" {
            return None;
        }
        let command = input.tool_input.get("command")?.as_str()?;
        let sandboxed = format!(
            "{} shell --cwd {} -c {}",
            shell_escape(sandbox_cmd),
            shell_escape(&input.cwd),
            shell_escape(command),
        );
        let mut updated = input.tool_input.clone();
        updated.as_object_mut()?.insert("command".into(), Value::String(sandboxed));
        Some(updated)
    }

    /// Context string injected into the agent's session at startup.
    ///
    /// Default: standard Clash session context.
    fn session_context(&self) -> &str {
        "Clash is active and enforcing policy on this session.\n\
         Run `clash commands` to see the full command hierarchy for managing policies, sandboxes, and debugging."
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a string field from JSON, returning "" if missing.
pub(crate) fn json_str<'a>(raw: &'a Value, field: &str) -> &'a str {
    raw.get(field).and_then(|v| v.as_str()).unwrap_or("")
}

/// Extract a string field from JSON with a default value.
pub(crate) fn json_str_or<'a>(raw: &'a Value, field: &str, default: &'a str) -> &'a str {
    raw.get(field).and_then(|v| v.as_str()).unwrap_or(default)
}

/// Extract a string from one of several possible field names.
pub(crate) fn json_str_any<'a>(raw: &'a Value, fields: &[&str]) -> &'a str {
    for field in fields {
        if let Some(s) = raw.get(*field).and_then(|v| v.as_str()) {
            return s;
        }
    }
    ""
}

/// Extract an optional Value from one of several possible field names.
pub(crate) fn json_value_any(raw: &Value, fields: &[&str]) -> Option<Value> {
    for field in fields {
        if let Some(v) = raw.get(*field) {
            return Some(v.clone());
        }
    }
    None
}

pub(crate) fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Construct the appropriate protocol implementation for an agent.
pub fn get_protocol(agent: AgentKind) -> Box<dyn HookProtocol> {
    match agent {
        AgentKind::Claude => Box::new(super::claude::ClaudeProtocol),
        AgentKind::Gemini => Box::new(super::gemini::GeminiProtocol),
        AgentKind::Codex => Box::new(super::codex::CodexProtocol),
        AgentKind::AmazonQ => Box::new(super::amazonq::AmazonQProtocol),
        AgentKind::OpenCode => Box::new(super::opencode::OpenCodeProtocol),
        AgentKind::Copilot => Box::new(super::copilot::CopilotProtocol),
    }
}
