//! Hook protocol abstraction for multi-agent support.
//!
//! Each coding agent sends/receives hook JSON in a different format.
//! The [`HookProtocol`] trait encapsulates these differences so the
//! core permission logic works identically regardless of which agent
//! is calling Clash.
//!
//! Required methods: [`agent`](HookProtocol::agent) and
//! [`parse_event`](HookProtocol::parse_event). Override format methods
//! only if the agent uses a non-standard output format.

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use crate::policy_decision::PolicyDecision;

/// Abstraction over agent-specific hook JSON formats.
///
/// Each agent (Claude Code, Gemini CLI, etc.) implements this trait to handle:
/// - Parsing its native JSON stdin into typed [`clash_hooks::HookEvent`]s
/// - Formatting Clash decisions back into the agent's expected JSON output
///
/// # Adding a New Agent
///
/// Two methods are required: [`agent`](HookProtocol::agent) and
/// [`parse_event`](HookProtocol::parse_event). All other methods have
/// sensible defaults. Override them only when your agent's protocol
/// diverges from the common JSON format.
pub trait HookProtocol {
    /// Which agent this protocol handles. **Required.**
    fn agent(&self) -> AgentKind;

    /// Parse the agent's raw JSON into a typed [`clash_hooks::HookEvent`].
    ///
    /// Default: assumes the JSON is in Claude convention and delegates to
    /// [`clash_hooks::recv_from_value`]. Override for agents that need
    /// field normalization before deserialization.
    fn parse_event(&self, raw: &Value) -> Result<clash_hooks::HookEvent> {
        Ok(clash_hooks::recv_from_value(raw.clone())?)
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

    /// Format a post-tool-use response with optional advisory context.
    ///
    /// Default: delegates to `format_allow` with reason "post-tool-use".
    fn format_post_tool_use(&self, context: Option<&str>) -> Value {
        self.format_allow(Some("post-tool-use"), context, None)
    }

    /// Format a continue/passthrough response.
    ///
    /// Default: `{ "continue": true }`
    fn format_continue(&self) -> Value {
        serde_json::json!({"continue": true})
    }

    /// Format a permission request response (approve or deny on behalf of user).
    ///
    /// Default: `{ "continue": true }` (passthrough to agent's native UI).
    fn format_permission_response(
        &self,
        _behavior: &str,
        _message: Option<&str>,
        _updated_input: Option<&Value>,
        _interrupt: Option<bool>,
    ) -> Value {
        self.format_continue()
    }

    /// Format a [`PolicyDecision`] into the agent's expected JSON output.
    ///
    /// Default: dispatches to `format_allow` / `format_deny` / `format_ask`.
    fn format_decision(&self, decision: &PolicyDecision) -> Value {
        match decision {
            PolicyDecision::Allow {
                reason,
                context,
                updated_input,
            } => self.format_allow(
                Some(reason.as_str()),
                context.as_deref(),
                updated_input.clone(),
            ),
            PolicyDecision::Deny { reason, context } => {
                self.format_deny(reason, context.as_deref())
            }
            PolicyDecision::Ask { reason, context } => {
                self.format_ask(Some(reason.as_str()), context.as_deref())
            }
            PolicyDecision::Pass => self.format_ask(None, None),
        }
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
