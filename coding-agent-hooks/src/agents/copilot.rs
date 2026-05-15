//! GitHub Copilot CLI hook protocol implementation.
//!
//! Copilot CLI uses `permissionDecision` with values "allow"/"deny"/"ask",
//! matching the same protocol as Claude Code hooks.

use anyhow::Result;
use serde_json::Value;

use super::{AgentKind, resolve_tool_name};
use crate::input::ToolUseHookInput;
use crate::protocol::{HookProtocol, json_str_any, json_value_any};

pub struct CopilotProtocol;

impl HookProtocol for CopilotProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Copilot
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        // Copilot CLI sends camelCase fields (toolName, sessionId, toolArgs)
        // while Claude Code sends snake_case (tool_name, session_id, tool_input).
        // Accept both forms for robustness.
        let tool_name = json_str_any(raw, &["toolName", "tool_name"]).to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::Copilot, &tool_name).to_string();

        // Copilot sends toolArgs as a JSON string; parse it into a Value.
        let tool_input = json_value_any(raw, &["tool_input", "toolArgs"])
            .and_then(|v| match v {
                Value::String(s) => serde_json::from_str(&s).ok(),
                other => Some(other),
            })
            .unwrap_or(Value::Object(serde_json::Map::new()));

        Ok(ToolUseHookInput {
            session_id: json_str_any(raw, &["sessionId", "session_id"]).to_string(),
            transcript_path: json_str_any(raw, &["transcript_path"]).to_string(),
            cwd: json_str_any(raw, &["cwd"]).to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: json_str_any(raw, &["hook_event_name"]).to_string(),
            tool_name: resolved,
            tool_input,
            tool_use_id: raw
                .get("toolCallId")
                .and_then(|v| v.as_str())
                .map(String::from),
            tool_response: json_value_any(raw, &["tool_response", "toolResponse"]),
            agent: Some(AgentKind::Copilot),
            original_tool_name: Some(original),
        })
    }

    // Copilot CLI uses the same permissionDecision protocol as Claude Code.
    fn format_allow(
        &self,
        reason: Option<&str>,
        _context: Option<&str>,
        _updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({ "permissionDecision": "allow" });
        if let Some(r) = reason {
            output["permissionDecisionReason"] = Value::String(r.to_string());
        }
        output
    }

    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        })
    }

    fn format_ask(&self, reason: Option<&str>, _context: Option<&str>) -> Value {
        let mut output = serde_json::json!({ "permissionDecision": "ask" });
        if let Some(r) = reason {
            output["permissionDecisionReason"] = Value::String(r.to_string());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_copilot_bash_snake_case() {
        let raw = serde_json::json!({
            "session_id": "cp-123",
            "cwd": "/home/user",
            "hook_event_name": "preToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "git status"}
        });
        let input = CopilotProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.session_id, "cp-123");
    }

    #[test]
    fn parse_copilot_bash_camel_case() {
        let raw = serde_json::json!({
            "sessionId": "cp-456",
            "cwd": "/home/user",
            "toolName": "bash",
            "toolArgs": "{\"command\":\"echo hello\"}"
        });
        let input = CopilotProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.session_id, "cp-456");
        // toolArgs is a JSON string that should be parsed into tool_input
        assert_eq!(input.tool_input["command"], "echo hello");
    }

    #[test]
    fn format_allow_copilot() {
        let out = CopilotProtocol.format_allow(None, None, None);
        assert_eq!(out["permissionDecision"], "allow");
    }

    #[test]
    fn format_deny_copilot() {
        let out = CopilotProtocol.format_deny("blocked", None);
        assert_eq!(out["permissionDecision"], "deny");
        assert_eq!(out["permissionDecisionReason"], "blocked");
    }

    #[test]
    fn format_ask_copilot() {
        let out = CopilotProtocol.format_ask(Some("needs approval"), None);
        assert_eq!(out["permissionDecision"], "ask");
        assert_eq!(out["permissionDecisionReason"], "needs approval");
    }
}
