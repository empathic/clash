//! Amazon Q Developer CLI hook protocol implementation.
//!
//! Amazon Q uses "action": "allow"/"deny" instead of "decision".

use anyhow::Result;
use serde_json::Value;

use super::protocol::{HookProtocol, json_str};
use super::{AgentKind, resolve_tool_name};
use crate::hooks::ToolUseHookInput;

pub struct AmazonQProtocol;

impl HookProtocol for AmazonQProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::AmazonQ
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let tool_name = json_str(raw, "tool_name").to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::AmazonQ, &tool_name).to_string();

        Ok(ToolUseHookInput {
            session_id: json_str(raw, "session_id").to_string(),
            transcript_path: json_str(raw, "transcript_path").to_string(),
            cwd: json_str(raw, "cwd").to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: json_str(raw, "hook_event_name").to_string(),
            tool_name: resolved,
            tool_input: raw
                .get("tool_input")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::AmazonQ),
            original_tool_name: Some(original),
        })
    }

    // Amazon Q uses "action" instead of "decision"
    fn format_allow(
        &self,
        reason: Option<&str>,
        _context: Option<&str>,
        _updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({ "action": "allow" });
        if let Some(r) = reason {
            output["reason"] = Value::String(r.to_string());
        }
        output
    }

    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({ "action": "deny", "reason": reason })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        serde_json::json!({ "action": "allow" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_amazonq_execute_bash() {
        let raw = serde_json::json!({
            "session_id": "q-123",
            "cwd": "/home/user",
            "hook_event_name": "preToolUse",
            "tool_name": "execute_bash",
            "tool_input": {"command": "npm test"}
        });
        let input = AmazonQProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("execute_bash"));
    }

    #[test]
    fn format_deny_amazonq() {
        let out = AmazonQProtocol.format_deny("no", None);
        assert_eq!(out["action"], "deny");
    }
}
