//! Amazon Q Developer CLI hook protocol implementation.
//!
//! Amazon Q uses "action": "allow"/"deny" instead of "decision".

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use super::protocol::HookProtocol;

pub struct AmazonQProtocol;

impl AmazonQProtocol {
    /// Normalize Amazon Q JSON to Claude convention for `recv_from_value`.
    fn normalize(raw: &Value) -> Value {
        let mut normalized = serde_json::Map::new();

        if let Some(obj) = raw.as_object() {
            for (k, v) in obj {
                normalized.insert(k.clone(), v.clone());
            }
        }

        // Amazon Q may use camelCase hook_event_name
        if let Some(name) = normalized.get("hook_event_name").and_then(|v| v.as_str()) {
            let pascal = super::copilot::normalize_event_name(name);
            normalized.insert("hook_event_name".into(), Value::String(pascal));
        }

        // Default transcript_path if missing
        if !normalized.contains_key("transcript_path") {
            normalized.insert("transcript_path".into(), Value::String(String::new()));
        }

        Value::Object(normalized)
    }
}

impl HookProtocol for AmazonQProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::AmazonQ
    }

    fn parse_event(&self, raw: &Value) -> Result<clash_hooks::HookEvent> {
        Ok(clash_hooks::recv_from_value(Self::normalize(raw))?)
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
    use clash_hooks::ToolEvent;

    #[test]
    fn parse_event_amazonq_execute_bash() {
        let raw = serde_json::json!({
            "session_id": "q-123",
            "cwd": "/home/user",
            "hook_event_name": "preToolUse",
            "tool_name": "execute_bash",
            "tool_input": {"command": "npm test"}
        });
        let event = AmazonQProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "execute_bash");
    }

    #[test]
    fn format_deny_amazonq() {
        let out = AmazonQProtocol.format_deny("no", None);
        assert_eq!(out["action"], "deny");
    }
}
