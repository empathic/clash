//! GitHub Copilot CLI hook protocol implementation.
//!
//! Copilot uses "approve"/"deny" decisions.

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use super::protocol::HookProtocol;

pub struct CopilotProtocol;

impl CopilotProtocol {
    /// Normalize Copilot JSON to Claude convention for `recv_from_value`.
    fn normalize(raw: &Value) -> Value {
        let mut normalized = serde_json::Map::new();

        if let Some(obj) = raw.as_object() {
            for (k, v) in obj {
                normalized.insert(k.clone(), v.clone());
            }
        }

        // Copilot may use camelCase hook_event_name (e.g., "preToolUse")
        if let Some(name) = normalized.get("hook_event_name").and_then(|v| v.as_str()) {
            let pascal = normalize_event_name(name);
            normalized.insert("hook_event_name".into(), Value::String(pascal));
        }

        // Default transcript_path if missing
        if !normalized.contains_key("transcript_path") {
            normalized.insert("transcript_path".into(), Value::String(String::new()));
        }

        Value::Object(normalized)
    }
}

/// Normalize camelCase event names to PascalCase Claude convention.
pub(super) fn normalize_event_name(name: &str) -> String {
    match name {
        "preToolUse" => "PreToolUse".into(),
        "postToolUse" => "PostToolUse".into(),
        "sessionStart" => "SessionStart".into(),
        "stop" => "Stop".into(),
        _ => name.to_string(),
    }
}

impl HookProtocol for CopilotProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Copilot
    }

    fn parse_event(&self, raw: &Value) -> Result<clash_hooks::HookEvent> {
        Ok(clash_hooks::recv_from_value(Self::normalize(raw))?)
    }

    // Copilot uses "approve"/"deny"
    fn format_allow(
        &self,
        reason: Option<&str>,
        _context: Option<&str>,
        _updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({ "decision": "approve" });
        if let Some(r) = reason {
            output["reason"] = Value::String(r.to_string());
        }
        output
    }

    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({ "decision": "deny", "reason": reason })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        serde_json::json!({ "decision": "approve" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_hooks::ToolEvent;

    #[test]
    fn parse_event_copilot_bash() {
        let raw = serde_json::json!({
            "session_id": "cp-123",
            "cwd": "/home/user",
            "hook_event_name": "preToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "git status"}
        });
        let event = CopilotProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "bash");
    }

    #[test]
    fn format_allow_copilot() {
        assert_eq!(
            CopilotProtocol.format_allow(None, None, None)["decision"],
            "approve"
        );
    }

    #[test]
    fn format_deny_copilot() {
        assert_eq!(CopilotProtocol.format_deny("no", None)["decision"], "deny");
    }
}
