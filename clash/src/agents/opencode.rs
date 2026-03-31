//! OpenCode hook protocol implementation.
//!
//! OpenCode uses a JS plugin API; the extension wrapper translates to
//! JSON stdin/stdout calls. Field names differ (tool, args, sessionID, directory).

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use super::protocol::{HookProtocol, json_str_any, json_value_any};

pub struct OpenCodeProtocol;

impl OpenCodeProtocol {
    /// Normalize OpenCode JSON to Claude convention for `recv_from_value`.
    fn normalize(raw: &Value) -> Value {
        let mut normalized = serde_json::Map::new();

        // Map OpenCode field names to Claude convention
        let session_id = json_str_any(raw, &["session_id", "sessionID"]);
        normalized.insert("session_id".into(), Value::String(session_id.to_string()));

        normalized.insert("transcript_path".into(), Value::String(String::new()));

        let cwd = json_str_any(raw, &["cwd", "directory"]);
        normalized.insert("cwd".into(), Value::String(cwd.to_string()));

        let event_name = json_str_any(raw, &["hook_event_name", "event"]);
        let pascal = super::copilot::normalize_event_name(event_name);
        normalized.insert("hook_event_name".into(), Value::String(pascal));

        let tool_name = json_str_any(raw, &["tool_name", "tool"]);
        if !tool_name.is_empty() {
            normalized.insert("tool_name".into(), Value::String(tool_name.to_string()));
        }

        if let Some(ti) = json_value_any(raw, &["tool_input", "args"]) {
            normalized.insert("tool_input".into(), ti);
        }

        if let Some(tr) = raw.get("tool_response") {
            normalized.insert("tool_response".into(), tr.clone());
        }

        // Copy through any standard fields we didn't already handle
        if let Some(pm) = raw.get("permission_mode") {
            normalized.insert("permission_mode".into(), pm.clone());
        }
        if let Some(tui) = raw.get("tool_use_id") {
            normalized.insert("tool_use_id".into(), tui.clone());
        }

        Value::Object(normalized)
    }
}

impl HookProtocol for OpenCodeProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::OpenCode
    }

    fn parse_event(&self, raw: &Value) -> Result<clash_hooks::HookEvent> {
        Ok(clash_hooks::recv_from_value(Self::normalize(raw))?)
    }

    // OpenCode uses "action" field and "ask" for passthrough
    fn format_allow(
        &self,
        _reason: Option<&str>,
        _context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({ "action": "allow" });
        if let Some(ui) = updated_input {
            output["args"] = ui;
        }
        output
    }

    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({ "action": "deny", "reason": reason })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        serde_json::json!({ "action": "ask" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_hooks::{HookEventCommon, ToolEvent};

    #[test]
    fn parse_event_opencode_bash() {
        let raw = serde_json::json!({
            "tool": "bash",
            "sessionID": "oc-123",
            "directory": "/home/user",
            "event": "PreToolUse",
            "args": {"command": "ls"}
        });
        let event = OpenCodeProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "bash");
        assert_eq!(e.session_id(), "oc-123");
        assert_eq!(e.cwd(), "/home/user");
    }

    #[test]
    fn format_deny_opencode() {
        assert_eq!(OpenCodeProtocol.format_deny("no", None)["action"], "deny");
    }
}
