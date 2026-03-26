//! OpenCode hook protocol implementation.
//!
//! OpenCode uses a JS plugin API; the extension wrapper translates to
//! JSON stdin/stdout calls. Field names differ (tool, args, sessionID, directory).

use anyhow::Result;
use serde_json::Value;

use super::protocol::{HookProtocol, json_str_any, json_value_any};
use super::{AgentKind, resolve_tool_name};
use crate::hooks::ToolUseHookInput;

pub struct OpenCodeProtocol;

impl HookProtocol for OpenCodeProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::OpenCode
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let tool_name = json_str_any(raw, &["tool_name", "tool"]).to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::OpenCode, &tool_name).to_string();

        Ok(ToolUseHookInput {
            session_id: json_str_any(raw, &["session_id", "sessionID"]).to_string(),
            transcript_path: String::new(),
            cwd: json_str_any(raw, &["cwd", "directory"]).to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: json_str_any(raw, &["hook_event_name", "event"])
                .to_string(),
            tool_name: resolved,
            tool_input: json_value_any(raw, &["tool_input", "args"])
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::OpenCode),
            original_tool_name: Some(original),
        })
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

    #[test]
    fn parse_opencode_bash() {
        let raw = serde_json::json!({
            "tool": "bash",
            "sessionID": "oc-123",
            "directory": "/home/user",
            "args": {"command": "ls"}
        });
        let input = OpenCodeProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.session_id, "oc-123");
        assert_eq!(input.cwd, "/home/user");
    }

    #[test]
    fn format_deny_opencode() {
        assert_eq!(OpenCodeProtocol.format_deny("no", None)["action"], "deny");
    }
}
