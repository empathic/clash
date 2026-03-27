//! OpenAI Codex CLI hook protocol implementation.
//!
//! Codex uses Proceed/Block/Modify decisions instead of allow/deny.

use anyhow::Result;
use serde_json::Value;

use super::protocol::{HookProtocol, json_str, json_str_any, json_value_any};
use super::{AgentKind, resolve_tool_name};
use crate::hooks::ToolUseHookInput;

pub struct CodexProtocol;

impl HookProtocol for CodexProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let tool_name = json_str(raw, "tool_name").to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::Codex, &tool_name).to_string();

        Ok(ToolUseHookInput {
            session_id: json_str(raw, "session_id").to_string(),
            transcript_path: json_str(raw, "transcript_path").to_string(),
            cwd: json_str_any(raw, &["cwd", "working_directory"]).to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: json_str(raw, "hook_event_name").to_string(),
            tool_name: resolved,
            tool_input: json_value_any(raw, &["tool_input", "input"])
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::Codex),
            original_tool_name: Some(original),
        })
    }

    // Codex uses "proceed"/"block"/"modify" instead of "allow"/"deny"
    fn format_allow(
        &self,
        reason: Option<&str>,
        _context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({ "decision": "proceed" });
        if let Some(r) = reason {
            output["reason"] = Value::String(r.to_string());
        }
        if let Some(ui) = updated_input {
            output["decision"] = Value::String("modify".to_string());
            output["tool_input"] = ui;
        }
        output
    }

    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({
            "decision": "block",
            "message": reason
        })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        serde_json::json!({ "decision": "proceed" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_codex_shell() {
        let raw = serde_json::json!({
            "session_id": "codex-123",
            "cwd": "/home/user",
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "git status"}
        });
        let input = CodexProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("shell"));
    }

    #[test]
    fn format_allow_codex() {
        assert_eq!(
            CodexProtocol.format_allow(None, None, None)["decision"],
            "proceed"
        );
    }

    #[test]
    fn format_deny_codex() {
        assert_eq!(CodexProtocol.format_deny("no", None)["decision"], "block");
    }

    #[test]
    fn format_modify_codex() {
        let ui = serde_json::json!({"command": "sandboxed"});
        let out = CodexProtocol.format_allow(None, None, Some(ui));
        assert_eq!(out["decision"], "modify");
    }
}
