//! OpenAI Codex CLI hook protocol implementation.
//!
//! Codex uses Proceed/Block/Modify decisions instead of allow/deny.

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use super::protocol::HookProtocol;

pub struct CodexProtocol;

impl CodexProtocol {
    /// Normalize Codex JSON to Claude convention for `recv_from_value`.
    fn normalize(raw: &Value) -> Value {
        let mut normalized = serde_json::Map::new();

        // Map field names to Claude convention
        if let Some(obj) = raw.as_object() {
            for (k, v) in obj {
                normalized.insert(k.clone(), v.clone());
            }
        }

        // Ensure cwd (Codex may use working_directory)
        if !normalized.contains_key("cwd")
            && let Some(wd) = raw.get("working_directory")
        {
            normalized.insert("cwd".into(), wd.clone());
        }

        // Ensure tool_input (Codex may use input)
        if !normalized.contains_key("tool_input")
            && let Some(input) = raw.get("input")
        {
            normalized.insert("tool_input".into(), input.clone());
        }

        // Default transcript_path if missing
        if !normalized.contains_key("transcript_path") {
            normalized.insert("transcript_path".into(), Value::String(String::new()));
        }

        Value::Object(normalized)
    }
}

impl HookProtocol for CodexProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn parse_event(&self, raw: &Value) -> Result<clash_hooks::HookEvent> {
        Ok(clash_hooks::recv_from_value(Self::normalize(raw))?)
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
    use clash_hooks::{HookEventCommon, ToolEvent};

    #[test]
    fn parse_event_codex_shell() {
        let raw = serde_json::json!({
            "session_id": "codex-123",
            "cwd": "/home/user",
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "git status"}
        });
        let event = CodexProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "shell");
    }

    #[test]
    fn parse_event_codex_working_directory() {
        let raw = serde_json::json!({
            "session_id": "codex-123",
            "working_directory": "/home/user",
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "ls"}
        });
        let event = CodexProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.cwd(), "/home/user");
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
