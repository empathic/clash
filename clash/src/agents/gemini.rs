//! Gemini CLI hook protocol implementation.
//!
//! Key differences from the default protocol:
//! - Tool input rewriting uses `hookSpecificOutput.tool_input` merge
//! - Session start uses `hookSpecificOutput` wrapper
//! - Uses non-standard hook_event_name values (e.g., "BeforeTool")

use anyhow::Result;
use serde_json::Value;

use super::AgentKind;
use super::protocol::HookProtocol;

pub struct GeminiProtocol;

impl GeminiProtocol {
    /// Normalize Gemini JSON to Claude convention for `recv_from_value`.
    fn normalize(raw: &Value) -> Value {
        let mut normalized = serde_json::Map::new();

        if let Some(obj) = raw.as_object() {
            for (k, v) in obj {
                normalized.insert(k.clone(), v.clone());
            }
        }

        // Gemini uses non-standard hook_event_name values
        if let Some(name) = normalized.get("hook_event_name").and_then(|v| v.as_str()) {
            let pascal = normalize_gemini_event(name);
            normalized.insert("hook_event_name".into(), Value::String(pascal));
        }

        // Default transcript_path if missing
        if !normalized.contains_key("transcript_path") {
            normalized.insert("transcript_path".into(), Value::String(String::new()));
        }

        Value::Object(normalized)
    }
}

/// Normalize Gemini event names to Claude PascalCase convention.
fn normalize_gemini_event(name: &str) -> String {
    match name {
        "BeforeTool" | "beforeTool" => "PreToolUse".into(),
        "AfterTool" | "afterTool" => "PostToolUse".into(),
        "sessionStart" | "SessionStart" => "SessionStart".into(),
        "stop" | "Stop" => "Stop".into(),
        _ => super::copilot::normalize_event_name(name),
    }
}

impl HookProtocol for GeminiProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Gemini
    }

    fn parse_event(&self, raw: &Value) -> Result<clash_hooks::HookEvent> {
        Ok(clash_hooks::recv_from_value(Self::normalize(raw))?)
    }

    // Gemini uses hookSpecificOutput for tool input rewrites
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
            output["hookSpecificOutput"] = serde_json::json!({ "tool_input": ui });
        }
        output
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        let mut output = serde_json::json!({ "decision": "allow" });
        if let Some(ctx) = context {
            output["hookSpecificOutput"] = serde_json::json!({
                "hookEventName": "SessionStart",
                "additionalContext": ctx
            });
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_hooks::{HookEventCommon, ToolEvent};

    #[test]
    fn parse_event_gemini_tool_use() {
        let raw = serde_json::json!({
            "session_id": "gem-123",
            "transcript_path": "/tmp/gemini.jsonl",
            "cwd": "/home/user",
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git status"},
            "timestamp": "2026-03-26T00:00:00Z"
        });
        let event = GeminiProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "run_shell_command");
        assert_eq!(e.session_id(), "gem-123");
    }

    #[test]
    fn parse_event_gemini_read_file() {
        let raw = serde_json::json!({
            "session_id": "gem-123",
            "cwd": "/home/user",
            "hook_event_name": "BeforeTool",
            "tool_name": "read_file",
            "tool_input": {"file_path": "/tmp/foo.txt"}
        });
        let event = GeminiProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "read_file");
    }

    #[test]
    fn format_allow_with_rewrite() {
        let updated = serde_json::json!({"command": "sandboxed"});
        let out = GeminiProtocol.format_allow(Some("ok"), None, Some(updated.clone()));
        assert_eq!(out["hookSpecificOutput"]["tool_input"], updated);
    }

    #[test]
    fn format_deny_uses_default() {
        let out = GeminiProtocol.format_deny("blocked", None);
        assert_eq!(out["decision"], "deny");
        assert_eq!(out["reason"], "blocked");
    }

    #[test]
    fn format_ask_uses_default() {
        let out = GeminiProtocol.format_ask(None, None);
        assert_eq!(out["continue"], true);
    }
}
