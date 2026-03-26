//! Gemini CLI hook protocol implementation.
//!
//! Key differences from the default protocol:
//! - Tool input rewriting uses `hookSpecificOutput.tool_input` merge
//! - Session start uses `hookSpecificOutput` wrapper

use anyhow::Result;
use serde_json::Value;

use super::protocol::{HookProtocol, json_str};
use super::{AgentKind, resolve_tool_name};
use crate::hooks::ToolUseHookInput;

pub struct GeminiProtocol;

impl HookProtocol for GeminiProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Gemini
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let tool_name = json_str(raw, "tool_name").to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::Gemini, &tool_name).to_string();

        Ok(ToolUseHookInput {
            session_id: json_str(raw, "session_id").to_string(),
            transcript_path: json_str(raw, "transcript_path").to_string(),
            cwd: json_str(raw, "cwd").to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: json_str(raw, "hook_event_name").to_string(),
            tool_name: resolved,
            tool_input: raw.get("tool_input").cloned()
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::Gemini),
            original_tool_name: Some(original),
        })
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

    // format_deny, format_ask, rewrite_for_sandbox, session_context — use defaults
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gemini_tool_use() {
        let raw = serde_json::json!({
            "session_id": "gem-123",
            "transcript_path": "/tmp/gemini.jsonl",
            "cwd": "/home/user",
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git status"},
            "timestamp": "2026-03-26T00:00:00Z"
        });
        let input = GeminiProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("run_shell_command"));
        assert_eq!(input.agent, Some(AgentKind::Gemini));
    }

    #[test]
    fn parse_gemini_read_file() {
        let raw = serde_json::json!({
            "session_id": "gem-123",
            "cwd": "/home/user",
            "hook_event_name": "BeforeTool",
            "tool_name": "read_file",
            "tool_input": {"file_path": "/tmp/foo.txt"}
        });
        let input = GeminiProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Read");
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
