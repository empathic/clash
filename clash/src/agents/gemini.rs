//! Gemini CLI hook protocol implementation.
//!
//! Gemini CLI sends BeforeTool/AfterTool events with a different JSON format
//! than Claude Code. This module translates between Gemini's format and Clash's
//! internal types.
//!
//! Key differences from Claude:
//! - Output uses `decision: "allow"|"deny"` instead of `permissionDecision`
//! - "Ask" maps to `{ "continue": true }` (fall through to Gemini's native prompt)
//! - Tool input rewriting uses `hookSpecificOutput.tool_input` merge
//! - No `permission_mode` field (Gemini has separate approval modes)

use anyhow::Result;
use serde_json::Value;

use super::protocol::HookProtocol;
use super::{AgentKind, resolve_tool_name};
use crate::hooks::{SessionStartHookInput, ToolUseHookInput};

/// Gemini CLI hook protocol handler.
pub struct GeminiProtocol;

impl HookProtocol for GeminiProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Gemini
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        // Gemini sends: tool_name, tool_input, session_id, cwd, hook_event_name,
        //               timestamp, mcp_context, original_request_name
        let tool_name = raw
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::Gemini, &tool_name).to_string();

        Ok(ToolUseHookInput {
            session_id: raw
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            transcript_path: raw
                .get("transcript_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            cwd: raw
                .get("cwd")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            // Gemini doesn't send permission_mode; default to "default"
            permission_mode: "default".to_string(),
            hook_event_name: raw
                .get("hook_event_name")
                .and_then(|v| v.as_str())
                .unwrap_or("BeforeTool")
                .to_string(),
            tool_name: resolved,
            tool_input: raw.get("tool_input").cloned().unwrap_or(Value::Object(
                serde_json::Map::new(),
            )),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::Gemini),
            original_tool_name: Some(original),
        })
    }

    fn parse_post_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        self.parse_tool_use(raw)
    }

    fn parse_session_start(&self, raw: &Value) -> Result<SessionStartHookInput> {
        Ok(SessionStartHookInput {
            session_id: raw
                .get("session_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            transcript_path: raw
                .get("transcript_path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            cwd: raw
                .get("cwd")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            permission_mode: None,
            hook_event_name: raw
                .get("hook_event_name")
                .and_then(|v| v.as_str())
                .unwrap_or("SessionStart")
                .to_string(),
            source: raw
                .get("source")
                .and_then(|v| v.as_str())
                .map(String::from),
            model: raw
                .get("model")
                .and_then(|v| v.as_str())
                .map(String::from),
        })
    }

    fn format_allow(
        &self,
        reason: Option<&str>,
        _context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value {
        let mut output = serde_json::json!({
            "decision": "allow"
        });
        if let Some(r) = reason {
            output["reason"] = Value::String(r.to_string());
        }
        if let Some(ui) = updated_input {
            output["hookSpecificOutput"] = serde_json::json!({
                "tool_input": ui
            });
        }
        output
    }

    fn format_deny(&self, reason: &str, _context: Option<&str>) -> Value {
        serde_json::json!({
            "decision": "deny",
            "reason": reason
        })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        // Fall through to Gemini's native permission prompt
        serde_json::json!({
            "continue": true
        })
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        let mut output = serde_json::json!({
            "decision": "allow"
        });
        if let Some(ctx) = context {
            output["hookSpecificOutput"] = serde_json::json!({
                "hookEventName": "SessionStart",
                "additionalContext": ctx
            });
        }
        output
    }

    fn rewrite_for_sandbox(
        &self,
        input: &ToolUseHookInput,
        sandbox_cmd: &str,
    ) -> Option<Value> {
        // Internal name "Bash" after normalization from "run_shell_command"
        if input.tool_name != "Bash" {
            return None;
        }
        let command = input.tool_input.get("command")?.as_str()?;

        let sandboxed = format!(
            "{} shell --cwd {} -c {}",
            shell_escape(sandbox_cmd),
            shell_escape(&input.cwd),
            shell_escape(command),
        );

        let mut updated = input.tool_input.clone();
        updated
            .as_object_mut()?
            .insert("command".into(), Value::String(sandboxed));
        Some(updated)
    }

    fn session_context(&self) -> &str {
        "Clash is active and enforcing policy on this session.\n\
         Run `clash commands` to see the full command hierarchy for managing policies, sandboxes, and debugging."
    }
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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

        let protocol = GeminiProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();

        // Gemini's run_shell_command maps to internal "Bash"
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(
            input.original_tool_name.as_deref(),
            Some("run_shell_command")
        );
        assert_eq!(input.agent, Some(AgentKind::Gemini));
        assert_eq!(input.session_id, "gem-123");
        assert_eq!(input.permission_mode, "default");
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

        let protocol = GeminiProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();

        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.original_tool_name.as_deref(), Some("read_file"));
    }

    #[test]
    fn format_allow_gemini() {
        let protocol = GeminiProtocol;
        let output = protocol.format_allow(Some("safe"), None, None);

        assert_eq!(output["decision"], "allow");
        assert_eq!(output["reason"], "safe");
    }

    #[test]
    fn format_deny_gemini() {
        let protocol = GeminiProtocol;
        let output = protocol.format_deny("blocked", None);

        assert_eq!(output["decision"], "deny");
        assert_eq!(output["reason"], "blocked");
    }

    #[test]
    fn format_ask_falls_through() {
        let protocol = GeminiProtocol;
        let output = protocol.format_ask(None, None);

        // Gemini "ask" = continue with native prompt
        assert_eq!(output["continue"], true);
        assert!(output.get("decision").is_none());
    }

    #[test]
    fn format_allow_with_rewrite() {
        let protocol = GeminiProtocol;
        let updated = serde_json::json!({"command": "clash shell -c 'ls'"});
        let output = protocol.format_allow(Some("sandboxed"), None, Some(updated.clone()));

        assert_eq!(output["decision"], "allow");
        assert_eq!(output["hookSpecificOutput"]["tool_input"], updated);
    }

    #[test]
    fn rewrite_sandbox_gemini() {
        let protocol = GeminiProtocol;
        let input = ToolUseHookInput {
            tool_name: "Bash".into(), // Already normalized
            tool_input: serde_json::json!({"command": "rm -rf /"}),
            cwd: "/home/user".into(),
            ..Default::default()
        };

        let result = protocol
            .rewrite_for_sandbox(&input, "/usr/bin/clash")
            .unwrap();
        let cmd = result["command"].as_str().unwrap();
        assert!(cmd.contains("clash"));
        assert!(cmd.contains("rm -rf /"));
    }
}
