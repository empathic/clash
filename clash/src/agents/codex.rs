//! OpenAI Codex CLI hook protocol implementation.
//!
//! Codex CLI uses TOML-configured hooks with JSON stdin/stdout.
//! PreToolUse hooks can return Proceed, Block, or Modify decisions.

use anyhow::Result;
use serde_json::Value;

use super::protocol::HookProtocol;
use super::{AgentKind, resolve_tool_name};
use crate::hooks::{SessionStartHookInput, ToolUseHookInput};

/// Codex CLI hook protocol handler.
pub struct CodexProtocol;

impl HookProtocol for CodexProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let tool_name = raw
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::Codex, &tool_name).to_string();

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
                .or_else(|| raw.get("working_directory"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: raw
                .get("hook_event_name")
                .and_then(|v| v.as_str())
                .unwrap_or("PreToolUse")
                .to_string(),
            tool_name: resolved,
            tool_input: raw
                .get("tool_input")
                .or_else(|| raw.get("input"))
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::Codex),
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
            hook_event_name: "SessionStart".to_string(),
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
        // Fall through to Codex's native approval
        serde_json::json!({ "decision": "proceed" })
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        let mut output = serde_json::json!({ "decision": "proceed" });
        if let Some(ctx) = context {
            output["additional_context"] = Value::String(ctx.to_string());
        }
        output
    }

    fn rewrite_for_sandbox(
        &self,
        input: &ToolUseHookInput,
        sandbox_cmd: &str,
    ) -> Option<Value> {
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
    fn parse_codex_shell() {
        let raw = serde_json::json!({
            "session_id": "codex-123",
            "cwd": "/home/user",
            "hook_event_name": "PreToolUse",
            "tool_name": "shell",
            "tool_input": {"command": "git status"}
        });

        let protocol = CodexProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();

        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("shell"));
        assert_eq!(input.agent, Some(AgentKind::Codex));
    }

    #[test]
    fn format_allow_codex() {
        let protocol = CodexProtocol;
        let output = protocol.format_allow(Some("safe"), None, None);
        assert_eq!(output["decision"], "proceed");
    }

    #[test]
    fn format_deny_codex() {
        let protocol = CodexProtocol;
        let output = protocol.format_deny("blocked", None);
        assert_eq!(output["decision"], "block");
        assert_eq!(output["message"], "blocked");
    }

    #[test]
    fn format_allow_with_modify() {
        let protocol = CodexProtocol;
        let updated = serde_json::json!({"command": "clash shell -c 'ls'"});
        let output = protocol.format_allow(Some("sandboxed"), None, Some(updated));
        assert_eq!(output["decision"], "modify");
    }
}
