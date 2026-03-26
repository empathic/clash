//! OpenCode hook protocol implementation.
//!
//! OpenCode uses a JS plugin API with tool.execute.before/after callbacks.
//! The extension wrapper translates this to JSON stdin/stdout calls to
//! `clash hook --agent opencode`.

use anyhow::Result;
use serde_json::Value;

use super::protocol::HookProtocol;
use super::{AgentKind, resolve_tool_name};
use crate::hooks::{SessionStartHookInput, ToolUseHookInput};

/// OpenCode hook protocol handler.
pub struct OpenCodeProtocol;

impl HookProtocol for OpenCodeProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::OpenCode
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        // OpenCode's plugin wrapper sends: tool, args, sessionID, directory
        let tool_name = raw
            .get("tool_name")
            .or_else(|| raw.get("tool"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::OpenCode, &tool_name).to_string();

        Ok(ToolUseHookInput {
            session_id: raw
                .get("session_id")
                .or_else(|| raw.get("sessionID"))
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
                .or_else(|| raw.get("directory"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            permission_mode: "default".to_string(),
            hook_event_name: raw
                .get("hook_event_name")
                .and_then(|v| v.as_str())
                .unwrap_or("tool.execute.before")
                .to_string(),
            tool_name: resolved,
            tool_input: raw
                .get("tool_input")
                .or_else(|| raw.get("args"))
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::OpenCode),
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
                .or_else(|| raw.get("sessionID"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            transcript_path: String::new(),
            cwd: raw
                .get("cwd")
                .or_else(|| raw.get("directory"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            permission_mode: None,
            hook_event_name: "session.created".to_string(),
            source: None,
            model: None,
        })
    }

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
        serde_json::json!({
            "action": "deny",
            "reason": reason
        })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        // Fall through to OpenCode's native permission prompt
        serde_json::json!({ "action": "ask" })
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        let mut output = serde_json::json!({ "action": "allow" });
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
    fn parse_opencode_bash() {
        let raw = serde_json::json!({
            "tool": "bash",
            "sessionID": "oc-123",
            "directory": "/home/user",
            "args": {"command": "ls"}
        });

        let protocol = OpenCodeProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();

        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("bash"));
        assert_eq!(input.agent, Some(AgentKind::OpenCode));
        assert_eq!(input.session_id, "oc-123");
        assert_eq!(input.cwd, "/home/user");
    }

    #[test]
    fn parse_opencode_read() {
        let raw = serde_json::json!({
            "tool": "read",
            "args": {"filePath": "/tmp/foo.txt"}
        });

        let protocol = OpenCodeProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Read");
    }

    #[test]
    fn format_deny_opencode() {
        let protocol = OpenCodeProtocol;
        let output = protocol.format_deny("blocked", None);
        assert_eq!(output["action"], "deny");
    }
}
