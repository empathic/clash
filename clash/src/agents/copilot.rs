//! GitHub Copilot CLI hook protocol implementation.
//!
//! Copilot CLI uses .github/hooks/*.json configuration with preToolUse/postToolUse
//! events that can approve or deny tool execution.

use anyhow::Result;
use serde_json::Value;

use super::protocol::HookProtocol;
use super::{AgentKind, resolve_tool_name};
use crate::hooks::{SessionStartHookInput, ToolUseHookInput};

/// Copilot CLI hook protocol handler.
pub struct CopilotProtocol;

impl HookProtocol for CopilotProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Copilot
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let tool_name = raw
            .get("tool_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let original = tool_name.clone();
        let resolved = resolve_tool_name(AgentKind::Copilot, &tool_name).to_string();

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
            permission_mode: "default".to_string(),
            hook_event_name: raw
                .get("hook_event_name")
                .and_then(|v| v.as_str())
                .unwrap_or("preToolUse")
                .to_string(),
            tool_name: resolved,
            tool_input: raw
                .get("tool_input")
                .cloned()
                .unwrap_or(Value::Object(serde_json::Map::new())),
            tool_use_id: None,
            tool_response: raw.get("tool_response").cloned(),
            agent: Some(AgentKind::Copilot),
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
            hook_event_name: "userPromptSubmitted".to_string(),
            source: None,
            model: None,
        })
    }

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
        serde_json::json!({
            "decision": "deny",
            "reason": reason
        })
    }

    fn format_ask(&self, _reason: Option<&str>, _context: Option<&str>) -> Value {
        // Fall through to Copilot's native approval
        serde_json::json!({ "decision": "approve" })
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        let mut output = serde_json::json!({ "decision": "approve" });
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
    fn parse_copilot_bash() {
        let raw = serde_json::json!({
            "session_id": "cp-123",
            "cwd": "/home/user",
            "hook_event_name": "preToolUse",
            "tool_name": "bash",
            "tool_input": {"command": "git status"}
        });

        let protocol = CopilotProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();

        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("bash"));
        assert_eq!(input.agent, Some(AgentKind::Copilot));
    }

    #[test]
    fn parse_copilot_view() {
        let raw = serde_json::json!({
            "tool_name": "view",
            "tool_input": {"file_path": "/tmp/foo.txt"}
        });

        let protocol = CopilotProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Read");
    }

    #[test]
    fn format_allow_copilot() {
        let protocol = CopilotProtocol;
        let output = protocol.format_allow(Some("safe"), None, None);
        assert_eq!(output["decision"], "approve");
    }

    #[test]
    fn format_deny_copilot() {
        let protocol = CopilotProtocol;
        let output = protocol.format_deny("blocked", None);
        assert_eq!(output["decision"], "deny");
    }
}
