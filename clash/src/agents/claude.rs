//! Claude Code hook protocol implementation.
//!
//! Claude Code sends/receives JSON via stdin/stdout with its own field naming
//! conventions. This module translates between Claude's format and Clash's
//! internal types.

use anyhow::Result;
use serde_json::Value;

use super::protocol::HookProtocol;
use super::{AgentKind, resolve_tool_name};
use crate::hooks::{HookOutput, SessionStartHookInput, ToolUseHookInput};

/// Claude Code hook protocol handler.
pub struct ClaudeProtocol;

impl HookProtocol for ClaudeProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Claude
    }

    fn parse_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        let mut input: ToolUseHookInput = serde_json::from_value(raw.clone())?;
        let original = input.tool_name.clone();
        input.tool_name = resolve_tool_name(AgentKind::Claude, &original).to_string();
        input.original_tool_name = Some(original);
        input.agent = Some(AgentKind::Claude);
        Ok(input)
    }

    fn parse_post_tool_use(&self, raw: &Value) -> Result<ToolUseHookInput> {
        self.parse_tool_use(raw)
    }

    fn parse_session_start(&self, raw: &Value) -> Result<SessionStartHookInput> {
        Ok(serde_json::from_value(raw.clone())?)
    }

    fn format_allow(
        &self,
        reason: Option<&str>,
        context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value {
        let mut output = HookOutput::allow(
            reason.map(String::from),
            context.map(String::from),
        );
        if let Some(ui) = updated_input {
            output.set_updated_input(ui);
        }
        serde_json::to_value(output).expect("HookOutput serialization cannot fail")
    }

    fn format_deny(&self, reason: &str, context: Option<&str>) -> Value {
        let output = HookOutput::deny(reason.to_string(), context.map(String::from));
        serde_json::to_value(output).expect("HookOutput serialization cannot fail")
    }

    fn format_ask(&self, reason: Option<&str>, context: Option<&str>) -> Value {
        let output = HookOutput::ask(reason.map(String::from), context.map(String::from));
        serde_json::to_value(output).expect("HookOutput serialization cannot fail")
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        let output = HookOutput::session_start(context.map(String::from));
        serde_json::to_value(output).expect("HookOutput serialization cannot fail")
    }

    fn rewrite_for_sandbox(
        &self,
        input: &ToolUseHookInput,
        sandbox_cmd: &str,
    ) -> Option<Value> {
        // Only rewrite shell commands (internal name "Bash")
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
        include_str!("../../docs/session-context.md")
    }
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tool_use_normalizes_name() {
        let raw = serde_json::json!({
            "session_id": "test",
            "transcript_path": "/tmp/t.jsonl",
            "cwd": "/tmp",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "toolu_01"
        });

        let protocol = ClaudeProtocol;
        let input = protocol.parse_tool_use(&raw).unwrap();

        // For Claude, Bash maps to internal "Bash" (identity)
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.agent, Some(AgentKind::Claude));
    }

    #[test]
    fn format_allow_matches_existing_format() {
        let protocol = ClaudeProtocol;
        let output = protocol.format_allow(Some("safe"), None, None);

        assert_eq!(output["continue"], true);
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"],
            "allow"
        );
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecisionReason"],
            "safe"
        );
    }

    #[test]
    fn format_deny_matches_existing_format() {
        let protocol = ClaudeProtocol;
        let output = protocol.format_deny("blocked", Some("context"));

        assert_eq!(output["continue"], true);
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"],
            "deny"
        );
    }

    #[test]
    fn format_ask_matches_existing_format() {
        let protocol = ClaudeProtocol;
        let output = protocol.format_ask(None, None);

        assert_eq!(output["continue"], true);
        assert_eq!(
            output["hookSpecificOutput"]["permissionDecision"],
            "ask"
        );
    }

    #[test]
    fn rewrite_for_sandbox_wraps_command() {
        let protocol = ClaudeProtocol;
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "ls -la"}),
            cwd: "/home/user".into(),
            ..Default::default()
        };

        let result = protocol
            .rewrite_for_sandbox(&input, "/usr/bin/clash")
            .unwrap();
        let cmd = result["command"].as_str().unwrap();
        assert!(cmd.contains("clash"));
        assert!(cmd.contains("shell"));
        assert!(cmd.contains("ls -la"));
    }

    #[test]
    fn rewrite_for_sandbox_ignores_non_bash() {
        let protocol = ClaudeProtocol;
        let input = ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: serde_json::json!({"file_path": "/tmp/foo"}),
            cwd: "/home/user".into(),
            ..Default::default()
        };

        assert!(protocol
            .rewrite_for_sandbox(&input, "/usr/bin/clash")
            .is_none());
    }
}
