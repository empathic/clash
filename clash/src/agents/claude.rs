//! Claude Code hook protocol implementation.
//!
//! Claude Code has a unique output format using `HookOutput` structs with
//! `permissionDecision`, `hookSpecificOutput`, etc. This requires custom
//! format methods — the defaults don't apply here.

use anyhow::Result;
use serde_json::Value;

use super::protocol::HookProtocol;
use super::{AgentKind, resolve_tool_name};
use crate::hooks::{HookOutput, SessionStartHookInput, StopHookInput, ToolUseHookInput};

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

    fn parse_session_start(&self, raw: &Value) -> Result<SessionStartHookInput> {
        Ok(serde_json::from_value(raw.clone())?)
    }

    fn parse_stop(&self, raw: &Value) -> Result<StopHookInput> {
        Ok(serde_json::from_value(raw.clone())?)
    }

    // Claude has a unique output format — must override all format methods.

    fn format_allow(
        &self,
        reason: Option<&str>,
        context: Option<&str>,
        updated_input: Option<Value>,
    ) -> Value {
        let mut output = HookOutput::allow(reason.map(String::from), context.map(String::from));
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

    fn session_context(&self) -> &str {
        include_str!("../../docs/session-context.md")
    }

    // parse_post_tool_use — uses default (delegates to parse_tool_use)
    // rewrite_for_sandbox — uses default (rewrites "Bash" command field)
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
        let input = ClaudeProtocol.parse_tool_use(&raw).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.original_tool_name.as_deref(), Some("Bash"));
        assert_eq!(input.agent, Some(AgentKind::Claude));
    }

    #[test]
    fn format_allow_matches_existing_format() {
        let output = ClaudeProtocol.format_allow(Some("safe"), None, None);
        assert_eq!(output["continue"], true);
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "allow");
    }

    #[test]
    fn format_deny_matches_existing_format() {
        let output = ClaudeProtocol.format_deny("blocked", Some("context"));
        assert_eq!(output["continue"], true);
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn format_ask_matches_existing_format() {
        let output = ClaudeProtocol.format_ask(None, None);
        assert_eq!(output["continue"], true);
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn rewrite_for_sandbox_uses_default() {
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: serde_json::json!({"command": "ls -la"}),
            cwd: "/home/user".into(),
            ..Default::default()
        };
        let result = ClaudeProtocol
            .rewrite_for_sandbox(&input, "/usr/bin/clash")
            .unwrap();
        assert!(result["command"].as_str().unwrap().contains("clash"));
    }
}
