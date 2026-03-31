//! Claude Code hook protocol implementation.
//!
//! Claude uses the nested `{ continue, hookSpecificOutput: { hookEventName, ... } }`
//! JSON format defined by [`HookOutput`]. All `format_*` methods serialize through
//! `HookOutput`'s serde implementation so the output is always wire-correct.
//!
//! `parse_event` uses the default implementation (`recv_from_value`), which
//! works because Claude's JSON is already in the canonical format.

use serde_json::Value;

use super::AgentKind;
use super::protocol::HookProtocol;
use crate::hooks::HookOutput;
use crate::policy_decision::PolicyDecision;

pub struct ClaudeProtocol;

impl HookProtocol for ClaudeProtocol {
    fn agent(&self) -> AgentKind {
        AgentKind::Claude
    }

    fn session_context(&self) -> &str {
        include_str!("../../docs/session-context.md")
    }

    // parse_event — uses default (recv_from_value), Claude JSON is canonical

    fn format_decision(&self, decision: &PolicyDecision) -> Value {
        serde_json::to_value(to_hook_output(decision)).unwrap()
    }

    fn format_session_start(&self, context: Option<&str>) -> Value {
        serde_json::to_value(HookOutput::session_start(context.map(String::from))).unwrap()
    }

    fn format_post_tool_use(&self, context: Option<&str>) -> Value {
        serde_json::to_value(HookOutput::post_tool_use(context.map(String::from))).unwrap()
    }

    fn format_continue(&self) -> Value {
        serde_json::to_value(HookOutput::continue_execution()).unwrap()
    }

    fn format_permission_response(
        &self,
        behavior: &str,
        message: Option<&str>,
        updated_input: Option<&Value>,
        interrupt: Option<bool>,
    ) -> Value {
        let output = match behavior {
            "allow" => HookOutput::approve_permission(updated_input.cloned()),
            _ => HookOutput::deny_permission(
                message.unwrap_or("denied").to_string(),
                interrupt.unwrap_or(false),
            ),
        };
        serde_json::to_value(&output).unwrap()
    }
}

/// Convert a [`PolicyDecision`] into a Claude-format [`HookOutput`].
fn to_hook_output(decision: &PolicyDecision) -> HookOutput {
    match decision {
        PolicyDecision::Allow {
            reason,
            context,
            updated_input,
        } => {
            let mut output = HookOutput::allow(Some(reason.clone()), context.clone());
            if let Some(ui) = updated_input {
                output.set_updated_input(ui.clone());
            }
            output
        }
        PolicyDecision::Deny { reason, context } => {
            HookOutput::deny(reason.clone(), context.clone())
        }
        PolicyDecision::Ask { reason, context } => {
            HookOutput::ask(Some(reason.clone()), context.clone())
        }
        PolicyDecision::Pass => HookOutput::continue_execution(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_hooks::ToolEvent;

    #[test]
    fn parse_event_claude_pre_tool_use() {
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
        let event = ClaudeProtocol.parse_event(&raw).unwrap();
        let clash_hooks::HookEvent::PreToolUse(e) = event else {
            panic!("expected PreToolUse");
        };
        assert_eq!(e.tool_name(), "Bash");
    }

    #[test]
    fn format_decision_round_trip() {
        let decision = PolicyDecision::Allow {
            reason: "policy: allowed".into(),
            context: None,
            updated_input: None,
        };
        let json = ClaudeProtocol.format_decision(&decision);
        let expected =
            serde_json::to_value(&HookOutput::allow(Some("policy: allowed".into()), None)).unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn format_decision_deny_round_trip() {
        let decision = PolicyDecision::Deny {
            reason: "blocked".into(),
            context: Some("ctx".into()),
        };
        let json = ClaudeProtocol.format_decision(&decision);
        let expected =
            serde_json::to_value(&HookOutput::deny("blocked".into(), Some("ctx".into()))).unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn format_decision_pass_round_trip() {
        let decision = PolicyDecision::Pass;
        let json = ClaudeProtocol.format_decision(&decision);
        let expected = serde_json::to_value(&HookOutput::continue_execution()).unwrap();
        assert_eq!(json, expected);
    }
}
