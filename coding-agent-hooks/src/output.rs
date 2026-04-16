//! Hook output types — structured responses sent back to agents via stdout.
//!
//! [`HookOutput`] is the complete response type. It is used directly by Claude
//! Code (serialized as JSON). Other agents convert it to their protocol format
//! via the [`HookProtocol`](crate::protocol::HookProtocol) trait methods.

use std::io::Write;

use serde::{Deserialize, Serialize};
use tracing::{Level, instrument};

/// The effect of a policy decision on a tool invocation.
///
/// This is the agent-agnostic representation of a permission decision.
/// Individual agents may use different vocabulary (e.g. "proceed"/"block",
/// "approve"/"deny"), but they all map to these three effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Permission is granted — tool execution proceeds.
    Allow,
    /// Permission requires user confirmation via the agent's native UI.
    Ask,
    /// Permission is denied — tool execution is blocked.
    Deny,
}

/// Hook-specific output for PreToolUse.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<Effect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Decision behavior for PermissionRequest responses.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PermissionBehavior {
    Allow,
    Deny,
}

/// Decision structure for PermissionRequest responses.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDecision {
    pub behavior: PermissionBehavior,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interrupt: Option<bool>,
}

/// Hook-specific output for PermissionRequest.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestOutput {
    pub hook_event_name: &'static str,
    pub decision: PermissionDecision,
}

/// Hook-specific output for SessionStart.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output for PostToolUse hooks — provides advisory context back to the agent.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Hook-specific output variants.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum HookSpecificOutput {
    PreToolUse(PreToolUseOutput),
    PostToolUse(PostToolUseOutput),
    PermissionRequest(PermissionRequestOutput),
    SessionStart(SessionStartOutput),
}

/// The complete hook output sent to an agent via stdout.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(rename = "continue")]
    pub should_continue: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

impl HookOutput {
    /// Private helper to construct a PreToolUse response with the given decision.
    fn pretooluse_output(
        decision: Effect,
        reason: Option<String>,
        context: Option<String>,
        updated_input: Option<serde_json::Value>,
    ) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PreToolUse(PreToolUseOutput {
                hook_event_name: "PreToolUse",
                permission_decision: Some(decision),
                permission_decision_reason: reason,
                updated_input,
                additional_context: context,
            })),
        }
    }

    /// Create an "allow" response for PreToolUse - bypasses permission system.
    #[instrument(level = Level::TRACE)]
    pub fn allow(reason: Option<String>, context: Option<String>) -> Self {
        Self::pretooluse_output(Effect::Allow, reason, context, None)
    }

    /// Create a "deny" response for PreToolUse - prevents tool execution.
    #[instrument(level = Level::TRACE)]
    pub fn deny(reason: String, context: Option<String>) -> Self {
        Self::pretooluse_output(Effect::Deny, Some(reason), context, None)
    }

    /// Create an "ask" response for PreToolUse - prompts user for confirmation.
    #[instrument(level = Level::TRACE)]
    pub fn ask(reason: Option<String>, context: Option<String>) -> Self {
        Self::pretooluse_output(Effect::Ask, reason, context, None)
    }

    /// Approve a permission request on behalf of the user.
    #[instrument(level = Level::TRACE)]
    pub fn approve_permission(updated_input: Option<serde_json::Value>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PermissionRequest(
                PermissionRequestOutput {
                    hook_event_name: "PermissionRequest",
                    decision: PermissionDecision {
                        behavior: PermissionBehavior::Allow,
                        updated_input,
                        message: None,
                        interrupt: None,
                    },
                },
            )),
        }
    }

    /// Deny a permission request on behalf of the user.
    #[instrument(level = Level::TRACE)]
    pub fn deny_permission(message: String, interrupt: bool) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::PermissionRequest(
                PermissionRequestOutput {
                    hook_event_name: "PermissionRequest",
                    decision: PermissionDecision {
                        behavior: PermissionBehavior::Deny,
                        updated_input: None,
                        message: Some(message),
                        interrupt: Some(interrupt),
                    },
                },
            )),
        }
    }

    /// Set the updated_input field on a PreToolUse response.
    /// This rewrites the tool input before the agent executes it.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_updated_input(&mut self, updated_input: serde_json::Value) {
        if let Some(HookSpecificOutput::PreToolUse(ref mut pre)) = self.hook_specific_output {
            pre.updated_input = Some(updated_input);
        }
    }

    /// Create a SessionStart response with optional context about the session setup.
    #[instrument(level = Level::TRACE)]
    pub fn session_start(additional_context: Option<String>) -> Self {
        Self {
            should_continue: true,
            hook_specific_output: Some(HookSpecificOutput::SessionStart(SessionStartOutput {
                hook_event_name: "SessionStart",
                additional_context,
            })),
        }
    }

    /// Create a PostToolUse response with optional advisory context.
    #[instrument(level = Level::TRACE)]
    pub fn post_tool_use(additional_context: Option<String>) -> Self {
        match additional_context {
            Some(ctx) => Self {
                should_continue: true,
                hook_specific_output: Some(HookSpecificOutput::PostToolUse(PostToolUseOutput {
                    hook_event_name: "PostToolUse",
                    additional_context: Some(ctx),
                })),
            },
            None => Self::continue_execution(),
        }
    }

    /// Continue execution without making a decision (for informational hooks).
    #[instrument(level = Level::TRACE)]
    pub fn continue_execution() -> Self {
        Self {
            should_continue: true,
            hook_specific_output: None,
        }
    }

    /// Write response to any writer (for testability).
    #[instrument(level = Level::TRACE, skip(self, writer))]
    pub fn write_to(&self, mut writer: impl Write) -> anyhow::Result<()> {
        serde_json::to_writer(&mut writer, self)?;
        writeln!(writer)?;
        Ok(())
    }

    /// Write response to stdout (convenience wrapper for production).
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn write_stdout(&self) -> anyhow::Result<()> {
        self.write_to(std::io::stdout().lock())
    }

    /// Extract the [`Effect`] from this output, if it contains a PreToolUse decision.
    pub fn effect(&self) -> Option<Effect> {
        match &self.hook_specific_output {
            Some(HookSpecificOutput::PreToolUse(pre)) => pre.permission_decision,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_allow() {
        let output = HookOutput::allow(Some("Safe command".into()), None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Safe command"
        );
    }

    #[test]
    fn test_output_deny() {
        let output = HookOutput::deny("Dangerous command".into(), None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Dangerous command"
        );
    }

    #[test]
    fn test_output_ask() {
        let output = HookOutput::ask(None, None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
        assert!(json["hookSpecificOutput"]["permissionDecisionReason"].is_null());
    }

    #[test]
    fn test_approve_permission() {
        let output = HookOutput::approve_permission(None);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");
        assert!(json["hookSpecificOutput"]["decision"]["updatedInput"].is_null());
    }

    #[test]
    fn test_approve_permission_with_updated_input() {
        let updated = serde_json::json!({"command": "ls -la"});
        let output = HookOutput::approve_permission(Some(updated.clone()));
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["decision"]["updatedInput"],
            updated
        );
    }

    #[test]
    fn test_deny_permission() {
        let output = HookOutput::deny_permission("Not allowed".into(), true);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["decision"]["message"],
            "Not allowed"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["interrupt"], true);
    }

    #[test]
    fn test_deny_permission_no_interrupt() {
        let output = HookOutput::deny_permission("Try again".into(), false);
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(json["hookSpecificOutput"]["decision"]["interrupt"], false);
    }

    #[test]
    fn test_effect_extraction() {
        assert_eq!(HookOutput::allow(None, None).effect(), Some(Effect::Allow));
        assert_eq!(
            HookOutput::deny("x".into(), None).effect(),
            Some(Effect::Deny)
        );
        assert_eq!(HookOutput::ask(None, None).effect(), Some(Effect::Ask));
        assert_eq!(HookOutput::continue_execution().effect(), None);
    }
}
