//! Hook output types serialized to Claude Code via stdout.
//!
//! After processing a hook event, the hook process writes a JSON response to
//! stdout. The types in this module represent those responses.

use std::io::Write;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Permission rule — the hook protocol's permission decision
// ---------------------------------------------------------------------------

/// The permission decision communicated back to Claude Code.
///
/// This type is serialized as part of the hook output JSON and controls
/// how Claude Code handles tool execution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionRule {
    /// Permission is granted without confirmation.
    Allow,
    /// Permission requires user confirmation.
    Ask,
    /// Permission is explicitly denied.
    Deny,
    /// No rule matches (default behavior applies).
    #[default]
    Unset,
}

// ---------------------------------------------------------------------------
// Hook-specific output types
// ---------------------------------------------------------------------------

/// Hook-specific output for PreToolUse events.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<PermissionRule>,
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

/// Hook-specific output for PermissionRequest events.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestOutput {
    pub hook_event_name: &'static str,
    pub decision: PermissionDecision,
}

/// Hook-specific output for SessionStart events.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionStartOutput {
    pub hook_event_name: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output for PostToolUse hooks — provides advisory context back to Claude.
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

// ---------------------------------------------------------------------------
// HookOutput — the complete response envelope
// ---------------------------------------------------------------------------

/// The complete hook output sent to Claude Code via stdout.
///
/// Every hook response includes a `continue` flag and an optional
/// hook-specific payload. Use the constructor methods ([`HookOutput::allow`],
/// [`HookOutput::deny`], etc.) to create well-formed responses.
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
        decision: PermissionRule,
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

    /// Create an "allow" response for PreToolUse — bypasses the permission system.
    pub fn allow(reason: Option<String>, context: Option<String>) -> Self {
        Self::pretooluse_output(PermissionRule::Allow, reason, context, None)
    }

    /// Create a "deny" response for PreToolUse — prevents tool execution.
    pub fn deny(reason: String, context: Option<String>) -> Self {
        Self::pretooluse_output(PermissionRule::Deny, Some(reason), context, None)
    }

    /// Create an "ask" response for PreToolUse — prompts the user for confirmation.
    pub fn ask(reason: Option<String>, context: Option<String>) -> Self {
        Self::pretooluse_output(PermissionRule::Ask, reason, context, None)
    }

    /// Approve a permission request on behalf of the user.
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
    ///
    /// When `interrupt` is true, Claude Code will stop the current conversation turn.
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

    /// Set the `updated_input` field on a PreToolUse response.
    /// This rewrites the tool input before Claude Code executes it.
    pub fn set_updated_input(&mut self, updated_input: serde_json::Value) {
        if let Some(HookSpecificOutput::PreToolUse(ref mut pre)) = self.hook_specific_output {
            pre.updated_input = Some(updated_input);
        }
    }

    /// Create a SessionStart response with optional context about the session setup.
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
    pub fn continue_execution() -> Self {
        Self {
            should_continue: true,
            hook_specific_output: None,
        }
    }

    /// Write response to any writer (for testability).
    pub fn write_to(&self, mut writer: impl Write) -> anyhow::Result<()> {
        serde_json::to_writer(&mut writer, self)?;
        writeln!(writer)?;
        Ok(())
    }

    /// Write response to stdout (convenience wrapper for production).
    pub fn write_stdout(&self) -> anyhow::Result<()> {
        self.write_to(std::io::stdout().lock())
    }
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// Exit codes for hook responses.
pub mod exit_code {
    /// Success — response written to stdout.
    pub const SUCCESS: i32 = 0;
    /// Blocking error — stderr message fed to Claude.
    pub const BLOCKING_ERROR: i32 = 2;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    fn test_session_start() {
        let output = HookOutput::session_start(Some("Ready".into()));
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["continue"], true);
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "SessionStart"
        );
        assert_eq!(
            json["hookSpecificOutput"]["additionalContext"],
            "Ready"
        );
    }

    #[test]
    fn test_post_tool_use() {
        let output = HookOutput::post_tool_use(Some("Advisory info".into()));
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PostToolUse"
        );
        assert_eq!(
            json["hookSpecificOutput"]["additionalContext"],
            "Advisory info"
        );
    }

    #[test]
    fn test_post_tool_use_none_is_continue() {
        let output = HookOutput::post_tool_use(None);
        assert_eq!(output, HookOutput::continue_execution());
    }

    #[test]
    fn test_continue_execution() {
        let output = HookOutput::continue_execution();
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["continue"], true);
        assert!(json.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn test_set_updated_input() {
        let mut output = HookOutput::allow(None, None);
        output.set_updated_input(serde_json::json!({"command": "ls"}));

        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();

        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["updatedInput"]["command"],
            "ls"
        );
    }

    #[test]
    fn test_permission_rule_serialization() {
        assert_eq!(
            serde_json::to_string(&PermissionRule::Allow).unwrap(),
            r#""allow""#
        );
        assert_eq!(
            serde_json::to_string(&PermissionRule::Ask).unwrap(),
            r#""ask""#
        );
        assert_eq!(
            serde_json::to_string(&PermissionRule::Deny).unwrap(),
            r#""deny""#
        );
        assert_eq!(
            serde_json::to_string(&PermissionRule::Unset).unwrap(),
            r#""unset""#
        );
    }
}
