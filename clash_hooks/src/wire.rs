//! Wire format types — the raw JSON structures Claude Code sends and expects.
//!
//! These types map 1:1 to the protocol JSON. They are public so advanced users
//! can inspect or construct raw responses, but most consumers should use the
//! typed event API in [`crate::event`] instead.

use serde::{Deserialize, Serialize};

// ── Input (stdin) ───────────────────────────────────────────────────

/// Fields shared by every hook event.
#[derive(Debug, Clone, Deserialize)]
pub struct CommonFields {
    pub session_id: String,
    pub transcript_path: String,
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: Option<String>,
    pub hook_event_name: String,
}

/// Fields specific to tool events (PreToolUse, PostToolUse, PostToolUseFailure, PermissionRequest).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ToolFields {
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<serde_json::Value>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub is_interrupt: Option<bool>,
}

/// Fields specific to SessionStart events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SessionStartFields {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

/// Fields specific to SessionEnd events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SessionEndFields {
    #[serde(default)]
    pub reason: Option<String>,
}

/// Fields specific to UserPromptSubmit events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct UserPromptSubmitFields {
    #[serde(default)]
    pub prompt: Option<String>,
}

/// Fields specific to Stop events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StopFields {
    #[serde(default)]
    pub stop_hook_active: Option<bool>,
    #[serde(default)]
    pub last_assistant_message: Option<String>,
}

/// Fields specific to StopFailure events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StopFailureFields {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_details: Option<serde_json::Value>,
    #[serde(default)]
    pub last_assistant_message: Option<String>,
}

/// Fields specific to SubagentStart events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SubagentStartFields {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
}

/// Fields specific to SubagentStop events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SubagentStopFields {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    #[serde(default)]
    pub agent_transcript_path: Option<String>,
    #[serde(default)]
    pub last_assistant_message: Option<String>,
}

/// Fields specific to TeammateIdle events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TeammateIdleFields {
    #[serde(default)]
    pub teammate_name: Option<String>,
    #[serde(default)]
    pub team_name: Option<String>,
}

/// Fields specific to TaskCompleted events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TaskCompletedFields {
    #[serde(default)]
    pub teammate_name: Option<String>,
    #[serde(default)]
    pub team_name: Option<String>,
    #[serde(default)]
    pub task_id: Option<String>,
    #[serde(default)]
    pub task_subject: Option<String>,
    #[serde(default)]
    pub task_description: Option<String>,
}

/// Fields specific to InstructionsLoaded events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct InstructionsLoadedFields {
    #[serde(default)]
    pub file_path: Option<String>,
    #[serde(default)]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub load_reason: Option<String>,
    #[serde(default)]
    pub globs: Option<Vec<String>>,
    #[serde(default)]
    pub trigger_file_path: Option<String>,
    #[serde(default)]
    pub parent_file_path: Option<String>,
}

/// Fields specific to ConfigChange events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ConfigChangeFields {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub file_path: Option<String>,
}

/// Fields specific to PreCompact events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PreCompactFields {
    #[serde(default)]
    pub trigger: Option<String>,
    #[serde(default)]
    pub custom_instructions: Option<String>,
}

/// Fields specific to PostCompact events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PostCompactFields {
    #[serde(default)]
    pub trigger: Option<String>,
    #[serde(default)]
    pub compact_summary: Option<String>,
}

/// Fields specific to Notification events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NotificationFields {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub notification_type: Option<String>,
}

/// Fields specific to Elicitation events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ElicitationFields {
    #[serde(default)]
    pub mcp_server_name: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub elicitation_id: Option<String>,
    #[serde(default)]
    pub requested_schema: Option<serde_json::Value>,
}

/// Fields specific to ElicitationResult events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ElicitationResultFields {
    #[serde(default)]
    pub mcp_server_name: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub content: Option<serde_json::Value>,
}

/// Fields specific to WorktreeCreate events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WorktreeCreateFields {
    #[serde(default)]
    pub name: Option<String>,
}

/// Fields specific to WorktreeRemove events.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WorktreeRemoveFields {
    #[serde(default)]
    pub worktree_path: Option<String>,
}

// ── Two-phase deserialization ────────────────────────────────────────

/// Phase-1 envelope: common fields + flattened catch-all for the rest.
#[derive(Debug, Deserialize)]
pub(crate) struct Envelope {
    #[serde(flatten)]
    pub common: CommonFields,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The parsed per-event payload after two-phase deserialization.
#[derive(Debug, Clone)]
pub(crate) enum EventPayload {
    Tool(ToolFields),
    SessionStart(SessionStartFields),
    SessionEnd(SessionEndFields),
    UserPromptSubmit(UserPromptSubmitFields),
    Stop(StopFields),
    StopFailure(StopFailureFields),
    SubagentStart(SubagentStartFields),
    SubagentStop(SubagentStopFields),
    TeammateIdle(TeammateIdleFields),
    TaskCompleted(TaskCompletedFields),
    InstructionsLoaded(InstructionsLoadedFields),
    ConfigChange(ConfigChangeFields),
    PreCompact(PreCompactFields),
    PostCompact(PostCompactFields),
    Notification(NotificationFields),
    Elicitation(ElicitationFields),
    ElicitationResult(ElicitationResultFields),
    WorktreeCreate(WorktreeCreateFields),
    WorktreeRemove(WorktreeRemoveFields),
    /// Unknown event — keep the raw extra map.
    Unknown(serde_json::Map<String, serde_json::Value>),
}

/// Parse the extra fields into the appropriate per-event struct.
pub(crate) fn parse_payload(
    event_name: &str,
    extra: serde_json::Map<String, serde_json::Value>,
) -> EventPayload {
    macro_rules! parse_event {
        ($variant:ident) => {
            serde_json::from_value(serde_json::Value::Object(extra.clone()))
                .map(EventPayload::$variant)
                .unwrap_or(EventPayload::Unknown(extra))
        };
    }
    match event_name {
        "PreToolUse" | "PostToolUse" | "PostToolUseFailure" | "PermissionRequest" => {
            parse_event!(Tool)
        }
        "SessionStart" => parse_event!(SessionStart),
        "SessionEnd" => parse_event!(SessionEnd),
        "UserPromptSubmit" => parse_event!(UserPromptSubmit),
        "Stop" => parse_event!(Stop),
        "StopFailure" => parse_event!(StopFailure),
        "SubagentStart" => parse_event!(SubagentStart),
        "SubagentStop" => parse_event!(SubagentStop),
        "TeammateIdle" => parse_event!(TeammateIdle),
        "TaskCompleted" => parse_event!(TaskCompleted),
        "InstructionsLoaded" => parse_event!(InstructionsLoaded),
        "ConfigChange" => parse_event!(ConfigChange),
        "PreCompact" => parse_event!(PreCompact),
        "PostCompact" => parse_event!(PostCompact),
        "Notification" => parse_event!(Notification),
        "Elicitation" => parse_event!(Elicitation),
        "ElicitationResult" => parse_event!(ElicitationResult),
        "WorktreeCreate" => parse_event!(WorktreeCreate),
        "WorktreeRemove" => parse_event!(WorktreeRemove),
        _ => EventPayload::Unknown(extra),
    }
}

// ── Output (stdout) ──────────────────────────────────────────────────

/// Raw JSON response written to stdout.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawOutput {
    #[serde(rename = "continue")]
    pub should_continue: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
    /// Top-level decision for PostToolUse/Stop/UserPromptSubmit blocking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Reason for a top-level block decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Top-level action for Elicitation responses (accept/decline/cancel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Top-level content for Elicitation accept responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
}

/// The `hookSpecificOutput` object inside a hook response.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision: Option<PreToolUseDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<PermissionDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppress_output: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
}

/// PreToolUse permission decision values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PreToolUseDecision {
    Allow,
    Deny,
    Ask,
}

/// PermissionRequest decision payload.
#[derive(Debug, Clone, Serialize)]
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

/// Behavior in a PermissionRequest decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionBehavior {
    Allow,
    Deny,
}
