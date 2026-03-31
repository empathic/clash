//! Hook event types — one struct per Claude Code hook event.
//!
//! Each event type has methods to construct the correct [`Response`] for that
//! event. The type system prevents returning the wrong response type.

use std::sync::OnceLock;

use crate::response::Response;
use crate::tool_input::*;
use crate::wire::{
    CommonFields, ConfigChangeFields, ElicitationFields, ElicitationResultFields, EventPayload,
    HookSpecificOutput, InstructionsLoadedFields, NotificationFields, PermissionBehavior,
    PermissionDecision, PostCompactFields, PreCompactFields, PreToolUseDecision, RawOutput,
    SessionEndFields, SessionStartFields, StopFailureFields, StopFields, SubagentStartFields,
    SubagentStopFields, TaskCompletedFields, TeammateIdleFields, ToolFields,
    UserPromptSubmitFields, WorktreeCreateFields, WorktreeRemoveFields,
};

// ── Cached tool input ────────────────────────────────────────────────

/// Wrapper that caches the parsed [`ToolInput`] so repeated calls to
/// `.bash()`, `.write()`, etc. don't re-parse from JSON each time.
#[derive(Debug)]
#[doc(hidden)]
pub struct CachedToolInput {
    pub(crate) common: CommonFields,
    pub(crate) fields: ToolFields,
    parsed: OnceLock<ToolInput>,
}

impl CachedToolInput {
    pub(crate) fn new(common: CommonFields, fields: ToolFields) -> Self {
        Self {
            common,
            fields,
            parsed: OnceLock::new(),
        }
    }

    fn typed_tool_input(&self) -> &ToolInput {
        self.parsed.get_or_init(|| {
            let tool_name = self.fields.tool_name.as_deref().unwrap_or("");
            let null = serde_json::Value::Null;
            let tool_input = self.fields.tool_input.as_ref().unwrap_or(&null);
            ToolInput::parse(tool_name, tool_input)
        })
    }
}

// ── HookEvent ────────────────────────────────────────────────────────

/// A hook event received from Claude Code.
///
/// Match on this to determine which event you're handling, then call methods
/// on the inner type to build a [`Response`].
#[derive(Debug)]
#[non_exhaustive]
pub enum HookEvent {
    PreToolUse(PreToolUse),
    PostToolUse(PostToolUse),
    PostToolUseFailure(PostToolUseFailure),
    PermissionRequest(PermissionRequest),
    SessionStart(SessionStart),
    SessionEnd(SessionEnd),
    UserPromptSubmit(UserPromptSubmit),
    Stop(Stop),
    StopFailure(StopFailure),
    SubagentStart(SubagentStart),
    SubagentStop(SubagentStop),
    TeammateIdle(TeammateIdle),
    TaskCompleted(TaskCompleted),
    InstructionsLoaded(InstructionsLoaded),
    ConfigChange(ConfigChange),
    PreCompact(PreCompact),
    PostCompact(PostCompact),
    Notification(Notification),
    Elicitation(Elicitation),
    ElicitationResult(ElicitationResult),
    WorktreeCreate(WorktreeCreate),
    WorktreeRemove(WorktreeRemove),
    /// An event type not recognized by this library version.
    Unknown(RawEvent),
}

impl HookEvent {
    /// Construct from two-phase parsed input.
    pub(crate) fn from_parsed(common: CommonFields, payload: EventPayload) -> Self {
        match payload {
            EventPayload::Tool(fields) => match common.hook_event_name.as_str() {
                "PreToolUse" => HookEvent::PreToolUse(PreToolUse {
                    cached: CachedToolInput::new(common, fields),
                }),
                "PostToolUse" => HookEvent::PostToolUse(PostToolUse {
                    cached: CachedToolInput::new(common, fields),
                }),
                "PostToolUseFailure" => HookEvent::PostToolUseFailure(PostToolUseFailure {
                    cached: CachedToolInput::new(common, fields),
                }),
                "PermissionRequest" => HookEvent::PermissionRequest(PermissionRequest {
                    cached: CachedToolInput::new(common, fields),
                }),
                _ => HookEvent::Unknown(RawEvent {
                    common,
                    extra: serde_json::Map::new(),
                }),
            },
            EventPayload::SessionStart(fields) => {
                HookEvent::SessionStart(SessionStart { common, fields })
            }
            EventPayload::SessionEnd(fields) => {
                HookEvent::SessionEnd(SessionEnd { common, fields })
            }
            EventPayload::UserPromptSubmit(fields) => {
                HookEvent::UserPromptSubmit(UserPromptSubmit { common, fields })
            }
            EventPayload::Stop(fields) => HookEvent::Stop(Stop { common, fields }),
            EventPayload::StopFailure(fields) => {
                HookEvent::StopFailure(StopFailure { common, fields })
            }
            EventPayload::SubagentStart(fields) => {
                HookEvent::SubagentStart(SubagentStart { common, fields })
            }
            EventPayload::SubagentStop(fields) => {
                HookEvent::SubagentStop(SubagentStop { common, fields })
            }
            EventPayload::TeammateIdle(fields) => {
                HookEvent::TeammateIdle(TeammateIdle { common, fields })
            }
            EventPayload::TaskCompleted(fields) => {
                HookEvent::TaskCompleted(TaskCompleted { common, fields })
            }
            EventPayload::InstructionsLoaded(fields) => {
                HookEvent::InstructionsLoaded(InstructionsLoaded { common, fields })
            }
            EventPayload::ConfigChange(fields) => {
                HookEvent::ConfigChange(ConfigChange { common, fields })
            }
            EventPayload::PreCompact(fields) => {
                HookEvent::PreCompact(PreCompact { common, fields })
            }
            EventPayload::PostCompact(fields) => {
                HookEvent::PostCompact(PostCompact { common, fields })
            }
            EventPayload::Notification(fields) => {
                HookEvent::Notification(Notification { common, fields })
            }
            EventPayload::Elicitation(fields) => {
                HookEvent::Elicitation(Elicitation { common, fields })
            }
            EventPayload::ElicitationResult(fields) => {
                HookEvent::ElicitationResult(ElicitationResult { common, fields })
            }
            EventPayload::WorktreeCreate(fields) => {
                HookEvent::WorktreeCreate(WorktreeCreate { common, fields })
            }
            EventPayload::WorktreeRemove(fields) => {
                HookEvent::WorktreeRemove(WorktreeRemove { common, fields })
            }
            EventPayload::Unknown(extra) => HookEvent::Unknown(RawEvent { common, extra }),
        }
    }

    /// The session ID for this event.
    pub fn session_id(&self) -> &str {
        &self.common_ref().session_id
    }

    /// The working directory.
    pub fn cwd(&self) -> &str {
        &self.common_ref().cwd
    }

    /// The hook event name string.
    pub fn hook_event_name(&self) -> &str {
        &self.common_ref().hook_event_name
    }

    fn common_ref(&self) -> &CommonFields {
        match self {
            HookEvent::PreToolUse(e) => &e.cached.common,
            HookEvent::PostToolUse(e) => &e.cached.common,
            HookEvent::PostToolUseFailure(e) => &e.cached.common,
            HookEvent::PermissionRequest(e) => &e.cached.common,
            HookEvent::SessionStart(e) => &e.common,
            HookEvent::SessionEnd(e) => &e.common,
            HookEvent::UserPromptSubmit(e) => &e.common,
            HookEvent::Stop(e) => &e.common,
            HookEvent::StopFailure(e) => &e.common,
            HookEvent::SubagentStart(e) => &e.common,
            HookEvent::SubagentStop(e) => &e.common,
            HookEvent::TeammateIdle(e) => &e.common,
            HookEvent::TaskCompleted(e) => &e.common,
            HookEvent::InstructionsLoaded(e) => &e.common,
            HookEvent::ConfigChange(e) => &e.common,
            HookEvent::PreCompact(e) => &e.common,
            HookEvent::PostCompact(e) => &e.common,
            HookEvent::Notification(e) => &e.common,
            HookEvent::Elicitation(e) => &e.common,
            HookEvent::ElicitationResult(e) => &e.common,
            HookEvent::WorktreeCreate(e) => &e.common,
            HookEvent::WorktreeRemove(e) => &e.common,
            HookEvent::Unknown(e) => &e.common,
        }
    }
}

// ── Shared helpers ───────────────────────────────────────────────────

/// Common fields available on all events.
pub trait HookEventCommon {
    /// Access the common wire fields shared by every event.
    fn common(&self) -> &CommonFields;

    /// The session ID.
    fn session_id(&self) -> &str {
        &self.common().session_id
    }

    /// The working directory.
    fn cwd(&self) -> &str {
        &self.common().cwd
    }

    /// The transcript file path.
    fn transcript_path(&self) -> &str {
        &self.common().transcript_path
    }

    /// The permission mode (e.g., "default", "plan", "bypassPermissions").
    fn permission_mode(&self) -> Option<&str> {
        self.common().permission_mode.as_deref()
    }

    /// The hook event name string.
    fn hook_event_name(&self) -> &str {
        &self.common().hook_event_name
    }

    /// Pass through — tells Claude Code to proceed with default behavior.
    fn pass(&self) -> Response {
        crate::pass()
    }
}

/// Shared tool-event fields and accessors.
pub trait ToolEvent: HookEventCommon {
    /// Access the cached tool input.
    #[doc(hidden)]
    fn cached_tool_input(&self) -> &CachedToolInput;

    /// The tool name (e.g., "Bash", "Read", "Write").
    fn tool_name(&self) -> &str {
        self.cached_tool_input()
            .fields
            .tool_name
            .as_deref()
            .unwrap_or("")
    }

    /// The raw tool input JSON.
    fn tool_input_raw(&self) -> &serde_json::Value {
        static NULL: serde_json::Value = serde_json::Value::Null;
        self.cached_tool_input()
            .fields
            .tool_input
            .as_ref()
            .unwrap_or(&NULL)
    }

    /// The tool use ID.
    fn tool_use_id(&self) -> Option<&str> {
        self.cached_tool_input().fields.tool_use_id.as_deref()
    }

    /// Parse the tool input into a typed [`ToolInput`].
    ///
    /// The result is cached — subsequent calls return a reference to the
    /// same parsed value without re-parsing from JSON.
    fn typed_tool_input(&self) -> &ToolInput {
        self.cached_tool_input().typed_tool_input()
    }

    /// Get typed Bash input, if this is a Bash tool invocation.
    fn bash(&self) -> Option<&BashInput> {
        match self.typed_tool_input() {
            ToolInput::Bash(b) => Some(b),
            _ => None,
        }
    }

    /// Get typed Write input.
    fn write(&self) -> Option<&WriteInput> {
        match self.typed_tool_input() {
            ToolInput::Write(w) => Some(w),
            _ => None,
        }
    }

    /// Get typed Edit input.
    fn edit(&self) -> Option<&EditInput> {
        match self.typed_tool_input() {
            ToolInput::Edit(e) => Some(e),
            _ => None,
        }
    }

    /// Get typed Read input.
    fn read(&self) -> Option<&ReadInput> {
        match self.typed_tool_input() {
            ToolInput::Read(r) => Some(r),
            _ => None,
        }
    }

    /// Get typed Glob input.
    fn glob(&self) -> Option<&GlobInput> {
        match self.typed_tool_input() {
            ToolInput::Glob(g) => Some(g),
            _ => None,
        }
    }

    /// Get typed Grep input.
    fn grep(&self) -> Option<&GrepInput> {
        match self.typed_tool_input() {
            ToolInput::Grep(g) => Some(g),
            _ => None,
        }
    }

    /// Get typed WebFetch input.
    fn web_fetch(&self) -> Option<&WebFetchInput> {
        match self.typed_tool_input() {
            ToolInput::WebFetch(w) => Some(w),
            _ => None,
        }
    }

    /// Get typed WebSearch input.
    fn web_search(&self) -> Option<&WebSearchInput> {
        match self.typed_tool_input() {
            ToolInput::WebSearch(w) => Some(w),
            _ => None,
        }
    }

    /// Get typed NotebookEdit input.
    fn notebook_edit(&self) -> Option<&NotebookEditInput> {
        match self.typed_tool_input() {
            ToolInput::NotebookEdit(n) => Some(n),
            _ => None,
        }
    }

    /// Get typed Skill input.
    fn skill(&self) -> Option<&SkillInput> {
        match self.typed_tool_input() {
            ToolInput::Skill(s) => Some(s),
            _ => None,
        }
    }

    /// Get typed Agent/Task input.
    fn agent(&self) -> Option<&AgentInput> {
        match self.typed_tool_input() {
            ToolInput::Agent(a) => Some(a),
            _ => None,
        }
    }

    /// Returns true if this is an interactive tool (AskUserQuestion,
    /// EnterPlanMode, ExitPlanMode) whose native UI would be skipped
    /// by an allow decision.
    fn is_interactive_tool(&self) -> bool {
        matches!(
            self.tool_name(),
            "AskUserQuestion" | "EnterPlanMode" | "ExitPlanMode"
        )
    }
}

// ── Helper to build responses ────────────────────────────────────────

fn make_hso(event_name: &str) -> HookSpecificOutput {
    HookSpecificOutput {
        hook_event_name: event_name.to_string(),
        permission_decision: None,
        permission_decision_reason: None,
        updated_input: None,
        additional_context: None,
        decision: None,
        suppress_output: None,
        system_message: None,
    }
}

fn hso_response(hso: HookSpecificOutput) -> Response {
    Response(RawOutput {
        should_continue: true,
        hook_specific_output: Some(hso),
        decision: None,
        reason: None,
        action: None,
        content: None,
    })
}

fn context_response(event_name: &str, ctx: impl Into<String>) -> Response {
    let mut hso = make_hso(event_name);
    hso.additional_context = Some(ctx.into());
    hso_response(hso)
}

fn block_response(reason: impl Into<String>) -> Response {
    Response(RawOutput {
        should_continue: true,
        hook_specific_output: None,
        decision: Some("block".to_string()),
        reason: Some(reason.into()),
        action: None,
        content: None,
    })
}

// ── Macros to reduce boilerplate for trait impls ─────────────────────

macro_rules! impl_common {
    ($ty:ident) => {
        impl HookEventCommon for $ty {
            fn common(&self) -> &CommonFields {
                &self.common
            }
        }
    };
}

macro_rules! impl_common_cached {
    ($ty:ident) => {
        impl HookEventCommon for $ty {
            fn common(&self) -> &CommonFields {
                &self.cached.common
            }
        }
    };
}

macro_rules! impl_tool_event {
    ($ty:ident) => {
        impl_common_cached!($ty);
        impl ToolEvent for $ty {
            fn cached_tool_input(&self) -> &CachedToolInput {
                &self.cached
            }
        }
    };
}

// ═══════════════════════════════════════════════════════════════════════
// EVENT TYPES
// ═══════════════════════════════════════════════════════════════════════

// ── PreToolUse ───────────────────────────────────────────────────────

/// Fires before a tool executes. Can allow, deny, ask, or pass through.
#[derive(Debug)]
pub struct PreToolUse {
    pub(crate) cached: CachedToolInput,
}

impl_tool_event!(PreToolUse);

impl PreToolUse {
    /// Allow this tool invocation — bypasses the permission system.
    pub fn allow(&self) -> Response {
        self.allow_with_reason(None::<String>)
    }

    /// Allow with a reason string.
    pub fn allow_with_reason(&self, reason: Option<impl Into<String>>) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Allow);
        hso.permission_decision_reason = reason.map(|r| r.into());
        hso_response(hso)
    }

    /// Deny this tool invocation — prevents execution.
    pub fn deny(&self, reason: impl Into<String>) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Deny);
        hso.permission_decision_reason = Some(reason.into());
        hso_response(hso)
    }

    /// Deny with additional context for Claude.
    pub fn deny_with_context(
        &self,
        reason: impl Into<String>,
        context: impl Into<String>,
    ) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Deny);
        hso.permission_decision_reason = Some(reason.into());
        hso.additional_context = Some(context.into());
        hso_response(hso)
    }

    /// Ask the user for confirmation before executing.
    pub fn ask(&self) -> Response {
        self.ask_with_reason(None::<String>)
    }

    /// Ask with a reason string.
    pub fn ask_with_reason(&self, reason: Option<impl Into<String>>) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Ask);
        hso.permission_decision_reason = reason.map(|r| r.into());
        hso_response(hso)
    }

    /// Allow and rewrite the tool input before execution.
    pub fn allow_with_modified_input(&self, updated_input: serde_json::Value) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Allow);
        hso.updated_input = Some(updated_input);
        hso_response(hso)
    }

    /// Allow with both a reason and additional context.
    pub fn allow_with_context(
        &self,
        reason: Option<impl Into<String>>,
        context: impl Into<String>,
    ) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Allow);
        hso.permission_decision_reason = reason.map(|r| r.into());
        hso.additional_context = Some(context.into());
        hso_response(hso)
    }

    /// Ask with additional context.
    pub fn ask_with_context(
        &self,
        reason: Option<impl Into<String>>,
        context: impl Into<String>,
    ) -> Response {
        let mut hso = make_hso("PreToolUse");
        hso.permission_decision = Some(PreToolUseDecision::Ask);
        hso.permission_decision_reason = reason.map(|r| r.into());
        hso.additional_context = Some(context.into());
        hso_response(hso)
    }
}

// ── PostToolUse ──────────────────────────────────────────────────────

/// Fires after a tool executes successfully.
#[derive(Debug)]
pub struct PostToolUse {
    pub(crate) cached: CachedToolInput,
}

impl_tool_event!(PostToolUse);

impl PostToolUse {
    /// The tool's response (output), if available.
    pub fn tool_response(&self) -> Option<&serde_json::Value> {
        self.cached.fields.tool_response.as_ref()
    }

    /// Provide advisory context to Claude about the tool result.
    pub fn context(&self, ctx: impl Into<String>) -> Response {
        context_response("PostToolUse", ctx)
    }

    /// Block after tool execution (tells Claude to disregard the result).
    pub fn block(&self, reason: impl Into<String>) -> Response {
        block_response(reason)
    }
}

// ── PostToolUseFailure ───────────────────────────────────────────────

/// Fires after a tool fails.
#[derive(Debug)]
pub struct PostToolUseFailure {
    pub(crate) cached: CachedToolInput,
}

impl_tool_event!(PostToolUseFailure);

impl PostToolUseFailure {
    /// The error message from the failed tool.
    pub fn error(&self) -> Option<&str> {
        self.cached.fields.error.as_deref()
    }

    /// Whether this failure was caused by an interrupt.
    pub fn is_interrupt(&self) -> bool {
        self.cached.fields.is_interrupt.unwrap_or(false)
    }

    /// Provide advisory context about the failure.
    pub fn context(&self, ctx: impl Into<String>) -> Response {
        context_response("PostToolUseFailure", ctx)
    }
}

// ── PermissionRequest ────────────────────────────────────────────────

/// Fires when Claude Code's permission dialog would appear.
/// The hook can approve or deny on behalf of the user.
#[derive(Debug)]
pub struct PermissionRequest {
    pub(crate) cached: CachedToolInput,
}

impl_tool_event!(PermissionRequest);

impl PermissionRequest {
    /// Approve the permission request.
    pub fn approve(&self) -> Response {
        self.approve_with_input(None)
    }

    /// Approve and optionally rewrite the tool input.
    pub fn approve_with_input(&self, updated_input: Option<serde_json::Value>) -> Response {
        let mut hso = make_hso("PermissionRequest");
        hso.decision = Some(PermissionDecision {
            behavior: PermissionBehavior::Allow,
            updated_input,
            message: None,
            interrupt: None,
        });
        hso_response(hso)
    }

    /// Deny the permission request.
    pub fn deny(&self, message: impl Into<String>) -> Response {
        let mut hso = make_hso("PermissionRequest");
        hso.decision = Some(PermissionDecision {
            behavior: PermissionBehavior::Deny,
            updated_input: None,
            message: Some(message.into()),
            interrupt: Some(false),
        });
        hso_response(hso)
    }

    /// Deny and interrupt Claude's current turn.
    pub fn deny_and_interrupt(&self, message: impl Into<String>) -> Response {
        let mut hso = make_hso("PermissionRequest");
        hso.decision = Some(PermissionDecision {
            behavior: PermissionBehavior::Deny,
            updated_input: None,
            message: Some(message.into()),
            interrupt: Some(true),
        });
        hso_response(hso)
    }
}

// ── SessionStart ─────────────────────────────────────────────────────

/// Fires when a new session starts, resumes, clears, or compacts.
#[derive(Debug, Clone)]
pub struct SessionStart {
    pub(crate) common: CommonFields,
    pub(crate) fields: SessionStartFields,
}

impl_common!(SessionStart);

impl SessionStart {
    /// The session source (e.g., "startup", "resume", "clear", "compact").
    pub fn source(&self) -> Option<&str> {
        self.fields.source.as_deref()
    }

    /// The model being used.
    pub fn model(&self) -> Option<&str> {
        self.fields.model.as_deref()
    }

    /// Inject context into the session (appears in Claude's system prompt).
    pub fn context(&self, ctx: impl Into<String>) -> Response {
        context_response("SessionStart", ctx)
    }
}

// ── SessionEnd ───────────────────────────────────────────────────────

/// Fires when a session ends.
#[derive(Debug, Clone)]
pub struct SessionEnd {
    pub(crate) common: CommonFields,
    pub(crate) fields: SessionEndFields,
}

impl_common!(SessionEnd);

impl SessionEnd {
    /// The exit reason (e.g., "clear", "resume", "logout").
    pub fn reason(&self) -> Option<&str> {
        self.fields.reason.as_deref()
    }
}

// ── UserPromptSubmit ─────────────────────────────────────────────────

/// Fires when the user submits a prompt.
#[derive(Debug, Clone)]
pub struct UserPromptSubmit {
    pub(crate) common: CommonFields,
    pub(crate) fields: UserPromptSubmitFields,
}

impl_common!(UserPromptSubmit);

impl UserPromptSubmit {
    /// The submitted prompt text.
    pub fn prompt(&self) -> Option<&str> {
        self.fields.prompt.as_deref()
    }

    /// Block this prompt from being processed.
    pub fn block(&self, reason: impl Into<String>) -> Response {
        block_response(reason)
    }

    /// Inject additional context alongside the prompt.
    pub fn context(&self, ctx: impl Into<String>) -> Response {
        context_response("UserPromptSubmit", ctx)
    }
}

// ── Stop ─────────────────────────────────────────────────────────────

/// Fires when Claude finishes responding.
#[derive(Debug, Clone)]
pub struct Stop {
    pub(crate) common: CommonFields,
    pub(crate) fields: StopFields,
}

impl_common!(Stop);

impl Stop {
    /// Whether a stop hook is currently active.
    pub fn stop_hook_active(&self) -> bool {
        self.fields.stop_hook_active.unwrap_or(false)
    }

    /// Claude's last assistant message.
    pub fn last_assistant_message(&self) -> Option<&str> {
        self.fields.last_assistant_message.as_deref()
    }

    /// Force Claude to continue the conversation instead of stopping.
    pub fn block(&self, reason: impl Into<String>) -> Response {
        block_response(reason)
    }
}

// ── StopFailure ──────────────────────────────────────────────────────

/// Fires when a turn ends due to an API error.
#[derive(Debug, Clone)]
pub struct StopFailure {
    pub(crate) common: CommonFields,
    pub(crate) fields: StopFailureFields,
}

impl_common!(StopFailure);

impl StopFailure {
    /// The error type (e.g., "rate_limit", "authentication_failed").
    pub fn error(&self) -> Option<&str> {
        self.fields.error.as_deref()
    }

    /// Additional error details.
    pub fn error_details(&self) -> Option<&serde_json::Value> {
        self.fields.error_details.as_ref()
    }

    /// Claude's last assistant message before the failure.
    pub fn last_assistant_message(&self) -> Option<&str> {
        self.fields.last_assistant_message.as_deref()
    }
}

// ── SubagentStart ────────────────────────────────────────────────────

/// Fires when a subagent is spawned.
#[derive(Debug, Clone)]
pub struct SubagentStart {
    pub(crate) common: CommonFields,
    pub(crate) fields: SubagentStartFields,
}

impl_common!(SubagentStart);

impl SubagentStart {
    /// The subagent's ID.
    pub fn agent_id(&self) -> Option<&str> {
        self.fields.agent_id.as_deref()
    }

    /// The subagent's type.
    pub fn agent_type(&self) -> Option<&str> {
        self.fields.agent_type.as_deref()
    }

    /// Inject context for the subagent.
    pub fn context(&self, ctx: impl Into<String>) -> Response {
        context_response("SubagentStart", ctx)
    }
}

// ── SubagentStop ─────────────────────────────────────────────────────

/// Fires when a subagent finishes.
#[derive(Debug, Clone)]
pub struct SubagentStop {
    pub(crate) common: CommonFields,
    pub(crate) fields: SubagentStopFields,
}

impl_common!(SubagentStop);

impl SubagentStop {
    /// The subagent's ID.
    pub fn agent_id(&self) -> Option<&str> {
        self.fields.agent_id.as_deref()
    }

    /// The subagent's type.
    pub fn agent_type(&self) -> Option<&str> {
        self.fields.agent_type.as_deref()
    }

    /// The subagent's transcript path.
    pub fn agent_transcript_path(&self) -> Option<&str> {
        self.fields.agent_transcript_path.as_deref()
    }

    /// The subagent's last assistant message.
    pub fn last_assistant_message(&self) -> Option<&str> {
        self.fields.last_assistant_message.as_deref()
    }

    /// Block the subagent's completion.
    pub fn block(&self, reason: impl Into<String>) -> Response {
        block_response(reason)
    }
}

// ── TeammateIdle ─────────────────────────────────────────────────────

/// Fires when an agent team teammate becomes idle.
#[derive(Debug, Clone)]
pub struct TeammateIdle {
    pub(crate) common: CommonFields,
    pub(crate) fields: TeammateIdleFields,
}

impl_common!(TeammateIdle);

impl TeammateIdle {
    pub fn teammate_name(&self) -> Option<&str> {
        self.fields.teammate_name.as_deref()
    }

    pub fn team_name(&self) -> Option<&str> {
        self.fields.team_name.as_deref()
    }
}

// ── TaskCompleted ────────────────────────────────────────────────────

/// Fires when a task is marked complete.
#[derive(Debug, Clone)]
pub struct TaskCompleted {
    pub(crate) common: CommonFields,
    pub(crate) fields: TaskCompletedFields,
}

impl_common!(TaskCompleted);

impl TaskCompleted {
    pub fn teammate_name(&self) -> Option<&str> {
        self.fields.teammate_name.as_deref()
    }

    pub fn team_name(&self) -> Option<&str> {
        self.fields.team_name.as_deref()
    }

    pub fn task_id(&self) -> Option<&str> {
        self.fields.task_id.as_deref()
    }

    pub fn task_subject(&self) -> Option<&str> {
        self.fields.task_subject.as_deref()
    }

    pub fn task_description(&self) -> Option<&str> {
        self.fields.task_description.as_deref()
    }
}

// ── InstructionsLoaded ───────────────────────────────────────────────

/// Fires when CLAUDE.md or similar instructions are loaded.
#[derive(Debug, Clone)]
pub struct InstructionsLoaded {
    pub(crate) common: CommonFields,
    pub(crate) fields: InstructionsLoadedFields,
}

impl_common!(InstructionsLoaded);

impl InstructionsLoaded {
    pub fn file_path(&self) -> Option<&str> {
        self.fields.file_path.as_deref()
    }

    pub fn memory_type(&self) -> Option<&str> {
        self.fields.memory_type.as_deref()
    }

    pub fn load_reason(&self) -> Option<&str> {
        self.fields.load_reason.as_deref()
    }
}

// ── ConfigChange ─────────────────────────────────────────────────────

/// Fires when a settings file changes.
#[derive(Debug, Clone)]
pub struct ConfigChange {
    pub(crate) common: CommonFields,
    pub(crate) fields: ConfigChangeFields,
}

impl_common!(ConfigChange);

impl ConfigChange {
    /// The config source (e.g., "user_settings", "project_settings").
    pub fn source(&self) -> Option<&str> {
        self.fields.source.as_deref()
    }

    pub fn file_path(&self) -> Option<&str> {
        self.fields.file_path.as_deref()
    }

    /// Block the config change.
    pub fn block(&self, reason: impl Into<String>) -> Response {
        block_response(reason)
    }
}

// ── PreCompact / PostCompact ─────────────────────────────────────────

/// Fires before context compaction.
#[derive(Debug, Clone)]
pub struct PreCompact {
    pub(crate) common: CommonFields,
    pub(crate) fields: PreCompactFields,
}

impl_common!(PreCompact);

impl PreCompact {
    /// What triggered compaction (e.g., "manual", "auto").
    pub fn trigger(&self) -> Option<&str> {
        self.fields.trigger.as_deref()
    }

    pub fn custom_instructions(&self) -> Option<&str> {
        self.fields.custom_instructions.as_deref()
    }
}

/// Fires after context compaction.
#[derive(Debug, Clone)]
pub struct PostCompact {
    pub(crate) common: CommonFields,
    pub(crate) fields: PostCompactFields,
}

impl_common!(PostCompact);

impl PostCompact {
    pub fn trigger(&self) -> Option<&str> {
        self.fields.trigger.as_deref()
    }

    pub fn compact_summary(&self) -> Option<&str> {
        self.fields.compact_summary.as_deref()
    }
}

// ── Notification ─────────────────────────────────────────────────────

/// Fires when Claude Code sends a notification.
#[derive(Debug, Clone)]
pub struct Notification {
    pub(crate) common: CommonFields,
    pub(crate) fields: NotificationFields,
}

impl_common!(Notification);

impl Notification {
    pub fn message(&self) -> Option<&str> {
        self.fields.message.as_deref()
    }

    pub fn title(&self) -> Option<&str> {
        self.fields.title.as_deref()
    }

    pub fn notification_type(&self) -> Option<&str> {
        self.fields.notification_type.as_deref()
    }

    /// Provide advisory context.
    pub fn context(&self, ctx: impl Into<String>) -> Response {
        context_response("Notification", ctx)
    }
}

// ── Elicitation ──────────────────────────────────────────────────────

/// Fires when an MCP server requests user input.
#[derive(Debug, Clone)]
pub struct Elicitation {
    pub(crate) common: CommonFields,
    pub(crate) fields: ElicitationFields,
}

impl_common!(Elicitation);

impl Elicitation {
    pub fn mcp_server_name(&self) -> Option<&str> {
        self.fields.mcp_server_name.as_deref()
    }

    pub fn message(&self) -> Option<&str> {
        self.fields.message.as_deref()
    }

    pub fn elicitation_id(&self) -> Option<&str> {
        self.fields.elicitation_id.as_deref()
    }

    pub fn requested_schema(&self) -> Option<&serde_json::Value> {
        self.fields.requested_schema.as_ref()
    }

    /// Accept the elicitation with content.
    pub fn accept(&self, content: serde_json::Value) -> Response {
        Response(RawOutput {
            should_continue: true,
            hook_specific_output: None,
            decision: None,
            reason: None,
            action: Some("accept".to_string()),
            content: Some(content),
        })
    }

    /// Decline the elicitation.
    pub fn decline(&self) -> Response {
        Response(RawOutput {
            should_continue: true,
            hook_specific_output: None,
            decision: None,
            reason: None,
            action: Some("decline".to_string()),
            content: None,
        })
    }

    /// Cancel the elicitation.
    pub fn cancel(&self) -> Response {
        Response(RawOutput {
            should_continue: true,
            hook_specific_output: None,
            decision: None,
            reason: None,
            action: Some("cancel".to_string()),
            content: None,
        })
    }
}

// ── ElicitationResult ────────────────────────────────────────────────

/// Fires when the user responds to an MCP elicitation.
#[derive(Debug, Clone)]
pub struct ElicitationResult {
    pub(crate) common: CommonFields,
    pub(crate) fields: ElicitationResultFields,
}

impl_common!(ElicitationResult);

impl ElicitationResult {
    pub fn mcp_server_name(&self) -> Option<&str> {
        self.fields.mcp_server_name.as_deref()
    }

    pub fn action(&self) -> Option<&str> {
        self.fields.action.as_deref()
    }

    pub fn content(&self) -> Option<&serde_json::Value> {
        self.fields.content.as_ref()
    }
}

// ── WorktreeCreate ───────────────────────────────────────────────────

/// Fires when a git worktree is created.
#[derive(Debug, Clone)]
pub struct WorktreeCreate {
    pub(crate) common: CommonFields,
    pub(crate) fields: WorktreeCreateFields,
}

impl_common!(WorktreeCreate);

impl WorktreeCreate {
    pub fn name(&self) -> Option<&str> {
        self.fields.name.as_deref()
    }
}

// ── WorktreeRemove ───────────────────────────────────────────────────

/// Fires when a git worktree is removed.
#[derive(Debug, Clone)]
pub struct WorktreeRemove {
    pub(crate) common: CommonFields,
    pub(crate) fields: WorktreeRemoveFields,
}

impl_common!(WorktreeRemove);

impl WorktreeRemove {
    pub fn worktree_path(&self) -> Option<&str> {
        self.fields.worktree_path.as_deref()
    }
}

// ── Unknown ──────────────────────────────────────────────────────────

/// An event type not recognized by this library version.
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub(crate) common: CommonFields,
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

impl_common!(RawEvent);

impl RawEvent {
    /// Access any extra fields not modeled by this library.
    pub fn extra(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.extra
    }
}

// ═══════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn pre_tool_use_json() -> &'static str {
        r#"{
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status", "timeout": 120000},
            "tool_use_id": "toolu_01ABC"
        }"#
    }

    fn session_start_json() -> &'static str {
        r#"{
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-sonnet-4-20250514"
        }"#
    }

    #[test]
    fn test_recv_pre_tool_use() {
        let event = crate::recv_from(pre_tool_use_json().as_bytes()).unwrap();
        match event {
            HookEvent::PreToolUse(e) => {
                assert_eq!(e.session_id(), "test-session");
                assert_eq!(e.tool_name(), "Bash");
                let bash = e.bash().unwrap();
                assert_eq!(bash.command, "git status");
            }
            other => panic!("expected PreToolUse, got {:?}", other),
        }
    }

    #[test]
    fn test_recv_session_start() {
        let event = crate::recv_from(session_start_json().as_bytes()).unwrap();
        match event {
            HookEvent::SessionStart(e) => {
                assert_eq!(e.session_id(), "test-session");
                assert_eq!(e.source(), Some("startup"));
                assert_eq!(e.model(), Some("claude-sonnet-4-20250514"));
            }
            other => panic!("expected SessionStart, got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_event() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "hook_event_name": "FutureEvent", "new_field": 42
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        assert!(matches!(event, HookEvent::Unknown(_)));
    }

    #[test]
    fn test_allow_response_serialization() {
        let event = crate::recv_from(pre_tool_use_json().as_bytes()).unwrap();
        let response = match event {
            HookEvent::PreToolUse(e) => e.allow(),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["continue"], true);
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
    }

    #[test]
    fn test_deny_response_serialization() {
        let event = crate::recv_from(pre_tool_use_json().as_bytes()).unwrap();
        let response = match event {
            HookEvent::PreToolUse(e) => e.deny("not allowed"),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "not allowed"
        );
    }

    #[test]
    fn test_permission_request_approve() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "permission_mode": "default",
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        let response = match event {
            HookEvent::PermissionRequest(e) => e.approve(),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");
    }

    #[test]
    fn test_permission_request_deny() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "permission_mode": "default",
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"}
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        let response = match event {
            HookEvent::PermissionRequest(e) => e.deny_and_interrupt("absolutely not"),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["decision"]["message"],
            "absolutely not"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["interrupt"], true);
    }

    #[test]
    fn test_session_start_context() {
        let event = crate::recv_from(session_start_json().as_bytes()).unwrap();
        let response = match event {
            HookEvent::SessionStart(e) => e.context("Hook is active"),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert_eq!(
            json["hookSpecificOutput"]["additionalContext"],
            "Hook is active"
        );
    }

    #[test]
    fn test_pass_through() {
        let response = crate::pass();
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["continue"], true);
        assert!(json.get("hookSpecificOutput").is_none());
    }

    #[test]
    fn test_post_tool_use_context() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"output": "file1 file2"}
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        let response = match event {
            HookEvent::PostToolUse(e) => {
                assert!(e.tool_response().is_some());
                e.context("observed ls output")
            }
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            out["hookSpecificOutput"]["additionalContext"],
            "observed ls output"
        );
    }

    #[test]
    fn test_typed_write_input() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.txt", "content": "hello"}
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        match event {
            HookEvent::PreToolUse(e) => {
                let w = e.write().unwrap();
                assert_eq!(w.file_path, "/tmp/test.txt");
                assert_eq!(w.content, "hello");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_interactive_tool_detection() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "AskUserQuestion",
            "tool_input": {}
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        match event {
            HookEvent::PreToolUse(e) => {
                assert!(e.is_interactive_tool());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_elicitation_accept_serializes_action_and_content() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "hook_event_name": "Elicitation",
            "mcp_server_name": "test-mcp",
            "message": "Enter your API key",
            "elicitation_id": "elic_01"
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        let response = match event {
            HookEvent::Elicitation(e) => e.accept(serde_json::json!({"api_key": "sk-123"})),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(out["continue"], true);
        assert_eq!(out["action"], "accept");
        assert_eq!(out["content"]["api_key"], "sk-123");
        // Should NOT have decision field
        assert!(out.get("decision").is_none());
    }

    #[test]
    fn test_elicitation_decline_serialization() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "hook_event_name": "Elicitation"
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        let response = match event {
            HookEvent::Elicitation(e) => e.decline(),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(out["action"], "decline");
        assert!(out.get("content").is_none());
    }

    #[test]
    fn test_elicitation_cancel_serialization() {
        let json = r#"{
            "session_id": "s", "transcript_path": "t", "cwd": "c",
            "hook_event_name": "Elicitation"
        }"#;
        let event = crate::recv_from(json.as_bytes()).unwrap();
        let response = match event {
            HookEvent::Elicitation(e) => e.cancel(),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let out: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(out["action"], "cancel");
    }

    #[test]
    fn test_response_with_context_builder() {
        let event = crate::recv_from(pre_tool_use_json().as_bytes()).unwrap();
        let response = match event {
            HookEvent::PreToolUse(e) => e.allow().with_context("sandbox active"),
            _ => unreachable!(),
        };
        let mut buf = Vec::new();
        crate::send_to(&response, &mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["additionalContext"],
            "sandbox active"
        );
    }
}
