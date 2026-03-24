//! Build [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) handlers in Rust.
//!
//! This crate provides the types and traits needed to implement Claude Code hooks.
//! Hooks let external programs intercept tool invocations, enforce policies,
//! inject context, and control permissions in a Claude Code session.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use claude_hooks::{HookHandler, HookOutput, ToolUseHookInput, SessionStartHookInput, StopHookInput};
//!
//! struct MyHook;
//!
//! impl HookHandler for MyHook {
//!     fn pre_tool_use(&self, input: &ToolUseHookInput) -> anyhow::Result<HookOutput> {
//!         if input.tool_name == "Bash" {
//!             // Deny all Bash invocations
//!             Ok(HookOutput::deny("Bash is not allowed".into(), None))
//!         } else {
//!             Ok(HookOutput::allow(None, None))
//!         }
//!     }
//! }
//!
//! fn main() -> anyhow::Result<()> {
//!     claude_hooks::main(MyHook)
//! }
//! ```
//!
//! Then register in `.claude/settings.json`:
//!
//! ```json
//! {
//!   "hooks": {
//!     "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "my-hook pre-tool-use" }] }],
//!     "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "my-hook post-tool-use" }] }]
//!   }
//! }
//! ```
//!
//! Or generate the full configuration with [`hooks_json`].
//!
//! # Hook lifecycle
//!
//! Claude Code fires hooks at these points:
//!
//! | Event | When | Your handler can |
//! |---|---|---|
//! | **PreToolUse** | Before a tool executes | Allow, deny, ask, or rewrite the input |
//! | **PostToolUse** | After a tool executes | Inject advisory context for Claude |
//! | **PermissionRequest** | User confirmation needed | Approve or deny on behalf of user |
//! | **SessionStart** | Session begins | Inject setup context |
//! | **Stop** | Turn ends without tool call | Perform cleanup |

pub mod input;
pub mod output;
pub mod tools;

// ---------------------------------------------------------------------------
// Re-exports — the most common types at crate root
// ---------------------------------------------------------------------------

pub use input::{HookInput, SessionStartHookInput, StopHookInput, ToolUseHookInput};
pub use output::{
    HookOutput, HookSpecificOutput, PermissionBehavior, PermissionDecision,
    PermissionRequestOutput, PermissionRule, PostToolUseOutput, PreToolUseOutput,
    SessionStartOutput, exit_code,
};
pub use tools::{
    BashInput, EditInput, GlobInput, GrepInput, ReadInput, ToolInput, WebFetchInput,
    WebSearchInput, WriteInput,
};

/// Re-export of [`tools::is_interactive`] under the legacy name used by clash.
pub use tools::is_interactive as is_interactive_tool;

// ---------------------------------------------------------------------------
// HookEvent
// ---------------------------------------------------------------------------

/// Hook events that Claude Code can fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookEvent {
    PreToolUse,
    PostToolUse,
    PermissionRequest,
    SessionStart,
    Stop,
}

impl HookEvent {
    /// All hook event types.
    pub const ALL: &[HookEvent] = &[
        HookEvent::PreToolUse,
        HookEvent::PostToolUse,
        HookEvent::PermissionRequest,
        HookEvent::SessionStart,
        HookEvent::Stop,
    ];

    /// The event name as used in `hooks.json` (PascalCase).
    pub fn as_str(&self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "PreToolUse",
            HookEvent::PostToolUse => "PostToolUse",
            HookEvent::PermissionRequest => "PermissionRequest",
            HookEvent::SessionStart => "SessionStart",
            HookEvent::Stop => "Stop",
        }
    }

    /// The subcommand name (kebab-case), suitable for CLI arguments.
    pub fn subcommand(&self) -> &'static str {
        match self {
            HookEvent::PreToolUse => "pre-tool-use",
            HookEvent::PostToolUse => "post-tool-use",
            HookEvent::PermissionRequest => "permission-request",
            HookEvent::SessionStart => "session-start",
            HookEvent::Stop => "stop",
        }
    }

    /// Parse from either PascalCase or kebab-case.
    pub fn parse(s: &str) -> Option<HookEvent> {
        match s {
            "PreToolUse" | "pre-tool-use" => Some(HookEvent::PreToolUse),
            "PostToolUse" | "post-tool-use" => Some(HookEvent::PostToolUse),
            "PermissionRequest" | "permission-request" => Some(HookEvent::PermissionRequest),
            "SessionStart" | "session-start" => Some(HookEvent::SessionStart),
            "Stop" | "stop" => Some(HookEvent::Stop),
            _ => None,
        }
    }
}

impl std::fmt::Display for HookEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HookHandler trait
// ---------------------------------------------------------------------------

/// Trait for implementing Claude Code hook handlers.
///
/// All methods have default implementations that pass through (continue execution
/// without making a decision). Override only the events you care about.
///
/// # Example
///
/// ```rust
/// use claude_hooks::{HookHandler, HookOutput, ToolUseHookInput, SessionStartHookInput, StopHookInput};
///
/// struct AuditHook;
///
/// impl HookHandler for AuditHook {
///     fn pre_tool_use(&self, input: &ToolUseHookInput) -> anyhow::Result<HookOutput> {
///         eprintln!("[audit] {} invoked in {}", input.tool_name, input.cwd);
///         Ok(HookOutput::continue_execution())
///     }
/// }
/// ```
pub trait HookHandler {
    /// Handle a PreToolUse event. Return a permission decision.
    fn pre_tool_use(&self, _input: &ToolUseHookInput) -> anyhow::Result<HookOutput> {
        Ok(HookOutput::continue_execution())
    }

    /// Handle a PostToolUse event. Return optional advisory context.
    fn post_tool_use(&self, _input: &ToolUseHookInput) -> anyhow::Result<HookOutput> {
        Ok(HookOutput::continue_execution())
    }

    /// Handle a PermissionRequest event. Approve or deny on behalf of the user.
    fn permission_request(&self, _input: &ToolUseHookInput) -> anyhow::Result<HookOutput> {
        Ok(HookOutput::continue_execution())
    }

    /// Handle a SessionStart event. Return optional setup context.
    fn session_start(&self, _input: &SessionStartHookInput) -> anyhow::Result<HookOutput> {
        Ok(HookOutput::continue_execution())
    }

    /// Handle a Stop event. Perform any cleanup.
    fn stop(&self, _input: &StopHookInput) -> anyhow::Result<HookOutput> {
        Ok(HookOutput::continue_execution())
    }
}

// ---------------------------------------------------------------------------
// Runner functions
// ---------------------------------------------------------------------------

/// Run a hook handler for the given event name.
///
/// Reads JSON input from stdin, dispatches to the appropriate handler method,
/// and writes JSON output to stdout.
///
/// Accepts both PascalCase (`"PreToolUse"`) and kebab-case (`"pre-tool-use"`).
pub fn run(event: &str, handler: &impl HookHandler) -> anyhow::Result<()> {
    let hook_event = HookEvent::parse(event).ok_or_else(|| {
        // Drain stdin to avoid broken pipe
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
        anyhow::anyhow!("unknown hook event: {event}")
    })?;

    let output = match hook_event {
        HookEvent::PreToolUse => {
            let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
            handler.pre_tool_use(&input)?
        }
        HookEvent::PostToolUse => {
            let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
            handler.post_tool_use(&input)?
        }
        HookEvent::PermissionRequest => {
            let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
            handler.permission_request(&input)?
        }
        HookEvent::SessionStart => {
            let input = SessionStartHookInput::from_reader(std::io::stdin().lock())?;
            handler.session_start(&input)?
        }
        HookEvent::Stop => {
            let input = StopHookInput::from_reader(std::io::stdin().lock())?;
            handler.stop(&input)?
        }
    };

    output.write_stdout()
}

/// Parse the event name from CLI arguments and run the handler.
///
/// Expects the event name as the first positional argument.
/// Accepts both PascalCase (`"PreToolUse"`) and kebab-case (`"pre-tool-use"`).
///
/// # Example
///
/// ```rust,no_run
/// use claude_hooks::{HookHandler, HookOutput, ToolUseHookInput, SessionStartHookInput, StopHookInput};
///
/// struct MyHook;
/// impl HookHandler for MyHook {}
///
/// fn main() -> anyhow::Result<()> {
///     claude_hooks::main(MyHook)
/// }
/// ```
///
/// Then register hooks like `"command": "my-hook pre-tool-use"`.
pub fn main(handler: impl HookHandler) -> anyhow::Result<()> {
    let event = std::env::args().nth(1).ok_or_else(|| {
        anyhow::anyhow!(
            "usage: <command> <event>\n\nevents: {}",
            HookEvent::ALL
                .iter()
                .map(|e| e.subcommand())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    run(&event, &handler)
}

// ---------------------------------------------------------------------------
// hooks.json generation
// ---------------------------------------------------------------------------

/// Generate a hooks configuration for the given command and events.
///
/// Returns a JSON object suitable for the `"hooks"` field of
/// `.claude/settings.json` or a plugin's `hooks/hooks.json`.
///
/// # Example
///
/// ```rust
/// use claude_hooks::{HookEvent, hooks_json};
///
/// // Register all events
/// let config = hooks_json("my-hook", HookEvent::ALL);
///
/// // Register only PreToolUse
/// let config = hooks_json("my-hook", &[HookEvent::PreToolUse]);
/// ```
pub fn hooks_json(command: &str, events: &[HookEvent]) -> serde_json::Value {
    let mut hooks = serde_json::Map::new();
    for event in events {
        hooks.insert(
            event.as_str().to_string(),
            serde_json::json!([{
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": format!("{command} {}", event.subcommand())
                }]
            }]),
        );
    }
    serde_json::json!({ "hooks": serde_json::Value::Object(hooks) })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_event_roundtrip() {
        for event in HookEvent::ALL {
            assert_eq!(HookEvent::parse(event.as_str()), Some(*event));
            assert_eq!(HookEvent::parse(event.subcommand()), Some(*event));
        }
    }

    #[test]
    fn hook_event_unknown() {
        assert_eq!(HookEvent::parse("NotAHook"), None);
    }

    #[test]
    fn hooks_json_generates_all_events() {
        let config = hooks_json("my-hook", HookEvent::ALL);
        let hooks = config["hooks"].as_object().unwrap();
        assert_eq!(hooks.len(), 5);
        assert!(hooks.contains_key("PreToolUse"));
        assert!(hooks.contains_key("PostToolUse"));
        assert!(hooks.contains_key("PermissionRequest"));
        assert!(hooks.contains_key("SessionStart"));
        assert!(hooks.contains_key("Stop"));

        // Check command format
        let pre = &hooks["PreToolUse"][0]["hooks"][0];
        assert_eq!(pre["command"], "my-hook pre-tool-use");
        assert_eq!(pre["type"], "command");
    }

    #[test]
    fn hooks_json_selective_events() {
        let config = hooks_json("test", &[HookEvent::PreToolUse, HookEvent::SessionStart]);
        let hooks = config["hooks"].as_object().unwrap();
        assert_eq!(hooks.len(), 2);
        assert!(hooks.contains_key("PreToolUse"));
        assert!(hooks.contains_key("SessionStart"));
    }

    #[test]
    fn default_handler_continues() {
        struct Noop;
        impl HookHandler for Noop {}

        let handler = Noop;
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            ..Default::default()
        };
        let output = handler.pre_tool_use(&input).unwrap();
        assert_eq!(output, HookOutput::continue_execution());
    }
}
