//! Type-safe Rust library for Claude Code hooks.
//!
//! This crate models the complete Claude Code hooks protocol — the stdin/stdout
//! JSON pipe that Claude Code uses to communicate with hook processes. It
//! provides:
//!
//! - **[`recv()`]** / **[`send()`]** — read an event from stdin, write a response to stdout
//! - **Event types** — one struct per hook event, each with typed response constructors
//! - **Tool input accessors** — `event.bash()`, `event.write()`, etc.
//! - **[`Response`]** — opaque type that serializes to the correct JSON wire format
//!
//! # Quick start
//!
//! ```no_run
//! use clash_hooks::{recv, send, HookEvent, HookEventCommon, ToolEvent};
//!
//! fn main() -> Result<(), clash_hooks::Error> {
//!     let event = recv()?;
//!     let response = match event {
//!         HookEvent::PreToolUse(e) => {
//!             if e.bash().is_some_and(|b| b.command.contains("rm -rf /")) {
//!                 e.deny("nope")
//!             } else {
//!                 e.pass()
//!             }
//!         }
//!         HookEvent::SessionStart(e) => e.context("My hook is active."),
//!         _ => clash_hooks::pass(),
//!     };
//!     send(&response)?;
//!     Ok(())
//! }
//! ```
//!
//! # Design
//!
//! Every event type has its own response constructors, so you **cannot** return
//! a SessionStart response from a PreToolUse handler — the type system prevents
//! it. The [`Response`] type is opaque; you build it via methods on event
//! structs and it serializes correctly.
//!
//! All event and tool input types are `#[non_exhaustive]`, so new fields added
//! by future Claude Code versions won't break your code.

pub mod event;
pub mod response;
pub mod tool_input;
pub mod wire;

pub use event::{HookEvent, HookEventCommon, ToolEvent};
pub use response::Response;
pub use tool_input::{
    AgentInput, BashInput, EditInput, GlobInput, GrepInput, NotebookEditInput, ReadInput,
    SkillInput, ToolInput, WebFetchInput, WebSearchInput, WriteInput,
};
pub use wire::{CommonFields, PreToolUseDecision};

use std::io::{Read, Write};

/// Errors from parsing hook input or writing hook output.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Failed to parse hook input JSON from stdin.
    #[error("failed to parse hook input: {0}")]
    InvalidInput(#[from] serde_json::Error),

    /// Failed to write hook response to stdout.
    #[error("failed to write hook response: {0}")]
    Output(#[from] std::io::Error),
}

/// Exit codes defined by the Claude Code hooks protocol.
pub mod exit_code {
    /// Success — response JSON was written to stdout.
    pub const SUCCESS: i32 = 0;
    /// Blocking error — stderr message is fed back to Claude as context.
    pub const BLOCKING_ERROR: i32 = 2;
}

// ── Core API ────────────────────────────────────────────────────────

/// Read a hook event from stdin.
///
/// This reads the full JSON object that Claude Code writes to the hook
/// process's stdin, and returns the appropriate [`HookEvent`] variant.
pub fn recv() -> Result<HookEvent, Error> {
    recv_from(std::io::stdin().lock())
}

/// Read a hook event from any [`Read`] source (useful for testing).
pub fn recv_from(reader: impl Read) -> Result<HookEvent, Error> {
    let envelope: wire::Envelope = serde_json::from_reader(reader)?;
    let payload = wire::parse_payload(&envelope.common.hook_event_name, envelope.extra);
    Ok(HookEvent::from_parsed(envelope.common, payload))
}

/// Parse a hook event from an already-deserialized JSON [`serde_json::Value`].
///
/// This is the key enabler for non-Claude agent protocols: normalize their
/// JSON to Claude convention, then feed it through this function for typed
/// deserialization.
pub fn recv_from_value(value: serde_json::Value) -> Result<HookEvent, Error> {
    let envelope: wire::Envelope = serde_json::from_value(value)?;
    let payload = wire::parse_payload(&envelope.common.hook_event_name, envelope.extra);
    Ok(HookEvent::from_parsed(envelope.common, payload))
}

/// Write a hook response to stdout.
pub fn send(response: &Response) -> Result<(), Error> {
    send_to(response, std::io::stdout().lock())
}

/// Write a hook response to any [`Write`] sink (useful for testing).
pub fn send_to(response: &Response, mut writer: impl Write) -> Result<(), Error> {
    serde_json::to_writer(&mut writer, &response.0)?;
    writeln!(writer)?;
    Ok(())
}

/// Convenience: a pass-through response that works for any event.
///
/// Equivalent to `continue_execution` — tells Claude Code to proceed with
/// default behavior.
pub fn pass() -> Response {
    Response(wire::RawOutput {
        should_continue: true,
        hook_specific_output: None,
        decision: None,
        reason: None,
        action: None,
        content: None,
    })
}

/// Run a hook with proper exit code handling.
///
/// Reads an event from stdin, calls `f`, writes the response to stdout on
/// success, or prints the error to stderr and exits with
/// [`exit_code::BLOCKING_ERROR`] on failure.
///
/// This function never returns.
pub fn main(
    f: impl FnOnce(HookEvent) -> Result<Response, Box<dyn std::error::Error + Send + Sync>>,
) -> ! {
    let result = (|| {
        let event = recv()?;
        let response = f(event).map_err(|e| Error::Output(std::io::Error::other(e)))?;
        send(&response)?;
        Ok::<(), Error>(())
    })();

    match result {
        Ok(()) => std::process::exit(exit_code::SUCCESS),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(exit_code::BLOCKING_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_from_value_round_trips_pre_tool_use() {
        let json = serde_json::json!({
            "session_id": "test-session",
            "transcript_path": "/tmp/transcript.jsonl",
            "cwd": "/home/user/project",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
            "tool_use_id": "toolu_01"
        });
        let event = recv_from_value(json).unwrap();
        match event {
            HookEvent::PreToolUse(e) => {
                assert_eq!(e.session_id(), "test-session");
                assert_eq!(e.tool_name(), "Bash");
                assert_eq!(e.bash().unwrap().command, "git status");
            }
            other => panic!("expected PreToolUse, got {other:?}"),
        }
    }

    #[test]
    fn recv_from_value_round_trips_session_start() {
        let json = serde_json::json!({
            "session_id": "s1",
            "transcript_path": "/tmp/t.jsonl",
            "cwd": "/tmp",
            "hook_event_name": "SessionStart",
            "source": "startup",
            "model": "claude-sonnet-4-20250514"
        });
        let event = recv_from_value(json).unwrap();
        match event {
            HookEvent::SessionStart(e) => {
                assert_eq!(e.session_id(), "s1");
                assert_eq!(e.source(), Some("startup"));
                assert_eq!(e.model(), Some("claude-sonnet-4-20250514"));
            }
            other => panic!("expected SessionStart, got {other:?}"),
        }
    }

    #[test]
    fn recv_from_value_matches_recv_from() {
        let json = serde_json::json!({
            "session_id": "s",
            "transcript_path": "t",
            "cwd": "c",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/f.txt", "content": "hi"}
        });
        // recv_from_value
        let event = recv_from_value(json.clone()).unwrap();
        let response = match event {
            HookEvent::PreToolUse(e) => e.allow(),
            _ => unreachable!(),
        };
        let mut buf_val = Vec::new();
        send_to(&response, &mut buf_val).unwrap();

        // recv_from (via bytes)
        let bytes = serde_json::to_vec(&json).unwrap();
        let event2 = recv_from(bytes.as_slice()).unwrap();
        let response2 = match event2 {
            HookEvent::PreToolUse(e) => e.allow(),
            _ => unreachable!(),
        };
        let mut buf_from = Vec::new();
        send_to(&response2, &mut buf_from).unwrap();

        assert_eq!(buf_val, buf_from);
    }
}
