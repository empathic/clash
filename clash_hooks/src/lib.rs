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
        let response = f(event)
            .map_err(|e| Error::Output(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
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
