//! The opaque [`Response`] type that serializes to correct Claude Code JSON.
//!
//! You never construct a `Response` directly — instead, call methods on event
//! types (e.g., `pre_tool_use.allow()`) or use [`crate::pass()`].

use crate::wire::RawOutput;

/// An opaque hook response that serializes to the correct JSON wire format.
///
/// Built via methods on event types or [`crate::pass()`]. Cannot be constructed
/// directly by library consumers.
#[derive(Debug, Clone)]
pub struct Response(pub(crate) RawOutput);

impl Response {
    /// Set advisory context that Claude sees after this hook runs.
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        if let Some(ref mut hso) = self.0.hook_specific_output {
            hso.additional_context = Some(ctx.into());
        }
        self
    }

    /// Set a system message (warning to the user, shown in the UI).
    pub fn with_system_message(mut self, msg: impl Into<String>) -> Self {
        if let Some(ref mut hso) = self.0.hook_specific_output {
            hso.system_message = Some(msg.into());
        }
        self
    }

    /// Suppress this hook's stdout from verbose mode output.
    pub fn suppress_output(mut self) -> Self {
        if let Some(ref mut hso) = self.0.hook_specific_output {
            hso.suppress_output = Some(true);
        }
        self
    }

    /// Access the underlying wire output (for advanced use or testing).
    pub fn as_raw(&self) -> &RawOutput {
        &self.0
    }
}
