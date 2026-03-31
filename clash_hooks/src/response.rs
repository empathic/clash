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
    ///
    /// # Panics (debug builds only)
    /// Panics if called on a response that has no `hookSpecificOutput`
    /// (e.g. a `pass()`, `block()`, or elicitation response).
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        debug_assert!(
            self.0.hook_specific_output.is_some(),
            "with_context() called on a response with no hookSpecificOutput — data would be silently dropped"
        );
        if let Some(ref mut hso) = self.0.hook_specific_output {
            hso.additional_context = Some(ctx.into());
        }
        self
    }

    /// Set a system message (warning to the user, shown in the UI).
    ///
    /// # Panics (debug builds only)
    /// Panics if called on a response that has no `hookSpecificOutput`.
    pub fn with_system_message(mut self, msg: impl Into<String>) -> Self {
        debug_assert!(
            self.0.hook_specific_output.is_some(),
            "with_system_message() called on a response with no hookSpecificOutput — data would be silently dropped"
        );
        if let Some(ref mut hso) = self.0.hook_specific_output {
            hso.system_message = Some(msg.into());
        }
        self
    }

    /// Suppress this hook's stdout from verbose mode output.
    ///
    /// # Panics (debug builds only)
    /// Panics if called on a response that has no `hookSpecificOutput`.
    pub fn suppress_output(mut self) -> Self {
        debug_assert!(
            self.0.hook_specific_output.is_some(),
            "suppress_output() called on a response with no hookSpecificOutput — data would be silently dropped"
        );
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

#[cfg(test)]
mod tests {
    #[test]
    #[should_panic(expected = "with_context() called on a response with no hookSpecificOutput")]
    fn test_with_context_panics_on_pass() {
        crate::pass().with_context("should panic");
    }
}
