//! Hook input/output types for the agent hook protocol.
//!
//! This module re-exports the core types from [`coding_agent_hooks`] and adds
//! clash-specific extensions (typed tool input parsing, interactive tool
//! classification).

// Re-export everything from the shared crate so existing `use crate::hooks::*`
// paths continue to work.
pub use coding_agent_hooks::input::*;
pub use coding_agent_hooks::output::*;

// Clash-specific typed tool input parsing.
pub use crate::claude::tools::{BashInput, EditInput, ReadInput, ToolInput, WriteInput};

/// Extension trait adding clash-specific methods to [`ToolUseHookInput`].
pub trait ToolUseHookInputExt {
    /// Get typed tool input based on tool_name.
    ///
    /// Delegates to [`crate::claude::tools::ToolInput::parse`] for the
    /// canonical tool-name -> typed-struct mapping.
    fn typed_tool_input(&self) -> crate::claude::tools::ToolInput;
}

impl ToolUseHookInputExt for ToolUseHookInput {
    fn typed_tool_input(&self) -> crate::claude::tools::ToolInput {
        crate::claude::tools::ToolInput::parse(&self.tool_name, self.tool_input.clone())
    }
}

/// Tools that require user interaction via the agent's native UI.
/// Auto-approving these would skip the interaction, so non-deny
/// decisions are converted to passthrough.
pub fn is_interactive_tool(tool_name: &str) -> bool {
    crate::claude::tools::is_interactive(tool_name)
}
