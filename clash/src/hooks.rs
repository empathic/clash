//! Claude Code hook types — re-exported from the [`claude_hooks`] crate.
//!
//! The hook protocol types (input, output, tools) live in the standalone
//! `claude_hooks` crate so that external projects can build hook handlers
//! without depending on clash. This module re-exports everything so that
//! existing `crate::hooks::*` imports continue to work.

pub use claude_hooks::input::*;
pub use claude_hooks::output::*;
pub use claude_hooks::tools::{BashInput, EditInput, ReadInput, ToolInput, WriteInput};
pub use claude_hooks::{exit_code, is_interactive_tool};
