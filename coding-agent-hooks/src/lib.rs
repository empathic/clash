//! Agent-agnostic hook protocol types and adapters for AI coding agents.
//!
//! This crate provides the building blocks for writing hook-based middleware
//! that works with any AI coding agent (Claude Code, Gemini CLI, Codex CLI,
//! Amazon Q, OpenCode, Copilot CLI, etc.).
//!
//! # Core Concepts
//!
//! - [`AgentKind`] identifies which agent is calling.
//! - [`HookProtocol`](protocol::HookProtocol) abstracts agent-specific JSON formats.
//! - [`ToolUseHookInput`](input::ToolUseHookInput) and friends are the normalized
//!   input types parsed from any agent's hook JSON.
//! - [`HookOutput`](output::HookOutput) is a structured response type (used
//!   directly by Claude Code; other agents convert via protocol methods).
//! - Tool and permission-mode name resolution normalizes across agents.
//!
//! # Adding a New Agent
//!
//! Implement [`HookProtocol`](protocol::HookProtocol) — only two methods are
//! required (`agent` and `parse_tool_use`). Add entries to the tool and mode
//! alias tables in [`agents`] so policy evaluation uses consistent names.

pub mod agents;
pub mod input;
pub mod output;
pub mod protocol;

// Re-export core types at the crate root for convenience.
pub use agents::AgentKind;
pub use input::{HookInput, SessionStartHookInput, StopHookInput, ToolUseHookInput};
pub use output::{
    Effect, HookOutput, HookSpecificOutput, PermissionBehavior, PermissionDecision,
    PermissionRequestOutput, PostToolUseOutput, PreToolUseOutput, SessionStartOutput,
};
pub use protocol::HookProtocol;
