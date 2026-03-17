//! Claude Code tool definitions and input schemas.
//!
//! This module is the canonical source of truth for well-known Claude Code tools,
//! their parameter schemas, and typed input structs. Other modules (TUI, hooks,
//! policy engine) should reference this module rather than maintaining their own
//! tool lists.

pub mod tools;
