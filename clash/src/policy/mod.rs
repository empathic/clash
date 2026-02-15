//! Capability-based policy language with s-expression syntax.
//!
//! Three capability domains: `exec` (commands), `fs` (filesystem), `net` (network).
//! Rules are `(effect (capability ...))` forms, e.g. `(deny (exec "git" "push" *))`.
//!
//! The policy speaks in capabilities, not Claude Code tool names — the eval
//! layer maps tools to capabilities.

pub mod edit;
pub mod error;
pub mod ir;
pub mod sandbox_types;
pub mod sexpr;
pub mod v2;

pub use error::{CompileError, PolicyError, PolicyParseError};
pub use ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};

use std::fmt;

use serde::{Deserialize, Serialize};

/// The effect a statement produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Allow the action without prompting.
    Allow,
    /// Deny the action.
    Deny,
    /// Prompt the user for confirmation.
    Ask,
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::Allow => write!(f, "allow"),
            Effect::Deny => write!(f, "deny"),
            Effect::Ask => write!(f, "ask"),
        }
    }
}
