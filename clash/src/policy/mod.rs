//! Capability-based policy language with s-expression syntax.
//!
//! Four capability domains: `exec` (commands), `fs` (filesystem), `net` (network), `tool` (agent tools).
//! Rules are `(effect (capability ...))` forms, e.g. `(deny (exec "git" "push" *))`.
//!
//! The policy speaks in capabilities, not Claude Code tool names — the eval
//! layer maps tools to capabilities.

pub mod ast;
pub mod compile;
pub mod decision_tree;
pub mod edit;
pub mod error;
pub mod eval;
pub mod ir;
pub mod parse;
pub mod print;
pub mod sandbox_types;
pub mod sexpr;
pub mod specificity;
pub mod version;

pub use compile::{
    AllShadows, ShadowInfo, compile_multi_level, compile_multi_level_with_internals,
    compile_policy, compile_policy_with_internals, detect_all_shadows,
};
pub use decision_tree::DecisionTree;
pub use error::{CompileError, PolicyError, PolicyParseError};
pub use ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
pub use print::print_tree;

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

impl std::str::FromStr for Effect {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Effect::Allow),
            "deny" => Ok(Effect::Deny),
            "ask" => Ok(Effect::Ask),
            _ => Err(format!("unknown effect: {s:?}")),
        }
    }
}
