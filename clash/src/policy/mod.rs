//! Match-tree policy language.
//!
//! Policies are authored in Starlark and compiled to a uniform trie IR.
//! Evaluation is a single DFS pass — first match wins.

pub mod compile;
pub mod error;
pub mod ir;
pub mod manifest_edit;
pub mod match_tree;
pub mod path;
pub mod sandbox_edit;
pub mod sandbox_types;

pub use compile::compile_multi_level_to_tree;
pub use error::{CompileError, PolicyError, PolicyParseError};
pub use ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
pub use match_tree::{CompiledPolicy, IncludeEntry, PolicyManifest};

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
