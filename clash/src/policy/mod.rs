//! Capability-based policy language.
//!
//! Four capability domains: `exec` (commands), `fs` (filesystem), `net` (network), `tool` (agent tools).
//!
//! Policies are authored and stored as JSON. The AST types serve as the
//! serialization IR via serde.

pub mod ast;
pub mod compile;
pub mod decision_tree;
pub mod edit;
pub mod error;
pub mod eval;
pub mod ir;
pub mod print;
pub mod sandbox_types;
pub mod schema;
pub mod specificity;
pub mod tree;

pub use ast::PolicyDocument;
pub use compile::{
    AllShadows, ShadowInfo, compile_document, compile_document_to_tree,
    compile_document_to_tree_with_internals, compile_multi_level_to_tree, detect_all_shadows,
    detect_all_shadows_from_rules,
};
pub use decision_tree::DecisionTree;
pub use error::{CompileError, PolicyError, PolicyParseError};
pub use ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
pub use print::print_tree;
pub use tree::PolicyTree;

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
