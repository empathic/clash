//! Clash policy language: parsing, IR, compilation, and evaluation.
//!
//! Extracted from `clash::policy` to break a circular dep with `clash-lsp`.
//! Policies are authored in Starlark and compiled to a uniform trie IR.
//! Evaluation is a single DFS pass — first match wins.

pub mod compile;
pub mod diff;
pub mod error;
pub mod format;
pub mod ir;
pub mod manifest_edit;
pub mod match_tree;
pub mod path;
pub mod sandbox_edit;
pub mod sandbox_types;
pub mod test_eval;

#[cfg(test)]
mod proptests;

pub use compile::compile_multi_level_to_tree;
pub use error::{CompileError, PolicyError, PolicyParseError};
pub use ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
pub use match_tree::{CompiledPolicy, IncludeEntry, PolicyManifest};

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PolicyLevel — inlined from clash::settings::discovery to avoid a circular dep
// ---------------------------------------------------------------------------

/// Policy level — where a policy file lives in the precedence hierarchy.
///
/// Higher-precedence levels override lower ones: Session > Project > User.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyLevel {
    /// User-level policy: `~/.clash/policy.star`
    User = 0,
    /// Project-level policy: `<project_root>/.clash/policy.star`
    Project = 1,
    /// Session-level policy: `/tmp/clash-<session_id>/policy.star`
    /// Temporary rules that last only for the current Claude Code session.
    Session = 2,
}

impl PolicyLevel {
    /// All persistent levels in precedence order (highest first).
    /// Session is excluded because it requires a session_id to resolve.
    pub fn all_by_precedence() -> &'static [PolicyLevel] {
        &[PolicyLevel::Project, PolicyLevel::User]
    }

    /// Display name for this level.
    pub fn name(&self) -> &'static str {
        match self {
            PolicyLevel::User => "user",
            PolicyLevel::Project => "project",
            PolicyLevel::Session => "session",
        }
    }
}

impl fmt::Display for PolicyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for PolicyLevel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(PolicyLevel::User),
            "project" => Ok(PolicyLevel::Project),
            "session" => Ok(PolicyLevel::Session),
            _ => anyhow::bail!(
                "unknown policy level: {s} (expected 'user', 'project', or 'session')"
            ),
        }
    }
}

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
