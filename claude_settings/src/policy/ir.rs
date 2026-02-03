//! Intermediate representation (IR) types for compiled policies.
//!
//! These are the runtime representations produced by compiling
//! a `PolicyDocument` AST. They contain pre-compiled regexes
//! and flattened profile rules for efficient evaluation.

use std::collections::HashMap;

use regex::Regex;

use super::{DelegateConfig, Effect, ProfileExpr, VerbPattern};
use crate::sandbox::{Cap, NetworkPolicy, SandboxPolicy};

/// A compiled policy ready for fast evaluation.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Default effect when no statement matches.
    pub default: Effect,
    /// Compiled statements in evaluation order (legacy format).
    pub statements: Vec<CompiledStatement>,
    /// Compiled constraint definitions (name → compiled constraint) — legacy format.
    pub(crate) constraints: HashMap<String, CompiledConstraintDef>,
    /// Profile definitions (name → profile expression) — legacy format.
    pub(crate) profiles: HashMap<String, ProfileExpr>,
    /// Flattened rules from the active profile (new format).
    /// When non-empty, evaluation uses this path instead of legacy statements.
    pub(crate) active_profile_rules: Vec<CompiledProfileRule>,
}

/// A compiled statement with pre-compiled matchers.
#[derive(Debug)]
pub struct CompiledStatement {
    pub effect: Effect,
    pub entity_matcher: CompiledPattern,
    pub verb_matcher: VerbPattern,
    pub noun_matcher: CompiledPattern,
    pub reason: Option<String>,
    pub delegate: Option<DelegateConfig>,
    /// Optional constraint binding (profile expression).
    pub profile: Option<ProfileExpr>,
}

/// A compiled constraint definition with pre-compiled regexes.
#[derive(Debug)]
pub(crate) struct CompiledConstraintDef {
    pub(crate) fs: Option<CompiledFilterExpr>,
    pub(crate) caps: Option<Cap>,
    pub(crate) network: Option<NetworkPolicy>,
    pub(crate) pipe: Option<bool>,
    pub(crate) redirect: Option<bool>,
    pub(crate) forbid_args: Option<Vec<String>>,
    pub(crate) require_args: Option<Vec<String>>,
}

/// A compiled filter expression with pre-compiled regexes.
#[derive(Debug)]
pub(crate) enum CompiledFilterExpr {
    Subpath(String),
    Literal(String),
    Regex(Regex),
    And(Box<CompiledFilterExpr>, Box<CompiledFilterExpr>),
    Or(Box<CompiledFilterExpr>, Box<CompiledFilterExpr>),
    Not(Box<CompiledFilterExpr>),
}

/// A compiled rule from the new profile-based format.
#[derive(Debug)]
pub(crate) struct CompiledProfileRule {
    pub(crate) effect: Effect,
    /// Raw verb string for matching (e.g. "bash", "safe-read", "*").
    pub(crate) verb: String,
    pub(crate) noun_matcher: CompiledPattern,
    pub(crate) constraints: Option<CompiledInlineConstraints>,
}

/// Compiled inline constraints for a new-format profile rule.
#[derive(Debug)]
pub(crate) struct CompiledInlineConstraints {
    /// Cap-scoped filesystem entries.
    pub(crate) fs: Option<Vec<(Cap, CompiledFilterExpr)>>,
    pub(crate) forbid_args: Vec<String>,
    pub(crate) require_args: Vec<String>,
    pub(crate) network: Option<NetworkPolicy>,
    pub(crate) pipe: Option<bool>,
    pub(crate) redirect: Option<bool>,
}

/// A compiled pattern (potentially negated).
#[derive(Debug)]
pub enum CompiledPattern {
    Match(CompiledMatchExpr),
    Not(CompiledMatchExpr),
}

/// A compiled match expression with pre-compiled regex for globs.
#[derive(Debug)]
pub enum CompiledMatchExpr {
    Any,
    Exact(String),
    Glob {
        pattern: String,
        regex: Regex,
    },
    Typed {
        entity_type: String,
        name: Option<String>,
    },
}

/// The result of evaluating a policy.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: Option<String>,
    /// Trace of how this decision was reached: which rules matched, which
    /// constraints passed/failed, and the final precedence logic.
    pub explanation: Vec<String>,
    pub delegate: Option<DelegateConfig>,
    /// Per-command sandbox policy generated from `fs`/`caps`/`network` constraints.
    /// Only present for bash (Execute) commands that matched allow rules with `fs` constraints.
    pub sandbox: Option<SandboxPolicy>,
}
