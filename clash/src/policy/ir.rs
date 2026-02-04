//! Intermediate representation (IR) types for compiled policies.
//!
//! These are the runtime representations produced by compiling
//! a `PolicyDocument` AST. They contain pre-compiled regexes
//! and flattened profile rules for efficient evaluation.

use std::collections::HashMap;

use regex::Regex;

use super::{Effect, ProfileExpr};
use crate::policy::sandbox_types::{Cap, NetworkPolicy, SandboxPolicy};

/// A compiled policy ready for fast evaluation.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Default effect when no rule matches.
    pub default: Effect,
    /// Compiled constraint definitions (name → compiled constraint).
    pub(crate) constraints: HashMap<String, CompiledConstraintDef>,
    /// Profile definitions (name → profile expression).
    pub(crate) profiles: HashMap<String, ProfileExpr>,
    /// Unified rule list for evaluation. Contains both legacy-converted rules
    /// (with entity_matcher/profile_guard) and new-format profile rules.
    pub(crate) active_profile_rules: Vec<CompiledProfileRule>,
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
///
/// Also used to represent converted legacy `Statement`s after Step 1.8,
/// enabling a single unified evaluation path.
#[derive(Debug)]
pub(crate) struct CompiledProfileRule {
    pub(crate) effect: Effect,
    /// Raw verb string for matching (e.g. "bash", "safe-read", "*").
    pub(crate) verb: String,
    pub(crate) noun_matcher: CompiledPattern,
    pub(crate) constraints: Option<CompiledInlineConstraints>,
    /// Entity matcher — `None` means match all entities (new-format rules).
    /// `Some(pattern)` used by legacy-converted rules to filter by entity.
    pub(crate) entity_matcher: Option<CompiledPattern>,
    /// Human-readable reason (from legacy rules, included in deny/ask decisions).
    pub(crate) reason: Option<String>,
    /// Profile guard expression (from legacy rules with constraint bindings).
    /// Evaluated at runtime via `check_profile()` against `constraints`/`profiles` maps.
    pub(crate) profile_guard: Option<ProfileExpr>,
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
    /// Structured trace of how this decision was reached.
    pub trace: DecisionTrace,
    /// Per-command sandbox policy generated from `fs`/`caps`/`network` constraints.
    /// Only present for bash (Execute) commands that matched allow rules with `fs` constraints.
    pub sandbox: Option<SandboxPolicy>,
}

impl PolicyDecision {
    /// Render the decision trace as a list of human-readable strings.
    /// Backward-compatible with the old `explanation: Vec<String>` field.
    /// Used for audit logs and structured tracing.
    pub fn explanation(&self) -> Vec<String> {
        self.trace.render()
    }

    /// Render the decision trace as human-readable English.
    /// Intended for display to users and AI agents via `additional_context`.
    pub fn human_explanation(&self) -> Vec<String> {
        self.trace.render_human()
    }
}

/// A rule that matched during evaluation.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Index of the rule in `active_profile_rules`.
    pub rule_index: usize,
    /// Human-readable description of the rule.
    pub description: String,
    /// The effect this rule produces.
    pub effect: Effect,
}

/// A rule that was skipped during evaluation.
#[derive(Debug, Clone)]
pub struct RuleSkip {
    /// Index of the rule in `active_profile_rules`.
    pub rule_index: usize,
    /// Human-readable description of the rule.
    pub description: String,
    /// Why this rule was skipped.
    pub reason: String,
}

/// Structured trace of a policy evaluation.
///
/// Records which rules matched, which were skipped and why,
/// and how the final decision was resolved.
#[derive(Debug, Clone)]
pub struct DecisionTrace {
    /// Rules that matched the request (entity/verb/noun/constraints all passed).
    pub matched_rules: Vec<RuleMatch>,
    /// Rules that were considered but skipped (constraint failure, entity mismatch, etc.).
    pub skipped_rules: Vec<RuleSkip>,
    /// Summary of how the final effect was determined (e.g. "deny > ask > allow").
    pub final_resolution: String,
}

impl DecisionTrace {
    /// Render the trace as a list of human-readable strings.
    /// Used for audit logs and structured tracing.
    pub fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for skip in &self.skipped_rules {
            lines.push(format!("skipped: {} ({})", skip.description, skip.reason));
        }
        for m in &self.matched_rules {
            lines.push(format!("matched: {}", m.description));
        }
        lines.push(self.final_resolution.clone());
        lines
    }

    /// Render the trace as clear, human-readable English.
    /// Intended for display to users and AI agents.
    pub fn render_human(&self) -> Vec<String> {
        let mut lines = Vec::new();

        for skip in &self.skipped_rules {
            let human_reason = humanize_skip_reason(&skip.description, &skip.reason);
            lines.push(human_reason);
        }

        for m in &self.matched_rules {
            lines.push(format!(
                "Rule '{}' matched — action {}",
                m.description,
                match m.effect {
                    Effect::Allow => "allowed",
                    Effect::Deny => "denied",
                    Effect::Ask => "requires approval",
                }
            ));
        }

        lines.push(humanize_resolution(&self.final_resolution));
        lines
    }
}

/// Convert a skip reason into human-readable English.
fn humanize_skip_reason(rule_desc: &str, reason: &str) -> String {
    if reason.contains("fs guard:") && reason.contains("does not match filter for") {
        // Extract cap name from "fs guard: '/path' does not match filter for X cap"
        let cap = reason
            .rsplit("for ")
            .next()
            .and_then(|s| s.strip_suffix(" cap"))
            .unwrap_or("the requested");
        let path = reason.split('\'').nth(1).unwrap_or("the path");
        format!(
            "Rule '{}' was skipped: '{}' is outside the allowed filesystem scope for {} operations",
            rule_desc, path, cap
        )
    } else if reason.contains("verb mismatch") {
        format!(
            "Rule '{}' was skipped: does not apply to this tool",
            rule_desc
        )
    } else if reason.contains("entity mismatch") {
        format!(
            "Rule '{}' was skipped: does not apply to this entity",
            rule_desc
        )
    } else if reason.contains("noun mismatch") {
        format!(
            "Rule '{}' was skipped: pattern does not match this command/path",
            rule_desc
        )
    } else if reason.contains("pipe constraint") {
        format!(
            "Rule '{}' was skipped: command contains a pipe operator which is not allowed",
            rule_desc
        )
    } else if reason.contains("redirect constraint") {
        format!(
            "Rule '{}' was skipped: command contains a redirect operator which is not allowed",
            rule_desc
        )
    } else if reason.contains("forbid-args") {
        format!(
            "Rule '{}' was skipped: command contains a forbidden argument",
            rule_desc
        )
    } else if reason.contains("require-args") {
        format!(
            "Rule '{}' was skipped: command is missing a required argument",
            rule_desc
        )
    } else if reason.starts_with("constraint failed:") {
        let detail = reason.strip_prefix("constraint failed: ").unwrap_or(reason);
        format!(
            "Rule '{}' was skipped: constraint not satisfied ({})",
            rule_desc, detail
        )
    } else {
        format!("Rule '{}' was skipped: {}", rule_desc, reason)
    }
}

/// Convert a final resolution string into human-readable English.
fn humanize_resolution(resolution: &str) -> String {
    if resolution.contains("deny") && resolution.contains("deny > ask > allow") {
        "Final decision: deny (deny rules take precedence over allow/ask)".into()
    } else if resolution.contains("ask") && resolution.contains("ask > allow") {
        "Final decision: ask (ask rules take precedence over allow)".into()
    } else if resolution == "result: allow" {
        "Final decision: allow".into()
    } else if resolution.starts_with("no rules matched") {
        let default = resolution.rsplit("default: ").next().unwrap_or("ask");
        format!("No rules matched this action. Defaulting to {}.", default)
    } else {
        // Fallback: pass through
        resolution.to_string()
    }
}
