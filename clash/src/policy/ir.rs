//! Intermediate representation (IR) types for compiled policies.
//!
//! These are the shared decision types used by the policy engine
//! and the rest of the system (permissions, audit, handlers).

use crate::policy::Effect;
use crate::policy::match_tree::SandboxRef;
use crate::policy::sandbox_types::SandboxPolicy;

/// The result of evaluating a policy.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: Option<String>,
    /// Structured trace of how this decision was reached.
    pub trace: DecisionTrace,
    /// Per-command sandbox policy generated from sandbox references.
    pub sandbox: Option<SandboxPolicy>,
    pub sandbox_name: Option<SandboxRef>,
}

impl PolicyDecision {
    /// Render the decision trace as a list of human-readable strings.
    pub fn explanation(&self) -> Vec<String> {
        self.trace.render()
    }

    /// Render the decision trace as human-readable English.
    pub fn human_explanation(&self) -> Vec<String> {
        self.trace.render_human()
    }
}

/// A rule that matched during evaluation.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_index: usize,
    pub description: String,
    pub effect: Effect,
    pub has_active_constraints: bool,
    /// Optional node ID for trace lookups.
    pub node_id: Option<u32>,
}

/// A rule that was skipped during evaluation.
#[derive(Debug, Clone)]
pub struct RuleSkip {
    pub rule_index: usize,
    pub description: String,
    pub reason: String,
}

/// Structured trace of a policy evaluation.
#[derive(Debug, Clone)]
pub struct DecisionTrace {
    pub matched_rules: Vec<RuleMatch>,
    pub skipped_rules: Vec<RuleSkip>,
    pub final_resolution: String,
}

impl DecisionTrace {
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

    pub fn render_human(&self) -> Vec<String> {
        let mut lines = Vec::new();

        for skip in &self.skipped_rules {
            lines.push(format!(
                "Rule '{}' was skipped: {}",
                skip.description,
                if skip.reason.contains("pattern mismatch") {
                    "pattern does not match this request"
                } else {
                    &skip.reason
                }
            ));
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

        let resolution = &self.final_resolution;
        if resolution.starts_with("result: ") {
            let effect = resolution.strip_prefix("result: ").unwrap_or(resolution);
            lines.push(format!("Final decision: {}", effect));
        } else if resolution.starts_with("no rules matched") {
            let default = resolution.rsplit("default: ").next().unwrap_or("ask");
            lines.push(format!("No rules matched. Defaulting to {}.", default));
        } else {
            lines.push(resolution.to_string());
        }

        lines
    }
}
