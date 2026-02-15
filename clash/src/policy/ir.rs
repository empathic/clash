//! Intermediate representation (IR) types for compiled policies.
//!
//! These are the shared decision types used by both the v2 policy engine
//! and the rest of the system (permissions, audit, handlers).

use crate::policy::Effect;
use crate::policy::sandbox_types::SandboxPolicy;

/// The result of evaluating a policy.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: Option<String>,
    /// Structured trace of how this decision was reached.
    pub trace: DecisionTrace,
    /// Per-command sandbox policy generated from sandbox references.
    /// Only present for bash (Execute) commands that matched allow rules with sandbox.
    pub sandbox: Option<SandboxPolicy>,
}

impl PolicyDecision {
    /// Render the decision trace as a list of human-readable strings.
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
    /// Index of the rule in the rule list.
    pub rule_index: usize,
    /// Human-readable description of the rule.
    pub description: String,
    /// The effect this rule produces.
    pub effect: Effect,
    /// Whether this rule had inline constraints that were actively checked.
    pub has_active_constraints: bool,
}

/// A rule that was skipped during evaluation.
#[derive(Debug, Clone)]
pub struct RuleSkip {
    /// Index of the rule in the rule list.
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
    /// Rules that matched the request.
    pub matched_rules: Vec<RuleMatch>,
    /// Rules that were considered but skipped.
    pub skipped_rules: Vec<RuleSkip>,
    /// Summary of how the final effect was determined.
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
    if reason.contains("pattern mismatch") {
        format!(
            "Rule '{}' was skipped: pattern does not match this request",
            rule_desc
        )
    } else if reason.contains("verb mismatch") {
        format!(
            "Rule '{}' was skipped: does not apply to this tool",
            rule_desc
        )
    } else {
        format!("Rule '{}' was skipped: {}", rule_desc, reason)
    }
}

/// Convert a final resolution string into human-readable English.
fn humanize_resolution(resolution: &str) -> String {
    if resolution.contains("deny") && resolution.contains("deny > ask > allow") {
        "Final decision: deny (deny rules take precedence over allow/ask). Use /clash:explain for details or /clash:edit to modify.".into()
    } else if resolution == "result: allow" {
        "Final decision: allow".into()
    } else if resolution.starts_with("no rules matched")
        || resolution.starts_with("no capability query")
    {
        let default = resolution.rsplit("default: ").next().unwrap_or("ask");
        format!(
            "No rules matched this action. Defaulting to {}. Use /clash:edit to add a rule for this action.",
            default
        )
    } else if resolution.starts_with("result: ") {
        let effect = resolution.strip_prefix("result: ").unwrap_or(resolution);
        format!("Final decision: {}", effect)
    } else if resolution.starts_with("resolved ") {
        let effect = resolution
            .strip_prefix("resolved ")
            .and_then(|s| s.split(' ').next())
            .unwrap_or(resolution);
        format!("Final decision: {} (multiple rules matched)", effect)
    } else {
        resolution.to_string()
    }
}
