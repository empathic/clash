//! Shared formatting helpers for human-readable and JSON policy output.
//!
//! Centralises the display patterns used by `cmd::explain`, `debug::replay`,
//! and `debug::sandbox` so that each call-site only needs to join/print the
//! returned `Vec<String>` lines.

use crate::policy::ir::PolicyDecision;
use crate::policy::sandbox_types::SandboxPolicy;
use crate::style;

/// Format the "Input:" header block (tool + noun).
pub fn format_tool_header(
    title: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
) -> Vec<String> {
    vec![
        style::bold(title).to_string(),
        format!("  {}   {}", style::cyan("tool:"), tool_name),
        format!("  {}   {}", style::cyan("arguments:"), arguments),
    ]
}

/// Format a policy decision: effect, reason, matched/skipped rules, resolution.
pub fn format_decision(decision: &PolicyDecision) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(format!(
        "{} {}",
        style::bold("Decision:"),
        style::effect(&decision.effect.to_string())
    ));
    if let Some(ref reason) = decision.reason {
        lines.push(format!("{} {}", style::bold("Reason:  "), reason));
    }
    lines.push(String::new());

    if !decision.trace.matched_rules.is_empty() {
        lines.push(style::header("Matched rules:").to_string());
        for m in &decision.trace.matched_rules {
            let eff = style::effect(&m.effect.to_string());
            lines.push(format!("  [{}] {} -> {}", m.rule_index, m.description, eff));
        }
        lines.push(String::new());
    }

    if !decision.trace.skipped_rules.is_empty() {
        lines.push(style::dim("Skipped rules:").to_string());
        for s in &decision.trace.skipped_rules {
            lines.push(format!(
                "  {} {} {}",
                style::dim(&format!("[{}]", s.rule_index)),
                style::dim(&s.description),
                style::dim(&format!("({})", s.reason))
            ));
        }
        lines.push(String::new());
    }

    lines.push(format!(
        "{} {}",
        style::bold("Resolution:"),
        style::effect(&decision.trace.final_resolution)
    ));

    lines
}

/// Format a sandbox policy summary (default caps, network, rules).
pub fn format_sandbox_summary(sandbox: &SandboxPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "  {}: {}",
        style::cyan("default"),
        sandbox.default.short()
    ));
    lines.push(format!(
        "  {}: {:?}",
        style::cyan("network"),
        sandbox.network
    ));
    for rule in &sandbox.rules {
        use crate::policy::sandbox_types::PathMatch;
        let path_display = match rule.path_match {
            PathMatch::Subpath => format!("{}/**", rule.path),
            PathMatch::ChildOf => format!("{}/*", rule.path),
            PathMatch::Regex => format!("{} (regex)", rule.path),
            PathMatch::Literal => rule.path.clone(),
        };
        lines.push(format!(
            "  {:?} {} in {}",
            rule.effect,
            rule.caps.short(),
            path_display
        ));
    }
    lines
}

/// Build the standard JSON representation of a policy decision.
pub fn decision_to_json(decision: &PolicyDecision) -> serde_json::Value {
    serde_json::json!({
        "effect": format!("{}", decision.effect),
        "reason": decision.reason,
        "matched_rules": decision.trace.matched_rules.iter().map(|m| {
            serde_json::json!({
                "rule_index": m.rule_index,
                "description": m.description,
                "effect": format!("{}", m.effect),
            })
        }).collect::<Vec<_>>(),
        "skipped_rules": decision.trace.skipped_rules.iter().map(|s| {
            serde_json::json!({
                "rule_index": s.rule_index,
                "description": s.description,
                "reason": s.reason,
            })
        }).collect::<Vec<_>>(),
        "resolution": decision.trace.final_resolution,
        "sandbox": decision.sandbox.as_ref().map(|s| serde_json::to_value(s).ok()),
    })
}

/// Colorize an effect string that may have a trailing suffix.
///
/// For example, `"allow (sandbox: test)"` will colour the `"allow"` prefix
/// green and leave `" (sandbox: test)"` unstyled.  This replaces the inline
/// reimplementation that was previously in `cmd::status::colorize_tree_line`.
pub fn colorize_effect_prefix(text: &str) -> String {
    if let Some(rest) = text.strip_prefix("allow") {
        format!("{}{}", style::green("allow"), rest)
    } else if let Some(rest) = text.strip_prefix("deny") {
        format!("{}{}", style::red("deny"), rest)
    } else if let Some(rest) = text.strip_prefix("ask") {
        format!("{}{}", style::yellow("ask"), rest)
    } else {
        text.to_string()
    }
}
