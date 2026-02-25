//! Command replay: re-evaluate tool invocations against the current policy.
//!
//! Takes a tool invocation (from CLI args, JSON stdin, or audit log) and
//! evaluates it against the current compiled policy, showing the full
//! decision trace, sandbox policy, and actionable suggestions.

use anyhow::{Context, Result};

use crate::policy::eval::CapQuery;
use crate::policy::ir::PolicyDecision;
use crate::policy::sandbox_types::SandboxPolicy;
use crate::policy::DecisionTree;
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

/// The result of replaying a tool invocation.
pub struct ReplayResult {
    /// The tool name that was evaluated.
    pub tool_name: String,
    /// Human-readable noun (command, path, domain, etc.).
    pub noun: String,
    /// The policy decision.
    pub decision: PolicyDecision,
    /// Whether multiple policy levels are active.
    pub multi_level: bool,
    /// Reference to the decision tree (for origin lookups).
    tree: DecisionTree,
}

impl ReplayResult {
    /// Render as human-readable text.
    pub fn format_human(&self) -> String {
        let mut lines = Vec::new();

        // Input summary
        lines.push(style::bold("Input:").to_string());
        lines.push(format!(
            "  {}   {}",
            style::cyan("tool:"),
            self.tool_name
        ));
        lines.push(format!("  {}   {}", style::cyan("noun:"), self.noun));
        lines.push(String::new());

        // Decision
        lines.push(format!(
            "{} {}",
            style::bold("Decision:"),
            style::effect(&self.decision.effect.to_string())
        ));
        if let Some(ref reason) = self.decision.reason {
            lines.push(format!("{} {}", style::bold("Reason:  "), reason));
        }

        // Level (if multi-level)
        if self.multi_level
            && let Some(first_match) = self.decision.trace.matched_rules.first()
                && let Some(level) = self.find_origin_level(first_match) {
                    lines.push(format!(
                        "{} {}",
                        style::bold("Level:   "),
                        style::cyan(&level.to_string())
                    ));
                }
        lines.push(String::new());

        // Matched rules
        if !self.decision.trace.matched_rules.is_empty() {
            lines.push(style::header("Matched rules:").to_string());
            for m in &self.decision.trace.matched_rules {
                let eff = style::effect(&m.effect.to_string());
                if self.multi_level {
                    if let Some(level) = self.find_origin_level(m) {
                        lines.push(format!(
                            "  [{}] {} {} -> {}",
                            m.rule_index,
                            style::cyan(&format!("[{}]", level)),
                            m.description,
                            eff
                        ));
                    } else {
                        lines.push(format!(
                            "  [{}] {} -> {}",
                            m.rule_index, m.description, eff
                        ));
                    }
                } else {
                    lines.push(format!(
                        "  [{}] {} -> {}",
                        m.rule_index, m.description, eff
                    ));
                }
            }
            lines.push(String::new());
        }

        // Skipped rules
        if !self.decision.trace.skipped_rules.is_empty() {
            lines.push(style::dim("Skipped rules:").to_string());
            for s in &self.decision.trace.skipped_rules {
                lines.push(format!(
                    "  {} {} {}",
                    style::dim(&format!("[{}]", s.rule_index)),
                    style::dim(&s.description),
                    style::dim(&format!("({})", s.reason))
                ));
            }
            lines.push(String::new());
        }

        // Resolution
        lines.push(format!(
            "{} {}",
            style::bold("Resolution:"),
            style::effect(&self.decision.trace.final_resolution)
        ));

        // Sandbox policy
        if let Some(ref sandbox) = self.decision.sandbox {
            lines.push(String::new());
            lines.push(style::header("Sandbox policy:").to_string());
            format_sandbox_summary(&mut lines, sandbox);
        }

        // Actionable suggestion for denials
        if self.decision.effect == crate::policy::Effect::Deny {
            lines.push(String::new());
            lines.push(format!(
                "{} {}",
                style::bold("To allow this:"),
                style::cyan(&self.suggest_allow_command())
            ));
        }

        lines.join("\n")
    }

    /// Render as JSON.
    pub fn format_json(&self) -> Result<String> {
        let mut output = serde_json::json!({
            "tool_name": self.tool_name,
            "noun": self.noun,
            "effect": format!("{}", self.decision.effect),
            "reason": self.decision.reason,
            "matched_rules": self.decision.trace.matched_rules.iter().map(|m| {
                serde_json::json!({
                    "rule_index": m.rule_index,
                    "description": m.description,
                    "effect": format!("{}", m.effect),
                })
            }).collect::<Vec<_>>(),
            "skipped_rules": self.decision.trace.skipped_rules.iter().map(|s| {
                serde_json::json!({
                    "rule_index": s.rule_index,
                    "description": s.description,
                    "reason": s.reason,
                })
            }).collect::<Vec<_>>(),
            "resolution": self.decision.trace.final_resolution,
            "sandbox": self.decision.sandbox.as_ref().map(|s| serde_json::to_value(s).ok()),
        });

        if self.decision.effect == crate::policy::Effect::Deny {
            output["suggestion"] = serde_json::json!(self.suggest_allow_command());
        }

        serde_json::to_string_pretty(&output).context("failed to serialize replay result")
    }

    /// Generate an allow command suggestion.
    fn suggest_allow_command(&self) -> String {
        use crate::policy::eval::tool_to_queries;

        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        let tool_input = build_tool_input(&self.tool_name, &self.noun);
        let queries = tool_to_queries(&self.tool_name, &tool_input, &cwd);

        let rule = match queries.first() {
            Some(CapQuery::Exec { bin, args }) => {
                if args.is_empty() {
                    format!("(exec \"{}\")", bin)
                } else {
                    let quoted: Vec<String> = args.iter().map(|a| format!("\"{}\"", a)).collect();
                    format!("(exec \"{}\" {})", bin, quoted.join(" "))
                }
            }
            Some(CapQuery::Fs { op, path }) => format!("(fs {} \"{}\")", op, path),
            Some(CapQuery::Net { domain }) => format!("(net \"{}\")", domain),
            Some(CapQuery::Tool { name }) => format!("(tool \"{}\")", name),
            None => return format!("clash allow '{}'", self.tool_name.to_lowercase()),
        };

        format!("clash allow '{rule}'")
    }

    /// Look up the origin PolicyLevel for a matched rule.
    fn find_origin_level(
        &self,
        m: &crate::policy::ir::RuleMatch,
    ) -> Option<&PolicyLevel> {
        use crate::policy::decision_tree::CompiledRule;
        let rule_lists: &[&[CompiledRule]] = &[
            &self.tree.exec_rules,
            &self.tree.fs_rules,
            &self.tree.net_rules,
            &self.tree.tool_rules,
        ];
        for rules in rule_lists {
            if let Some(rule) = rules.get(m.rule_index) {
                let desc = rule.source.to_string();
                if m.description.starts_with(&desc) {
                    return rule.origin_level.as_ref();
                }
            }
        }
        None
    }
}

/// Replay a tool invocation given CLI arguments.
///
/// `tool` is a domain keyword (bash, read, write, edit) or full tool name (Bash, Read, etc.).
/// `input` is the command, path, or noun.
pub fn replay_from_args(tool: &str, input: Option<&str>, cwd: &str) -> Result<ReplayResult> {
    let (tool_name, tool_input) = resolve_tool_input(tool, input)?;

    let settings = ClashSettings::load_or_create()?;
    let tree = settings
        .decision_tree()
        .ok_or_else(|| anyhow::anyhow!("no compiled policy available — run `clash init`"))?
        .clone();

    let multi_level = settings.loaded_policies().len() > 1;
    let decision = tree.evaluate(&tool_name, &tool_input, cwd);
    let noun = crate::permissions::extract_noun(&tool_name, &tool_input);

    Ok(ReplayResult {
        tool_name,
        noun,
        decision,
        multi_level,
        tree,
    })
}

/// Replay the last entry from the active session's audit log.
pub fn replay_last(session_id: Option<&str>) -> Result<ReplayResult> {
    use crate::debug::log;

    let entries = if let Some(explicit) = session_id {
        log::read_session_log(explicit)?
    } else {
        match log::resolve_session_id(None)?
            .and_then(|id| log::read_session_log(&id).ok())
        {
            Some(entries) if !entries.is_empty() => entries,
            _ => log::read_all_session_logs()?,
        }
    };
    let last = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("no audit log entries found"))?;

    // Re-evaluate the last tool invocation against current policy.
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    replay_from_args(
        &last.tool_name,
        Some(&last.tool_input_summary),
        &cwd,
    )
}

/// Resolve tool name and input JSON from CLI arguments.
///
/// Mirrors the logic in `cmd/explain.rs` for consistency.
pub(crate) fn resolve_tool_input(
    tool: &str,
    input: Option<&str>,
) -> Result<(String, serde_json::Value)> {
    let noun = input.unwrap_or_default();

    if tool.to_lowercase() == "tool" {
        return Ok((noun.to_string(), serde_json::json!({})));
    }

    let (tool_name, input_field) = match tool.to_lowercase().as_str() {
        "bash" => ("Bash", "command"),
        "read" => ("Read", "file_path"),
        "write" => ("Write", "file_path"),
        "edit" => ("Edit", "file_path"),
        _ => {
            let field = match tool {
                "Bash" => "command",
                "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
                "Glob" | "Grep" => "pattern",
                "WebFetch" => "url",
                "WebSearch" => "query",
                _ => "command",
            };
            return Ok((tool.to_string(), serde_json::json!({ field: noun })));
        }
    };

    Ok((
        tool_name.to_string(),
        serde_json::json!({ input_field: noun }),
    ))
}

/// Build a minimal tool_input JSON from tool name and noun.
fn build_tool_input(tool_name: &str, noun: &str) -> serde_json::Value {
    let field = match tool_name {
        "Bash" => "command",
        "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
        "Glob" | "Grep" => "pattern",
        "WebFetch" => "url",
        "WebSearch" => "query",
        _ => "command",
    };
    serde_json::json!({ field: noun })
}

/// Format sandbox policy summary lines.
fn format_sandbox_summary(lines: &mut Vec<String>, sandbox: &SandboxPolicy) {
    lines.push(format!(
        "  {}: {}",
        style::cyan("default"),
        sandbox.default.display()
    ));
    lines.push(format!(
        "  {}: {:?}",
        style::cyan("network"),
        sandbox.network
    ));
    for rule in &sandbox.rules {
        lines.push(format!(
            "  {:?} {} in {}",
            rule.effect,
            rule.caps.display(),
            rule.path
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_tool_input_bash() {
        let (name, input) = resolve_tool_input("bash", Some("git push")).unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "git push");
    }

    #[test]
    fn test_resolve_tool_input_read() {
        let (name, input) = resolve_tool_input("read", Some("/tmp/file.txt")).unwrap();
        assert_eq!(name, "Read");
        assert_eq!(input["file_path"], "/tmp/file.txt");
    }

    #[test]
    fn test_resolve_tool_input_full_name() {
        let (name, input) = resolve_tool_input("WebFetch", Some("https://example.com")).unwrap();
        assert_eq!(name, "WebFetch");
        assert_eq!(input["url"], "https://example.com");
    }

    #[test]
    fn test_resolve_tool_input_tool_domain() {
        let (name, input) = resolve_tool_input("tool", Some("CustomTool")).unwrap();
        assert_eq!(name, "CustomTool");
        assert_eq!(input, serde_json::json!({}));
    }

    #[test]
    fn test_build_tool_input_bash() {
        let input = build_tool_input("Bash", "git status");
        assert_eq!(input["command"], "git status");
    }

    #[test]
    fn test_build_tool_input_read() {
        let input = build_tool_input("Read", "/tmp/file");
        assert_eq!(input["file_path"], "/tmp/file");
    }
}
