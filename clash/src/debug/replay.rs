//! Command replay: re-evaluate tool invocations against the current policy.

use anyhow::{Context, Result};

use crate::policy::ir::PolicyDecision;
use crate::policy::sandbox_types::SandboxPolicy;
use crate::settings::ClashSettings;
use crate::style;

/// The result of replaying a tool invocation.
pub struct ReplayResult {
    pub tool_name: String,
    pub noun: String,
    pub decision: PolicyDecision,
    pub multi_level: bool,
}

impl ReplayResult {
    /// Render as human-readable text.
    pub fn format_human(&self) -> String {
        let mut lines = Vec::new();

        lines.push(style::bold("Input:").to_string());
        lines.push(format!("  {}   {}", style::cyan("tool:"), self.tool_name));
        lines.push(format!("  {}   {}", style::cyan("noun:"), self.noun));
        lines.push(String::new());

        lines.push(format!(
            "{} {}",
            style::bold("Decision:"),
            style::effect(&self.decision.effect.to_string())
        ));
        if let Some(ref reason) = self.decision.reason {
            lines.push(format!("{} {}", style::bold("Reason:  "), reason));
        }
        lines.push(String::new());

        if !self.decision.trace.matched_rules.is_empty() {
            lines.push(style::header("Matched rules:").to_string());
            for m in &self.decision.trace.matched_rules {
                let eff = style::effect(&m.effect.to_string());
                lines.push(format!("  [{}] {} -> {}", m.rule_index, m.description, eff));
            }
            lines.push(String::new());
        }

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

        lines.push(format!(
            "{} {}",
            style::bold("Resolution:"),
            style::effect(&self.decision.trace.final_resolution)
        ));

        if let Some(ref sandbox) = self.decision.sandbox {
            lines.push(String::new());
            lines.push(format!(
                "{} {} ",
                style::header("Sandbox policy:"),
                &self
                    .decision
                    .sandbox_name
                    .as_ref()
                    .map(|x| x.0.clone())
                    .unwrap_or_default(),
            ));
            format_sandbox_summary(&mut lines, sandbox);
        }

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

    fn suggest_allow_command(&self) -> String {
        format!("clash allow '{}'", self.tool_name.to_lowercase())
    }
}

/// Replay a tool invocation given CLI arguments.
pub fn replay_from_args(tool: &str, input: Option<&str>, _cwd: &str) -> Result<ReplayResult> {
    let (tool_name, tool_input) = resolve_tool_input(tool, input)?;

    let settings = ClashSettings::load_or_create()?;
    let policy = settings
        .policy_tree()
        .ok_or_else(|| anyhow::anyhow!("no compiled policy available — run `clash init`"))?;

    let multi_level = settings.loaded_policies().len() > 1;
    let decision = policy.evaluate(&tool_name, &tool_input);
    let noun = crate::permissions::extract_noun(&tool_name, &tool_input);

    Ok(ReplayResult {
        tool_name,
        noun,
        decision,
        multi_level,
    })
}

/// Replay the most recent audit log entry.
pub fn replay_last(session_filter: Option<&str>) -> Result<ReplayResult> {
    use crate::debug::log;

    let mut entries = log::read_all_session_logs()?;
    if let Some(filter) = session_filter {
        entries.retain(|e| e.session_id.contains(filter));
    }
    let last = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("no audit log entries found"))?;

    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    replay_from_args(&last.tool_name, Some(&last.tool_input_summary), &cwd)
}

/// Replay an audit log entry identified by its short hash.
pub fn replay_hash(hash: &str) -> Result<ReplayResult> {
    let entry = crate::debug::log::find_by_hash(hash)?;
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    replay_from_args(&entry.tool_name, Some(&entry.tool_input_summary), &cwd)
}

/// Resolve tool name and input JSON from CLI arguments.
pub(crate) fn resolve_tool_input(
    tool: &str,
    input: Option<&str>,
) -> Result<(String, serde_json::Value)> {
    let noun = input.unwrap_or_default();

    if tool.to_lowercase() == "tool" {
        return Ok((noun.to_string(), serde_json::json!({})));
    }

    let tool_name = match tool.to_lowercase().as_str() {
        "bash" => "Bash",
        "read" => "Read",
        "write" => "Write",
        "edit" => "Edit",
        _ => tool,
    };

    let tool_input = serde_json::from_str::<serde_json::Value>(noun)
        .ok()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| build_tool_input(tool_name, noun));

    Ok((tool_name.to_string(), tool_input))
}

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
    fn test_resolve_tool_input_json_passthrough() {
        let json_input = r#"{"command":"ls -lha","description":"List files"}"#;
        let (name, input) = resolve_tool_input("Bash", Some(json_input)).unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "ls -lha");
        assert_eq!(input["description"], "List files");
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
