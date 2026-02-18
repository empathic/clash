use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{Level, instrument};

use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

#[derive(Deserialize)]
pub struct ExplainInput {
    tool_name: String,
    tool_input: serde_json::Value,
    #[serde(default = "default_cwd")]
    cwd: String,
}

fn default_cwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Explain which policy rule would match a given tool invocation.
///
/// Accepts CLI args (`clash explain bash "git push"`) or JSON from stdin.
#[instrument(level = Level::TRACE)]
pub fn run(json_output: bool, tool: Option<String>, input_arg: Option<String>) -> Result<()> {
    let input: ExplainInput = if let Some(tool_str) = tool {
        // Build from CLI arguments
        let (tool_name, input_field) = match tool_str.to_lowercase().as_str() {
            "bash" => ("Bash", "command"),
            "read" => ("Read", "file_path"),
            "write" => ("Write", "file_path"),
            "edit" => ("Edit", "file_path"),
            _ => {
                // Allow full tool names (Bash, Read, etc.) as-is
                let field = match tool_str.as_str() {
                    "Bash" => "command",
                    "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
                    "Glob" | "Grep" => "pattern",
                    "WebFetch" => "url",
                    "WebSearch" => "query",
                    _ => "command",
                };
                // Leak to get 'static -- fine for a CLI tool that runs once
                let name: &'static str = Box::leak(tool_str.into_boxed_str());
                (name, field)
            }
        };
        let noun = input_arg.unwrap_or_default();
        ExplainInput {
            tool_name: tool_name.to_string(),
            tool_input: serde_json::json!({ input_field: noun }),
            cwd: default_cwd(),
        }
    } else {
        // Read from stdin
        serde_json::from_reader(std::io::stdin().lock()).context(
            "failed to parse JSON from stdin (expected {\"tool_name\":..., \"tool_input\":...})\n\nUsage: clash explain bash \"git push\"  OR  echo '{...}' | clash explain",
        )?
    };

    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.decision_tree() {
        Some(t) => t,
        None => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"error": "no compiled policy available"})
                );
            } else {
                eprintln!("No compiled policy available.");
                eprintln!("Create ~/.clash/policy.sexpr or run `clash init`.");
            }
            return Ok(());
        }
    };

    let multi_level = settings.loaded_policies().len() > 1;
    let decision = tree.evaluate(&input.tool_name, &input.tool_input, &input.cwd);
    let noun = crate::permissions::extract_noun(&input.tool_name, &input.tool_input);

    // Helper to look up origin_level for a matched rule by searching all domain
    // rule lists. The rule_index is relative to its domain list, so we check
    // each list at that index for a matching description.
    let find_origin_level = |m: &crate::policy::ir::RuleMatch| -> Option<&PolicyLevel> {
        let rule_lists: &[&[crate::policy::decision_tree::CompiledRule]] = &[
            &tree.exec_rules,
            &tree.fs_rules,
            &tree.net_rules,
            &tree.tool_rules,
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
    };

    if json_output {
        let mut output = serde_json::json!({
            "effect": format!("{}", decision.effect),
            "reason": decision.reason,
            "matched_rules": decision.trace.matched_rules.iter().map(|m| {
                let mut entry = serde_json::json!({
                    "rule_index": m.rule_index,
                    "description": m.description,
                    "effect": format!("{}", m.effect),
                });
                if multi_level
                    && let Some(level) = find_origin_level(m)
                {
                    entry["level"] = serde_json::json!(level.to_string());
                }
                entry
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
        });
        // Add top-level "level" from the first (winning) matched rule.
        if multi_level
            && let Some(first_match) = decision.trace.matched_rules.first()
            && let Some(level) = find_origin_level(first_match)
        {
            output["level"] = serde_json::json!(level.to_string());
        }
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", style::bold("Input:"));
        println!("  {}   {}", style::cyan("tool:"), input.tool_name);
        println!("  {}   {}", style::cyan("noun:"), noun);
        println!();

        println!(
            "{} {}",
            style::bold("Decision:"),
            style::effect(&decision.effect.to_string())
        );
        if let Some(ref reason) = decision.reason {
            println!("{} {}", style::bold("Reason:  "), reason);
        }
        if multi_level
            && let Some(first_match) = decision.trace.matched_rules.first()
            && let Some(level) = find_origin_level(first_match)
        {
            println!(
                "{} {}",
                style::bold("Level:   "),
                style::cyan(&level.to_string())
            );
        }
        println!();

        if !decision.trace.matched_rules.is_empty() {
            println!("{}", style::header("Matched rules:"));
            for m in &decision.trace.matched_rules {
                let eff = style::effect(&m.effect.to_string());
                if multi_level {
                    if let Some(level) = find_origin_level(m) {
                        println!(
                            "  [{}] {} {} -> {}",
                            m.rule_index,
                            style::cyan(&format!("[{}]", level)),
                            m.description,
                            eff
                        );
                    } else {
                        println!("  [{}] {} -> {}", m.rule_index, m.description, eff);
                    }
                } else {
                    println!("  [{}] {} -> {}", m.rule_index, m.description, eff);
                }
            }
            println!();
        }

        if !decision.trace.skipped_rules.is_empty() {
            println!("{}", style::dim("Skipped rules:"));
            for s in &decision.trace.skipped_rules {
                println!(
                    "  {} {} {}",
                    style::dim(&format!("[{}]", s.rule_index)),
                    style::dim(&s.description),
                    style::dim(&format!("({})", s.reason))
                );
            }
            println!();
        }

        println!(
            "{} {}",
            style::bold("Resolution:"),
            style::effect(&decision.trace.final_resolution.clone())
        );

        if let Some(ref sandbox) = decision.sandbox {
            println!();
            println!("{}", style::header("Sandbox policy:"));
            println!(
                "  {}: {}",
                style::cyan("default"),
                sandbox.default.display()
            );
            println!("  {}: {:?}", style::cyan("network"), sandbox.network);
            for rule in &sandbox.rules {
                println!(
                    "  {:?} {} in {}",
                    rule.effect,
                    rule.caps.display(),
                    rule.path
                );
            }
        }
    }

    Ok(())
}
