use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{Level, instrument};

use crate::settings::ClashSettings;
use crate::style;

#[derive(Deserialize)]
pub struct ExplainInput {
    tool_name: String,
    tool_input: serde_json::Value,
    #[serde(default = "default_cwd")]
    #[allow(dead_code)]
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
        if tool_str.to_lowercase() == "tool" {
            let tool_name = input_arg.unwrap_or_default();
            ExplainInput {
                tool_name,
                tool_input: serde_json::json!({}),
                cwd: default_cwd(),
            }
        } else {
            let (tool_name, input_field) = match tool_str.to_lowercase().as_str() {
                "bash" => ("Bash", "command"),
                "read" => ("Read", "file_path"),
                "write" => ("Write", "file_path"),
                "edit" => ("Edit", "file_path"),
                _ => {
                    let field = match tool_str.as_str() {
                        "Bash" => "command",
                        "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
                        "Glob" | "Grep" => "pattern",
                        "WebFetch" => "url",
                        "WebSearch" => "query",
                        _ => "command",
                    };
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
        }
    } else {
        serde_json::from_reader(std::io::stdin().lock()).context(
            "failed to parse JSON from stdin (expected {\"tool_name\":..., \"tool_input\":...})\n\nUsage: clash explain bash \"git push\"  OR  echo '{...}' | clash explain",
        )?
    };

    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.policy_tree() {
        Some(t) => t,
        None => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"error": "no compiled policy available"})
                );
            } else {
                eprintln!("No compiled policy available.");
                eprintln!("Create ~/.clash/policy.star or run `clash init`.");
            }
            return Ok(());
        }
    };

    let decision = tree.evaluate(&input.tool_name, &input.tool_input);
    let noun = crate::permissions::extract_noun(&input.tool_name, &input.tool_input);

    if json_output {
        let output = serde_json::json!({
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
        });
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
        println!();

        if !decision.trace.matched_rules.is_empty() {
            println!("{}", style::header("Matched rules:"));
            for m in &decision.trace.matched_rules {
                let eff = style::effect(&m.effect.to_string());
                println!("  [{}] {} -> {}", m.rule_index, m.description, eff);
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
