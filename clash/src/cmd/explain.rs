use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{Level, instrument};

use crate::display;
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
        let output = display::decision_to_json(&decision);
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let mut lines = display::format_tool_header("Input:", &input.tool_name, &noun);
        lines.push(String::new());
        lines.extend(display::format_decision(&decision));

        if let Some(ref sandbox) = decision.sandbox {
            lines.push(String::new());
            lines.push(style::header("Sandbox policy:").to_string());
            lines.extend(display::format_sandbox_summary(sandbox));
        }

        println!("{}", lines.join("\n"));
    }

    Ok(())
}
