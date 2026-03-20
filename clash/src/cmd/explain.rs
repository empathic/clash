use anyhow::Result;
use tracing::{Level, instrument};

use crate::debug::replay;
use crate::display;
use crate::policy::match_tree::QueryContext;
use crate::settings::ClashSettings;
use crate::style;
use crate::trace_display;
use crate::ui;

/// Explain which policy rule would match a given tool invocation.
///
/// Accepts CLI args (`clash explain bash "git push"`) or JSON from stdin.
/// With `--trace`, shows a detailed per-condition decision trace.
#[instrument(level = Level::TRACE)]
pub fn run(json_output: bool, trace_mode: bool, tool: String, input_args: String) -> Result<()> {
    let input_arg = if input_args.is_empty() {
        None
    } else {
        Some(input_args.as_str())
    };
    let (tool_name, tool_input) = replay::resolve_tool_input(&tool, input_arg)?;

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
                eprintln!("run `clash init`.");
            }
            return Ok(());
        }
    };

    if trace_mode {
        let ctx = QueryContext::from_tool(&tool_name, &tool_input);
        let policy_trace = trace_display::build_trace(tree, &ctx);

        if json_output {
            let output = trace_display::trace_to_json(&policy_trace);
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            ui::print_tool_header("Input:", &tool_name, &tool_input);
            println!();
            for line in trace_display::render_trace(&policy_trace) {
                println!("{line}");
            }
        }
    } else {
        let decision = tree.evaluate(&tool_name, &tool_input);

        if json_output {
            let output = display::decision_to_json(&decision);
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            ui::print_tool_header("Input:", &tool_name, &tool_input);
            println!();
            ui::print_decision(&decision);

            if let Some(ref sandbox) = decision.sandbox {
                println!();
                println!("{}", style::header("Sandbox policy:"));
                ui::print_sandbox_summary(sandbox);
            }
        }
    }

    Ok(())
}
