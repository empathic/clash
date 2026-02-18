use anyhow::Result;

use crate::cli::Cli;

/// Print the full command + subcommand hierarchy.
pub fn run(json: bool, show_all: bool) -> Result<()> {
    use clap::CommandFactory;
    let cmd = Cli::command();

    if json {
        let tree = command_to_json(&cmd, show_all);
        println!("{}", serde_json::to_string_pretty(&tree)?);
    } else {
        print_command_tree(&cmd, 0, show_all);
    }
    Ok(())
}

fn command_to_json(cmd: &clap::Command, show_all: bool) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "name": cmd.get_name(),
    });

    if let Some(about) = cmd.get_about() {
        obj["about"] = serde_json::Value::String(about.to_string());
    }

    // Collect visible (and hidden if show_all) arguments.
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| show_all || !a.is_hide_set())
        .filter(|a| a.get_id() != "help" && a.get_id() != "version")
        .map(|a| {
            let mut arg = serde_json::json!({
                "name": a.get_id().as_str(),
            });
            if let Some(help) = a.get_help() {
                arg["help"] = serde_json::Value::String(help.to_string());
            }
            if a.get_action().takes_values() {
                arg["takes_value"] = serde_json::Value::Bool(true);
            }
            if a.is_required_set() {
                arg["required"] = serde_json::Value::Bool(true);
            }
            arg
        })
        .collect();

    if !args.is_empty() {
        obj["args"] = serde_json::Value::Array(args);
    }

    let subs: Vec<serde_json::Value> = cmd
        .get_subcommands()
        .filter(|s| show_all || !s.is_hide_set())
        .map(|s| command_to_json(s, show_all))
        .collect();

    if !subs.is_empty() {
        obj["subcommands"] = serde_json::Value::Array(subs);
    }

    obj
}

fn print_command_tree(cmd: &clap::Command, depth: usize, show_all: bool) {
    let indent = "  ".repeat(depth);
    let name = cmd.get_name();
    let about = cmd.get_about().map(|a| a.to_string()).unwrap_or_default();

    if depth == 0 {
        println!("{name}  {about}");
    } else {
        println!("{indent}{name}  {about}");
    }

    // Show arguments for leaf commands
    let has_subcommands = cmd.get_subcommands().any(|s| show_all || !s.is_hide_set());
    if !has_subcommands {
        for arg in cmd.get_arguments() {
            if arg.get_id() == "help" || arg.get_id() == "version" {
                continue;
            }
            if !show_all && arg.is_hide_set() {
                continue;
            }
            let arg_name = arg.get_id().as_str();
            let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
            let required = if arg.is_required_set() { " *" } else { "" };
            println!("{indent}  --{arg_name}{required}  {help}");
        }
    }

    for sub in cmd.get_subcommands() {
        if !show_all && sub.is_hide_set() {
            continue;
        }
        print_command_tree(sub, depth + 1, show_all);
    }
}
