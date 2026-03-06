use std::path::Path;

use anyhow::{Context, Result};
use tracing::{Level, instrument};

use crate::cli::PolicyCmd;
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

/// Handle `clash policy` subcommands.
#[instrument(level = Level::TRACE)]
pub fn run(cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Schema { json } => super::schema::run(json),
        PolicyCmd::Explain { json, tool, args } => {
            let input = if args.is_empty() {
                None
            } else {
                Some(args.join(" "))
            };
            super::explain::run(json, tool, input)
        }
        PolicyCmd::List { json } => handle_list(json),
        PolicyCmd::Validate { file, json } => handle_validate(file, json),
        PolicyCmd::Show { json } => handle_show(json),
        PolicyCmd::Edit { scope } => handle_edit(scope),
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

/// Handle `clash policy list`.
fn handle_list(json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.policy_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                anyhow::bail!("{}", err);
            }
            anyhow::bail!("no policy configured — run `clash init`");
        }
    };

    let all_rules: Vec<&crate::policy::decision_tree::CompiledRule> = tree
        .exec_rules
        .iter()
        .chain(&tree.fs_rules)
        .chain(&tree.net_rules)
        .chain(&tree.tool_rules)
        .collect();

    if json {
        let entries: Vec<serde_json::Value> = all_rules
            .iter()
            .map(|r| {
                let origin = r.origin_policy.as_deref().unwrap_or(&tree.policy_name);
                let builtin = origin.starts_with("__internal_");
                let mut entry = serde_json::json!({
                    "effect": format!("{}", r.effect),
                    "rule": r.source.to_string(),
                    "origin": origin,
                    "builtin": builtin,
                });
                if let Some(ref level) = r.origin_level {
                    entry["level"] = serde_json::json!(level.to_string());
                }
                entry
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        if all_rules.is_empty() {
            println!(
                "No rules in policy {}.",
                style::cyan(&format!("\"{}\"", tree.policy_name))
            );
            return Ok(());
        }
        println!(
            "Policy {} {}\n",
            style::cyan(&format!("\"{}\"", tree.policy_name)),
            style::dim(&format!(
                "(default: {}, {} rules)",
                style::effect(&tree.default.to_string()),
                all_rules.len()
            ))
        );
        for rule in &all_rules {
            let tag = if let Some(ref level) = rule.origin_level {
                format!("{} ", style::cyan(&format!("[{}]", level)))
            } else if rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            {
                format!("{} ", style::dim("[builtin]"))
            } else {
                String::new()
            };
            println!("  {}{}", tag, rule.source);
        }
    }
    Ok(())
}

/// Handle `clash policy show`.
fn handle_show(json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.policy_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                anyhow::bail!("{}", err);
            }
            anyhow::bail!("no policy configured — run `clash init`");
        }
    };

    let loaded = settings.loaded_policies();

    if json {
        let rule_count = tree.exec_rules.len()
            + tree.fs_rules.len()
            + tree.net_rules.len()
            + tree.tool_rules.len();
        let output = serde_json::json!({
            "policy_name": tree.policy_name,
            "default": format!("{}", tree.default),
            "rule_count": rule_count,
            "source": tree.to_source(),
            "levels": loaded
                .iter()
                .map(|lp| {
                    serde_json::json!({
                        "level": lp.level.to_string(),
                        "path": lp.path.display().to_string(),
                        "source": &lp.source,
                    })
                })
                .collect::<Vec<serde_json::Value>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        for lp in loaded {
            println!(
                "{} {}",
                style::cyan(&format!("[{}]", lp.level)),
                lp.path.display()
            );
            println!("{}", style::dim(&"─".repeat(40)));
            print!("{}", lp.source);
            if !lp.source.ends_with('\n') {
                println!();
            }
            println!();
        }
        if loaded.is_empty() {
            print!("{}", crate::policy::print_tree(tree));
        }
    }
    Ok(())
}

/// Handle `clash policy validate`.
fn handle_validate(file: Option<std::path::PathBuf>, json: bool) -> Result<()> {
    if let Some(path) = file {
        return validate_single_file(&path, json);
    }

    // Validate all available policy levels.
    let levels = ClashSettings::available_policy_levels();
    if levels.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::json!({"valid": false, "error": "no policy files found", "hint": "run `clash init` to create a policy"})
            );
        } else {
            eprintln!("{}: no policy files found", style::err_red_bold("error"));
            eprintln!(
                "  {}: run {} to create a policy",
                style::err_cyan_bold("hint"),
                style::bold("clash init")
            );
        }
        std::process::exit(1);
    }

    let mut all_valid = true;
    let mut results: Vec<serde_json::Value> = Vec::new();

    for (level, path) in &levels {
        let source = match crate::settings::evaluate_star_policy(path) {
            Ok(s) => s,
            Err(e) => {
                all_valid = false;
                if json {
                    results.push(serde_json::json!({
                        "level": level.to_string(),
                        "path": path.display().to_string(),
                        "valid": false,
                        "error": format!("{}", e),
                    }));
                } else {
                    eprintln!(
                        "{} {} {}",
                        style::err_red_bold("✗"),
                        style::cyan(&format!("[{}]", level)),
                        path.display()
                    );
                    eprintln!("  {}", style::dim(&format!("{}", e)));
                }
                continue;
            }
        };

        match crate::policy::compile::compile_policy(&source) {
            Ok(tree) => {
                let rule_count = tree.exec_rules.len()
                    + tree.fs_rules.len()
                    + tree.net_rules.len()
                    + tree.tool_rules.len();
                if json {
                    results.push(serde_json::json!({
                        "level": level.to_string(),
                        "path": path.display().to_string(),
                        "valid": true,
                        "policy_name": tree.policy_name,
                        "default": format!("{}", tree.default),
                        "rule_count": rule_count,
                    }));
                } else {
                    println!(
                        "{} {} {}",
                        style::green_bold("✓"),
                        style::cyan(&format!("[{}]", level)),
                        path.display()
                    );
                    println!(
                        "  policy {}, default {}, {} rules",
                        style::bold(&format!("\"{}\"", tree.policy_name)),
                        style::effect(&tree.default.to_string()),
                        rule_count
                    );
                }
            }
            Err(e) => {
                all_valid = false;
                let hint = extract_policy_hint(&e);
                if json {
                    let mut entry = serde_json::json!({
                        "level": level.to_string(),
                        "path": path.display().to_string(),
                        "valid": false,
                        "error": format!("{}", e),
                    });
                    if let Some(h) = &hint {
                        entry["hint"] = serde_json::json!(h);
                    }
                    results.push(entry);
                } else {
                    eprintln!(
                        "{} {} {}",
                        style::err_red_bold("✗"),
                        style::cyan(&format!("[{}]", level)),
                        path.display()
                    );
                    eprintln!("  {}", e);
                    if let Some(h) = hint {
                        eprintln!("  {}: {}", style::err_cyan_bold("hint"), h);
                    }
                }
            }
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "valid": all_valid,
                "levels": results,
            }))?
        );
    } else if all_valid {
        println!("\n{}", style::green_bold("All policy files are valid."));
    } else {
        eprintln!("\n{}", style::err_red_bold("Policy validation failed."));
        std::process::exit(1);
    }

    Ok(())
}

fn validate_single_file(path: &std::path::Path, json: bool) -> Result<()> {
    let source = crate::settings::evaluate_star_policy(path)
        .with_context(|| format!("failed to evaluate: {}", path.display()))?;

    match crate::policy::compile::compile_policy(&source) {
        Ok(tree) => {
            let rule_count = tree.exec_rules.len()
                + tree.fs_rules.len()
                + tree.net_rules.len()
                + tree.tool_rules.len();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "path": path.display().to_string(),
                        "policy_name": tree.policy_name,
                        "default": format!("{}", tree.default),
                        "rule_count": rule_count,
                    }))?
                );
            } else {
                println!("{} {}", style::green_bold("✓"), path.display());
                println!(
                    "  policy {}, default {}, {} rules",
                    style::bold(&format!("\"{}\"", tree.policy_name)),
                    style::effect(&tree.default.to_string()),
                    rule_count
                );
            }
            Ok(())
        }
        Err(e) => {
            let hint = extract_policy_hint(&e);
            if json {
                let mut entry = serde_json::json!({
                    "valid": false,
                    "path": path.display().to_string(),
                    "error": format!("{}", e),
                });
                if let Some(h) = &hint {
                    entry["hint"] = serde_json::json!(h);
                }
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                eprintln!("{} {}", style::err_red_bold("✗"), path.display());
                eprintln!("  {}", e);
                if let Some(h) = hint {
                    eprintln!("  {}: {}", style::err_cyan_bold("hint"), h);
                }
            }
            std::process::exit(1);
        }
    }
}

/// Open a policy file in `$EDITOR` (falls back to `vi`).
pub fn open_in_editor(path: &Path) -> Result<()> {
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
    let status = std::process::Command::new(&editor)
        .arg(path)
        .status()
        .with_context(|| format!("failed to launch editor: {editor}"))?;
    if !status.success() {
        anyhow::bail!("editor exited with {status}");
    }
    Ok(())
}

/// Handle `clash policy edit`.
fn handle_edit(scope: Option<String>) -> Result<()> {
    let level = match scope.as_deref() {
        Some("user") => PolicyLevel::User,
        Some("project") => PolicyLevel::Project,
        Some(other) => {
            anyhow::bail!("unknown scope: \"{other}\" (expected \"user\" or \"project\")")
        }
        None => ClashSettings::default_scope(),
    };
    let path = ClashSettings::policy_file_for_level(level)?;
    if !path.exists() {
        anyhow::bail!(
            "no policy file at {} — run `clash init {}` first",
            path.display(),
            level,
        );
    }
    open_in_editor(&path)
}

/// Extract a help hint from an anyhow error chain.
fn extract_policy_hint(err: &anyhow::Error) -> Option<String> {
    err.chain().find_map(|cause| {
        if let Some(e) = cause.downcast_ref::<crate::policy::error::PolicyParseError>() {
            return e.help();
        }
        if let Some(e) = cause.downcast_ref::<crate::policy::error::CompileError>() {
            return e.help();
        }
        None
    })
}
