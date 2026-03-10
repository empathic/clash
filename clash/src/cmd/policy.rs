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
    let policy = match settings.policy_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                anyhow::bail!("{}", err);
            }
            anyhow::bail!("no policy configured — run `clash init`");
        }
    };

    if json {
        let rules = policy.format_rules();
        let entries: Vec<serde_json::Value> = rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                serde_json::json!({
                    "index": i,
                    "rule": r,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        let lines = policy.format_tree();
        if lines.is_empty() {
            println!(
                "No rules in policy. {}",
                style::dim(&format!("(default: {})", policy.default_effect))
            );
            return Ok(());
        }
        println!(
            "Policy {}\n",
            style::dim(&format!(
                "(default: {})",
                style::effect(&policy.default_effect.to_string()),
            ))
        );
        for line in &lines {
            println!("  {}", line);
        }
    }
    Ok(())
}

/// Handle `clash policy show`.
fn handle_show(json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let policy = match settings.policy_tree() {
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
        let output = serde_json::json!({
            "default": format!("{}", policy.default_effect),
            "rule_count": policy.rule_count(),
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
            for rule in policy.format_rules() {
                println!("  {}", rule);
            }
        }
    }
    Ok(())
}

/// Handle `clash policy validate`.
fn handle_validate(file: Option<std::path::PathBuf>, json: bool) -> Result<()> {
    if let Some(path) = file {
        return validate_single_file(&path, json);
    }

    let levels = ClashSettings::available_policy_levels();
    if levels.is_empty() {
        let diag = ClashSettings::diagnose_missing_policies();
        if json {
            let details: Vec<serde_json::Value> = diag
                .iter()
                .map(|(level, path, reason)| {
                    serde_json::json!({"level": level, "path": path, "reason": reason})
                })
                .collect();
            println!(
                "{}",
                serde_json::json!({"valid": false, "error": "no policy files found", "hint": "run `clash init` to create a policy", "checked": details})
            );
        } else {
            eprintln!("{}: no policy files found", style::err_red_bold("error"));
            eprintln!();
            eprintln!("  Checked the following locations:");
            for (level, path, reason) in &diag {
                eprintln!(
                    "    {} ({}): {} — {}",
                    level,
                    path,
                    style::err_red_bold("✗"),
                    reason
                );
            }
            eprintln!();
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

        match crate::policy::compile::compile_to_tree(&source) {
            Ok(policy) => {
                if json {
                    results.push(serde_json::json!({
                        "level": level.to_string(),
                        "path": path.display().to_string(),
                        "valid": true,
                        "default": format!("{}", policy.default_effect),
                        "rule_count": policy.rule_count(),
                    }));
                } else {
                    println!(
                        "{} {} {}",
                        style::green_bold("✓"),
                        style::cyan(&format!("[{}]", level)),
                        path.display()
                    );
                    println!(
                        "  default {}, {} rules",
                        style::effect(&policy.default_effect.to_string()),
                        policy.rule_count()
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

    match crate::policy::compile::compile_to_tree(&source) {
        Ok(policy) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "path": path.display().to_string(),
                        "default": format!("{}", policy.default_effect),
                        "rule_count": policy.rule_count(),
                    }))?
                );
            } else {
                println!("{} {}", style::green_bold("✓"), path.display());
                println!(
                    "  default {}, {} rules",
                    style::effect(&policy.default_effect.to_string()),
                    policy.rule_count()
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
