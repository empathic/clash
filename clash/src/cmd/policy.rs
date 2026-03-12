use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{Level, info, instrument};

use crate::cli::PolicyCmd;
use crate::policy::manifest_edit;
use crate::policy::match_tree::{Decision, PolicyManifest};
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
        PolicyCmd::Edit { scope, raw } => handle_edit(scope, raw),
        PolicyCmd::Allow {
            command,
            tool,
            bin,
            sandbox,
            scope,
        } => handle_allow(command, tool, bin, sandbox, scope),
        PolicyCmd::Deny {
            command,
            tool,
            bin,
            scope,
        } => handle_deny(command, tool, bin, scope),
        PolicyCmd::Remove {
            command,
            tool,
            bin,
            scope,
        } => handle_remove(command, tool, bin, scope),
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
        let source = match crate::settings::evaluate_policy_file(path) {
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
                let warnings = policy.platform_warnings();
                if json {
                    let mut entry = serde_json::json!({
                        "level": level.to_string(),
                        "path": path.display().to_string(),
                        "valid": true,
                        "default": format!("{}", policy.default_effect),
                        "rule_count": policy.rule_count(),
                    });
                    if !warnings.is_empty() {
                        entry["warnings"] = serde_json::json!(warnings);
                    }
                    results.push(entry);
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
                    for w in &warnings {
                        eprintln!("  {} {}", style::err_yellow("warning:"), w,);
                    }
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
    let source = crate::settings::evaluate_policy_file(path)
        .with_context(|| format!("failed to evaluate: {}", path.display()))?;

    match crate::policy::compile::compile_to_tree(&source) {
        Ok(policy) => {
            let warnings = policy.platform_warnings();
            if json {
                let mut output = serde_json::json!({
                    "valid": true,
                    "path": path.display().to_string(),
                    "default": format!("{}", policy.default_effect),
                    "rule_count": policy.rule_count(),
                });
                if !warnings.is_empty() {
                    output["warnings"] = serde_json::json!(warnings);
                }
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{} {}", style::green_bold("✓"), path.display());
                println!(
                    "  default {}, {} rules",
                    style::effect(&policy.default_effect.to_string()),
                    policy.rule_count()
                );
                for w in &warnings {
                    eprintln!("  {} {}", style::err_yellow("warning:"), w,);
                }
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
fn handle_edit(scope: Option<String>, raw: bool) -> Result<()> {
    if raw {
        // --raw: open in $EDITOR
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
        return open_in_editor(&path);
    }

    // Interactive TUI editor
    let path = resolve_manifest_path(scope)?;
    crate::tui::run(&path)
}

// ---------------------------------------------------------------------------
// Allow / Deny / Remove handlers
// ---------------------------------------------------------------------------

/// Resolve the policy.json path for the given scope, creating it if needed.
pub(crate) fn resolve_manifest_path(scope: Option<String>) -> Result<PathBuf> {
    let level = match scope.as_deref() {
        Some("user") => PolicyLevel::User,
        Some("project") => PolicyLevel::Project,
        Some(other) => {
            anyhow::bail!("unknown scope: \"{other}\" (expected \"user\" or \"project\")")
        }
        None => ClashSettings::default_scope(),
    };

    let dir = match level {
        PolicyLevel::User => ClashSettings::settings_dir()?,
        PolicyLevel::Project => ClashSettings::project_root()?.join(".clash"),
        PolicyLevel::Session => anyhow::bail!("session scope not supported for policy mutation"),
    };

    let json_path = dir.join("policy.json");
    if json_path.exists() {
        return Ok(json_path);
    }

    // If policy.star exists but no policy.json, create a manifest that includes it.
    let star_path = dir.join("policy.star");
    let manifest = if star_path.exists() {
        PolicyManifest {
            includes: vec![crate::policy::match_tree::IncludeEntry {
                path: "policy.star".into(),
            }],
            policy: crate::policy::match_tree::CompiledPolicy {
                sandboxes: std::collections::HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        }
    } else {
        // No policy at all — create a bare manifest.
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
        PolicyManifest {
            includes: vec![],
            policy: crate::policy::match_tree::CompiledPolicy {
                sandboxes: std::collections::HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        }
    };

    crate::policy_loader::write_manifest(&json_path, &manifest)?;
    info!(path = %json_path.display(), "Created policy.json");
    Ok(json_path)
}

/// Parse a positional command string into (bin, args).
///
/// Splits on whitespace: `"gh pr create"` → `("gh", ["pr", "create"])`.
/// If the command vec has multiple words (from trailing_var_arg), joins them first.
fn parse_command(command: &[String]) -> Option<(String, Vec<String>)> {
    // Join all positional args, then split on whitespace to handle both
    // `clash policy allow "gh pr create"` and `clash policy allow gh pr create`.
    let joined = command.join(" ");
    let parts: Vec<&str> = joined.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let bin = parts[0].to_string();
    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
    Some((bin, args))
}

/// Build a rule node from CLI arguments.
///
/// Priority: positional `command` > `--bin` > `--tool`.
/// If no flags or command are provided, returns an error.
fn build_rule_node(
    command: &[String],
    tool: Option<String>,
    bin: Option<String>,
    decision: Decision,
) -> Result<crate::policy::match_tree::Node> {
    // Positional command takes priority.
    if let Some((bin_name, args)) = parse_command(command) {
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        return Ok(manifest_edit::build_exec_rule(
            &bin_name, &arg_refs, decision,
        ));
    }
    match (tool.as_deref(), bin.as_deref()) {
        (_, Some(bin_name)) => Ok(manifest_edit::build_exec_rule(bin_name, &[], decision)),
        (Some(tool_name), None) => Ok(manifest_edit::build_tool_rule(tool_name, decision)),
        (None, None) => anyhow::bail!("provide a command, --tool, or --bin"),
    }
}

fn handle_allow(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    sandbox: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let path = resolve_manifest_path(scope)?;
    let mut manifest = crate::policy_loader::read_manifest(&path)?;
    let sandbox_ref = sandbox.map(crate::policy::match_tree::SandboxRef);
    let node = build_rule_node(&command, tool, bin, Decision::Allow(sandbox_ref))?;
    let result = manifest_edit::upsert_rule(&mut manifest, node);
    crate::policy_loader::write_manifest(&path, &manifest)?;
    match result {
        manifest_edit::UpsertResult::Inserted => println!("{} Rule added", style::green_bold("✓")),
        manifest_edit::UpsertResult::Replaced => {
            println!(
                "{} Rule updated (replaced existing)",
                style::green_bold("✓")
            )
        }
    }
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}

fn handle_deny(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let path = resolve_manifest_path(scope)?;
    let mut manifest = crate::policy_loader::read_manifest(&path)?;
    let node = build_rule_node(&command, tool, bin, Decision::Deny)?;
    let result = manifest_edit::upsert_rule(&mut manifest, node);
    crate::policy_loader::write_manifest(&path, &manifest)?;
    match result {
        manifest_edit::UpsertResult::Inserted => println!("{} Rule added", style::green_bold("✓")),
        manifest_edit::UpsertResult::Replaced => {
            println!(
                "{} Rule updated (replaced existing)",
                style::green_bold("✓")
            )
        }
    }
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}

fn handle_remove(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let path = resolve_manifest_path(scope)?;
    let mut manifest = crate::policy_loader::read_manifest(&path)?;
    // Decision doesn't matter for removal — only the observable chain is compared.
    let node = build_rule_node(&command, tool, bin, Decision::Deny)?;
    if manifest_edit::remove_rule(&mut manifest, &node) {
        crate::policy_loader::write_manifest(&path, &manifest)?;
        println!("{} Rule removed", style::green_bold("✓"));
        println!("  {}", style::dim(&path.display().to_string()));
    } else {
        println!("No matching rule found");
    }
    Ok(())
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
