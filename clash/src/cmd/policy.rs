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
        PolicyCmd::Explain {
            json,
            trace,
            tool,
            args,
        } => super::explain::run(json, trace, tool.unwrap_or_default(), args.join(" ")),
        PolicyCmd::Check { json } => handle_check_portable(json),
        PolicyCmd::Convert { file, replace } => handle_convert(file, replace),
        PolicyCmd::List { json } => handle_list(json),
        PolicyCmd::Validate { file, json } => handle_validate(file, json),
        PolicyCmd::Show { json } => handle_show(json),
        PolicyCmd::Edit { scope, raw, test } => handle_edit(scope, raw, test),
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

/// Handle `clash policy check` — scan for portability issues.
fn handle_check_portable(json: bool) -> Result<()> {
    use crate::policy::match_tree::{Node, Observable, Pattern, Value};
    use crate::style;
    use crate::ui;

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

    /// Collect portability warnings by walking the tree.
    struct Warning {
        tool_name: String,
        canonical: Option<&'static str>,
        source: Option<String>,
    }

    fn walk_tree(nodes: &[Node], warnings: &mut Vec<Warning>) {
        for node in nodes {
            match node {
                Node::Condition {
                    observe: Observable::ToolName,
                    pattern,
                    children,
                    source,
                    ..
                } => {
                    check_pattern(pattern, source, warnings);
                    walk_tree(children, warnings);
                }
                Node::Condition { children, .. } => walk_tree(children, warnings),
                Node::Decision(_) => {}
            }
        }
    }

    fn check_pattern(pattern: &Pattern, source: &Option<String>, warnings: &mut Vec<Warning>) {
        match pattern {
            Pattern::Literal(Value::Literal(name)) => {
                // Check if this is an internal (Claude-specific) name that has a canonical alias
                if let Some(canonical) = crate::agents::internal_to_canonical(name) {
                    warnings.push(Warning {
                        tool_name: name.clone(),
                        canonical: Some(canonical),
                        source: source.clone(),
                    });
                }
                // Check if this is an agent-native name that's not canonical
                else if crate::agents::resolve_any_to_internal(name).is_some()
                    && crate::agents::canonical_to_internal(name).is_none()
                    && crate::agents::internal_to_canonical(name).is_none()
                {
                    // It's an agent-native name like "run_shell_command"
                    let internal = crate::agents::resolve_any_to_internal(name).unwrap();
                    let canonical = crate::agents::internal_to_canonical(internal);
                    warnings.push(Warning {
                        tool_name: name.clone(),
                        canonical,
                        source: source.clone(),
                    });
                }
            }
            Pattern::AnyOf(pats) => {
                for p in pats {
                    check_pattern(p, source, warnings);
                }
            }
            _ => {}
        }
    }

    let mut warnings = Vec::new();
    walk_tree(&policy.tree, &mut warnings);

    if json {
        let entries: Vec<serde_json::Value> = warnings
            .iter()
            .map(|w| {
                serde_json::json!({
                    "tool_name": w.tool_name,
                    "suggestion": w.canonical,
                    "source": w.source,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    if warnings.is_empty() {
        ui::success("Policy is portable — no agent-specific tool names found.");
        println!(
            "  All tool name rules use canonical names or capabilities that work across agents."
        );
    } else {
        println!(
            "  {} portability warning(s) found:\n",
            style::yellow_bold(&warnings.len().to_string())
        );
        for w in &warnings {
            let location = w.source.as_deref().unwrap_or("unknown");
            print!(
                "  {} tool(\"{}\") is agent-specific",
                style::yellow_bold("!"),
                w.tool_name
            );
            if let Some(canonical) = w.canonical {
                print!(
                    " — use tool(\"{}\") for portability",
                    style::green_bold(canonical)
                );
            }
            println!();
            println!("    {}", style::dim(location));
        }
        println!();
        println!(
            "  {} Canonical names (shell, read, write, edit, glob, grep, web_fetch, web_search)",
            style::dim("Tip:")
        );
        println!(
            "  {} match across all supported agents automatically.",
            style::dim("    ")
        );
    }

    Ok(())
}

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
fn handle_edit(scope: Option<String>, raw: bool, test: bool) -> Result<()> {
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
    crate::tui::run_with_options(&path, test, false)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Allow / Deny / Remove handlers
// ---------------------------------------------------------------------------

/// The mutation to apply to a policy rule.
enum PolicyMutation {
    Allow { sandbox: Option<String> },
    Deny,
    Remove,
}

/// Shared pipeline for allow / deny / remove: resolve path, build node, mutate, write, report.
fn apply_mutation(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
    mutation: PolicyMutation,
) -> Result<()> {
    let path = resolve_manifest_path(scope)?;
    if path.extension().is_some_and(|ext| ext == "star") {
        anyhow::bail!(
            "CLI rule mutations are not yet supported for .star files — use `clash policy edit` instead"
        );
    }
    let mut manifest = crate::policy_loader::read_manifest(&path)?;

    // For Remove we only need the observable chain — Decision::Deny is a dummy.
    let dummy_decision = Decision::Deny;
    let decision = match &mutation {
        PolicyMutation::Allow { sandbox } => Decision::Allow(
            sandbox
                .as_deref()
                .map(|s| crate::policy::match_tree::SandboxRef(s.to_string())),
        ),
        PolicyMutation::Deny | PolicyMutation::Remove => dummy_decision,
    };

    let node = build_rule_node(&command, tool, bin, decision)?;

    let result_str = match mutation {
        PolicyMutation::Remove => {
            if manifest_edit::remove_rule(&mut manifest, &node) {
                crate::policy_loader::write_manifest(&path, &manifest)?;
                println!("{} Rule removed", style::green_bold("✓"));
                println!("  {}", style::dim(&path.display().to_string()));
            } else {
                println!("No matching rule found");
            }
            return Ok(());
        }
        _ => {
            let result = manifest_edit::upsert_rule(&mut manifest, node);
            crate::policy_loader::write_manifest(&path, &manifest)?;
            match result {
                manifest_edit::UpsertResult::Inserted => "Rule added",
                manifest_edit::UpsertResult::Replaced => "Rule updated (replaced existing)",
            }
        }
    };

    println!("{} {}", style::green_bold("✓"), result_str);
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}

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

    // Prefer .star over .json — .star is the primary format when both exist.
    let star_path = dir.join("policy.star");
    if star_path.exists() {
        return Ok(star_path);
    }

    let json_path = dir.join("policy.json");
    if json_path.exists() {
        return Ok(json_path);
    }

    // No policy at all — create a bare manifest.
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    let manifest = PolicyManifest {
        includes: vec![],
        policy: crate::policy::match_tree::CompiledPolicy {
            sandboxes: std::collections::HashMap::new(),
            tree: vec![],
            default_effect: crate::policy::Effect::Deny,
            default_sandbox: None,
        },
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
        (Some(tool_name), None) => {
            // Resolve canonical/case-insensitive names: "shell" → "Bash", "bash" → "Bash", etc.
            let resolved = crate::agents::resolve_any_to_internal(tool_name).unwrap_or(tool_name);
            Ok(manifest_edit::build_tool_rule(resolved, decision))
        }
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
    apply_mutation(command, tool, bin, scope, PolicyMutation::Allow { sandbox })
}

fn handle_deny(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    apply_mutation(command, tool, bin, scope, PolicyMutation::Deny)
}

fn handle_remove(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    apply_mutation(command, tool, bin, scope, PolicyMutation::Remove)
}

/// Handle `clash policy convert` — convert policy.json to policy.star.
fn handle_convert(file: Option<PathBuf>, replace: bool) -> Result<()> {
    let json_path = match file {
        Some(p) => p,
        None => resolve_manifest_path(None)?,
    };

    if !json_path.exists() {
        anyhow::bail!("policy file not found: {}", json_path.display());
    }

    if json_path
        .extension()
        .is_some_and(|ext| ext == "star")
    {
        anyhow::bail!("file is already a .star file: {}", json_path.display());
    }

    // Read and parse the JSON manifest
    let raw = std::fs::read_to_string(&json_path)
        .with_context(|| format!("failed to read {}", json_path.display()))?;
    let manifest: PolicyManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", json_path.display()))?;

    // Convert manifest to Starlark AST
    let manifest_json = serde_json::to_value(&manifest.policy)
        .context("failed to serialize manifest")?;
    let tree = manifest_json
        .get("tree")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let sandboxes = manifest_json
        .get("sandboxes")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let default_effect = manifest_json
        .get("default_effect")
        .and_then(|v| v.as_str())
        .unwrap_or("ask");
    let default_sandbox = manifest_json
        .get("default_sandbox")
        .and_then(|v| v.as_str());

    // Build a fresh .star AST
    use clash_starlark::codegen::ast::{Expr, Stmt};
    use clash_starlark::codegen::builder;

    let effect_expr = match default_effect {
        "allow" => builder::allow(),
        "deny" => builder::deny(),
        _ => builder::ask(),
    };

    let mut stmts = vec![
        Stmt::load("@clash//std.star", &["policy", "settings", "allow", "deny", "ask"]),
        Stmt::Blank,
    ];

    // Add sandbox definitions
    for (name, sb_value) in &sandboxes {
        let expr = clash_starlark::codegen::from_manifest::sandbox_json_to_expr(name, sb_value);
        stmts.push(Stmt::Expr(expr));
        stmts.push(Stmt::Blank);
        clash_starlark::codegen::mutate::ensure_loaded(&mut stmts, "sandbox");
    }

    // Settings
    let settings = if let Some(sb) = default_sandbox {
        builder::settings(effect_expr.clone(), Some(Expr::string(sb)))
    } else {
        builder::settings(effect_expr.clone(), None)
    };
    stmts.push(Stmt::Expr(settings));
    stmts.push(Stmt::Blank);

    // Policy with rules
    let rule_exprs: Vec<Expr> = tree
        .iter()
        .map(clash_starlark::codegen::from_manifest::node_json_to_expr)
        .collect();
    let policy_expr = builder::policy("default", effect_expr, rule_exprs, None);
    stmts.push(Stmt::Expr(policy_expr));

    // Ensure we have all needed names in the load statement
    let source = clash_starlark::codegen::serialize(&stmts);

    // Determine which names are actually used and rebuild load
    for name in ["tool", "when", "sandbox"] {
        if source.contains(&format!("{name}(")) {
            clash_starlark::codegen::mutate::ensure_loaded(&mut stmts, name);
        }
    }

    let source = clash_starlark::codegen::serialize(&stmts);

    // Validate: evaluate the generated source to make sure it works
    let star_path = json_path.with_extension("star");
    let base_dir = json_path.parent().unwrap_or(Path::new("."));
    clash_starlark::evaluate(&source, &star_path.display().to_string(), base_dir)
        .context("generated .star file failed validation")?;

    // Write the .star file
    std::fs::write(&star_path, &source)
        .with_context(|| format!("failed to write {}", star_path.display()))?;

    info!(path = %star_path.display(), "wrote .star policy");
    eprintln!(
        "{} Converted {} → {}",
        style::green_bold("✓"),
        json_path.display(),
        star_path.display()
    );

    if replace {
        std::fs::remove_file(&json_path)
            .with_context(|| format!("failed to remove {}", json_path.display()))?;
        eprintln!(
            "{} Removed {}",
            style::green_bold("✓"),
            json_path.display()
        );
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
