use anyhow::{Context, Result, bail};
use tracing::{Level, instrument};

use crate::cli::PolicyCmd;
use crate::policy::Effect;
use crate::policy::ast::Rule as AstRule;
use crate::policy::ast::{
    CapMatcher, ExecMatcher, FsMatcher, FsOp, NetMatcher, OpPattern, PathExpr, PathFilter, Pattern,
    ToolMatcher,
};
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

/// Handle `clash policy` subcommands.
#[instrument(level = Level::TRACE)]
pub fn run(cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Shell {
            dry_run,
            scope,
            command,
        } => run_policy_shell(dry_run, scope, command),
        PolicyCmd::Schema { json } => super::schema::run(json),
        PolicyCmd::Explain { json, tool, args } => {
            let input = if args.is_empty() {
                None
            } else {
                Some(args.join(" "))
            };
            super::explain::run(json, tool, input)
        }
        PolicyCmd::Allow {
            rule,
            dry_run,
            scope,
        } => handle_allow_deny(Effect::Allow, &rule, dry_run, scope.as_deref()),
        PolicyCmd::Deny {
            rule,
            dry_run,
            scope,
        } => handle_allow_deny(Effect::Deny, &rule, dry_run, scope.as_deref()),
        PolicyCmd::Ask {
            rule,
            dry_run,
            scope,
        } => handle_allow_deny(Effect::Ask, &rule, dry_run, scope.as_deref()),
        PolicyCmd::Remove {
            rule,
            dry_run,
            scope,
        } => handle_remove(&rule, dry_run, scope.as_deref()),
        PolicyCmd::List { json } => handle_list(json),
        PolicyCmd::Validate { file, json } => handle_validate(file, json),
        PolicyCmd::Show { json } => handle_show(json),
    }
}

// ---------------------------------------------------------------------------
// Policy file I/O
// ---------------------------------------------------------------------------

/// Parse a `--scope` flag value into a `PolicyLevel`.
///
/// If `None`, uses `ClashSettings::default_scope()` (project if a project policy
/// exists, otherwise user).
fn resolve_scope(scope: Option<&str>) -> Result<PolicyLevel> {
    match scope {
        Some(s) => s.parse::<PolicyLevel>().context("invalid --scope value"),
        None => Ok(ClashSettings::default_scope()),
    }
}

/// Read the policy source from disk.
///
/// If a `PolicyLevel` is specified, loads from that level's path.
/// Otherwise, uses the user-level policy (backward-compatible default).
fn load_policy_source(level: Option<PolicyLevel>) -> Result<(std::path::PathBuf, String)> {
    let path = match level {
        Some(l) => ClashSettings::policy_file_for_level(l)?,
        None => ClashSettings::policy_file()?,
    };
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;
    Ok((path, source))
}

/// Write policy source back to disk after validating it compiles.
fn write_policy(path: &std::path::Path, source: &str) -> Result<()> {
    // Validate before writing — never write a broken policy.
    crate::policy::compile_policy(source)
        .context("modified policy failed to compile — not writing")?;
    // Ensure parent directory exists (important for project-level policies).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    std::fs::write(path, source)
        .with_context(|| format!("failed to write policy file: {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI rule parsing: bare verbs and s-expr syntax
// ---------------------------------------------------------------------------

/// Parse a CLI rule string into one or more AST rules.
///
/// Bare verbs (edit, bash, read, web) expand to convenient defaults.
/// Strings starting with `(` are parsed as s-expr matcher bodies.
fn parse_cli_rule(effect: Effect, rule_str: &str) -> Result<Vec<AstRule>> {
    if rule_str.starts_with('(') {
        // Power-user s-expr: parse as a capability matcher body and wrap with effect.
        let full = format!("(policy \"_\" ({effect} {rule_str}))");
        let top_levels =
            crate::policy::parse::parse(&full).context("failed to parse s-expr rule")?;
        match top_levels.into_iter().next() {
            Some(crate::policy::ast::TopLevel::Policy { mut body, .. }) => {
                let rules: Vec<AstRule> = body
                    .drain(..)
                    .filter_map(|item| match item {
                        crate::policy::ast::PolicyItem::Rule(r) => Some(r),
                        _ => None,
                    })
                    .collect();
                if rules.is_empty() {
                    bail!("no rule parsed from: {rule_str}");
                }
                Ok(rules)
            }
            _ => bail!("unexpected parse result for: {rule_str}"),
        }
    } else {
        // Bare verb shortcuts
        match rule_str {
            "bash" => Ok(vec![
                AstRule {
                    effect,
                    matcher: CapMatcher::Exec(ExecMatcher {
                        bin: Pattern::Any,
                        args: vec![],
                        has_args: vec![],
                    }),
                    sandbox: None,
                },
                AstRule {
                    effect,
                    matcher: CapMatcher::Fs(FsMatcher {
                        op: OpPattern::Or(vec![
                            FsOp::Read,
                            FsOp::Write,
                            FsOp::Create,
                            FsOp::Delete,
                        ]),
                        path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), true)),
                    }),
                    sandbox: None,
                },
            ]),
            "edit" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Fs(FsMatcher {
                    op: OpPattern::Or(vec![FsOp::Write, FsOp::Create]),
                    path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), true)),
                }),
                sandbox: None,
            }]),
            "read" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Fs(FsMatcher {
                    op: OpPattern::Single(FsOp::Read),
                    path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), true)),
                }),
                sandbox: None,
            }]),
            "web" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Net(NetMatcher {
                    domain: Pattern::Any,
                }),
                sandbox: None,
            }]),
            "tool" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Tool(ToolMatcher { name: Pattern::Any }),
                sandbox: None,
            }]),
            other => bail!(
                "unknown verb: {other}\n\nSupported verbs: bash, edit, read, web, tool\n\
                 Or pass an s-expr: clash policy allow '(exec \"git\" *)'"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

/// Minimal policy source used when creating a new project-level policy file.
const MINIMAL_POLICY: &str = "(default deny \"main\")\n(policy \"main\")\n";

/// Handle `clash allow`, `clash deny`, `clash ask`, `clash policy allow`, etc.
pub fn handle_allow_deny(
    effect: Effect,
    rule_str: &str,
    dry_run: bool,
    scope: Option<&str>,
) -> Result<()> {
    let level = resolve_scope(scope)?;

    // Load source for this level, creating a minimal policy for project scope if needed.
    let (path, source) = match load_policy_source(Some(level)) {
        Ok(ps) => ps,
        Err(_) if level == PolicyLevel::Project || level == PolicyLevel::Session => {
            let path = ClashSettings::policy_file_for_level(level)?;
            (path, MINIMAL_POLICY.to_string())
        }
        Err(e) => return Err(e),
    };

    let policy_name = crate::policy::edit::active_policy(&source)?;
    let rules = parse_cli_rule(effect, rule_str)?;

    let mut modified = source.clone();

    for rule in &rules {
        modified = crate::policy::edit::add_rule(&modified, &policy_name, rule)?;
    }

    if dry_run {
        print!("{modified}");
    } else if modified == source {
        println!("{} Rule already exists (no change).", style::dim("·"));
    } else {
        write_policy(&path, &modified)?;
        let level_msg = format!(
            "{} Added rule to {} policy",
            style::shield(),
            style::cyan(&level.to_string())
        );
        // Print a friendly confirmation for bare verbs, raw s-expr for power users.
        if let Some(msg) = friendly_confirmation(effect, rule_str) {
            println!("{} {msg}", style::green_bold("✓"));
            println!("{level_msg}");
        } else {
            for rule in &rules {
                println!("{} Added: {rule}", style::green_bold("✓"));
            }
            println!("{level_msg}");
        }
    }
    Ok(())
}

/// Return a human-friendly confirmation message for bare verb shortcuts.
fn friendly_confirmation(effect: Effect, verb: &str) -> Option<String> {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".into());

    let action = match effect {
        Effect::Allow => "can now",
        Effect::Deny => "can no longer",
        Effect::Ask => "will be asked before",
    };

    match verb {
        "edit" => Some(format!(
            "Claude {action} edit files in {cwd}.\n  \
             Files outside this directory are still protected."
        )),
        "bash" => Some(format!(
            "Claude {action} run commands.\n  \
             Use 'clash deny' to block specific dangerous commands."
        )),
        "read" => Some(format!("Claude {action} read files in {cwd}.")),
        "web" => Some(format!("Claude {action} search the web and fetch URLs.")),
        "tool" => Some(format!(
            "Claude {action} use agent tools (Skill, Task, etc.)."
        )),
        _ => None,
    }
}

/// Run `clash policy shell` — transactional policy editor.
fn run_policy_shell(dry_run: bool, scope: Option<String>, command: Option<String>) -> Result<()> {
    use crate::shell::ShellSession;
    use std::io::IsTerminal;

    if let Some(stmt) = command {
        // One-liner mode: -c 'add allow:bash'
        let mut session = ShellSession::new(scope.as_deref(), dry_run, false)?;
        session.run_command(&stmt)
    } else if !std::io::stdin().is_terminal() {
        // Pipe mode: read from stdin
        let mut session = ShellSession::new(scope.as_deref(), dry_run, false)?;
        let reader = std::io::BufReader::new(std::io::stdin().lock());
        session.run_pipe(reader)
    } else {
        // Interactive REPL
        let mut session = ShellSession::new(scope.as_deref(), dry_run, true)?;
        session.run_interactive()
    }
}

/// Parse an amend-style rule: either "(effect (matcher ...))" or "effect:verb".
///
/// Unlike `parse_cli_rule`, the effect is embedded in the rule string itself,
/// allowing mixed effects in a single amend command.
fn parse_amend_rule(rule_str: &str) -> Result<Vec<AstRule>> {
    if rule_str.starts_with('(') {
        let full = format!("(policy \"_\" {rule_str})");
        let top_levels =
            crate::policy::parse::parse(&full).context("failed to parse amend rule")?;
        match top_levels.into_iter().next() {
            Some(crate::policy::ast::TopLevel::Policy { mut body, .. }) => {
                let rules: Vec<AstRule> = body
                    .drain(..)
                    .filter_map(|item| match item {
                        crate::policy::ast::PolicyItem::Rule(r) => Some(r),
                        _ => None,
                    })
                    .collect();
                if rules.is_empty() {
                    bail!("no rule parsed from: {rule_str}");
                }
                Ok(rules)
            }
            _ => bail!("unexpected parse result for: {rule_str}"),
        }
    } else if let Some((effect_str, verb)) = rule_str.split_once(':') {
        let effect = match effect_str {
            "allow" => Effect::Allow,
            "deny" => Effect::Deny,
            "ask" => Effect::Ask,
            _ => bail!(
                "unknown effect: {effect_str}\n\n\
                 Supported effects: allow, deny, ask\n\
                 Example: clash amend allow:bash deny:web"
            ),
        };
        parse_cli_rule(effect, verb)
    } else {
        bail!(
            "invalid amend rule: {rule_str}\n\n\
             Expected either:\n  \
             - Full rule: '(allow (exec \"git\" *))'\n  \
             - Shortcut:  'allow:bash'"
        )
    }
}

/// Handle `clash amend` — add and remove multiple rules atomically.
pub fn handle_amend(
    rules: Vec<String>,
    remove: Vec<String>,
    dry_run: bool,
    scope: Option<&str>,
) -> Result<()> {
    let level = resolve_scope(scope)?;

    let (path, source) = match load_policy_source(Some(level)) {
        Ok(ps) => ps,
        Err(_) if level == PolicyLevel::Project || level == PolicyLevel::Session => {
            let path = ClashSettings::policy_file_for_level(level)?;
            (path, MINIMAL_POLICY.to_string())
        }
        Err(e) => return Err(e),
    };

    let policy_name = crate::policy::edit::active_policy(&source)?;
    let mut modified = source.clone();
    let mut added_count = 0usize;
    let mut removed_count = 0usize;
    let mut added_rules: Vec<String> = Vec::new();

    // Apply removals first (before adds, so we can replace rules atomically).
    for remove_str in &remove {
        modified = crate::policy::edit::remove_rule(&modified, &policy_name, remove_str)
            .with_context(|| format!("failed to remove rule: {remove_str}"))?;
        removed_count += 1;
    }

    // Apply additions.
    for rule_str in &rules {
        let parsed_rules = parse_amend_rule(rule_str)
            .with_context(|| format!("failed to parse rule: {rule_str}"))?;
        for rule in &parsed_rules {
            let before = modified.clone();
            modified = crate::policy::edit::add_rule(&modified, &policy_name, rule)?;
            if modified != before {
                added_count += 1;
                added_rules.push(rule.to_string());
            }
        }
    }

    if dry_run {
        print!("{modified}");
        return Ok(());
    }

    if modified == source {
        println!(
            "{} No changes needed (policy already up to date).",
            style::dim("·")
        );
        return Ok(());
    }

    write_policy(&path, &modified)?;

    let level_tag = style::cyan(&level.to_string());
    if added_count > 0 {
        for rule_str in &added_rules {
            println!("{} Added: {rule_str}", style::green_bold("✓"));
        }
    }
    if removed_count > 0 {
        for remove_str in &remove {
            println!("{} Removed: {remove_str}", style::red_bold("✗"));
        }
    }
    println!(
        "{} Amended {} policy ({} added, {} removed)",
        style::shield(),
        level_tag,
        added_count,
        removed_count,
    );

    Ok(())
}

/// Handle `clash policy remove`.
fn handle_remove(rule_str: &str, dry_run: bool, scope: Option<&str>) -> Result<()> {
    let level = resolve_scope(scope)?;

    let (path, source) = load_policy_source(Some(level))?;
    let policy_name = crate::policy::edit::active_policy(&source)?;
    let modified = crate::policy::edit::remove_rule(&source, &policy_name, rule_str)?;

    if dry_run {
        print!("{modified}");
    } else {
        write_policy(&path, &modified)?;
        println!(
            "{} Removed rule from {} policy: {rule_str}",
            style::red_bold("✗"),
            style::cyan(&level.to_string())
        );
    }
    Ok(())
}

/// Handle `clash policy list`.
fn handle_list(json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.decision_tree() {
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
    let tree = match settings.decision_tree() {
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
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                all_valid = false;
                if json {
                    results.push(serde_json::json!({
                        "level": level.to_string(),
                        "path": path.display().to_string(),
                        "valid": false,
                        "error": format!("failed to read: {}", e),
                    }));
                } else {
                    eprintln!(
                        "{} {} {}",
                        style::err_red_bold("✗"),
                        style::cyan(&format!("[{}]", level)),
                        path.display()
                    );
                    eprintln!("  {}", style::dim(&format!("failed to read: {}", e)));
                }
                continue;
            }
        };

        match crate::policy::compile_policy(&source) {
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
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read: {}", path.display()))?;

    match crate::policy::compile_policy(&source) {
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
