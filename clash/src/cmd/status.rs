use anyhow::Result;
use tracing::{Level, instrument};

use crate::display;
use crate::policy::Effect;
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

/// Show policy status: layers, rules, and potential issues.
#[instrument(level = Level::TRACE)]
pub fn run(_json: bool, verbose: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let policy = match settings.policy_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                eprintln!("Policy error: {}", err);
            } else {
                eprintln!("No policy configured. Run `clash init` to get started.");
            }
            return Ok(());
        }
    };

    // Banner
    println!("{}", style::banner());
    println!();

    if crate::settings::is_disabled() {
        println!(
            "  {} Clash is {}",
            style::yellow_bold("!"),
            style::yellow_bold("DISABLED")
        );
        println!(
            "  {} is set — all hooks are pass-through, no policy enforcement is active.",
            style::cyan("CLASH_DISABLE")
        );
        println!("  Unset the variable to re-enable clash.");
        return Ok(());
    } else if crate::settings::is_passthrough() {
        println!(
            "  {} Clash is in {} mode",
            style::yellow_bold("!"),
            style::yellow_bold("PASSTHROUGH")
        );
        println!(
            "  {} is set — permission decisions are deferred to Claude Code's native permission system.",
            style::cyan("CLASH_PASSTHROUGH")
        );
        println!("  Unset the variable to re-enable policy enforcement.");
        println!();
    }

    // Policy version
    println!(
        "{} {}",
        style::header("Policy version"),
        style::dim("(syntax v5)")
    );
    println!();

    let loaded = settings.loaded_policies();
    let multi_level = loaded.len() > 1;

    let level_path = |level: PolicyLevel| -> Option<String> {
        loaded
            .iter()
            .find(|lp| lp.level == level)
            .map(|lp| lp.path.display().to_string())
    };

    println!("{}", style::header("Policy layers"));
    println!("{}", style::dim("─────────────"));
    for &level in &[
        PolicyLevel::User,
        PolicyLevel::Project,
        PolicyLevel::Session,
    ] {
        match level_path(level) {
            Some(path) => println!("  {:<10} {}", style::cyan(&format!("{}:", level)), path),
            None => println!(
                "  {:<10} {}",
                style::cyan(&format!("{}:", level)),
                style::dim("(none)")
            ),
        }
    }
    if multi_level {
        println!();
        println!(
            "  {}",
            style::dim("Precedence: session > project > user (automatic)")
        );
    }
    println!();

    println!(
        "{} {}",
        style::header("Effective policy"),
        style::dim(&format!(
            "(default: {})",
            style::effect(&policy.default_effect.to_string())
        ))
    );
    println!("{}", style::dim("─────────────────────────────────"));

    let lines = policy.format_tree();
    if lines.is_empty() {
        println!(
            "  {}",
            style::dim(&format!(
                "(no rules — default {} applies to everything)",
                policy.default_effect
            ))
        );
    } else {
        for line in &lines {
            println!("  {}", colorize_tree_line(line));
        }
    }

    let everything_else = match policy.default_effect {
        Effect::Allow => style::green("allowed"),
        Effect::Deny => style::red("denied"),
        Effect::Ask => style::yellow("requires approval"),
    };
    println!("\n  Everything else: {}", everything_else);
    println!();
    println!(
        "{}  {}",
        style::header("Sandboxes"),
        style::dim("r=read w=write c=create d=delete x=execute")
    );
    println!("{}", style::dim("─────────────────────────────────"));
    if policy.sandboxes.is_empty() {
        println!("  {}", style::dim("(no sandboxes defined)"));
    } else {
        print_sandbox_table(&policy.sandboxes);
    }

    println!("{}", style::header("Potential issues"));
    println!("{}", style::dim("────────────────"));

    let mut issues = Vec::new();

    if policy.default_effect == Effect::Allow && policy.tree.is_empty() {
        issues.push("Default is allow with no rules: everything is permitted.".to_string());
    }

    if issues.is_empty() {
        println!("  {} No issues detected.", style::green_bold("✓"));
    } else {
        for issue in &issues {
            println!("  {} {}", style::yellow_bold("!"), issue);
        }
    }

    Ok(())
}

/// Right-pad a (possibly ANSI-colored) string to `width` visible characters.
fn rpad(s: &str, width: usize) -> String {
    console::pad_str(s, width, console::Alignment::Left, None).into_owned()
}

/// Left-pad a (possibly ANSI-colored) string to `width` visible characters.
fn lpad(s: &str, width: usize) -> String {
    console::pad_str(s, width, console::Alignment::Right, None).into_owned()
}

/// Print sandboxes as a compact matrix: paths down the left, sandbox names across the top.
fn print_sandbox_table(
    sandboxes: &std::collections::HashMap<String, crate::policy::sandbox_types::SandboxPolicy>,
) {
    use crate::policy::sandbox_types::{NetworkPolicy, RuleEffect};

    let mut names: Vec<&str> = sandboxes.keys().map(|s| s.as_str()).collect();
    names.sort();

    // Collect unique path labels, then sort by specificity (general first).
    let mut paths: Vec<String> = Vec::new();
    for name in &names {
        for rule in &sandboxes[*name].rules {
            let suffix = match rule.path_match {
                crate::policy::sandbox_types::PathMatch::Subpath => "/**",
                crate::policy::sandbox_types::PathMatch::Literal => "",
                crate::policy::sandbox_types::PathMatch::Regex => " (re)",
            };
            let key = format!("{}{}", rule.path, suffix);
            if !paths.contains(&key) {
                paths.push(key);
            }
        }
    }
    paths.sort_by_key(|p| {
        let stripped = p.strip_suffix("/**").unwrap_or(p);
        stripped.matches('/').count() + stripped.matches('$').count()
    });

    // Collect unique network domains across sandboxes.
    let mut domains: Vec<String> = Vec::new();
    for name in &names {
        if let NetworkPolicy::AllowDomains(ds) = &sandboxes[*name].network {
            for d in ds {
                if !domains.contains(d) {
                    domains.push(d.clone());
                }
            }
        }
    }

    let col_w = names.iter().map(|n| n.len()).max().unwrap_or(5).max(5);
    let domain_max = domains.iter().map(|d| d.len()).max().unwrap_or(0);
    let path_w = paths
        .iter()
        .map(|p| p.len())
        .max()
        .unwrap_or(7)
        .max(domain_max)
        .max(7);

    // Header row.
    let hdr: Vec<String> = names.iter().map(|n| lpad(&style::cyan(n), col_w)).collect();
    println!("  {} {}", rpad("", path_w), hdr.join(" "));

    // Default row.
    let def: Vec<String> = names
        .iter()
        .map(|n| lpad(&style::dim(&sandboxes[*n].default.short()), col_w))
        .collect();
    println!("  {} {}", rpad(&style::dim("default"), path_w), def.join(" "));

    // Network row.
    let net: Vec<String> = names
        .iter()
        .map(|n| {
            let s = match &sandboxes[*n].network {
                NetworkPolicy::Deny => style::red("deny"),
                NetworkPolicy::Allow => style::green("allow"),
                NetworkPolicy::Localhost => style::yellow("localhost"),
                NetworkPolicy::AllowDomains(_) => style::yellow("proxy"),
            };
            lpad(&s, col_w)
        })
        .collect();
    println!("  {} {}", rpad(&style::dim("net"), path_w), net.join(" "));

    // Domain rows.
    for domain in &domains {
        let cells: Vec<String> = names
            .iter()
            .map(|n| {
                let cell = match &sandboxes[*n].network {
                    NetworkPolicy::Allow => style::green("allow"),
                    NetworkPolicy::AllowDomains(ds) if ds.iter().any(|d| d == domain) => {
                        style::green("allow")
                    }
                    _ => style::dim("·····"),
                };
                lpad(&cell, col_w)
            })
            .collect();
        println!("  {} {}", rpad(&style::dim(domain), path_w), cells.join(" "));
    }

    // Path rows.
    for path in &paths {
        let cells: Vec<String> = names
            .iter()
            .map(|n| {
                let matched = sandboxes[*n].rules.iter().find(|r| {
                    let suffix = match r.path_match {
                        crate::policy::sandbox_types::PathMatch::Subpath => "/**",
                        crate::policy::sandbox_types::PathMatch::Literal => "",
                        crate::policy::sandbox_types::PathMatch::Regex => " (re)",
                    };
                    format!("{}{}", r.path, suffix) == *path
                });
                let cell = match matched {
                    Some(r) => {
                        let s = r.caps.short();
                        match r.effect {
                            RuleEffect::Allow => style::green(&s),
                            RuleEffect::Deny => style::red(&s),
                        }
                    }
                    None => style::dim("·····"),
                };
                lpad(&cell, col_w)
            })
            .collect();
        println!("  {} {}", rpad(&style::dim(path), path_w), cells.join(" "));
    }
}

/// Colorize a tree line by highlighting the effect after the `→` separator.
fn colorize_tree_line(line: &str) -> String {
    if let Some(idx) = line.rfind(" → ") {
        let (prefix, rest) = line.split_at(idx);
        let effect = &rest[" → ".len()..];
        format!("{} → {}", prefix, display::colorize_effect_prefix(effect))
    } else if line.starts_with("allow") || line.starts_with("deny") || line.starts_with("ask") {
        display::colorize_effect_prefix(line)
    } else {
        line.to_string()
    }
}
