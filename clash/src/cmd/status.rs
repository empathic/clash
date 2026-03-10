use anyhow::Result;
use tracing::{Level, instrument};

use crate::display;
use crate::policy::Effect;
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

/// Show policy status: layers, rules, and potential issues.
#[instrument(level = Level::TRACE)]
pub fn run(_json: bool, verbose: bool) -> Result<()> {
    if crate::settings::is_disabled() {
        println!("{}", style::banner());
        println!();
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
    }

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
    println!("{}", style::header("Sandboxes"));
    println!("{}", style::dim("─────────────────────────────────"));
    if policy.sandboxes.is_empty() {
        println!("  {}", style::dim("(no sandboxes defined)"));
    }
    for (name, sb) in policy.sandboxes.iter() {
        println!("  {}", style::cyan(name));
        println!("    default: {}", style::dim(&sb.default.display()));
        for rule in &sb.rules {
            let effect_str = match rule.effect {
                crate::policy::sandbox_types::RuleEffect::Allow => style::green("allow"),
                crate::policy::sandbox_types::RuleEffect::Deny => style::red("deny"),
            };
            let match_suffix = match rule.path_match {
                crate::policy::sandbox_types::PathMatch::Subpath => "/**",
                crate::policy::sandbox_types::PathMatch::Literal => "",
                crate::policy::sandbox_types::PathMatch::Regex => " (regex)",
            };
            println!(
                "    {} {} {}",
                effect_str,
                rule.caps.display(),
                style::dim(&format!("{}{}", rule.path, match_suffix))
            );
        }
        let net_str = match &sb.network {
            crate::policy::sandbox_types::NetworkPolicy::Deny => style::red("deny"),
            crate::policy::sandbox_types::NetworkPolicy::Allow => style::green("allow"),
            crate::policy::sandbox_types::NetworkPolicy::Localhost => style::yellow("localhost"),
            crate::policy::sandbox_types::NetworkPolicy::AllowDomains(domains) => {
                style::green(&format!("allow [{}]", domains.join(", ")))
            }
        };
        println!("    network: {}", net_str);
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
