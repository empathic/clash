use anyhow::Result;
use tracing::{Level, instrument};

use crate::policy::Effect;
use crate::policy::ast::OpPattern;
use crate::policy::decision_tree::CompiledRule;
use crate::settings::{ClashSettings, PolicyLevel};
use crate::style;

/// Show policy status: layers, rules with shadowing, and potential issues.
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
    let tree = match settings.decision_tree() {
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

    let loaded = settings.loaded_policies();
    let multi_level = loaded.len() > 1;

    // Build a lookup for level paths.
    let level_path = |level: PolicyLevel| -> Option<String> {
        loaded
            .iter()
            .find(|lp| lp.level == level)
            .map(|lp| lp.path.display().to_string())
    };

    // 1. Policy layers
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

    // 2. Effective policy — rules in evaluation order with shadow detection
    println!(
        "{} {}",
        style::header("Effective policy"),
        style::dim(&format!(
            "(default: {})",
            style::effect(&tree.default.to_string())
        ))
    );
    println!("{}", style::dim("─────────────────────────────────"));

    let shadows = crate::policy::detect_all_shadows(tree);

    let print_rules =
        |label: &str,
         rules: &[CompiledRule],
         shadow_map: &std::collections::HashMap<usize, crate::policy::ShadowInfo>| {
            if rules.is_empty() {
                return;
            }

            // Count builtin vs non-builtin rules
            let builtin_count = rules
                .iter()
                .filter(|r| {
                    r.origin_policy
                        .as_ref()
                        .is_some_and(|p| p.starts_with("__internal_"))
                })
                .count();
            let non_builtin_count = rules.len() - builtin_count;

            // When not verbose and there are only builtin rules, show just the summary
            if !verbose && non_builtin_count == 0 && builtin_count > 0 {
                println!("  {}:", style::bold(label));
                println!(
                    "    {}",
                    style::dim(&format!(
                        "{} builtin rules (clash status --verbose to show)",
                        builtin_count
                    ))
                );
                return;
            }

            println!("  {}:", style::bold(label));

            // When not verbose, show builtin summary first, then non-builtin rules
            if !verbose && builtin_count > 0 {
                println!(
                    "    {}",
                    style::dim(&format!(
                        "{} builtin rules (clash status --verbose to show)",
                        builtin_count
                    ))
                );
            }

            for (i, rule) in rules.iter().enumerate() {
                let builtin = rule
                    .origin_policy
                    .as_ref()
                    .is_some_and(|p| p.starts_with("__internal_"));

                // Skip builtin rules in non-verbose mode
                if !verbose && builtin {
                    continue;
                }

                // Source tag: [builtin], [user], [project], [session]
                let tag = if builtin {
                    style::dim("[builtin]")
                } else if let Some(ref level) = rule.origin_level {
                    style::cyan(&format!("[{}]", level))
                } else {
                    String::new()
                };

                // Shadow indicator
                let shadow_note = if let Some(info) = shadow_map.get(&i) {
                    style::yellow(&format!("  <- shadowed by {}", info.shadowed_by_level))
                } else {
                    String::new()
                };

                let effect_str = style::effect(&format!("{:<5}", rule.effect));

                println!(
                    "    [{}] {:<45} {}{}",
                    effect_str, rule.source.matcher, tag, shadow_note,
                );
            }
        };

    print_rules("Exec", &tree.exec_rules, &shadows.exec);
    print_rules("Filesystem", &tree.fs_rules, &shadows.fs);
    print_rules("Network", &tree.net_rules, &shadows.net);
    print_rules("Tool", &tree.tool_rules, &shadows.tool);

    let total =
        tree.exec_rules.len() + tree.fs_rules.len() + tree.net_rules.len() + tree.tool_rules.len();
    if total == 0 {
        println!(
            "  {}",
            style::dim(&format!(
                "(no rules — default {} applies to everything)",
                tree.default
            ))
        );
    }

    let everything_else = match tree.default {
        Effect::Allow => style::green("allowed"),
        Effect::Deny => style::red("denied"),
        Effect::Ask => style::yellow("requires approval"),
    };
    println!("\n  Everything else: {}", everything_else);
    println!();

    // 3. Potential issues
    println!("{}", style::header("Potential issues"));
    println!("{}", style::dim("────────────────"));
    let mut issues = Vec::new();

    // Check for overly permissive wildcard exec rules
    for rule in &tree.exec_rules {
        if rule.effect == Effect::Allow
            && !rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            && let crate::policy::ast::CapMatcher::Exec(ref m) = rule.source.matcher
            && matches!(m.bin, crate::policy::ast::Pattern::Any)
        {
            issues.push(
                "Wildcard exec allow: all commands are allowed. Consider restricting to specific programs."
                    .to_string(),
            );
        }
    }

    // Check for overly permissive fs rules
    for rule in &tree.fs_rules {
        if rule.effect == Effect::Allow
            && !rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            && let crate::policy::ast::CapMatcher::Fs(ref m) = rule.source.matcher
            && matches!(m.op, OpPattern::Any)
            && m.path.is_none()
        {
            issues.push(
                "Wildcard filesystem allow: all file operations on all paths are allowed."
                    .to_string(),
            );
        }
    }

    // Check for overly permissive net rules
    for rule in &tree.net_rules {
        if rule.effect == Effect::Allow
            && !rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            && let crate::policy::ast::CapMatcher::Net(ref m) = rule.source.matcher
            && matches!(m.domain, crate::policy::ast::Pattern::Any)
        {
            issues.push(
                "Wildcard network allow: all domains are accessible. Consider restricting to specific domains."
                    .to_string(),
            );
        }
    }

    // Check default allow with no deny rules
    if tree.default == Effect::Allow
        && tree
            .exec_rules
            .iter()
            .chain(&tree.fs_rules)
            .chain(&tree.net_rules)
            .all(|r| r.effect != Effect::Deny)
    {
        issues.push("Default is allow with no deny rules: everything is permitted.".to_string());
    }

    // Check for shadowed rules
    let shadow_count =
        shadows.exec.len() + shadows.fs.len() + shadows.net.len() + shadows.tool.len();
    if shadow_count > 0 {
        issues.push(format!(
            "{} rule(s) shadowed by higher-precedence layers (marked with <- above).",
            shadow_count
        ));
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
