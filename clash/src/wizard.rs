//! Interactive policy configuration wizard.
//!
//! Presents a terminal-based wizard using `dialoguer` that walks the user
//! through capability, network, and git-safety choices, then applies the
//! resulting rules to the policy YAML.

use anyhow::{Context, Result};
use dialoguer::{Confirm, MultiSelect, Select, theme::ColorfulTheme};

use crate::policy::ast::ProfileRule;
use crate::policy::edit::{self, InlineConstraintArgs};
use crate::policy::parse;

// ── Capability / git-safety enums ──────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Capability {
    Read,
    Edit,
    Bash,
    Web,
}

const CAPABILITY_LABELS: &[&str] = &[
    "Read files in this project",
    "Edit and create files in this project",
    "Run shell commands in this project",
    "Search the web and fetch URLs",
];

const CAPABILITIES: &[Capability] = &[
    Capability::Read,
    Capability::Edit,
    Capability::Bash,
    Capability::Web,
];

#[derive(Debug, Clone, Copy)]
enum GitSafety {
    BlockPush,
    BlockDestructive,
    ApproveCommit,
}

const GIT_LABELS: &[&str] = &[
    "Block git push (recommended)",
    "Block destructive operations: --force, --hard (recommended)",
    "Require approval for git commit",
];

const GIT_OPTIONS: &[GitSafety] = &[
    GitSafety::BlockPush,
    GitSafety::BlockDestructive,
    GitSafety::ApproveCommit,
];

// ── Helpers ────────────────────────────────────────────────────────────

/// Format a `ProfileRule` as "effect verb noun" (e.g. "allow bash *").
fn format_profile_rule(rule: &ProfileRule) -> String {
    let noun = crate::policy::ast::format_pattern_str(&rule.noun);
    format!("{} {} {}", rule.effect, rule.verb, noun)
}

// ── Public entry point ─────────────────────────────────────────────────

/// Run the interactive wizard, returning the modified YAML.
///
/// * `yaml`    – current policy YAML content
/// * `profile` – target profile name (usually "main")
/// * `cwd`     – working directory for scoping filesystem constraints
pub fn run(yaml: &str, profile: &str, cwd: &str) -> Result<String> {
    let theme = ColorfulTheme::default();

    // ── Handle existing rules ──────────────────────────────────────────
    let mut working_yaml = yaml.to_string();

    let doc = parse::parse_yaml(yaml).context("failed to parse policy.yaml")?;
    let existing_rules = parse::flatten_profile(profile, &doc.profile_defs).unwrap_or_default();

    if !existing_rules.is_empty() {
        println!("\nYou have {} rules configured:", existing_rules.len());
        for rule in &existing_rules {
            println!("  {}", format_profile_rule(rule));
        }
        println!();

        let reconfigure = Confirm::with_theme(&theme)
            .with_prompt("Reconfigure from scratch? (No = keep existing and add to them)")
            .default(false)
            .interact()?;

        if reconfigure {
            for rule in &existing_rules {
                let rule_str = format_profile_rule(rule);
                working_yaml = edit::remove_rule(&working_yaml, profile, &rule_str)
                    .unwrap_or_else(|_| working_yaml.clone());
            }
            println!("Cleared existing rules.");
        }
    }

    // ── Step 1: capabilities ───────────────────────────────────────────
    let defaults = &[true, false, false, false];

    println!();
    let selected_indices = MultiSelect::with_theme(&theme)
        .with_prompt("What should Claude be able to do?")
        .items(CAPABILITY_LABELS)
        .defaults(defaults)
        .interact()?;

    let selected_caps: Vec<Capability> =
        selected_indices.iter().map(|&i| CAPABILITIES[i]).collect();

    let bash_selected = selected_caps.iter().any(|c| matches!(c, Capability::Bash));

    // ── Step 2: network (only when bash is selected) ───────────────────
    let block_network = if bash_selected {
        println!();
        let choice = Select::with_theme(&theme)
            .with_prompt("Can shell commands access the network? (e.g. curl, npm install)")
            .items(&[
                "No  — block network access (recommended)",
                "Yes — allow network access",
            ])
            .default(0)
            .interact()?;
        choice == 0
    } else {
        false
    };

    // ── Step 3: git safety (only when bash is selected) ────────────────
    let git_selections: Vec<usize> = if bash_selected {
        let git_defaults = &[true, true, false];

        println!();
        MultiSelect::with_theme(&theme)
            .with_prompt("Git restrictions")
            .items(GIT_LABELS)
            .defaults(git_defaults)
            .interact()?
    } else {
        vec![]
    };

    // ── Build rule list from selections ────────────────────────────────
    let mut rules: Vec<(String, InlineConstraintArgs)> = Vec::new();

    for cap in &selected_caps {
        match cap {
            Capability::Read => {
                rules.push((
                    "allow read *".into(),
                    InlineConstraintArgs {
                        fs: vec![format!("read:subpath({})", cwd)],
                        ..Default::default()
                    },
                ));
            }
            Capability::Edit => {
                rules.push((
                    "allow edit *".into(),
                    InlineConstraintArgs {
                        fs: vec![format!("write:subpath({})", cwd)],
                        ..Default::default()
                    },
                ));
                rules.push((
                    "allow write *".into(),
                    InlineConstraintArgs {
                        fs: vec![format!("write+create:subpath({})", cwd)],
                        ..Default::default()
                    },
                ));
            }
            Capability::Bash => {
                rules.push((
                    "allow bash *".into(),
                    InlineConstraintArgs {
                        fs: vec![format!("full:subpath({})", cwd)],
                        network: if block_network {
                            Some("deny".into())
                        } else {
                            None
                        },
                        ..Default::default()
                    },
                ));
            }
            Capability::Web => {
                rules.push(("allow webfetch *".into(), InlineConstraintArgs::default()));
                rules.push(("allow websearch *".into(), InlineConstraintArgs::default()));
            }
        }
    }

    // Git safety deny/ask rules
    for &idx in &git_selections {
        match GIT_OPTIONS[idx] {
            GitSafety::BlockPush => {
                rules.push((
                    "deny bash git push*".into(),
                    InlineConstraintArgs::default(),
                ));
            }
            GitSafety::BlockDestructive => {
                rules.push((
                    "deny bash *--force*".into(),
                    InlineConstraintArgs::default(),
                ));
                rules.push(("deny bash *--hard*".into(), InlineConstraintArgs::default()));
            }
            GitSafety::ApproveCommit => {
                rules.push((
                    "ask bash git commit*".into(),
                    InlineConstraintArgs::default(),
                ));
            }
        }
    }

    // ── Summary ────────────────────────────────────────────────────────
    println!("\n--- Your policy ---");

    let mut can_lines: Vec<String> = Vec::new();
    for cap in &selected_caps {
        match cap {
            Capability::Read => can_lines.push(format!("  Read files in {}", cwd)),
            Capability::Edit => {
                can_lines.push(format!("  Edit and create files in {}", cwd));
            }
            Capability::Bash => {
                let net = if block_network {
                    " (network blocked)"
                } else {
                    ""
                };
                can_lines.push(format!("  Run commands in {}{}", cwd, net));
            }
            Capability::Web => {
                can_lines.push("  Search the web and fetch URLs".into());
            }
        }
    }

    if can_lines.is_empty() {
        println!("Claude can: (nothing — all actions require approval)");
    } else {
        println!("Claude can:");
        for line in &can_lines {
            println!("{}", line);
        }
    }

    let blocked: Vec<&str> = git_selections
        .iter()
        .filter_map(|&idx| match GIT_OPTIONS[idx] {
            GitSafety::BlockPush => Some("git push"),
            GitSafety::BlockDestructive => Some("--force, --hard"),
            GitSafety::ApproveCommit => None,
        })
        .collect();
    if !blocked.is_empty() {
        println!("\nBlocked:\n  {}", blocked.join(", "));
    }

    let needs_approval: Vec<&str> = git_selections
        .iter()
        .filter_map(|&idx| match GIT_OPTIONS[idx] {
            GitSafety::ApproveCommit => Some("git commit"),
            _ => None,
        })
        .collect();
    if !needs_approval.is_empty() {
        println!("\nRequires approval:\n  {}", needs_approval.join(", "));
    }

    println!("\nDefault: deny (unmatched actions are blocked)");
    println!();

    // ── Confirm ────────────────────────────────────────────────────────
    let apply = Confirm::with_theme(&theme)
        .with_prompt("Apply this policy?")
        .default(true)
        .interact()?;

    if !apply {
        println!("Cancelled. No changes were made.");
        return Ok(yaml.to_string());
    }

    // ── Apply rules ────────────────────────────────────────────────────
    for (rule_str, constraints) in &rules {
        working_yaml = edit::add_rule(&working_yaml, profile, rule_str, constraints)
            .with_context(|| format!("failed to add rule: {}", rule_str))?;
    }

    println!("Policy updated.");
    Ok(working_yaml)
}
