//! Interactive policy configuration wizard.
//!
//! Walks users through enabling capabilities step by step.
//! Called by `clash policy setup`.

use std::io::{self, BufRead, Write};

use anyhow::{Context, Result};

use crate::policy::Effect;
use crate::policy::v2::ast::*;
use crate::settings::ClashSettings;

/// Capability choice presented during the wizard.
struct Capability {
    /// Short name shown to the user.
    verb: &'static str,
    /// One-line description shown to the user.
    description: &'static str,
    /// The rules to add when this capability is allowed.
    allow_rules: fn() -> Vec<Rule>,
}

fn bash_rules() -> Vec<Rule> {
    vec![Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Any,
            args: vec![],
        }),
        sandbox: None,
    }]
}

fn edit_rules() -> Vec<Rule> {
    vec![Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Fs(FsMatcher {
            op: OpPattern::Or(vec![FsOp::Write, FsOp::Create]),
            path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
        }),
        sandbox: None,
    }]
}

fn read_rules() -> Vec<Rule> {
    vec![Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Fs(FsMatcher {
            op: OpPattern::Single(FsOp::Read),
            path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
        }),
        sandbox: None,
    }]
}

fn web_rules() -> Vec<Rule> {
    vec![Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Net(NetMatcher {
            domain: Pattern::Any,
        }),
        sandbox: None,
    }]
}

const CAPABILITIES: &[Capability] = &[
    Capability {
        verb: "read",
        description: "Read files in your project",
        allow_rules: read_rules,
    },
    Capability {
        verb: "edit",
        description: "Edit and create files in your project",
        allow_rules: edit_rules,
    },
    Capability {
        verb: "bash",
        description: "Run shell commands",
        allow_rules: bash_rules,
    },
    Capability {
        verb: "web",
        description: "Search the web and fetch URLs",
        allow_rules: web_rules,
    },
];

enum Choice {
    Allow,
    Deny,
    Skip,
}

/// Run the interactive setup wizard.
pub fn run() -> Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    println!("Clash Policy Setup");
    println!("==================\n");
    println!("This wizard will configure what Claude can do in this project.");
    println!("For each capability, choose: allow, deny, or skip.\n");

    let mut to_allow: Vec<&Capability> = Vec::new();
    let mut to_deny: Vec<&Capability> = Vec::new();

    for cap in CAPABILITIES {
        let choice = prompt_capability(&mut reader, cap)?;
        match choice {
            Choice::Allow => to_allow.push(cap),
            Choice::Deny => to_deny.push(cap),
            Choice::Skip => {}
        }
    }

    println!();

    if to_allow.is_empty() && to_deny.is_empty() {
        println!("No changes made. Your policy is unchanged.");
        println!("\nYou can always add rules later:");
        println!("  clash allow edit     Allow file editing");
        println!("  clash allow bash     Allow commands");
        return Ok(());
    }

    // Load the policy
    let path = ClashSettings::policy_file()?;
    let source = if path.exists() {
        std::fs::read_to_string(&path).context("failed to read policy file")?
    } else {
        crate::settings::DEFAULT_POLICY.to_string()
    };

    let policy_name = crate::policy::edit::active_policy(&source)?;
    let mut current = source;

    // Apply allow rules
    for cap in &to_allow {
        for rule in (cap.allow_rules)() {
            current = crate::policy::edit::add_rule(&current, &policy_name, &rule)?;
        }
        println!("  Allowed: {}", cap.verb);
    }

    // Apply deny rules (same rules but with deny effect)
    for cap in &to_deny {
        for mut rule in (cap.allow_rules)() {
            rule.effect = Effect::Deny;
            current = crate::policy::edit::add_rule(&current, &policy_name, &rule)?;
        }
        println!("  Denied:  {}", cap.verb);
    }

    // Validate before writing
    crate::policy::v2::compile_policy(&current).context("modified policy is invalid")?;
    std::fs::write(&path, &current).context("failed to write policy file")?;

    println!("\nSetup complete. Use 'clash policy list' to see your rules.");
    println!("Use 'clash allow' / 'clash deny' to make changes anytime.");

    Ok(())
}

fn prompt_capability(reader: &mut impl BufRead, cap: &Capability) -> Result<Choice> {
    loop {
        print!(
            "  {} — {} [a]llow / [d]eny / [s]kip? ",
            cap.verb, cap.description
        );
        io::stdout().flush()?;

        let mut input = String::new();
        if reader.read_line(&mut input)? == 0 {
            println!();
            return Ok(Choice::Skip);
        }

        match input.trim().to_lowercase().as_str() {
            "a" | "allow" => return Ok(Choice::Allow),
            "d" | "deny" => return Ok(Choice::Deny),
            "s" | "skip" | "" => return Ok(Choice::Skip),
            _ => println!("    Please enter 'a', 'd', or 's'."),
        }
    }
}
