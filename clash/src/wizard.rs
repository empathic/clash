//! Interactive policy configurator.
//!
//! Walks users through building a policy rule by rule using a decision-tree
//! interface. Each step presents only syntactically valid options.
//! Called by `clash edit`.
//!
//! Every prompt supports Escape/q to go back to the previous step.

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, MultiSelect, Select};

use crate::policy::Effect;
use crate::policy::ast::*;
use crate::policy::edit;
use crate::settings::ClashSettings;

// ---------------------------------------------------------------------------
// Human-readable descriptions
// ---------------------------------------------------------------------------

/// Describe a rule in plain English.
pub fn describe_rule(rule: &Rule) -> String {
    let effect = describe_effect(rule.effect);
    let cap = describe_matcher(&rule.matcher);
    format!("{effect} {cap}")
}

fn describe_effect(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "Allow",
        Effect::Deny => "Deny",
        Effect::Ask => "Ask before",
    }
}

fn describe_matcher(matcher: &CapMatcher) -> String {
    match matcher {
        CapMatcher::Exec(m) => describe_exec(m),
        CapMatcher::Fs(m) => describe_fs(m),
        CapMatcher::Net(m) => describe_net(m),
        CapMatcher::Tool(m) => describe_tool(m),
    }
}

fn describe_exec(m: &ExecMatcher) -> String {
    let bin = describe_pattern(&m.bin);
    if m.args.is_empty() && m.has_args.is_empty() {
        return format!("running {bin}");
    }
    // Common pattern: (exec "git" *) → "running git (any args)"
    if m.has_args.is_empty() && m.args.len() == 1 && m.args[0] == Pattern::Any {
        return format!("running {bin} (any args)");
    }
    // Common pattern: (exec "git" "push" *) → "running git push (any trailing args)"
    if m.has_args.is_empty() && m.args.last() == Some(&Pattern::Any) && m.args.len() >= 2 {
        let fixed: Vec<String> = m.args[..m.args.len() - 1]
            .iter()
            .map(describe_pattern)
            .collect();
        return format!("running {bin} {} (any trailing args)", fixed.join(" "));
    }
    // Pure :has mode: "running git with push and --force (any order)"
    if m.args.is_empty() && !m.has_args.is_empty() {
        let has: Vec<String> = m.has_args.iter().map(describe_pattern).collect();
        return format!("running {bin} with {} (any order)", has.join(" and "));
    }
    // Mixed: positional + :has
    if !m.has_args.is_empty() {
        let positional: Vec<String> = m.args.iter().map(describe_pattern).collect();
        let has: Vec<String> = m.has_args.iter().map(describe_pattern).collect();
        return format!(
            "running {bin} {} with {} (any order)",
            positional.join(" "),
            has.join(" and ")
        );
    }
    let args: Vec<String> = m.args.iter().map(describe_pattern).collect();
    format!("running {bin} {} (exact)", args.join(" "))
}

fn describe_fs(m: &FsMatcher) -> String {
    let op = match &m.op {
        OpPattern::Any => "any operation on".to_string(),
        OpPattern::Single(op) => format!("{}ing", describe_fs_op(*op)),
        OpPattern::Or(ops) => {
            let names: Vec<&str> = ops.iter().map(|o| describe_fs_op(*o)).collect();
            format!("{}ing", names.join("/"))
        }
    };
    match &m.path {
        None => format!("{op} any file"),
        Some(pf) => format!("{op} {}", describe_path_filter(pf)),
    }
}

fn describe_fs_op(op: FsOp) -> &'static str {
    match op {
        FsOp::Read => "read",
        FsOp::Write => "write",
        FsOp::Create => "create",
        FsOp::Delete => "delete",
    }
}

fn describe_net(m: &NetMatcher) -> String {
    let domain = describe_pattern(&m.domain);
    format!("network access to {domain}")
}

fn describe_tool(m: &ToolMatcher) -> String {
    let name = describe_pattern(&m.name);
    format!("tool {name}")
}

fn describe_pattern(p: &Pattern) -> String {
    match p {
        Pattern::Any => "anything".into(),
        Pattern::Literal(s) => format!("\"{s}\""),
        Pattern::Regex(r) => format!("/{r}/"),
        Pattern::Or(ps) => {
            let parts: Vec<String> = ps.iter().map(describe_pattern).collect();
            parts.join(" or ")
        }
        Pattern::Not(inner) => format!("not {}", describe_pattern(inner)),
    }
}

fn describe_path_filter(pf: &PathFilter) -> String {
    match pf {
        PathFilter::Subpath(PathExpr::Env(name)) => format!("files under ${name}"),
        PathFilter::Subpath(PathExpr::Static(s)) => format!("files under {s}"),
        PathFilter::Subpath(PathExpr::Join(parts)) => {
            let desc: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    PathExpr::Env(name) => format!("${name}"),
                    PathExpr::Static(s) => s.clone(),
                    PathExpr::Join(_) => "(join ...)".into(),
                })
                .collect();
            format!("files under {}", desc.concat())
        }
        PathFilter::Literal(s) => format!("\"{s}\""),
        PathFilter::Regex(r) => format!("paths matching /{r}/"),
        PathFilter::Or(fs) => {
            let parts: Vec<String> = fs.iter().map(describe_path_filter).collect();
            parts.join(" or ")
        }
        PathFilter::Not(inner) => format!("not {}", describe_path_filter(inner)),
    }
}

// ---------------------------------------------------------------------------
// Prompt helpers (all return None on Escape = "go back")
// ---------------------------------------------------------------------------

/// Show a Select prompt. Returns `None` if the user presses Escape.
fn select(prompt: &str, items: &[&str]) -> Result<Option<usize>> {
    Select::new()
        .with_prompt(prompt)
        .items(items)
        .default(0)
        .interact_opt()
        .context("terminal error")
}

/// Show a MultiSelect prompt. Returns `None` if the user presses Escape.
fn multi_select(prompt: &str, items: &[&str]) -> Result<Option<Vec<usize>>> {
    MultiSelect::new()
        .with_prompt(prompt)
        .items(items)
        .interact_opt()
        .context("terminal error")
}

/// Show a text Input prompt. Returns `None` if the user presses Escape.
fn input(prompt: &str) -> Result<Option<String>> {
    Input::new()
        .with_prompt(prompt)
        .allow_empty(false)
        .interact_text()
        .map(Some)
        .context("terminal error")
}

/// Show a Confirm prompt. Returns `None` if the user presses Escape.
fn confirm(prompt: &str, default: bool) -> Result<Option<bool>> {
    Confirm::new()
        .with_prompt(prompt)
        .default(default)
        .interact_opt()
        .context("terminal error")
}

// ---------------------------------------------------------------------------
// Pattern prompts
// ---------------------------------------------------------------------------

/// Prompt the user to build a Pattern. Returns `None` to go back.
fn prompt_pattern(noun: &str) -> Result<Option<Pattern>> {
    let items = &["Any", "Specific (exact match)", "Regex pattern"];

    let sel = match select(&format!("Match which {noun}?"), items)? {
        Some(s) => s,
        None => return Ok(None),
    };

    match sel {
        0 => Ok(Some(Pattern::Any)),
        1 => {
            let value = match input(&format!("Enter exact {noun}"))? {
                Some(v) => v,
                None => return Ok(None),
            };
            Ok(Some(Pattern::Literal(value)))
        }
        2 => {
            let value = match input(&format!("Enter regex for {noun} (without slashes)"))? {
                Some(v) => v,
                None => return Ok(None),
            };
            Ok(Some(Pattern::Regex(value)))
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Domain-specific prompts
// ---------------------------------------------------------------------------

/// Prompt for an exec matcher. Returns `None` to go back.
///
/// The flow matches how people think about command rules:
///   - "any command"           → (exec)
///   - "git with any args"     → (exec "git" *)
///   - "git push with any args"→ (exec "git" "push" *)
///   - "exactly git status"    → (exec "git" "status")
fn prompt_exec() -> Result<Option<ExecMatcher>> {
    let bin = match prompt_pattern("command")? {
        Some(p) => p,
        None => return Ok(None),
    };

    // "Any command" needs no further qualification.
    if matches!(bin, Pattern::Any) {
        return Ok(Some(ExecMatcher {
            bin,
            args: vec![],
            has_args: vec![],
        }));
    }

    let items = &[
        "With any arguments    (recommended)  e.g. git *",
        "Subcommand + any args (positional)   e.g. git push *",
        "Exact invocation only                e.g. git status",
        "Contains arguments    (any order)    e.g. git push :has --force",
    ];

    let sel = match select("How should arguments be matched?", items)? {
        Some(s) => s,
        None => return Ok(None),
    };

    match sel {
        // (exec "git" *)
        0 => Ok(Some(ExecMatcher {
            bin,
            args: vec![Pattern::Any],
            has_args: vec![],
        })),

        // (exec "git" "push" *) — prompt for positional args
        1 => {
            println!(
                "  Note: arguments are matched by position. \"git push *\" matches\n  \
                 \"git push origin\" but NOT \"git --verbose push\"."
            );
            let mut sub_args = Vec::new();
            loop {
                let sub = match input("Enter subcommand / argument")? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                sub_args.push(Pattern::Literal(sub));

                match confirm("Add another fixed argument?", false)? {
                    Some(true) => continue,
                    _ => break,
                }
            }
            // Trailing wildcard so it matches any remaining args.
            sub_args.push(Pattern::Any);
            Ok(Some(ExecMatcher {
                bin,
                args: sub_args,
                has_args: vec![],
            }))
        }

        // (exec "git" "status") — exact, no trailing wildcard
        2 => {
            let mut exact_args = Vec::new();
            match confirm("Does this command take specific arguments?", false)? {
                Some(true) => loop {
                    let arg = match input("Enter argument")? {
                        Some(v) => v,
                        None => return Ok(None),
                    };
                    exact_args.push(Pattern::Literal(arg));

                    match confirm("Add another argument?", false)? {
                        Some(true) => continue,
                        _ => break,
                    }
                },
                Some(false) => {} // no args — matches bare command only
                None => return Ok(None),
            }
            Ok(Some(ExecMatcher {
                bin,
                args: exact_args,
                has_args: vec![],
            }))
        }

        // (exec "git" "push" :has "--force") — subcommand + order-independent flags
        3 => {
            println!(
                "  First, enter any subcommands that must appear in order (positional).\n  \
                 Then, enter arguments that must appear anywhere (any order).\n  \
                 Example: git push :has \"--force\" matches \"git push --force origin\"."
            );

            // Optional positional subcommand(s).
            let mut positional = Vec::new();
            match confirm("Does this rule start with a subcommand (e.g. push)?", true)? {
                Some(true) => loop {
                    let sub = match input("Enter subcommand")? {
                        Some(v) => v,
                        None => return Ok(None),
                    };
                    positional.push(Pattern::Literal(sub));

                    match confirm("Add another positional subcommand?", false)? {
                        Some(true) => continue,
                        _ => break,
                    }
                },
                Some(false) => {}
                None => return Ok(None),
            }

            // Required orderless arguments.
            let mut has_args = Vec::new();
            loop {
                let arg = match input("Enter required argument (matched in any order)")? {
                    Some(v) => v,
                    None => return Ok(None),
                };
                has_args.push(Pattern::Literal(arg));

                match confirm("Add another required argument?", false)? {
                    Some(true) => continue,
                    _ => break,
                }
            }
            Ok(Some(ExecMatcher {
                bin,
                args: positional,
                has_args,
            }))
        }

        _ => unreachable!(),
    }
}

/// Prompt for a filesystem matcher. Returns `None` to go back.
fn prompt_fs() -> Result<Option<FsMatcher>> {
    let op_items = &["Any operation", "read", "write", "create", "delete"];
    let selections = match multi_select(
        "Which filesystem operations? (space to select, enter to confirm)",
        op_items,
    )? {
        Some(s) => s,
        None => return Ok(None),
    };

    let op = if selections.is_empty() || selections.contains(&0) {
        OpPattern::Any
    } else {
        let ops: Vec<FsOp> = selections
            .iter()
            .filter_map(|&i| match i {
                1 => Some(FsOp::Read),
                2 => Some(FsOp::Write),
                3 => Some(FsOp::Create),
                4 => Some(FsOp::Delete),
                _ => None,
            })
            .collect();
        match ops.len() {
            0 => OpPattern::Any,
            1 => OpPattern::Single(ops[0]),
            _ => OpPattern::Or(ops),
        }
    };

    let path = match prompt_path_filter()? {
        Some(p) => p,
        None => return Ok(None),
    };

    Ok(Some(FsMatcher { op, path }))
}

/// Prompt for an optional path filter. Returns `None` to go back.
/// The inner `Option<PathFilter>` represents "any path" (None) vs a specific filter.
fn prompt_path_filter() -> Result<Option<Option<PathFilter>>> {
    let items = &[
        "Any path",
        "Under current directory ($PWD)",
        "Under home directory ($HOME)",
        "Under a custom path",
        "Exact file path",
        "Regex pattern on path",
    ];

    let sel = match select("Constrain to which paths?", items)? {
        Some(s) => s,
        None => return Ok(None),
    };

    match sel {
        0 => Ok(Some(None)),
        1 => Ok(Some(Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))))),
        2 => Ok(Some(Some(PathFilter::Subpath(PathExpr::Env(
            "HOME".into(),
        ))))),
        3 => {
            let path = match input("Enter path")? {
                Some(v) => v,
                None => return Ok(None),
            };
            Ok(Some(Some(PathFilter::Subpath(PathExpr::Static(path)))))
        }
        4 => {
            let path = match input("Enter exact file path")? {
                Some(v) => v,
                None => return Ok(None),
            };
            Ok(Some(Some(PathFilter::Literal(path))))
        }
        5 => {
            let regex = match input("Enter path regex (without slashes)")? {
                Some(v) => v,
                None => return Ok(None),
            };
            Ok(Some(Some(PathFilter::Regex(regex))))
        }
        _ => unreachable!(),
    }
}

/// Prompt for a network matcher. Returns `None` to go back.
fn prompt_net() -> Result<Option<NetMatcher>> {
    let domain = match prompt_pattern("domain")? {
        Some(p) => p,
        None => return Ok(None),
    };
    Ok(Some(NetMatcher { domain }))
}

// ---------------------------------------------------------------------------
// Rule building
// ---------------------------------------------------------------------------

/// Prompt to build a complete rule. Returns `None` if cancelled at any step.
fn prompt_rule() -> Result<Option<Rule>> {
    // Effect — Escape cancels the whole rule.
    let effects = &["Allow", "Deny", "Ask (prompt user)"];
    let effect = match select("Effect", effects)? {
        Some(0) => Effect::Allow,
        Some(1) => Effect::Deny,
        Some(2) => Effect::Ask,
        Some(_) => unreachable!(),
        None => return Ok(None),
    };

    // Domain — Escape goes back to effect, so we loop the whole thing.
    let matcher = 'domain: loop {
        let domains = &[
            "Commands   — what programs can be executed",
            "Filesystem — read, write, create, delete files",
            "Network    — which domains can be accessed",
        ];

        let domain_sel = match select("Capability", domains)? {
            Some(s) => s,
            None => return Ok(None), // back past effect = cancel
        };

        // Domain-specific prompts. None = go back to domain selection.
        let maybe_matcher = match domain_sel {
            0 => prompt_exec()?.map(CapMatcher::Exec),
            1 => prompt_fs()?.map(CapMatcher::Fs),
            2 => prompt_net()?.map(CapMatcher::Net),
            _ => unreachable!(),
        };

        match maybe_matcher {
            Some(m) => break 'domain m,
            None => continue, // re-show domain selection
        }
    };

    let rule = Rule {
        effect,
        matcher,
        sandbox: None,
    };

    // Preview
    println!();
    println!("  Rule:    {rule}");
    println!("  Meaning: {}", describe_rule(&rule));
    println!();

    match confirm("Add this rule?", true)? {
        Some(true) => Ok(Some(rule)),
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Rule display
// ---------------------------------------------------------------------------

/// Display all rules in the current policy.
fn show_rules(source: &str) -> Result<()> {
    let top_levels = crate::policy::parse::parse(source)?;
    let mut rules: Vec<Rule> = Vec::new();
    let mut policy_name = String::from("main");

    for tl in &top_levels {
        match tl {
            TopLevel::Default { policy, .. } => {
                policy_name = policy.clone();
            }
            TopLevel::Policy { name, body } => {
                for item in body {
                    if let PolicyItem::Rule(r) = item {
                        rules.push(r.clone());
                    }
                }
            }
        }
    }

    if rules.is_empty() {
        println!("  (no rules — default effect applies to everything)");
    } else {
        for (i, rule) in rules.iter().enumerate() {
            eprintln!("  {}. {} — {}", i + 1, rule, describe_rule(rule));
        }
    }

    Ok(())
}

/// Collect rules from the active policy for removal selection.
fn collect_rules(source: &str) -> Result<Vec<Rule>> {
    let top_levels = crate::policy::parse::parse(source)?;
    let policy_name = edit::active_policy(source)?;
    let mut rules = Vec::new();

    for tl in &top_levels {
        if let TopLevel::Policy { name, body } = tl
            && *name == policy_name
        {
            for item in body {
                if let PolicyItem::Rule(r) = item {
                    rules.push(r.clone());
                }
            }
        }
    }

    Ok(rules)
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run the interactive setup wizard.
pub fn run() -> Result<()> {
    println!("Clash Policy Setup");
    println!("==================");
    println!("Press Escape to go back at any point.\n");

    // Load or create the policy.
    let path = ClashSettings::policy_file()?;
    let mut source = if path.exists() {
        std::fs::read_to_string(&path).context("failed to read policy file")?
    } else {
        std::fs::create_dir_all(path.parent().unwrap())?;
        crate::settings::DEFAULT_POLICY.to_string()
    };

    println!("Current rules:\n{}", &source);
    show_rules(&source)?;
    println!();

    // Main loop.
    loop {
        let actions = &["Add a rule", "Remove a rule", "Done"];
        let action = match select("What would you like to do?", actions)? {
            Some(a) => a,
            None => break, // Escape at top level = Done
        };

        match action {
            // Add
            0 => {
                if let Some(rule) = prompt_rule()? {
                    let policy_name = edit::active_policy(&source)?;
                    source = edit::add_rule(&source, &policy_name, &rule)?;
                    println!("\nCurrent rules:");
                    show_rules(&source)?;
                    println!();
                }
            }
            // Remove
            1 => {
                let rules = collect_rules(&source)?;
                if rules.is_empty() {
                    println!("  No rules to remove.\n");
                    continue;
                }

                let items: Vec<String> = rules
                    .iter()
                    .map(|r| format!("{r}  — {}", describe_rule(r)))
                    .collect();
                let item_refs: Vec<&str> = items.iter().map(|s| s.as_str()).collect();

                if let Some(sel) = select("Remove which rule?", &item_refs)? {
                    let rule_text = rules[sel].to_string();
                    let policy_name = edit::active_policy(&source)?;
                    source = edit::remove_rule(&source, &policy_name, &rule_text)?;
                    println!("  Removed.\n");
                    println!("Current rules:");
                    show_rules(&source)?;
                    println!();
                }
            }
            // Done
            2 => break,
            _ => unreachable!(),
        }
    }

    // Validate and write.
    crate::policy::compile_policy(&source).context("policy validation failed")?;
    std::fs::write(&path, &source).context("failed to write policy file")?;

    println!("\nPolicy saved to {}", path.display());
    println!("Use 'clash status' to see what Claude can do.");
    println!("Use 'clash allow' / 'clash deny' to make quick changes anytime.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_exec_any() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Any,
                args: vec![],
                has_args: vec![],
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow running anything");
    }

    #[test]
    fn describe_exec_with_any_args() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("git".into()),
                args: vec![Pattern::Any],
                has_args: vec![],
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow running \"git\" (any args)");
    }

    #[test]
    fn describe_exec_subcommand_trailing() {
        let rule = Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("git".into()),
                args: vec![Pattern::Literal("push".into()), Pattern::Any],
                has_args: vec![],
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Deny running \"git\" \"push\" (any trailing args)"
        );
    }

    #[test]
    fn describe_exec_exact() {
        let rule = Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("git".into()),
                args: vec![Pattern::Literal("status".into())],
                has_args: vec![],
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Deny running \"git\" \"status\" (exact)"
        );
    }

    #[test]
    fn describe_fs_read_cwd() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Single(FsOp::Read),
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow reading files under $PWD");
    }

    #[test]
    fn describe_fs_multi_op() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Or(vec![FsOp::Write, FsOp::Create]),
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow writ/creating files under $PWD");
    }

    #[test]
    fn describe_net_any() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Net(NetMatcher {
                domain: Pattern::Any,
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow network access to anything");
    }

    #[test]
    fn describe_net_specific() {
        let rule = Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Net(NetMatcher {
                domain: Pattern::Literal("evil.com".into()),
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Deny network access to \"evil.com\"");
    }

    #[test]
    fn describe_ask_effect() {
        let rule = Rule {
            effect: Effect::Ask,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("rm".into()),
                args: vec![],
                has_args: vec![],
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Ask before running \"rm\"");
    }

    #[test]
    fn describe_fs_any_path() {
        let rule = Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Single(FsOp::Delete),
                path: None,
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Deny deleting any file");
    }

    #[test]
    fn describe_regex_pattern() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Regex(r"cargo-.*".into()),
                args: vec![],
                has_args: vec![],
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow running /cargo-.*/");
    }

    #[test]
    fn describe_or_pattern() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Net(NetMatcher {
                domain: Pattern::Or(vec![
                    Pattern::Literal("github.com".into()),
                    Pattern::Literal("crates.io".into()),
                ]),
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Allow network access to \"github.com\" or \"crates.io\""
        );
    }

    #[test]
    fn describe_exec_has_only() {
        let rule = Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("git".into()),
                args: vec![],
                has_args: vec![
                    Pattern::Literal("push".into()),
                    Pattern::Literal("--force".into()),
                ],
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Deny running \"git\" with \"push\" and \"--force\" (any order)"
        );
    }

    #[test]
    fn describe_exec_mixed_positional_has() {
        let rule = Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("git".into()),
                args: vec![Pattern::Literal("push".into())],
                has_args: vec![Pattern::Literal("--force".into())],
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Deny running \"git\" \"push\" with \"--force\" (any order)"
        );
    }
}
