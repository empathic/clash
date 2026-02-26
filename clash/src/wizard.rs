//! Human-readable rule descriptions.
//!
//! Converts policy AST rules into plain-English descriptions used by the
//! policy shell and other display surfaces.

use crate::policy::Effect;
use crate::policy::ast::*;

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
        OpPattern::Single(op) => describe_fs_op_gerund(*op).to_string(),
        OpPattern::Or(ops) => {
            let names: Vec<&str> = ops.iter().map(|o| describe_fs_op_gerund(*o)).collect();
            names.join("/")
        }
    };
    match &m.path {
        None => format!("{op} any file"),
        Some(pf) => format!("{op} {}", describe_path_filter(pf)),
    }
}

fn describe_fs_op_gerund(op: FsOp) -> &'static str {
    match op {
        FsOp::Read => "reading",
        FsOp::Write => "writing",
        FsOp::Create => "creating",
        FsOp::Delete => "deleting",
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
        PathFilter::Subpath(PathExpr::Env(name), worktree) => {
            let wt = if *worktree {
                " (and git worktree paths)"
            } else {
                ""
            };
            format!("files under ${name}{wt}")
        }
        PathFilter::Subpath(PathExpr::Static(s), worktree) => {
            let wt = if *worktree {
                " (and git worktree paths)"
            } else {
                ""
            };
            format!("files under {s}{wt}")
        }
        PathFilter::Subpath(PathExpr::Join(parts), worktree) => {
            let desc: Vec<String> = parts
                .iter()
                .map(|p| match p {
                    PathExpr::Env(name) => format!("${name}"),
                    PathExpr::Static(s) => s.clone(),
                    PathExpr::Join(_) => "(join ...)".into(),
                })
                .collect();
            let wt = if *worktree {
                " (and git worktree paths)"
            } else {
                ""
            };
            format!("files under {}{wt}", desc.concat())
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
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), false)),
            }),
            sandbox: None,
        };
        assert_eq!(describe_rule(&rule), "Allow reading files under $PWD");
    }

    #[test]
    fn describe_fs_read_cwd_worktree() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Single(FsOp::Read),
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), true)),
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Allow reading files under $PWD (and git worktree paths)"
        );
    }

    #[test]
    fn describe_fs_write_static_worktree() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Single(FsOp::Write),
                path: Some(PathFilter::Subpath(
                    PathExpr::Static("/tmp/project".into()),
                    true,
                )),
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Allow writing files under /tmp/project (and git worktree paths)"
        );
    }

    #[test]
    fn describe_fs_join_worktree() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Single(FsOp::Read),
                path: Some(PathFilter::Subpath(
                    PathExpr::Join(vec![
                        PathExpr::Env("HOME".into()),
                        PathExpr::Static("/projects".into()),
                    ]),
                    true,
                )),
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Allow reading files under $HOME/projects (and git worktree paths)"
        );
    }

    #[test]
    fn describe_fs_multi_op() {
        let rule = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Fs(FsMatcher {
                op: OpPattern::Or(vec![FsOp::Write, FsOp::Create]),
                path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), false)),
            }),
            sandbox: None,
        };
        assert_eq!(
            describe_rule(&rule),
            "Allow writing/creating files under $PWD"
        );
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
