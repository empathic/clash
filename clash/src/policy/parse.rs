//! Parser: s-expression tokens → AST.
//!
//! Consumes the generic `SExpr` tree from `sexpr.rs` and produces typed
//! `TopLevel` nodes. Errors are reported with source spans.

use anyhow::{Result, bail, ensure};

use crate::policy::Effect;
use crate::policy::sexpr::{self, SExpr};

use super::ast::*;

/// Parse a policy source string into a list of top-level declarations.
pub fn parse(source: &str) -> Result<Vec<TopLevel>> {
    let sexprs = sexpr::parse(source).map_err(|e| anyhow::anyhow!("{e}"))?;
    sexprs.iter().map(parse_top_level).collect()
}

fn parse_top_level(expr: &SExpr) -> Result<TopLevel> {
    let list = require_list(expr, "top-level form")?;
    let head = require_atom(&list[0], "top-level keyword")?;
    match head {
        "default" => parse_default(list),
        "policy" => parse_policy(list),
        other => bail!("unknown top-level form: {other}"),
    }
}

fn parse_default(list: &[SExpr]) -> Result<TopLevel> {
    ensure!(
        list.len() == 3,
        "(default) expects exactly 2 arguments: effect and policy name"
    );
    let effect = parse_effect(&list[1])?;
    let policy = require_string(&list[2], "policy name")?;
    Ok(TopLevel::Default {
        effect,
        policy: policy.to_string(),
    })
}

fn parse_policy(list: &[SExpr]) -> Result<TopLevel> {
    ensure!(list.len() >= 2, "(policy) requires a name");
    let name = require_string(&list[1], "policy name")?.to_string();
    let body = list[2..]
        .iter()
        .map(parse_policy_item)
        .collect::<Result<_>>()?;
    Ok(TopLevel::Policy { name, body })
}

fn parse_policy_item(expr: &SExpr) -> Result<PolicyItem> {
    let list = require_list(expr, "policy item")?;
    let head = require_atom(&list[0], "policy item keyword")?;
    match head {
        "include" => {
            ensure!(list.len() == 2, "(include) expects exactly 1 argument");
            let name = require_string(&list[1], "include target")?;
            Ok(PolicyItem::Include(name.to_string()))
        }
        "allow" | "deny" | "ask" => {
            let effect = parse_effect_str(head)?;
            ensure!(
                list.len() >= 2,
                "({head}) expects at least 1 capability matcher"
            );
            let matcher = parse_cap_matcher(&list[1])?;

            // Scan remaining elements for :sandbox "name" keyword arg.
            let sandbox = parse_keyword_sandbox(&list[2..])?;

            Ok(PolicyItem::Rule(Rule {
                effect,
                matcher,
                sandbox,
            }))
        }
        other => bail!("unknown policy item: {other}"),
    }
}

/// Parse an optional `:sandbox "name"` keyword argument from remaining elements.
fn parse_keyword_sandbox(rest: &[SExpr]) -> Result<Option<String>> {
    if let Some((i, expr)) = rest.iter().enumerate().next() {
        match expr {
            SExpr::Atom(s, _) if s == ":sandbox" => {
                ensure!(i + 1 < rest.len(), ":sandbox requires a string argument");
                let name = require_string(&rest[i + 1], ":sandbox value")?;
                Ok(Some(name.to_string()))
            }
            other => bail!("unexpected element in rule: {:?}", other),
        }
    } else {
        Ok(None)
    }
}

fn parse_cap_matcher(expr: &SExpr) -> Result<CapMatcher> {
    let list = require_list(expr, "capability matcher")?;
    let head = require_atom(&list[0], "capability kind")?;
    match head {
        "exec" => parse_exec_matcher(&list[1..]).map(CapMatcher::Exec),
        "fs" => parse_fs_matcher(&list[1..]).map(CapMatcher::Fs),
        "net" => parse_net_matcher(&list[1..]).map(CapMatcher::Net),
        other => bail!("unknown capability: {other}"),
    }
}

fn parse_exec_matcher(args: &[SExpr]) -> Result<ExecMatcher> {
    if args.is_empty() {
        return Ok(ExecMatcher {
            bin: Pattern::Any,
            args: vec![],
            has_args: vec![],
        });
    }
    let bin = parse_pattern(&args[0])?;

    // Parse positional args until we hit `:has`, then parse the rest as
    // orderless patterns.
    let mut positional = Vec::new();
    let mut has = Vec::new();
    let mut saw_has = false;

    for expr in &args[1..] {
        if !saw_has {
            if let SExpr::Atom(s, _) = expr
                && s == ":has"
            {
                saw_has = true;
                continue;
            }
            positional.push(parse_pattern(expr)?);
        } else {
            has.push(parse_pattern(expr)?);
        }
    }

    Ok(ExecMatcher {
        bin,
        args: positional,
        has_args: has,
    })
}

fn parse_fs_matcher(args: &[SExpr]) -> Result<FsMatcher> {
    if args.is_empty() {
        return Ok(FsMatcher {
            op: OpPattern::Any,
            path: None,
        });
    }
    let op = parse_op_pattern(&args[0])?;
    let path = if args.len() > 1 {
        Some(parse_path_filter(&args[1])?)
    } else {
        None
    };
    Ok(FsMatcher { op, path })
}

fn parse_net_matcher(args: &[SExpr]) -> Result<NetMatcher> {
    if args.is_empty() {
        return Ok(NetMatcher {
            domain: Pattern::Any,
        });
    }
    ensure!(args.len() == 1, "(net) expects at most 1 argument");
    let domain = parse_pattern(&args[0])?;
    Ok(NetMatcher { domain })
}

fn parse_op_pattern(expr: &SExpr) -> Result<OpPattern> {
    match expr {
        SExpr::Atom(s, _) if s == "*" => Ok(OpPattern::Any),
        SExpr::Atom(s, _) => {
            let op = parse_fs_op(s)?;
            Ok(OpPattern::Single(op))
        }
        SExpr::List(children, _) => {
            let head = require_atom(&children[0], "op pattern keyword")?;
            match head {
                "or" => {
                    let ops = children[1..]
                        .iter()
                        .map(|c| {
                            let name = require_atom(c, "fs operation")?;
                            parse_fs_op(name)
                        })
                        .collect::<Result<_>>()?;
                    Ok(OpPattern::Or(ops))
                }
                other => bail!("unknown op pattern form: {other}"),
            }
        }
        _ => bail!("expected operation pattern"),
    }
}

fn parse_fs_op(s: &str) -> Result<FsOp> {
    match s {
        "read" => Ok(FsOp::Read),
        "write" => Ok(FsOp::Write),
        "create" => Ok(FsOp::Create),
        "delete" => Ok(FsOp::Delete),
        other => bail!("unknown fs operation: {other}"),
    }
}

fn parse_pattern(expr: &SExpr) -> Result<Pattern> {
    match expr {
        SExpr::Atom(s, _) if s == "*" => Ok(Pattern::Any),
        SExpr::Atom(s, _) => Ok(Pattern::Literal(s.clone())),
        SExpr::Str(s, _) => Ok(Pattern::Literal(s.clone())),
        SExpr::Regex(r, _) => Ok(Pattern::Regex(r.clone())),
        SExpr::List(children, _) => {
            ensure!(!children.is_empty(), "empty list in pattern position");
            let head = require_atom(&children[0], "pattern keyword")?;
            match head {
                "or" => {
                    let ps = children[1..]
                        .iter()
                        .map(parse_pattern)
                        .collect::<Result<_>>()?;
                    Ok(Pattern::Or(ps))
                }
                "not" => {
                    ensure!(children.len() == 2, "(not) expects exactly 1 argument");
                    let inner = parse_pattern(&children[1])?;
                    Ok(Pattern::Not(Box::new(inner)))
                }
                other => bail!("unknown pattern form: {other}"),
            }
        }
    }
}

fn parse_path_filter(expr: &SExpr) -> Result<PathFilter> {
    match expr {
        SExpr::Str(s, _) => Ok(PathFilter::Literal(s.clone())),
        SExpr::Atom(s, _) => Ok(PathFilter::Literal(s.clone())),
        SExpr::Regex(r, _) => Ok(PathFilter::Regex(r.clone())),
        SExpr::List(children, _) => {
            ensure!(!children.is_empty(), "empty list in path filter position");
            let head = require_atom(&children[0], "path filter keyword")?;
            match head {
                "subpath" => {
                    ensure!(children.len() == 2, "(subpath) expects exactly 1 argument");
                    let path_expr = parse_path_expr(&children[1])?;
                    Ok(PathFilter::Subpath(path_expr))
                }
                "or" => {
                    let fs = children[1..]
                        .iter()
                        .map(parse_path_filter)
                        .collect::<Result<_>>()?;
                    Ok(PathFilter::Or(fs))
                }
                "not" => {
                    ensure!(children.len() == 2, "(not) expects exactly 1 argument");
                    let inner = parse_path_filter(&children[1])?;
                    Ok(PathFilter::Not(Box::new(inner)))
                }
                other => bail!("unknown path filter form: {other}"),
            }
        }
    }
}

fn parse_path_expr(expr: &SExpr) -> Result<PathExpr> {
    match expr {
        SExpr::Str(s, _) | SExpr::Atom(s, _) => Ok(PathExpr::Static(s.clone())),
        SExpr::List(children, _) => {
            ensure!(!children.is_empty(), "empty list in path expression");
            let head = require_atom(&children[0], "path expression keyword")?;
            match head {
                "env" => {
                    ensure!(children.len() == 2, "(env) expects exactly 1 argument");
                    let name = require_string_or_atom(&children[1], "env var name")?;
                    Ok(PathExpr::Env(name.to_string()))
                }
                other => bail!("unknown path expression form: {other}"),
            }
        }
        _ => bail!("expected path expression"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_effect(expr: &SExpr) -> Result<Effect> {
    let s = require_atom(expr, "effect")?;
    parse_effect_str(s)
}

fn parse_effect_str(s: &str) -> Result<Effect> {
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        other => bail!("unknown effect: {other}"),
    }
}

fn require_list<'a>(expr: &'a SExpr, context: &str) -> Result<&'a [SExpr]> {
    expr.as_list()
        .ok_or_else(|| anyhow::anyhow!("expected list for {context}, got {:?}", expr))
}

fn require_atom<'a>(expr: &'a SExpr, context: &str) -> Result<&'a str> {
    match expr {
        SExpr::Atom(s, _) => Ok(s.as_str()),
        _ => bail!("expected atom for {context}, got {:?}", expr),
    }
}

fn require_string<'a>(expr: &'a SExpr, context: &str) -> Result<&'a str> {
    match expr {
        SExpr::Str(s, _) => Ok(s.as_str()),
        _ => bail!(
            "expected quoted string for {context}, got {:?} (names must be quoted)",
            expr
        ),
    }
}

fn require_string_or_atom<'a>(expr: &'a SExpr, context: &str) -> Result<&'a str> {
    expr.as_str()
        .ok_or_else(|| anyhow::anyhow!("expected string or atom for {context}, got {:?}", expr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_form() {
        let ast = parse(r#"(default deny "main")"#).unwrap();
        assert_eq!(ast.len(), 1);
        match &ast[0] {
            TopLevel::Default { effect, policy } => {
                assert_eq!(*effect, Effect::Deny);
                assert_eq!(policy, "main");
            }
            _ => panic!("expected Default"),
        }
    }

    #[test]
    fn parse_empty_policy() {
        let ast = parse(r#"(policy "empty")"#).unwrap();
        match &ast[0] {
            TopLevel::Policy { name, body } => {
                assert_eq!(name, "empty");
                assert!(body.is_empty());
            }
            _ => panic!("expected Policy"),
        }
    }

    #[test]
    fn parse_exec_rule() {
        let ast = parse(r#"(policy "p" (deny (exec "git" "push" *)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        assert_eq!(rule.effect, Effect::Deny);
        assert_eq!(rule.sandbox, None);
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert_eq!(m.bin, Pattern::Literal("git".into()));
                assert_eq!(m.args.len(), 2);
                assert_eq!(m.args[0], Pattern::Literal("push".into()));
                assert_eq!(m.args[1], Pattern::Any);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_fs_rule() {
        let ast =
            parse(r#"(policy "p" (allow (fs (or read write) (subpath (env PWD)))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => {
                assert_eq!(m.op, OpPattern::Or(vec![FsOp::Read, FsOp::Write]));
                match &m.path {
                    Some(PathFilter::Subpath(PathExpr::Env(name))) => {
                        assert_eq!(name, "PWD");
                    }
                    other => panic!("expected Subpath(Env(PWD)), got {other:?}"),
                }
            }
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn parse_net_regex() {
        let ast = parse(r#"(policy "p" (deny (net /.*\.evil\.com/)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Net(m) => {
                assert_eq!(m.domain, Pattern::Regex(r".*\.evil\.com".into()));
            }
            _ => panic!("expected Net"),
        }
    }

    #[test]
    fn parse_include() {
        let ast = parse(r#"(policy "main" (include "cwd-access"))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::Include(name) => assert_eq!(name, "cwd-access"),
            _ => panic!("expected Include"),
        }
    }

    #[test]
    fn parse_or_pattern() {
        let ast = parse(r#"(policy "p" (allow (exec (or "npm" "cargo" "pip") *)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => match &m.bin {
                Pattern::Or(ps) => {
                    assert_eq!(ps.len(), 3);
                    assert_eq!(ps[0], Pattern::Literal("npm".into()));
                }
                other => panic!("expected Or pattern, got {other:?}"),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn parse_sandbox_keyword() {
        let ast = parse(r#"(policy "p" (allow (exec "cargo" *) :sandbox "cargo-env"))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        assert_eq!(rule.effect, Effect::Allow);
        assert_eq!(rule.sandbox, Some("cargo-env".into()));
    }

    #[test]
    fn parse_error_sandbox_without_value() {
        let err = parse(r#"(policy "p" (allow (exec "cargo" *) :sandbox))"#).unwrap_err();
        assert!(
            err.to_string().contains(":sandbox requires a string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_bare_atom_policy_name() {
        let err = parse("(policy main (allow (exec)))").unwrap_err();
        assert!(
            err.to_string().contains("expected quoted string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_bare_atom_default_name() {
        let err = parse("(default deny main)").unwrap_err();
        assert!(
            err.to_string().contains("expected quoted string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_bare_atom_include_name() {
        let err = parse(r#"(policy "main" (include cwd-access))"#).unwrap_err();
        assert!(
            err.to_string().contains("expected quoted string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_full_example() {
        let source = r#"
(default deny "main")

(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")

  (deny  (exec "git" "push" *))
  (deny  (exec "git" "reset" *))
  (ask   (exec "git" "commit" *))
  (allow (exec "git" *))
  (allow (exec (or "npm" "cargo" "pip") *))

  (allow (fs (or read write) (subpath (env PWD))))
  (deny  (fs write ".env"))

  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        let ast = parse(source).unwrap();
        assert_eq!(ast.len(), 3);
    }

    #[test]
    fn round_trip_parse_display_parse() {
        let source = r#"
(default deny "main")

(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")
  (deny  (exec "git" "push" *))
  (allow (exec "git" *))
  (allow (exec "cargo" *) :sandbox "cargo-env")
  (allow (fs (or read write) (subpath (env PWD))))
  (deny  (fs write ".env"))
  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        let ast1 = parse(source).unwrap();
        // Display each top-level form and re-parse.
        let printed: String = ast1
            .iter()
            .map(|tl| tl.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_has_keyword() {
        let ast = parse(r#"(policy "p" (deny (exec "git" :has "push" "--force")))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert_eq!(m.bin, Pattern::Literal("git".into()));
                assert!(m.args.is_empty());
                assert_eq!(m.has_args.len(), 2);
                assert_eq!(m.has_args[0], Pattern::Literal("push".into()));
                assert_eq!(m.has_args[1], Pattern::Literal("--force".into()));
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_has_with_positional_prefix() {
        let ast = parse(r#"(policy "p" (deny (exec "git" "push" :has "--force" "--no-verify")))"#)
            .unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert_eq!(m.bin, Pattern::Literal("git".into()));
                assert_eq!(m.args.len(), 1);
                assert_eq!(m.args[0], Pattern::Literal("push".into()));
                assert_eq!(m.has_args.len(), 2);
                assert_eq!(m.has_args[0], Pattern::Literal("--force".into()));
                assert_eq!(m.has_args[1], Pattern::Literal("--no-verify".into()));
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_has_with_regex() {
        let ast = parse(r#"(policy "p" (deny (exec "git" :has "push" /--force/)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert!(!m.has_args.is_empty());
                assert_eq!(m.has_args[1], Pattern::Regex("--force".into()));
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_has_with_not() {
        let ast =
            parse(r#"(policy "p" (deny (exec "git" :has "push" (not "--dry-run"))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert!(!m.has_args.is_empty());
                assert_eq!(
                    m.has_args[1],
                    Pattern::Not(Box::new(Pattern::Literal("--dry-run".into())))
                );
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn round_trip_has() {
        let source = r#"(policy "p" (deny (exec "git" :has "push" "--force")))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn round_trip_mixed_positional_has() {
        let source = r#"(policy "p" (deny (exec "git" "push" :has "--force")))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_positional_unchanged() {
        // Ensure regular positional parsing still works and does not produce has_args.
        let ast = parse(r#"(policy "p" (deny (exec "git" "push" *)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert!(m.has_args.is_empty());
                assert_eq!(m.args.len(), 2);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_error_unknown_effect() {
        let err = parse(r#"(policy "p" (boom (exec)))"#).unwrap_err();
        assert!(err.to_string().contains("unknown policy item: boom"));
    }

    #[test]
    fn parse_error_unknown_capability() {
        let err = parse(r#"(policy "p" (allow (foobar)))"#).unwrap_err();
        assert!(err.to_string().contains("unknown capability: foobar"));
    }
}
