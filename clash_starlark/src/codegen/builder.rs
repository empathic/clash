//! Domain-specific builder helpers for Clash policy Starlark.
//!
//! These produce [`Stmt`] and [`Expr`] nodes matching the patterns used in
//! Clash's Starlark DSL (`@clash//std.star`).

use super::ast::{DictEntry, Expr, Stmt};

// ---------------------------------------------------------------------------
// Load statements
// ---------------------------------------------------------------------------

pub fn load_std(names: &[&str]) -> Stmt {
    Stmt::load("@clash//std.star", names)
}

pub fn load_builtin() -> Stmt {
    Stmt::load("@clash//builtin.star", &["base"])
}

pub fn load_sandboxes(names: &[&str]) -> Stmt {
    Stmt::load("@clash//sandboxes.star", names)
}

// ---------------------------------------------------------------------------
// Effects
// ---------------------------------------------------------------------------

pub fn allow() -> Expr {
    Expr::call("allow", vec![])
}

pub fn allow_with_sandbox(sandbox: Expr) -> Expr {
    Expr::call_kwargs("allow", vec![], vec![("sandbox", sandbox)])
}

pub fn deny() -> Expr {
    Expr::call("deny", vec![])
}

pub fn ask() -> Expr {
    Expr::call("ask", vec![])
}

// ---------------------------------------------------------------------------
// Tool rules
// ---------------------------------------------------------------------------

/// `tool(["a"])` or `tool(["a", "b"])`
///
/// Always uses list form for consistency and easier future modification.
pub fn tool(names: &[&str]) -> Expr {
    let list = names.iter().map(|n| Expr::string(*n)).collect::<Vec<_>>();
    Expr::call("tool", vec![Expr::list(list)])
}

// ---------------------------------------------------------------------------
// Match rules
// ---------------------------------------------------------------------------

/// A key in a match dict — either a single string or a tuple of strings.
pub enum MatchKey {
    Single(String),
    Tuple(Vec<String>),
}

impl From<&str> for MatchKey {
    fn from(s: &str) -> Self {
        MatchKey::Single(s.to_owned())
    }
}

impl From<&[&str]> for MatchKey {
    fn from(v: &[&str]) -> Self {
        MatchKey::Tuple(v.iter().map(|s| (*s).to_owned()).collect())
    }
}

impl<const N: usize> From<[&str; N]> for MatchKey {
    fn from(v: [&str; N]) -> Self {
        MatchKey::Tuple(v.iter().map(|s| (*s).to_owned()).collect())
    }
}

/// A value in a match dict — either an effect expression or a nested dict.
pub enum MatchValue {
    Effect(Expr),
    Nested(Vec<(MatchKey, MatchValue)>),
}

/// Build a `match({...})` expression from a nested key-value structure.
pub fn match_rule(entries: Vec<(MatchKey, MatchValue)>) -> Expr {
    Expr::call("match", vec![match_dict(entries)])
}

fn match_dict(entries: Vec<(MatchKey, MatchValue)>) -> Expr {
    let dict_entries = entries
        .into_iter()
        .map(|(k, v)| {
            let key = match k {
                MatchKey::Single(s) => Expr::string(s),
                MatchKey::Tuple(items) => {
                    Expr::tuple(items.into_iter().map(Expr::string).collect())
                }
            };
            let value = match v {
                MatchValue::Effect(e) => e,
                MatchValue::Nested(inner) => match_dict(inner),
            };
            DictEntry::new(key, value)
        })
        .collect();
    Expr::dict(dict_entries)
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

/// Build a `sandbox(...)` call expression.
pub fn sandbox(name: &str, kwargs: Vec<(&str, Expr)>) -> Expr {
    Expr::call_kwargs("sandbox", vec![], {
        let mut kw: Vec<(&str, Expr)> = vec![("name", Expr::string(name))];
        kw.extend(kwargs);
        kw
    })
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Build a `policy(default = ..., rules = [...])` expression.
pub fn policy(default: Expr, rules: Vec<Expr>, default_sandbox: Option<Expr>) -> Expr {
    let mut kwargs: Vec<(&str, Expr)> = vec![("default", default)];
    if let Some(sb) = default_sandbox {
        kwargs.push(("default_sandbox", sb));
    }
    kwargs.push(("rules", Expr::list(rules)));
    Expr::call_kwargs("policy", vec![], kwargs)
}

/// Build a complete `def main(): return policy(...)` function.
pub fn main_fn(body: Vec<Stmt>) -> Stmt {
    Stmt::def("main", body)
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

pub fn cwd(kwargs: Vec<(&str, Expr)>) -> Expr {
    Expr::call_kwargs("cwd", vec![], kwargs)
}

pub fn home() -> Expr {
    Expr::call("home", vec![])
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

/// `net("domain")`
pub fn net(domain: &str) -> Expr {
    Expr::call("net", vec![Expr::string(domain)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::serialize::serialize;

    #[test]
    fn tool_rule_single() {
        let expr = tool(&["Read"]).allow();
        let stmts = vec![Stmt::Expr(expr)];
        let src = serialize(&stmts);
        assert_eq!(src, "tool([\"Read\"]).allow()\n");
    }

    #[test]
    fn tool_rule_multiple_with_sandbox() {
        let expr = tool(&["Read", "Glob", "Grep"])
            .sandbox(Expr::ident("_fs_box"))
            .allow();
        let stmts = vec![Stmt::Expr(expr)];
        let src = serialize(&stmts);
        assert_eq!(
            src,
            "tool([\"Read\", \"Glob\", \"Grep\"]).sandbox(_fs_box).allow()\n"
        );
    }

    #[test]
    fn match_rule_nested() {
        let rule = crate::match_tree! {
            "Bash" => {
                "git" => {
                    "push" => {
                        "--force" => deny(),
                    },
                },
            },
        };
        let src = crate::codegen::serialize::serialize(&[Stmt::Expr(rule)]);
        assert!(src.contains("\"Bash\""));
        assert!(src.contains("\"git\""));
        assert!(src.contains("\"push\""));
        assert!(src.contains("deny()"));
    }

    #[test]
    fn full_policy() {
        let stmts = vec![
            load_std(&["match", "tool", "policy", "allow", "deny"]),
            Stmt::Blank,
            main_fn(vec![Stmt::Return(policy(
                deny(),
                vec![tool(&["Read"]).allow()],
                None,
            ))]),
        ];
        let src = serialize(&stmts);
        assert!(src.contains("load(\"@clash//std.star\""));
        assert!(src.contains("def main():"));
        assert!(src.contains("return policy("));
        assert!(src.contains("tool([\"Read\"]).allow()"));
    }
}
