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
    Stmt::load("@clash//builtin.star", &["builtins"])
}

pub fn load_sandboxes(names: &[&str]) -> Stmt {
    Stmt::load("@clash//sandboxes.star", names)
}

/// Load symbols from an ecosystem `.star` file (e.g., `rust.star`, `go.star`).
pub fn load_ecosystem(filename: &str, names: &[&str]) -> Stmt {
    Stmt::load(format!("@clash//{filename}"), names)
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

pub fn deny_with_sandbox(sandbox: Expr) -> Expr {
    Expr::call_kwargs("deny", vec![], vec![("sandbox", sandbox)])
}

pub fn ask() -> Expr {
    Expr::call("ask", vec![])
}

pub fn ask_with_sandbox(sandbox: Expr) -> Expr {
    Expr::call_kwargs("ask", vec![], vec![("sandbox", sandbox)])
}

// ---------------------------------------------------------------------------
// Match rules
// ---------------------------------------------------------------------------

/// A key in a match dict.
///
/// Supports raw strings (tool names), typed `Mode()`/`Tool()` keys,
/// and tuples for matching multiple keys.
pub enum MatchKey {
    /// A raw string key (tool name, backwards-compatible).
    Single(String),
    /// A tuple of raw string keys.
    Tuple(Vec<String>),
    /// A typed `Mode("name")` key for mode-based routing.
    Mode(String),
    /// A typed `Tool("name")` key for explicit tool matching.
    Tool(String),
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

/// Build a dict expression from a nested key-value structure.
///
/// Previously this wrapped the dict in a `when()` call, but `when()` has been
/// removed.  The returned expression is now a plain dict suitable for passing
/// directly to `policy()` or `merge()`.
pub fn match_rule(entries: Vec<(MatchKey, MatchValue)>) -> Expr {
    match_dict(entries, true)
}

/// Build a simple tool match rule: `{tool("Name"): effect()}` or
/// `{tool(("A", "B")): effect()}` for multiple tool names.
pub fn tool_match(names: &[&str], effect: Expr) -> Expr {
    let key: MatchKey = if names.len() == 1 {
        MatchKey::Single(names[0].to_owned())
    } else {
        MatchKey::Tuple(names.iter().map(|s| (*s).to_owned()).collect())
    };
    match_rule(vec![(key, MatchValue::Effect(effect))])
}

fn match_dict(entries: Vec<(MatchKey, MatchValue)>, is_root: bool) -> Expr {
    let dict_entries = entries
        .into_iter()
        .map(|(k, v)| {
            let key = match k {
                MatchKey::Single(s) => {
                    if is_root {
                        Expr::call("tool", vec![Expr::string(s)])
                    } else {
                        Expr::string(s)
                    }
                }
                MatchKey::Tuple(items) => {
                    let tup = Expr::tuple(items.into_iter().map(Expr::string).collect());
                    if is_root {
                        Expr::call("tool", vec![tup])
                    } else {
                        tup
                    }
                }
                MatchKey::Mode(name) => Expr::call("Mode", vec![Expr::string(name)]),
                MatchKey::Tool(name) => Expr::call("tool", vec![Expr::string(name)]),
            };
            let value = match v {
                MatchValue::Effect(e) => e,
                MatchValue::Nested(inner) => match_dict(inner, false),
            };
            DictEntry::new(key, value)
        })
        .collect();
    Expr::dict(dict_entries)
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

/// Build a `sandbox(name=..., ...)` call expression.
///
/// Additional kwargs (e.g. `default`, `fs`, `net`, `doc`) are appended after `name`.
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

/// Build a `policy("name", {...})` or `policy("name", merge({...}, {...}))` call.
///
/// When `rules` is empty an empty dict is passed.  When there is a single rule
/// it is passed directly.  Multiple rules are wrapped in `merge(...)`.
pub fn policy(name: &str, default: Expr, rules: Vec<Expr>, default_sandbox: Option<Expr>) -> Expr {
    let dict_arg = match rules.len() {
        0 => Expr::dict(vec![]),
        1 => rules.into_iter().next().unwrap(),
        _ => merge(rules),
    };
    let mut kwargs: Vec<(&str, Expr)> = vec![("default", default)];
    if let Some(sb) = default_sandbox {
        kwargs.push(("default_sandbox", sb));
    }
    Expr::call_kwargs("policy", vec![Expr::string(name), dict_arg], kwargs)
}

/// Build a `merge(a, b, ...)` call to combine multiple dicts.
pub fn merge(exprs: Vec<Expr>) -> Expr {
    Expr::call("merge", exprs)
}

/// Build a `settings(default = ..., ...)` call statement.
pub fn settings(default: Expr, default_sandbox: Option<Expr>) -> Expr {
    let mut kwargs: Vec<(&str, Expr)> = vec![("default", default)];
    if let Some(sb) = default_sandbox {
        kwargs.push(("default_sandbox", sb));
    }
    Expr::call_kwargs("settings", vec![], kwargs)
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
    fn tool_match_single() {
        let expr = tool_match(&["Read"], allow());
        let stmts = vec![Stmt::Expr(expr)];
        let src = serialize(&stmts);
        assert_eq!(src, "{tool(\"Read\"): allow()}\n");
    }

    #[test]
    fn tool_match_multiple_with_sandbox() {
        let expr = tool_match(
            &["Read", "Glob", "Grep"],
            allow_with_sandbox(Expr::ident("_fs_box")),
        );
        let stmts = vec![Stmt::Expr(expr)];
        let src = serialize(&stmts);
        assert!(
            src.contains("tool((\"Read\", \"Glob\", \"Grep\")): allow(sandbox = _fs_box)"),
            "got:\n{src}"
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
            load_std(&["policy", "settings", "allow", "deny"]),
            Stmt::Blank,
            Stmt::Expr(settings(deny(), None)),
            Stmt::Blank,
            Stmt::Expr(policy(
                "default",
                deny(),
                vec![tool_match(&["Read"], allow())],
                None,
            )),
        ];
        let src = serialize(&stmts);
        assert!(src.contains("load(\"@clash//std.star\""));
        assert!(src.contains("settings("));
        assert!(src.contains("policy(\"default\""));
        assert!(src.contains("{tool(\"Read\"): allow()}"), "got:\n{src}");
    }

    #[test]
    fn load_ecosystem_file() {
        let stmt = load_ecosystem("rust.star", &["rust_safe", "rust_full"]);
        let src = serialize(&[stmt]);
        assert_eq!(
            src,
            "load(\"@clash//rust.star\", \"rust_safe\", \"rust_full\")\n"
        );
    }
}
