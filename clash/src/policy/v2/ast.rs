//! AST types for the v2 policy language.
//!
//! Every node implements `Display` so the AST round-trips to valid source text.

use std::fmt;

use crate::policy::Effect;

/// A top-level declaration in a policy file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopLevel {
    /// `(default deny "main")` — sets the default effect and active policy name.
    Default { effect: Effect, policy: String },
    /// `(policy name ...)` — a named policy containing rules and includes.
    Policy { name: String, body: Vec<PolicyItem> },
}

/// An item inside a `(policy ...)` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyItem {
    /// `(include "other-policy")` — import rules from another policy by name.
    Include(String),
    /// A rule: `(effect (capability ...))`.
    Rule(Rule),
}

/// A single permission rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub effect: Effect,
    pub matcher: CapMatcher,
    /// Optional sandbox policy reference for exec rules: `:sandbox "name"`.
    pub sandbox: Option<String>,
}

/// A capability matcher — one of the three capability domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapMatcher {
    Exec(ExecMatcher),
    Fs(FsMatcher),
    Net(NetMatcher),
}

/// Matches command execution: `(exec bin [args...] [:has patterns...])`.
///
/// Arguments before `:has` are matched positionally (left-to-right).
/// Arguments after `:has` are matched orderlessly — each pattern must match
/// at least one of the remaining arguments, regardless of position.
///
/// Examples:
/// ```text
/// (exec "git" "push" *)                 ; positional only
/// (exec "git" :has "push" "--force")     ; orderless only
/// (exec "git" "push" :has "--force")     ; positional "push", then --force anywhere
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecMatcher {
    /// Binary pattern. `Pattern::Any` if omitted.
    pub bin: Pattern,
    /// Positional argument patterns. Each pattern matches the arg at the same
    /// index. Empty = match any args.
    pub args: Vec<Pattern>,
    /// Orderless argument patterns (after `:has`). Each pattern must match at
    /// least one of the remaining args (those not consumed by positional).
    /// Empty = no orderless constraint.
    pub has_args: Vec<Pattern>,
}

/// Matches filesystem operations: `(fs [op] [path])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsMatcher {
    /// Operation filter. `OpPattern::Any` if omitted.
    pub op: OpPattern,
    /// Path filter. `None` = match any path.
    pub path: Option<PathFilter>,
}

/// Matches network access: `(net [domain])`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetMatcher {
    /// Domain pattern. `Pattern::Any` if omitted.
    pub domain: Pattern,
}

/// A filesystem operation pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpPattern {
    /// Matches any operation.
    Any,
    /// A single operation.
    Single(FsOp),
    /// `(or read write ...)` — matches any of the listed operations.
    Or(Vec<FsOp>),
}

/// Filesystem operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsOp {
    Read,
    Write,
    Create,
    Delete,
}

/// A general-purpose pattern used for matching strings (binary names, args, domains).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `*` — matches anything.
    Any,
    /// `"literal"` or bare `atom` — exact string match.
    Literal(String),
    /// `/pattern/` — regex match.
    Regex(String),
    /// `(or p1 p2 ...)` — matches any of.
    Or(Vec<Pattern>),
    /// `(not p)` — negation.
    Not(Box<Pattern>),
}

/// A path filter used in `(fs ...)` position 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathFilter {
    /// `(subpath expr)` — recursive subtree match.
    Subpath(PathExpr),
    /// `"path"` or bare atom — exact file match.
    Literal(String),
    /// `/pattern/` — regex on resolved path.
    Regex(String),
    /// `(or f1 f2 ...)`.
    Or(Vec<PathFilter>),
    /// `(not f)`.
    Not(Box<PathFilter>),
}

/// A path expression that may reference environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathExpr {
    /// A static path string.
    Static(String),
    /// `(env NAME)` — resolved at compile time.
    Env(String),
}

// ---------------------------------------------------------------------------
// Display implementations for round-trip printing
// ---------------------------------------------------------------------------

impl fmt::Display for TopLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TopLevel::Default { effect, policy } => {
                write!(f, "(default {effect} \"{policy}\")")
            }
            TopLevel::Policy { name, body } => {
                write!(f, "(policy \"{name}\"")?;
                for item in body {
                    write!(f, "\n  {item}")?;
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for PolicyItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyItem::Include(name) => write!(f, "(include \"{name}\")"),
            PolicyItem::Rule(rule) => write!(f, "{rule}"),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({} {}", self.effect, self.matcher)?;
        if let Some(name) = &self.sandbox {
            write!(f, " :sandbox \"{name}\"")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for CapMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapMatcher::Exec(m) => write!(f, "{m}"),
            CapMatcher::Fs(m) => write!(f, "{m}"),
            CapMatcher::Net(m) => write!(f, "{m}"),
        }
    }
}

impl fmt::Display for ExecMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(exec")?;
        let has_content = !self.args.is_empty() || !self.has_args.is_empty();
        if self.bin != Pattern::Any || has_content {
            write!(f, " {}", self.bin)?;
        }
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        if !self.has_args.is_empty() {
            write!(f, " :has")?;
            for arg in &self.has_args {
                write!(f, " {arg}")?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Display for FsMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(fs")?;
        if self.op != OpPattern::Any || self.path.is_some() {
            write!(f, " {}", self.op)?;
        }
        if let Some(path) = &self.path {
            write!(f, " {path}")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NetMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(net")?;
        if self.domain != Pattern::Any {
            write!(f, " {}", self.domain)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for OpPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpPattern::Any => write!(f, "*"),
            OpPattern::Single(op) => write!(f, "{op}"),
            OpPattern::Or(ops) => {
                write!(f, "(or")?;
                for op in ops {
                    write!(f, " {op}")?;
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for FsOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsOp::Read => write!(f, "read"),
            FsOp::Write => write!(f, "write"),
            FsOp::Create => write!(f, "create"),
            FsOp::Delete => write!(f, "delete"),
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pattern::Any => write!(f, "*"),
            Pattern::Literal(s) => {
                write!(f, "\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            }
            Pattern::Regex(r) => write!(f, "/{r}/"),
            Pattern::Or(ps) => {
                write!(f, "(or")?;
                for p in ps {
                    write!(f, " {p}")?;
                }
                write!(f, ")")
            }
            Pattern::Not(p) => write!(f, "(not {p})"),
        }
    }
}

impl fmt::Display for PathFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathFilter::Subpath(expr) => write!(f, "(subpath {expr})"),
            PathFilter::Literal(s) => {
                write!(f, "\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            }
            PathFilter::Regex(r) => write!(f, "/{r}/"),
            PathFilter::Or(fs) => {
                write!(f, "(or")?;
                for pf in fs {
                    write!(f, " {pf}")?;
                }
                write!(f, ")")
            }
            PathFilter::Not(pf) => write!(f, "(not {pf})"),
        }
    }
}

impl fmt::Display for PathExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathExpr::Static(s) => {
                write!(f, "\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
            }
            PathExpr::Env(name) => write!(f, "(env {name})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_default() {
        let d = TopLevel::Default {
            effect: Effect::Deny,
            policy: "main".into(),
        };
        assert_eq!(d.to_string(), r#"(default deny "main")"#);
    }

    #[test]
    fn display_simple_policy() {
        let p = TopLevel::Policy {
            name: "main".into(),
            body: vec![
                PolicyItem::Include("cwd-access".into()),
                PolicyItem::Rule(Rule {
                    effect: Effect::Allow,
                    matcher: CapMatcher::Exec(ExecMatcher {
                        bin: Pattern::Literal("git".into()),
                        args: vec![Pattern::Any],
                        has_args: vec![],
                    }),
                    sandbox: None,
                }),
            ],
        };
        let s = p.to_string();
        assert!(s.contains(r#"(include "cwd-access")"#));
        assert!(s.contains("(allow (exec \"git\" *))"));
    }

    #[test]
    fn display_rule_with_sandbox() {
        let r = Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("cargo".into()),
                args: vec![Pattern::Any],
                has_args: vec![],
            }),
            sandbox: Some("cargo-env".into()),
        };
        assert_eq!(
            r.to_string(),
            r#"(allow (exec "cargo" *) :sandbox "cargo-env")"#
        );
    }

    #[test]
    fn display_fs_matcher() {
        let m = FsMatcher {
            op: OpPattern::Or(vec![FsOp::Read, FsOp::Write]),
            path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
        };
        assert_eq!(m.to_string(), "(fs (or read write) (subpath (env PWD)))");
    }

    #[test]
    fn display_net_regex() {
        let m = NetMatcher {
            domain: Pattern::Regex(r".*\.evil\.com".into()),
        };
        assert_eq!(m.to_string(), r"(net /.*\.evil\.com/)");
    }

    #[test]
    fn display_pattern_not() {
        let p = Pattern::Not(Box::new(Pattern::Literal("secret".into())));
        assert_eq!(p.to_string(), "(not \"secret\")");
    }
}
