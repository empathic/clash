//! Decision tree IR — the compiled form of a v2 policy.
//!
//! Rules are pre-compiled with regex patterns and sorted by specificity.
//! The decision tree groups rules by capability domain for efficient lookup.

use std::collections::HashMap;

use regex::Regex;

use crate::policy::Effect;

use super::ast::{self, Rule};
use super::specificity::Specificity;

/// A compiled policy decision tree, ready for evaluation.
#[derive(Debug)]
pub struct DecisionTree {
    /// The default effect when no rule matches.
    pub default: Effect,
    /// The name of the active policy.
    pub policy_name: String,
    /// Compiled exec rules, sorted by specificity (most specific first).
    pub exec_rules: Vec<CompiledRule>,
    /// Compiled fs rules, sorted by specificity (most specific first).
    pub fs_rules: Vec<CompiledRule>,
    /// Compiled net rules, sorted by specificity (most specific first).
    pub net_rules: Vec<CompiledRule>,
    /// Pre-compiled sandbox policy rules indexed by name. Each contains the
    /// compiled fs/net rules from the referenced `(policy ...)` block.
    pub sandbox_policies: HashMap<String, Vec<CompiledRule>>,
}

/// A single compiled rule with pre-built regexes and a specificity rank.
#[derive(Debug)]
pub struct CompiledRule {
    /// The effect this rule produces.
    pub effect: Effect,
    /// Pre-compiled matcher for efficient evaluation.
    pub matcher: CompiledMatcher,
    /// The original AST rule (preserved for round-trip printing).
    pub source: Rule,
    /// Computed specificity rank.
    pub specificity: Specificity,
    /// Optional sandbox policy name (only for exec rules).
    pub sandbox: Option<String>,
}

/// A pre-compiled capability matcher.
#[derive(Debug)]
pub enum CompiledMatcher {
    Exec(CompiledExec),
    Fs(CompiledFs),
    Net(CompiledNet),
}

/// Pre-compiled exec matcher.
#[derive(Debug)]
pub struct CompiledExec {
    pub bin: CompiledPattern,
    pub args: Vec<CompiledPattern>,
}

/// Pre-compiled fs matcher.
#[derive(Debug)]
pub struct CompiledFs {
    pub op: ast::OpPattern,
    pub path: Option<CompiledPathFilter>,
}

/// Pre-compiled net matcher.
#[derive(Debug)]
pub struct CompiledNet {
    pub domain: CompiledPattern,
}

/// A pattern with pre-compiled regex (if applicable).
#[derive(Debug)]
pub enum CompiledPattern {
    Any,
    Literal(String),
    Regex(Regex),
    Or(Vec<CompiledPattern>),
    Not(Box<CompiledPattern>),
}

/// A pre-compiled path filter.
#[derive(Debug)]
pub enum CompiledPathFilter {
    Subpath(String), // resolved path (env vars expanded)
    Literal(String),
    Regex(Regex),
    Or(Vec<CompiledPathFilter>),
    Not(Box<CompiledPathFilter>),
}

impl DecisionTree {
    /// Reconstruct the source text from the preserved AST nodes.
    pub fn to_source(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "(default {} \"{}\")\n",
            self.default, self.policy_name
        ));

        let all_rules: Vec<&CompiledRule> = self
            .exec_rules
            .iter()
            .chain(&self.fs_rules)
            .chain(&self.net_rules)
            .collect();

        if !all_rules.is_empty() {
            out.push_str(&format!("\n(policy \"{}\"", self.policy_name));
            for rule in &all_rules {
                out.push_str(&format!("\n  {}", rule.source));
            }
            out.push(')');
            out.push('\n');
        }

        out
    }
}

impl CompiledPattern {
    /// Test if this pattern matches a string value.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            CompiledPattern::Any => true,
            CompiledPattern::Literal(s) => s == value,
            CompiledPattern::Regex(r) => r.is_match(value),
            CompiledPattern::Or(ps) => ps.iter().any(|p| p.matches(value)),
            CompiledPattern::Not(p) => !p.matches(value),
        }
    }
}

impl CompiledPathFilter {
    /// Test if this path filter matches a resolved path.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            CompiledPathFilter::Subpath(base) => {
                path == base || path.starts_with(&format!("{base}/"))
            }
            CompiledPathFilter::Literal(s) => s == path,
            CompiledPathFilter::Regex(r) => r.is_match(path),
            CompiledPathFilter::Or(fs) => fs.iter().any(|f| f.matches(path)),
            CompiledPathFilter::Not(f) => !f.matches(path),
        }
    }
}

impl CompiledExec {
    /// Test if this exec matcher matches a binary name and argument list.
    pub fn matches(&self, bin: &str, args: &[&str]) -> bool {
        if !self.bin.matches(bin) {
            return false;
        }
        // Each pattern position must match the corresponding arg.
        // If we have more patterns than args, unmatched patterns must be Any.
        for (i, pat) in self.args.iter().enumerate() {
            match args.get(i) {
                Some(arg) => {
                    if !pat.matches(arg) {
                        return false;
                    }
                }
                None => {
                    // No arg at this position — only matches if pattern is Any.
                    if !matches!(pat, CompiledPattern::Any) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

impl CompiledFs {
    /// Test if this fs matcher matches a filesystem operation and resolved path.
    pub fn matches(&self, op: ast::FsOp, path: &str) -> bool {
        // Check operation filter.
        match &self.op {
            ast::OpPattern::Any => {}
            ast::OpPattern::Single(expected) => {
                if *expected != op {
                    return false;
                }
            }
            ast::OpPattern::Or(ops) => {
                if !ops.contains(&op) {
                    return false;
                }
            }
        }
        // Check path filter.
        match &self.path {
            None => true,
            Some(pf) => pf.matches(path),
        }
    }
}

impl CompiledNet {
    /// Test if this net matcher matches a domain string.
    pub fn matches(&self, domain: &str) -> bool {
        self.domain.matches(domain)
    }
}
