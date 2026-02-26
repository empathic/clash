//! Specificity computation for policy rules.
//!
//! Rules are ranked by containment: if every request matching rule A also
//! matches rule B, then A is more specific than B. More specific rules take
//! precedence. Two rules with the same specificity and different effects are a
//! compile-time conflict.

use std::cmp::Ordering;

use super::ast::*;

/// Specificity score for a single rule. Higher = more specific.
///
/// Each capability dimension contributes an ordered score. Dimensions are
/// compared lexicographically: the first non-equal dimension decides ordering.
///
/// Only implements `PartialOrd` because some rules are incomparable (partial order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Specificity {
    /// Primary: pattern specificity of the main discriminator (bin/op+path/domain).
    pub primary: u8,
    /// Secondary: further refinement (arg count for exec, op specificity for fs).
    pub secondary: u8,
}

impl Specificity {
    /// Compute specificity for a capability matcher.
    pub fn from_matcher(matcher: &CapMatcher) -> Self {
        match matcher {
            CapMatcher::Exec(m) => Self::from_exec(m),
            CapMatcher::Fs(m) => Self::from_fs(m),
            CapMatcher::Net(m) => Self::from_net(m),
            CapMatcher::Tool(m) => Self::from_tool(m),
        }
    }

    fn from_exec(m: &ExecMatcher) -> Self {
        let primary = pattern_rank(&m.bin);
        // More args = more specific (each arg narrows the match).
        // Literal args count more than wildcards.
        let mut secondary = m
            .args
            .iter()
            .map(pattern_rank)
            .sum::<u8>()
            .saturating_add(m.args.len() as u8);
        // :has patterns add specificity but less than positional (orderless
        // is a weaker constraint). Each has-pattern adds its rank but not a
        // bonus for position count.
        let has_score: u8 = m.has_args.iter().map(pattern_rank).sum();
        secondary = secondary.saturating_add(has_score);
        Self { primary, secondary }
    }

    fn from_fs(m: &FsMatcher) -> Self {
        let primary = match &m.path {
            Some(pf) => path_filter_rank(pf),
            None => 0, // matches any path
        };
        let secondary = op_pattern_rank(&m.op);
        Self { primary, secondary }
    }

    fn from_net(m: &NetMatcher) -> Self {
        let secondary = match &m.path {
            Some(pf) => path_filter_rank(pf),
            None => 0,
        };
        Self {
            primary: pattern_rank(&m.domain),
            secondary,
        }
    }

    fn from_tool(m: &ToolMatcher) -> Self {
        Self {
            primary: pattern_rank(&m.name),
            secondary: 0,
        }
    }
}

impl PartialOrd for Specificity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        // Lexicographic comparison: primary first, then secondary.
        match self.primary.cmp(&other.primary) {
            Ordering::Equal => Some(self.secondary.cmp(&other.secondary)),
            ord => Some(ord),
        }
    }
}

/// Rank a general pattern by specificity (higher = more specific).
fn pattern_rank(p: &Pattern) -> u8 {
    match p {
        Pattern::Any => 0,
        Pattern::Regex(_) => 1,
        Pattern::Or(ps) => {
            // An `or` is at most as specific as its most general member,
            // but more specific than a bare wildcard.
            let min = ps.iter().map(pattern_rank).min().unwrap_or(0);
            // Clamp: at least 1 (better than wildcard), at most 2 (less than literal).
            min.clamp(1, 2)
        }
        Pattern::Not(_) => 1, // negation is roughly as specific as regex
        Pattern::Literal(_) => 3,
    }
}

/// Rank a path filter by specificity.
fn path_filter_rank(pf: &PathFilter) -> u8 {
    match pf {
        PathFilter::Subpath(_, _) => 1,
        PathFilter::Regex(_) => 2,
        PathFilter::Literal(_) => 3,
        PathFilter::Or(fs) => {
            let min = fs.iter().map(path_filter_rank).min().unwrap_or(0);
            min.clamp(1, 2)
        }
        PathFilter::Not(_) => 1,
    }
}

/// Rank an operation pattern by specificity.
fn op_pattern_rank(op: &OpPattern) -> u8 {
    match op {
        OpPattern::Any => 0,
        OpPattern::Or(ops) => {
            // More ops = less specific.
            if ops.len() == 1 { 2 } else { 1 }
        }
        OpPattern::Single(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_more_specific_than_wildcard() {
        let a = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![],
            has_args: vec![],
        }));
        let b = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Any,
            args: vec![],
            has_args: vec![],
        }));
        assert!(a > b);
    }

    #[test]
    fn more_args_more_specific() {
        let a = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![Pattern::Literal("push".into()), Pattern::Any],
            has_args: vec![],
        }));
        let b = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![Pattern::Any],
            has_args: vec![],
        }));
        assert!(a > b);
    }

    #[test]
    fn literal_path_more_specific_than_subpath() {
        let a = Specificity::from_matcher(&CapMatcher::Fs(FsMatcher {
            op: OpPattern::Single(FsOp::Write),
            path: Some(PathFilter::Literal(".env".into())),
        }));
        let b = Specificity::from_matcher(&CapMatcher::Fs(FsMatcher {
            op: OpPattern::Single(FsOp::Write),
            path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()), false)),
        }));
        assert!(a > b);
    }

    #[test]
    fn single_op_more_specific_than_or() {
        let a = Specificity::from_matcher(&CapMatcher::Fs(FsMatcher {
            op: OpPattern::Single(FsOp::Read),
            path: None,
        }));
        let b = Specificity::from_matcher(&CapMatcher::Fs(FsMatcher {
            op: OpPattern::Or(vec![FsOp::Read, FsOp::Write]),
            path: None,
        }));
        assert!(a > b);
    }

    #[test]
    fn net_literal_more_specific_than_regex() {
        let a = Specificity::from_matcher(&CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal("github.com".into()),
            path: None,
        }));
        let b = Specificity::from_matcher(&CapMatcher::Net(NetMatcher {
            domain: Pattern::Regex(".*".into()),
            path: None,
        }));
        assert!(a > b);
    }

    #[test]
    fn equal_specificity() {
        let a = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![Pattern::Any],
            has_args: vec![],
        }));
        let b = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("npm".into()),
            args: vec![Pattern::Any],
            has_args: vec![],
        }));
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Equal));
    }

    #[test]
    fn has_less_specific_than_positional() {
        // (exec "git" "push" *) — positional, secondary = rank(push) + rank(*) + 2 = 3+0+2 = 5
        let positional = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![Pattern::Literal("push".into()), Pattern::Any],
            has_args: vec![],
        }));
        // (exec "git" :has "push") — has only, secondary = rank(push) = 3 (no position bonus)
        let has = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![],
            has_args: vec![Pattern::Literal("push".into())],
        }));
        assert!(positional > has);
    }

    #[test]
    fn mixed_positional_has_more_specific_than_has_only() {
        // (exec "git" "push" :has "--force") — positional "push" + has "--force"
        let mixed = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![Pattern::Literal("push".into())],
            has_args: vec![Pattern::Literal("--force".into())],
        }));
        // (exec "git" :has "push" "--force") — both orderless
        let has_only = Specificity::from_matcher(&CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal("git".into()),
            args: vec![],
            has_args: vec![
                Pattern::Literal("push".into()),
                Pattern::Literal("--force".into()),
            ],
        }));
        assert!(mixed > has_only);
    }

    #[test]
    fn net_with_path_more_specific_than_without() {
        let with_path = Specificity::from_matcher(&CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal("github.com".into()),
            path: Some(PathFilter::Subpath(
                PathExpr::Static("/owner/repo".into()),
                false,
            )),
        }));
        let without_path = Specificity::from_matcher(&CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal("github.com".into()),
            path: None,
        }));
        assert!(with_path > without_path);
    }

    #[test]
    fn net_literal_path_more_specific_than_subpath() {
        let literal = Specificity::from_matcher(&CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal("github.com".into()),
            path: Some(PathFilter::Literal("/owner/repo/issues".into())),
        }));
        let subpath = Specificity::from_matcher(&CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal("github.com".into()),
            path: Some(PathFilter::Subpath(
                PathExpr::Static("/owner/repo".into()),
                false,
            )),
        }));
        assert!(literal > subpath);
    }
}
