//! Policy tree: build a visual tree from AST rules, flatten for rendering.

use std::fmt;

use crate::policy::Effect;
use crate::policy::ast::*;
use crate::settings::{LoadedPolicy, PolicyLevel};

// ---------------------------------------------------------------------------
// Node kinds
// ---------------------------------------------------------------------------

/// The kind of each node in the visual tree.
#[derive(Debug, Clone)]
pub enum TreeNodeKind {
    /// Top-level capability domain grouping.
    Domain(DomainKind),
    /// A named policy block with its level.
    PolicyBlock { name: String, level: PolicyLevel },
    /// Binary pattern in an exec matcher.
    Binary(String),
    /// Positional arg pattern.
    Arg(String),
    /// The `:has` separator.
    HasMarker,
    /// Orderless arg pattern.
    HasArg(String),
    /// Filesystem path node.
    PathNode(String),
    /// Filesystem operation node.
    FsOp(String),
    /// Network domain pattern.
    NetDomain(String),
    /// Tool name pattern.
    ToolName(String),
    /// Leaf: the rule's effect with provenance.
    Leaf {
        effect: Effect,
        rule: Rule,
        level: PolicyLevel,
        policy: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    Exec,
    Filesystem,
    Network,
    Tool,
}

impl fmt::Display for DomainKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainKind::Exec => write!(f, "Exec"),
            DomainKind::Filesystem => write!(f, "Filesystem"),
            DomainKind::Network => write!(f, "Network"),
            DomainKind::Tool => write!(f, "Tool"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tree node
// ---------------------------------------------------------------------------

/// A node in the policy tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub kind: TreeNodeKind,
    pub children: Vec<TreeNode>,
    pub expanded: bool,
}

impl TreeNode {
    fn new(kind: TreeNodeKind) -> Self {
        Self {
            kind,
            children: Vec::new(),
            expanded: true,
        }
    }

    /// Count all leaf rules under this node (recursive).
    pub fn rule_count(&self) -> usize {
        match &self.kind {
            TreeNodeKind::Leaf { .. } => 1,
            _ => self.children.iter().map(|c| c.rule_count()).sum(),
        }
    }

    /// Count leaf effects: (allow, deny, ask).
    pub fn effect_counts(&self) -> (usize, usize, usize) {
        match &self.kind {
            TreeNodeKind::Leaf { effect, .. } => match effect {
                Effect::Allow => (1, 0, 0),
                Effect::Deny => (0, 1, 0),
                Effect::Ask => (0, 0, 1),
            },
            _ => {
                let (mut a, mut d, mut k) = (0, 0, 0);
                for child in &self.children {
                    let (ca, cd, ck) = child.effect_counts();
                    a += ca;
                    d += cd;
                    k += ck;
                }
                (a, d, k)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Flat row for rendering
// ---------------------------------------------------------------------------

/// A flattened row ready for terminal rendering.
#[derive(Debug, Clone)]
pub struct FlatRow {
    pub kind: TreeNodeKind,
    pub depth: usize,
    pub expanded: bool,
    pub has_children: bool,
    /// Path of child indices from root to this node.
    pub tree_path: Vec<usize>,
    /// For drawing tree connector lines: true = draw vertical line at this depth.
    pub connectors: Vec<bool>,
}

// ---------------------------------------------------------------------------
// Build the visual tree from loaded policies
// ---------------------------------------------------------------------------

/// A rule with provenance info.
#[derive(Clone)]
struct ProvenanceRule {
    rule: Rule,
    level: PolicyLevel,
    policy_name: String,
}

// ---------------------------------------------------------------------------
// Or-expansion helpers
// ---------------------------------------------------------------------------

/// Expand a Pattern::Or into individual alternatives (recursive).
fn expand_pattern(pat: &Pattern) -> Vec<String> {
    match pat {
        Pattern::Or(ps) => ps.iter().flat_map(expand_pattern).collect(),
        other => vec![other.to_string()],
    }
}

/// Expand an OpPattern::Or into individual operations.
fn expand_op(op: &OpPattern) -> Vec<String> {
    match op {
        OpPattern::Or(ops) => ops.iter().map(|o| o.to_string()).collect(),
        other => vec![other.to_string()],
    }
}

/// Expand a PathFilter::Or into individual paths (recursive).
fn expand_path_filter(pf: &PathFilter) -> Vec<String> {
    match pf {
        PathFilter::Or(fs) => fs.iter().flat_map(expand_path_filter).collect(),
        other => vec![other.to_string()],
    }
}

/// Cartesian product of expanded pattern alternatives.
fn cartesian(sets: &[Vec<String>]) -> Vec<Vec<String>> {
    if sets.is_empty() {
        return vec![vec![]];
    }
    let rest = cartesian(&sets[1..]);
    let mut result = Vec::new();
    for item in &sets[0] {
        for r in &rest {
            let mut combo = vec![item.clone()];
            combo.extend(r.iter().cloned());
            result.push(combo);
        }
    }
    result
}

/// Build the full visual tree from loaded policies.
pub fn build_tree(policies: &[LoadedPolicy]) -> Vec<TreeNode> {
    let mut all_rules: Vec<ProvenanceRule> = Vec::new();

    for loaded in policies {
        let Ok(top_levels) = crate::policy::parse::parse(&loaded.source) else {
            continue;
        };
        for tl in top_levels {
            if let TopLevel::Policy { name, body } = tl {
                for item in body {
                    if let PolicyItem::Rule(rule) = item {
                        all_rules.push(ProvenanceRule {
                            rule,
                            level: loaded.level,
                            policy_name: name.clone(),
                        });
                    }
                }
            }
        }
    }

    // Group by domain
    let mut exec_rules = Vec::new();
    let mut fs_rules = Vec::new();
    let mut net_rules = Vec::new();
    let mut tool_rules = Vec::new();

    for pr in all_rules {
        match &pr.rule.matcher {
            CapMatcher::Exec(_) => exec_rules.push(pr),
            CapMatcher::Fs(_) => fs_rules.push(pr),
            CapMatcher::Net(_) => net_rules.push(pr),
            CapMatcher::Tool(_) => tool_rules.push(pr),
        }
    }

    let mut roots = Vec::new();

    roots.extend(build_exec_tree(exec_rules));

    // Fs, net, and tool rules apply to any command — group under "*"
    let mut wildcard_children = Vec::new();
    wildcard_children.extend(build_fs_tree(fs_rules));
    wildcard_children.extend(build_net_tree(net_rules));
    wildcard_children.extend(build_tool_tree(tool_rules));
    if !wildcard_children.is_empty() {
        let mut wildcard = TreeNode::new(TreeNodeKind::Binary("*".to_string()));
        wildcard.children = wildcard_children;
        roots.push(wildcard);
    }

    // Merge top-level nodes that share a key (e.g. same binary from different policies,
    // or exec rules for "*" merging with the wildcard node above)
    merge_nodes(&mut roots);

    roots
}

// ---------------------------------------------------------------------------
// Exec tree: trie on (bin, args...)
// ---------------------------------------------------------------------------

fn build_exec_tree(rules: Vec<ProvenanceRule>) -> Vec<TreeNode> {
    // Group by binary pattern, expanding Or into individual alternatives
    let mut by_bin: Vec<(String, Vec<ProvenanceRule>)> = Vec::new();

    for pr in rules {
        let bin_texts = match &pr.rule.matcher {
            CapMatcher::Exec(m) => expand_pattern(&m.bin),
            _ => continue,
        };
        for bin_text in bin_texts {
            if let Some(entry) = by_bin.iter_mut().find(|(k, _)| *k == bin_text) {
                entry.1.push(pr.clone());
            } else {
                by_bin.push((bin_text, vec![pr.clone()]));
            }
        }
    }

    by_bin
        .into_iter()
        .map(|(bin_text, rules)| {
            let mut bin_node = TreeNode::new(TreeNodeKind::Binary(bin_text));
            bin_node.children = build_exec_args_tree(rules);
            bin_node
        })
        .collect()
}

fn build_exec_args_tree(rules: Vec<ProvenanceRule>) -> Vec<TreeNode> {
    let mut children = Vec::new();

    for pr in rules {
        let (args, has_args) = match &pr.rule.matcher {
            CapMatcher::Exec(m) => (&m.args, &m.has_args),
            _ => continue,
        };

        if args.is_empty() && has_args.is_empty() {
            let leaf = TreeNode::new(TreeNodeKind::Leaf {
                effect: pr.rule.effect,
                rule: pr.rule.clone(),
                level: pr.level,
                policy: pr.policy_name.clone(),
            });
            let mut domain = TreeNode::new(TreeNodeKind::Domain(DomainKind::Exec));
            domain.children.push(leaf);
            children.push(domain);
            continue;
        }

        // Expand Or patterns into all combinations
        let arg_sets: Vec<Vec<String>> = args.iter().map(expand_pattern).collect();
        let has_sets: Vec<Vec<String>> = has_args.iter().map(expand_pattern).collect();
        let arg_combos = cartesian(&arg_sets);
        let has_combos = cartesian(&has_sets);

        for arg_combo in &arg_combos {
            for has_combo in &has_combos {
                let leaf = TreeNode::new(TreeNodeKind::Leaf {
                    effect: pr.rule.effect,
                    rule: pr.rule.clone(),
                    level: pr.level,
                    policy: pr.policy_name.clone(),
                });
                let mut domain = TreeNode::new(TreeNodeKind::Domain(DomainKind::Exec));
                domain.children.push(leaf);

                let mut chain_nodes: Vec<TreeNode> = Vec::new();
                for text in arg_combo {
                    chain_nodes.push(TreeNode::new(TreeNodeKind::Arg(text.clone())));
                }
                if !has_combo.is_empty() {
                    chain_nodes.push(TreeNode::new(TreeNodeKind::HasMarker));
                    for text in has_combo {
                        chain_nodes.push(TreeNode::new(TreeNodeKind::HasArg(text.clone())));
                    }
                }

                let mut current = domain;
                for mut node in chain_nodes.into_iter().rev() {
                    node.children.push(current);
                    current = node;
                }
                children.push(current);
            }
        }
    }

    merge_nodes(&mut children);
    children
}

/// Merge nodes with the same kind by combining their children.
fn merge_nodes(nodes: &mut Vec<TreeNode>) {
    if nodes.len() <= 1 {
        return;
    }

    let mut merged: Vec<TreeNode> = Vec::new();

    for node in nodes.drain(..) {
        let key = node_key(&node.kind);
        if let Some(existing) = merged.iter_mut().find(|n| node_key(&n.kind) == key) {
            // Merge children
            let mut new_children = existing.children.clone();
            new_children.extend(node.children);
            merge_nodes(&mut new_children);
            existing.children = new_children;
        } else {
            merged.push(node);
        }
    }

    *nodes = merged;
}

/// Key for merging nodes — nodes with the same key get merged.
fn node_key(kind: &TreeNodeKind) -> String {
    match kind {
        TreeNodeKind::Arg(s) | TreeNodeKind::HasArg(s) | TreeNodeKind::Binary(s) => s.clone(),
        TreeNodeKind::HasMarker => ":has".into(),
        TreeNodeKind::PathNode(s) => s.clone(),
        TreeNodeKind::FsOp(s) => s.clone(),
        TreeNodeKind::NetDomain(s) => s.clone(),
        TreeNodeKind::ToolName(s) => s.clone(),
        TreeNodeKind::Domain(d) => format!("{d}"),
        TreeNodeKind::PolicyBlock { name, level } => format!("{name}[{level}]"),
        TreeNodeKind::Leaf { rule, level, .. } => format!("leaf:{}:{}", rule, level),
    }
}

// ---------------------------------------------------------------------------
// Fs tree
// ---------------------------------------------------------------------------

fn build_fs_tree(rules: Vec<ProvenanceRule>) -> Vec<TreeNode> {
    let mut children = Vec::new();

    for pr in rules {
        let (ops, paths) = match &pr.rule.matcher {
            CapMatcher::Fs(m) => (expand_op(&m.op), m.path.as_ref().map(expand_path_filter)),
            _ => continue,
        };

        for op in &ops {
            let leaf = TreeNode::new(TreeNodeKind::Leaf {
                effect: pr.rule.effect,
                rule: pr.rule.clone(),
                level: pr.level,
                policy: pr.policy_name.clone(),
            });
            let mut domain = TreeNode::new(TreeNodeKind::Domain(DomainKind::Filesystem));
            domain.children.push(leaf);

            if let Some(path_texts) = &paths {
                for path_text in path_texts {
                    let mut path_node = TreeNode::new(TreeNodeKind::PathNode(path_text.clone()));
                    if op == "*" {
                        path_node.children.push(domain.clone());
                    } else {
                        let mut op_node = TreeNode::new(TreeNodeKind::FsOp(op.clone()));
                        op_node.children.push(domain.clone());
                        path_node.children.push(op_node);
                    }
                    children.push(path_node);
                }
            } else if op == "*" {
                children.push(domain);
            } else {
                let mut op_node = TreeNode::new(TreeNodeKind::FsOp(op.clone()));
                op_node.children.push(domain);
                children.push(op_node);
            }
        }
    }

    merge_nodes(&mut children);
    children
}

// ---------------------------------------------------------------------------
// Net tree
// ---------------------------------------------------------------------------

fn build_net_tree(rules: Vec<ProvenanceRule>) -> Vec<TreeNode> {
    let mut children = Vec::new();

    for pr in rules {
        let domain_texts = match &pr.rule.matcher {
            CapMatcher::Net(m) => expand_pattern(&m.domain),
            _ => continue,
        };

        for domain_text in domain_texts {
            let leaf = TreeNode::new(TreeNodeKind::Leaf {
                effect: pr.rule.effect,
                rule: pr.rule.clone(),
                level: pr.level,
                policy: pr.policy_name.clone(),
            });
            let mut domain = TreeNode::new(TreeNodeKind::Domain(DomainKind::Network));
            domain.children.push(leaf);

            if domain_text == "*" {
                children.push(domain);
            } else {
                let mut domain_node = TreeNode::new(TreeNodeKind::NetDomain(domain_text));
                domain_node.children.push(domain);
                children.push(domain_node);
            }
        }
    }

    merge_nodes(&mut children);
    children
}

// ---------------------------------------------------------------------------
// Tool tree
// ---------------------------------------------------------------------------

fn build_tool_tree(rules: Vec<ProvenanceRule>) -> Vec<TreeNode> {
    let mut children = Vec::new();

    for pr in rules {
        let name_texts = match &pr.rule.matcher {
            CapMatcher::Tool(m) => expand_pattern(&m.name),
            _ => continue,
        };

        for name_text in name_texts {
            let leaf = TreeNode::new(TreeNodeKind::Leaf {
                effect: pr.rule.effect,
                rule: pr.rule.clone(),
                level: pr.level,
                policy: pr.policy_name.clone(),
            });
            let mut domain = TreeNode::new(TreeNodeKind::Domain(DomainKind::Tool));
            domain.children.push(leaf);

            if name_text == "*" {
                children.push(domain);
            } else {
                let mut name_node = TreeNode::new(TreeNodeKind::ToolName(name_text));
                name_node.children.push(domain);
                children.push(name_node);
            }
        }
    }

    merge_nodes(&mut children);
    children
}

// ---------------------------------------------------------------------------
// Flatten tree for rendering
// ---------------------------------------------------------------------------

/// Flatten the tree into rows for rendering, respecting collapsed state.
pub fn flatten(roots: &[TreeNode]) -> Vec<FlatRow> {
    let mut rows = Vec::new();
    for (i, root) in roots.iter().enumerate() {
        let is_last = i == roots.len() - 1;
        flatten_node(root, 0, &mut [], &mut vec![i], is_last, &mut rows);
    }
    rows
}

fn flatten_node(
    node: &TreeNode,
    depth: usize,
    parent_connectors: &mut [bool],
    tree_path: &mut Vec<usize>,
    is_last_sibling: bool,
    out: &mut Vec<FlatRow>,
) {
    let mut connectors = parent_connectors.to_owned();
    if depth > 0 {
        // The connector at (depth-1) indicates whether we should draw a vertical
        // line continuing down from the parent. We draw it if there are more
        // siblings after this one.
        if connectors.len() >= depth {
            connectors[depth - 1] = !is_last_sibling;
        } else {
            connectors.push(!is_last_sibling);
        }
    }

    out.push(FlatRow {
        kind: node.kind.clone(),
        depth,
        expanded: node.expanded,
        has_children: !node.children.is_empty(),
        tree_path: tree_path.clone(),
        connectors: connectors.clone(),
    });

    if node.expanded {
        for (i, child) in node.children.iter().enumerate() {
            let is_last = i == node.children.len() - 1;
            tree_path.push(i);
            flatten_node(child, depth + 1, &mut connectors, tree_path, is_last, out);
            tree_path.pop();
        }
    }
}

/// Look up a node in the tree by its path.
pub fn node_at_path<'a>(roots: &'a [TreeNode], path: &[usize]) -> Option<&'a TreeNode> {
    if path.is_empty() {
        return None;
    }
    let mut current = roots.get(path[0])?;
    for &idx in &path[1..] {
        current = current.children.get(idx)?;
    }
    Some(current)
}

/// Look up a mutable node in the tree by its path.
pub fn node_at_path_mut<'a>(roots: &'a mut [TreeNode], path: &[usize]) -> Option<&'a mut TreeNode> {
    if path.is_empty() {
        return None;
    }
    let mut current = roots.get_mut(path[0])?;
    for &idx in &path[1..] {
        current = current.children.get_mut(idx)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::{LoadedPolicy, PolicyLevel};

    fn test_policy(level: PolicyLevel, source: &str) -> LoadedPolicy {
        LoadedPolicy {
            level,
            path: PathBuf::from("/tmp/test"),
            source: source.to_string(),
        }
    }

    #[test]
    fn build_tree_empty() {
        let roots = build_tree(&[]);
        assert!(roots.is_empty());
    }

    #[test]
    fn build_tree_empty_source() {
        let policy = test_policy(PolicyLevel::User, "");
        let roots = build_tree(&[policy]);
        assert!(roots.is_empty());
    }

    #[test]
    fn build_tree_single_exec() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let roots = build_tree(&[policy]);

        // Should have one root: Binary(r#""git""#) — Pattern::Literal Display includes quotes
        assert_eq!(roots.len(), 1);
        assert!(
            matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == r#""git""#),
            "root should be Binary(\"git\"), got {:?}",
            roots[0].kind
        );

        // Binary -> Domain(Exec) -> Leaf
        assert_eq!(roots[0].children.len(), 1);
        assert!(matches!(
            &roots[0].children[0].kind,
            TreeNodeKind::Domain(DomainKind::Exec)
        ));
        assert_eq!(roots[0].children[0].children.len(), 1);
        assert!(matches!(
            &roots[0].children[0].children[0].kind,
            TreeNodeKind::Leaf {
                effect: Effect::Allow,
                ..
            }
        ));
    }

    #[test]
    fn build_tree_exec_with_args() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (deny (exec "git" "push" *)))"#,
        );
        let roots = build_tree(&[policy]);

        assert_eq!(roots.len(), 1);
        assert!(
            matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == r#""git""#),
            "root should be Binary(\"git\"), got {:?}",
            roots[0].kind
        );

        // Binary -> Arg("push") -> Arg("*") -> Domain(Exec) -> Leaf
        let child = &roots[0].children[0];
        assert!(
            matches!(&child.kind, TreeNodeKind::Arg(s) if s == r#""push""#),
            "first child should be Arg(\"push\"), got {:?}",
            child.kind
        );
        let child2 = &child.children[0];
        assert!(matches!(&child2.kind, TreeNodeKind::Arg(s) if s == "*"));
        let domain = &child2.children[0];
        assert!(matches!(
            &domain.kind,
            TreeNodeKind::Domain(DomainKind::Exec)
        ));
        let leaf = &domain.children[0];
        assert!(matches!(
            &leaf.kind,
            TreeNodeKind::Leaf {
                effect: Effect::Deny,
                ..
            }
        ));
    }

    #[test]
    fn build_tree_fs_rule() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (fs read "/tmp")))"#,
        );
        let roots = build_tree(&[policy]);

        // Fs rules go under a wildcard "*" binary node
        assert_eq!(roots.len(), 1);
        assert!(matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == "*"));

        // Should contain a path node for "/tmp"
        fn find_leaf(node: &TreeNode) -> bool {
            if matches!(&node.kind, TreeNodeKind::Leaf { .. }) {
                return true;
            }
            node.children.iter().any(find_leaf)
        }
        assert!(find_leaf(&roots[0]));
    }

    #[test]
    fn build_tree_net_rule() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (net "example.com")))"#,
        );
        let roots = build_tree(&[policy]);
        assert!(!roots.is_empty());

        // Net goes under "*" binary
        assert!(matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == "*"));
    }

    #[test]
    fn build_tree_tool_rule() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (ask (tool "Bash")))"#);
        let roots = build_tree(&[policy]);
        assert!(!roots.is_empty());

        assert!(matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == "*"));
    }

    #[test]
    fn build_tree_merge_wildcards() {
        // An exec rule for * and an fs rule should merge under one Binary("*") node
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec *)) (deny (fs read "/tmp")))"#,
        );
        let roots = build_tree(&[policy]);

        // Both should be under one "*" node
        assert_eq!(roots.len(), 1);
        assert!(matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == "*"));
        // Should have at least 2 children (Domain(Exec) and something from fs)
        assert!(roots[0].children.len() >= 2);
    }

    #[test]
    fn build_tree_multi_level() {
        let user = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let project = test_policy(
            PolicyLevel::Project,
            r#"(policy "main" (deny (exec "git")))"#,
        );
        let roots = build_tree(&[user, project]);

        // Both rules are for "git", should merge under one Binary("git") node
        assert_eq!(roots.len(), 1);
        assert!(matches!(&roots[0].kind, TreeNodeKind::Binary(s) if s == r#""git""#));

        // Should have two leaves (one allow from User, one deny from Project)
        fn count_leaves(node: &TreeNode) -> usize {
            match &node.kind {
                TreeNodeKind::Leaf { .. } => 1,
                _ => node.children.iter().map(count_leaves).sum(),
            }
        }
        assert_eq!(count_leaves(&roots[0]), 2);
    }

    #[test]
    fn flatten_all_expanded() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let roots = build_tree(&[policy]);
        let rows = flatten(&roots);

        // All nodes are expanded by default, so all should be visible:
        // Binary("git") -> Domain(Exec) -> Leaf = 3 rows
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[1].depth, 1);
        assert_eq!(rows[2].depth, 2);
    }

    #[test]
    fn flatten_collapsed_hides_children() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let mut roots = build_tree(&[policy]);

        // Collapse the root
        roots[0].expanded = false;
        let rows = flatten(&roots);

        // Only the root should be visible
        assert_eq!(rows.len(), 1);
        assert!(matches!(&rows[0].kind, TreeNodeKind::Binary(s) if s == r#""git""#));
        assert!(!rows[0].expanded);
    }

    #[test]
    fn flatten_tree_path_correct() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git")) (deny (exec "cargo")))"#,
        );
        let roots = build_tree(&[policy]);
        let rows = flatten(&roots);

        // Every row's tree_path should resolve back to a valid node
        for row in &rows {
            let node = node_at_path(&roots, &row.tree_path);
            assert!(
                node.is_some(),
                "tree_path {:?} should resolve to a node",
                row.tree_path
            );
        }
    }

    #[test]
    fn node_at_path_valid() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let roots = build_tree(&[policy]);

        // Path [0] = first root
        let node = node_at_path(&roots, &[0]);
        assert!(node.is_some());
        assert!(matches!(&node.unwrap().kind, TreeNodeKind::Binary(s) if s == r#""git""#));

        // Path [0, 0] = first child of first root
        let node = node_at_path(&roots, &[0, 0]);
        assert!(node.is_some());
    }

    #[test]
    fn node_at_path_invalid() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let roots = build_tree(&[policy]);

        // Out of bounds
        assert!(node_at_path(&roots, &[99]).is_none());
        assert!(node_at_path(&roots, &[0, 99]).is_none());
    }

    #[test]
    fn node_at_path_empty() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let roots = build_tree(&[policy]);

        assert!(node_at_path(&roots, &[]).is_none());
    }

    #[test]
    fn effect_counts_single() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let roots = build_tree(&[policy]);
        let (allow, deny, ask) = roots[0].effect_counts();
        assert_eq!((allow, deny, ask), (1, 0, 0));
    }

    #[test]
    fn effect_counts_mixed() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git")) (deny (exec "rm")) (ask (exec "sudo")))"#,
        );
        let roots = build_tree(&[policy]);
        let total: (usize, usize, usize) = roots.iter().fold((0, 0, 0), |(a, d, k), root| {
            let (ra, rd, rk) = root.effect_counts();
            (a + ra, d + rd, k + rk)
        });
        assert_eq!(total, (1, 1, 1));
    }

    #[test]
    fn rule_count() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git")) (deny (exec "rm")))"#,
        );
        let roots = build_tree(&[policy]);
        let total: usize = roots.iter().map(|r| r.rule_count()).sum();
        assert_eq!(total, 2);
    }
}
