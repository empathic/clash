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
