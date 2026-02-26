//! Policy tree: build a visual tree from AST rules, flatten for rendering.
//!
//! Nodes are stored in a `TreeArena` (flat `Vec<TreeNode>` indexed by `NodeId`).
//! `FlatRow` carries a `NodeId` instead of cloning the `TreeNodeKind`, so
//! navigation is a cheap index lookup rather than a path traversal.

use std::fmt;
use std::ops::{Index, IndexMut};

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
        /// Whether this rule is shadowed by a higher-precedence rule at another level.
        is_shadowed: bool,
    },
    /// Leaf for a sandbox sub-rule (child of a sandboxed exec rule).
    SandboxLeaf {
        effect: Effect,
        sandbox_rule: Rule,
        parent_rule: Rule,
        level: PolicyLevel,
        policy: String,
    },
    /// Grouping node for sandbox sub-rules (child of a sandboxed Leaf).
    SandboxGroup,
    /// A named sandbox reference (child of a sandboxed Leaf).
    SandboxName(String),
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
// NodeId and TreeArena
// ---------------------------------------------------------------------------

/// Index into a `TreeArena`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(usize);

impl NodeId {
    /// Create a dummy NodeId for use in tests where the arena is not used.
    #[cfg(test)]
    pub fn dummy() -> Self {
        NodeId(0)
    }
}

/// A node stored in the arena.
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub kind: TreeNodeKind,
    pub children: Vec<NodeId>,
    pub parent: Option<NodeId>,
    pub expanded: bool,
}

/// Arena holding all tree nodes, plus the root set.
#[derive(Debug, Clone)]
pub struct TreeArena {
    nodes: Vec<TreeNode>,
    pub root_ids: Vec<NodeId>,
}

impl TreeArena {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            root_ids: Vec::new(),
        }
    }

    /// Allocate a new node, returning its ID.
    fn alloc(&mut self, kind: TreeNodeKind, parent: Option<NodeId>) -> NodeId {
        let id = NodeId(self.nodes.len());
        self.nodes.push(TreeNode {
            kind,
            children: Vec::new(),
            parent,
            expanded: true,
        });
        id
    }

    pub fn is_empty(&self) -> bool {
        self.root_ids.is_empty()
    }

    /// Iterate over root nodes.
    pub fn roots(&self) -> impl Iterator<Item = (NodeId, &TreeNode)> {
        self.root_ids.iter().map(|&id| (id, &self.nodes[id.0]))
    }

    /// Get a node by ID.
    pub fn get(&self, id: NodeId) -> &TreeNode {
        &self.nodes[id.0]
    }

    /// Get a mutable node by ID.
    pub fn get_mut(&mut self, id: NodeId) -> &mut TreeNode {
        &mut self.nodes[id.0]
    }

    /// Count all leaf rules under a node (recursive).
    pub fn rule_count(&self, id: NodeId) -> usize {
        let node = &self[id];
        match &node.kind {
            TreeNodeKind::Leaf { .. } => 1,
            TreeNodeKind::SandboxLeaf { .. } => 0,
            _ => {
                let children: Vec<NodeId> = node.children.clone();
                children.iter().map(|&c| self.rule_count(c)).sum()
            }
        }
    }

    /// Count leaf effects under a node: (allow, deny, ask).
    pub fn effect_counts(&self, id: NodeId) -> (usize, usize, usize) {
        let node = &self[id];
        match &node.kind {
            TreeNodeKind::Leaf { effect, .. } => match effect {
                Effect::Allow => (1, 0, 0),
                Effect::Deny => (0, 1, 0),
                Effect::Ask => (0, 0, 1),
            },
            TreeNodeKind::SandboxLeaf { .. } => (0, 0, 0),
            _ => {
                let children: Vec<NodeId> = node.children.clone();
                let (mut a, mut d, mut k) = (0, 0, 0);
                for &c in &children {
                    let (ca, cd, ck) = self.effect_counts(c);
                    a += ca;
                    d += cd;
                    k += ck;
                }
                (a, d, k)
            }
        }
    }

    /// Collect the ancestor chain from root to the given node (inclusive).
    pub fn ancestors(&self, id: NodeId) -> Vec<NodeId> {
        let mut chain = Vec::new();
        let mut cur = id;
        loop {
            chain.push(cur);
            match self[cur].parent {
                Some(p) => cur = p,
                None => break,
            }
        }
        chain.reverse();
        chain
    }

    /// Walk all nodes in the arena, calling `f` on each.
    pub fn for_each_mut(&mut self, mut f: impl FnMut(&mut TreeNode)) {
        for node in &mut self.nodes {
            f(node);
        }
    }

    /// Walk all descendants of a node (not including the node itself).
    fn walk(&self, id: NodeId, f: &mut impl FnMut(NodeId, &TreeNode)) {
        let children: Vec<NodeId> = self[id].children.clone();
        for cid in children {
            f(cid, &self[cid]);
            self.walk(cid, f);
        }
    }

    /// Walk all nodes in the entire arena.
    fn walk_all(&self, f: &mut impl FnMut(NodeId, &TreeNode)) {
        for &rid in &self.root_ids {
            f(rid, &self[rid]);
            self.walk(rid, f);
        }
    }
}

impl Index<NodeId> for TreeArena {
    type Output = TreeNode;
    fn index(&self, id: NodeId) -> &TreeNode {
        &self.nodes[id.0]
    }
}

impl IndexMut<NodeId> for TreeArena {
    fn index_mut(&mut self, id: NodeId) -> &mut TreeNode {
        &mut self.nodes[id.0]
    }
}

// ---------------------------------------------------------------------------
// Flat row for rendering
// ---------------------------------------------------------------------------

/// A flattened row ready for terminal rendering.
#[derive(Debug, Clone)]
pub struct FlatRow {
    /// The arena node this row represents.
    pub node_id: NodeId,
    pub depth: usize,
    pub expanded: bool,
    pub has_children: bool,
    /// For drawing tree connector lines: true = draw vertical line at this depth.
    pub connectors: Vec<bool>,
}

// ---------------------------------------------------------------------------
// Build node (private, used only during tree construction)
// ---------------------------------------------------------------------------

/// Temporary tree structure used during building. Converted to arena afterwards.
#[derive(Debug, Clone)]
struct BuildNode {
    kind: TreeNodeKind,
    children: Vec<BuildNode>,
    expanded: bool,
}

impl BuildNode {
    fn new(kind: TreeNodeKind) -> Self {
        Self {
            kind,
            children: Vec::new(),
            expanded: true,
        }
    }
}

/// Convert a list of BuildNodes into the arena, returning their NodeIds.
fn insert_build_nodes(
    arena: &mut TreeArena,
    nodes: Vec<BuildNode>,
    parent: Option<NodeId>,
) -> Vec<NodeId> {
    let mut ids = Vec::with_capacity(nodes.len());
    for bn in nodes {
        let id = arena.alloc(bn.kind, parent);
        arena[id].expanded = bn.expanded;
        if let Some(p) = parent {
            arena[p].children.push(id);
        }
        let child_ids = insert_build_nodes(arena, bn.children, Some(id));
        // children were already pushed during insert_build_nodes via arena[p].children.push
        let _ = child_ids;
        ids.push(id);
    }
    ids
}

// ---------------------------------------------------------------------------
// Build the visual tree from loaded policies
// ---------------------------------------------------------------------------

/// A rule with provenance info.
#[derive(Clone)]
pub(crate) struct ProvenanceRule {
    pub rule: Rule,
    pub level: PolicyLevel,
    pub policy_name: String,
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

/// Build the full visual tree from loaded policies, returning an arena.
pub fn build_tree(policies: &[LoadedPolicy]) -> TreeArena {
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

    let mut roots: Vec<BuildNode> = Vec::new();

    roots.extend(build_exec_tree(exec_rules));

    // Fs, net, and tool rules apply to any command — group under "*"
    let mut wildcard_children = Vec::new();
    wildcard_children.extend(build_fs_tree(fs_rules, &regular_leaf));
    wildcard_children.extend(build_net_tree(net_rules, &regular_leaf));
    wildcard_children.extend(build_tool_tree(tool_rules, &regular_leaf));
    if !wildcard_children.is_empty() {
        let mut wildcard = BuildNode::new(TreeNodeKind::Binary("*".to_string()));
        wildcard.children = wildcard_children;
        roots.push(wildcard);
    }

    // Merge top-level nodes that share a key
    merge_nodes(&mut roots);

    // Convert BuildNode tree into arena
    let mut arena = TreeArena::new();
    let root_ids = insert_build_nodes(&mut arena, roots, None);
    arena.root_ids = root_ids;
    arena
}

// ---------------------------------------------------------------------------
// Exec tree: trie on (bin, args...)
// ---------------------------------------------------------------------------

fn build_exec_tree(rules: Vec<ProvenanceRule>) -> Vec<BuildNode> {
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
            let mut bin_node = BuildNode::new(TreeNodeKind::Binary(bin_text));
            bin_node.children = build_exec_args_tree(rules);
            bin_node
        })
        .collect()
}

/// Build a regular Leaf node from a ProvenanceRule.
fn regular_leaf(pr: &ProvenanceRule) -> BuildNode {
    BuildNode::new(TreeNodeKind::Leaf {
        effect: pr.rule.effect,
        rule: pr.rule.clone(),
        level: pr.level,
        policy: pr.policy_name.clone(),
        is_shadowed: false,
    })
}

/// Append sandbox children to a Leaf node based on the rule's sandbox field.
fn append_sandbox_children(
    leaf: &mut BuildNode,
    parent_rule: &Rule,
    level: PolicyLevel,
    policy: &str,
    sandbox: &Option<SandboxRef>,
) {
    match sandbox {
        Some(SandboxRef::Inline(rules)) => {
            let make_leaf = |pr: &ProvenanceRule| {
                BuildNode::new(TreeNodeKind::SandboxLeaf {
                    effect: pr.rule.effect,
                    sandbox_rule: pr.rule.clone(),
                    parent_rule: parent_rule.clone(),
                    level,
                    policy: policy.to_string(),
                })
            };
            let mut fs_rules = Vec::new();
            let mut net_rules = Vec::new();
            let mut tool_rules = Vec::new();
            for r in rules {
                let pr = ProvenanceRule {
                    rule: r.clone(),
                    level,
                    policy_name: policy.to_string(),
                };
                match &r.matcher {
                    CapMatcher::Fs(_) => fs_rules.push(pr),
                    CapMatcher::Net(_) => net_rules.push(pr),
                    CapMatcher::Tool(_) => tool_rules.push(pr),
                    CapMatcher::Exec(_) => {} // exec-in-sandbox not expected
                }
            }
            let mut group = BuildNode::new(TreeNodeKind::SandboxGroup);
            group.children.extend(build_fs_tree(fs_rules, &make_leaf));
            group.children.extend(build_net_tree(net_rules, &make_leaf));
            group
                .children
                .extend(build_tool_tree(tool_rules, &make_leaf));
            if !group.children.is_empty() {
                leaf.children.push(group);
            }
        }
        Some(SandboxRef::Named(name)) => {
            leaf.children
                .push(BuildNode::new(TreeNodeKind::SandboxName(name.clone())));
        }
        None => {}
    }
}

fn build_exec_args_tree(rules: Vec<ProvenanceRule>) -> Vec<BuildNode> {
    let mut children = Vec::new();

    for pr in rules {
        let (args, has_args) = match &pr.rule.matcher {
            CapMatcher::Exec(m) => (&m.args, &m.has_args),
            _ => continue,
        };

        if args.is_empty() && has_args.is_empty() {
            let mut leaf = BuildNode::new(TreeNodeKind::Leaf {
                effect: pr.rule.effect,
                rule: pr.rule.clone(),
                level: pr.level,
                policy: pr.policy_name.clone(),
                is_shadowed: false,
            });
            append_sandbox_children(
                &mut leaf,
                &pr.rule,
                pr.level,
                &pr.policy_name,
                &pr.rule.sandbox,
            );
            let mut domain = BuildNode::new(TreeNodeKind::Domain(DomainKind::Exec));
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
                let mut leaf = BuildNode::new(TreeNodeKind::Leaf {
                    effect: pr.rule.effect,
                    rule: pr.rule.clone(),
                    level: pr.level,
                    policy: pr.policy_name.clone(),
                    is_shadowed: false,
                });
                append_sandbox_children(
                    &mut leaf,
                    &pr.rule,
                    pr.level,
                    &pr.policy_name,
                    &pr.rule.sandbox,
                );
                let mut domain = BuildNode::new(TreeNodeKind::Domain(DomainKind::Exec));
                domain.children.push(leaf);

                let mut chain_nodes: Vec<BuildNode> = Vec::new();
                for text in arg_combo {
                    chain_nodes.push(BuildNode::new(TreeNodeKind::Arg(text.clone())));
                }
                if !has_combo.is_empty() {
                    chain_nodes.push(BuildNode::new(TreeNodeKind::HasMarker));
                    for text in has_combo {
                        chain_nodes.push(BuildNode::new(TreeNodeKind::HasArg(text.clone())));
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
fn merge_nodes(nodes: &mut Vec<BuildNode>) {
    if nodes.len() <= 1 {
        return;
    }

    let mut merged: Vec<BuildNode> = Vec::new();

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
        TreeNodeKind::SandboxLeaf {
            sandbox_rule,
            parent_rule,
            ..
        } => format!("sbx-leaf:{sandbox_rule}:{parent_rule}"),
        TreeNodeKind::SandboxGroup => "sbx-group".into(),
        TreeNodeKind::SandboxName(name) => format!("sbx-name:{name}"),
    }
}

// ---------------------------------------------------------------------------
// Fs tree
// ---------------------------------------------------------------------------

fn build_fs_tree(
    rules: Vec<ProvenanceRule>,
    make_leaf: &dyn Fn(&ProvenanceRule) -> BuildNode,
) -> Vec<BuildNode> {
    let mut children = Vec::new();

    for pr in rules {
        let (ops, paths) = match &pr.rule.matcher {
            CapMatcher::Fs(m) => (expand_op(&m.op), m.path.as_ref().map(expand_path_filter)),
            _ => continue,
        };

        for op in &ops {
            let leaf = make_leaf(&pr);
            let mut domain = BuildNode::new(TreeNodeKind::Domain(DomainKind::Filesystem));
            domain.children.push(leaf);

            if let Some(path_texts) = &paths {
                for path_text in path_texts {
                    let mut path_node = BuildNode::new(TreeNodeKind::PathNode(path_text.clone()));
                    if op == "*" {
                        path_node.children.push(domain.clone());
                    } else {
                        let mut op_node = BuildNode::new(TreeNodeKind::FsOp(op.clone()));
                        op_node.children.push(domain.clone());
                        path_node.children.push(op_node);
                    }
                    children.push(path_node);
                }
            } else if op == "*" {
                children.push(domain);
            } else {
                let mut op_node = BuildNode::new(TreeNodeKind::FsOp(op.clone()));
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

fn build_net_tree(
    rules: Vec<ProvenanceRule>,
    make_leaf: &dyn Fn(&ProvenanceRule) -> BuildNode,
) -> Vec<BuildNode> {
    let mut children = Vec::new();

    for pr in rules {
        let domain_texts = match &pr.rule.matcher {
            CapMatcher::Net(m) => expand_pattern(&m.domain),
            _ => continue,
        };

        for domain_text in domain_texts {
            let leaf = make_leaf(&pr);
            let mut domain = BuildNode::new(TreeNodeKind::Domain(DomainKind::Network));
            domain.children.push(leaf);

            if domain_text == "*" {
                children.push(domain);
            } else {
                let mut domain_node = BuildNode::new(TreeNodeKind::NetDomain(domain_text));
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

fn build_tool_tree(
    rules: Vec<ProvenanceRule>,
    make_leaf: &dyn Fn(&ProvenanceRule) -> BuildNode,
) -> Vec<BuildNode> {
    let mut children = Vec::new();

    for pr in rules {
        let name_texts = match &pr.rule.matcher {
            CapMatcher::Tool(m) => expand_pattern(&m.name),
            _ => continue,
        };

        for name_text in name_texts {
            let leaf = make_leaf(&pr);
            let mut domain = BuildNode::new(TreeNodeKind::Domain(DomainKind::Tool));
            domain.children.push(leaf);

            if name_text == "*" {
                children.push(domain);
            } else {
                let mut name_node = BuildNode::new(TreeNodeKind::ToolName(name_text));
                name_node.children.push(domain);
                children.push(name_node);
            }
        }
    }

    merge_nodes(&mut children);
    children
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

/// Extract searchable text from a node kind.
pub fn node_search_text(kind: &TreeNodeKind) -> String {
    match kind {
        TreeNodeKind::Domain(d) => d.to_string(),
        TreeNodeKind::PolicyBlock { name, level } => format!("{name} {level}"),
        TreeNodeKind::Binary(s)
        | TreeNodeKind::Arg(s)
        | TreeNodeKind::HasArg(s)
        | TreeNodeKind::PathNode(s)
        | TreeNodeKind::FsOp(s)
        | TreeNodeKind::NetDomain(s)
        | TreeNodeKind::ToolName(s) => s.clone(),
        TreeNodeKind::HasMarker => ":has".into(),
        TreeNodeKind::Leaf {
            effect,
            rule,
            policy,
            ..
        } => format!("{effect} {rule} {policy}"),
        TreeNodeKind::SandboxLeaf { sandbox_rule, .. } => format!("sandbox {sandbox_rule}"),
        TreeNodeKind::SandboxGroup => "sandbox".into(),
        TreeNodeKind::SandboxName(name) => format!("sandbox {name}"),
    }
}

/// Search the full arena for nodes matching a query (case-insensitive),
/// regardless of collapsed state. Returns NodeIds of all matching nodes.
pub fn search_tree(arena: &TreeArena, query: &str) -> Vec<NodeId> {
    let query_lower = query.to_lowercase();
    if query_lower.is_empty() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    arena.walk_all(&mut |id, node| {
        let text = node_search_text(&node.kind);
        if text.to_lowercase().contains(&query_lower) {
            matches.push(id);
        }
    });
    matches
}

// ---------------------------------------------------------------------------
// Flatten tree for rendering
// ---------------------------------------------------------------------------

/// Flatten the tree into rows for rendering, respecting collapsed state.
pub fn flatten(arena: &TreeArena) -> Vec<FlatRow> {
    let mut rows = Vec::new();
    let root_count = arena.root_ids.len();
    for (i, &root_id) in arena.root_ids.iter().enumerate() {
        let is_last = i == root_count - 1;
        flatten_node(arena, root_id, 0, &mut [], is_last, &mut rows);
    }
    rows
}

fn flatten_node(
    arena: &TreeArena,
    node_id: NodeId,
    depth: usize,
    parent_connectors: &mut [bool],
    is_last_sibling: bool,
    out: &mut Vec<FlatRow>,
) {
    let node = &arena[node_id];
    let mut connectors = parent_connectors.to_owned();
    if depth > 0 {
        if connectors.len() >= depth {
            connectors[depth - 1] = !is_last_sibling;
        } else {
            connectors.push(!is_last_sibling);
        }
    }

    out.push(FlatRow {
        node_id,
        depth,
        expanded: node.expanded,
        has_children: !node.children.is_empty(),
        connectors: connectors.clone(),
    });

    if node.expanded {
        let children: Vec<NodeId> = node.children.clone();
        let child_count = children.len();
        for (i, child_id) in children.into_iter().enumerate() {
            let is_last = i == child_count - 1;
            flatten_node(arena, child_id, depth + 1, &mut connectors, is_last, out);
        }
    }
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
        let arena = build_tree(&[]);
        assert!(arena.root_ids.is_empty());
    }

    #[test]
    fn build_tree_empty_source() {
        let policy = test_policy(PolicyLevel::User, "");
        let arena = build_tree(&[policy]);
        assert!(arena.root_ids.is_empty());
    }

    #[test]
    fn build_tree_single_exec() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let arena = build_tree(&[policy]);

        // Should have one root: Binary(r#""git""#)
        assert_eq!(arena.root_ids.len(), 1);
        let root = &arena[arena.root_ids[0]];
        assert!(
            matches!(&root.kind, TreeNodeKind::Binary(s) if s == r#""git""#),
            "root should be Binary(\"git\"), got {:?}",
            root.kind
        );

        // Binary -> Domain(Exec) -> Leaf
        assert_eq!(root.children.len(), 1);
        let domain = &arena[root.children[0]];
        assert!(matches!(
            &domain.kind,
            TreeNodeKind::Domain(DomainKind::Exec)
        ));
        assert_eq!(domain.children.len(), 1);
        let leaf = &arena[domain.children[0]];
        assert!(matches!(
            &leaf.kind,
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
        let arena = build_tree(&[policy]);

        assert_eq!(arena.root_ids.len(), 1);
        let root = &arena[arena.root_ids[0]];
        assert!(
            matches!(&root.kind, TreeNodeKind::Binary(s) if s == r#""git""#),
            "root should be Binary(\"git\"), got {:?}",
            root.kind
        );

        // Binary -> Arg("push") -> Arg("*") -> Domain(Exec) -> Leaf
        let child = &arena[root.children[0]];
        assert!(
            matches!(&child.kind, TreeNodeKind::Arg(s) if s == r#""push""#),
            "first child should be Arg(\"push\"), got {:?}",
            child.kind
        );
        let child2 = &arena[child.children[0]];
        assert!(matches!(&child2.kind, TreeNodeKind::Arg(s) if s == "*"));
        let domain = &arena[child2.children[0]];
        assert!(matches!(
            &domain.kind,
            TreeNodeKind::Domain(DomainKind::Exec)
        ));
        let leaf = &arena[domain.children[0]];
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
        let arena = build_tree(&[policy]);

        // Fs rules go under a wildcard "*" binary node
        assert_eq!(arena.root_ids.len(), 1);
        let root = &arena[arena.root_ids[0]];
        assert!(matches!(&root.kind, TreeNodeKind::Binary(s) if s == "*"));

        // Should contain a leaf somewhere
        fn find_leaf(arena: &TreeArena, id: NodeId) -> bool {
            if matches!(&arena[id].kind, TreeNodeKind::Leaf { .. }) {
                return true;
            }
            arena[id].children.iter().any(|&c| find_leaf(arena, c))
        }
        assert!(find_leaf(&arena, arena.root_ids[0]));
    }

    #[test]
    fn build_tree_net_rule() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (net "example.com")))"#,
        );
        let arena = build_tree(&[policy]);
        assert!(!arena.root_ids.is_empty());

        // Net goes under "*" binary
        let root = &arena[arena.root_ids[0]];
        assert!(matches!(&root.kind, TreeNodeKind::Binary(s) if s == "*"));
    }

    #[test]
    fn build_tree_tool_rule() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (ask (tool "Bash")))"#);
        let arena = build_tree(&[policy]);
        assert!(!arena.root_ids.is_empty());

        let root = &arena[arena.root_ids[0]];
        assert!(matches!(&root.kind, TreeNodeKind::Binary(s) if s == "*"));
    }

    #[test]
    fn build_tree_merge_wildcards() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec *)) (deny (fs read "/tmp")))"#,
        );
        let arena = build_tree(&[policy]);

        assert_eq!(arena.root_ids.len(), 1);
        let root = &arena[arena.root_ids[0]];
        assert!(matches!(&root.kind, TreeNodeKind::Binary(s) if s == "*"));
        assert!(root.children.len() >= 2);
    }

    #[test]
    fn build_tree_multi_level() {
        let user = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let project = test_policy(
            PolicyLevel::Project,
            r#"(policy "main" (deny (exec "git")))"#,
        );
        let arena = build_tree(&[user, project]);

        assert_eq!(arena.root_ids.len(), 1);
        let root = &arena[arena.root_ids[0]];
        assert!(matches!(&root.kind, TreeNodeKind::Binary(s) if s == r#""git""#));

        // Should have two leaves
        fn count_leaves(arena: &TreeArena, id: NodeId) -> usize {
            match &arena[id].kind {
                TreeNodeKind::Leaf { .. } => 1,
                _ => arena[id]
                    .children
                    .iter()
                    .map(|&c| count_leaves(arena, c))
                    .sum(),
            }
        }
        assert_eq!(count_leaves(&arena, arena.root_ids[0]), 2);
    }

    #[test]
    fn flatten_all_expanded() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let arena = build_tree(&[policy]);
        let rows = flatten(&arena);

        // Binary("git") -> Domain(Exec) -> Leaf = 3 rows
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[1].depth, 1);
        assert_eq!(rows[2].depth, 2);
    }

    #[test]
    fn flatten_collapsed_hides_children() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let mut arena = build_tree(&[policy]);

        // Collapse the root
        let root_id = arena.root_ids[0];
        arena[root_id].expanded = false;
        let rows = flatten(&arena);

        assert_eq!(rows.len(), 1);
        assert!(matches!(&arena[rows[0].node_id].kind, TreeNodeKind::Binary(s) if s == r#""git""#));
        assert!(!rows[0].expanded);
    }

    #[test]
    fn flatten_node_id_valid() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git")) (deny (exec "cargo")))"#,
        );
        let arena = build_tree(&[policy]);
        let rows = flatten(&arena);

        // Every row's node_id should resolve to a valid node
        for row in &rows {
            let _node = &arena[row.node_id]; // Should not panic
        }
    }

    #[test]
    fn effect_counts_single() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let arena = build_tree(&[policy]);
        let (allow, deny, ask) = arena.effect_counts(arena.root_ids[0]);
        assert_eq!((allow, deny, ask), (1, 0, 0));
    }

    #[test]
    fn effect_counts_mixed() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git")) (deny (exec "rm")) (ask (exec "sudo")))"#,
        );
        let arena = build_tree(&[policy]);
        let total: (usize, usize, usize) =
            arena.root_ids.iter().fold((0, 0, 0), |(a, d, k), &root| {
                let (ra, rd, rk) = arena.effect_counts(root);
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
        let arena = build_tree(&[policy]);
        let total: usize = arena.root_ids.iter().map(|&r| arena.rule_count(r)).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn build_tree_sandboxed_exec_inline() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (ask (exec "ls" "-lha") :sandbox (allow (fs))))"#,
        );
        let arena = build_tree(&[policy]);

        fn find_leaf(arena: &TreeArena, id: NodeId) -> Option<NodeId> {
            if matches!(&arena[id].kind, TreeNodeKind::Leaf { .. }) {
                return Some(id);
            }
            arena[id].children.iter().find_map(|&c| find_leaf(arena, c))
        }
        let leaf_id = find_leaf(&arena, arena.root_ids[0]).expect("should have a leaf");
        let leaf = &arena[leaf_id];
        assert!(
            !leaf.children.is_empty(),
            "sandboxed leaf should have children (sub-tree)"
        );

        fn find_sandbox_leaf(arena: &TreeArena, id: NodeId) -> Option<NodeId> {
            if matches!(&arena[id].kind, TreeNodeKind::SandboxLeaf { .. }) {
                return Some(id);
            }
            arena[id]
                .children
                .iter()
                .find_map(|&c| find_sandbox_leaf(arena, c))
        }
        let sbx_id = find_sandbox_leaf(&arena, leaf_id).expect("should have a SandboxLeaf");
        assert!(
            matches!(
                &arena[sbx_id].kind,
                TreeNodeKind::SandboxLeaf {
                    effect: Effect::Allow,
                    ..
                }
            ),
            "sandbox leaf should have Allow effect, got {:?}",
            arena[sbx_id].kind
        );
    }

    #[test]
    fn build_tree_sandboxed_exec_inline_decomposed() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (ask (exec "ls" "-lha") :sandbox (allow (fs read "/tmp")) (deny (net *))))"#,
        );
        let arena = build_tree(&[policy]);

        fn find_leaf(arena: &TreeArena, id: NodeId) -> Option<NodeId> {
            if matches!(&arena[id].kind, TreeNodeKind::Leaf { .. }) {
                return Some(id);
            }
            arena[id].children.iter().find_map(|&c| find_leaf(arena, c))
        }
        let leaf_id = find_leaf(&arena, arena.root_ids[0]).expect("should have a leaf");

        fn count_sandbox_leaves(arena: &TreeArena, id: NodeId) -> usize {
            let here = if matches!(&arena[id].kind, TreeNodeKind::SandboxLeaf { .. }) {
                1
            } else {
                0
            };
            here + arena[id]
                .children
                .iter()
                .map(|&c| count_sandbox_leaves(arena, c))
                .sum::<usize>()
        }
        let sbx_count = count_sandbox_leaves(&arena, leaf_id);
        assert_eq!(sbx_count, 2, "should have 2 SandboxLeaf nodes (fs + net)");

        fn has_domain(arena: &TreeArena, id: NodeId, kind: super::DomainKind) -> bool {
            matches!(&arena[id].kind, TreeNodeKind::Domain(d) if *d == kind)
                || arena[id]
                    .children
                    .iter()
                    .any(|&c| has_domain(arena, c, kind))
        }
        assert!(has_domain(&arena, leaf_id, super::DomainKind::Filesystem));
        assert!(has_domain(&arena, leaf_id, super::DomainKind::Network));
    }

    #[test]
    fn build_tree_sandboxed_exec_fs_with_path() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs read "/tmp"))))"#,
        );
        let arena = build_tree(&[policy]);

        fn find_leaf(arena: &TreeArena, id: NodeId) -> Option<NodeId> {
            if matches!(&arena[id].kind, TreeNodeKind::Leaf { .. }) {
                return Some(id);
            }
            arena[id].children.iter().find_map(|&c| find_leaf(arena, c))
        }
        let leaf_id = find_leaf(&arena, arena.root_ids[0]).expect("should have a leaf");

        fn has_path_node(arena: &TreeArena, id: NodeId) -> bool {
            matches!(&arena[id].kind, TreeNodeKind::PathNode(_))
                || arena[id].children.iter().any(|&c| has_path_node(arena, c))
        }
        assert!(
            has_path_node(&arena, leaf_id),
            "sandbox fs with path should create PathNode sub-tree"
        );
    }

    #[test]
    fn sandbox_leaf_not_counted_in_rule_count() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs)) (deny (net *))))"#,
        );
        let arena = build_tree(&[policy]);
        let total: usize = arena.root_ids.iter().map(|&r| arena.rule_count(r)).sum();
        assert_eq!(total, 1, "sandbox leaves should not count as rules");

        let (allow, deny, ask) = arena.root_ids.iter().fold((0, 0, 0), |(a, d, k), &r| {
            let (ra, rd, rk) = arena.effect_counts(r);
            (a + ra, d + rd, k + rk)
        });
        assert_eq!(
            (allow, deny, ask),
            (0, 0, 1),
            "only the parent ask should be counted"
        );
    }

    #[test]
    fn build_tree_sandboxed_exec_named() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "cargo" *) :sandbox "cargo-env"))"#,
        );
        let arena = build_tree(&[policy]);

        fn find_leaf(arena: &TreeArena, id: NodeId) -> Option<NodeId> {
            if matches!(&arena[id].kind, TreeNodeKind::Leaf { .. }) {
                return Some(id);
            }
            arena[id].children.iter().find_map(|&c| find_leaf(arena, c))
        }
        let leaf_id = find_leaf(&arena, arena.root_ids[0]).expect("should have a leaf");
        let leaf = &arena[leaf_id];
        assert_eq!(
            leaf.children.len(),
            1,
            "named sandbox should have one child"
        );
        let child = &arena[leaf.children[0]];
        assert!(
            matches!(&child.kind, TreeNodeKind::SandboxName(name) if name == "cargo-env"),
            "sandbox child should be SandboxName(\"cargo-env\"), got {:?}",
            child.kind
        );
    }

    #[test]
    fn node_search_text_variants() {
        assert_eq!(node_search_text(&TreeNodeKind::Binary("git".into())), "git");
        assert_eq!(
            node_search_text(&TreeNodeKind::Domain(DomainKind::Exec)),
            "Exec"
        );
        assert_eq!(node_search_text(&TreeNodeKind::HasMarker), ":has");
        assert_eq!(node_search_text(&TreeNodeKind::SandboxGroup), "sandbox");
        assert_eq!(
            node_search_text(&TreeNodeKind::SandboxName("test".into())),
            "sandbox test"
        );
    }

    #[test]
    fn search_tree_finds_all_matches() {
        let policy = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git")) (deny (exec "cargo")))"#,
        );
        let arena = build_tree(&[policy]);

        let matches = search_tree(&arena, "Exec");
        assert!(
            matches.len() >= 2,
            "should find at least 2 Exec domain nodes, got {}",
            matches.len()
        );
    }

    #[test]
    fn search_tree_case_insensitive() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let arena = build_tree(&[policy]);

        let upper = search_tree(&arena, "GIT");
        let lower = search_tree(&arena, "git");
        assert_eq!(upper.len(), lower.len());
        assert!(!upper.is_empty());
    }

    #[test]
    fn search_tree_empty_query() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let arena = build_tree(&[policy]);
        assert!(search_tree(&arena, "").is_empty());
    }

    #[test]
    fn search_tree_no_match() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let arena = build_tree(&[policy]);
        assert!(search_tree(&arena, "zzzznotfound").is_empty());
    }

    #[test]
    fn search_tree_finds_collapsed_nodes() {
        let policy = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let mut arena = build_tree(&[policy]);

        // Collapse everything
        arena.for_each_mut(|node| node.expanded = false);

        let matches = search_tree(&arena, "allow");
        assert!(
            !matches.is_empty(),
            "search_tree should find nodes regardless of collapsed state"
        );
    }

    // -----------------------------------------------------------------------
    // Property-based tests
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    use crate::policy::ast::strategies::arb_rule;

    /// Generate a policy source from arbitrary rules.
    fn arb_policy_source() -> impl Strategy<Value = String> {
        prop::collection::vec(arb_rule(), 1..=8).prop_map(|rules| {
            let mut s = String::from("(policy \"main\"");
            for rule in &rules {
                s.push_str(&format!("\n  {rule}"));
            }
            s.push_str("\n)");
            s
        })
    }

    proptest! {
        /// Every FlatRow's node_id resolves to a valid node in the arena.
        #[test]
        fn flat_row_node_ids_valid(source in arb_policy_source()) {
            let policy = test_policy(PolicyLevel::User, &source);
            let arena = build_tree(&[policy]);
            let rows = flatten(&arena);

            for row in &rows {
                let _node = &arena[row.node_id]; // should not panic
            }
        }

        /// expand_all + flatten is deterministic regardless of prior collapsed state.
        #[test]
        fn flatten_expand_all_idempotent(source in arb_policy_source()) {
            let policy = test_policy(PolicyLevel::User, &source);

            // Build tree and expand all, flatten
            let mut arena1 = build_tree(&[policy.clone()]);
            arena1.for_each_mut(|node| node.expanded = true);
            let rows1 = flatten(&arena1);

            // Build fresh tree, collapse all, then expand all, flatten
            let mut arena2 = build_tree(&[policy]);
            arena2.for_each_mut(|node| node.expanded = false);
            arena2.for_each_mut(|node| node.expanded = true);
            let rows2 = flatten(&arena2);

            prop_assert_eq!(rows1.len(), rows2.len(),
                "expand_all should produce same row count regardless of prior state");
            for (i, (r1, r2)) in rows1.iter().zip(rows2.iter()).enumerate() {
                prop_assert_eq!(r1.depth, r2.depth,
                    "row {} depth mismatch after expand_all", i);
                prop_assert!(r1.node_id == r2.node_id,
                    "row {} node_id mismatch after expand_all: {:?} vs {:?}",
                    i, r1.node_id, r2.node_id);
            }
        }
    }
}
