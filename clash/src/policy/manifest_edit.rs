//! CRUD operations on [`PolicyManifest`] tree nodes.
//!
//! Provides `upsert_rule` (add-or-replace) and `remove_rule` for CLI-driven
//! policy mutation. After every mutation the tree is compacted.

use crate::policy::match_tree::{MatchVerdict, Node, Observable, Pattern, PolicyManifest};

/// Result of an upsert operation.
#[derive(Debug, PartialEq, Eq)]
pub enum UpsertResult {
    /// A new rule was prepended.
    Inserted,
    /// An existing rule's decision was replaced.
    Replaced,
}

/// Add or replace a rule in a [`PolicyManifest`].
///
/// Walks the manifest's root-level tree nodes looking for one whose observable
/// chain matches `new_node`. If found, replaces the leaf decision; otherwise
/// prepends the new node (highest priority via first-match semantics).
///
/// Compacts the tree after mutation.
pub fn upsert_rule(manifest: &mut PolicyManifest, new_node: Node) -> UpsertResult {
    let result = if let Some(idx) = find_matching_chain(&manifest.policy.tree, &new_node) {
        // Replace the leaf decision of the existing node.
        replace_leaf_decision(&mut manifest.policy.tree[idx], leaf_decision(&new_node));
        UpsertResult::Replaced
    } else {
        // Prepend so the new rule has highest priority.
        manifest.policy.tree.insert(0, new_node);
        UpsertResult::Inserted
    };
    manifest.policy.tree = Node::compact(std::mem::take(&mut manifest.policy.tree));
    result
}

/// Remove a rule whose observable chain matches `target`.
///
/// Returns `true` if a rule was removed, `false` if no match was found.
/// Compacts the tree after mutation.
pub fn remove_rule(manifest: &mut PolicyManifest, target: &Node) -> bool {
    if let Some(idx) = find_matching_chain(&manifest.policy.tree, target) {
        manifest.policy.tree.remove(idx);
        manifest.policy.tree = Node::compact(std::mem::take(&mut manifest.policy.tree));
        true
    } else {
        false
    }
}

/// Find the index of a root-level node whose observable chain matches `target`.
fn find_matching_chain(tree: &[Node], target: &Node) -> Option<usize> {
    tree.iter()
        .position(|existing| same_match_chain(existing, target))
}

/// Check if two rule branches have the same observable chain.
///
/// Walks both trees in lockstep comparing `(observable, pattern)` at each level.
/// The leaf decision is ignored — only the condition path matters.
fn same_match_chain(a: &Node, b: &Node) -> bool {
    match (a, b) {
        (
            Node::Condition {
                observe: obs_a,
                pattern: pat_a,
                children: ch_a,
                ..
            },
            Node::Condition {
                observe: obs_b,
                pattern: pat_b,
                children: ch_b,
                ..
            },
        ) => {
            if obs_a != obs_b || !patterns_equal(pat_a, pat_b) {
                return false;
            }
            // Compare the single-child chains. If both have exactly one child,
            // recurse. If both are leaves (decision children), they match
            // (we ignore the decision itself). Otherwise, they differ.
            match (ch_a.len(), ch_b.len()) {
                (1, 1) => same_match_chain(&ch_a[0], &ch_b[0]),
                // Both end in decisions (possibly different) → same chain.
                _ if children_are_all_decisions(ch_a) && children_are_all_decisions(ch_b) => true,
                // One has a decision child and the other has more conditions → different.
                _ => false,
            }
        }
        // Two decisions (bare) → same (trivially).
        (Node::Decision(_), Node::Decision(_)) => true,
        _ => false,
    }
}

/// Compare two patterns for structural equality.
///
/// `Pattern` contains `Regex` which doesn't impl `PartialEq`, so we compare
/// via their serialized JSON representation.
fn patterns_equal(a: &Pattern, b: &Pattern) -> bool {
    // Fast path for common cases.
    match (a, b) {
        (Pattern::Wildcard, Pattern::Wildcard) => return true,
        (Pattern::Literal(va), Pattern::Literal(vb)) => return va == vb,
        (Pattern::Prefix(va), Pattern::Prefix(vb)) => return va == vb,
        _ => {}
    }
    // Fallback: compare JSON representations.
    let ja = serde_json::to_value(a);
    let jb = serde_json::to_value(b);
    match (ja, jb) {
        (Ok(va), Ok(vb)) => va == vb,
        _ => false,
    }
}

fn children_are_all_decisions(children: &[Node]) -> bool {
    children.iter().all(|n| matches!(n, Node::Decision(_)))
}

/// Extract the leaf decision from a node tree (DFS to the first Decision).
fn leaf_decision(node: &Node) -> Option<&MatchVerdict> {
    match node {
        Node::Decision(d) => Some(d),
        Node::Condition { children, .. } => children.iter().find_map(leaf_decision),
    }
}

/// Replace the leaf decision(s) in a node tree.
fn replace_leaf_decision(node: &mut Node, new_decision: Option<&MatchVerdict>) {
    let Some(new_decision) = new_decision else {
        return;
    };
    match node {
        Node::Decision(d) => *d = new_decision.clone(),
        Node::Condition { children, .. } => {
            for child in children.iter_mut() {
                replace_leaf_decision(child, Some(new_decision));
            }
        }
    }
}

/// Build a condition chain from CLI arguments.
///
/// Constructs a `Node` tree representing a match chain, e.g.:
/// `tool_name=Bash → positional_arg(0)=gh → positional_arg(1)=pr → positional_arg(2)=create → decision`
pub fn build_exec_rule(bin: &str, args: &[&str], decision: MatchVerdict) -> Node {
    // Build the chain from the leaf (decision) upward.
    let mut current = Node::Decision(decision);

    // Args become positional_arg(1), positional_arg(2), ... in reverse.
    for (i, arg) in args.iter().enumerate().rev() {
        current = Node::Condition {
            observe: Observable::PositionalArg((i + 1) as i32),
            pattern: Pattern::Literal(crate::policy::match_tree::Value::Literal(
                (*arg).to_string(),
            )),
            children: vec![current],
            doc: None,
            source: None,
            terminal: false,
        };
    }

    // Binary is positional_arg(0).
    current = Node::Condition {
        observe: Observable::PositionalArg(0),
        pattern: Pattern::Literal(crate::policy::match_tree::Value::Literal(bin.into())),
        children: vec![current],
        doc: None,
        source: None,
        terminal: false,
    };

    // Outermost: tool_name = "Bash".
    Node::Condition {
        observe: Observable::ToolName,
        pattern: Pattern::Literal(crate::policy::match_tree::Value::Literal("Bash".into())),
        children: vec![current],
        doc: None,
        source: None,
        terminal: false,
    }
}

/// Build a tool-name rule (e.g. allow/deny a specific tool like "Read", "Write").
pub fn build_tool_rule(tool_name: &str, decision: MatchVerdict) -> Node {
    Node::Condition {
        observe: Observable::ToolName,
        pattern: Pattern::Literal(crate::policy::match_tree::Value::Literal(tool_name.into())),
        children: vec![Node::Decision(decision)],
        doc: None,
        source: None,
        terminal: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::match_tree::*;
    use std::collections::HashMap;

    fn empty_manifest() -> PolicyManifest {
        PolicyManifest {
            includes: vec![],
            policy: CompiledPolicy {
                sandboxes: HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        }
    }

    #[test]
    fn upsert_inserts_new_rule() {
        let mut manifest = empty_manifest();
        let node = build_exec_rule("grep", &[], MatchVerdict::Allow(None));
        let result = upsert_rule(&mut manifest, node);
        assert_eq!(result, UpsertResult::Inserted);
        assert_eq!(manifest.policy.tree.len(), 1);
    }

    #[test]
    fn upsert_replaces_same_chain() {
        let mut manifest = empty_manifest();
        let allow = build_exec_rule("grep", &[], MatchVerdict::Allow(None));
        upsert_rule(&mut manifest, allow);
        assert_eq!(manifest.policy.tree.len(), 1);

        // Now deny the same chain — should replace, not add.
        let deny = build_exec_rule("grep", &[], MatchVerdict::Deny);
        let result = upsert_rule(&mut manifest, deny);
        assert_eq!(result, UpsertResult::Replaced);
        // After compact, still 1 root node.
        assert_eq!(manifest.policy.tree.len(), 1);

        // The leaf should now be deny.
        let leaf = leaf_decision(&manifest.policy.tree[0]);
        assert!(matches!(leaf, Some(MatchVerdict::Deny)));
    }

    #[test]
    fn upsert_different_bins_are_separate() {
        let mut manifest = empty_manifest();
        upsert_rule(
            &mut manifest,
            build_exec_rule("grep", &[], MatchVerdict::Allow(None)),
        );
        upsert_rule(
            &mut manifest,
            build_exec_rule("rm", &[], MatchVerdict::Deny),
        );
        // Both should exist (compacted under a shared Bash parent).
        let total_rules = count_leaf_decisions(&manifest.policy.tree);
        assert_eq!(total_rules, 2);
    }

    #[test]
    fn remove_existing_rule() {
        let mut manifest = empty_manifest();
        upsert_rule(
            &mut manifest,
            build_exec_rule("grep", &[], MatchVerdict::Allow(None)),
        );
        let target = build_exec_rule("grep", &[], MatchVerdict::Allow(None));
        assert!(remove_rule(&mut manifest, &target));
        assert!(manifest.policy.tree.is_empty());
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut manifest = empty_manifest();
        upsert_rule(
            &mut manifest,
            build_exec_rule("grep", &[], MatchVerdict::Allow(None)),
        );
        let target = build_exec_rule("rm", &[], MatchVerdict::Allow(None));
        assert!(!remove_rule(&mut manifest, &target));
    }

    #[test]
    fn tool_rule_upsert() {
        let mut manifest = empty_manifest();
        let node = build_tool_rule("WebSearch", MatchVerdict::Deny);
        let result = upsert_rule(&mut manifest, node);
        assert_eq!(result, UpsertResult::Inserted);

        // Replace with allow.
        let node2 = build_tool_rule("WebSearch", MatchVerdict::Allow(None));
        let result2 = upsert_rule(&mut manifest, node2);
        assert_eq!(result2, UpsertResult::Replaced);

        let leaf = leaf_decision(&manifest.policy.tree[0]);
        assert!(matches!(leaf, Some(MatchVerdict::Allow(None))));
    }

    #[test]
    fn exec_rule_with_args() {
        let mut manifest = empty_manifest();
        let node = build_exec_rule("gh", &["pr", "create"], MatchVerdict::Allow(None));
        upsert_rule(&mut manifest, node);

        // Should produce: Bash → gh → pr → create → allow
        let total = count_leaf_decisions(&manifest.policy.tree);
        assert_eq!(total, 1);

        // Same chain with different decision replaces it.
        let deny = build_exec_rule("gh", &["pr", "create"], MatchVerdict::Deny);
        let result = upsert_rule(&mut manifest, deny);
        assert_eq!(result, UpsertResult::Replaced);
        let leaf = leaf_decision(&manifest.policy.tree[0]);
        assert!(matches!(leaf, Some(MatchVerdict::Deny)));
    }

    #[test]
    fn exec_rule_different_args_are_separate() {
        let mut manifest = empty_manifest();
        upsert_rule(
            &mut manifest,
            build_exec_rule("gh", &["pr", "create"], MatchVerdict::Allow(None)),
        );
        upsert_rule(
            &mut manifest,
            build_exec_rule("gh", &["pr", "merge"], MatchVerdict::Deny),
        );
        let total = count_leaf_decisions(&manifest.policy.tree);
        assert_eq!(total, 2);
    }

    /// Count the total number of Decision leaves in a tree.
    fn count_leaf_decisions(nodes: &[Node]) -> usize {
        nodes
            .iter()
            .map(|n| match n {
                Node::Decision(_) => 1,
                Node::Condition { children, .. } => count_leaf_decisions(children),
            })
            .sum()
    }
}
