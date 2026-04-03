//! Agent harness default permissions.
//!
//! Generates lowest-priority policy rules that allow agents to access their
//! own infrastructure directories (e.g., Claude → ~/.claude/). These rules
//! are appended after all user-defined policy levels so user rules always
//! take precedence.

use crate::agents::AgentKind;
use crate::policy::match_tree::{Decision, Node, Observable, Pattern, Value};
use crate::settings::is_harness_defaults_disabled;

/// Check whether harness defaults should be injected.
///
/// Disabled if:
/// 1. `CLASH_NO_HARNESS_DEFAULTS` env var is set (checked first)
/// 2. `harness_defaults` is explicitly `false` in the compiled policy settings
///
/// `policy_setting` is the `CompiledPolicy.harness_defaults` field.
pub fn is_harness_enabled(policy_setting: Option<bool>) -> bool {
    if is_harness_defaults_disabled() {
        return false;
    }
    policy_setting.unwrap_or(true)
}

/// Generate harness default rules for the given agent.
///
/// Returns an empty vec for agents without defined harness paths.
/// All returned nodes are stamped with `source: "harness"`.
pub fn harness_nodes(agent: AgentKind) -> Vec<Node> {
    let paths = match agent {
        AgentKind::Claude => claude_harness_paths(),
        _ => return Vec::new(),
    };

    let mut nodes = Vec::new();
    for (path, ops) in paths {
        for op in ops {
            let mut node = Node::Condition {
                observe: Observable::FsOp,
                pattern: Pattern::Literal(Value::Literal(op.to_string())),
                children: vec![Node::Condition {
                    observe: Observable::FsPath,
                    pattern: Pattern::Prefix(path.clone()),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            };
            node.stamp_source("harness");
            nodes.push(node);
        }
    }
    nodes
}

/// Claude Code harness paths: (path_value, allowed_ops).
fn claude_harness_paths() -> Vec<(Value, Vec<&'static str>)> {
    vec![
        // ~/.claude/ — memories, settings, plugin cache, skills
        (
            Value::Path(vec![
                Value::Env("HOME".to_string()),
                Value::Literal(".claude".to_string()),
            ]),
            vec!["read", "write"],
        ),
        // <project>/.claude/ — project config (read-only)
        (
            Value::Path(vec![
                Value::Env("PWD".to_string()),
                Value::Literal(".claude".to_string()),
            ]),
            vec!["read"],
        ),
        // <transcript_dir>/ — session transcripts, task output
        (
            Value::Env("TRANSCRIPT_DIR".to_string()),
            vec!["read", "write"],
        ),
    ]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn claude_harness_nodes_not_empty() {
        let nodes = harness_nodes(AgentKind::Claude);
        assert!(!nodes.is_empty(), "Claude should have harness rules");
    }

    #[test]
    fn claude_harness_nodes_stamped_as_harness() {
        let nodes = harness_nodes(AgentKind::Claude);
        for node in &nodes {
            if let Node::Condition { source, .. } = node {
                assert_eq!(source.as_deref(), Some("harness"));
            }
        }
    }

    #[test]
    fn unknown_agent_returns_empty() {
        let nodes = harness_nodes(AgentKind::Copilot);
        assert!(nodes.is_empty());
    }

    #[test]
    fn harness_enabled_checks_policy_setting() {
        // Cannot test env var in unit tests due to process-wide mutation,
        // but we can test the policy_setting path.
        assert!(is_harness_enabled(None));
        assert!(!is_harness_enabled(Some(false)));
        assert!(is_harness_enabled(Some(true)));
    }

    #[test]
    fn claude_harness_node_count() {
        let nodes = harness_nodes(AgentKind::Claude);
        // 3 paths: ~/.claude (read+write), <project>/.claude (read), $TRANSCRIPT_DIR (read+write)
        // = 2 + 1 + 2 = 5 nodes
        assert_eq!(nodes.len(), 5);
    }
}
