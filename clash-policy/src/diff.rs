//! Tree diff utility for policy changes.
//!
//! Compiles before/after policies, renders with `format_tree()`, and produces
//! a unified diff suitable for terminal display (with optional colors).

use similar::{ChangeTag, TextDiff};

use console::Style;

use crate::format::format_tree;
use crate::match_tree::CompiledPolicy;

/// Produce a unified diff between two compiled policies, rendered as tree strings.
///
/// Returns `None` if the two policies produce identical tree output.
pub fn tree_diff(before: &CompiledPolicy, after: &CompiledPolicy) -> Option<String> {
    let before_lines = format_tree(before);
    let after_lines = format_tree(after);

    let before_text = before_lines.join("\n");
    let after_text = after_lines.join("\n");

    if before_text == after_text {
        return None;
    }

    let diff = TextDiff::from_lines(&before_text, &after_text);
    let mut output = String::new();

    for change in diff.iter_all_changes() {
        let line = change.value().trim_end_matches('\n');
        match change.tag() {
            ChangeTag::Delete => {
                output.push_str(
                    &Style::new()
                        .red()
                        .apply_to(format!("- {line}"))
                        .to_string(),
                );
                output.push('\n');
            }
            ChangeTag::Insert => {
                output.push_str(
                    &Style::new()
                        .green()
                        .apply_to(format!("+ {line}"))
                        .to_string(),
                );
                output.push('\n');
            }
            ChangeTag::Equal => {
                output.push_str(&format!("  {line}"));
                output.push('\n');
            }
        }
    }

    Some(output)
}

/// Produce a plain (uncolored) unified diff between two compiled policies.
///
/// Useful for testing and non-TTY environments.
pub fn tree_diff_plain(before: &CompiledPolicy, after: &CompiledPolicy) -> Option<String> {
    let before_lines = format_tree(before);
    let after_lines = format_tree(after);

    let before_text = before_lines.join("\n");
    let after_text = after_lines.join("\n");

    if before_text == after_text {
        return None;
    }

    let diff = TextDiff::from_lines(&before_text, &after_text);
    let mut output = String::new();

    for change in diff.iter_all_changes() {
        let line = change.value().trim_end_matches('\n');
        match change.tag() {
            ChangeTag::Delete => {
                output.push_str(&format!("- {line}\n"));
            }
            ChangeTag::Insert => {
                output.push_str(&format!("+ {line}\n"));
            }
            ChangeTag::Equal => {
                output.push_str(&format!("  {line}\n"));
            }
        }
    }

    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_tree::*;
    use std::collections::HashMap;

    fn empty_policy() -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![],
            default_effect: crate::Effect::Deny,
            default_sandbox: None,
            on_sandbox_violation: Default::default(),
            harness_defaults: None,
        }
    }

    fn policy_with_rule(bin: &str, decision: Decision) -> CompiledPolicy {
        let node = Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::PositionalArg(0),
                pattern: Pattern::Literal(Value::Literal(bin.into())),
                children: vec![Node::Decision(decision)],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        };
        CompiledPolicy {
            tree: vec![node],
            ..empty_policy()
        }
    }

    #[test]
    fn identical_policies_produce_no_diff() {
        let p = policy_with_rule("git", Decision::Allow(None));
        assert!(tree_diff_plain(&p, &p).is_none());
    }

    #[test]
    fn added_rule_shows_in_diff() {
        let before = empty_policy();
        let after = policy_with_rule("git", Decision::Allow(None));
        let diff = tree_diff_plain(&before, &after).unwrap();
        assert!(diff.contains("+ "), "expected additions in diff:\n{diff}");
        assert!(diff.contains("git"), "expected 'git' in diff:\n{diff}");
    }

    #[test]
    fn removed_rule_shows_in_diff() {
        let before = policy_with_rule("git", Decision::Allow(None));
        let after = empty_policy();
        let diff = tree_diff_plain(&before, &after).unwrap();
        assert!(diff.contains("- "), "expected deletions in diff:\n{diff}");
    }

    #[test]
    fn changed_decision_shows_in_diff() {
        let before = policy_with_rule("git", Decision::Allow(None));
        let after = policy_with_rule("git", Decision::Deny);
        let diff = tree_diff_plain(&before, &after).unwrap();
        assert!(diff.contains("- "), "expected deletions:\n{diff}");
        assert!(diff.contains("+ "), "expected additions:\n{diff}");
    }
}
