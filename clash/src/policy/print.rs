//! Human-readable decision tree printer for `clash policy show`.

use std::fmt;

use super::decision_tree::CompiledRule;
use super::tree::{Node, PolicyTree};

/// Format a policy tree as a human-readable summary.
pub fn print_tree(tree: &PolicyTree) -> String {
    let mut out = String::new();
    out.push_str(&format!("Policy: {}\n", tree.policy_name));
    out.push_str(&format!("Default: {}\n", tree.default));

    if tree.version >= 2 {
        out.push_str("\nTree structure:\n");
        print_node(&mut out, &tree.root, tree, 2);
    } else {
        print_section(&mut out, "Exec rules", &tree.exec_rules);
        print_section(&mut out, "Filesystem rules", &tree.fs_rules);
        print_section(&mut out, "Network rules", &tree.net_rules);
        print_section(&mut out, "Tool rules", &tree.tool_rules);
    }

    out
}

/// Format just the tree structure (no policy name/default header).
pub fn print_tree_structure(tree: &PolicyTree) -> String {
    let mut out = String::new();
    print_node(&mut out, &tree.root, tree, 2);
    out
}

fn print_node(out: &mut String, node: &Node, tree: &PolicyTree, indent: usize) {
    let pad = " ".repeat(indent);
    let meta = &tree.node_meta[node.id() as usize];

    match node {
        Node::Sequence { children, .. } => {
            out.push_str(&format!("{pad}Sequence:\n"));
            for child in children {
                print_node(out, child, tree, indent + 2);
            }
        }
        Node::DenyOverrides { children, .. } => {
            out.push_str(&format!("{pad}DenyOverrides:\n"));
            for child in children {
                print_node(out, child, tree, indent + 2);
            }
        }
        Node::When { body, .. } => {
            let desc = if meta.description.is_empty() {
                "...".to_string()
            } else {
                meta.description.clone()
            };
            out.push_str(&format!("{pad}When {desc}:\n"));
            print_node(out, body, tree, indent + 2);
        }
        Node::Match {
            observable,
            arms,
            constraint_policy,
            ..
        } => {
            let constraint_tag = if constraint_policy.is_some() {
                " [constraint]"
            } else {
                ""
            };
            out.push_str(&format!("{pad}Match {observable:?}{constraint_tag}:\n"));
            for arm in arms {
                out.push_str(&format!("{pad}  {:?} =>\n", arm.pattern));
                print_node(out, &arm.body, tree, indent + 4);
            }
        }
        Node::Leaf { effect, .. } => {
            let builtin_tag = if meta
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            {
                " [builtin]"
            } else {
                ""
            };
            let desc = if meta.description.is_empty() {
                String::new()
            } else {
                format!(" {}", meta.description)
            };
            out.push_str(&format!("{pad}[{effect}]{desc}{builtin_tag}\n"));
        }
    }
}

fn print_section(out: &mut String, title: &str, rules: &[CompiledRule]) {
    if rules.is_empty() {
        return;
    }
    out.push_str(&format!(
        "\n{title} ({} rules, most specific first):\n",
        rules.len()
    ));
    for (i, rule) in rules.iter().enumerate() {
        let builtin_tag = if rule
            .origin_policy
            .as_ref()
            .is_some_and(|p| p.starts_with("__internal_"))
        {
            " [builtin]"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {}. [{}] {} (specificity: {:?}){}\n",
            i + 1,
            rule.effect,
            rule.source,
            rule.specificity,
            builtin_tag,
        ));
    }
}

impl fmt::Display for PolicyTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", print_tree(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::compile::{EnvResolver, compile_policy_with_env, compile_to_tree};
    use std::collections::HashMap;

    struct TestEnv(HashMap<String, String>);
    impl EnvResolver for TestEnv {
        fn resolve(&self, name: &str) -> anyhow::Result<String> {
            self.0
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not set"))
        }
    }

    #[test]
    fn print_tree_output() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *))
  (allow (net "github.com")))
"#;
        let env = TestEnv(HashMap::from([("PWD".into(), "/tmp".into())]));
        let dt = compile_policy_with_env(source, &env).unwrap();
        let tree = PolicyTree::from_decision_tree(dt);
        let output = print_tree(&tree);
        assert!(output.contains("Policy: main"));
        assert!(output.contains("Default: deny"));
        assert!(output.contains("Exec rules (2 rules"));
        assert!(output.contains("Network rules (1 rules"));
        assert!(!output.contains("Filesystem rules"));
    }

    #[test]
    fn print_builtin_annotation() {
        use crate::policy::compile::compile_policy_with_internals;

        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let internal = r#"
(policy "__internal_test__"
  (allow (fs read (subpath "/test"))))
"#;
        let env = TestEnv(HashMap::new());
        let dt =
            compile_policy_with_internals(user_source, &env, &[("__internal_test__", internal)])
                .unwrap();
        let tree = PolicyTree::from_decision_tree(dt);
        let output = print_tree(&tree);
        assert!(
            output.contains("[builtin]"),
            "expected [builtin] tag, got:\n{output}"
        );
        // User rules should NOT have [builtin].
        let exec_line = output.lines().find(|l| l.contains("exec")).unwrap();
        assert!(
            !exec_line.contains("[builtin]"),
            "user rule should not be [builtin]: {exec_line}"
        );
    }

    #[test]
    fn print_tree_v2_structure() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (command "cargo")
    (sandbox
      (match ctx.http.domain
        "crates.io" :allow
        * :deny))))
"#;
        let env = TestEnv(HashMap::from([("PWD".into(), "/tmp".into())]));
        let tree = compile_to_tree(source, &env).unwrap();
        let output = print_tree(&tree);
        assert!(
            output.contains("Tree structure:"),
            "expected 'Tree structure:', got:\n{output}"
        );
        assert!(
            output.contains("When"),
            "expected 'When' node, got:\n{output}"
        );
        // Should contain either Sandbox or Match depending on compilation
        assert!(
            output.contains("Sandbox") || output.contains("Match"),
            "expected 'Sandbox' or 'Match' node, got:\n{output}"
        );
        // Should NOT contain old flat section headers
        assert!(
            !output.contains("Exec rules"),
            "v2 output should not contain flat 'Exec rules' section, got:\n{output}"
        );
    }
}
