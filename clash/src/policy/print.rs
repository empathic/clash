//! Human-readable decision tree printer for `clash policy show`.

use std::fmt;

use super::decision_tree::{CompiledRule, DecisionTree};

/// Format a decision tree as a human-readable summary.
pub fn print_tree(tree: &DecisionTree) -> String {
    let mut out = String::new();
    out.push_str(&format!("Policy: {}\n", tree.policy_name));
    out.push_str(&format!("Default: {}\n", tree.default));

    print_section(&mut out, "Exec rules", &tree.exec_rules);
    print_section(&mut out, "Filesystem rules", &tree.fs_rules);
    print_section(&mut out, "Network rules", &tree.net_rules);

    out
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
        out.push_str(&format!(
            "  {}. [{}] {} (specificity: {:?})\n",
            i + 1,
            rule.effect,
            rule.source,
            rule.specificity,
        ));
    }
}

impl fmt::Display for DecisionTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", print_tree(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::compile::{EnvResolver, compile_policy_with_env};
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
        let tree = compile_policy_with_env(source, &env).unwrap();
        let output = print_tree(&tree);
        assert!(output.contains("Policy: main"));
        assert!(output.contains("Default: deny"));
        assert!(output.contains("Exec rules (2 rules"));
        assert!(output.contains("Network rules (1 rules"));
        assert!(!output.contains("Filesystem rules"));
    }
}
