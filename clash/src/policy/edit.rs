//! AST-based editing for policy files.
//!
//! Parses the source → mutates the AST → serializes back via `Display`.
//! Comments are lost on edit, but the policy stays valid (round-trip proven
//! by the `round_trip_parse_display_parse` test in `parse`).

use anyhow::{Result, bail};

use crate::policy::ast::{PolicyItem, Rule, TopLevel};
use crate::policy::parse;

/// Add a rule to the named policy block. Returns modified source.
///
/// Idempotent: if an identical rule already exists (compared via Display), the
/// source is returned unchanged.
pub fn add_rule(source: &str, policy_name: &str, rule: &Rule) -> Result<String> {
    let mut top_levels = parse::parse(source)?;
    let body = find_policy_mut(&mut top_levels, policy_name)?;

    let rule_str = rule.to_string();
    if body.iter().any(|item| match item {
        PolicyItem::Rule(r) => r.to_string() == rule_str,
        _ => false,
    }) {
        return Ok(source.to_string());
    }

    body.push(PolicyItem::Rule(rule.clone()));
    Ok(serialize_top_levels(&top_levels))
}

/// Remove a rule matching the given Display text. Returns modified source.
pub fn remove_rule(source: &str, policy_name: &str, rule_text: &str) -> Result<String> {
    let mut top_levels = parse::parse(source)?;
    let body = find_policy_mut(&mut top_levels, policy_name)?;

    let before = body.len();
    body.retain(|item| match item {
        PolicyItem::Rule(r) => r.to_string() != rule_text,
        _ => true,
    });

    if body.len() == before {
        bail!("rule not found: {}", rule_text);
    }

    Ok(serialize_top_levels(&top_levels))
}

/// Return the active policy name from the `(default ...)` declaration.
pub fn active_policy(source: &str) -> Result<String> {
    let top_levels = parse::parse(source)?;
    for tl in &top_levels {
        if let TopLevel::Default { policy, .. } = tl {
            return Ok(policy.clone());
        }
    }
    bail!("no (default ...) declaration found in policy")
}

/// Serialize `Vec<TopLevel>` back to source text.
fn serialize_top_levels(items: &[TopLevel]) -> String {
    items
        .iter()
        .map(|tl| tl.to_string())
        .collect::<Vec<_>>()
        .join("\n\n")
        + "\n"
}

/// Find a mutable reference to the body of the named policy.
fn find_policy_mut<'a>(items: &'a mut [TopLevel], name: &str) -> Result<&'a mut Vec<PolicyItem>> {
    for item in items.iter_mut() {
        if let TopLevel::Policy { name: pname, body } = item
            && pname == name
        {
            return Ok(body);
        }
    }
    bail!("policy not found: {}", name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Effect;
    use crate::policy::ast::*;

    fn default_policy() -> &'static str {
        crate::settings::DEFAULT_POLICY
    }

    fn exec_any_rule(effect: Effect) -> Rule {
        Rule {
            effect,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Any,
                args: vec![],
                has_args: vec![],
            }),
            sandbox: None,
        }
    }

    fn git_push_deny() -> Rule {
        Rule {
            effect: Effect::Deny,
            matcher: CapMatcher::Exec(ExecMatcher {
                bin: Pattern::Literal("git".into()),
                args: vec![Pattern::Literal("push".into()), Pattern::Any],
                has_args: vec![],
            }),
            sandbox: None,
        }
    }

    #[test]
    fn active_policy_from_default() {
        let name = active_policy(default_policy()).unwrap();
        assert_eq!(name, "main");
    }

    #[test]
    fn add_rule_to_default_policy() {
        let rule = exec_any_rule(Effect::Allow);
        let result = add_rule(default_policy(), "main", &rule).unwrap();
        assert!(
            result.contains("(allow (exec))"),
            "expected exec rule in output:\n{result}"
        );
        // Should still parse cleanly
        let ast = parse::parse(&result).unwrap();
        assert!(ast.len() >= 2);
    }

    #[test]
    fn add_rule_idempotent() {
        let rule = exec_any_rule(Effect::Allow);
        let first = add_rule(default_policy(), "main", &rule).unwrap();
        let second = add_rule(&first, "main", &rule).unwrap();
        assert_eq!(first, second, "adding same rule twice should be idempotent");
    }

    #[test]
    fn remove_rule_works() {
        let rule = git_push_deny();
        let added = add_rule(default_policy(), "main", &rule).unwrap();
        let rule_text = rule.to_string();
        let removed = remove_rule(&added, "main", &rule_text).unwrap();
        assert!(
            !removed.contains("git"),
            "rule should be removed:\n{removed}"
        );
    }

    #[test]
    fn remove_rule_not_found() {
        let err = remove_rule(default_policy(), "main", "(deny (exec))").unwrap_err();
        assert!(err.to_string().contains("rule not found"));
    }

    #[test]
    fn round_trip_preserves_validity() {
        let rule = git_push_deny();
        let modified = add_rule(default_policy(), "main", &rule).unwrap();
        // Re-parse and re-serialize should produce identical output
        let ast = parse::parse(&modified).unwrap();
        let reserialized = serialize_top_levels(&ast);
        let ast2 = parse::parse(&reserialized).unwrap();
        assert_eq!(ast, ast2);
    }

    #[test]
    fn add_rule_policy_not_found() {
        let rule = exec_any_rule(Effect::Allow);
        let err = add_rule(default_policy(), "nonexistent", &rule).unwrap_err();
        assert!(err.to_string().contains("policy not found"));
    }
}
