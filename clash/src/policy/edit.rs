//! AST-based editing for policy files.
//!
//! Parses the source → mutates the AST → serializes back via `Display`.
//! Comments are lost on edit, but the policy stays valid (round-trip proven
//! by the `round_trip_parse_display_parse` test in `parse`).

use anyhow::{Result, bail};

use crate::policy::Effect;
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

/// Ensure a `(policy "name" ...)` block exists. If not, insert it (parsed from
/// `body_source`) before the active policy so it's defined before any reference.
/// Returns the (possibly modified) source. Idempotent.
pub fn ensure_policy_block(source: &str, name: &str, body_source: &str) -> Result<String> {
    let mut top_levels = parse::parse(source)?;

    // Already exists? No-op.
    if top_levels
        .iter()
        .any(|tl| matches!(tl, TopLevel::Policy { name: n, .. } if n == name))
    {
        return Ok(source.to_string());
    }

    // Parse the new block.
    let new_block = parse::parse(body_source)?;
    let block = new_block
        .into_iter()
        .find(|tl| matches!(tl, TopLevel::Policy { .. }))
        .ok_or_else(|| anyhow::anyhow!("body_source must contain a (policy ...) block"))?;

    // Insert before the active policy block so the sandbox is defined first.
    let active = active_policy(source).unwrap_or_else(|_| "main".into());
    let pos = top_levels
        .iter()
        .position(|tl| matches!(tl, TopLevel::Policy { name: n, .. } if *n == active))
        .unwrap_or(top_levels.len());
    top_levels.insert(pos, block);

    Ok(serialize_top_levels(&top_levels))
}

/// Update the default declaration's effect and/or policy name. Returns modified source.
///
/// If no `(default ...)` exists, prepends one.
pub fn set_default(source: &str, effect: Effect, policy: &str) -> Result<String> {
    let mut top_levels = parse::parse(source)?;
    let mut found = false;
    for tl in &mut top_levels {
        if let TopLevel::Default {
            effect: e,
            policy: p,
        } = tl
        {
            *e = effect;
            *p = policy.to_string();
            found = true;
            break;
        }
    }
    if !found {
        top_levels.insert(
            0,
            TopLevel::Default {
                effect,
                policy: policy.to_string(),
            },
        );
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

/// Find a rule in the named policy that has the same capability matcher
/// as `rule` but differs in effect or sandbox. Returns the Display text of
/// the conflicting rule, or `None` if no conflict exists.
pub fn find_conflicting_rule(
    source: &str,
    policy_name: &str,
    rule: &Rule,
) -> Result<Option<String>> {
    let top_levels = parse::parse(source)?;
    for tl in &top_levels {
        if let TopLevel::Policy { name, body } = tl
            && name == policy_name
        {
            for item in body {
                if let PolicyItem::Rule(existing) = item
                    && existing.matcher == rule.matcher
                    && (existing.effect != rule.effect || existing.sandbox != rule.sandbox)
                {
                    return Ok(Some(existing.to_string()));
                }
            }
        }
    }
    Ok(None)
}

/// Normalize source by parsing and re-serializing. Strips comments and applies
/// canonical formatting so that subsequent edits diff cleanly against the baseline.
pub fn normalize(source: &str) -> Result<String> {
    let top_levels = parse::parse(source)?;
    Ok(serialize_top_levels(&top_levels))
}

/// Serialize `Vec<TopLevel>` back to source text.
///
/// Also available as `serialize_ast` for external callers.
pub fn serialize_ast(items: &[TopLevel]) -> String {
    serialize_top_levels(items)
}

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
    fn set_default_changes_effect() {
        let result = set_default(default_policy(), Effect::Allow, "main").unwrap();
        assert!(result.contains("(default allow \"main\")"));
    }

    #[test]
    fn set_default_changes_policy_name() {
        let result = set_default(default_policy(), Effect::Deny, "sandbox").unwrap();
        assert!(result.contains("(default deny \"sandbox\")"));
    }

    #[test]
    fn set_default_prepends_when_missing() {
        let source = "(policy \"main\")\n";
        let result = set_default(source, Effect::Ask, "main").unwrap();
        assert!(result.starts_with("(default ask \"main\")"));
    }

    #[test]
    fn add_rule_policy_not_found() {
        let rule = exec_any_rule(Effect::Allow);
        let err = add_rule(default_policy(), "nonexistent", &rule).unwrap_err();
        assert!(err.to_string().contains("policy not found"));
    }
}
