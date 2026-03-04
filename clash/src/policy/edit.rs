//! Struct-based editing for policy documents.
//!
//! All operations mutate a `PolicyDocument` in place. No parsing or
//! serialization happens here — callers are responsible for loading and
//! saving the document (typically via `serde_json`).

use anyhow::{Result, bail};

use crate::policy::Effect;
use crate::policy::ast::{PolicyDocument, PolicyDef, PolicyItem, Rule};

/// Add a rule to the named policy block in a document.
///
/// Idempotent: if an identical rule already exists (compared via JSON
/// serialization), no change is made.
pub fn add_rule(doc: &mut PolicyDocument, policy_name: &str, rule: Rule) -> Result<()> {
    let body = find_policy_mut(doc, policy_name)?;
    let rule_json = serde_json::to_string(&rule).unwrap_or_default();
    if body.iter().any(|item| match item {
        PolicyItem::Rule(r) => serde_json::to_string(r).unwrap_or_default() == rule_json,
        _ => false,
    }) {
        return Ok(());
    }
    body.push(PolicyItem::Rule(rule));
    Ok(())
}

/// Remove a rule at the given index from the named policy.
pub fn remove_rule(doc: &mut PolicyDocument, policy_name: &str, index: usize) -> Result<()> {
    let body = find_policy_mut(doc, policy_name)?;
    if index >= body.len() {
        bail!(
            "rule index {index} out of range (policy has {} items)",
            body.len()
        );
    }
    body.remove(index);
    Ok(())
}

/// Remove a rule matching the given JSON text.
pub fn remove_rule_by_text(
    doc: &mut PolicyDocument,
    policy_name: &str,
    rule_text: &str,
) -> Result<()> {
    let body = find_policy_mut(doc, policy_name)?;
    let before = body.len();
    body.retain(|item| match item {
        PolicyItem::Rule(r) => serde_json::to_string(r).unwrap_or_default() != rule_text,
        _ => true,
    });
    if body.len() == before {
        bail!("rule not found: {rule_text}");
    }
    Ok(())
}

/// Set the default effect for the document.
pub fn set_default(doc: &mut PolicyDocument, effect: Effect) {
    doc.default_effect = Some(effect);
}

/// Return the active policy name.
///
/// Falls back to `"main"` when no explicit `use` declaration is present.
pub fn active_policy(doc: &PolicyDocument) -> &str {
    doc.use_policy.as_deref().unwrap_or("main")
}

/// Ensure a named policy block exists in the document.
///
/// If a policy with the given name already exists this is a no-op.
/// Otherwise a new empty `PolicyDef` is inserted before the active policy
/// so that it is defined before any reference.
pub fn ensure_policy_block(doc: &mut PolicyDocument, name: &str) {
    if doc.policies.iter().any(|p| p.name == name) {
        return;
    }
    let active = doc.use_policy.as_deref().unwrap_or("main");
    let pos = doc
        .policies
        .iter()
        .position(|p| p.name == active)
        .unwrap_or(doc.policies.len());
    doc.policies.insert(
        pos,
        PolicyDef {
            name: name.to_string(),
            body: vec![],
        },
    );
}

/// Find a rule in the named policy that has the same capability matcher
/// as `rule` but differs in effect or sandbox. Returns a clone of the
/// conflicting rule, or `None` if no conflict exists.
pub fn find_conflicting_rule(
    doc: &PolicyDocument,
    policy_name: &str,
    rule: &Rule,
) -> Option<Rule> {
    for def in &doc.policies {
        if def.name == policy_name {
            for item in &def.body {
                if let PolicyItem::Rule(existing) = item {
                    if existing.matcher == rule.matcher
                        && (existing.effect != rule.effect || existing.sandbox != rule.sandbox)
                    {
                        return Some(existing.clone());
                    }
                }
            }
        }
    }
    None
}

/// Find a mutable reference to the body of the named policy.
fn find_policy_mut<'a>(doc: &'a mut PolicyDocument, name: &str) -> Result<&'a mut Vec<PolicyItem>> {
    for def in &mut doc.policies {
        if def.name == name {
            return Ok(&mut def.body);
        }
    }
    bail!("policy not found: {name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ast::*;

    fn sample_doc() -> PolicyDocument {
        PolicyDocument {
            schema_version: 4,
            use_policy: Some("main".into()),
            default_effect: Some(Effect::Deny),
            policies: vec![PolicyDef {
                name: "main".into(),
                body: vec![PolicyItem::Rule(Rule {
                    effect: Effect::Allow,
                    matcher: CapMatcher::Fs(FsMatcher {
                        op: OpPattern::Single(FsOp::Read),
                        path: Some(PathFilter::Subpath {
                            path: PathExpr::Env("PWD".into()),
                            worktree: true,
                        }),
                    }),
                    sandbox: None,
                })],
            }],
        }
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
    fn active_policy_returns_use_field() {
        let doc = sample_doc();
        assert_eq!(active_policy(&doc), "main");
    }

    #[test]
    fn active_policy_defaults_to_main() {
        let doc = PolicyDocument {
            schema_version: 4,
            use_policy: None,
            default_effect: None,
            policies: vec![],
        };
        assert_eq!(active_policy(&doc), "main");
    }

    #[test]
    fn add_rule_appends() {
        let mut doc = sample_doc();
        let rule = exec_any_rule(Effect::Allow);
        add_rule(&mut doc, "main", rule.clone()).unwrap();
        assert_eq!(doc.policies[0].body.len(), 2);
        assert!(matches!(&doc.policies[0].body[1], PolicyItem::Rule(r) if *r == rule));
    }

    #[test]
    fn add_rule_idempotent() {
        let mut doc = sample_doc();
        let rule = exec_any_rule(Effect::Allow);
        add_rule(&mut doc, "main", rule.clone()).unwrap();
        let len_after_first = doc.policies[0].body.len();
        add_rule(&mut doc, "main", rule).unwrap();
        assert_eq!(doc.policies[0].body.len(), len_after_first);
    }

    #[test]
    fn add_rule_policy_not_found() {
        let mut doc = sample_doc();
        let err = add_rule(&mut doc, "nonexistent", exec_any_rule(Effect::Allow)).unwrap_err();
        assert!(err.to_string().contains("policy not found"));
    }

    #[test]
    fn remove_rule_by_index() {
        let mut doc = sample_doc();
        assert_eq!(doc.policies[0].body.len(), 1);
        remove_rule(&mut doc, "main", 0).unwrap();
        assert!(doc.policies[0].body.is_empty());
    }

    #[test]
    fn remove_rule_out_of_range() {
        let mut doc = sample_doc();
        let err = remove_rule(&mut doc, "main", 99).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn remove_rule_by_text_works() {
        let mut doc = sample_doc();
        let rule = git_push_deny();
        add_rule(&mut doc, "main", rule.clone()).unwrap();
        let rule_json = serde_json::to_string(&rule).unwrap();
        remove_rule_by_text(&mut doc, "main", &rule_json).unwrap();
        // Only the original fs rule should remain.
        assert_eq!(doc.policies[0].body.len(), 1);
    }

    #[test]
    fn remove_rule_by_text_not_found() {
        let mut doc = sample_doc();
        let err = remove_rule_by_text(&mut doc, "main", "bogus").unwrap_err();
        assert!(err.to_string().contains("rule not found"));
    }

    #[test]
    fn set_default_updates_effect() {
        let mut doc = sample_doc();
        assert_eq!(doc.default_effect, Some(Effect::Deny));
        set_default(&mut doc, Effect::Allow);
        assert_eq!(doc.default_effect, Some(Effect::Allow));
    }

    #[test]
    fn ensure_policy_block_creates_new() {
        let mut doc = sample_doc();
        assert_eq!(doc.policies.len(), 1);
        ensure_policy_block(&mut doc, "sandbox");
        assert_eq!(doc.policies.len(), 2);
        // Inserted before "main" (the active policy).
        assert_eq!(doc.policies[0].name, "sandbox");
        assert_eq!(doc.policies[1].name, "main");
    }

    #[test]
    fn ensure_policy_block_idempotent() {
        let mut doc = sample_doc();
        ensure_policy_block(&mut doc, "main");
        assert_eq!(doc.policies.len(), 1);
    }

    #[test]
    fn find_conflicting_rule_detects_conflict() {
        let mut doc = sample_doc();
        let allow = exec_any_rule(Effect::Allow);
        add_rule(&mut doc, "main", allow.clone()).unwrap();
        let deny = exec_any_rule(Effect::Deny);
        let conflict = find_conflicting_rule(&doc, "main", &deny);
        assert!(conflict.is_some());
        assert_eq!(conflict.unwrap().effect, Effect::Allow);
    }

    #[test]
    fn find_conflicting_rule_none_when_no_conflict() {
        let doc = sample_doc();
        let rule = exec_any_rule(Effect::Allow);
        assert!(find_conflicting_rule(&doc, "main", &rule).is_none());
    }
}
