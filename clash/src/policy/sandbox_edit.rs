//! CRUD operations on sandbox definitions within a [`PolicyManifest`].
//!
//! Provides `create_sandbox`, `delete_sandbox`, `add_rule`, and `remove_rule`
//! for CLI-driven sandbox mutation.

use anyhow::{Result, bail};

use crate::policy::match_tree::PolicyManifest;
use crate::policy::sandbox_types::{
    Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy, SandboxRule,
};

/// Result of an add-rule operation.
#[derive(Debug, PartialEq, Eq)]
pub enum UpsertResult {
    /// A new rule was added.
    Inserted,
    /// An existing rule with the same path was replaced.
    Replaced,
}

/// Create a new named sandbox in the manifest.
///
/// Returns an error if a sandbox with that name already exists.
pub fn create_sandbox(
    manifest: &mut PolicyManifest,
    name: &str,
    default: Cap,
    network: NetworkPolicy,
    doc: Option<String>,
) -> Result<()> {
    if manifest.policy.sandboxes.contains_key(name) {
        bail!("sandbox '{name}' already exists");
    }
    manifest.policy.sandboxes.insert(
        name.to_string(),
        SandboxPolicy {
            default,
            rules: vec![],
            network,
            doc,
        },
    );
    Ok(())
}

/// Delete a named sandbox from the manifest.
///
/// Returns an error if the sandbox does not exist.
pub fn delete_sandbox(manifest: &mut PolicyManifest, name: &str) -> Result<()> {
    if manifest.policy.sandboxes.remove(name).is_none() {
        bail!(
            "sandbox '{name}' not found (available: {:?})",
            manifest.policy.sandboxes.keys().collect::<Vec<_>>()
        );
    }
    Ok(())
}

/// Add or replace a filesystem rule in a named sandbox.
///
/// If a rule with the same path already exists, it is replaced.
pub fn add_rule(
    manifest: &mut PolicyManifest,
    sandbox_name: &str,
    effect: RuleEffect,
    caps: Cap,
    path: String,
    path_match: PathMatch,
    doc: Option<String>,
) -> Result<UpsertResult> {
    let sandbox = manifest
        .policy
        .sandboxes
        .get_mut(sandbox_name)
        .ok_or_else(|| anyhow::anyhow!("sandbox '{sandbox_name}' not found"))?;

    if let Some(existing) = sandbox.rules.iter_mut().find(|r| r.path == path) {
        existing.effect = effect;
        existing.caps = caps;
        existing.path_match = path_match;
        existing.doc = doc;
        Ok(UpsertResult::Replaced)
    } else {
        sandbox.rules.push(SandboxRule {
            effect,
            caps,
            path,
            path_match,
            follow_worktrees: false,
            doc,
        });
        Ok(UpsertResult::Inserted)
    }
}

/// Remove a rule matching the given path from a named sandbox.
///
/// Returns `true` if a rule was removed.
pub fn remove_rule(manifest: &mut PolicyManifest, sandbox_name: &str, path: &str) -> Result<bool> {
    let sandbox = manifest
        .policy
        .sandboxes
        .get_mut(sandbox_name)
        .ok_or_else(|| anyhow::anyhow!("sandbox '{sandbox_name}' not found"))?;

    let before = sandbox.rules.len();
    sandbox.rules.retain(|r| r.path != path);
    Ok(sandbox.rules.len() < before)
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
                on_sandbox_violation: Default::default(),
            },
        }
    }

    #[test]
    fn create_inserts_new_sandbox() {
        let mut m = empty_manifest();
        create_sandbox(
            &mut m,
            "dev",
            Cap::READ | Cap::EXECUTE,
            NetworkPolicy::Deny,
            None,
        )
        .unwrap();
        assert!(m.policy.sandboxes.contains_key("dev"));
        let sb = &m.policy.sandboxes["dev"];
        assert_eq!(sb.default, Cap::READ | Cap::EXECUTE);
        assert_eq!(sb.network, NetworkPolicy::Deny);
        assert!(sb.rules.is_empty());
    }

    #[test]
    fn create_errors_on_duplicate() {
        let mut m = empty_manifest();
        create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Deny, None).unwrap();
        let err = create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Allow, None);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn delete_removes_sandbox() {
        let mut m = empty_manifest();
        create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Deny, None).unwrap();
        delete_sandbox(&mut m, "dev").unwrap();
        assert!(!m.policy.sandboxes.contains_key("dev"));
    }

    #[test]
    fn delete_errors_on_missing() {
        let mut m = empty_manifest();
        let err = delete_sandbox(&mut m, "nope");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn add_rule_inserts() {
        let mut m = empty_manifest();
        create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Deny, None).unwrap();
        let result = add_rule(
            &mut m,
            "dev",
            RuleEffect::Allow,
            Cap::READ | Cap::WRITE,
            "$PWD".into(),
            PathMatch::Subpath,
            None,
        )
        .unwrap();
        assert_eq!(result, UpsertResult::Inserted);
        assert_eq!(m.policy.sandboxes["dev"].rules.len(), 1);
    }

    #[test]
    fn add_rule_replaces_same_path() {
        let mut m = empty_manifest();
        create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Deny, None).unwrap();
        add_rule(
            &mut m,
            "dev",
            RuleEffect::Allow,
            Cap::READ,
            "$PWD".into(),
            PathMatch::Subpath,
            None,
        )
        .unwrap();
        let result = add_rule(
            &mut m,
            "dev",
            RuleEffect::Deny,
            Cap::WRITE,
            "$PWD".into(),
            PathMatch::Subpath,
            None,
        )
        .unwrap();
        assert_eq!(result, UpsertResult::Replaced);
        assert_eq!(m.policy.sandboxes["dev"].rules.len(), 1);
        assert_eq!(m.policy.sandboxes["dev"].rules[0].effect, RuleEffect::Deny);
        assert_eq!(m.policy.sandboxes["dev"].rules[0].caps, Cap::WRITE);
    }

    #[test]
    fn add_rule_errors_on_missing_sandbox() {
        let mut m = empty_manifest();
        let err = add_rule(
            &mut m,
            "nope",
            RuleEffect::Allow,
            Cap::READ,
            "$PWD".into(),
            PathMatch::Subpath,
            None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn remove_rule_by_path() {
        let mut m = empty_manifest();
        create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Deny, None).unwrap();
        add_rule(
            &mut m,
            "dev",
            RuleEffect::Allow,
            Cap::READ,
            "$PWD".into(),
            PathMatch::Subpath,
            None,
        )
        .unwrap();
        assert!(remove_rule(&mut m, "dev", "$PWD").unwrap());
        assert!(m.policy.sandboxes["dev"].rules.is_empty());
    }

    #[test]
    fn remove_rule_returns_false_when_no_match() {
        let mut m = empty_manifest();
        create_sandbox(&mut m, "dev", Cap::READ, NetworkPolicy::Deny, None).unwrap();
        assert!(!remove_rule(&mut m, "dev", "/nonexistent").unwrap());
    }
}
