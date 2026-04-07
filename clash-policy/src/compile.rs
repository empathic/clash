//! Compiler: Starlark JSON → CompiledPolicy.
//!
//! Parses v5 match-tree JSON emitted by the Starlark evaluator,
//! merges internal policies, validates sandbox references, and
//! sorts by specificity.

use anyhow::{Result, bail};

use crate::match_tree::{CompiledPolicy, Node};

/// Environment variable resolver used during compilation to expand `(env NAME)`.
pub trait EnvResolver {
    fn resolve(&self, name: &str) -> Result<String>;
}

/// Default resolver that reads from `std::env`.
pub struct StdEnvResolver;

/// Sentinel path for session variables not available outside a hook context.
pub const UNAVAILABLE_SESSION_PATH: &str = "/dev/null/.clash-no-session";

/// Session-level variables with safe defaults for when no hook context exists.
const SESSION_VAR_DEFAULTS: &[(&str, &str)] = &[("TRANSCRIPT_DIR", UNAVAILABLE_SESSION_PATH)];

impl EnvResolver for StdEnvResolver {
    fn resolve(&self, name: &str) -> Result<String> {
        match std::env::var(name) {
            Ok(val) => Ok(val),
            Err(_) => {
                for &(var, default) in SESSION_VAR_DEFAULTS {
                    if name == var {
                        return Ok(default.to_string());
                    }
                }
                anyhow::bail!("environment variable not set: {name}")
            }
        }
    }
}

/// Compile a JSON policy source string into a `CompiledPolicy`.
pub fn compile_to_tree(source: &str) -> Result<CompiledPolicy> {
    compile_policy(source)
}

/// Compile multiple policy levels with internals, returning a merged `CompiledPolicy`.
///
/// Merges all levels into a single policy: higher-precedence rules come first
/// so they match before lower-precedence ones (first-match semantics).
///
/// Each tuple is `(level, json_source, source_path)` where `source_path` is the
/// display path of the file the policy was loaded from (e.g. `~/.config/clash/policy.star`).
pub fn compile_multi_level_to_tree(
    levels: &[(crate::PolicyLevel, &str, &str)],
) -> Result<CompiledPolicy> {
    if levels.is_empty() {
        bail!("no policy levels to compile");
    }

    if levels.len() == 1 {
        return compile_policy_with_source(levels[0].1, levels[0].2);
    }

    // Sort by precedence (highest first) for first-match semantics.
    let mut sorted: Vec<(crate::PolicyLevel, &str, &str)> = levels.to_vec();
    sorted.sort_by(|a, b| b.0.cmp(&a.0));

    // Start with an empty merged policy using the default from the highest level.
    let first: CompiledPolicy = serde_json::from_str(sorted[0].1)
        .map_err(|e| anyhow::anyhow!("{} policy: invalid JSON: {}", sorted[0].0.name(), e))?;
    let mut merged = CompiledPolicy {
        sandboxes: first.sandboxes,
        default_sandbox: first.default_sandbox,
        on_sandbox_violation: first.on_sandbox_violation,
        tree: first.tree,
        default_effect: first.default_effect,
        harness_defaults: first.harness_defaults,
    };

    // Annotate root-level nodes from the first level with source provenance.
    let first_source = sorted[0].2;
    for node in &mut merged.tree {
        node.stamp_source(first_source);
    }

    // Append rules from lower-precedence levels.
    for (level, src, path) in &sorted[1..] {
        let mut policy: CompiledPolicy = serde_json::from_str(src)
            .map_err(|e| anyhow::anyhow!("{} policy: invalid JSON: {}", level.name(), e))?;
        for node in &mut policy.tree {
            node.stamp_source(path);
        }
        merged.tree.extend(policy.tree);
        for (k, v) in policy.sandboxes {
            merged.sandboxes.entry(k).or_insert(v);
        }
        // If any level explicitly disables harness defaults, honor it.
        if policy.harness_defaults == Some(false) {
            merged.harness_defaults = Some(false);
        }
    }

    let errors = merged.validate();
    if !errors.is_empty() {
        bail!("match tree validation errors: {}", errors.join("; "));
    }

    merged.tree = Node::compact(merged.tree);

    Ok(merged)
}

/// Compile a single policy source.
fn compile_policy(source: &str) -> Result<CompiledPolicy> {
    compile_policy_with_source(source, "")
}

/// Compile a single policy source, annotating root nodes with the given source path.
fn compile_policy_with_source(source: &str, source_path: &str) -> Result<CompiledPolicy> {
    let mut policy: CompiledPolicy = serde_json::from_str(source)
        .map_err(|e| anyhow::anyhow!("invalid match tree policy JSON: {e}"))?;

    if !source_path.is_empty() {
        for node in &mut policy.tree {
            node.stamp_source(source_path);
        }
    }

    let errors = policy.validate();
    if !errors.is_empty() {
        bail!("match tree validation errors: {}", errors.join("; "));
    }

    policy.tree = Node::compact(policy.tree);

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_basic_policy() {
        let source = r#"{
            "schema_version": 5,
            "default_effect": "deny",
            "sandboxes": {},
            "tree": [{
                "condition": {
                    "observe": "tool_name",
                    "pattern": {"literal": {"literal": "Bash"}},
                    "children": [{"decision": {"allow": null}}]
                }
            }]
        }"#;
        let policy = compile_to_tree(source).unwrap();
        assert_eq!(policy.tree.len(), 1);
        assert_eq!(policy.default_effect, crate::Effect::Deny);
    }

    #[test]
    fn compile_with_internals() {
        let source = r#"{
            "schema_version": 5,
            "default_effect": "deny",
            "sandboxes": {},
            "tree": [{
                "condition": {
                    "observe": "tool_name",
                    "pattern": {"literal": {"literal": "Bash"}},
                    "children": [{"decision": {"allow": null}}]
                }
            }]
        }"#;
        // With no internals, should just compile the source.
        let policy = compile_policy(source).unwrap();
        assert_eq!(policy.tree.len(), 1);
    }

    #[test]
    fn compile_valid_sandbox_reference() {
        let source = r#"{
            "schema_version": 5,
            "default_effect": "deny",
            "sandboxes": {
                "dev": {
                    "default": ["read", "execute"],
                    "network": "deny"
                }
            },
            "tree": [{
                "condition": {
                    "observe": "tool_name",
                    "pattern": {"literal": {"literal": "Bash"}},
                    "children": [{"decision": {"allow": "dev"}}]
                }
            }]
        }"#;
        let policy = compile_to_tree(source);
        assert!(policy.is_ok(), "valid sandbox reference should compile");
        let policy = policy.unwrap();
        assert!(policy.sandboxes.contains_key("dev"));
    }

    #[test]
    fn compile_undefined_sandbox_reference_fails() {
        let source = r#"{
            "schema_version": 5,
            "default_effect": "deny",
            "sandboxes": {},
            "tree": [{
                "condition": {
                    "observe": "tool_name",
                    "pattern": {"literal": {"literal": "Bash"}},
                    "children": [{"decision": {"allow": "nonexistent"}}]
                }
            }]
        }"#;
        let result = compile_to_tree(source);
        assert!(result.is_err(), "undefined sandbox reference should fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent"),
            "error should mention the undefined sandbox name, got: {err}"
        );
    }

    #[test]
    fn multi_level_merge_respects_harness_defaults_from_any_level() {
        // User policy (lowest precedence) disables harness defaults.
        let user = r#"{
            "schema_version": 5, "default_effect": "ask",
            "sandboxes": {}, "tree": [],
            "harness_defaults": false
        }"#;
        // Project policy (higher precedence) does not set harness_defaults.
        let project = r#"{
            "schema_version": 5, "default_effect": "deny",
            "sandboxes": {}, "tree": []
        }"#;
        let levels = vec![
            (crate::PolicyLevel::User, user, "user"),
            (crate::PolicyLevel::Project, project, "project"),
        ];
        let merged = compile_multi_level_to_tree(&levels).unwrap();
        assert_eq!(
            merged.harness_defaults,
            Some(false),
            "harness_defaults=false from any level should be honored"
        );
    }
}
