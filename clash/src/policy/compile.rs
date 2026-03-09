//! Compiler: Starlark JSON → CompiledPolicy.
//!
//! Parses v5 match-tree JSON emitted by the Starlark evaluator,
//! merges internal policies, validates sandbox references, and
//! sorts by specificity.

use anyhow::{Result, bail};

use crate::policy::match_tree::{CompiledPolicy, Node};

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
pub fn compile_multi_level_to_tree(
    levels: &[(crate::settings::PolicyLevel, &str)],
) -> Result<CompiledPolicy> {
    if levels.is_empty() {
        bail!("no policy levels to compile");
    }

    if levels.len() == 1 {
        return compile_policy(levels[0].1);
    }

    // Sort by precedence (highest first) for first-match semantics.
    let mut sorted: Vec<(crate::settings::PolicyLevel, &str)> = levels.to_vec();
    sorted.sort_by(|a, b| b.0.cmp(&a.0));

    // Start with an empty merged policy using the default from the highest level.
    let first: CompiledPolicy = serde_json::from_str(sorted[0].1)
        .map_err(|e| anyhow::anyhow!("{} policy: invalid JSON: {}", sorted[0].0.name(), e))?;
    let mut merged = CompiledPolicy {
        sandboxes: first.sandboxes,
        tree: first.tree,
        default_effect: first.default_effect,
    };

    // Append rules from lower-precedence levels.
    for (level, source) in &sorted[1..] {
        let policy: CompiledPolicy = serde_json::from_str(source)
            .map_err(|e| anyhow::anyhow!("{} policy: invalid JSON: {}", level.name(), e))?;
        merged.tree.extend(policy.tree);
        for (k, v) in policy.sandboxes {
            merged.sandboxes.entry(k).or_insert(v);
        }
    }

    let errors = merged.validate();
    if !errors.is_empty() {
        bail!("match tree validation errors: {}", errors.join("; "));
    }

    merged.tree = Node::compact(merged.tree);

    Ok(merged)
}

/// Compile a single policy source with optional internal policies.
fn compile_policy(source: &str) -> Result<CompiledPolicy> {
    let mut policy: CompiledPolicy = serde_json::from_str(source)
        .map_err(|e| anyhow::anyhow!("invalid match tree policy JSON: {e}"))?;

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
        assert_eq!(policy.default_effect, crate::policy::Effect::Deny);
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
}
