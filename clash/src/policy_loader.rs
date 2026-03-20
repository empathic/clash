//! Policy discovery, evaluation, and compilation.
//!
//! This module extracts the policy loading pipeline from [`crate::settings`]:
//!
//! 1. **Discovery** — finding `policy.json` / `policy.star` files at user/project/session levels
//! 2. **Validation** — checking file metadata (size, permissions, type)
//! 3. **Evaluation** — running Starlark `.star` files through `clash_starlark`,
//!    or parsing `.json` manifests (with optional `includes`)
//! 4. **Compilation** — compiling evaluated JSON sources into a [`CompiledPolicy`] tree

use std::path::Path;

use anyhow::{Context, Result};
use tracing::{error, warn};

#[cfg(test)]
use tracing::info;

use crate::policy::compile;
use crate::policy::match_tree::{CompiledPolicy, PolicyManifest};
use crate::settings::{LoadedPolicy, PolicyLevel};

/// Maximum policy file size (1 MiB).
pub const MAX_POLICY_SIZE: u64 = 1024 * 1024;

/// Outcome of attempting to load a single policy file.
///
/// On success, carries both the evaluated JSON source (needed for compilation)
/// and the [`LoadedPolicy`] metadata.
pub struct ValidatedPolicy {
    /// The evaluated JSON source text.
    pub json_source: String,
    /// The loaded policy metadata.
    pub loaded: LoadedPolicy,
}

/// Evaluate a `.star` policy file through the Starlark evaluator and return
/// the compiled JSON source text.
pub fn evaluate_star_policy(path: &Path) -> Result<String> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let base_dir = path.parent().unwrap_or(Path::new("."));

    let output = clash_starlark::evaluate(&source, &path.display().to_string(), base_dir)?;

    Ok(output.json)
}

/// Load a `policy.json` manifest: parse the JSON, resolve includes, and return
/// a merged JSON source string suitable for [`compile::compile_to_tree`].
pub fn load_json_policy(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let manifest: PolicyManifest = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    if manifest.includes.is_empty() {
        // No includes — the manifest JSON is the policy source directly.
        return Ok(raw);
    }

    // Merge: inline tree nodes come first (highest precedence), then includes in order.
    let base_dir = path.parent().unwrap_or(Path::new("."));
    merge_manifest_with_includes(&manifest, base_dir)
}

/// Merge a [`PolicyManifest`]'s inline policy with its `includes`.
///
/// Inline tree nodes come first (first-match wins), followed by included
/// policies in declaration order.
fn merge_manifest_with_includes(manifest: &PolicyManifest, base_dir: &Path) -> Result<String> {
    let mut merged = manifest.policy.clone();

    for include in &manifest.includes {
        let json_source = evaluate_include(&include.path, base_dir)?;
        let included: CompiledPolicy = serde_json::from_str(&json_source)
            .with_context(|| format!("failed to parse included policy {:?}", include.path))?;

        // Append included rules after inline rules (lower precedence).
        merged.tree.extend(included.tree);
        // Merge sandboxes (inline wins on conflict).
        for (k, v) in included.sandboxes {
            merged.sandboxes.entry(k).or_insert(v);
        }
    }

    serde_json::to_string(&merged).context("failed to serialize merged policy")
}

/// Evaluate an include entry and return the compiled JSON source.
///
/// For `.star` files (local or `@clash//` stdlib), evaluates through Starlark.
/// Local `.star` includes must define a `main()` function that returns a policy.
fn evaluate_include(include_path: &str, base_dir: &Path) -> Result<String> {
    if include_path.starts_with("@clash//") {
        // Stdlib includes are library modules — they export values, not main().
        // Wrap in a minimal Starlark policy that loads the export and returns it.
        evaluate_stdlib_include(include_path)
    } else {
        // Local .star file — must define main().
        let resolved = base_dir.join(include_path);
        evaluate_star_policy(&resolved)
    }
}

/// Evaluate a `@clash//` stdlib module by wrapping it in a Starlark policy.
///
/// The wrapper loads the module, imports its `base` export (the conventional
/// name for a reusable policy value), and returns it from `main()`.
fn evaluate_stdlib_include(include_path: &str) -> Result<String> {
    let wrapper = format!(
        "load(\"{include_path}\", \"base\")\n\
         def main():\n    return base\n"
    );
    let output = clash_starlark::evaluate(&wrapper, "<include>", Path::new("."))
        .with_context(|| format!("failed to evaluate stdlib include {include_path}"))?;
    Ok(output.json)
}

/// Read and parse a `policy.json` file into a [`PolicyManifest`].
///
/// This does NOT resolve includes — call [`load_json_policy`] for full loading.
pub fn read_manifest(path: &Path) -> Result<PolicyManifest> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

/// Resolve includes and return the combined included policy plus any warnings.
///
/// Evaluates each include entry and merges their rules and sandboxes.
/// Returns the merged included content (without the inline policy) and a list
/// of warnings for includes that failed to evaluate or parse.
/// Rules/sandboxes from includes should be treated as read-only in the TUI.
pub fn resolve_includes(
    manifest: &PolicyManifest,
    base_dir: &Path,
) -> Result<(CompiledPolicy, Vec<String>)> {
    use std::collections::HashMap;

    let mut merged = CompiledPolicy {
        sandboxes: HashMap::new(),
        tree: vec![],
        default_effect: manifest.policy.default_effect,
        default_sandbox: None,
    };

    let mut warnings = Vec::new();

    for include in &manifest.includes {
        match evaluate_include(&include.path, base_dir) {
            Ok(json_source) => match serde_json::from_str::<CompiledPolicy>(&json_source) {
                Ok(included) => {
                    for mut node in included.tree {
                        node.stamp_source(&include.path);
                        merged.tree.push(node);
                    }
                    for (k, v) in included.sandboxes {
                        merged.sandboxes.entry(k).or_insert(v);
                    }
                }
                Err(e) => {
                    warnings.push(format!("{}: parse error: {e}", include.path));
                }
            },
            Err(e) => {
                warnings.push(format!("{}: {e:#}", include.path));
            }
        }
    }

    if !warnings.is_empty() {
        tracing::warn!("include resolution warnings: {}", warnings.join("; "));
    }

    Ok((merged, warnings))
}

/// Write a [`PolicyManifest`] to disk as pretty-printed JSON.
pub fn write_manifest(path: &Path, manifest: &PolicyManifest) -> Result<()> {
    let json =
        serde_json::to_string_pretty(manifest).context("failed to serialize policy manifest")?;
    std::fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))
}

/// Validate a policy file's metadata (existence, type, size, permissions).
///
/// Returns `Some(metadata)` when the file is suitable for loading.
/// Returns `None` when the file is missing, is a directory, or exceeds the
/// size limit.
fn validate_policy_file(path: &Path, level: PolicyLevel) -> Option<std::fs::Metadata> {
    match validate_policy_file_with_diagnostics(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            check_permissions_warning(path, level, &metadata);
            Some(metadata)
        }
        Err(ValidationError::NotFound) => None,
        Err(e) => {
            warn!(path = %path.display(), level = %level, "Policy file invalid: {e}");
            None
        }
    }
}

/// Validate a policy file with rich diagnostic messages suitable for user display.
///
/// Returns `Ok(metadata)` when the file is suitable for loading, or a
/// [`ValidationError`] describing exactly what is wrong.
fn validate_policy_file_with_diagnostics(
    path: &Path,
) -> Result<std::fs::Metadata, ValidationError> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ValidationError::NotFound);
        }
        Err(e) => {
            return Err(ValidationError::IoError(format!(
                "Cannot read policy file at {}: {}",
                path.display(),
                e
            )));
        }
    };

    if metadata.is_dir() {
        return Err(ValidationError::IsDirectory(format!(
            "{} is a directory, not a file. Remove it and run `clash init` to create a policy.",
            path.display()
        )));
    }

    if metadata.len() > MAX_POLICY_SIZE {
        return Err(ValidationError::TooLarge(format!(
            "policy file is too large ({} bytes, max {} bytes). Check that {} is the correct file.",
            metadata.len(),
            MAX_POLICY_SIZE,
            path.display()
        )));
    }

    Ok(metadata)
}

/// Emit a warning if the policy file is readable by other users.
#[cfg(unix)]
fn check_permissions_warning(path: &Path, level: PolicyLevel, metadata: &std::fs::Metadata) {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    if mode & 0o044 != 0 {
        warn!(
            path = %path.display(),
            level = %level,
            mode = format!("{:o}", mode),
            "policy file is readable by other users; consider `chmod 600`"
        );
    }
}

/// Reason a policy file failed metadata validation.
enum ValidationError {
    /// File does not exist (not an error — just absent).
    NotFound,
    /// I/O error reading metadata.
    IoError(String),
    /// Path is a directory, not a file.
    IsDirectory(String),
    /// File exceeds the size limit.
    TooLarge(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::NotFound => write!(f, "file not found"),
            ValidationError::IoError(msg)
            | ValidationError::IsDirectory(msg)
            | ValidationError::TooLarge(msg) => write!(f, "{msg}"),
        }
    }
}

/// Try to load and validate a policy file, returning the evaluated JSON source
/// and a [`LoadedPolicy`] on success.
///
/// Returns `None` when the file is missing, is a directory, exceeds the size
/// limit, or fails Starlark evaluation. Writes diagnostics to `policy_error`
/// on evaluation failure.
pub fn try_load_policy(
    level: PolicyLevel,
    path: &Path,
    policy_error: &mut Option<String>,
) -> Option<ValidatedPolicy> {
    let _metadata = validate_policy_file(path, level)?;

    let is_json = path.extension().is_some_and(|ext| ext == "json");
    let result = if is_json {
        load_json_policy(path)
    } else {
        evaluate_star_policy(path)
    };

    match result {
        Ok(json_source) => {
            let loaded = LoadedPolicy {
                level,
                path: path.to_path_buf(),
                source: json_source.clone(),
            };
            Some(ValidatedPolicy {
                json_source,
                loaded,
            })
        }
        Err(e) => {
            let kind = if is_json { "JSON" } else { "starlark" };
            error!(
                path = %path.display(),
                level = %level,
                error = %e,
                "Failed to evaluate {kind} policy"
            );
            *policy_error = Some(format!("Failed to evaluate {}: {}", path.display(), e));
            None
        }
    }
}

/// Compile one or more evaluated policy JSON sources into a [`CompiledPolicy`] tree.
///
/// Each tuple is `(level, json_source, source_display_path)`.
/// When a single source is provided, uses `compile_to_tree`. When multiple
/// sources are provided, uses `compile_multi_level_to_tree` to merge them
/// with level-based precedence.
pub fn compile_policies(level_sources: &[(PolicyLevel, String, String)]) -> Result<CompiledPolicy> {
    let level_refs: Vec<(PolicyLevel, &str, &str)> = level_sources
        .iter()
        .map(|(l, s, p)| (*l, s.as_str(), p.as_str()))
        .collect();
    compile::compile_multi_level_to_tree(&level_refs)
}

/// Compile a raw policy JSON source string directly into a [`CompiledPolicy`] tree.
///
/// This is a thin wrapper around [`compile::compile_to_tree`] for callers that
/// have a single source string rather than level-tagged sources.
pub fn compile_source(source: &str) -> Result<CompiledPolicy> {
    compile::compile_to_tree(source)
}

/// Validate and load a policy file with full diagnostics, then compile it.
///
/// Produces detailed error messages suitable for surfacing to users.
/// Used by the test-only `load_policy_from_path` in settings.
#[cfg(test)]
pub fn load_and_compile_single(
    path: &Path,
    policy_error: &mut Option<String>,
) -> Option<CompiledPolicy> {
    let metadata = match validate_policy_file_with_diagnostics(path) {
        Ok(m) => m,
        Err(ValidationError::NotFound) => return None,
        Err(e) => {
            warn!(path = %path.display(), "Policy file invalid: {e}");
            *policy_error = Some(e.to_string());
            return None;
        }
    };

    #[cfg(unix)]
    check_permissions_warning(path, PolicyLevel::User, &metadata);
    #[cfg(not(unix))]
    let _ = metadata;

    let is_json = path.extension().is_some_and(|ext| ext == "json");
    let eval_result = if is_json {
        load_json_policy(path)
    } else {
        evaluate_star_policy(path)
    };

    match eval_result {
        Ok(json_source) => match compile::compile_to_tree(&json_source) {
            Ok(tree) => {
                info!(path = %path.display(), "Loaded policy");
                Some(tree)
            }
            Err(e) => {
                let msg = format!("Failed to compile policy: {}", e);
                warn!(path = %path.display(), error = %e, "Failed to compile policy");
                *policy_error = Some(msg);
                None
            }
        },
        Err(e) => {
            let msg = format!("Failed to evaluate policy: {}", e);
            warn!(path = %path.display(), error = %e, "Failed to evaluate policy");
            *policy_error = Some(msg);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_json_policy_without_includes() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("policy.json");
        std::fs::write(
            &json_path,
            r#"{
                "default_effect": "deny",
                "sandboxes": {},
                "tree": [{
                    "condition": {
                        "observe": "tool_name",
                        "pattern": {"literal": {"literal": "Bash"}},
                        "children": [{"decision": {"allow": null}}]
                    }
                }]
            }"#,
        )
        .unwrap();

        let source = load_json_policy(&json_path).unwrap();
        let policy: CompiledPolicy = serde_json::from_str(&source).unwrap();
        assert_eq!(policy.tree.len(), 1);
    }

    #[test]
    fn load_json_policy_with_star_include() {
        let dir = tempfile::tempdir().unwrap();

        // Write a local .star include file.
        let star_path = dir.path().join("extra.star");
        std::fs::write(
            &star_path,
            r#"
load("@clash//std.star", "tool", "policy", "deny")
def main():
    return policy(default = deny(), rules = [tool("Read").allow()])
"#,
        )
        .unwrap();

        // Write policy.json that includes extra.star and has its own inline rule.
        let json_path = dir.path().join("policy.json");
        std::fs::write(
            &json_path,
            r#"{
                "default_effect": "deny",
                "sandboxes": {},
                "includes": [{"path": "extra.star"}],
                "tree": [{
                    "condition": {
                        "observe": "tool_name",
                        "pattern": {"literal": {"literal": "Bash"}},
                        "children": [{"decision": {"allow": null}}]
                    }
                }]
            }"#,
        )
        .unwrap();

        let source = load_json_policy(&json_path).unwrap();
        let policy: CompiledPolicy = serde_json::from_str(&source).unwrap();
        // Should have inline (Bash) + included (Read) rules.
        assert!(
            policy.tree.len() >= 2,
            "expected at least 2 rules, got {}",
            policy.tree.len()
        );
    }

    #[test]
    fn load_json_policy_with_stdlib_include() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("policy.json");
        std::fs::write(
            &json_path,
            r#"{
                "default_effect": "deny",
                "sandboxes": {},
                "includes": [{"path": "@clash//builtin.star"}],
                "tree": []
            }"#,
        )
        .unwrap();

        let source = load_json_policy(&json_path).unwrap();
        let policy: CompiledPolicy = serde_json::from_str(&source).unwrap();
        // builtin.star exports rules for clash commands + claude tools.
        assert!(
            !policy.tree.is_empty(),
            "builtin.star should contribute rules"
        );
    }

    #[test]
    fn manifest_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("policy.json");

        let manifest = PolicyManifest {
            includes: vec![crate::policy::match_tree::IncludeEntry {
                path: "@clash//builtin.star".into(),
            }],
            policy: CompiledPolicy {
                sandboxes: std::collections::HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        };

        write_manifest(&json_path, &manifest).unwrap();
        let loaded = read_manifest(&json_path).unwrap();
        assert_eq!(loaded.includes.len(), 1);
        assert_eq!(loaded.includes[0].path, "@clash//builtin.star");
    }
}
