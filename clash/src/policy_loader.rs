//! Policy discovery, evaluation, and compilation.
//!
//! This module extracts the policy loading pipeline from [`crate::settings`]:
//!
//! 1. **Discovery** — finding `policy.star` files at user/project/session levels
//! 2. **Validation** — checking file metadata (size, permissions, type)
//! 3. **Evaluation** — running Starlark `.star` files through `clash_starlark`
//! 4. **Compilation** — compiling evaluated JSON sources into a [`CompiledPolicy`] tree

use std::path::Path;

use anyhow::{Context, Result};
use tracing::{error, warn};

#[cfg(test)]
use tracing::info;

use crate::policy::compile;
use crate::policy::match_tree::CompiledPolicy;
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

/// Validate a policy file's metadata (existence, type, size, permissions).
///
/// Returns `Some(metadata)` when the file is suitable for loading.
/// Returns `None` when the file is missing, is a directory, or exceeds the
/// size limit.
fn validate_policy_file(path: &Path, level: PolicyLevel) -> Option<std::fs::Metadata> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(
                path = %path.display(),
                level = %level,
                error = %e,
                "Failed to stat policy file"
            );
            return None;
        }
    };

    if metadata.is_dir() || metadata.len() > MAX_POLICY_SIZE {
        return None;
    }

    #[cfg(unix)]
    {
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

    Some(metadata)
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

    match evaluate_star_policy(path) {
        Ok(json_source) => {
            let loaded = LoadedPolicy {
                level,
                path: path.to_path_buf(),
                source: json_source.clone(),
            };
            Some(ValidatedPolicy { json_source, loaded })
        }
        Err(e) => {
            error!(
                path = %path.display(),
                level = %level,
                error = %e,
                "Failed to evaluate starlark policy"
            );
            *policy_error = Some(format!("Failed to evaluate {}: {}", path.display(), e));
            None
        }
    }
}

/// Compile one or more evaluated policy JSON sources into a [`CompiledPolicy`] tree.
///
/// When a single source is provided, uses `compile_to_tree`. When multiple
/// sources are provided, uses `compile_multi_level_to_tree` to merge them
/// with level-based precedence.
pub fn compile_policies(level_sources: &[(PolicyLevel, String)]) -> Result<CompiledPolicy> {
    if level_sources.len() == 1 {
        let (_, source) = &level_sources[0];
        compile::compile_to_tree(source)
    } else {
        let level_refs: Vec<(PolicyLevel, &str)> = level_sources
            .iter()
            .map(|(l, s)| (*l, s.as_str()))
            .collect();
        compile::compile_multi_level_to_tree(&level_refs)
    }
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
/// Unlike [`try_load_policy`], this function produces detailed error messages
/// for directory files and oversized files, suitable for surfacing to users.
/// Used by the test-only `load_policy_from_path` in settings.
#[cfg(test)]
pub fn load_and_compile_single(
    path: &Path,
    policy_error: &mut Option<String>,
) -> Option<CompiledPolicy> {
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to stat policy file");
            *policy_error = Some(format!(
                "Cannot read policy file at {}: {}",
                path.display(),
                e
            ));
            return None;
        }
    };

    if metadata.is_dir() {
        let msg = format!(
            "{} is a directory, not a file. Remove it and run `clash init` to create a policy.",
            path.display()
        );
        warn!(path = %path.display(), "policy file is a directory");
        *policy_error = Some(msg);
        return None;
    }

    if metadata.len() > MAX_POLICY_SIZE {
        let msg = format!(
            "policy file is too large ({} bytes, max {} bytes). \
             Check that {} is the correct file.",
            metadata.len(),
            MAX_POLICY_SIZE,
            path.display()
        );
        warn!(path = %path.display(), size = metadata.len(), "policy file exceeds size limit");
        *policy_error = Some(msg);
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o044 != 0 {
            warn!(
                path = %path.display(),
                mode = format!("{:o}", mode),
                "policy file is readable by other users; consider `chmod 600`"
            );
        }
    }

    match evaluate_star_policy(path) {
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
