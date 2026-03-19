//! Stderr parsing for filesystem sandbox violations.
//!
//! When no audit log entries are available (e.g., on Linux, or when `log show`
//! didn't capture anything), this module falls back to parsing error messages
//! from command output to extract blocked filesystem paths.

use std::collections::BTreeSet;

use regex::Regex;
use tracing::warn;

use crate::policy::sandbox_types::{Cap, RuleEffect, SandboxPolicy};

use super::formatter::BlockedPath;
use super::{FS_ERROR_PATTERNS, MAX_REPORTED_PATHS, is_noise_path, suggest_parent_directory};

/// Check if text contains filesystem error patterns (case-insensitive).
pub(crate) fn contains_fs_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    FS_ERROR_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Extract file paths from error text using regex patterns.
///
/// Handles common error formats from Go, Python, Node.js, Rust, and shell tools.
pub(crate) fn extract_paths_from_errors(text: &str) -> Vec<String> {
    // Compile patterns on each call — this runs only in PostToolUse (not hot path).
    let patterns = [
        // "open /path: operation not permitted" (Go, C, generic syscall wrappers)
        r"(?:open|stat|read|write|mkdir|access|unlink|rename|chmod|chown|lstat|readlink|creat|opendir)\s+(/[^\s:]+):\s*(?i:operation not permitted|permission denied)",
        // "Operation not permitted: '/path'" or "Permission denied: '/path'" (Python)
        r"(?i:operation not permitted|permission denied):\s*'(/[^']+)'",
        // "'/path': Operation not permitted" or "'/path': Permission denied" (Ruby, others)
        r"'(/[^']+)':\s*(?i:operation not permitted|permission denied)",
        // "EACCES: permission denied, open '/path'" (Node.js)
        r"(?i:EACCES|EPERM):\s*(?:permission denied|operation not permitted),?\s*\w+\s*'([^']+)'",
        // "/path: Permission denied" or "/path: Operation not permitted" (shell, coreutils)
        // Must start with / to avoid matching non-path text.
        r"(/(?:[^\s:])+):\s*(?:Permission denied|Operation not permitted)",
    ];

    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();

    for pattern in &patterns {
        let re = match Regex::new(pattern) {
            Ok(re) => re,
            Err(e) => {
                warn!(pattern = pattern, error = %e, "Failed to compile path extraction regex");
                continue;
            }
        };
        for cap in re.captures_iter(text) {
            if let Some(m) = cap.get(1) {
                let path = m.as_str().to_string();
                // Only include absolute paths, deduplicate
                if path.starts_with('/') && seen.insert(path.clone()) {
                    paths.push(path);
                }
            }
        }
    }

    paths
}

/// Extract file paths from error messages and verify they're restricted by the sandbox.
pub(crate) fn extract_blocked_paths(
    text: &str,
    sandbox: &SandboxPolicy,
    cwd: &str,
) -> Vec<BlockedPath> {
    let paths = extract_paths_from_errors(text);
    let mut blocked = Vec::new();
    let mut seen_dirs = BTreeSet::new();

    for path in paths {
        if is_noise_path(&path) || !is_likely_sandbox_violation(&path, sandbox, cwd) {
            continue;
        }

        let dir = suggest_parent_directory(&path);
        // Deduplicate by suggested directory — multiple files in the same dir
        // should produce one suggestion, not many.
        if seen_dirs.insert(dir.clone()) {
            blocked.push(BlockedPath {
                current_caps: sandbox.effective_caps(&path, cwd),
                path,
                suggested_dir: dir,
            });
        }

        if blocked.len() >= MAX_REPORTED_PATHS {
            break;
        }
    }

    blocked
}

/// Determine if a permission error on this path is likely caused by the sandbox.
///
/// Checks two conditions to reduce false positives:
/// 1. The sandbox doesn't grant write+create for this path (most common cause)
/// 2. The path is not under any explicitly allowed subpath (it's "foreign" to the sandbox)
pub(crate) fn is_likely_sandbox_violation(path: &str, sandbox: &SandboxPolicy, cwd: &str) -> bool {
    let caps = sandbox.effective_caps(path, cwd);
    let missing_write_or_create = !caps.contains(Cap::WRITE) || !caps.contains(Cap::CREATE);

    let under_explicit_allow = sandbox.rules.iter().any(|rule| {
        if rule.effect != RuleEffect::Allow {
            return false;
        }
        let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
        path.starts_with(&resolved)
    });

    missing_write_or_create && !under_explicit_allow
}
