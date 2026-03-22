//! Audit log violation reading and path extraction.
//!
//! `clash sandbox exec` captures sandbox violations from the macOS unified log
//! after the sandboxed process exits and writes them to the session `audit.jsonl`.
//! This module reads those entries back and converts them into [`BlockedPath`]
//! entries for hint generation.

use std::collections::BTreeSet;

use tracing::info;

use crate::audit;
use crate::hooks::ToolUseHookInput;
use crate::policy::sandbox_types::SandboxPolicy;

use super::formatter::BlockedPath;
use super::{
    MAX_REPORTED_PATHS, is_noise_path, operation_to_required_caps, suggest_parent_directory,
};

/// Read sandbox violations from the session audit log.
///
/// `clash sandbox exec` captures violations from the macOS unified log after
/// the sandboxed process exits and writes them to the session `audit.jsonl`.
/// This function reads them back by `tool_use_id`.
pub(crate) fn read_audit_violations(input: &ToolUseHookInput) -> Vec<audit::SandboxViolation> {
    if input.session_id.is_empty() {
        return Vec::new();
    }
    let tool_use_id = match input.tool_use_id.as_deref() {
        Some(id) => id,
        None => return Vec::new(),
    };
    audit::read_sandbox_violations(&input.session_id, tool_use_id)
}

/// Convert audit-derived violations into `BlockedPath` entries.
pub(crate) fn paths_from_audit(
    violations: &[audit::SandboxViolation],
    sandbox: &SandboxPolicy,
    cwd: &str,
) -> Vec<BlockedPath> {
    let mut blocked = Vec::new();
    let mut seen_dirs = BTreeSet::new();

    for v in violations {
        if is_noise_path(&v.path) {
            continue;
        }
        // If the sandbox policy already grants the caps this operation needs,
        // this violation is from another sandboxed process (noise), not ours.
        if let Some(required) = operation_to_required_caps(&v.operation) {
            let granted = sandbox.effective_caps(&v.path, cwd);
            if granted.contains(required) {
                continue;
            }
        }
        let dir = suggest_parent_directory(&v.path);
        if seen_dirs.insert(dir.clone()) {
            blocked.push(BlockedPath {
                current_caps: sandbox.effective_caps(&v.path, cwd),
                path: v.path.clone(),
                suggested_dir: dir,
            });
        }
        if blocked.len() >= MAX_REPORTED_PATHS {
            break;
        }
    }

    info!(
        audit_blocked_count = blocked.len(),
        "audit_source: paths extracted from audit violations"
    );

    blocked
}
