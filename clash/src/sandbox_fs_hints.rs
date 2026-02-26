//! Detect filesystem errors in sandboxed Bash output and provide actionable hints.
//!
//! When a Bash command runs inside a clash sandbox, filesystem access outside
//! the sandbox's allowed paths is blocked at the OS level. The command sees
//! "operation not permitted" or "permission denied" errors. This module detects
//! those errors in PostToolUse responses, identifies which paths were blocked,
//! and returns advisory context explaining the cause and suggesting policy fixes.
//!
//! This is the filesystem counterpart to [`crate::network_hints`], which handles
//! network sandbox violations.

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;
use tracing::{Level, info, instrument, warn};

use crate::audit;
use crate::hooks::ToolUseHookInput;
use crate::network_hints::extract_response_text;
use crate::policy::sandbox_types::{Cap, RuleEffect, SandboxPolicy};
use crate::settings::ClashSettings;

/// Filesystem error patterns that indicate a process had access blocked.
///
/// These are substrings matched case-insensitively against the tool response text.
const FS_ERROR_PATTERNS: &[&str] = &[
    // macOS Seatbelt produces EPERM
    "operation not permitted",
    // Linux Landlock produces EACCES, also common for general fs errors
    "permission denied",
];

/// Maximum number of blocked paths to report in a single hint.
const MAX_REPORTED_PATHS: usize = 5;

/// Paths that are commonly denied by macOS Seatbelt but are not user-visible
/// errors. These are background denials from process startup (DTrace, etc.)
/// that should be filtered out to avoid confusing noise in hints.
const NOISE_PATH_PREFIXES: &[&str] = &["/dev/dtrace", "/dev/dtracehelper", "/dev/oslog"];

/// Check if a PostToolUse Bash response contains filesystem errors likely caused
/// by sandbox restrictions. Returns advisory context if so.
///
/// Uses two data sources:
/// 1. **Audit log** (primary): reads sandbox violations written by `clash sandbox
///    exec` after the sandboxed process exited. These are kernel-verified denials
///    captured from the macOS unified log.
/// 2. **Stderr heuristic** (fallback): parses error messages from the command
///    output to extract paths. Used when no audit entries are found (Linux, or
///    if `log show` didn't capture anything).
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn check_for_sandbox_fs_hint(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> Option<String> {
    // Only check Bash tool responses
    if input.tool_name != "Bash" {
        return None;
    }

    // Get the sandbox policy. Try re-evaluation first (works if tool_input
    // is the original command). Fall back to extracting the policy from the
    // rewritten command string (PostToolUse may receive the rewritten command
    // like "clash sandbox exec --policy '{...}' ...").
    let sandbox = match resolve_sandbox_policy(input, settings) {
        Some(s) => s,
        None => {
            info!("check_for_sandbox_fs_hint: no sandbox policy resolved, skipping");
            return None;
        }
    };

    // Source 1: Read violations from the audit log (written by clash sandbox exec).
    // This is the primary, high-confidence source — kernel-verified denials.
    let audit_violations = read_audit_violations(input);
    let has_audit = !audit_violations.is_empty();

    // Source 2: Parse stderr for filesystem error patterns (fallback).
    // Note: don't use `?` on tool_response — we still want to proceed if we
    // have audit violations even when the response is missing.
    let response_text = input
        .tool_response
        .as_ref()
        .and_then(|r| extract_response_text(r));
    let stderr_has_errors = response_text.as_ref().is_some_and(|t| contains_fs_error(t));

    info!(
        has_audit = has_audit,
        audit_count = audit_violations.len(),
        has_response = response_text.is_some(),
        stderr_has_errors = stderr_has_errors,
        "check_for_sandbox_fs_hint: source analysis"
    );

    // If neither source found anything, bail early.
    if !has_audit && !stderr_has_errors {
        return None;
    }

    // Merge paths from both sources.
    let mut blocked_paths = Vec::new();

    // Audit-derived paths are high-confidence (kernel-verified denials).
    if has_audit {
        blocked_paths.extend(paths_from_audit(&audit_violations, &sandbox, &input.cwd));
    }

    // Stderr heuristic paths fill in gaps (e.g., paths the audit missed,
    // or Linux where no audit entries exist).
    if let Some(ref text) = response_text {
        let extracted_paths = extract_paths_from_errors(text);
        info!(
            extracted_count = extracted_paths.len(),
            paths = ?extracted_paths,
            "check_for_sandbox_fs_hint: paths extracted from stderr"
        );
        let stderr_blocked = extract_blocked_paths(text, &sandbox, &input.cwd);
        info!(
            stderr_blocked_count = stderr_blocked.len(),
            "check_for_sandbox_fs_hint: stderr paths confirmed as sandbox violations"
        );
        // Deduplicate: only add stderr paths whose suggested_dir isn't already covered.
        let existing_dirs: BTreeSet<String> = blocked_paths
            .iter()
            .map(|bp| bp.suggested_dir.clone())
            .collect();
        for bp in stderr_blocked {
            if !existing_dirs.contains(&bp.suggested_dir) {
                blocked_paths.push(bp);
            }
        }
    }

    if blocked_paths.is_empty() {
        info!("check_for_sandbox_fs_hint: no blocked paths after filtering, returning None");
        return None;
    }

    info!(
        tool = "Bash",
        blocked_count = blocked_paths.len(),
        from_audit = has_audit,
        "Detected filesystem sandbox violations in command output"
    );

    Some(build_fs_hint(&blocked_paths))
}

/// Try to recover the sandbox policy for this tool invocation.
///
/// 1. Re-evaluate the policy (works when PostToolUse gets the original command).
/// 2. Fall back to extracting the `--policy` JSON from the rewritten command
///    string (works when PostToolUse gets the `clash sandbox exec ...` wrapper).
fn resolve_sandbox_policy(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> Option<SandboxPolicy> {
    // Path 1: re-evaluate against the decision tree.
    if let Some(tree) = settings.decision_tree() {
        let decision = tree.evaluate(&input.tool_name, &input.tool_input, &input.cwd);
        if let Some(sandbox) = decision.sandbox {
            info!("resolve_sandbox_policy: found sandbox via decision tree re-evaluation");
            return Some(sandbox);
        }
        info!("resolve_sandbox_policy: decision tree returned no sandbox");
    } else {
        info!("resolve_sandbox_policy: no decision tree available");
    }

    // Path 2: extract --policy JSON from the rewritten command string.
    let command = input.tool_input.get("command")?.as_str()?;
    if !command.contains("sandbox exec") || !command.contains("--policy") {
        info!(
            command_prefix = &command[..command.len().min(80)],
            "resolve_sandbox_policy: command does not contain sandbox exec + --policy"
        );
        return None;
    }

    let result = extract_policy_json(command);
    info!(
        found = result.is_some(),
        "resolve_sandbox_policy: extracted policy JSON from rewritten command"
    );
    result
}

/// Extract the sandbox policy JSON from a rewritten `clash sandbox exec` command.
fn extract_policy_json(command: &str) -> Option<SandboxPolicy> {
    let policy_idx = command.find("--policy ")?;
    let after_flag = &command[policy_idx + "--policy ".len()..];

    // The policy JSON is shell-escaped in single quotes: '--policy '{...}''
    // We need to find the JSON object boundaries.
    let json_start = after_flag.find('{')?;
    let json_str = &after_flag[json_start..];

    // Find the matching closing brace (handling nesting).
    let mut depth = 0;
    let mut end = 0;
    for (i, ch) in json_str.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }

    if end == 0 {
        return None;
    }

    serde_json::from_str(&json_str[..end]).ok()
}

/// Check if text contains filesystem error patterns (case-insensitive).
fn contains_fs_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    FS_ERROR_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Filter out sandbox noise paths that aren't user-visible errors.
fn is_noise_path(path: &str) -> bool {
    NOISE_PATH_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Map a Seatbelt operation to the sandbox `Cap` flags it requires.
///
/// If the sandbox policy already grants these caps for a path, then a deny
/// event for that operation can't be from *our* sandbox — it's noise from
/// another sandboxed process on the system. Returns `None` for unknown
/// operations so they are kept conservatively.
fn operation_to_required_caps(operation: &str) -> Option<Cap> {
    match operation {
        op if op.starts_with("file-read-") => Some(Cap::READ),
        "file-write-create" => Some(Cap::WRITE | Cap::CREATE),
        "file-write-unlink" => Some(Cap::WRITE | Cap::DELETE),
        op if op.starts_with("file-write-") => Some(Cap::WRITE),
        _ => None,
    }
}

// ── Audit log reading ────────────────────────────────────────────────────

/// Read sandbox violations from the session audit log.
///
/// `clash sandbox exec` captures violations from the macOS unified log after
/// the sandboxed process exits and writes them to the session `audit.jsonl`.
/// This function reads them back by `tool_use_id`.
fn read_audit_violations(input: &ToolUseHookInput) -> Vec<audit::SandboxViolation> {
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
fn paths_from_audit(
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

    blocked
}

/// A filesystem path that was blocked by the sandbox.
#[derive(Debug)]
struct BlockedPath {
    /// The actual file path from the error message.
    path: String,
    /// The parent directory to suggest allowing access to.
    suggested_dir: String,
    /// What capabilities the sandbox currently grants for this path.
    current_caps: Cap,
}

/// Extract file paths from error messages and verify they're restricted by the sandbox.
fn extract_blocked_paths(text: &str, sandbox: &SandboxPolicy, cwd: &str) -> Vec<BlockedPath> {
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
fn is_likely_sandbox_violation(path: &str, sandbox: &SandboxPolicy, cwd: &str) -> bool {
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

/// Extract file paths from error text using regex patterns.
///
/// Handles common error formats from Go, Python, Node.js, Rust, and shell tools.
fn extract_paths_from_errors(text: &str) -> Vec<String> {
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

/// Find a useful parent directory to suggest for a blocked path.
///
/// For paths under `$HOME`, suggests the top-level dot-directory (e.g., `~/.fly`).
/// For other paths, suggests the immediate parent directory.
fn suggest_parent_directory(path: &str) -> String {
    let p = Path::new(path);

    if let Some(home) = dirs::home_dir()
        && let Ok(rel) = p.strip_prefix(&home)
    {
        // Look for the first component — if it starts with "." it's a config dir
        if let Some(first) = rel.components().next() {
            let first_str = first.as_os_str().to_string_lossy();
            if first_str.starts_with('.') {
                return home.join(first_str.as_ref()).to_string_lossy().into_owned();
            }
        }
    }

    // Fallback: immediate parent directory
    p.parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Build advisory context for Claude when a sandbox blocks filesystem access.
fn build_fs_hint(blocked: &[BlockedPath]) -> String {
    let mut lines = vec![
        "SANDBOX_FS_HINT: This command failed with filesystem permission errors.".into(),
        "The clash sandbox is blocking access to paths outside its allowed directories.".into(),
        String::new(),
        "Blocked paths:".into(),
    ];

    for bp in blocked {
        let caps_display = if bp.current_caps.is_empty() {
            "none".to_string()
        } else {
            bp.current_caps.display()
        };
        lines.push(format!(
            "  - {} (sandbox grants: {})",
            bp.path, caps_display
        ));
    }

    lines.push(String::new());
    lines.push("How to fix — add filesystem access to the policy:".into());

    for bp in blocked {
        lines.push(format!(
            "  (allow (fs (or read write create) (subpath \"{}\")))",
            bp.suggested_dir
        ));
    }

    lines.extend([
        String::new(),
        "Or use `/clash:edit` to modify the policy interactively.".into(),
        String::new(),
        "Agent instructions:".into(),
        "- Tell the user the filesystem error is caused by the clash sandbox".into(),
        "- Suggest adding the rules above to their sandbox or policy".into(),
        "- Do NOT retry the command — it will fail again until the policy is updated".into(),
    ]);

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::policy::sandbox_types::{NetworkPolicy, PathMatch, SandboxRule};

    // --- contains_fs_error ---

    #[test]
    fn test_contains_fs_error_operation_not_permitted() {
        assert!(contains_fs_error(
            "open /Users/user/.fly/perms.123: operation not permitted"
        ));
    }

    #[test]
    fn test_contains_fs_error_permission_denied() {
        assert!(contains_fs_error("Permission denied: '/tmp/secret'"));
    }

    #[test]
    fn test_contains_fs_error_case_insensitive() {
        assert!(contains_fs_error("OPERATION NOT PERMITTED"));
    }

    #[test]
    fn test_contains_fs_error_no_match() {
        assert!(!contains_fs_error("file not found: /tmp/test.txt"));
    }

    // --- extract_paths_from_errors ---

    #[test]
    fn test_extract_path_go_style() {
        let text = "open /Users/user/.fly/perms.123: operation not permitted";
        let paths = extract_paths_from_errors(text);
        assert_eq!(paths, vec!["/Users/user/.fly/perms.123"]);
    }

    #[test]
    fn test_extract_path_python_style() {
        let text = "PermissionError: [Errno 1] Operation not permitted: '/home/user/.cache/thing'";
        let paths = extract_paths_from_errors(text);
        assert!(paths.contains(&"/home/user/.cache/thing".to_string()));
    }

    #[test]
    fn test_extract_path_node_style() {
        let text = "Error: EACCES: permission denied, open '/tmp/app/config.json'";
        let paths = extract_paths_from_errors(text);
        assert!(paths.contains(&"/tmp/app/config.json".to_string()));
    }

    #[test]
    fn test_extract_path_shell_style() {
        let text = "/etc/shadow: Permission denied";
        let paths = extract_paths_from_errors(text);
        assert!(paths.contains(&"/etc/shadow".to_string()));
    }

    #[test]
    fn test_extract_path_issue_example() {
        // The exact error from GitHub issue #101
        let text = "Error: failed ensuring config directory perms: open /Users/emschwartz/.fly/perms.3199984107: operation not permitted";
        let paths = extract_paths_from_errors(text);
        assert!(paths.contains(&"/Users/emschwartz/.fly/perms.3199984107".to_string()));
    }

    #[test]
    fn test_extract_path_multiple_errors() {
        let text = "open /Users/user/.fly/config: operation not permitted\nstat /Users/user/.cache/sccache/db: operation not permitted";
        let paths = extract_paths_from_errors(text);
        assert!(paths.len() >= 2);
        assert!(paths.contains(&"/Users/user/.fly/config".to_string()));
        assert!(paths.contains(&"/Users/user/.cache/sccache/db".to_string()));
    }

    #[test]
    fn test_extract_path_no_match() {
        let text = "curl: (6) Could not resolve host: example.com";
        let paths = extract_paths_from_errors(text);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_path_deduplicates() {
        let text = "open /tmp/foo: operation not permitted\nopen /tmp/foo: operation not permitted";
        let paths = extract_paths_from_errors(text);
        assert_eq!(paths.len(), 1);
    }

    // --- suggest_parent_directory ---

    #[test]
    fn test_suggest_parent_home_dotdir() {
        let home = dirs::home_dir().unwrap();
        let path = format!("{}/.fly/perms.123", home.display());
        let suggested = suggest_parent_directory(&path);
        assert_eq!(suggested, format!("{}/.fly", home.display()));
    }

    #[test]
    fn test_suggest_parent_home_deep_dotdir() {
        let home = dirs::home_dir().unwrap();
        let path = format!("{}/.cache/sccache/some/deep/file.db", home.display());
        let suggested = suggest_parent_directory(&path);
        assert_eq!(suggested, format!("{}/.cache", home.display()));
    }

    #[test]
    fn test_suggest_parent_non_home_path() {
        let suggested = suggest_parent_directory("/opt/homebrew/lib/libfoo.so");
        assert_eq!(suggested, "/opt/homebrew/lib");
    }

    // --- is_likely_sandbox_violation ---

    #[test]
    fn test_violation_outside_allowed_paths() {
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::all(),
                path: "/project".into(),
                path_match: PathMatch::Subpath,
            }],
            network: NetworkPolicy::Deny,
        };
        // Path outside /project → likely violation
        assert!(is_likely_sandbox_violation(
            "/Users/user/.fly/config",
            &sandbox,
            "/project"
        ));
    }

    #[test]
    fn test_no_violation_inside_allowed_paths() {
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::all(),
                path: "/project".into(),
                path_match: PathMatch::Subpath,
            }],
            network: NetworkPolicy::Deny,
        };
        // Path inside /project with full caps → not a violation
        assert!(!is_likely_sandbox_violation(
            "/project/src/main.rs",
            &sandbox,
            "/project"
        ));
    }

    #[test]
    fn test_no_violation_when_write_granted() {
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        };
        // Default grants write+create → not a violation even for foreign paths
        assert!(!is_likely_sandbox_violation(
            "/Users/user/.fly/config",
            &sandbox,
            "/project"
        ));
    }

    // --- build_fs_hint ---

    #[test]
    fn test_build_hint_contains_key_info() {
        let blocked = vec![BlockedPath {
            path: "/Users/user/.fly/perms.123".into(),
            suggested_dir: "/Users/user/.fly".into(),
            current_caps: Cap::READ | Cap::EXECUTE,
        }];
        let hint = build_fs_hint(&blocked);
        assert!(hint.contains("SANDBOX_FS_HINT"));
        assert!(hint.contains("/Users/user/.fly/perms.123"));
        assert!(hint.contains("/Users/user/.fly"));
        assert!(hint.contains("read + execute"));
        assert!(hint.contains("/clash:edit"));
        assert!(hint.contains("Do NOT retry"));
    }

    #[test]
    fn test_build_hint_empty_caps() {
        let blocked = vec![BlockedPath {
            path: "/secret/file".into(),
            suggested_dir: "/secret".into(),
            current_caps: Cap::empty(),
        }];
        let hint = build_fs_hint(&blocked);
        assert!(hint.contains("none"));
    }

    // --- paths_from_audit ---

    #[test]
    fn test_is_noise_path() {
        assert!(is_noise_path("/dev/dtracehelper"));
        assert!(is_noise_path("/dev/dtrace"));
        assert!(is_noise_path("/dev/oslog/foo"));
        assert!(!is_noise_path("/Users/user/.fly/config"));
        assert!(!is_noise_path("/var/tmp/test"));
        assert!(!is_noise_path("/dev/null")); // not in the noise list
    }

    #[test]
    fn test_paths_from_audit_filters_noise() {
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        };
        let violations = vec![
            audit::SandboxViolation {
                operation: "file-read-data".into(),
                path: "/dev/dtracehelper".into(),
            },
            audit::SandboxViolation {
                operation: "file-write-create".into(),
                path: "/Users/user/.fly/config".into(),
            },
        ];
        let blocked = paths_from_audit(&violations, &sandbox, "/project");
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].path.contains(".fly"));
    }

    #[test]
    fn test_paths_from_audit_deduplicates_by_dir() {
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        };
        let violations = vec![
            audit::SandboxViolation {
                operation: "file-write-create".into(),
                path: "/Users/user/.fly/perms.123".into(),
            },
            audit::SandboxViolation {
                operation: "file-write-data".into(),
                path: "/Users/user/.fly/config.json".into(),
            },
        ];
        let blocked = paths_from_audit(&violations, &sandbox, "/project");
        // Both paths are under ~/.fly — should be deduplicated to one entry
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].suggested_dir.ends_with(".fly"));
    }

    // --- operation_to_required_caps ---

    #[test]
    fn test_operation_to_required_caps() {
        // file-read-* → READ
        assert_eq!(
            operation_to_required_caps("file-read-data"),
            Some(Cap::READ)
        );
        assert_eq!(
            operation_to_required_caps("file-read-metadata"),
            Some(Cap::READ)
        );

        // file-write-create → WRITE | CREATE
        assert_eq!(
            operation_to_required_caps("file-write-create"),
            Some(Cap::WRITE | Cap::CREATE)
        );

        // file-write-unlink → WRITE | DELETE
        assert_eq!(
            operation_to_required_caps("file-write-unlink"),
            Some(Cap::WRITE | Cap::DELETE)
        );

        // file-write-* (other) → WRITE
        assert_eq!(
            operation_to_required_caps("file-write-data"),
            Some(Cap::WRITE)
        );
        assert_eq!(
            operation_to_required_caps("file-write-flags"),
            Some(Cap::WRITE)
        );

        // Unknown → None (keep conservatively)
        assert_eq!(operation_to_required_caps("network-outbound"), None);
        assert_eq!(operation_to_required_caps("process-exec"), None);
    }

    // --- paths_from_audit policy-aware filtering ---

    #[test]
    fn test_paths_from_audit_filters_granted_read() {
        // Sandbox grants READ (via default caps) — a file-read-data violation
        // on that path must be from another process, so it should be filtered.
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        };
        let violations = vec![audit::SandboxViolation {
            operation: "file-read-data".into(),
            path: "/Applications/LM Studio.app/Contents/Info.plist".into(),
        }];
        let blocked = paths_from_audit(&violations, &sandbox, "/project");
        assert!(
            blocked.is_empty(),
            "read violation on path where sandbox grants READ should be filtered"
        );
    }

    #[test]
    fn test_paths_from_audit_keeps_denied_write() {
        // Sandbox only grants READ+EXECUTE by default — a file-write-create
        // violation is a real sandbox denial and should be kept.
        let sandbox = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        };
        let violations = vec![audit::SandboxViolation {
            operation: "file-write-create".into(),
            path: "/Users/user/Desktop/testfile".into(),
        }];
        let blocked = paths_from_audit(&violations, &sandbox, "/project");
        assert_eq!(
            blocked.len(),
            1,
            "write violation where sandbox denies WRITE should be kept"
        );
        assert!(blocked[0].path.contains("Desktop"));
    }

    // --- check_for_sandbox_fs_hint (integration) ---

    #[test]
    fn test_check_returns_none_for_non_bash() {
        let input = ToolUseHookInput {
            tool_name: "Read".into(),
            tool_response: Some(json!("operation not permitted")),
            ..Default::default()
        };
        let settings = ClashSettings::default();
        assert!(check_for_sandbox_fs_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_none_without_response() {
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_response: None,
            ..Default::default()
        };
        let settings = ClashSettings::default();
        assert!(check_for_sandbox_fs_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_none_for_non_fs_error() {
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_response: Some(json!("file not found")),
            ..Default::default()
        };
        let settings = ClashSettings::default();
        assert!(check_for_sandbox_fs_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_none_without_policy() {
        let settings = ClashSettings::default();
        assert!(settings.decision_tree().is_none());
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "fly logs"}),
            tool_response: Some(json!(
                "open /Users/user/.fly/perms.123: operation not permitted"
            )),
            ..Default::default()
        };
        assert!(check_for_sandbox_fs_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_hint_with_sandbox() {
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"
(default deny "main")
(policy "main"
  (allow (exec *))
  (allow (fs read (subpath "/tmp"))))
"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "fly logs --app scour-rs"}),
            tool_response: Some(json!(
                "Error: failed ensuring config directory perms: open /Users/emschwartz/.fly/perms.3199984107: operation not permitted"
            )),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let result = check_for_sandbox_fs_hint(&input, &settings);
        assert!(
            result.is_some(),
            "should return hint for sandboxed filesystem error"
        );
        let hint = result.unwrap();
        assert!(hint.contains("SANDBOX_FS_HINT"));
        assert!(hint.contains(".fly"));
    }

    #[test]
    fn test_check_returns_none_when_path_is_allowed() {
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"
(default deny "main")
(policy "main"
  (allow (exec *))
  (allow (fs (or read write create) (subpath "/Users/emschwartz/.fly"))))
"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "fly logs"}),
            tool_response: Some(json!(
                "open /Users/emschwartz/.fly/perms.123: operation not permitted"
            )),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        // Path is under an explicitly allowed subpath → not a sandbox violation
        let result = check_for_sandbox_fs_hint(&input, &settings);
        assert!(
            result.is_none(),
            "should not hint when the path is explicitly allowed"
        );
    }

    #[test]
    fn test_check_returns_hint_with_explicit_sandbox() {
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"
(default deny "main")
(policy "restricted"
  (allow (fs read (subpath "/project"))))
(policy "main"
  (allow (exec "fly" *) :sandbox "restricted"))
"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "fly logs --app scour-rs"}),
            tool_response: Some(json!(
                "open /Users/user/.fly/perms.123: operation not permitted"
            )),
            cwd: "/project".into(),
            ..Default::default()
        };
        let result = check_for_sandbox_fs_hint(&input, &settings);
        assert!(
            result.is_some(),
            "should return hint for explicit sandbox violation"
        );
    }
}
