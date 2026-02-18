//! Detect permission acceptances and learn session-level policy rules.
//!
//! When Clash returns "ask" for a tool use, the user sees a permission prompt
//! in Claude Code's UI. If they accept, PostToolUse fires and we can infer
//! an allow rule to add to the session policy — so the same kind of action
//! won't require re-approval for the rest of the session.
//!
//! ## How it works
//!
//! 1. **PreToolUse returns Ask** → `record_pending_ask()` writes a marker file
//!    in the session directory keyed by `tool_use_id`.
//! 2. **PostToolUse fires** → `process_post_tool_use()` checks for a pending
//!    ask marker. If found, the user accepted the permission, so we infer a
//!    session-scoped allow rule and write it to the session policy file.
//!
//! Rules are intentionally somewhat broad (e.g., allow the binary with any args)
//! so users don't get re-prompted for similar actions within the same session.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::policy::ast::{
    CapMatcher, ExecMatcher, FsMatcher, FsOp, NetMatcher, OpPattern, PathExpr, PathFilter, Pattern,
    Rule, ToolMatcher,
};
use crate::policy::edit;
use crate::policy::eval::{extract_domain, resolve_path};
use crate::policy::Effect;

/// Directory within the session dir where pending ask markers are stored.
const PENDING_DIR: &str = "pending_asks";

/// Minimal policy source for a new session policy file.
const MINIMAL_SESSION_POLICY: &str = "(default deny \"main\")\n(policy \"main\")\n";

// ---------------------------------------------------------------------------
// Pending ask tracking
// ---------------------------------------------------------------------------

/// Record that we returned "ask" for a tool use, so PostToolUse can detect
/// the user's acceptance later.
pub fn record_pending_ask(
    session_id: &str,
    tool_use_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) {
    let dir = pending_dir(session_id);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(error = %e, "Failed to create pending asks directory");
        return;
    }

    let entry = serde_json::json!({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd,
    });

    let path = dir.join(sanitize_id(tool_use_id));
    if let Err(e) = std::fs::write(&path, entry.to_string()) {
        warn!(error = %e, path = %path.display(), "Failed to write pending ask marker");
    } else {
        debug!(tool_use_id, tool_name, "Recorded pending ask");
    }
}

/// Check if a PostToolUse event corresponds to a previously-asked permission
/// that the user accepted. If so, infer and write a session policy rule.
///
/// Returns `Ok(Some(rule_description))` if a rule was added, `Ok(None)` if
/// there was no pending ask for this tool_use_id.
pub fn process_post_tool_use(
    session_id: &str,
    tool_use_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) -> Result<Option<String>> {
    let marker_path = pending_dir(session_id).join(sanitize_id(tool_use_id));

    // No pending ask for this tool use — nothing to do.
    if !marker_path.exists() {
        return Ok(None);
    }

    // Clean up the marker regardless of whether rule generation succeeds.
    let _ = std::fs::remove_file(&marker_path);

    info!(
        tool_use_id,
        tool_name, "User accepted permission — inferring session rule"
    );

    let rule = match infer_allow_rule(tool_name, tool_input, cwd) {
        Some(r) => r,
        None => {
            debug!(tool_name, "Could not infer allow rule for tool");
            return Ok(None);
        }
    };

    let rule_str = rule.to_string();
    write_session_rule(session_id, &rule)?;

    info!(rule = %rule_str, "Added session policy rule from user approval");
    Ok(Some(rule_str))
}

// ---------------------------------------------------------------------------
// Rule inference
// ---------------------------------------------------------------------------

/// Infer a session-scoped allow rule from a tool invocation.
///
/// The rules are intentionally somewhat broad — the goal is to avoid
/// re-prompting for similar actions within the same session. For example,
/// approving `git status` allows all `git` commands.
pub fn infer_allow_rule(
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) -> Option<Rule> {
    match tool_name {
        "Bash" => infer_exec_rule(tool_input),
        "Read" | "Glob" | "Grep" => infer_fs_read_rule(tool_input, cwd),
        "Write" | "Edit" | "NotebookEdit" => infer_fs_write_rule(tool_input, cwd),
        "WebFetch" => infer_net_rule(tool_input),
        "WebSearch" => Some(Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Net(NetMatcher {
                domain: Pattern::Any,
            }),
            sandbox: None,
        }),
        _ => Some(Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Tool(ToolMatcher {
                name: Pattern::Literal(tool_name.to_string()),
            }),
            sandbox: None,
        }),
    }
}

/// Infer an exec allow rule from a Bash tool input.
///
/// Extracts the binary name and allows it with wildcard args:
/// `(allow (exec "<bin>" *))`.
fn infer_exec_rule(tool_input: &serde_json::Value) -> Option<Rule> {
    let command = tool_input.get("command")?.as_str()?;
    let parts: Vec<&str> = command.split_whitespace().collect();
    let bin = *parts.first()?;

    // Don't create overly broad rules for shell builtins or pipes.
    if bin.is_empty() || bin.contains('/') && !bin.starts_with('/') {
        return None;
    }

    // Strip path prefix to get just the binary name.
    let bin_name = Path::new(bin)
        .file_name()?
        .to_str()?;

    Some(Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Exec(ExecMatcher {
            bin: Pattern::Literal(bin_name.to_string()),
            args: vec![Pattern::Any],
            has_args: vec![],
        }),
        sandbox: None,
    })
}

/// Infer a filesystem read rule from a Read/Glob/Grep tool input.
///
/// Allows reading under the parent directory of the accessed path:
/// `(allow (fs read (subpath "<parent_dir>")))`.
fn infer_fs_read_rule(tool_input: &serde_json::Value, cwd: &str) -> Option<Rule> {
    let path = tool_input
        .get("file_path")
        .or_else(|| tool_input.get("path"))
        .and_then(|v| v.as_str())?;

    let resolved = resolve_path(path, cwd);
    let parent = PathBuf::from(&resolved)
        .parent()?
        .to_string_lossy()
        .to_string();

    Some(Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Fs(FsMatcher {
            op: OpPattern::Single(FsOp::Read),
            path: Some(PathFilter::Subpath(PathExpr::Static(parent))),
        }),
        sandbox: None,
    })
}

/// Infer a filesystem write rule from a Write/Edit tool input.
///
/// Allows read+write+create under the parent directory:
/// `(allow (fs (or read write create) (subpath "<parent_dir>")))`.
fn infer_fs_write_rule(tool_input: &serde_json::Value, cwd: &str) -> Option<Rule> {
    let path = tool_input.get("file_path")?.as_str()?;
    let resolved = resolve_path(path, cwd);
    let parent = PathBuf::from(&resolved)
        .parent()?
        .to_string_lossy()
        .to_string();

    Some(Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Fs(FsMatcher {
            op: OpPattern::Or(vec![FsOp::Read, FsOp::Write, FsOp::Create]),
            path: Some(PathFilter::Subpath(PathExpr::Static(parent))),
        }),
        sandbox: None,
    })
}

/// Infer a network allow rule from a WebFetch tool input.
///
/// Allows access to the specific domain: `(allow (net "<domain>"))`.
fn infer_net_rule(tool_input: &serde_json::Value) -> Option<Rule> {
    let url = tool_input.get("url")?.as_str()?;
    let domain = extract_domain(url);
    if domain.is_empty() {
        return None;
    }

    Some(Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal(domain),
        }),
        sandbox: None,
    })
}

// ---------------------------------------------------------------------------
// Session policy file management
// ---------------------------------------------------------------------------

/// Write an inferred allow rule to the session-level policy file.
///
/// Creates the session policy file with a minimal skeleton if it doesn't exist.
/// Uses `edit::add_rule` which is idempotent — duplicate rules are silently skipped.
fn write_session_rule(session_id: &str, rule: &Rule) -> Result<()> {
    let session_dir = crate::audit::session_dir(session_id);
    let policy_path = session_dir.join("policy.sexpr");

    // Read existing session policy or start with a minimal skeleton.
    let source = if policy_path.exists() {
        std::fs::read_to_string(&policy_path)
            .with_context(|| format!("failed to read session policy: {}", policy_path.display()))?
    } else {
        MINIMAL_SESSION_POLICY.to_string()
    };

    let policy_name = edit::active_policy(&source)
        .unwrap_or_else(|_| "main".to_string());

    let modified = edit::add_rule(&source, &policy_name, rule)
        .context("failed to add rule to session policy")?;

    // Don't write if nothing changed (idempotent).
    if modified == source {
        debug!("Rule already exists in session policy, skipping write");
        return Ok(());
    }

    // Validate the modified policy compiles before writing.
    crate::policy::compile_policy(&modified)
        .context("inferred session policy failed to compile — not writing")?;

    std::fs::create_dir_all(&session_dir)
        .with_context(|| format!("failed to create session dir: {}", session_dir.display()))?;
    std::fs::write(&policy_path, &modified)
        .with_context(|| format!("failed to write session policy: {}", policy_path.display()))?;

    debug!(path = %policy_path.display(), "Updated session policy file");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pending_dir(session_id: &str) -> PathBuf {
    crate::audit::session_dir(session_id).join(PENDING_DIR)
}

/// Sanitize a tool_use_id for use as a filename.
fn sanitize_id(id: &str) -> String {
    id.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_infer_exec_rule_git() {
        let rule = infer_allow_rule("Bash", &json!({"command": "git status"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("exec"), "expected exec rule, got: {s}");
        assert!(s.contains("\"git\""), "expected git binary, got: {s}");
        assert!(s.contains("*"), "expected wildcard args, got: {s}");
    }

    #[test]
    fn test_infer_exec_rule_npm() {
        let rule =
            infer_allow_rule("Bash", &json!({"command": "npm install express"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("\"npm\""), "expected npm binary, got: {s}");
    }

    #[test]
    fn test_infer_exec_rule_absolute_path() {
        let rule =
            infer_allow_rule("Bash", &json!({"command": "/usr/bin/git status"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("\"git\""), "should strip path prefix, got: {s}");
    }

    #[test]
    fn test_infer_fs_read_rule() {
        let rule = infer_allow_rule(
            "Read",
            &json!({"file_path": "/etc/hosts"}),
            "/home/user/project",
        )
        .unwrap();
        let s = rule.to_string();
        assert!(s.contains("fs"), "expected fs rule, got: {s}");
        assert!(s.contains("read"), "expected read op, got: {s}");
        assert!(s.contains("\"/etc\""), "expected /etc parent, got: {s}");
    }

    #[test]
    fn test_infer_fs_write_rule() {
        let rule = infer_allow_rule(
            "Write",
            &json!({"file_path": "/home/user/project/src/main.rs"}),
            "/home/user/project",
        )
        .unwrap();
        let s = rule.to_string();
        assert!(s.contains("fs"), "expected fs rule, got: {s}");
        assert!(s.contains("write"), "expected write op, got: {s}");
        assert!(
            s.contains("/home/user/project/src"),
            "expected parent dir, got: {s}"
        );
    }

    #[test]
    fn test_infer_net_rule() {
        let rule = infer_allow_rule(
            "WebFetch",
            &json!({"url": "https://github.com/foo/bar"}),
            "/tmp",
        )
        .unwrap();
        let s = rule.to_string();
        assert!(s.contains("net"), "expected net rule, got: {s}");
        assert!(
            s.contains("\"github.com\""),
            "expected domain, got: {s}"
        );
    }

    #[test]
    fn test_infer_websearch_rule() {
        let rule = infer_allow_rule("WebSearch", &json!({"query": "rust async"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("net"), "expected net rule, got: {s}");
        // WebSearch allows any domain
        assert!(
            !s.contains('"'),
            "websearch should use wildcard, got: {s}"
        );
    }

    #[test]
    fn test_infer_tool_rule() {
        let rule = infer_allow_rule("Task", &json!({"prompt": "do something"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("tool"), "expected tool rule, got: {s}");
        assert!(s.contains("\"Task\""), "expected Task name, got: {s}");
    }

    #[test]
    fn test_infer_empty_command_returns_none() {
        let rule = infer_allow_rule("Bash", &json!({"command": ""}), "/tmp");
        assert!(rule.is_none(), "empty command should return None");
    }

    #[test]
    fn test_pending_ask_roundtrip() {
        let session_id = format!("test-pending-{}", std::process::id());
        let session_dir = crate::audit::session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&session_dir);
        std::fs::create_dir_all(&session_dir).unwrap();

        // Record a pending ask.
        record_pending_ask(
            &session_id,
            "toolu_01ABC",
            "Bash",
            &json!({"command": "git status"}),
            "/tmp",
        );

        // The marker file should exist.
        let marker = pending_dir(&session_id).join("toolu_01ABC");
        assert!(marker.exists(), "pending ask marker should exist");

        // Process the approval — should return the rule.
        let result = process_post_tool_use(
            &session_id,
            "toolu_01ABC",
            "Bash",
            &json!({"command": "git status"}),
            "/tmp",
        )
        .unwrap();
        assert!(result.is_some(), "should have generated a rule");
        assert!(
            result.unwrap().contains("git"),
            "rule should mention git"
        );

        // Marker should be cleaned up.
        assert!(!marker.exists(), "marker should be removed after processing");

        // Session policy file should exist.
        let policy_path = session_dir.join("policy.sexpr");
        assert!(policy_path.exists(), "session policy should be created");
        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            policy.contains("git"),
            "session policy should contain git rule: {policy}"
        );

        // Clean up.
        let _ = std::fs::remove_dir_all(&session_dir);
    }

    #[test]
    fn test_process_no_pending_ask() {
        let session_id = format!("test-no-pending-{}", std::process::id());
        let session_dir = crate::audit::session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&session_dir);
        std::fs::create_dir_all(&session_dir).unwrap();

        let result = process_post_tool_use(
            &session_id,
            "toolu_nonexistent",
            "Bash",
            &json!({"command": "ls"}),
            "/tmp",
        )
        .unwrap();
        assert!(result.is_none(), "should return None when no pending ask");

        let _ = std::fs::remove_dir_all(&session_dir);
    }

    #[test]
    fn test_write_session_rule_idempotent() {
        let session_id = format!("test-idempotent-{}", std::process::id());
        let session_dir = crate::audit::session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&session_dir);
        std::fs::create_dir_all(&session_dir).unwrap();

        let rule = infer_allow_rule("Bash", &json!({"command": "git status"}), "/tmp").unwrap();

        // Write twice.
        write_session_rule(&session_id, &rule).unwrap();
        let first = std::fs::read_to_string(session_dir.join("policy.sexpr")).unwrap();
        write_session_rule(&session_id, &rule).unwrap();
        let second = std::fs::read_to_string(session_dir.join("policy.sexpr")).unwrap();

        assert_eq!(first, second, "writing same rule twice should be idempotent");

        let _ = std::fs::remove_dir_all(&session_dir);
    }

    #[test]
    fn test_sanitize_id() {
        assert_eq!(sanitize_id("toolu_01ABC"), "toolu_01ABC");
        assert_eq!(sanitize_id("foo/bar"), "foo_bar");
        assert_eq!(sanitize_id("a.b.c"), "a_b_c");
    }
}
