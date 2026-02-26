//! Detect permission acceptances and suggest session-level policy rules.
//!
//! When Clash returns "ask" for a tool use, the user sees a permission prompt
//! in Claude Code's UI. If they accept, PostToolUse fires and we can suggest
//! a session-scoped allow rule for Claude to offer the user — so similar actions
//! can be pre-approved for the rest of the session.
//!
//! ## How it works
//!
//! 1. **PreToolUse returns Ask** → `record_pending_ask()` writes a marker file
//!    in the session directory keyed by `tool_use_id`.
//! 2. **PostToolUse fires** → `process_post_tool_use()` checks for a pending
//!    ask marker. If found, the user accepted the permission, so we suggest a
//!    session-scoped allow rule via advisory context — Claude can then offer the
//!    user the option to persist it for the session.
//!
//! Rules are NOT automatically written. Instead, Claude is given context about
//! the approval and a suggested `clash policy allow --scope session` command.
//! This lets the user decide whether to persist the permission with full control
//! over the rule's scope.

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::permissions::extract_noun;
use crate::policy::Effect;
use crate::policy::ast::{
    CapMatcher, ExecMatcher, FsMatcher, FsOp, NetMatcher, OpPattern, PathExpr, PathFilter, Pattern,
    Rule, ToolMatcher,
};
use crate::policy::eval::{extract_domain, resolve_path};

/// Directory within the session dir where pending ask markers are stored.
const PENDING_DIR: &str = "pending_asks";

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

/// Advisory context returned when a user approves a previously-asked permission.
///
/// Contains the suggested rule and a CLI command for Claude to offer the user.
#[derive(Debug, Clone)]
pub struct ApprovalAdvice {
    /// Human-readable description of what was approved (e.g., "git status").
    pub noun: String,
    /// The tool name that was approved.
    pub tool_name: String,
    /// The suggested allow rule as an s-expression string.
    pub suggested_rule: String,
    /// The full CLI command to add this as a session rule.
    pub cli_command: String,
}

impl ApprovalAdvice {
    /// Format as context text for injection into PostToolUse output.
    pub fn as_context(&self) -> String {
        format!(
            "The user just approved {} for \"{}\". \
             If they want to allow similar actions for the rest of this session, \
             you can suggest running:\n  {}\n\
             Always confirm with the user before adding session rules. \
             Use --dry-run first to preview the change.",
            self.tool_name, self.noun, self.cli_command,
        )
    }
}

/// Check if a PostToolUse event corresponds to a previously-asked permission
/// that the user accepted. If so, return advisory context suggesting a session
/// rule for Claude to offer the user.
///
/// Returns `Ok(Some(advice))` if the user approved a pending ask, `Ok(None)` if
/// there was no pending ask for this tool_use_id.
pub fn process_post_tool_use(
    tool_use_id: &str,
    session_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) -> Option<ApprovalAdvice> {
    let marker_path = pending_dir(session_id).join(sanitize_id(tool_use_id));

    // No pending ask for this tool use — nothing to do.
    if !marker_path.exists() {
        return None;
    }

    // Clean up the marker regardless of whether rule generation succeeds.
    let _ = std::fs::remove_file(&marker_path);

    info!(
        tool_use_id,
        tool_name, "User accepted permission — generating advisory context"
    );

    let rule = match suggest_allow_rule(tool_name, tool_input, cwd) {
        Some(r) => r,
        None => {
            debug!(tool_name, "Could not suggest allow rule for tool");
            return None;
        }
    };

    let rule_str = rule.to_string();
    let noun = extract_noun(tool_name, tool_input);
    let cli_command = format!("clash policy allow '{}' --scope session", rule_str);

    info!(rule = %rule_str, "Suggesting session rule for user approval");

    Some(ApprovalAdvice {
        noun,
        tool_name: tool_name.to_string(),
        suggested_rule: rule_str,
        cli_command,
    })
}

// ---------------------------------------------------------------------------
// Rule suggestion
// ---------------------------------------------------------------------------

/// Suggest a session-scoped allow rule from a tool invocation.
///
/// The rules aim for a reasonable balance between specificity and convenience.
/// For exec rules, we allow the binary with wildcard args (e.g., `git *`).
/// For fs rules, we scope to the parent directory.
/// For net rules, we scope to the specific domain.
pub fn suggest_allow_rule(
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) -> Option<Rule> {
    match tool_name {
        "Bash" => suggest_exec_rule(tool_input),
        "Read" | "Glob" | "Grep" => suggest_fs_read_rule(tool_input, cwd),
        "Write" | "Edit" | "NotebookEdit" => suggest_fs_write_rule(tool_input, cwd),
        "WebFetch" => suggest_net_rule(tool_input),
        "WebSearch" => Some(Rule {
            effect: Effect::Allow,
            matcher: CapMatcher::Net(NetMatcher {
                domain: Pattern::Any,
                path: None,
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

/// Suggest an exec allow rule from a Bash tool input.
///
/// Extracts the binary name and suggests it with wildcard args:
/// `(allow (exec "<bin>" *))`.
fn suggest_exec_rule(tool_input: &serde_json::Value) -> Option<Rule> {
    let command = tool_input.get("command")?.as_str()?;
    let parts: Vec<&str> = command.split_whitespace().collect();
    let bin = *parts.first()?;

    // Don't create rules for shell builtins or relative paths.
    if bin.is_empty() || bin.contains('/') && !bin.starts_with('/') {
        return None;
    }

    // Strip path prefix to get just the binary name.
    let bin_name = Path::new(bin).file_name()?.to_str()?;

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

/// Suggest a filesystem read rule from a Read/Glob/Grep tool input.
///
/// Suggests reading under the parent directory of the accessed path:
/// `(allow (fs read (subpath "<parent_dir>")))`.
fn suggest_fs_read_rule(tool_input: &serde_json::Value, cwd: &str) -> Option<Rule> {
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
            path: Some(PathFilter::Subpath(PathExpr::Static(parent), false)),
        }),
        sandbox: None,
    })
}

/// Suggest a filesystem write rule from a Write/Edit tool input.
///
/// Suggests read+write+create under the parent directory:
/// `(allow (fs (or read write create) (subpath "<parent_dir>")))`.
fn suggest_fs_write_rule(tool_input: &serde_json::Value, cwd: &str) -> Option<Rule> {
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
            path: Some(PathFilter::Subpath(PathExpr::Static(parent), false)),
        }),
        sandbox: None,
    })
}

/// Suggest a network allow rule from a WebFetch tool input.
///
/// Suggests access to the specific domain: `(allow (net "<domain>"))`.
fn suggest_net_rule(tool_input: &serde_json::Value) -> Option<Rule> {
    let url = tool_input.get("url")?.as_str()?;
    let domain = extract_domain(url);
    if domain.is_empty() {
        return None;
    }

    Some(Rule {
        effect: Effect::Allow,
        matcher: CapMatcher::Net(NetMatcher {
            domain: Pattern::Literal(domain),
            path: None,
        }),
        sandbox: None,
    })
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
    fn test_suggest_exec_rule_git() {
        let rule = suggest_allow_rule("Bash", &json!({"command": "git status"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("exec"), "expected exec rule, got: {s}");
        assert!(s.contains("\"git\""), "expected git binary, got: {s}");
        assert!(s.contains("*"), "expected wildcard args, got: {s}");
    }

    #[test]
    fn test_suggest_exec_rule_npm() {
        let rule =
            suggest_allow_rule("Bash", &json!({"command": "npm install express"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("\"npm\""), "expected npm binary, got: {s}");
    }

    #[test]
    fn test_suggest_exec_rule_absolute_path() {
        let rule =
            suggest_allow_rule("Bash", &json!({"command": "/usr/bin/git status"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("\"git\""), "should strip path prefix, got: {s}");
    }

    #[test]
    fn test_suggest_fs_read_rule() {
        let rule = suggest_allow_rule(
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
    fn test_suggest_fs_write_rule() {
        let rule = suggest_allow_rule(
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
    fn test_suggest_net_rule() {
        let rule = suggest_allow_rule(
            "WebFetch",
            &json!({"url": "https://github.com/foo/bar"}),
            "/tmp",
        )
        .unwrap();
        let s = rule.to_string();
        assert!(s.contains("net"), "expected net rule, got: {s}");
        assert!(s.contains("\"github.com\""), "expected domain, got: {s}");
    }

    #[test]
    fn test_suggest_websearch_rule() {
        let rule =
            suggest_allow_rule("WebSearch", &json!({"query": "rust async"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("net"), "expected net rule, got: {s}");
        // WebSearch allows any domain
        assert!(!s.contains('"'), "websearch should use wildcard, got: {s}");
    }

    #[test]
    fn test_suggest_tool_rule() {
        let rule = suggest_allow_rule("Task", &json!({"prompt": "do something"}), "/tmp").unwrap();
        let s = rule.to_string();
        assert!(s.contains("tool"), "expected tool rule, got: {s}");
        assert!(s.contains("\"Task\""), "expected Task name, got: {s}");
    }

    #[test]
    fn test_suggest_empty_command_returns_none() {
        let rule = suggest_allow_rule("Bash", &json!({"command": ""}), "/tmp");
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

        // Process the approval — should return advisory context.
        let result = process_post_tool_use(
            "toolu_01ABC",
            &session_id,
            "Bash",
            &json!({"command": "git status"}),
            "/tmp",
        );
        assert!(result.is_some(), "should have generated advice");
        let advice = result.unwrap();
        assert!(
            advice.suggested_rule.contains("git"),
            "rule should mention git"
        );
        assert!(
            advice.cli_command.contains("--scope session"),
            "command should include --scope session"
        );
        assert!(
            advice.cli_command.contains("clash policy allow"),
            "command should use clash policy allow"
        );

        // Marker should be cleaned up.
        assert!(
            !marker.exists(),
            "marker should be removed after processing"
        );

        // Session policy file should NOT exist (we no longer write automatically).
        let policy_path = session_dir.join("policy.sexpr");
        assert!(
            !policy_path.exists(),
            "session policy should NOT be created automatically"
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
            "toolu_nonexistent",
            &session_id,
            "Bash",
            &json!({"command": "ls"}),
            "/tmp",
        );
        assert!(result.is_none(), "should return None when no pending ask");

        let _ = std::fs::remove_dir_all(&session_dir);
    }

    #[test]
    fn test_approval_advice_context_format() {
        let advice = ApprovalAdvice {
            noun: "git status".to_string(),
            tool_name: "Bash".to_string(),
            suggested_rule: "(exec \"git\" *)".to_string(),
            cli_command: "clash policy allow '(exec \"git\" *)' --scope session".to_string(),
        };
        let ctx = advice.as_context();
        assert!(ctx.contains("Bash"), "should mention tool name");
        assert!(ctx.contains("git status"), "should mention noun");
        assert!(
            ctx.contains("--scope session"),
            "should mention session scope"
        );
        assert!(ctx.contains("--dry-run"), "should mention dry-run");
        assert!(ctx.contains("confirm"), "should mention confirmation");
    }

    #[test]
    fn test_sanitize_id() {
        assert_eq!(sanitize_id("toolu_01ABC"), "toolu_01ABC");
        assert_eq!(sanitize_id("foo/bar"), "foo_bar");
        assert_eq!(sanitize_id("a.b.c"), "a_b_c");
    }
}
