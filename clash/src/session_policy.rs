//! Detect permission acceptances and suggest session-level policy rules.
//!
//! When Clash returns "ask" for a tool use, the user sees a permission prompt.
//! If they accept, PostToolUse fires and we suggest a session-scoped allow rule
//! for Claude to offer the user.

use std::path::PathBuf;

use tracing::{debug, info, warn};

use crate::permissions::extract_noun;

/// Directory within the session dir where pending ask markers are stored.
const PENDING_DIR: &str = "pending_asks";

/// Record that we returned "ask" for a tool use.
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
#[derive(Debug, Clone)]
pub struct ApprovalAdvice {
    pub noun: String,
    pub tool_name: String,
    pub suggested_rule: String,
    pub cli_command: String,
}

impl ApprovalAdvice {
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
/// that the user accepted.
pub fn process_post_tool_use(
    tool_use_id: &str,
    session_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) -> Option<ApprovalAdvice> {
    let marker_path = pending_dir(session_id).join(sanitize_id(tool_use_id));

    if !marker_path.exists() {
        return None;
    }

    let _ = std::fs::remove_file(&marker_path);

    info!(
        tool_use_id,
        tool_name, "User accepted permission — generating advisory context"
    );

    let rule_desc = suggest_rule_description(tool_name, tool_input, cwd)?;
    let noun = extract_noun(tool_name, tool_input);
    let cli_command = format!("clash policy allow '{}' --scope session", rule_desc);

    info!(rule = %rule_desc, "Suggesting session rule for user approval");

    Some(ApprovalAdvice {
        noun,
        tool_name: tool_name.to_string(),
        suggested_rule: rule_desc,
        cli_command,
    })
}

/// Suggest a human-readable rule description from a tool invocation.
pub fn suggest_rule_description(
    tool_name: &str,
    tool_input: &serde_json::Value,
    _cwd: &str,
) -> Option<String> {
    use clash_starlark::codegen::builder::*;
    use clash_starlark::codegen::expr_to_string;

    match tool_name {
        "Bash" => {
            let command = tool_input.get("command")?.as_str()?;
            let parts: Vec<&str> = command.split_whitespace().collect();
            let bin = *parts.first()?;
            if bin.is_empty() {
                return None;
            }
            let bin_name = std::path::Path::new(bin).file_name()?.to_str()?;
            let expr = clash_starlark::match_tree! {
                "Bash" => {
                    bin_name => allow(),
                },
            };
            Some(expr_to_string(&expr))
        }
        "Read" | "Glob" | "Grep" => {
            let path = tool_input
                .get("file_path")
                .or_else(|| tool_input.get("path"))
                .and_then(|v| v.as_str())?;
            let parent = PathBuf::from(path).parent()?.to_string_lossy().to_string();
            let expr = tool_match(&[tool_name], allow());
            Some(format!("{} # path: {}", expr_to_string(&expr), parent))
        }
        "Write" | "Edit" | "NotebookEdit" => {
            let path = tool_input.get("file_path")?.as_str()?;
            let parent = PathBuf::from(path).parent()?.to_string_lossy().to_string();
            let expr = tool_match(&[tool_name], allow());
            Some(format!("{} # path: {}", expr_to_string(&expr), parent))
        }
        "WebFetch" => {
            let url = tool_input.get("url")?.as_str()?;
            let without_scheme = url
                .strip_prefix("https://")
                .or_else(|| url.strip_prefix("http://"))
                .unwrap_or(url);
            let domain = without_scheme.split('/').next().unwrap_or(without_scheme);
            let domain = domain.split(':').next().unwrap_or(domain);
            if domain.is_empty() {
                return None;
            }
            Some(expr_to_string(&net(domain)))
        }
        _ => Some(expr_to_string(&tool_match(&[tool_name], allow()))),
    }
}

fn pending_dir(session_id: &str) -> PathBuf {
    crate::session_dir::SessionDir::new(session_id)
        .root()
        .join(PENDING_DIR)
}

fn sanitize_id(id: &str) -> String {
    id.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_suggest_exec_rule() {
        let desc =
            suggest_rule_description("Bash", &json!({"command": "git status"}), "/tmp").unwrap();
        assert!(desc.contains("git"), "expected git, got: {desc}");
    }

    #[test]
    fn test_suggest_tool_rule() {
        let desc =
            suggest_rule_description("Task", &json!({"prompt": "do something"}), "/tmp").unwrap();
        assert!(desc.contains("Task"), "expected Task, got: {desc}");
    }

    #[test]
    fn test_suggest_empty_command_returns_none() {
        let desc = suggest_rule_description("Bash", &json!({"command": ""}), "/tmp");
        assert!(desc.is_none());
    }

    #[test]
    fn test_pending_ask_roundtrip() {
        let session_id = format!("test-pending-{}", std::process::id());
        let session_dir = crate::audit::session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&session_dir);
        std::fs::create_dir_all(&session_dir).unwrap();

        record_pending_ask(
            &session_id,
            "toolu_01ABC",
            "Bash",
            &json!({"command": "git status"}),
            "/tmp",
        );

        let marker = pending_dir(&session_id).join("toolu_01ABC");
        assert!(marker.exists());

        let result = process_post_tool_use(
            "toolu_01ABC",
            &session_id,
            "Bash",
            &json!({"command": "git status"}),
            "/tmp",
        );
        assert!(result.is_some());
        let advice = result.unwrap();
        assert!(advice.suggested_rule.contains("git"));
        assert!(advice.cli_command.contains("--scope session"));

        assert!(!marker.exists());
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
        assert!(result.is_none());

        let _ = std::fs::remove_dir_all(&session_dir);
    }

    #[test]
    fn test_approval_advice_context_format() {
        let advice = ApprovalAdvice {
            noun: "git status".to_string(),
            tool_name: "Bash".to_string(),
            suggested_rule: "match({\"Bash\": {\"git\"}})".to_string(),
            cli_command: "clash policy allow 'match({\"Bash\": {\"git\"}})' --scope session"
                .to_string(),
        };
        let ctx = advice.as_context();
        assert!(ctx.contains("Bash"));
        assert!(ctx.contains("git status"));
        assert!(ctx.contains("--scope session"));
        assert!(ctx.contains("--dry-run"));
        assert!(ctx.contains("confirm"));
    }

    #[test]
    fn test_sanitize_id() {
        assert_eq!(sanitize_id("toolu_01ABC"), "toolu_01ABC");
        assert_eq!(sanitize_id("foo/bar"), "foo_bar");
    }
}
