//! Hint message formatting and suggestion generation.
//!
//! Builds the advisory context string that is returned to Claude when sandbox
//! filesystem violations are detected. The hint includes a description of the
//! problem and actionable `clash sandbox add-rule` commands for each blocked path.

use crate::policy::sandbox_types::{Cap, ViolationAction};

/// A filesystem path that was blocked by the sandbox.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct BlockedPath {
    /// The actual file path from the error message.
    pub path: String,
    /// The parent directory to suggest allowing access to.
    pub suggested_dir: String,
    /// What capabilities the sandbox currently grants for this path.
    pub current_caps: Cap,
}

/// Build advisory context for Claude when a sandbox blocks filesystem access.
pub(crate) fn build_fs_hint(
    sandbox_name: &str,
    blocked: &[BlockedPath],
    action: ViolationAction,
) -> String {
    let mut lines = vec![format!(
        "SANDBOX VIOLATION: sandbox \"{sandbox_name}\" blocked filesystem access."
    )];

    for bp in blocked {
        let grants = format_caps(bp.current_caps);
        lines.push(format!("- write to {} (sandbox grants: {grants})", bp.path));
    }

    lines.push(String::new());
    lines.push("To fix:".into());
    for bp in blocked {
        let needed = needed_caps_string(bp.current_caps);
        lines.push(format!(
            "  clash sandbox add-rule --name {sandbox_name} --path '{}' --allow '{needed}'",
            bp.suggested_dir
        ));
    }

    lines.push(String::new());
    lines.push(directive_text(action).into());

    lines.join("\n")
}

fn format_caps(caps: Cap) -> String {
    let mut parts = Vec::new();
    if caps.contains(Cap::READ) { parts.push("read"); }
    if caps.contains(Cap::WRITE) { parts.push("write"); }
    if caps.contains(Cap::CREATE) { parts.push("create"); }
    if caps.contains(Cap::DELETE) { parts.push("delete"); }
    if caps.contains(Cap::EXECUTE) { parts.push("execute"); }
    if parts.is_empty() { "none".into() } else { parts.join("+") }
}

fn needed_caps_string(current: Cap) -> String {
    let mut needed = vec!["read", "write", "create"];
    if current.contains(Cap::EXECUTE) {
        needed.push("execute");
    }
    needed.join("+")
}

/// Get the directive text for a given violation action.
///
/// Shared by both filesystem and network hint builders.
pub(crate) fn directive_text(action: ViolationAction) -> &'static str {
    match action {
        ViolationAction::Stop => {
            "Do NOT retry — it will fail again. Fix the policy first, then re-run the command."
        }
        ViolationAction::Workaround => {
            "The sandbox restricts this path. Try an alternative approach to accomplish your goal \
             without accessing these paths. If no workaround is possible, tell the user and suggest \
             the policy fix above."
        }
        ViolationAction::Smart => {
            "Assess: if these paths look like missing dependencies or build artifacts, suggest the \
             policy fix above. If they look like paths outside the project's scope, find an \
             alternative approach instead."
        }
    }
}
