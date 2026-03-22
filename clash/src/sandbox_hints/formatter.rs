//! Hint message formatting and suggestion generation.
//!
//! Builds the advisory context string that is returned to Claude when sandbox
//! filesystem violations are detected. The hint includes a description of the
//! problem and actionable `clash sandbox add-rule` commands for each blocked path.

use crate::policy::sandbox_types::Cap;

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
pub(crate) fn build_fs_hint(blocked: &[BlockedPath]) -> String {
    let mut lines =
        vec!["SANDBOX_FS_HINT: Command failed — sandbox is blocking filesystem access.".into()];

    // Generate specific `clash sandbox add-rule` commands for each blocked path.
    for bp in blocked {
        lines.push(format!(
            "To allow: clash sandbox add-rule --name <SANDBOX> --path \"{}\" --allow \"read + write + create\"",
            bp.suggested_dir
        ));
    }

    lines.push("Do NOT retry — it will fail again until the policy is updated.".into());

    lines.join("\n")
}
