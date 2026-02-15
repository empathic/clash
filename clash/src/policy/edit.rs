//! Comment-preserving YAML editing for policy files.
//!
//! Not yet implemented for the v2 policy format. The public functions are
//! stubbed so that callers compile but bail at runtime until v2 editing
//! support is added.

use anyhow::{Result, bail};

/// CLI-provided inline constraints to attach below a rule.
#[derive(Debug, Default)]
pub struct InlineConstraintArgs {
    /// Filesystem constraints: `"caps:filter_expr"` pairs.
    /// e.g. `"full:subpath(~/Library/Caches)"`, `"read+write:subpath(.)"`.
    pub fs: Vec<String>,
    /// URL domain patterns: `"github.com"` (require), `"!evil.com"` (forbid).
    pub url: Vec<String>,
    /// Argument constraints: `"--dry-run"` (require), `"!-delete"` (forbid).
    pub args: Vec<String>,
    /// Allow piping (stdin/stdout redirection between commands).
    pub pipe: Option<bool>,
    /// Allow shell redirects (>, >>, <).
    pub redirect: Option<bool>,
    /// Network policy: "allow" or "deny".
    pub network: Option<String>,
}

impl InlineConstraintArgs {
    /// Returns true if there are no constraints to emit.
    pub fn is_empty(&self) -> bool {
        self.fs.is_empty()
            && self.url.is_empty()
            && self.args.is_empty()
            && self.pipe.is_none()
            && self.network.is_none()
            && self.redirect.is_none()
    }

    /// Validate that all `--fs` entries have the required `caps:filter` format.
    pub fn validate(&self) -> Result<()> {
        for entry in &self.fs {
            if entry.split_once(':').is_none() {
                bail!(
                    "invalid --fs value '{}': expected 'caps:filter_expr' \
                     (e.g. 'full:subpath(~/dir)', 'read+write:subpath(.)') ",
                    entry
                );
            }
        }
        Ok(())
    }
}

/// Add a rule to a profile's rules block, preserving comments.
/// Returns the modified YAML text.
pub fn add_rule(
    _yaml: &str,
    _profile: &str,
    _rule: &str,
    _constraints: &InlineConstraintArgs,
) -> Result<String> {
    bail!("not yet implemented for v2 policy format")
}

/// Remove a rule from a profile's rules block, preserving comments.
/// Returns the modified YAML text.
pub fn remove_rule(_yaml: &str, _profile: &str, _rule: &str) -> Result<String> {
    bail!("not yet implemented for v2 policy format")
}

/// Resolve the target profile: use the provided override or fall back to the active profile.
pub fn resolve_profile(_yaml: &str, _profile_override: Option<&str>) -> Result<String> {
    bail!("not yet implemented for v2 policy format")
}

/// Check whether the given YAML text uses the new profile-based format.
pub fn is_new_format(_yaml: &str) -> bool {
    // Stub: v2 format detection not yet implemented.
    false
}

/// Summary information about the policy for the `show` command.
pub struct PolicyInfo {
    pub default_permission: String,
    pub active_profile: String,
    pub profiles: Vec<String>,
}

/// Extract policy info from the YAML text.
pub fn policy_info(_yaml: &str) -> Result<PolicyInfo> {
    bail!("not yet implemented for v2 policy format")
}
