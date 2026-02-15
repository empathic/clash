//! Interactive policy configuration wizard.
//!
//! Not yet implemented for the v2 policy format.

use anyhow::Result;

/// Run the interactive wizard, returning the modified policy text.
pub fn run(_yaml: &str, _profile: &str, _cwd: &str) -> Result<String> {
    anyhow::bail!("interactive wizard not yet implemented for v2 policy format")
}
