//! Policy file discovery and default policy compilation.

use std::path::PathBuf;

use anyhow::{Context, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};

/// Policy level — where a policy file lives in the precedence hierarchy.
///
/// Higher-precedence levels override lower ones: Session > Project > User.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyLevel {
    /// User-level policy: `~/.clash/policy.json` (or `policy.star`)
    User = 0,
    /// Project-level policy: `<project_root>/.clash/policy.json` (or `policy.star`)
    Project = 1,
    /// Session-level policy: `/tmp/clash-<session_id>/policy.star`
    /// Temporary rules that last only for the current Claude Code session.
    Session = 2,
}

impl PolicyLevel {
    /// All persistent levels in precedence order (highest first).
    /// Session is excluded because it requires a session_id to resolve.
    pub fn all_by_precedence() -> &'static [PolicyLevel] {
        &[PolicyLevel::Project, PolicyLevel::User]
    }

    /// Display name for this level.
    pub fn name(&self) -> &'static str {
        match self {
            PolicyLevel::User => "user",
            PolicyLevel::Project => "project",
            PolicyLevel::Session => "session",
        }
    }
}

impl std::fmt::Display for PolicyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for PolicyLevel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "user" => Ok(PolicyLevel::User),
            "project" => Ok(PolicyLevel::Project),
            "session" => Ok(PolicyLevel::Session),
            _ => anyhow::bail!(
                "unknown policy level: {s} (expected 'user', 'project', or 'session')"
            ),
        }
    }
}

/// Default policy source template embedded at compile time.
/// Contains `{preset}` placeholders for the sandbox preset name.
pub const DEFAULT_POLICY_TEMPLATE: &str = include_str!("../default_policy.star");

/// Available sandbox presets for `clash init`.
pub const SANDBOX_PRESETS: &[SandboxPreset] = &[
    SandboxPreset {
        name: "dev",
        description: "Build tools, git — read+write project, read home, no network",
    },
    SandboxPreset {
        name: "dev_network",
        description: "Package managers, gh — read+write project, full network",
    },
    SandboxPreset {
        name: "read_only",
        description: "Linters, analyzers — read project + home, no writes outside temp",
    },
    SandboxPreset {
        name: "restricted",
        description: "Untrusted scripts — read-only project, no network",
    },
    SandboxPreset {
        name: "unrestricted",
        description: "Fully trusted — all filesystem + network access",
    },
];

/// A sandbox preset that can be selected during `clash init`.
pub struct SandboxPreset {
    pub name: &'static str,
    pub description: &'static str,
}

impl crate::dialog::SelectItem for SandboxPreset {
    fn label(&self) -> &str {
        self.name
    }
    fn description(&self) -> &str {
        self.description
    }
    fn variants() -> &'static [Self] {
        SANDBOX_PRESETS
    }
}

/// Compile the default policy with the given sandbox preset to JSON.
///
/// Substitutes `{preset}` in the template with the chosen preset name,
/// then evaluates the Starlark source and returns pretty-printed JSON.
pub fn compile_default_policy_to_json_with_preset(preset: &str) -> Result<String> {
    let source = DEFAULT_POLICY_TEMPLATE.replace("{preset}", preset);
    let output =
        clash_starlark::evaluate(&source, "<default_policy>", std::path::Path::new("."))
            .with_context(|| format!("failed to compile default policy with preset '{preset}'"))?;
    let value: serde_json::Value =
        serde_json::from_str(&output.json).context("default policy produced invalid JSON")?;
    serde_json::to_string_pretty(&value).context("failed to pretty-print default policy JSON")
}

/// Compile the default policy with the `dev` preset (used for auto-creation).
pub fn compile_default_policy_to_json() -> Result<String> {
    compile_default_policy_to_json_with_preset("dev")
}

/// Returns the clash settings directory (`~/.clash/`).
///
/// Respects `CLASH_HOME` env var for override, otherwise defaults to `$HOME/.clash`.
pub fn settings_dir() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CLASH_HOME") {
        return Ok(PathBuf::from(p));
    }
    home_dir()
        .map(|h| h.join(".clash"))
        .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot determine settings directory"))
}

/// Returns the user-level policy file path.
///
/// Respects `CLASH_POLICY_FILE` env var for override.
/// Prefers `policy.json` over `policy.star` when both exist.
pub fn policy_file() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CLASH_POLICY_FILE") {
        return Ok(PathBuf::from(p));
    }
    let dir = settings_dir()?;
    Ok(prefer_json_over_star(&dir))
}

/// Returns the project-level policy file path.
///
/// Prefers `policy.json` over `policy.star` when both exist.
pub fn project_policy_file(project_root: &std::path::Path) -> PathBuf {
    let dir = project_root.join(".clash");
    prefer_json_over_star(&dir)
}

/// Returns the session-level policy file path for the given session ID.
pub fn session_policy_file(session_id: &str) -> PathBuf {
    crate::session_dir::SessionDir::new(session_id).policy()
}

/// Return `policy.json` if it exists in `dir`, otherwise `policy.star`.
pub(crate) fn prefer_json_over_star(dir: &std::path::Path) -> PathBuf {
    let json_path = dir.join("policy.json");
    if json_path.exists() {
        json_path
    } else {
        dir.join("policy.star")
    }
}

/// Shorten a path by replacing the home directory prefix with `~`.
pub(crate) fn tilde_path(path: &std::path::Path) -> String {
    if let Some(home) = home_dir()
        && let Ok(rest) = path.strip_prefix(&home)
    {
        return format!("~/{}", rest.display());
    }
    path.display().to_string()
}

/// Find the nearest ancestor directory containing the given name.
///
/// If `stop_at` is provided, stops searching before checking that directory.
/// This prevents `~/.clash/` from being mistaken for a project root.
pub(crate) fn find_ancestor_with(
    start: &std::path::Path,
    name: &str,
    stop_at: Option<&std::path::Path>,
) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        if let Some(boundary) = stop_at
            && current == boundary
        {
            return None;
        }
        if current.join(name).exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Evaluate a `.star` policy file and return the compiled JSON source.
///
/// Delegates to [`policy_loader::evaluate_star_policy`]. This wrapper is kept
/// for backward compatibility with callers that import from `settings`.
pub fn evaluate_star_policy(path: &std::path::Path) -> Result<String> {
    crate::policy_loader::evaluate_star_policy(path)
}

/// Evaluate a policy file (`.json` or `.star`) and return the compiled JSON source.
///
/// Dispatches based on file extension: `.json` → [`policy_loader::load_json_policy`],
/// `.star` (or anything else) → [`policy_loader::evaluate_star_policy`].
pub fn evaluate_policy_file(path: &std::path::Path) -> Result<String> {
    if path.extension().is_some_and(|ext| ext == "json") {
        crate::policy_loader::load_json_policy(path)
    } else {
        crate::policy_loader::evaluate_star_policy(path)
    }
}

/// Extract the `notifications:` section from a YAML string.
///
/// Returns the parsed config (falling back to defaults on error) and an
/// optional warning message if parsing failed.
pub fn parse_notification_config(yaml_str: &str) -> (crate::notifications::NotificationConfig, Option<String>) {
    use serde::Deserialize;
    use tracing::warn;

    #[derive(Deserialize)]
    struct RawYaml {
        #[serde(default)]
        notifications: Option<crate::notifications::NotificationConfig>,
    }

    match serde_yaml::from_str::<RawYaml>(yaml_str) {
        Ok(raw) => (raw.notifications.unwrap_or_default(), None),
        Err(e) => {
            let warning = format!("notifications config parse error: {}", e);
            warn!(error = %e, "Failed to parse notifications config");
            (crate::notifications::NotificationConfig::default(), Some(warning))
        }
    }
}

/// Extract the `audit:` section from a YAML string.
///
/// Returns the parsed config, falling back to defaults on error.
pub(crate) fn parse_audit_config(yaml_str: &str) -> crate::audit::AuditConfig {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct RawYaml {
        #[serde(default)]
        audit: Option<crate::audit::AuditConfig>,
    }

    match serde_yaml::from_str::<RawYaml>(yaml_str) {
        Ok(raw) => raw.audit.unwrap_or_default(),
        Err(_) => crate::audit::AuditConfig::default(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[allow(dead_code)]
    struct TestEnv;
    impl crate::policy::compile::EnvResolver for TestEnv {
        fn resolve(&self, name: &str) -> anyhow::Result<String> {
            match name {
                "PWD" => Ok("/tmp".into()),
                "HOME" => Ok("/tmp/home".into()),
                "TMPDIR" => Ok("/tmp".into()),
                other => anyhow::bail!("unknown env var in test: {other}"),
            }
        }
    }

    #[test]
    fn default_policy_compiles() -> anyhow::Result<()> {
        let source = DEFAULT_POLICY_TEMPLATE.replace("{preset}", "dev");
        let output =
            clash_starlark::evaluate(&source, "default_policy.star", std::path::Path::new("."))?;
        let tree = crate::policy::compile::compile_to_tree(&output.json)?;
        let _ = tree;
        Ok(())
    }

    #[test]
    fn default_policy_compiles_all_presets() -> anyhow::Result<()> {
        for preset in SANDBOX_PRESETS {
            compile_default_policy_to_json_with_preset(preset.name)?;
        }
        Ok(())
    }

    #[test]
    fn default_policy_cwd_sandbox_uses_subpath() -> anyhow::Result<()> {
        let json_str = compile_default_policy_to_json_with_preset("dev")?;
        let policy: serde_json::Value = serde_json::from_str(&json_str)?;
        let cwd_sandbox = &policy["sandboxes"]["cwd"];
        let rules = cwd_sandbox["rules"].as_array().unwrap();
        // The $PWD rule should be subpath (from .recurse()), not literal.
        let pwd_rule = rules
            .iter()
            .find(|r| r["path"].as_str() == Some("$PWD"))
            .expect("should have a $PWD rule");
        assert_eq!(
            pwd_rule["path_match"].as_str(),
            Some("subpath"),
            "cwd() with .recurse() should produce subpath match, got: {pwd_rule}"
        );
        Ok(())
    }
}
