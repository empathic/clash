//! Test environment setup for clester.
//!
//! Creates isolated temp directories with the correct settings file
//! hierarchy so clash reads controlled configuration during tests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tempfile::TempDir;

use crate::script::{SettingsConfig, SettingsSpec};

/// An isolated test environment with controlled HOME and project directories.
pub struct TestEnvironment {
    /// The temp directory that owns the filesystem (dropped = cleaned up).
    _temp: TempDir,

    /// Path to the fake HOME directory.
    pub home_dir: PathBuf,

    /// Path to the fake project directory.
    pub project_dir: PathBuf,
}

impl TestEnvironment {
    /// Create a new test environment from the settings configuration.
    pub fn setup(settings: &SettingsConfig) -> Result<Self> {
        let temp = TempDir::new().context("failed to create temp directory")?;
        let base = temp.path();

        let home_dir = base.join("home");
        let project_dir = base.join("project");

        // Create directory structure
        std::fs::create_dir_all(home_dir.join(".claude")).context("failed to create ~/.claude")?;
        std::fs::create_dir_all(home_dir.join(".clash")).context("failed to create ~/.clash")?;
        std::fs::create_dir_all(project_dir.join(".claude")).context("failed to create .claude")?;
        // Also create a .git dir so PathResolver finds the project root
        std::fs::create_dir_all(project_dir.join(".git")).context("failed to create .git")?;

        // Write settings files
        if let Some(ref user) = settings.user {
            let path = home_dir.join(".claude/settings.json");
            write_settings_file(&path, user)?;
        }

        if let Some(ref project) = settings.project {
            let path = project_dir.join(".claude/settings.json");
            write_settings_file(&path, project)?;
        }

        if let Some(ref project_local) = settings.project_local {
            let path = project_dir.join(".claude/settings.local.json");
            write_settings_file(&path, project_local)?;
        }

        // Also write the clash settings file (which wraps claude settings).
        // Clash loads its own settings from ~/.clash/settings.json and then
        // merges in claude settings. We write a minimal clash settings file.
        let clash_settings_path = home_dir.join(".clash/settings.json");
        std::fs::write(&clash_settings_path, "{}").context("failed to write clash settings")?;

        Ok(Self {
            _temp: temp,
            home_dir,
            project_dir,
        })
    }
}

/// Convert a SettingsSpec into a Claude Code settings JSON and write it.
fn write_settings_file(path: &Path, spec: &SettingsSpec) -> Result<()> {
    let mut settings = serde_json::Map::new();

    if let Some(ref perms) = spec.permissions {
        let mut perm_obj = serde_json::Map::new();

        if !perms.allow.is_empty() {
            perm_obj.insert(
                "allow".into(),
                serde_json::Value::Array(
                    perms
                        .allow
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        if !perms.deny.is_empty() {
            perm_obj.insert(
                "deny".into(),
                serde_json::Value::Array(
                    perms
                        .deny
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        if !perms.ask.is_empty() {
            perm_obj.insert(
                "ask".into(),
                serde_json::Value::Array(
                    perms
                        .ask
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }

        settings.insert("permissions".into(), serde_json::Value::Object(perm_obj));
    }

    if let Some(ref model) = spec.model {
        settings.insert("model".into(), serde_json::Value::String(model.clone()));
    }

    if let Some(ref env) = spec.env {
        let env_obj: serde_json::Map<String, serde_json::Value> = env
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        settings.insert("env".into(), serde_json::Value::Object(env_obj));
    }

    let json = serde_json::to_string_pretty(&settings)?;
    std::fs::write(path, json).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{PermissionsSpec, SettingsConfig, SettingsSpec};

    #[test]
    fn test_setup_creates_directories() {
        let config = SettingsConfig {
            user: Some(SettingsSpec {
                permissions: Some(PermissionsSpec {
                    allow: vec!["Bash(git:*)".into()],
                    deny: vec![],
                    ask: vec![],
                }),
                model: None,
                env: None,
            }),
            project: None,
            project_local: None,
        };

        let env = TestEnvironment::setup(&config).unwrap();
        assert!(env.home_dir.join(".claude/settings.json").exists());
        assert!(env.project_dir.join(".claude").exists());
        assert!(env.project_dir.join(".git").exists());
    }

    #[test]
    fn test_settings_file_content() {
        let config = SettingsConfig {
            user: Some(SettingsSpec {
                permissions: Some(PermissionsSpec {
                    allow: vec!["Bash(git:*)".into()],
                    deny: vec!["Read(.env)".into()],
                    ask: vec![],
                }),
                model: Some("test-model".into()),
                env: None,
            }),
            project: None,
            project_local: None,
        };

        let env = TestEnvironment::setup(&config).unwrap();
        let content = std::fs::read_to_string(env.home_dir.join(".claude/settings.json")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert!(
            parsed["permissions"]["allow"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("Bash(git:*)".into()))
        );
        assert_eq!(parsed["model"], "test-model");
    }
}
