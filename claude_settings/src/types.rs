//! Type definitions for Claude Code settings.
//!
//! This module contains all the data structures used to represent
//! Claude Code settings at various levels (user, project, system).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::permission;

/// The main settings structure for Claude Code.
///
/// This represents the full schema of a Claude Code settings file,
/// supporting all configuration options available at user and project levels.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    /// Tool permission configuration controlling what Claude Code can access.
    #[serde(default, skip_serializing_if = "permission::PermissionSet::is_empty")]
    pub permissions: permission::PermissionSet,

    /// Environment variables to set for tool execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,

    /// Override the default Claude model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Hook configurations for pre/post tool execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,

    /// Sandbox configuration for command execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<Sandbox>,

    /// Attribution settings for git commits and PRs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,

    /// Map of enabled plugins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled_plugins: Option<HashMap<String, bool>>,

    /// Number of days before session cleanup (default: 30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_period_days: Option<u32>,

    /// Preferred response language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,

    /// Any additional fields not explicitly defined.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Tool permission configuration.
///
/// Controls which tools Claude Code is allowed to use, which require
/// user confirmation, and which are explicitly denied.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Permissions {
    /// Tools that are always allowed without confirmation.
    /// Format: "ToolName(pattern:*)" or just "ToolName"
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,

    /// Tools that require user confirmation before use.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ask: Vec<String>,

    /// Tools that are explicitly denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
}

/// Hook configurations for various lifecycle events.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Hooks {
    /// Hooks that run before a tool is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_tool_use: Option<HookConfig>,

    /// Hooks that run after a tool is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_tool_use: Option<HookConfig>,

    /// Hooks that run when Claude Code stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<HookMatcher>>,

    /// Hooks that run on notification events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification: Option<HookConfig>,
}

/// Hook configuration that can be either a simple command map or a list of matchers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HookConfig {
    /// Simple map of tool name to command.
    Simple(HashMap<String, String>),
    /// List of hook matchers with patterns.
    Matchers(Vec<HookMatcher>),
}

impl HookConfig {
    // FIXME(eliot): super gross but we probably should re-write any existing hook configs
    // into Matcher based hook configs.
    pub fn insert(self, pat: &str, command: &str) -> Self {
        match self {
            HookConfig::Simple(hash_map) => Self::Matchers(
                hash_map
                    .into_iter()
                    .map(|(pat, cmd)| HookMatcher {
                        matcher: pat,
                        hooks: vec![Hook {
                            hook_type: "command".into(),
                            command: Some(cmd),
                            timeout: None,
                        }],
                    })
                    .collect(),
            )
            .insert(pat, command),
            HookConfig::Matchers(mut hook_matchers) => {
                let mut found = false;
                for hm in &mut hook_matchers {
                    if hm.matcher == pat {
                        hm.hooks.push(Hook {
                            hook_type: "command".into(),
                            command: Some(command.into()),
                            timeout: None,
                        });
                        found = true;
                    }
                }
                if !found {
                    hook_matchers.push(HookMatcher {
                        matcher: pat.into(),
                        hooks: vec![Hook {
                            hook_type: "command".into(),
                            command: Some(command.into()),
                            timeout: None,
                        }],
                    });
                }
                Self::Matchers(hook_matchers)
            }
        }
    }
}

impl Default for HookConfig {
    fn default() -> Self {
        Self::Simple(HashMap::new())
    }
}

/// A hook matcher that triggers hooks based on patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookMatcher {
    /// Pattern to match against (empty string matches all).
    #[serde(default)]
    pub matcher: String,

    /// List of hooks to execute when pattern matches.
    #[serde(default)]
    pub hooks: Vec<Hook>,
}

/// A single hook definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hook {
    /// The type of hook (e.g., "command").
    #[serde(rename = "type")]
    pub hook_type: String,

    /// The command to execute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Timeout in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Sandbox configuration for command execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Sandbox {
    /// Whether sandboxing is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Automatically allow bash commands when sandboxed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_allow_bash_if_sandboxed: Option<bool>,

    /// Commands excluded from sandboxing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_commands: Option<Vec<String>>,
}

/// Attribution settings for git operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Attribution {
    /// Message to include in git commits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,

    /// Message to include in pull requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pr: Option<String>,
}

/// Represents the scope/level at which settings are applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingsLevel {
    /// System-wide managed settings (highest priority, typically read-only).
    /// Location: /etc/claude-code/managed-settings.json
    System,

    /// Project-level local settings (not committed to version control).
    /// Location: .claude/settings.local.json
    ProjectLocal,

    /// Project-level shared settings (committed to version control).
    /// Location: .claude/settings.json
    Project,

    /// User-level settings (personal defaults).
    /// Location: ~/.claude/settings.json
    User,
}

impl SettingsLevel {
    /// Returns all levels in order of priority (highest to lowest).
    pub fn all_by_priority() -> &'static [SettingsLevel] {
        &[
            SettingsLevel::System,
            SettingsLevel::ProjectLocal,
            SettingsLevel::Project,
            SettingsLevel::User,
        ]
    }

    /// Returns the display name for this level.
    pub fn name(&self) -> &'static str {
        match self {
            SettingsLevel::System => "system",
            SettingsLevel::ProjectLocal => "project-local",
            SettingsLevel::Project => "project",
            SettingsLevel::User => "user",
        }
    }
}

impl Settings {
    /// Creates a new empty Settings instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a Settings instance with the specified permissions.
    pub fn with_permissions(mut self, permissions: permission::PermissionSet) -> Self {
        self.permissions = permissions;
        self
    }

    /// Creates a Settings instance with the specified environment variables.
    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = Some(env);
        self
    }

    /// Creates a Settings instance with the specified model.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Creates a Settings instance with the specified hooks.
    pub fn with_hooks(mut self, hooks: Hooks) -> Self {
        self.hooks = Some(hooks);
        self
    }

    /// Creates a Settings instance with the specified sandbox configuration.
    pub fn with_sandbox(mut self, sandbox: Sandbox) -> Self {
        self.sandbox = Some(sandbox);
        self
    }

    /// Creates a Settings instance with the specified attribution.
    pub fn with_attribution(mut self, attribution: Attribution) -> Self {
        self.attribution = Some(attribution);
        self
    }

    /// Returns true if all fields are None or empty.
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
            && self.env.is_none()
            && self.model.is_none()
            && self.hooks.is_none()
            && self.sandbox.is_none()
            && self.attribution.is_none()
            && self.enabled_plugins.is_none()
            && self.cleanup_period_days.is_none()
            && self.language.is_none()
            && self.extra.is_empty()
    }

    /// The key used in `extra` to track clash installation status.
    const CLASH_INSTALLED_KEY: &'static str = "_clashInstalled";

    /// Returns true if these settings were installed by clash.
    ///
    /// This checks for the presence of the `_clashInstalled` marker field.
    pub fn is_clash_installed(&self) -> bool {
        self.extra
            .get(Self::CLASH_INSTALLED_KEY)
            .is_some_and(|v| v.as_bool().unwrap_or(false))
    }

    /// Marks these settings as installed by clash.
    ///
    /// This sets the `_clashInstalled` field to `true`.
    pub fn mark_clash_installed(&mut self) {
        self.extra.insert(
            Self::CLASH_INSTALLED_KEY.to_string(),
            serde_json::json!(true),
        );
    }

    /// Clears the clash installation marker from these settings.
    pub fn clear_clash_installed(&mut self) {
        self.extra.remove(Self::CLASH_INSTALLED_KEY);
    }

    /// Builder method to mark settings as clash-installed.
    pub fn with_clash_installed(mut self) -> Self {
        self.mark_clash_installed();
        self
    }
}

impl Permissions {
    /// Creates a new empty Permissions instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a tool pattern to the allow list.
    pub fn allow(mut self, pattern: impl Into<String>) -> Self {
        self.allow.push(pattern.into());
        self
    }

    /// Adds a tool pattern to the ask list.
    pub fn ask(mut self, pattern: impl Into<String>) -> Self {
        self.ask.push(pattern.into());
        self
    }

    /// Adds a tool pattern to the deny list.
    pub fn deny(mut self, pattern: impl Into<String>) -> Self {
        self.deny.push(pattern.into());
        self
    }

    /// Returns true if all lists are empty.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.ask.is_empty() && self.deny.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::PermissionSet;

    use super::*;

    #[test]
    fn test_settings_serialization() {
        let settings = Settings::new()
            .with_model("claude-opus-4-5-20251101")
            .with_permissions(PermissionSet::new().allow("Bash(git:*)").deny("Read(.env)"));

        let json = serde_json::to_string_pretty(&settings).unwrap();
        let parsed: Settings = serde_json::from_str(&json).unwrap();

        assert_eq!(settings, parsed);
        assert_eq!(parsed.model.unwrap(), "claude-opus-4-5-20251101");
    }

    #[test]
    fn test_permissions_builder() {
        let perms = Permissions::new()
            .allow("Bash(git diff:*)")
            .allow("Bash(npm run:*)")
            .deny("Read(.env)")
            .ask("Bash(rm:*)");

        assert_eq!(perms.allow.len(), 2);
        assert_eq!(perms.deny.len(), 1);
        assert_eq!(perms.ask.len(), 1);
    }

    #[test]
    fn test_settings_level_priority() {
        let levels = SettingsLevel::all_by_priority();
        assert_eq!(levels[0], SettingsLevel::System);
        assert_eq!(levels[3], SettingsLevel::User);
    }

    #[test]
    fn test_empty_settings() {
        let settings = Settings::new();
        assert!(settings.is_empty());

        let settings_with_model = Settings::new().with_model("test");
        assert!(!settings_with_model.is_empty());
    }

    #[test]
    fn test_clash_installed_marker() {
        let settings = Settings::new();
        assert!(!settings.is_clash_installed());

        let settings = Settings::new().with_clash_installed();
        assert!(settings.is_clash_installed());

        let mut settings = Settings::new();
        settings.mark_clash_installed();
        assert!(settings.is_clash_installed());

        settings.clear_clash_installed();
        assert!(!settings.is_clash_installed());
    }

    #[test]
    fn test_clash_installed_serialization() {
        let settings = Settings::new()
            .with_model("test-model")
            .with_clash_installed();

        let json = serde_json::to_string(&settings).unwrap();
        assert!(json.contains("_clashInstalled"));

        let parsed: Settings = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_clash_installed());
        assert_eq!(parsed.model.as_deref(), Some("test-model"));
    }
}
