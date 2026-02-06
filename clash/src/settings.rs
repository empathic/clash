use std::path::PathBuf;

use crate::policy::CompiledPolicy;
use crate::policy::parse::desugar_claude_permissions;
use crate::policy::{ClaudePermissions, PolicyConfig, PolicyDocument};
use anyhow::Result;
use claude_settings::ClaudeSettings;
use dirs::home_dir;
use serde::Deserialize;
use tracing::{Level, info, instrument, warn};

use crate::audit::AuditConfig;
use crate::notifications::NotificationConfig;

#[derive(Debug, Default)]
pub struct ClashSettings {
    /// Parsed policy document loaded at runtime from policy.yaml or compiled from Claude settings.
    pub(crate) policy: Option<PolicyDocument>,

    /// Pre-compiled policy for fast evaluation. Compiled once during `load_or_create()`.
    compiled: Option<CompiledPolicy>,

    /// Notification and external service configuration, loaded from policy.yaml.
    pub notifications: NotificationConfig,

    /// Warning message if parsing the notifications config failed or was incomplete.
    pub notification_warning: Option<String>,

    /// Audit logging configuration, loaded from policy.yaml.
    pub audit: AuditConfig,

    /// Error message if policy.yaml failed to parse or compile.
    policy_error: Option<String>,
}

impl ClashSettings {
    pub fn settings_dir() -> Result<PathBuf> {
        home_dir()
            .map(|h| h.join(".clash"))
            .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot determine settings directory"))
    }

    pub fn policy_file() -> Result<PathBuf> {
        Self::settings_dir().map(|d| d.join("policy.yaml"))
    }

    /// Return the policy parse/compile error, if any.
    pub fn policy_error(&self) -> Option<&str> {
        self.policy_error.as_deref()
    }

    /// Set the policy document directly and recompile.
    ///
    /// This is useful for library consumers who want to construct settings
    /// programmatically without loading from disk.
    pub fn set_policy(&mut self, doc: PolicyDocument) {
        self.policy = Some(doc);
        self.compile_policy();
    }

    /// Try to load and compile the policy document from ~/.clash/policy.yaml.
    #[instrument(level = Level::TRACE, skip(self))]
    fn load_policy_file(&mut self) -> Option<PolicyDocument> {
        let path = match Self::policy_file() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Cannot determine policy file path");
                return None;
            }
        };
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    // Parse notification and audit configs from the same YAML file.
                    let (notif_config, notif_warning) = parse_notification_config(&contents);
                    self.notifications = notif_config;
                    self.notification_warning = notif_warning;
                    self.audit = parse_audit_config(&contents);

                    match crate::policy::parse::parse_yaml(&contents) {
                        Ok(doc) => {
                            info!(path = %path.display(), "Loaded policy document");
                            Some(doc)
                        }
                        Err(e) => {
                            let msg = format!("Failed to parse policy.yaml: {}", e);
                            warn!(path = %path.display(), error = %e, "Failed to parse policy.yaml");
                            self.policy_error = Some(msg);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to read policy.yaml");
                    None
                }
            }
        } else {
            None
        }
    }

    /// Compile Claude Code's permissions into a PolicyDocument.
    ///
    /// Reads Claude settings via ClaudeSettings::new().effective(), converts the
    /// PermissionSet to ClaudePermissions, and desugars into policy Statements.
    #[instrument(level = Level::TRACE)]
    fn compile_claude_to_policy() -> Option<PolicyDocument> {
        let effective = match ClaudeSettings::new().effective() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "Failed to load Claude Code settings for policy compilation");
                return None;
            }
        };

        let perms = effective.permissions.to_permissions();
        let claude_perms = ClaudePermissions {
            allow: perms.allow,
            deny: perms.deny,
            ask: perms.ask,
        };

        let statements = desugar_claude_permissions(&claude_perms);
        if statements.is_empty() {
            info!("No Claude permissions found; compiled policy has no statements");
        }

        Some(PolicyDocument {
            policy: PolicyConfig::default(),
            permissions: None,
            constraints: Default::default(),
            profiles: Default::default(),
            statements,
            default_config: None,
            profile_defs: Default::default(),
        })
    }

    /// Resolve the policy: use policy.yaml if it exists, else compile Claude settings.
    #[instrument(level = Level::TRACE, skip(self))]
    fn resolve_policy(&mut self) {
        self.policy = self
            .load_policy_file()
            .or_else(Self::compile_claude_to_policy);
    }

    /// Return the pre-compiled policy, if one was successfully compiled during loading.
    pub fn compiled_policy(&self) -> Option<&CompiledPolicy> {
        self.compiled.as_ref()
    }

    /// Compile the policy document (if present) and cache the result.
    fn compile_policy(&mut self) {
        self.compiled = self
            .policy
            .as_ref()
            .and_then(|doc| match CompiledPolicy::compile(doc) {
                Ok(compiled) => Some(compiled),
                Err(e) => {
                    let msg = format!("Failed to compile policy: {}", e);
                    warn!(error = %e, "Failed to compile policy document");
                    self.policy_error = Some(msg);
                    None
                }
            });
    }

    /// Load settings by resolving the policy from disk and compiling it.
    #[instrument(level = Level::TRACE)]
    pub fn load_or_create() -> Result<Self> {
        let mut this = Self::default();
        this.resolve_policy();
        this.compile_policy();
        Ok(this)
    }
}

/// Extract the `notifications:` section from a policy YAML string.
///
/// This is parsed independently of the policy rules so that the notification
/// config doesn't need to live in the `claude_settings` library.
///
/// Returns the parsed config (falling back to defaults on error) and an
/// optional warning message if parsing failed.
pub fn parse_notification_config(yaml_str: &str) -> (NotificationConfig, Option<String>) {
    #[derive(Deserialize)]
    struct RawYaml {
        #[serde(default)]
        notifications: Option<NotificationConfig>,
    }

    match serde_yaml::from_str::<RawYaml>(yaml_str) {
        Ok(raw) => (raw.notifications.unwrap_or_default(), None),
        Err(e) => {
            let warning = format!("notifications config parse error: {}", e);
            warn!(error = %e, "Failed to parse notifications config from policy.yaml");
            (NotificationConfig::default(), Some(warning))
        }
    }
}

/// Default policy template written by `clash init`.
pub const DEFAULT_POLICY: &str = include_str!("default_policy.yaml");

/// Extract the `audit:` section from a policy YAML string.
///
/// Returns the parsed config, falling back to defaults on error.
fn parse_audit_config(yaml_str: &str) -> AuditConfig {
    #[derive(Deserialize)]
    struct RawYaml {
        #[serde(default)]
        audit: Option<AuditConfig>,
    }

    match serde_yaml::from_str::<RawYaml>(yaml_str) {
        Ok(raw) => raw.audit.unwrap_or_default(),
        Err(_) => AuditConfig::default(),
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn default_policy_parses() -> anyhow::Result<()> {
        let pol = crate::policy::parse::parse_yaml(super::DEFAULT_POLICY)?;
        assert!(pol.profile_defs.len() > 0, "{pol:#?}");
        Ok(())
    }
}
