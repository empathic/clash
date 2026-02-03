use std::path::PathBuf;

use anyhow::Result;
use claude_settings::policy::CompiledPolicy;
use claude_settings::policy::parse::parse_yaml;
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use tracing::{Level, info, instrument, warn};

use crate::audit::AuditConfig;
use crate::notifications::NotificationConfig;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ClashSettings {
    /// Parsed policy document (not serialized — loaded at runtime from policy.yaml).
    #[serde(skip)]
    pub(crate) policy: Option<claude_settings::policy::PolicyDocument>,

    /// Notification and external service configuration, loaded from policy.yaml.
    #[serde(skip)]
    pub notifications: NotificationConfig,

    /// Warning message if parsing the notifications config failed or was incomplete.
    #[serde(skip)]
    pub notification_warning: Option<String>,

    /// Audit logging configuration, loaded from policy.yaml.
    #[serde(skip)]
    pub audit: AuditConfig,
}

impl ClashSettings {
    #[instrument(level = Level::TRACE)]
    pub fn settings_dir() -> PathBuf {
        home_dir()
            .expect("user must have $HOME set in environment")
            .join(".clash")
    }
    #[instrument(level = Level::TRACE)]
    pub fn settings_file() -> PathBuf {
        Self::settings_dir().join("settings.json")
    }
    #[instrument(level = Level::TRACE)]
    pub fn policy_file() -> PathBuf {
        Self::settings_dir().join("policy.yaml")
    }

    /// Try to load and compile the policy document from ~/.clash/policy.yaml.
    #[instrument(level = Level::TRACE, skip(self))]
    fn load_policy_file(&mut self) -> Option<claude_settings::policy::PolicyDocument> {
        let path = Self::policy_file();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    // Parse notification and audit configs from the same YAML file.
                    let (notif_config, notif_warning) = parse_notification_config(&contents);
                    self.notifications = notif_config;
                    self.notification_warning = notif_warning;
                    self.audit = parse_audit_config(&contents);

                    match parse_yaml(&contents) {
                        Ok(doc) => {
                            info!(path = %path.display(), "Loaded policy document");
                            Some(doc)
                        }
                        Err(e) => {
                            warn!(path = %path.display(), error = %e, "Failed to parse policy.yaml");
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

    /// Load the policy from ~/.clash/policy.yaml.
    #[instrument(level = Level::TRACE, skip(self))]
    fn resolve_policy(&mut self) {
        self.policy = self.load_policy_file();
    }

    /// Compile the loaded policy document into a CompiledPolicy for evaluation.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn compiled_policy(&self) -> Option<CompiledPolicy> {
        self.policy
            .as_ref()
            .and_then(|doc| match CompiledPolicy::compile(doc) {
                Ok(compiled) => Some(compiled),
                Err(e) => {
                    warn!(error = %e, "Failed to compile policy document");
                    None
                }
            })
    }

    #[instrument(level = Level::TRACE, skip(self))]
    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(Self::settings_dir())?;
        Ok(std::fs::write(
            Self::settings_file(),
            serde_json::to_string_pretty(&self)?,
        )?)
    }

    #[instrument(level = Level::TRACE)]
    pub fn load() -> Result<Self> {
        let mut loaded: Self =
            serde_json::from_str(&std::fs::read_to_string(Self::settings_file())?)?;
        loaded.resolve_policy();
        Ok(loaded)
    }

    #[instrument(level = Level::TRACE)]
    pub fn create() -> Result<Self> {
        let mut this = Self::default();
        this.resolve_policy();
        this.save()?;
        Ok(this)
    }

    #[instrument(level = Level::TRACE)]
    pub fn load_or_create() -> Result<Self> {
        Self::load().or_else(|_| Self::create())
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
