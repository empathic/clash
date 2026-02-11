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

    /// Maximum policy file size (1 MiB). Files larger than this are rejected
    /// to avoid excessive memory usage from accidentally pointing at the wrong file.
    const MAX_POLICY_SIZE: u64 = 1024 * 1024;

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
        self.load_policy_from_path(&path)
    }

    /// Load and validate a policy file from an explicit path.
    ///
    /// Performs validation (exists, is file, size limit, permissions) before
    /// reading and parsing. Sets `policy_error` on failure.
    fn load_policy_from_path(&mut self, path: &std::path::Path) -> Option<PolicyDocument> {
        // Check metadata before attempting to read.
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to stat policy.yaml");
                self.policy_error = Some(format!(
                    "Cannot read policy.yaml at {}: {}",
                    path.display(),
                    e
                ));
                return None;
            }
        };

        if metadata.is_dir() {
            let msg = format!(
                "{} is a directory, not a file. Remove it and run `clash init` to create a policy.",
                path.display()
            );
            warn!(path = %path.display(), "policy.yaml is a directory");
            self.policy_error = Some(msg);
            return None;
        }

        if metadata.len() > Self::MAX_POLICY_SIZE {
            let msg = format!(
                "policy.yaml is too large ({} bytes, max {} bytes). \
                 Check that {} is the correct file.",
                metadata.len(),
                Self::MAX_POLICY_SIZE,
                path.display()
            );
            warn!(path = %path.display(), size = metadata.len(), "policy.yaml exceeds size limit");
            self.policy_error = Some(msg);
            return None;
        }

        // Warn about overly permissive file permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            // Warn if group-readable (0o040) or world-readable (0o004).
            if mode & 0o044 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode),
                    "policy.yaml is readable by other users; consider `chmod 600`"
                );
            }
        }

        match std::fs::read_to_string(path) {
            Ok(contents) => {
                if contents.trim().is_empty() {
                    warn!(path = %path.display(), "policy.yaml is empty — using default (ask for everything)");
                    self.policy_error = Some(
                        "policy.yaml is empty. All actions will default to 'ask'. \
                         Run `clash init --force` to generate a starter policy."
                            .into(),
                    );
                    return None;
                }

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
                let msg = match e.kind() {
                    std::io::ErrorKind::PermissionDenied => format!(
                        "Permission denied reading {}. Check file ownership and permissions.",
                        path.display()
                    ),
                    _ => format!("Failed to read policy.yaml: {}", e),
                };
                warn!(path = %path.display(), error = %e, "Failed to read policy.yaml");
                self.policy_error = Some(msg);
                None
            }
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
    use super::*;
    use std::io::Write;

    #[test]
    fn default_policy_parses() -> anyhow::Result<()> {
        let pol = crate::policy::parse::parse_yaml(super::DEFAULT_POLICY)?;
        assert!(pol.profile_defs.len() > 0, "{pol:#?}");
        Ok(())
    }

    #[test]
    fn load_missing_file_returns_none() {
        let mut settings = ClashSettings::default();
        let path = std::path::Path::new("/tmp/clash-test-nonexistent-policy.yaml");
        let _ = std::fs::remove_file(path); // ensure it doesn't exist
        let result = settings.load_policy_from_path(path);
        assert!(result.is_none());
        assert!(
            settings.policy_error.is_none(),
            "missing file should not set error"
        );
    }

    #[test]
    fn load_directory_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::create_dir(&policy_path).unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_none());
        assert!(
            settings.policy_error().unwrap().contains("is a directory"),
            "expected directory error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_empty_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::write(&policy_path, "").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_none());
        assert!(
            settings.policy_error().unwrap().contains("empty"),
            "expected empty file error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_whitespace_only_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::write(&policy_path, "   \n\n  \t  \n").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_none());
        assert!(
            settings.policy_error().unwrap().contains("empty"),
            "expected empty file error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_oversized_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        // Write a file just over the 1 MiB limit.
        let mut f = std::fs::File::create(&policy_path).unwrap();
        let chunk = vec![b'#'; 8192];
        for _ in 0..(ClashSettings::MAX_POLICY_SIZE / 8192 + 1) {
            f.write_all(&chunk).unwrap();
        }
        drop(f);

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_none());
        assert!(
            settings.policy_error().unwrap().contains("too large"),
            "expected size error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_valid_policy_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::write(&policy_path, DEFAULT_POLICY).unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_some(), "valid policy should parse successfully");
        assert!(settings.policy_error.is_none());
    }

    #[test]
    fn load_malformed_yaml_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.yaml");
        std::fs::write(&policy_path, "{{{{invalid yaml: [}}}").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_none());
        assert!(
            settings.policy_error().unwrap().contains("Failed to parse"),
            "expected parse error, got: {:?}",
            settings.policy_error()
        );
    }
}
