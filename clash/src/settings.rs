use std::path::PathBuf;

use crate::policy::DecisionTree;
use anyhow::Result;
use dirs::home_dir;
use serde::Deserialize;
use tracing::{Level, info, instrument, warn};

use crate::audit::AuditConfig;
use crate::notifications::NotificationConfig;

/// Default policy source embedded at compile time.
pub const DEFAULT_POLICY: &str = include_str!("default_policy.sexpr");

#[derive(Debug, Default)]
pub struct ClashSettings {
    /// Pre-compiled decision tree for fast evaluation.
    compiled: Option<DecisionTree>,

    /// Notification and external service configuration, loaded from policy.yaml.
    pub notifications: NotificationConfig,

    /// Warning message if parsing the notifications config failed or was incomplete.
    pub notification_warning: Option<String>,

    /// Audit logging configuration, loaded from policy.yaml.
    pub audit: AuditConfig,

    /// Error message if policy failed to parse or compile.
    policy_error: Option<String>,
}

impl ClashSettings {
    pub fn settings_dir() -> Result<PathBuf> {
        home_dir()
            .map(|h| h.join(".clash"))
            .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot determine settings directory"))
    }

    pub fn policy_file() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("CLASH_POLICY_FILE") {
            return Ok(PathBuf::from(p));
        }
        Self::settings_dir().map(|d| d.join("policy.sexpr"))
    }

    /// Return the policy parse/compile error, if any.
    pub fn policy_error(&self) -> Option<&str> {
        self.policy_error.as_deref()
    }

    /// Set the policy source directly (compile from s-expression text).
    pub fn set_policy_source(&mut self, source: &str) {
        match crate::policy::compile_policy(source) {
            Ok(tree) => {
                self.compiled = Some(tree);
                self.policy_error = None;
            }
            Err(e) => {
                let msg = format!("Failed to compile policy: {}", e);
                warn!(error = %e, "Failed to compile policy");
                self.policy_error = Some(msg);
                self.compiled = None;
            }
        }
    }

    /// Maximum policy file size (1 MiB).
    const MAX_POLICY_SIZE: u64 = 1024 * 1024;

    /// Return the pre-compiled decision tree, if one was successfully compiled.
    pub fn decision_tree(&self) -> Option<&DecisionTree> {
        self.compiled.as_ref()
    }

    /// Try to load and compile the policy from the policy file.
    #[instrument(level = Level::TRACE, skip(self))]
    fn load_policy_file(&mut self) -> bool {
        let path = match Self::policy_file() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "Cannot determine policy file path");
                return false;
            }
        };
        self.load_policy_from_path(&path)
    }

    /// Load and validate a policy file from an explicit path, then compile it.
    ///
    /// Returns true if a policy was successfully loaded and compiled.
    fn load_policy_from_path(&mut self, path: &std::path::Path) -> bool {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to stat policy file");
                self.policy_error = Some(format!(
                    "Cannot read policy file at {}: {}",
                    path.display(),
                    e
                ));
                return false;
            }
        };

        if metadata.is_dir() {
            let msg = format!(
                "{} is a directory, not a file. Remove it and run `clash init` to create a policy.",
                path.display()
            );
            warn!(path = %path.display(), "policy file is a directory");
            self.policy_error = Some(msg);
            return false;
        }

        if metadata.len() > Self::MAX_POLICY_SIZE {
            let msg = format!(
                "policy file is too large ({} bytes, max {} bytes). \
                 Check that {} is the correct file.",
                metadata.len(),
                Self::MAX_POLICY_SIZE,
                path.display()
            );
            warn!(path = %path.display(), size = metadata.len(), "policy file exceeds size limit");
            self.policy_error = Some(msg);
            return false;
        }

        // Warn about overly permissive file permissions on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o044 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode),
                    "policy file is readable by other users; consider `chmod 600`"
                );
            }
        }

        match std::fs::read_to_string(path) {
            Ok(mut contents) => {
                if contents.trim().is_empty() {
                    warn!(path = %path.display(), "policy file is empty — using default (ask for everything)");
                    self.policy_error = Some(
                        "policy file is empty. All actions will default to 'ask'. \
                         Run `clash init --force` to generate a starter policy."
                            .into(),
                    );
                    return false;
                }

                // Auto-migrate: (env CWD) was renamed to (env PWD).
                if contents.contains("(env CWD)") {
                    contents = contents.replace("(env CWD)", "(env PWD)");
                    if let Err(e) = std::fs::write(path, &contents) {
                        warn!(path = %path.display(), error = %e, "Failed to auto-migrate CWD→PWD");
                    } else {
                        info!(path = %path.display(), "Auto-migrated (env CWD) → (env PWD)");
                    }
                }

                // Try to parse notification/audit config from YAML comments or
                // a separate yaml file. For now, check if there is a companion
                // policy.yaml for notification/audit config.
                self.load_notification_audit_config();

                match crate::policy::compile_policy(&contents) {
                    Ok(tree) => {
                        info!(path = %path.display(), "Loaded policy");
                        self.compiled = Some(tree);
                        true
                    }
                    Err(e) => {
                        let msg = format!("Failed to compile policy: {}", e);
                        warn!(path = %path.display(), error = %e, "Failed to compile policy");
                        self.policy_error = Some(msg);
                        false
                    }
                }
            }
            Err(e) => {
                let msg = match e.kind() {
                    std::io::ErrorKind::PermissionDenied => format!(
                        "Permission denied reading {}. Check file ownership and permissions.",
                        path.display()
                    ),
                    _ => format!("Failed to read policy file: {}", e),
                };
                warn!(path = %path.display(), error = %e, "Failed to read policy file");
                self.policy_error = Some(msg);
                false
            }
        }
    }

    /// Load notification and audit config from a companion policy.yaml if it exists.
    fn load_notification_audit_config(&mut self) {
        let yaml_path = match Self::settings_dir() {
            Ok(d) => d.join("policy.yaml"),
            Err(_) => return,
        };
        if let Ok(contents) = std::fs::read_to_string(&yaml_path) {
            let (notif_config, notif_warning) = parse_notification_config(&contents);
            self.notifications = notif_config;
            self.notification_warning = notif_warning;
            self.audit = parse_audit_config(&contents);
        }
    }

    /// Load settings by resolving the policy from disk and compiling it.
    #[instrument(level = Level::TRACE)]
    pub fn load_or_create() -> Result<Self> {
        let mut this = Self::default();
        this.load_policy_file();
        Ok(this)
    }
}

/// Extract the `notifications:` section from a YAML string.
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
            warn!(error = %e, "Failed to parse notifications config");
            (NotificationConfig::default(), Some(warning))
        }
    }
}

/// Extract the `audit:` section from a YAML string.
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

    struct TestEnv;
    impl crate::policy::compile::EnvResolver for TestEnv {
        fn resolve(&self, name: &str) -> anyhow::Result<String> {
            match name {
                "PWD" => Ok("/tmp".into()),
                other => anyhow::bail!("unknown env var in test: {other}"),
            }
        }
    }

    #[test]
    fn default_policy_compiles() -> anyhow::Result<()> {
        let tree = crate::policy::compile::compile_policy_with_env(DEFAULT_POLICY, &TestEnv)?;
        assert!(
            !tree.fs_rules.is_empty(),
            "default policy should have fs rules"
        );
        Ok(())
    }

    #[test]
    fn load_missing_file_returns_false() {
        let mut settings = ClashSettings::default();
        let path = std::path::Path::new("/tmp/clash-test-nonexistent-policy.sexpr");
        let _ = std::fs::remove_file(path);
        let result = settings.load_policy_from_path(path);
        assert!(!result);
        assert!(
            settings.policy_error.is_none(),
            "missing file should not set error"
        );
    }

    #[test]
    fn load_directory_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        std::fs::create_dir(&policy_path).unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings.policy_error().unwrap().contains("is a directory"),
            "expected directory error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_empty_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        std::fs::write(&policy_path, "").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings.policy_error().unwrap().contains("empty"),
            "expected empty file error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_whitespace_only_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        std::fs::write(&policy_path, "   \n\n  \t  \n").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings.policy_error().unwrap().contains("empty"),
            "expected empty file error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_oversized_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        let mut f = std::fs::File::create(&policy_path).unwrap();
        let chunk = vec![b'#'; 8192];
        for _ in 0..(ClashSettings::MAX_POLICY_SIZE / 8192 + 1) {
            f.write_all(&chunk).unwrap();
        }
        drop(f);

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings.policy_error().unwrap().contains("too large"),
            "expected size error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_valid_policy_succeeds() {
        // Use a policy without (env PWD) to avoid needing env vars in tests.
        let simple_policy = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath "/tmp"))))
"#;
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        std::fs::write(&policy_path, simple_policy).unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result, "valid policy should compile successfully");
        assert!(settings.policy_error.is_none());
        assert!(settings.decision_tree().is_some());
    }

    #[test]
    fn load_malformed_policy_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        std::fs::write(&policy_path, "(((invalid policy").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings
                .policy_error()
                .unwrap()
                .contains("Failed to compile"),
            "expected compile error, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn set_policy_source_works() {
        // Use a policy without (env PWD) to avoid needing env vars in tests.
        let simple_policy = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath "/tmp"))))
"#;
        let mut settings = ClashSettings::default();
        settings.set_policy_source(simple_policy);
        assert!(settings.decision_tree().is_some());
        assert!(settings.policy_error.is_none());
    }
}
