use std::path::PathBuf;

use crate::policy::DecisionTree;
use anyhow::{Context, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use tracing::{Level, info, instrument, warn};

use crate::audit::AuditConfig;
use crate::notifications::NotificationConfig;

/// Policy level — where a policy file lives in the precedence hierarchy.
///
/// Higher-precedence levels override lower ones: Session > Project > User.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyLevel {
    /// User-level policy: `~/.clash/policy.sexpr`
    User = 0,
    /// Project-level policy: `<project_root>/.clash/policy.sexpr`
    Project = 1,
    /// Session-level policy: `/tmp/clash-<session_id>/policy.sexpr`
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

/// Default policy source embedded at compile time.
pub const DEFAULT_POLICY: &str = include_str!("default_policy.sexpr");

/// Internal policies embedded at compile time. Each entry is (name, source).
/// These are always active unless the user defines a policy with the same name.
pub const INTERNAL_POLICIES: &[(&str, &str)] = &[
    ("__internal_clash__", include_str!("internal_clash.sexpr")),
    ("__internal_claude__", include_str!("internal_claude.sexpr")),
];

/// A policy source loaded from a specific level.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    /// Which level this policy came from.
    pub level: PolicyLevel,
    /// The file path it was loaded from.
    pub path: PathBuf,
    /// The raw source text.
    pub source: String,
}

#[derive(Debug, Default)]
pub struct ClashSettings {
    /// Pre-compiled decision tree for fast evaluation.
    compiled: Option<DecisionTree>,

    /// Policy sources loaded from each level (ordered by precedence, highest first).
    loaded_policies: Vec<LoadedPolicy>,

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

    /// Returns the user-level policy file path.
    ///
    /// Respects `CLASH_POLICY_FILE` env var for backward compatibility.
    pub fn policy_file() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("CLASH_POLICY_FILE") {
            return Ok(PathBuf::from(p));
        }
        Self::settings_dir().map(|d| d.join("policy.sexpr"))
    }

    /// Returns the policy file path for a specific level.
    ///
    /// For `Session`, reads the active session ID from `~/.clash/active_session`.
    pub fn policy_file_for_level(level: PolicyLevel) -> Result<PathBuf> {
        match level {
            PolicyLevel::User => Self::policy_file(),
            PolicyLevel::Project => {
                let root = Self::project_root()?;
                Ok(root.join(".clash").join("policy.sexpr"))
            }
            PolicyLevel::Session => {
                let session_id = Self::active_session_id()?;
                Ok(Self::session_policy_path(&session_id))
            }
        }
    }

    // Returns the policy file path for a session, given its ID.
    pub fn session_policy_path(session_id: &str) -> PathBuf {
        crate::audit::session_dir(session_id).join("policy.sexpr")
    }

    /// Path to the active-session marker file.
    fn active_session_file() -> Result<PathBuf> {
        Self::settings_dir().map(|d| d.join("active_session"))
    }

    /// Read the active session ID from `~/.clash/active_session`.
    pub fn active_session_id() -> Result<String> {
        let path = Self::active_session_file()?;
        let id = std::fs::read_to_string(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow::anyhow!("no active session — start a session with `clash launch` first")
                } else {
                    anyhow::anyhow!("failed to read active session: {e}")
                }
            })?
            .trim()
            .to_string();
        if id.is_empty() {
            anyhow::bail!("active session file is empty");
        }
        Ok(id)
    }

    /// Write the active session ID to `~/.clash/active_session`.
    pub fn set_active_session(session_id: &str) -> Result<()> {
        let path = Self::active_session_file()?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, session_id)?;
        Ok(())
    }

    /// Find the project root by walking up from cwd looking for `.clash/` or `.git/`.
    ///
    /// Stops searching at `$HOME` — `~/.clash/` is the user config dir, not a project.
    /// Returns an error if no project root is found (e.g. in a temp directory).
    pub fn project_root() -> Result<PathBuf> {
        let cwd = std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("cannot determine current directory: {e}"))?;
        let stop_at = home_dir();

        // First, look for .clash directory
        if let Some(root) = find_ancestor_with(&cwd, ".clash", stop_at.as_deref()) {
            return Ok(root);
        }

        // Fallback to .git
        if let Some(root) = find_ancestor_with(&cwd, ".git", stop_at.as_deref()) {
            return Ok(root);
        }

        anyhow::bail!(
            "no project root found (looked for .clash/ or .git/ in ancestors of {})",
            cwd.display()
        )
    }

    /// Returns all policy levels that have an existing policy file.
    ///
    /// Levels are returned in precedence order (highest first: project, then user).
    pub fn available_policy_levels() -> Vec<(PolicyLevel, PathBuf)> {
        let mut levels = Vec::new();
        for &level in PolicyLevel::all_by_precedence() {
            if let Ok(path) = Self::policy_file_for_level(level)
                && path.exists()
                && path.is_file()
            {
                levels.push((level, path));
            }
        }
        levels
    }

    /// Determine the default scope for modification commands.
    ///
    /// If a project-level policy exists, returns `Project`; else `User`.
    /// Session scope is never the default — it must be explicitly requested.
    pub fn default_scope() -> PolicyLevel {
        if let Ok(path) = Self::policy_file_for_level(PolicyLevel::Project)
            && path.exists()
            && path.is_file()
        {
            return PolicyLevel::Project;
        }
        PolicyLevel::User
    }

    /// Ensure a user-level policy file exists, creating one with safe defaults if not.
    ///
    /// Returns `Ok(Some(path))` if a new file was created, `Ok(None)` if one already existed.
    /// The created file uses the embedded `DEFAULT_POLICY` (deny-all with read access to CWD).
    pub fn ensure_user_policy_exists() -> Result<Option<PathBuf>> {
        let path = Self::policy_file().context("failed to determine user policy file path")?;
        Self::ensure_policy_at(path)
    }

    /// Write the default policy to `path` if it doesn't already exist.
    fn ensure_policy_at(path: PathBuf) -> Result<Option<PathBuf>> {
        if path.exists() {
            return Ok(None);
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;

            // Restrict directory permissions on unix (owner-only).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        std::fs::write(&path, DEFAULT_POLICY)
            .with_context(|| format!("failed to write default policy to {}", path.display()))?;

        // Restrict file permissions on unix (owner-only read/write).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        info!(path = %path.display(), "Created default user policy");
        Ok(Some(path))
    }

    /// Path to a legacy YAML policy file (pre-sexp migration).
    pub fn legacy_policy_file() -> Result<PathBuf> {
        Self::settings_dir().map(|d| d.join("policy.yaml"))
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

    /// Load and validate a policy file from an explicit path, then compile it.
    ///
    /// Returns true if a policy was successfully loaded and compiled.
    #[cfg(test)]
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

    /// Load settings without session context (for CLI commands).
    ///
    /// Loads user and project policies only. Session-level policies are excluded
    /// because CLI commands run outside of an active Claude Code session — the
    /// `~/.clash/active_session` marker may be stale from a previous session.
    ///
    /// Use `load_or_create_with_session()` with an explicit session ID (from hook
    /// input) to include session-level policies.
    pub fn load_or_create() -> Result<Self> {
        Self::load_or_create_with_session(None)
    }

    /// Return the loaded policy sources (ordered by precedence, highest first).
    pub fn loaded_policies(&self) -> &[LoadedPolicy] {
        &self.loaded_policies
    }

    /// Load settings by resolving policies from disk and compiling them.
    ///
    /// Loads from all available levels (user, project, session) and merges them
    /// with session > project > user precedence.
    ///
    /// Pass `session_id` when processing a hook event (it's in the hook input JSON).
    /// For CLI commands, pass `None` — session policy won't be loaded.
    #[instrument(level = Level::TRACE, skip(session_id))]
    pub fn load_or_create_with_session(session_id: Option<&str>) -> Result<Self> {
        let mut this = Self::default();

        // Collect policy sources from all available levels.
        let mut level_sources: Vec<(PolicyLevel, String)> = Vec::new();

        // Load persistent levels (user, project) in reverse precedence order.
        for &level in PolicyLevel::all_by_precedence().iter().rev() {
            if let Ok(path) = Self::policy_file_for_level(level)
                && let Some((source, loaded)) = this.try_load_policy_from_path(level, &path)
            {
                level_sources.push((level, source));
                this.loaded_policies.push(loaded);
            }
        }

        // Load session-level policy if session_id is provided.
        if let Some(sid) = session_id {
            let session_path = Self::session_policy_path(sid);
            if let Some((source, loaded)) =
                this.try_load_policy_from_path(PolicyLevel::Session, &session_path)
            {
                level_sources.push((PolicyLevel::Session, source));
                this.loaded_policies.push(loaded);
            }
        }

        // Re-sort loaded_policies by precedence (highest first).
        this.loaded_policies.sort_by(|a, b| b.level.cmp(&a.level));

        if level_sources.is_empty() {
            // No policy files found — keep default (no compiled tree).
            return Ok(this);
        }

        // If only one level, compile directly (backward-compatible path).
        if level_sources.len() == 1 {
            let (_, source) = &level_sources[0];
            this.set_policy_source(source);
            return Ok(this);
        }

        // Multiple levels: compile and merge.
        let level_refs: Vec<(PolicyLevel, &str)> = level_sources
            .iter()
            .map(|(l, s)| (*l, s.as_str()))
            .collect();

        match crate::policy::compile_multi_level(&level_refs) {
            Ok(tree) => {
                this.compiled = Some(tree);
                this.policy_error = None;
            }
            Err(e) => {
                let msg = format!("Failed to compile merged policy: {}", e);
                warn!(error = %e, "Failed to compile merged policy");
                this.policy_error = Some(msg);
            }
        }

        Ok(this)
    }

    /// Try to load and validate a policy file from a path, returning the source
    /// text and a LoadedPolicy if successful.
    fn try_load_policy_from_path(
        &mut self,
        level: PolicyLevel,
        path: &std::path::Path,
    ) -> Option<(String, LoadedPolicy)> {
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    level = %level,
                    error = %e,
                    "Failed to stat policy file"
                );
                return None;
            }
        };

        if metadata.is_dir() || metadata.len() > Self::MAX_POLICY_SIZE {
            return None;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o044 != 0 {
                warn!(
                    path = %path.display(),
                    level = %level,
                    mode = format!("{:o}", mode),
                    "policy file is readable by other users; consider `chmod 600`"
                );
            }
        }

        match std::fs::read_to_string(path) {
            Ok(mut contents) => {
                if contents.trim().is_empty() {
                    return None;
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

                // Load notification config only from user-level policy.yaml
                if level == PolicyLevel::User {
                    self.load_notification_audit_config();
                }

                let loaded = LoadedPolicy {
                    level,
                    path: path.to_path_buf(),
                    source: contents.clone(),
                };

                Some((contents, loaded))
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    level = %level,
                    error = %e,
                    "Failed to read policy file"
                );
                None
            }
        }
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

/// Find the nearest ancestor directory containing the given name.
///
/// If `stop_at` is provided, stops searching before checking that directory.
/// This prevents `~/.clash/` from being mistaken for a project root.
fn find_ancestor_with(
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

    #[test]
    fn ensure_policy_creates_file_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join(".clash").join("policy.sexpr");

        let result = ClashSettings::ensure_policy_at(policy_path.clone()).unwrap();
        assert!(result.is_some(), "should have created the file");
        assert_eq!(result.unwrap(), policy_path);
        assert!(policy_path.exists(), "policy file should exist on disk");

        let contents = std::fs::read_to_string(&policy_path).unwrap();
        assert_eq!(contents, DEFAULT_POLICY, "should contain default policy");
    }

    #[test]
    fn ensure_policy_noop_when_exists() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexpr");
        std::fs::write(&policy_path, "(default deny \"main\")\n(policy \"main\")").unwrap();

        let result = ClashSettings::ensure_policy_at(policy_path.clone()).unwrap();
        assert!(result.is_none(), "should not recreate existing file");

        // Verify original content is preserved.
        let contents = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            contents.contains("default deny"),
            "original content preserved"
        );
        assert!(
            !contents.contains("cwd-access"),
            "should not overwrite with default"
        );
    }

    #[test]
    #[cfg(unix)]
    fn ensure_policy_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join(".clash").join("policy.sexpr");

        ClashSettings::ensure_policy_at(policy_path.clone()).unwrap();
        let mode = std::fs::metadata(&policy_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "policy file should be owner-only read/write");
    }
}
