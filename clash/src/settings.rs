use std::path::PathBuf;

use crate::policy::match_tree::CompiledPolicy;
use crate::policy_loader;
use anyhow::{Context, Result};
use dirs::home_dir;
use serde::{Deserialize, Serialize};
use tracing::{Level, info, instrument, warn};

use crate::audit::AuditConfig;
use crate::notifications::NotificationConfig;

/// The environment variable that disables all clash hooks.
///
/// When set to any non-empty value (except `"0"` or `"false"`), clash becomes a
/// pass-through — all hooks return immediately without evaluating policy.
/// This is naturally session-scoped when set in the shell that launches Claude Code.
pub const CLASH_DISABLE_ENV: &str = "CLASH_DISABLE";

/// Check whether clash is disabled via the [`CLASH_DISABLE`](CLASH_DISABLE_ENV) environment variable.
///
/// Returns `true` when the variable is set to any non-empty value except `"0"` or `"false"`.
pub fn is_disabled() -> bool {
    std::env::var(CLASH_DISABLE_ENV)
        .ok()
        .is_some_and(|v| is_truthy_disable_value(&v))
}

/// Returns `true` when `value` should be interpreted as "disabled".
///
/// A non-empty string that is not `"0"` or `"false"` means disabled.
fn is_truthy_disable_value(value: &str) -> bool {
    !value.is_empty() && value != "0" && value != "false"
}

/// Policy level — where a policy file lives in the precedence hierarchy.
///
/// Higher-precedence levels override lower ones: Session > Project > User.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyLevel {
    /// User-level policy: `~/.clash/policy.star`
    User = 0,
    /// Project-level policy: `<project_root>/.clash/policy.star`
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

/// Default policy source embedded at compile time.
pub const DEFAULT_POLICY: &str = include_str!("default_policy.star");

/// Session-level context from Claude Code hook input.
///
/// Carries runtime values that aren't available as standard environment
/// variables but are needed to resolve session-specific policy variables.
#[derive(Debug, Clone, Default)]
pub struct HookContext {
    /// Parent directory of the session transcript file. Agent output files
    /// are stored here and must always be readable.
    pub transcript_dir: Option<String>,
}

impl HookContext {
    /// Build from a transcript_path (as received in hook input).
    pub fn from_transcript_path(transcript_path: &str) -> Self {
        let transcript_dir = if transcript_path.is_empty() {
            None
        } else {
            std::path::Path::new(transcript_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
        };
        Self { transcript_dir }
    }
}

/// Environment resolver that provides session-level variables from [`HookContext`]
/// in addition to standard environment variables.
///
/// Overrides `TRANSCRIPT_DIR` with the real value from hook context when available,
/// otherwise falls through to [`StdEnvResolver`](crate::policy::compile::StdEnvResolver)
/// which returns a safe sentinel.
struct SessionEnvResolver<'a> {
    hook_ctx: Option<&'a HookContext>,
}

impl crate::policy::compile::EnvResolver for SessionEnvResolver<'_> {
    fn resolve(&self, name: &str) -> anyhow::Result<String> {
        if name == "TRANSCRIPT_DIR"
            && let Some(dir) = self.hook_ctx.and_then(|ctx| ctx.transcript_dir.clone())
        {
            return Ok(dir);
        }
        crate::policy::compile::StdEnvResolver.resolve(name)
    }
}

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
    /// Pre-compiled policy tree for fast evaluation.
    compiled: Option<CompiledPolicy>,

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
    /// Respects `CLASH_POLICY_FILE` env var for override.
    pub fn policy_file() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("CLASH_POLICY_FILE") {
            return Ok(PathBuf::from(p));
        }
        Ok(Self::settings_dir()?.join("policy.star"))
    }

    /// Returns the policy file path for a specific level.
    ///
    /// For `Session`, reads the active session ID from `~/.clash/active_session`.
    pub fn policy_file_for_level(level: PolicyLevel) -> Result<PathBuf> {
        match level {
            PolicyLevel::User => Self::policy_file(),
            PolicyLevel::Project => {
                let root = Self::project_root()?;
                Ok(root.join(".clash").join("policy.star"))
            }
            PolicyLevel::Session => {
                let session_id = Self::active_session_id()?;
                Ok(Self::session_policy_path(&session_id))
            }
        }
    }

    // Returns the policy file path for a session, given its ID.
    pub fn session_policy_path(session_id: &str) -> PathBuf {
        crate::audit::session_dir(session_id).join("policy.star")
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

    /// Diagnostic: reports what paths were checked for each policy level and why
    /// they were not found. Returns a list of `(level_name, path_or_error, reason)`.
    pub fn diagnose_missing_policies() -> Vec<(String, String, String)> {
        let mut results = Vec::new();
        for &level in PolicyLevel::all_by_precedence() {
            match Self::policy_file_for_level(level) {
                Ok(path) => {
                    let path_str = path.display().to_string();
                    match std::fs::metadata(&path) {
                        Ok(m) if m.is_file() => {
                            results.push((level.name().to_string(), path_str, "ok".to_string()));
                        }
                        Ok(_) => {
                            results.push((
                                level.name().to_string(),
                                path_str,
                                "path exists but is not a file".to_string(),
                            ));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                            results.push((
                                level.name().to_string(),
                                path_str,
                                "file does not exist".to_string(),
                            ));
                        }
                        Err(e) => {
                            results.push((level.name().to_string(), path_str, format!("{e}")));
                        }
                    }
                }
                Err(e) => {
                    results.push((level.name().to_string(), "—".to_string(), format!("{e}")));
                }
            }
        }
        results
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

    /// Return the policy parse/compile error, if any.
    pub fn policy_error(&self) -> Option<&str> {
        self.policy_error.as_deref()
    }

    /// Set the policy source directly (compile from policy source text).
    pub fn set_policy_source(&mut self, source: &str) {
        match policy_loader::compile_source(source) {
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

    /// Maximum policy file size (1 MiB) — canonical value in [`policy_loader`].
    #[cfg(test)]
    const MAX_POLICY_SIZE: u64 = policy_loader::MAX_POLICY_SIZE;

    /// Return the pre-compiled policy tree, if one was successfully compiled.
    pub fn policy_tree(&self) -> Option<&CompiledPolicy> {
        self.compiled.as_ref()
    }

    /// Backward-compat alias for `policy_tree()`.
    #[doc(hidden)]
    pub fn decision_tree(&self) -> Option<&CompiledPolicy> {
        self.compiled.as_ref()
    }

    /// Load and validate a .star policy file from an explicit path, then compile it.
    ///
    /// Returns true if a policy was successfully loaded and compiled.
    #[cfg(test)]
    fn load_policy_from_path(&mut self, path: &std::path::Path) -> bool {
        match policy_loader::load_and_compile_single(path, &mut self.policy_error) {
            Some(tree) => {
                self.load_notification_audit_config();
                self.compiled = Some(tree);
                true
            }
            None => false,
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
        Self::load_or_create_with_session(None, None)
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
    ///
    /// Pass `hook_ctx` to inject session-specific internal policies (e.g., the
    /// transcript directory). Pass `None` for CLI commands.
    #[instrument(level = Level::TRACE, skip(session_id, hook_ctx))]
    pub fn load_or_create_with_session(
        session_id: Option<&str>,
        hook_ctx: Option<&HookContext>,
    ) -> Result<Self> {
        let mut this = Self::default();

        // Collect policy sources from all available levels.
        let mut level_sources: Vec<(PolicyLevel, String)> = Vec::new();

        // Load persistent levels (user, project) in reverse precedence order.
        for &level in PolicyLevel::all_by_precedence().iter().rev() {
            if let Ok(path) = Self::policy_file_for_level(level)
                && let Some(validated) =
                    policy_loader::try_load_policy(level, &path, &mut this.policy_error)
            {
                if level == PolicyLevel::User {
                    this.load_notification_audit_config();
                }
                level_sources.push((level, validated.json_source));
                this.loaded_policies.push(validated.loaded);
            }
        }

        // Load session-level policy if session_id is provided.
        if let Some(sid) = session_id {
            let session_path = Self::session_policy_path(sid);
            if let Some(validated) = policy_loader::try_load_policy(
                PolicyLevel::Session,
                &session_path,
                &mut this.policy_error,
            ) {
                level_sources.push((PolicyLevel::Session, validated.json_source));
                this.loaded_policies.push(validated.loaded);
            }
        }

        // Re-sort loaded_policies by precedence (highest first).
        this.loaded_policies.sort_by(|a, b| b.level.cmp(&a.level));

        if level_sources.is_empty() {
            // No policy files found — keep default (no compiled tree).
            return Ok(this);
        }

        // Compile all discovered policies into a single tree.
        match policy_loader::compile_policies(&level_sources) {
            Ok(tree) => {
                this.compiled = Some(tree);
                this.policy_error = None;
            }
            Err(e) => {
                let msg = format!("Failed to compile policy: {}", e);
                warn!(error = %e, "Failed to compile policy");
                this.policy_error = Some(msg);
            }
        }

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

/// Evaluate a `.star` policy file and return the compiled JSON source.
///
/// Delegates to [`policy_loader::evaluate_star_policy`]. This wrapper is kept
/// for backward compatibility with callers that import from `settings`.
pub fn evaluate_star_policy(path: &std::path::Path) -> Result<String> {
    policy_loader::evaluate_star_policy(path)
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
                "HOME" => Ok("/tmp/home".into()),
                "TMPDIR" => Ok("/tmp".into()),
                other => anyhow::bail!("unknown env var in test: {other}"),
            }
        }
    }

    #[test]
    fn default_policy_compiles() -> anyhow::Result<()> {
        let output = clash_starlark::evaluate(
            DEFAULT_POLICY,
            "default_policy.star",
            std::path::Path::new("."),
        )?;
        let tree = crate::policy::compile::compile_to_tree(&output.json)?;
        let _ = tree;
        Ok(())
    }

    #[test]
    fn load_missing_file_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent-policy.star");
        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&path);
        assert!(!result);
        assert!(
            settings.policy_error.is_none(),
            "missing file should not set error"
        );
    }

    #[test]
    fn load_directory_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.star");
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
        let policy_path = dir.path().join("policy.star");
        std::fs::write(&policy_path, "").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings.policy_error().is_some(),
            "expected error for empty file, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn load_oversized_file_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.star");
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
        let star_policy = "load(\"@clash//std.star\", \"policy\")\ndef main():\n    return policy(default = allow, rules = [])\n";
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.star");
        std::fs::write(&policy_path, star_policy).unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result, "valid policy should compile successfully");
        assert!(settings.policy_error.is_none());
        assert!(settings.decision_tree().is_some());
    }

    #[test]
    fn load_malformed_policy_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.star");
        std::fs::write(&policy_path, "this is not valid starlark {{{").unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(!result);
        assert!(
            settings.policy_error().is_some(),
            "expected error for malformed policy, got: {:?}",
            settings.policy_error()
        );
    }

    #[test]
    fn set_policy_source_works() {
        let simple_policy = r#"{"schema_version":5,"default_effect":"deny","sandboxes":{},"tree":[
            {"condition":{"observe":"fs_op","pattern":{"literal":{"literal":"read"}},"children":[
                {"condition":{"observe":"fs_path","pattern":{"prefix":{"literal":"/tmp"}},"children":[
                    {"decision":{"allow":null}}
                ]}}
            ]}}
        ]}"#;
        let mut settings = ClashSettings::default();
        settings.set_policy_source(simple_policy);
        assert!(settings.decision_tree().is_some());
        assert!(settings.policy_error.is_none());
    }

    #[test]
    fn ensure_policy_creates_file_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join(".clash").join("policy.star");

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
        let policy_path = dir.path().join("policy.star");
        std::fs::write(
            &policy_path,
            "def main():\n    return policy(default = deny, rules = [])\n",
        )
        .unwrap();

        let result = ClashSettings::ensure_policy_at(policy_path.clone()).unwrap();
        assert!(result.is_none(), "should not recreate existing file");

        // Verify original content is preserved.
        let contents = std::fs::read_to_string(&policy_path).unwrap();
        assert!(contents.contains("def main"), "original content preserved");
    }

    #[test]
    #[cfg(unix)]
    fn ensure_policy_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join(".clash").join("policy.star");

        ClashSettings::ensure_policy_at(policy_path.clone()).unwrap();
        let mode = std::fs::metadata(&policy_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "policy file should be owner-only read/write");
    }

    // --- HookContext / SessionEnvResolver tests ---

    #[test]
    fn hook_context_from_transcript_path() {
        let ctx = HookContext::from_transcript_path("/tmp/session-123/transcript.jsonl");
        assert_eq!(ctx.transcript_dir.as_deref(), Some("/tmp/session-123"));
    }

    #[test]
    fn hook_context_from_empty_path() {
        let ctx = HookContext::from_transcript_path("");
        assert!(ctx.transcript_dir.is_none());
    }

    #[test]
    fn hook_context_from_root_file() {
        let ctx = HookContext::from_transcript_path("/transcript.jsonl");
        assert_eq!(ctx.transcript_dir.as_deref(), Some("/"));
    }

    #[test]
    fn session_resolver_provides_transcript_dir() {
        use crate::policy::compile::EnvResolver;
        let ctx = HookContext::from_transcript_path("/tmp/session-123/transcript.jsonl");
        let resolver = SessionEnvResolver {
            hook_ctx: Some(&ctx),
        };
        assert_eq!(
            resolver.resolve("TRANSCRIPT_DIR").unwrap(),
            "/tmp/session-123"
        );
    }

    #[test]
    fn session_resolver_returns_sentinel_without_context() {
        use crate::policy::compile::{EnvResolver, UNAVAILABLE_SESSION_PATH};
        let resolver = SessionEnvResolver { hook_ctx: None };
        let result = resolver.resolve("TRANSCRIPT_DIR").unwrap();
        assert_eq!(result, UNAVAILABLE_SESSION_PATH);
    }

    #[test]
    fn session_resolver_falls_through_to_std_env() {
        use crate::policy::compile::EnvResolver;
        let resolver = SessionEnvResolver { hook_ctx: None };
        // HOME should always be set in test environments
        let result = resolver.resolve("HOME");
        assert!(result.is_ok(), "HOME should resolve via StdEnvResolver");
    }

    //
    // These test `is_truthy_disable_value` directly to avoid env var races.
    // `env::set_var` is process-wide and Rust runs tests on parallel threads,
    // so multiple tests mutating the same env var is inherently racy.

    #[test]
    fn is_truthy_disable_value_not_set() {
        // Empty string = not disabled (matches env var missing or empty).
        assert!(!is_truthy_disable_value(""));
    }

    #[test]
    fn is_truthy_disable_value_falsy() {
        assert!(!is_truthy_disable_value("0"));
        assert!(!is_truthy_disable_value("false"));
    }

    #[test]
    fn is_truthy_disable_value_truthy() {
        assert!(is_truthy_disable_value("1"));
        assert!(is_truthy_disable_value("true"));
        assert!(is_truthy_disable_value("yes"));
        assert!(is_truthy_disable_value("anything"));
    }
}
