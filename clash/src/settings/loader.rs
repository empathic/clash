//! Policy loading, compilation, and ClashSettings construction.

use std::path::PathBuf;

use anyhow::{Context, Result};
use dirs::home_dir;
use tracing::{Level, info, instrument, warn};

use crate::policy::match_tree::CompiledPolicy;
use crate::policy_loader;

use super::discovery::{
    self, PolicyLevel, compile_default_policy_to_json, find_ancestor_with, parse_audit_config,
    parse_notification_config, prefer_json_over_star, session_policy_file, settings_dir,
    tilde_path,
};
use super::{ClashSettings, HookContext, LoadedPolicy};

impl ClashSettings {
    /// Returns the clash settings directory (`~/.clash/`).
    ///
    /// Respects `CLASH_HOME` env var for override, otherwise defaults to `$HOME/.clash`.
    pub fn settings_dir() -> Result<PathBuf> {
        discovery::settings_dir()
    }

    /// Returns the user-level policy file path.
    ///
    /// Respects `CLASH_POLICY_FILE` env var for override.
    /// Prefers `policy.json` over `policy.star` when both exist.
    pub fn policy_file() -> Result<PathBuf> {
        discovery::policy_file()
    }

    /// Returns the policy file path for a specific level.
    ///
    /// Prefers `policy.json` over `policy.star` when both exist.
    /// For `Session`, reads the active session ID from `~/.clash/active_session`.
    pub fn policy_file_for_level(level: PolicyLevel) -> Result<PathBuf> {
        match level {
            PolicyLevel::User => Self::policy_file(),
            PolicyLevel::Project => {
                let root = Self::project_root()?;
                let dir = root.join(".clash");
                Ok(prefer_json_over_star(&dir))
            }
            PolicyLevel::Session => {
                let session_id = Self::active_session_id()?;
                Ok(Self::session_policy_path(&session_id))
            }
        }
    }

    // Returns the policy file path for a session, given its ID.
    pub fn session_policy_path(session_id: &str) -> PathBuf {
        session_policy_file(session_id)
    }

    /// Path to the active-session marker file.
    fn active_session_file() -> Result<PathBuf> {
        settings_dir().map(|d| d.join("active_session"))
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
        let parent = path
            .parent()
            .context("active session file path has no parent directory")?;
        std::fs::create_dir_all(parent)?;
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

    /// Write the compiled default policy JSON to `path` if no policy exists.
    ///
    /// The path passed in may point to `policy.star` (from `prefer_json_over_star`
    /// when no file exists yet). We always write `policy.json` instead, compiling
    /// the embedded Starlark source to JSON at runtime.
    fn ensure_policy_at(path: PathBuf) -> Result<Option<PathBuf>> {
        if path.exists() {
            return Ok(None);
        }

        // Always write the compiled JSON variant, even if `path` ends in `.star`.
        let json_path = path.with_extension("json");

        if let Some(parent) = json_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;

            // Restrict directory permissions on unix (owner-only).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let json =
            compile_default_policy_to_json().context("failed to compile default policy to JSON")?;
        std::fs::write(&json_path, &json).with_context(|| {
            format!("failed to write default policy to {}", json_path.display())
        })?;

        // Restrict file permissions on unix (owner-only read/write).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&json_path, std::fs::Permissions::from_mode(0o600));
        }

        info!(path = %json_path.display(), "Created default user policy");
        Ok(Some(json_path))
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
        let yaml_path = match settings_dir() {
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
    #[instrument(level = Level::TRACE, skip(session_id, _hook_ctx))]
    pub fn load_or_create_with_session(
        session_id: Option<&str>,
        _hook_ctx: Option<&HookContext>,
    ) -> Result<Self> {
        let mut this = Self::default();

        // Collect policy sources from all available levels.
        // Each entry: (level, json_source, display_path).
        let mut level_sources: Vec<(PolicyLevel, String, String)> = Vec::new();

        // Load persistent levels (user, project) in reverse precedence order.
        for &level in PolicyLevel::all_by_precedence().iter().rev() {
            if let Ok(path) = Self::policy_file_for_level(level)
                && let Some(validated) =
                    policy_loader::try_load_policy(level, &path, &mut this.policy_error)
            {
                if level == PolicyLevel::User {
                    this.load_notification_audit_config();
                }
                let display_path = tilde_path(&path);
                level_sources.push((level, validated.json_source, display_path));
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
                let display_path = tilde_path(&session_path);
                level_sources.push((PolicyLevel::Session, validated.json_source, display_path));
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

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;

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
        let star_policy = "load(\"@clash//std.star\", \"allow\", \"policy\")\ndef main():\n    return policy(default = allow(), rules = [])\n";
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
    fn ensure_policy_creates_json_file_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        // Pass a .star path — ensure_policy_at should write .json instead.
        let star_path = dir.path().join(".clash").join("policy.star");
        let json_path = dir.path().join(".clash").join("policy.json");

        let result = ClashSettings::ensure_policy_at(star_path).unwrap();
        assert!(result.is_some(), "should have created the file");
        assert_eq!(result.unwrap(), json_path);
        assert!(json_path.exists(), "policy.json should exist on disk");

        let contents = std::fs::read_to_string(&json_path).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&contents).expect("written file should be valid JSON");
        assert!(
            parsed.get("tree").is_some(),
            "JSON should contain a tree field"
        );
    }

    #[test]
    fn ensure_policy_noop_when_exists() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.star");
        std::fs::write(
            &policy_path,
            "load(\"@clash//std.star\", \"policy\", \"deny\")\ndef main():\n    return policy(default = deny(), rules = [])\n",
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
        let star_path = dir.path().join(".clash").join("policy.star");
        let json_path = dir.path().join(".clash").join("policy.json");

        ClashSettings::ensure_policy_at(star_path).unwrap();
        let mode = std::fs::metadata(&json_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "policy file should be owner-only read/write");
    }

    // --- HookContext / SessionEnvResolver tests ---

    /// Environment resolver that provides session-level variables from [`HookContext`]
    /// in addition to standard environment variables.
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
}
