use std::path::PathBuf;

use crate::policy::CompiledPolicy;
use crate::policy::parse::desugar_claude_permissions;
use crate::policy::{ClaudePermissions, PolicyConfig, PolicyDocument};
use anyhow::Result;
use claude_settings::ClaudeSettings;
use dirs::home_dir;
use tracing::{Level, info, instrument, warn};

#[derive(Debug, Default)]
pub struct ClashSettings {
    /// Parsed policy document loaded at runtime from policy file or compiled from Claude settings.
    pub(crate) policy: Option<PolicyDocument>,

    /// Pre-compiled policy for fast evaluation. Compiled once during `load_or_create()`.
    compiled: Option<CompiledPolicy>,

    /// Error message if policy file failed to parse or compile.
    policy_error: Option<String>,

    /// Notification configuration (defaults for now; follow-up: s-expr forms).
    pub notifications: crate::notifications::NotificationConfig,

    /// Audit configuration (defaults for now; follow-up: s-expr forms).
    pub audit: crate::audit::AuditConfig,
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
        let dir = Self::settings_dir()?;
        Ok(dir.join("policy.sexp"))
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

    /// Try to load and compile the policy document from ~/.clash/policy.sexp.
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
                warn!(path = %path.display(), error = %e, "Failed to stat policy file");
                self.policy_error = Some(format!(
                    "Cannot read policy file at {}: {}",
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
            warn!(path = %path.display(), "policy file is a directory");
            self.policy_error = Some(msg);
            return None;
        }

        if metadata.len() > Self::MAX_POLICY_SIZE {
            let msg = format!(
                "Policy file is too large ({} bytes, max {} bytes). \
                 Check that {} is the correct file.",
                metadata.len(),
                Self::MAX_POLICY_SIZE,
                path.display()
            );
            warn!(path = %path.display(), size = metadata.len(), "policy file exceeds size limit");
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
                    "policy file is readable by other users; consider `chmod 600`"
                );
            }
        }

        match std::fs::read_to_string(path) {
            Ok(contents) => {
                if contents.trim().is_empty() {
                    warn!(path = %path.display(), "policy file is empty — using default (ask for everything)");
                    self.policy_error = Some(
                        "Policy file is empty. All actions will default to 'ask'. \
                         Run `clash init --force` to generate a starter policy."
                            .into(),
                    );
                    return None;
                }

                match crate::policy::parse::parse_policy(&contents) {
                    Ok(doc) => {
                        info!(path = %path.display(), "Loaded policy document");
                        Some(doc)
                    }
                    Err(e) => {
                        let msg = format!("Failed to parse policy file: {}", e);
                        warn!(path = %path.display(), error = %e, "Failed to parse policy file");
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
                    _ => format!("Failed to read policy file: {}", e),
                };
                warn!(path = %path.display(), error = %e, "Failed to read policy file");
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

    /// Resolve the policy: use policy file if it exists, else compile Claude settings.
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

    /// If `CLASH_PROFILE` is set, override the active profile in the policy document.
    fn apply_profile_override(&mut self) {
        if let Ok(profile) = std::env::var("CLASH_PROFILE")
            && let Some(ref mut doc) = self.policy
            && let Some(ref mut dc) = doc.default_config
        {
            info!(from = %dc.profile, to = %profile, "Overriding active profile from CLASH_PROFILE");
            dc.profile = profile;
        }
    }

    /// Load settings by resolving the policy from disk and compiling it.
    #[instrument(level = Level::TRACE)]
    pub fn load_or_create() -> Result<Self> {
        let mut this = Self::default();
        this.resolve_policy();
        this.apply_profile_override();
        this.compile_policy();
        Ok(this)
    }
}

/// Default policy template written by `clash init` (s-expr format).
pub const DEFAULT_POLICY: &str = include_str!("default_policy.sexp");

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_policy_parses() -> anyhow::Result<()> {
        let pol = crate::policy::parse::parse_policy(super::DEFAULT_POLICY)?;
        assert!(pol.profile_defs.len() > 0, "{pol:#?}");
        Ok(())
    }

    #[test]
    fn load_missing_file_returns_none() {
        let mut settings = ClashSettings::default();
        let path = std::path::Path::new("/tmp/clash-test-nonexistent-policy.sexp");
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
        let policy_path = dir.path().join("policy.sexp");
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
        let policy_path = dir.path().join("policy.sexp");
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
        let policy_path = dir.path().join("policy.sexp");
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
        let policy_path = dir.path().join("policy.sexp");
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
        let policy_path = dir.path().join("policy.sexp");
        std::fs::write(&policy_path, DEFAULT_POLICY).unwrap();

        let mut settings = ClashSettings::default();
        let result = settings.load_policy_from_path(&policy_path);
        assert!(result.is_some(), "valid policy should parse successfully");
        assert!(settings.policy_error.is_none());
    }

    #[test]
    fn load_malformed_policy_sets_error() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.sexp");
        std::fs::write(&policy_path, "((( invalid s-expr").unwrap();

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
