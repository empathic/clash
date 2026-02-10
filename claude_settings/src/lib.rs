//! # Claude Settings
//!
//! A Rust library for reading and writing Claude Code settings on Unix-like systems.
//!
//! ## Overview
//!
//! Claude Code uses a hierarchical settings system with multiple levels:
//!
//! 1. **System** (`/etc/claude-code/managed-settings.json`) - Read-only, highest priority
//! 2. **Project Local** (`.claude/settings.local.json`) - Project-specific, not version controlled
//! 3. **Project** (`.claude/settings.json`) - Project-specific, version controlled
//! 4. **User** (`~/.claude/settings.json`) - User defaults, lowest priority
//!
//! This library provides:
//! - Type-safe settings structures with serde serialization
//! - Read/write operations for each settings level
//! - Automatic path resolution based on project structure
//! - Settings merging with proper precedence handling
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use claude_settings::{ClaudeSettings, Settings, SettingsLevel, PermissionSet};
//!
//! // Create a settings manager
//! let manager = ClaudeSettings::new();
//!
//! // Read user settings
//! if let Ok(Some(settings)) = manager.read(SettingsLevel::User) {
//!     println!("User model: {:?}", settings.model);
//! }
//!
//! // Write project settings
//! let settings = Settings::new()
//!     .with_model("claude-sonnet-4-20250514")
//!     .with_permissions(
//!         PermissionSet::new()
//!             .allow("Bash(git:*)")
//!             .deny("Read(.env)")
//!     );
//!
//! manager.write(SettingsLevel::Project, &settings).unwrap();
//!
//! // Get effective settings (merged from all levels)
//! let effective = manager.effective().unwrap();
//! ```
//!
//! ## Settings Structure
//!
//! The main [`Settings`] struct supports all Claude Code configuration options:
//!
//! - `permissions` - Tool permission rules (allow/ask/deny)
//! - `env` - Environment variables for tool execution
//! - `model` - Override the default Claude model
//! - `hooks` - Pre/post tool execution hooks
//! - `sandbox` - Command sandboxing configuration
//! - `attribution` - Git commit/PR attribution messages
//! - `enabled_plugins` - Plugin enable/disable map
//! - `cleanup_period_days` - Session cleanup period
//! - `language` - Preferred response language
//!
//! ## Structured Permissions
//!
//! The [`permission`] module provides structured permission parsing and querying:
//!
//! ```rust
//! use claude_settings::permission::{Permission, PermissionSet, PermissionRule};
//!
//! // Parse permission patterns
//! let perm = Permission::parse("Bash(git:*)").unwrap();
//! assert!(perm.matches("Bash", Some("git status")));
//!
//! // Build a permission set
//! let set = PermissionSet::new()
//!     .allow(Permission::prefix("Bash", "git"))
//!     .deny(Permission::exact("Read", ".env"));
//!
//! // Query permissions
//! assert_eq!(set.check("Bash", Some("git status")), PermissionRule::Allow);
//! assert_eq!(set.check("Read", Some(".env")), PermissionRule::Deny);
//! ```
//!
//! ## Figment Integration
//!
//! Use [`merge::FigmentLoader`] for advanced configuration merging:
//!
//! ```rust,no_run
//! use claude_settings::merge::FigmentLoader;
//!
//! let loader = FigmentLoader::with_defaults();
//! let settings = loader.load().unwrap();
//! ```
//!
//! ## Scoped Settings (Context Manager)
//!
//! Use [`SettingsGuard`] for temporary modifications that auto-restore:
//!
//! ```rust,no_run
//! use claude_settings::{ClaudeSettings, SettingsLevel};
//!
//! let manager = ClaudeSettings::new();
//!
//! // Make temporary changes that auto-restore when guard drops
//! {
//!     let mut guard = manager.scoped(SettingsLevel::User)?;
//!     guard.set_model("temporary-model")
//!          .add_allow("Bash(rm:*)")
//!          .set_env("DEBUG", "1");
//!     guard.apply()?;
//!
//!     // Changes are active here...
//! } // Original settings automatically restored
//!
//! # Ok::<(), claude_settings::SettingsError>(())
//! ```

pub mod error;
pub mod guard;
pub mod io;
pub mod merge;
pub mod paths;
pub mod permission;
pub mod types;

pub use error::{Result, SettingsError};
pub use guard::{MultiLevelGuard, SettingsGuard};
pub use io::SettingsIO;
pub use merge::{FigmentLoader, Merge, SettingsMerger};
pub use paths::PathResolver;
pub use permission::{Permission, PermissionPattern, PermissionRule, PermissionSet};
pub use types::{
    Attribution, Hook, HookConfig, HookMatcher, Hooks, Permissions, Sandbox, Settings,
    SettingsLevel,
};

use tracing::{Level, instrument};

/// High-level interface for managing Claude Code settings.
///
/// This is the primary entry point for most use cases. It provides
/// convenient methods for reading, writing, and merging settings
/// across all levels.
///
/// # Example
///
/// ```rust,no_run
/// use claude_settings::{ClaudeSettings, Settings, SettingsLevel};
///
/// let manager = ClaudeSettings::new();
///
/// // Read settings from a specific level
/// let user_settings = manager.read(SettingsLevel::User)?;
///
/// // Get effective settings (merged from all levels)
/// let effective = manager.effective()?;
///
/// // Write settings to project level
/// let settings = Settings::new().with_model("claude-sonnet-4-20250514");
/// manager.write(SettingsLevel::Project, &settings)?;
/// # Ok::<(), claude_settings::SettingsError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ClaudeSettings {
    io: SettingsIO,
}

impl Default for ClaudeSettings {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeSettings {
    /// Creates a new ClaudeSettings manager with default path resolution.
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        Self {
            io: SettingsIO::new(),
        }
    }

    /// Creates a ClaudeSettings manager with a custom path resolver.
    ///
    /// This is useful for testing or when working with non-standard paths.
    ///
    /// # Example
    ///
    /// ```rust
    /// use claude_settings::{ClaudeSettings, PathResolver};
    ///
    /// let resolver = PathResolver::new()
    ///     .with_home("/custom/home")
    ///     .with_project("/custom/project");
    ///
    /// let manager = ClaudeSettings::with_resolver(resolver);
    /// ```
    #[instrument(level = Level::TRACE)]
    pub fn with_resolver(resolver: PathResolver) -> Self {
        Self {
            io: SettingsIO::with_resolver(resolver),
        }
    }

    /// Returns a reference to the underlying SettingsIO.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn io(&self) -> &SettingsIO {
        &self.io
    }

    /// Returns a reference to the path resolver.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn resolver(&self) -> &PathResolver {
        self.io.resolver()
    }

    /// Reads settings from the specified level.
    ///
    /// Returns `Ok(None)` if the settings file doesn't exist.
    /// Returns `Err` if there's a read or parse error.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn read(&self, level: SettingsLevel) -> Result<Option<Settings>> {
        self.io.read_optional(level)
    }

    /// Reads settings from the specified level, returning default if not found.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn read_or_default(&self, level: SettingsLevel) -> Result<Settings> {
        Ok(self.io.read_optional(level)?.unwrap_or_default())
    }

    /// Writes settings to the specified level.
    ///
    /// Creates the settings directory if it doesn't exist.
    /// Returns an error if trying to write to the System level (read-only).
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn write(&self, level: SettingsLevel, settings: &Settings) -> Result<()> {
        self.io.write(level, settings)
    }

    /// Checks if settings exist at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn exists(&self, level: SettingsLevel) -> Result<bool> {
        self.io.exists(level)
    }

    /// Deletes the settings file at the specified level.
    ///
    /// Returns an error if trying to delete System level settings.
    /// Returns Ok(()) if the file doesn't exist.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn delete(&self, level: SettingsLevel) -> Result<()> {
        self.io.delete(level)
    }

    /// Returns the effective settings by merging all levels.
    ///
    /// Settings are merged according to Claude Code's precedence rules:
    /// System > Project Local > Project > User
    ///
    /// Higher precedence settings override lower precedence ones.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn effective(&self) -> Result<Settings> {
        let all = self.io.read_all()?;
        Ok(merge::merge_all(&all))
    }

    /// Returns settings from all existing levels along with their paths.
    ///
    /// Useful for debugging or displaying which settings files are active.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn list_all(&self) -> Result<Vec<(SettingsLevel, std::path::PathBuf, Settings)>> {
        let mut results = Vec::new();

        for level in SettingsLevel::all_by_priority() {
            let path = self.resolver().settings_path(*level)?;
            if let Some(settings) = self.read(*level)? {
                results.push((*level, path, settings));
            }
        }

        Ok(results)
    }

    /// Updates settings at a level by applying a function.
    ///
    /// Reads existing settings (or default if none exist), applies the
    /// update function, and writes the result back.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, SettingsLevel, PermissionSet};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// manager.update(SettingsLevel::User, |settings| {
    ///     settings.model = Some("claude-opus-4-5-20251101".to_string());
    ///     settings.permissions = PermissionSet::new().allow("Bash(git:*)");
    /// })?;
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self, f))]
    pub fn update<F>(&self, level: SettingsLevel, f: F) -> Result<()>
    where
        F: FnOnce(&mut Settings),
    {
        let mut settings = self.read_or_default(level)?;
        f(&mut settings);
        self.write(level, &settings)
    }

    /// Adds a permission to the allow list at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn add_allow_permission(&self, level: SettingsLevel, pattern: &str) -> Result<()> {
        self.update(level, |settings| {
            settings.permissions.insert_allow(pattern);
        })
    }

    /// Adds a permission to the deny list at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn add_deny_permission(&self, level: SettingsLevel, pattern: &str) -> Result<()> {
        self.update(level, |settings| {
            settings.permissions.insert_deny(pattern);
        })
    }

    /// Sets the model at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_model(&self, level: SettingsLevel, model: &str) -> Result<()> {
        self.update(level, |settings| {
            settings.model = Some(model.to_string());
        })
    }

    /// Sets an environment variable at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_env(&self, level: SettingsLevel, key: &str, value: &str) -> Result<()> {
        self.update(level, |settings| {
            let env = settings.env.get_or_insert_with(Default::default);
            env.insert(key.to_string(), value.to_string());
        })
    }

    /// Removes an environment variable at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_env(&self, level: SettingsLevel, key: &str) -> Result<()> {
        self.update(level, |settings| {
            if let Some(ref mut env) = settings.env {
                env.remove(key);
            }
        })
    }

    /// Adds a permission to the ask list at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn add_ask_permission(&self, level: SettingsLevel, pattern: &str) -> Result<()> {
        self.update(level, |settings| {
            settings.permissions.insert_ask(pattern);
        })
    }

    /// Removes a permission from all lists at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_permission(&self, level: SettingsLevel, pattern: &str) -> Result<()> {
        self.update(level, |settings| {
            settings.permissions.remove(&pattern.into());
        })
    }

    /// Returns a structured PermissionSet from the effective settings.
    ///
    /// This allows for easy querying of permission rules.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, PermissionRule};
    ///
    /// let manager = ClaudeSettings::new();
    /// let perms = manager.effective_permissions()?;
    ///
    /// if perms.is_allowed("Bash", Some("git status")) {
    ///     println!("git status is allowed");
    /// }
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn effective_permissions(&self) -> Result<PermissionSet> {
        let settings = self.effective()?;
        Ok(settings.permissions.clone())
    }

    /// Returns a structured PermissionSet from settings at a specific level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn permissions_at(&self, level: SettingsLevel) -> Result<Option<PermissionSet>> {
        match self.read(level)? {
            Some(settings) => Ok(Some(settings.permissions.clone())),
            None => Ok(None),
        }
    }

    /// Updates permissions at a level using a PermissionSet.
    ///
    /// This replaces all existing permissions at that level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_permissions(&self, level: SettingsLevel, perms: &PermissionSet) -> Result<()> {
        self.update(level, |settings| {
            settings.permissions = perms.clone();
        })
    }

    /// Clears the model setting at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_model(&self, level: SettingsLevel) -> Result<()> {
        self.update(level, |settings| {
            settings.model = None;
        })
    }

    /// Clears all permissions at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_permissions(&self, level: SettingsLevel) -> Result<()> {
        self.update(level, |settings| {
            settings.permissions.clear();
        })
    }

    /// Clears all environment variables at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_env(&self, level: SettingsLevel) -> Result<()> {
        self.update(level, |settings| {
            settings.env = None;
        })
    }

    /// Sets the language at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_language(&self, level: SettingsLevel, language: &str) -> Result<()> {
        self.update(level, |settings| {
            settings.language = Some(language.to_string());
        })
    }

    /// Sets bypass_permissions at the specified level.
    ///
    /// When enabled, Claude Code starts with permissions bypassed (equivalent to
    /// `--dangerously-skip-permissions`), letting an external tool like Clash be
    /// the sole permission handler.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_bypass_permissions(&self, level: SettingsLevel, enabled: bool) -> Result<()> {
        self.update(level, |settings| {
            settings.bypass_permissions = Some(enabled);
        })
    }

    /// Sets sandbox enabled/disabled at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_sandbox_enabled(&self, level: SettingsLevel, enabled: bool) -> Result<()> {
        self.update(level, |settings| {
            let sandbox = settings.sandbox.get_or_insert_with(Sandbox::default);
            sandbox.enabled = Some(enabled);
        })
    }

    /// Sets the cleanup period in days at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_cleanup_period(&self, level: SettingsLevel, days: u32) -> Result<()> {
        self.update(level, |settings| {
            settings.cleanup_period_days = Some(days);
        })
    }

    /// Enables or disables a plugin at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_plugin_enabled(
        &self,
        level: SettingsLevel,
        plugin: &str,
        enabled: bool,
    ) -> Result<()> {
        self.update(level, |settings| {
            let plugins = settings
                .enabled_plugins
                .get_or_insert_with(Default::default);
            plugins.insert(plugin.to_string(), enabled);
        })
    }

    /// Backs up settings at the specified level by copying to `{path}.{suffix}`.
    ///
    /// Returns the backup path on success, or `Ok(None)` if the settings file doesn't exist.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, SettingsLevel};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// // Create a backup before making changes
    /// if let Some(backup_path) = manager.backup(SettingsLevel::User, "bak")? {
    ///     println!("Backup created at: {:?}", backup_path);
    /// }
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn backup(&self, level: SettingsLevel, suffix: &str) -> Result<Option<std::path::PathBuf>> {
        self.io.backup(level, suffix)
    }

    /// Writes settings to the specified level, backing up the existing file first.
    ///
    /// If settings exist at this level, they will be copied to `{path}.{suffix}` before writing.
    /// Returns the backup path if a backup was created, or `None` if no file existed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, Settings, SettingsLevel};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// let new_settings = Settings::new().with_model("new-model");
    ///
    /// // Write with backup - creates settings.json.bak if settings.json exists
    /// manager.write_with_backup(SettingsLevel::User, &new_settings, "bak")?;
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn write_with_backup(
        &self,
        level: SettingsLevel,
        settings: &Settings,
        backup_suffix: &str,
    ) -> Result<Option<std::path::PathBuf>> {
        self.io.write_with_backup(level, settings, backup_suffix)
    }

    /// Restores settings at the specified level from a backup file.
    ///
    /// Copies `{path}.{suffix}` back to `{path}`.
    /// Returns `Ok(true)` if restored, `Ok(false)` if the backup doesn't exist.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, Settings, SettingsLevel};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// // Write with backup
    /// let new_settings = Settings::new().with_model("new-model");
    /// manager.write_with_backup(SettingsLevel::User, &new_settings, "bak")?;
    ///
    /// // Later, restore from backup if needed
    /// if manager.restore_from_backup(SettingsLevel::User, "bak")? {
    ///     println!("Settings restored from backup");
    /// }
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn restore_from_backup(&self, level: SettingsLevel, suffix: &str) -> Result<bool> {
        self.io.restore_from_backup(level, suffix)
    }

    /// Checks if a backup exists for the specified level and suffix.
    ///
    /// Returns `Ok(true)` if the backup file exists, `Ok(false)` otherwise.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, SettingsLevel};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// // Check if a backup exists before attempting restore
    /// if manager.backup_exists(SettingsLevel::User, "bak")? {
    ///     manager.restore_from_backup(SettingsLevel::User, "bak")?;
    /// }
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn backup_exists(&self, level: SettingsLevel, suffix: &str) -> Result<bool> {
        self.io.backup_exists(level, suffix)
    }

    /// Creates a scoped guard for temporary settings modifications.
    ///
    /// The guard provides a fluent API for modifying settings. When the guard
    /// is dropped, the original settings are automatically restored.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, SettingsLevel};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// // Set some initial settings
    /// manager.set_model(SettingsLevel::User, "original-model")?;
    ///
    /// {
    ///     let mut guard = manager.scoped(SettingsLevel::User)?;
    ///
    ///     // Make temporary changes
    ///     guard.set_model("temporary-model")
    ///          .add_allow("Bash(rm:*)")
    ///          .set_env("DEBUG", "1");
    ///
    ///     // Apply changes to disk
    ///     guard.apply()?;
    ///
    ///     // Changes are active within this scope
    ///     let settings = manager.read(SettingsLevel::User)?.unwrap();
    ///     assert_eq!(settings.model.as_deref(), Some("temporary-model"));
    ///
    /// } // guard dropped, original settings restored
    ///
    /// // Back to original
    /// let settings = manager.read(SettingsLevel::User)?.unwrap();
    /// assert_eq!(settings.model.as_deref(), Some("original-model"));
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    ///
    /// # Commit vs Apply
    ///
    /// - `apply()` writes changes to disk but still restores on drop
    /// - `commit()` writes changes and prevents restoration (changes become permanent)
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn scoped(&self, level: SettingsLevel) -> Result<SettingsGuard<'_>> {
        SettingsGuard::new(self, level)
    }

    /// Creates a multi-level scoped guard for temporary modifications.
    ///
    /// This allows modifying multiple settings levels at once, with all
    /// levels restored when the guard is dropped.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use claude_settings::{ClaudeSettings, SettingsLevel};
    ///
    /// let manager = ClaudeSettings::new();
    ///
    /// {
    ///     let mut guard = manager.scoped_multi(&[
    ///         SettingsLevel::User,
    ///         SettingsLevel::Project,
    ///     ])?;
    ///
    ///     guard.level_mut(SettingsLevel::User)
    ///          .unwrap()
    ///          .set_model("temp-user-model");
    ///
    ///     guard.level_mut(SettingsLevel::Project)
    ///          .unwrap()
    ///          .add_deny("Read(.env)");
    ///
    ///     guard.apply()?;
    /// } // Both levels restored
    /// # Ok::<(), claude_settings::SettingsError>(())
    /// ```
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn scoped_multi(&self, levels: &[SettingsLevel]) -> Result<MultiLevelGuard<'_>> {
        MultiLevelGuard::new(self, levels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_manager() -> (TempDir, ClaudeSettings) {
        let temp = TempDir::new().unwrap();
        let resolver = PathResolver::new()
            .with_home(temp.path().join("home"))
            .with_project(temp.path().join("project"));

        fs::create_dir_all(temp.path().join("home/.claude")).unwrap();
        fs::create_dir_all(temp.path().join("project/.claude")).unwrap();

        (temp, ClaudeSettings::with_resolver(resolver))
    }

    #[test]
    fn test_read_write_cycle() {
        let (_temp, manager) = setup_test_manager();

        let settings = Settings::new()
            .with_model("test-model")
            .with_permissions(PermissionSet::new().allow("Bash(git:*)"));

        manager.write(SettingsLevel::User, &settings).unwrap();

        let read = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(read.model.unwrap(), "test-model");
    }

    #[test]
    fn test_effective_settings() {
        let (_temp, manager) = setup_test_manager();

        // User level: model + permission
        let user = Settings::new()
            .with_model("user-model")
            .with_permissions(PermissionSet::new().allow("Bash(git:*)"));
        manager.write(SettingsLevel::User, &user).unwrap();

        // Project level: different model + additional permission
        let project = Settings::new()
            .with_model("project-model")
            .with_permissions(PermissionSet::new().deny("Read(.env)"));
        manager.write(SettingsLevel::Project, &project).unwrap();

        let effective = manager.effective().unwrap();

        // Project model should win
        assert_eq!(effective.model.unwrap(), "project-model");

        // Both permissions should be present
        let perms = &effective.permissions;
        assert!(perms.is_allowed("Bash", Some("git status")));
        assert!(perms.is_denied("Read", Some(".env")));
    }

    #[test]
    fn test_update() {
        let (_temp, manager) = setup_test_manager();

        manager
            .update(SettingsLevel::User, |s| {
                s.model = Some("updated-model".to_string());
            })
            .unwrap();

        let read = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(read.model.unwrap(), "updated-model");
    }

    #[test]
    fn test_add_permissions() {
        let (_temp, manager) = setup_test_manager();

        manager
            .add_allow_permission(SettingsLevel::User, "Bash(git:*)")
            .unwrap();
        manager
            .add_deny_permission(SettingsLevel::User, "Read(.env)")
            .unwrap();

        let read = manager.read(SettingsLevel::User).unwrap().unwrap();
        let perms = &read.permissions;

        assert!(perms.is_allowed("Bash", Some("git status")));
        assert!(perms.is_denied("Read", Some(".env")));
    }

    #[test]
    fn test_set_and_remove_env() {
        let (_temp, manager) = setup_test_manager();

        manager
            .set_env(SettingsLevel::User, "MY_VAR", "my_value")
            .unwrap();

        let read = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(
            read.env.as_ref().unwrap().get("MY_VAR").unwrap(),
            "my_value"
        );

        manager.remove_env(SettingsLevel::User, "MY_VAR").unwrap();

        let read = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert!(!read.env.as_ref().unwrap().contains_key("MY_VAR"));
    }

    #[test]
    fn test_list_all() {
        let (_temp, manager) = setup_test_manager();

        manager
            .write(SettingsLevel::User, &Settings::new().with_model("user"))
            .unwrap();
        manager
            .write(
                SettingsLevel::Project,
                &Settings::new().with_model("project"),
            )
            .unwrap();

        let all = manager.list_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_set_bypass_permissions() {
        let (_temp, manager) = setup_test_manager();

        manager
            .set_bypass_permissions(SettingsLevel::User, true)
            .unwrap();

        let read = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(read.bypass_permissions, Some(true));
    }
}
