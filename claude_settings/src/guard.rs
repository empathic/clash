//! RAII guards for scoped settings mutations.
//!
//! This module provides context-manager-like functionality for temporarily
//! modifying settings and automatically restoring them when exiting a scope.
//!
//! ## Example
//!
//! ```rust,no_run
//! use claude_settings::{ClaudeSettings, SettingsLevel, Permission};
//!
//! let manager = ClaudeSettings::new();
//!
//! // Original settings are preserved
//! {
//!     let mut guard = manager.scoped(SettingsLevel::User)?;
//!
//!     // Make temporary changes
//!     guard.set_model("claude-opus-4-5-20251101");
//!     guard.add_allow("Bash(rm:*)");
//!
//!     // Changes are active within this scope
//!     // ...
//!
//! } // guard dropped here, original settings restored
//!
//! // Original settings are back
//! # Ok::<(), claude_settings::SettingsError>(())
//! ```

use std::ops::{Deref, DerefMut};

use tracing::{Level, instrument};

use crate::error::Result;
use crate::permission::PermissionSet;
use crate::types::{Hook, HookConfig, HookMatcher, Hooks, Sandbox, Settings, SettingsLevel};
use crate::{ClaudeSettings, Permission};

/// A guard that restores settings when dropped.
///
/// This provides RAII-style scoped mutations. When the guard is dropped,
/// it automatically restores the original settings.
///
/// Use [`ClaudeSettings::scoped`] to create a guard.
#[must_use = "if unused, the guard will immediately restore settings"]
pub struct SettingsGuard<'a> {
    manager: &'a ClaudeSettings,
    level: SettingsLevel,
    original: Option<Settings>,
    current: Settings,
    committed: bool,
}

impl<'a> SettingsGuard<'a> {
    /// Creates a new settings guard for the given level.
    ///
    /// Saves the current settings (if any) and initializes with a copy
    /// for modification.
    #[instrument(level = Level::TRACE, skip(manager))]
    pub(crate) fn new(manager: &'a ClaudeSettings, level: SettingsLevel) -> Result<Self> {
        let original = manager.read(level)?;
        let current = original.clone().unwrap_or_default();

        Ok(Self {
            manager,
            level,
            original,
            current,
            committed: false,
        })
    }

    /// Returns the settings level this guard operates on.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn level(&self) -> SettingsLevel {
        self.level
    }

    /// Returns the original settings (before any modifications).
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn original(&self) -> Option<&Settings> {
        self.original.as_ref()
    }

    /// Applies the current modifications to disk.
    ///
    /// This writes the current state to the settings file but does NOT
    /// prevent restoration on drop. Call [`commit`](Self::commit) to
    /// persist changes permanently.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn apply(&self) -> Result<()> {
        self.manager.write(self.level, &self.current)
    }

    /// Commits the changes permanently, preventing restoration on drop.
    ///
    /// After calling this, the guard will NOT restore the original settings
    /// when dropped.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn commit(mut self) -> Result<()> {
        self.apply()?;
        self.committed = true;
        Ok(())
    }

    /// Discards changes and restores original settings immediately.
    ///
    /// This is equivalent to dropping the guard, but explicit.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn restore(self) -> Result<()> {
        // Drop will handle restoration
        drop(self);
        Ok(())
    }

    /// Resets the current state to the original settings.
    ///
    /// This undoes all in-memory changes but does NOT write to disk.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn reset(&mut self) {
        self.current = self.original.clone().unwrap_or_default();
    }

    // =========================================================================
    // Mutation methods
    // =========================================================================

    /// Sets the model.
    #[instrument(level = Level::TRACE, skip(self, model))]
    pub fn set_model(&mut self, model: impl Into<String>) -> &mut Self {
        self.current.model = Some(model.into());
        self
    }

    /// Clears the model.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_model(&mut self) -> &mut Self {
        self.current.model = None;
        self
    }

    /// Sets the language.
    #[instrument(level = Level::TRACE, skip(self, language))]
    pub fn set_language(&mut self, language: impl Into<String>) -> &mut Self {
        self.current.language = Some(language.into());
        self
    }

    /// Sets the cleanup period in days.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_cleanup_period(&mut self, days: u32) -> &mut Self {
        self.current.cleanup_period_days = Some(days);
        self
    }

    /// Adds a permission to the allow list.
    #[instrument(level = Level::TRACE, skip(self, pattern))]
    pub fn add_allow(&mut self, pattern: impl Into<Permission>) -> &mut Self {
        self.current.permissions.insert_allow(pattern);
        self
    }

    /// Adds a permission to the ask list.
    #[instrument(level = Level::TRACE, skip(self, pattern))]
    pub fn add_ask(&mut self, pattern: impl Into<Permission>) -> &mut Self {
        self.current.permissions.insert_ask(pattern);
        self
    }

    /// Adds a permission to the deny list.
    #[instrument(level = Level::TRACE, skip(self, pattern))]
    pub fn add_deny(&mut self, pattern: impl Into<Permission>) -> &mut Self {
        self.current.permissions.insert_deny(pattern);
        self
    }

    /// Removes a permission from all lists.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_permission(&mut self, pattern: &str) -> &mut Self {
        self.current.permissions.remove(&pattern.into());
        self
    }

    /// Clears all permissions.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_permissions(&mut self) -> &mut Self {
        self.current.permissions.clear();
        self
    }

    /// Sets permissions from a PermissionSet.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_permissions(&mut self, perms: PermissionSet) -> &mut Self {
        self.current.permissions = perms;
        self
    }

    /// Sets an environment variable.
    #[instrument(level = Level::TRACE, skip(self, key, value))]
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        let env = self.current.env.get_or_insert_with(Default::default);
        env.insert(key.into(), value.into());
        self
    }

    /// Removes an environment variable.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_env(&mut self, key: &str) -> &mut Self {
        if let Some(ref mut env) = self.current.env {
            env.remove(key);
        }
        self
    }

    /// Clears all environment variables.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_env(&mut self) -> &mut Self {
        self.current.env = None;
        self
    }

    /// Sets sandbox enabled/disabled.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn set_sandbox_enabled(&mut self, enabled: bool) -> &mut Self {
        let sandbox = self.current.sandbox.get_or_insert_with(Sandbox::default);
        sandbox.enabled = Some(enabled);
        self
    }

    /// Enables or disables a plugin.
    #[instrument(level = Level::TRACE, skip(self, plugin))]
    pub fn set_plugin_enabled(&mut self, plugin: impl Into<String>, enabled: bool) -> &mut Self {
        let plugins = self
            .current
            .enabled_plugins
            .get_or_insert_with(Default::default);
        plugins.insert(plugin.into(), enabled);
        self
    }

    /// Applies a custom mutation function.
    #[instrument(level = Level::TRACE, skip(self, f))]
    pub fn mutate<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut Settings),
    {
        f(&mut self.current);
        self
    }

    // =========================================================================
    // Hook methods
    // =========================================================================

    /// Adds a pre-tool-use hook with a matcher pattern.
    ///
    /// The matcher pattern can be empty to match all tools, or a specific tool name.
    #[instrument(level = Level::TRACE, skip(self, matcher))]
    pub fn add_pre_tool_use_hook(&mut self, matcher: impl Into<String>, hook: Hook) -> &mut Self {
        let hooks = self.current.hooks.get_or_insert_with(Hooks::default);
        let config = hooks
            .pre_tool_use
            .get_or_insert_with(|| HookConfig::Matchers(Vec::new()));

        match config {
            HookConfig::Matchers(matchers) => {
                let matcher_str = matcher.into();
                // Find existing matcher or create new one
                if let Some(existing) = matchers.iter_mut().find(|m| m.matcher == matcher_str) {
                    existing.hooks.push(hook);
                } else {
                    matchers.push(HookMatcher {
                        matcher: matcher_str,
                        hooks: vec![hook],
                    });
                }
            }
            HookConfig::Simple(map) => {
                // Convert simple config to matchers
                let mut matchers: Vec<HookMatcher> = map
                    .iter()
                    .map(|(tool, cmd)| HookMatcher {
                        matcher: tool.clone(),
                        hooks: vec![Hook {
                            hook_type: "command".to_string(),
                            command: Some(cmd.clone()),
                            timeout: None,
                        }],
                    })
                    .collect();

                let matcher_str = matcher.into();
                matchers.push(HookMatcher {
                    matcher: matcher_str,
                    hooks: vec![hook],
                });
                *config = HookConfig::Matchers(matchers);
            }
        }
        self
    }

    /// Adds a post-tool-use hook with a matcher pattern.
    ///
    /// The matcher pattern can be empty to match all tools, or a specific tool name.
    #[instrument(level = Level::TRACE, skip(self, matcher))]
    pub fn add_post_tool_use_hook(&mut self, matcher: impl Into<String>, hook: Hook) -> &mut Self {
        let hooks = self.current.hooks.get_or_insert_with(Hooks::default);
        let config = hooks
            .post_tool_use
            .get_or_insert_with(|| HookConfig::Matchers(Vec::new()));

        match config {
            HookConfig::Matchers(matchers) => {
                let matcher_str = matcher.into();
                if let Some(existing) = matchers.iter_mut().find(|m| m.matcher == matcher_str) {
                    existing.hooks.push(hook);
                } else {
                    matchers.push(HookMatcher {
                        matcher: matcher_str,
                        hooks: vec![hook],
                    });
                }
            }
            HookConfig::Simple(map) => {
                let mut matchers: Vec<HookMatcher> = map
                    .iter()
                    .map(|(tool, cmd)| HookMatcher {
                        matcher: tool.clone(),
                        hooks: vec![Hook {
                            hook_type: "command".to_string(),
                            command: Some(cmd.clone()),
                            timeout: None,
                        }],
                    })
                    .collect();

                let matcher_str = matcher.into();
                matchers.push(HookMatcher {
                    matcher: matcher_str,
                    hooks: vec![hook],
                });
                *config = HookConfig::Matchers(matchers);
            }
        }
        self
    }

    /// Adds a stop hook with a matcher pattern.
    #[instrument(level = Level::TRACE, skip(self, matcher))]
    pub fn add_stop_hook(&mut self, matcher: impl Into<String>, hook: Hook) -> &mut Self {
        let hooks = self.current.hooks.get_or_insert_with(Hooks::default);
        let stop_hooks = hooks.stop.get_or_insert_with(Vec::new);

        let matcher_str = matcher.into();
        if let Some(existing) = stop_hooks.iter_mut().find(|m| m.matcher == matcher_str) {
            existing.hooks.push(hook);
        } else {
            stop_hooks.push(HookMatcher {
                matcher: matcher_str,
                hooks: vec![hook],
            });
        }
        self
    }

    /// Adds a notification hook with a matcher pattern.
    #[instrument(level = Level::TRACE, skip(self, matcher))]
    pub fn add_notification_hook(&mut self, matcher: impl Into<String>, hook: Hook) -> &mut Self {
        let hooks = self.current.hooks.get_or_insert_with(Hooks::default);
        let config = hooks
            .notification
            .get_or_insert_with(|| HookConfig::Matchers(Vec::new()));

        match config {
            HookConfig::Matchers(matchers) => {
                let matcher_str = matcher.into();
                if let Some(existing) = matchers.iter_mut().find(|m| m.matcher == matcher_str) {
                    existing.hooks.push(hook);
                } else {
                    matchers.push(HookMatcher {
                        matcher: matcher_str,
                        hooks: vec![hook],
                    });
                }
            }
            HookConfig::Simple(map) => {
                let mut matchers: Vec<HookMatcher> = map
                    .iter()
                    .map(|(tool, cmd)| HookMatcher {
                        matcher: tool.clone(),
                        hooks: vec![Hook {
                            hook_type: "command".to_string(),
                            command: Some(cmd.clone()),
                            timeout: None,
                        }],
                    })
                    .collect();

                let matcher_str = matcher.into();
                matchers.push(HookMatcher {
                    matcher: matcher_str,
                    hooks: vec![hook],
                });
                *config = HookConfig::Matchers(matchers);
            }
        }
        self
    }

    /// Clears all hooks.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_hooks(&mut self) -> &mut Self {
        self.current.hooks = None;
        self
    }

    /// Clears pre-tool-use hooks.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_pre_tool_use_hooks(&mut self) -> &mut Self {
        if let Some(ref mut hooks) = self.current.hooks {
            hooks.pre_tool_use = None;
        }
        self
    }

    /// Clears post-tool-use hooks.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_post_tool_use_hooks(&mut self) -> &mut Self {
        if let Some(ref mut hooks) = self.current.hooks {
            hooks.post_tool_use = None;
        }
        self
    }

    /// Clears stop hooks.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_stop_hooks(&mut self) -> &mut Self {
        if let Some(ref mut hooks) = self.current.hooks {
            hooks.stop = None;
        }
        self
    }

    /// Clears notification hooks.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear_notification_hooks(&mut self) -> &mut Self {
        if let Some(ref mut hooks) = self.current.hooks {
            hooks.notification = None;
        }
        self
    }
}

impl<'a> Deref for SettingsGuard<'a> {
    type Target = Settings;

    fn deref(&self) -> &Self::Target {
        &self.current
    }
}

impl<'a> DerefMut for SettingsGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.current
    }
}

impl<'a> Drop for SettingsGuard<'a> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // Restore original settings
        let result = match &self.original {
            Some(settings) => self.manager.write(self.level, settings),
            None => self.manager.delete(self.level),
        };

        if let Err(e) = result {
            // Can't propagate errors from drop, so log it
            eprintln!(
                "warning: failed to restore settings at {:?}: {}",
                self.level, e
            );
        }
    }
}

/// A multi-level guard that can modify settings at multiple levels.
///
/// When dropped, all levels are restored to their original state.
#[must_use = "if unused, the guard will immediately restore settings"]
pub struct MultiLevelGuard<'a> {
    guards: Vec<SettingsGuard<'a>>,
}

impl<'a> MultiLevelGuard<'a> {
    /// Creates a new multi-level guard for the given levels.
    #[instrument(level = Level::TRACE, skip(manager))]
    pub(crate) fn new(manager: &'a ClaudeSettings, levels: &[SettingsLevel]) -> Result<Self> {
        let mut guards = Vec::with_capacity(levels.len());
        for &level in levels {
            guards.push(SettingsGuard::new(manager, level)?);
        }
        Ok(Self { guards })
    }

    /// Returns a mutable reference to the guard for a specific level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn level_mut(&mut self, level: SettingsLevel) -> Option<&mut SettingsGuard<'a>> {
        self.guards.iter_mut().find(|g| g.level() == level)
    }

    /// Returns a reference to the guard for a specific level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn level(&self, level: SettingsLevel) -> Option<&SettingsGuard<'a>> {
        self.guards.iter().find(|g| g.level() == level)
    }

    /// Applies all changes to disk.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn apply(&self) -> Result<()> {
        for guard in &self.guards {
            guard.apply()?;
        }
        Ok(())
    }

    /// Commits all changes permanently.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn commit(self) -> Result<()> {
        for guard in self.guards {
            guard.commit()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathResolver;
    use std::fs;
    use tempfile::TempDir;

    fn setup() -> (TempDir, ClaudeSettings) {
        let temp = TempDir::new().unwrap();
        let resolver = PathResolver::new()
            .with_home(temp.path().join("home"))
            .with_project(temp.path().join("project"));

        fs::create_dir_all(temp.path().join("home/.claude")).unwrap();
        fs::create_dir_all(temp.path().join("project/.claude")).unwrap();

        (temp, ClaudeSettings::with_resolver(resolver))
    }

    #[test]
    fn test_guard_restores_on_drop() {
        let (_temp, manager) = setup();

        // Set initial settings
        manager
            .set_model(SettingsLevel::User, "original-model")
            .unwrap();

        // Verify initial state
        let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(settings.model.as_deref(), Some("original-model"));

        // Create guard and modify
        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();
            guard.set_model("temporary-model");
            guard.apply().unwrap();

            // Verify temporary change
            let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
            assert_eq!(settings.model.as_deref(), Some("temporary-model"));
        }

        // Verify restoration after drop
        let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(settings.model.as_deref(), Some("original-model"));
    }

    #[test]
    fn test_guard_commit_prevents_restoration() {
        let (_temp, manager) = setup();

        manager
            .set_model(SettingsLevel::User, "original-model")
            .unwrap();

        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();
            guard.set_model("committed-model");
            guard.commit().unwrap();
        }

        // Changes should persist after drop
        let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
        assert_eq!(settings.model.as_deref(), Some("committed-model"));
    }

    #[test]
    fn test_guard_restores_to_none() {
        let (_temp, manager) = setup();

        // Start with no settings
        assert!(manager.read(SettingsLevel::User).unwrap().is_none());

        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();
            guard.set_model("temporary-model");
            guard.apply().unwrap();

            // Settings exist now
            assert!(manager.read(SettingsLevel::User).unwrap().is_some());
        }

        // Settings should be deleted after drop
        assert!(manager.read(SettingsLevel::User).unwrap().is_none());
    }

    #[test]
    fn test_guard_chained_mutations() {
        let (_temp, manager) = setup();

        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();
            guard
                .set_model("test-model")
                .set_language("en")
                .add_allow("Bash(git:*)")
                .add_deny("Read(.env)")
                .set_env("MY_VAR", "my_value");
            guard.apply().unwrap();

            let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
            assert_eq!(settings.model.as_deref(), Some("test-model"));
            assert_eq!(settings.language.as_deref(), Some("en"));
            assert!(settings.permissions.is_allowed("Bash", Some("git status")));
        }
    }

    #[test]
    fn test_guard_reset() {
        let (_temp, manager) = setup();

        manager
            .set_model(SettingsLevel::User, "original-model")
            .unwrap();

        let mut guard = manager.scoped(SettingsLevel::User).unwrap();
        guard.set_model("changed-model");

        assert_eq!(guard.model.as_deref(), Some("changed-model"));

        guard.reset();

        assert_eq!(guard.model.as_deref(), Some("original-model"));
    }

    #[test]
    fn test_guard_deref() {
        let (_temp, manager) = setup();

        let mut guard = manager.scoped(SettingsLevel::User).unwrap();

        // Can access Settings fields through deref
        guard.model = Some("direct-model".to_string());
        assert_eq!(guard.model.as_deref(), Some("direct-model"));
    }

    #[test]
    fn test_multi_level_guard() {
        let (_temp, manager) = setup();

        manager
            .set_model(SettingsLevel::User, "user-original")
            .unwrap();
        manager
            .set_model(SettingsLevel::Project, "project-original")
            .unwrap();

        {
            let mut guard = manager
                .scoped_multi(&[SettingsLevel::User, SettingsLevel::Project])
                .unwrap();

            guard
                .level_mut(SettingsLevel::User)
                .unwrap()
                .set_model("user-temp");
            guard
                .level_mut(SettingsLevel::Project)
                .unwrap()
                .set_model("project-temp");
            guard.apply().unwrap();

            assert_eq!(
                manager
                    .read(SettingsLevel::User)
                    .unwrap()
                    .unwrap()
                    .model
                    .as_deref(),
                Some("user-temp")
            );
            assert_eq!(
                manager
                    .read(SettingsLevel::Project)
                    .unwrap()
                    .unwrap()
                    .model
                    .as_deref(),
                Some("project-temp")
            );
        }

        // Both restored
        assert_eq!(
            manager
                .read(SettingsLevel::User)
                .unwrap()
                .unwrap()
                .model
                .as_deref(),
            Some("user-original")
        );
        assert_eq!(
            manager
                .read(SettingsLevel::Project)
                .unwrap()
                .unwrap()
                .model
                .as_deref(),
            Some("project-original")
        );
    }

    #[test]
    fn test_guard_add_hooks() {
        let (_temp, manager) = setup();

        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();

            // Add a pre-tool-use hook
            guard.add_pre_tool_use_hook(
                "Bash",
                Hook {
                    hook_type: "command".to_string(),
                    command: Some("echo pre-bash".to_string()),
                    timeout: Some(5000),
                },
            );

            // Add a post-tool-use hook
            guard.add_post_tool_use_hook(
                "",
                Hook {
                    hook_type: "command".to_string(),
                    command: Some("echo post-all".to_string()),
                    timeout: None,
                },
            );

            // Add a stop hook
            guard.add_stop_hook(
                "",
                Hook {
                    hook_type: "command".to_string(),
                    command: Some("echo stopping".to_string()),
                    timeout: None,
                },
            );

            guard.apply().unwrap();

            let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
            let hooks = settings.hooks.as_ref().unwrap();

            // Verify pre_tool_use hook
            match hooks.pre_tool_use.as_ref().unwrap() {
                HookConfig::Matchers(matchers) => {
                    assert_eq!(matchers.len(), 1);
                    assert_eq!(matchers[0].matcher, "Bash");
                    assert_eq!(matchers[0].hooks.len(), 1);
                    assert_eq!(
                        matchers[0].hooks[0].command.as_deref(),
                        Some("echo pre-bash")
                    );
                }
                _ => panic!("Expected Matchers config"),
            }

            // Verify post_tool_use hook
            match hooks.post_tool_use.as_ref().unwrap() {
                HookConfig::Matchers(matchers) => {
                    assert_eq!(matchers.len(), 1);
                    assert_eq!(matchers[0].matcher, "");
                    assert_eq!(
                        matchers[0].hooks[0].command.as_deref(),
                        Some("echo post-all")
                    );
                }
                _ => panic!("Expected Matchers config"),
            }

            // Verify stop hook
            let stop_hooks = hooks.stop.as_ref().unwrap();
            assert_eq!(stop_hooks.len(), 1);
            assert_eq!(
                stop_hooks[0].hooks[0].command.as_deref(),
                Some("echo stopping")
            );
        }
    }

    #[test]
    fn test_guard_add_multiple_hooks_same_matcher() {
        let (_temp, manager) = setup();

        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();

            // Add two hooks with the same matcher
            guard
                .add_pre_tool_use_hook(
                    "Bash",
                    Hook {
                        hook_type: "command".to_string(),
                        command: Some("echo first".to_string()),
                        timeout: None,
                    },
                )
                .add_pre_tool_use_hook(
                    "Bash",
                    Hook {
                        hook_type: "command".to_string(),
                        command: Some("echo second".to_string()),
                        timeout: None,
                    },
                );

            guard.apply().unwrap();

            let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
            let hooks = settings.hooks.as_ref().unwrap();

            match hooks.pre_tool_use.as_ref().unwrap() {
                HookConfig::Matchers(matchers) => {
                    // Should have one matcher with two hooks
                    assert_eq!(matchers.len(), 1);
                    assert_eq!(matchers[0].matcher, "Bash");
                    assert_eq!(matchers[0].hooks.len(), 2);
                    assert_eq!(matchers[0].hooks[0].command.as_deref(), Some("echo first"));
                    assert_eq!(matchers[0].hooks[1].command.as_deref(), Some("echo second"));
                }
                _ => panic!("Expected Matchers config"),
            }
        }
    }

    #[test]
    fn test_guard_clear_hooks() {
        let (_temp, manager) = setup();

        {
            let mut guard = manager.scoped(SettingsLevel::User).unwrap();
            guard
                .add_pre_tool_use_hook(
                    "Bash",
                    Hook {
                        hook_type: "command".to_string(),
                        command: Some("echo test".to_string()),
                        timeout: None,
                    },
                )
                .add_post_tool_use_hook(
                    "",
                    Hook {
                        hook_type: "command".to_string(),
                        command: Some("echo test".to_string()),
                        timeout: None,
                    },
                );
            guard.apply().unwrap();

            // Verify hooks exist
            let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
            assert!(settings.hooks.is_some());

            // Clear all hooks
            guard.clear_hooks();
            guard.apply().unwrap();

            let settings = manager.read(SettingsLevel::User).unwrap().unwrap();
            assert!(settings.hooks.is_none());
        }
    }
}
