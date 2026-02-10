//! Settings merging with precedence support.
//!
//! This module provides utilities for merging settings from multiple
//! levels according to Claude Code's precedence rules.
//!
//! ## Figment Integration
//!
//! This module also provides integration with [figment](https://docs.rs/figment/)
//! for more advanced configuration merging scenarios:
//!
//! ```rust,no_run
//! use claude_settings::merge::FigmentLoader;
//! use claude_settings::PathResolver;
//!
//! let resolver = PathResolver::new();
//! let loader = FigmentLoader::new(resolver);
//!
//! // Load and merge all settings using figment
//! let settings = loader.load().unwrap();
//! ```

use std::collections::HashMap;
use std::path::Path;

use figment::Figment;
use figment::providers::{Format, Json, Serialized};
use tracing::{Level, instrument};

use crate::error::Result;
use crate::paths::PathResolver;
use crate::types::{Attribution, Hooks, Permissions, Sandbox, Settings, SettingsLevel};

/// Trait for types that can be merged with precedence.
pub trait Merge {
    /// Merges self with another value, preferring values from `other` (higher precedence).
    fn merge(&self, other: &Self) -> Self;
}

impl Merge for Settings {
    fn merge(&self, other: &Self) -> Self {
        Settings {
            permissions: self.permissions.merge(&other.permissions),
            env: merge_option_map(&self.env, &other.env),
            model: other.model.clone().or_else(|| self.model.clone()),
            hooks: merge_option(&self.hooks, &other.hooks),
            sandbox: merge_option(&self.sandbox, &other.sandbox),
            attribution: merge_option(&self.attribution, &other.attribution),
            enabled_plugins: merge_option_map(&self.enabled_plugins, &other.enabled_plugins),
            cleanup_period_days: other.cleanup_period_days.or(self.cleanup_period_days),
            language: other.language.clone().or_else(|| self.language.clone()),
            bypass_permissions: other.bypass_permissions.or(self.bypass_permissions),
            extra: merge_maps(&self.extra, &other.extra),
        }
    }
}

impl Merge for Permissions {
    fn merge(&self, other: &Self) -> Self {
        // For permissions, we combine all lists (higher precedence values
        // are typically processed first at runtime)
        Permissions {
            allow: merge_vecs(&self.allow, &other.allow),
            ask: merge_vecs(&self.ask, &other.ask),
            deny: merge_vecs(&self.deny, &other.deny),
        }
    }
}

impl Merge for Hooks {
    fn merge(&self, other: &Self) -> Self {
        // For hooks, higher precedence completely overrides each hook type
        Hooks {
            pre_tool_use: other
                .pre_tool_use
                .clone()
                .or_else(|| self.pre_tool_use.clone()),
            post_tool_use: other
                .post_tool_use
                .clone()
                .or_else(|| self.post_tool_use.clone()),
            stop: other.stop.clone().or_else(|| self.stop.clone()),
            notification: other
                .notification
                .clone()
                .or_else(|| self.notification.clone()),
        }
    }
}

impl Merge for Sandbox {
    fn merge(&self, other: &Self) -> Self {
        Sandbox {
            enabled: other.enabled.or(self.enabled),
            auto_allow_bash_if_sandboxed: other
                .auto_allow_bash_if_sandboxed
                .or(self.auto_allow_bash_if_sandboxed),
            excluded_commands: other
                .excluded_commands
                .clone()
                .or_else(|| self.excluded_commands.clone()),
        }
    }
}

impl Merge for Attribution {
    fn merge(&self, other: &Self) -> Self {
        Attribution {
            commit: other.commit.clone().or_else(|| self.commit.clone()),
            pr: other.pr.clone().or_else(|| self.pr.clone()),
        }
    }
}

/// Merges two optional values, with `higher` taking precedence.
fn merge_option<T: Merge + Clone>(lower: &Option<T>, higher: &Option<T>) -> Option<T> {
    match (lower, higher) {
        (Some(l), Some(h)) => Some(l.merge(h)),
        (Some(l), None) => Some(l.clone()),
        (None, Some(h)) => Some(h.clone()),
        (None, None) => None,
    }
}

/// Merges two optional hash maps, with `higher` taking precedence.
fn merge_option_map<K, V>(
    lower: &Option<HashMap<K, V>>,
    higher: &Option<HashMap<K, V>>,
) -> Option<HashMap<K, V>>
where
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    match (lower, higher) {
        (Some(l), Some(h)) => Some(merge_maps(l, h)),
        (Some(l), None) => Some(l.clone()),
        (None, Some(h)) => Some(h.clone()),
        (None, None) => None,
    }
}

/// Merges two hash maps, with `higher` taking precedence for duplicate keys.
fn merge_maps<K, V>(lower: &HashMap<K, V>, higher: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    let mut result = lower.clone();
    for (k, v) in higher {
        result.insert(k.clone(), v.clone());
    }
    result
}

/// Merges two vectors, combining all unique elements.
fn merge_vecs<T: Clone + PartialEq>(lower: &[T], higher: &[T]) -> Vec<T> {
    let mut result = higher.to_vec();
    for item in lower {
        if !result.contains(item) {
            result.push(item.clone());
        }
    }
    result
}

/// Merges multiple settings in order of precedence.
///
/// Settings are expected to be ordered from highest to lowest precedence.
#[instrument(level = Level::TRACE)]
pub fn merge_all(settings: &[(SettingsLevel, Settings)]) -> Settings {
    if settings.is_empty() {
        return Settings::default();
    }

    // Start with the lowest precedence and merge up
    let mut iter = settings.iter().rev();
    let (_, first) = iter.next().unwrap();
    let mut result = first.clone();

    for (_, higher) in iter {
        result = result.merge(higher);
    }

    result
}

/// Builder for constructing merged settings from multiple levels.
#[derive(Debug, Default)]
pub struct SettingsMerger {
    settings: Vec<(SettingsLevel, Settings)>,
}

impl SettingsMerger {
    /// Creates a new empty SettingsMerger.
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds settings at a specific level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn add(mut self, level: SettingsLevel, settings: Settings) -> Self {
        self.settings.push((level, settings));
        self
    }

    /// Adds settings if present (Some).
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn add_optional(self, level: SettingsLevel, settings: Option<Settings>) -> Self {
        match settings {
            Some(s) => self.add(level, s),
            None => self,
        }
    }

    /// Merges all added settings and returns the result.
    ///
    /// Settings are sorted by precedence before merging.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn merge(mut self) -> Settings {
        // Sort by precedence (system > project-local > project > user)
        self.settings.sort_by_key(|(level, _)| match level {
            SettingsLevel::System => 0,
            SettingsLevel::ProjectLocal => 1,
            SettingsLevel::Project => 2,
            SettingsLevel::User => 3,
        });

        merge_all(&self.settings)
    }
}

/// Loads and merges settings using figment.
///
/// This provides an alternative to the manual `Merge` trait implementation,
/// using figment's powerful configuration merging capabilities.
///
/// Settings are loaded in order of precedence (lowest to highest):
/// 1. User settings (`~/.claude/settings.json`)
/// 2. Project settings (`.claude/settings.json`)
/// 3. Project local settings (`.claude/settings.local.json`)
/// 4. System settings (`/etc/claude-code/managed-settings.json`)
///
/// Higher precedence settings override lower precedence ones.
#[derive(Debug, Clone)]
pub struct FigmentLoader {
    resolver: PathResolver,
}

impl FigmentLoader {
    /// Creates a new FigmentLoader with the given path resolver.
    #[instrument(level = Level::TRACE)]
    pub fn new(resolver: PathResolver) -> Self {
        Self { resolver }
    }

    /// Creates a new FigmentLoader with default path resolution.
    #[instrument(level = Level::TRACE)]
    pub fn with_defaults() -> Self {
        Self::new(PathResolver::new())
    }

    /// Returns the underlying figment with all providers configured.
    ///
    /// This allows you to add additional providers or customize the merge.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn figment(&self) -> Result<Figment> {
        let mut figment = Figment::from(Serialized::defaults(Settings::default()));

        // Add providers in order of precedence (lowest to highest)
        // User settings (lowest precedence)
        if let Ok(path) = self.resolver.settings_path(SettingsLevel::User)
            && path.exists()
        {
            figment = figment.merge(Json::file(&path));
        }

        // Project settings
        if let Ok(path) = self.resolver.settings_path(SettingsLevel::Project)
            && path.exists()
        {
            figment = figment.merge(Json::file(&path));
        }

        // Project local settings
        if let Ok(path) = self.resolver.settings_path(SettingsLevel::ProjectLocal)
            && path.exists()
        {
            figment = figment.merge(Json::file(&path));
        }

        // System settings (highest precedence)
        if let Ok(path) = self.resolver.settings_path(SettingsLevel::System)
            && path.exists()
        {
            figment = figment.merge(Json::file(&path));
        }

        Ok(figment)
    }

    /// Loads and merges all settings, returning the effective configuration.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn load(&self) -> Result<Settings> {
        let figment = self.figment()?;
        Ok(figment.extract()?)
    }

    /// Loads settings with an additional JSON file merged on top.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn load_with_file(&self, path: &Path) -> Result<Settings> {
        let mut figment = self.figment()?;
        figment = figment.merge(Json::file(path));
        Ok(figment.extract()?)
    }

    /// Loads settings with additional runtime overrides.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn load_with_overrides(&self, overrides: Settings) -> Result<Settings> {
        let mut figment = self.figment()?;
        figment = figment.merge(Serialized::defaults(overrides));
        Ok(figment.extract()?)
    }
}

impl Default for FigmentLoader {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use crate::PermissionSet;

    use super::*;

    #[test]
    fn test_merge_settings_model() {
        let user = Settings::new().with_model("user-model");
        let project = Settings::new().with_model("project-model");

        let merged = user.merge(&project);
        assert_eq!(merged.model.unwrap(), "project-model");
    }

    #[test]
    fn test_merge_settings_model_fallback() {
        let user = Settings::new().with_model("user-model");
        let project = Settings::new();

        let merged = user.merge(&project);
        assert_eq!(merged.model.unwrap(), "user-model");
    }

    #[test]
    fn test_merge_permissions() {
        let user_perms = Permissions::new().allow("Bash(git:*)").deny("Read(.env)");

        let project_perms = Permissions::new().allow("Bash(npm:*)").allow("Bash(git:*)"); // duplicate

        let merged = user_perms.merge(&project_perms);

        // Should have both allows (no duplicates)
        assert_eq!(merged.allow.len(), 2);
        assert!(merged.allow.contains(&"Bash(git:*)".to_string()));
        assert!(merged.allow.contains(&"Bash(npm:*)".to_string()));

        // Should have the deny from user
        assert_eq!(merged.deny.len(), 1);
    }

    #[test]
    fn test_merge_env_maps() {
        let mut user_env = HashMap::new();
        user_env.insert("KEY1".to_string(), "user-value1".to_string());
        user_env.insert("KEY2".to_string(), "user-value2".to_string());

        let mut project_env = HashMap::new();
        project_env.insert("KEY1".to_string(), "project-value1".to_string());
        project_env.insert("KEY3".to_string(), "project-value3".to_string());

        let user = Settings::new().with_env(user_env);
        let project = Settings::new().with_env(project_env);

        let merged = user.merge(&project);
        let env = merged.env.unwrap();

        // KEY1 should be overwritten by project
        assert_eq!(env.get("KEY1").unwrap(), "project-value1");
        // KEY2 should be from user
        assert_eq!(env.get("KEY2").unwrap(), "user-value2");
        // KEY3 should be from project
        assert_eq!(env.get("KEY3").unwrap(), "project-value3");
    }

    #[test]
    fn test_merge_all() {
        let user = Settings::new().with_model("user-model");
        let project = Settings::new().with_model("project-model");
        let project_local = Settings::new(); // No model set

        let settings = vec![
            (SettingsLevel::ProjectLocal, project_local),
            (SettingsLevel::Project, project),
            (SettingsLevel::User, user),
        ];

        let merged = merge_all(&settings);

        // project-model should win (higher precedence than user, project-local has none)
        assert_eq!(merged.model.unwrap(), "project-model");
    }

    #[test]
    fn test_settings_merger() {
        let user = Settings::new()
            .with_model("user-model")
            .with_permissions(PermissionSet::new().allow("Bash(git:*)"));

        let project = Settings::new().with_permissions(PermissionSet::new().deny("Read(.env)"));

        let merged = SettingsMerger::new()
            .add(SettingsLevel::User, user)
            .add(SettingsLevel::Project, project)
            .merge();

        // Model from user (project didn't set one)
        assert_eq!(merged.model.unwrap(), "user-model");

        // Permissions merged from both
        let perms = merged.permissions;
        assert!(perms.is_allowed("Bash", Some("git status")));
        assert!(perms.is_denied("Read", Some(".env")));
    }

    #[test]
    fn test_settings_merger_precedence() {
        let user = Settings::new().with_model("user-model");
        let project = Settings::new().with_model("project-model");
        let project_local = Settings::new().with_model("local-model");

        // Add in random order - merger should sort by precedence
        let merged = SettingsMerger::new()
            .add(SettingsLevel::User, user)
            .add(SettingsLevel::ProjectLocal, project_local)
            .add(SettingsLevel::Project, project)
            .merge();

        // ProjectLocal has highest precedence
        assert_eq!(merged.model.unwrap(), "local-model");
    }

    #[test]
    fn test_figment_loader_with_overrides() {
        let resolver = PathResolver::new()
            .with_home("/nonexistent/home")
            .with_project("/nonexistent/project");

        let loader = FigmentLoader::new(resolver);

        let overrides = Settings::new().with_model("override-model");
        let settings = loader.load_with_overrides(overrides).unwrap();

        assert_eq!(settings.model.unwrap(), "override-model");
    }

    #[test]
    fn test_figment_loader_empty() {
        let resolver = PathResolver::new()
            .with_home("/nonexistent/home")
            .with_project("/nonexistent/project");

        let loader = FigmentLoader::new(resolver);
        let settings = loader.load().unwrap();

        // Should return default settings when no files exist
        assert!(settings.model.is_none());
        assert!(settings.permissions.is_empty());
    }
}
