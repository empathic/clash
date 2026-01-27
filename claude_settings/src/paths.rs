//! Path resolution for Claude Code settings files.
//!
//! This module provides utilities for determining the correct file paths
//! for settings at different levels (user, project, system).

use std::env;
use std::path::{Path, PathBuf};

use crate::error::{Result, SettingsError};
use crate::types::SettingsLevel;

/// The name of the Claude settings directory.
const CLAUDE_DIR: &str = ".claude";

/// The name of the settings file.
const SETTINGS_FILE: &str = "settings.json";

/// The name of the local settings file.
const SETTINGS_LOCAL_FILE: &str = "settings.local.json";

/// The system-wide managed settings path.
const SYSTEM_SETTINGS_PATH: &str = "/etc/claude-code/managed-settings.json";

/// Resolver for Claude Code settings file paths.
#[derive(Debug, Clone)]
pub struct PathResolver {
    /// Override for the home directory (useful for testing).
    home_override: Option<PathBuf>,

    /// Override for the project directory.
    project_override: Option<PathBuf>,
}

impl Default for PathResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PathResolver {
    /// Creates a new PathResolver with default paths.
    pub fn new() -> Self {
        Self {
            home_override: None,
            project_override: None,
        }
    }

    /// Creates a PathResolver with a custom home directory.
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home_override = Some(home.into());
        self
    }

    /// Creates a PathResolver with a custom project directory.
    pub fn with_project(mut self, project: impl Into<PathBuf>) -> Self {
        self.project_override = Some(project.into());
        self
    }

    /// Returns the home directory path.
    pub fn home_dir(&self) -> Result<PathBuf> {
        if let Some(ref home) = self.home_override {
            return Ok(home.clone());
        }

        env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| SettingsError::NoHomeDirectory)
    }

    /// Returns the project directory path.
    ///
    /// If not explicitly set, attempts to find the project root by looking
    /// for a .claude directory or .git directory in the current directory
    /// or its parents.
    pub fn project_dir(&self) -> Result<PathBuf> {
        if let Some(ref project) = self.project_override {
            return Ok(project.clone());
        }

        let cwd =
            env::current_dir().map_err(|e| SettingsError::NoProjectDirectory(e.to_string()))?;

        // First, check if .claude exists in current directory or parents
        if let Some(path) = find_ancestor_with(&cwd, CLAUDE_DIR) {
            return Ok(path);
        }

        // Fallback to finding .git directory
        if let Some(path) = find_ancestor_with(&cwd, ".git") {
            return Ok(path);
        }

        // Use current directory as fallback
        Ok(cwd)
    }

    /// Returns the path for the settings file at the given level.
    pub fn settings_path(&self, level: SettingsLevel) -> Result<PathBuf> {
        match level {
            SettingsLevel::System => Ok(PathBuf::from(SYSTEM_SETTINGS_PATH)),

            SettingsLevel::User => {
                let home = self.home_dir()?;
                Ok(home.join(CLAUDE_DIR).join(SETTINGS_FILE))
            }

            SettingsLevel::Project => {
                let project = self.project_dir()?;
                Ok(project.join(CLAUDE_DIR).join(SETTINGS_FILE))
            }

            SettingsLevel::ProjectLocal => {
                let project = self.project_dir()?;
                Ok(project.join(CLAUDE_DIR).join(SETTINGS_LOCAL_FILE))
            }
        }
    }

    /// Returns all settings paths in order of precedence (highest first).
    pub fn all_settings_paths(&self) -> Result<Vec<(SettingsLevel, PathBuf)>> {
        let mut paths = Vec::new();

        for level in SettingsLevel::all_by_priority() {
            match self.settings_path(*level) {
                Ok(path) => paths.push((*level, path)),
                Err(SettingsError::NoHomeDirectory) if *level == SettingsLevel::User => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(paths)
    }

    /// Returns the path to the .claude directory for a given level.
    pub fn claude_dir(&self, level: SettingsLevel) -> Result<PathBuf> {
        match level {
            SettingsLevel::System => Ok(PathBuf::from("/etc/claude-code")),
            SettingsLevel::User => {
                let home = self.home_dir()?;
                Ok(home.join(CLAUDE_DIR))
            }
            SettingsLevel::Project | SettingsLevel::ProjectLocal => {
                let project = self.project_dir()?;
                Ok(project.join(CLAUDE_DIR))
            }
        }
    }
}

/// Finds the nearest ancestor directory containing the given name.
fn find_ancestor_with(start: &Path, name: &str) -> Option<PathBuf> {
    let mut current = start.to_path_buf();

    loop {
        if current.join(name).exists() {
            return Some(current);
        }

        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_path_resolver_with_overrides() {
        let resolver = PathResolver::new()
            .with_home("/custom/home")
            .with_project("/custom/project");

        assert_eq!(resolver.home_dir().unwrap(), PathBuf::from("/custom/home"));
        assert_eq!(
            resolver.project_dir().unwrap(),
            PathBuf::from("/custom/project")
        );
    }

    #[test]
    fn test_user_settings_path() {
        let resolver = PathResolver::new().with_home("/home/testuser");

        let path = resolver.settings_path(SettingsLevel::User).unwrap();
        assert_eq!(path, PathBuf::from("/home/testuser/.claude/settings.json"));
    }

    #[test]
    fn test_project_settings_path() {
        let resolver = PathResolver::new().with_project("/my/project");

        let path = resolver.settings_path(SettingsLevel::Project).unwrap();
        assert_eq!(path, PathBuf::from("/my/project/.claude/settings.json"));
    }

    #[test]
    fn test_project_local_settings_path() {
        let resolver = PathResolver::new().with_project("/my/project");

        let path = resolver.settings_path(SettingsLevel::ProjectLocal).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/my/project/.claude/settings.local.json")
        );
    }

    #[test]
    fn test_system_settings_path() {
        let resolver = PathResolver::new();

        let path = resolver.settings_path(SettingsLevel::System).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/etc/claude-code/managed-settings.json")
        );
    }

    #[test]
    fn test_find_ancestor_with_claude_dir() {
        let temp = TempDir::new().unwrap();
        let project_root = temp.path();
        let claude_dir = project_root.join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();

        let nested = project_root.join("src/components");
        std::fs::create_dir_all(&nested).unwrap();

        let found = find_ancestor_with(&nested, ".claude");
        assert_eq!(found, Some(project_root.to_path_buf()));
    }
}
