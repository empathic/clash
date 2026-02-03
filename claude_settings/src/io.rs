//! File I/O operations for Claude Code settings.
//!
//! This module provides functions to read and write settings files
//! at various levels (user, project, system).

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use tracing::{Level, instrument};

use crate::error::{Result, SettingsError};
use crate::paths::PathResolver;
use crate::types::{Settings, SettingsLevel};

/// Reads settings from a specific file path.
#[instrument(level = Level::TRACE)]
pub fn read_settings_from_path(path: &Path) -> Result<Settings> {
    let content = fs::read_to_string(path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => SettingsError::NotFound(path.to_path_buf()),
        ErrorKind::PermissionDenied => SettingsError::PermissionDenied {
            path: path.to_path_buf(),
            source: e,
        },
        _ => SettingsError::ReadError {
            path: path.to_path_buf(),
            source: e,
        },
    })?;

    serde_json::from_str(&content).map_err(|e| SettingsError::ParseError {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Reads settings from a specific file path, returning None if not found.
#[instrument(level = Level::TRACE)]
pub fn read_settings_from_path_optional(path: &Path) -> Result<Option<Settings>> {
    match read_settings_from_path(path) {
        Ok(settings) => Ok(Some(settings)),
        Err(SettingsError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Writes settings to a specific file path.
///
/// Creates parent directories if they don't exist.
#[instrument(level = Level::TRACE)]
pub fn write_settings_to_path(path: &Path, settings: &Settings) -> Result<()> {
    // Create parent directories if needed
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent).map_err(|e| SettingsError::CreateDirError {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let content = serde_json::to_string_pretty(settings)?;

    fs::write(path, content).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => SettingsError::PermissionDenied {
            path: path.to_path_buf(),
            source: e,
        },
        _ => SettingsError::WriteError {
            path: path.to_path_buf(),
            source: e,
        },
    })
}

/// Computes the backup path for a given path and suffix.
///
/// For `path/to/settings.json` with suffix `bak`, returns `path/to/settings.json.bak`.
fn backup_path_for(path: &Path, suffix: &str) -> PathBuf {
    let mut backup_path = path.as_os_str().to_owned();
    backup_path.push(".");
    backup_path.push(suffix);
    PathBuf::from(backup_path)
}

/// Backs up a settings file by copying it to `{path}.{suffix}`.
///
/// Returns the backup path on success, or `Ok(None)` if the source file doesn't exist.
#[instrument(level = Level::TRACE)]
pub fn backup_settings_file(path: &Path, suffix: &str) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }

    let backup_path = backup_path_for(path, suffix);

    fs::copy(path, &backup_path).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => SettingsError::PermissionDenied {
            path: backup_path.clone(),
            source: e,
        },
        _ => SettingsError::WriteError {
            path: backup_path.clone(),
            source: e,
        },
    })?;

    Ok(Some(backup_path))
}

/// Writes settings to a path, backing up the existing file first.
///
/// If the file exists, it will be copied to `{path}.{suffix}` before writing.
/// Returns the backup path if a backup was created, or `None` if the file didn't exist.
#[instrument(level = Level::TRACE)]
pub fn write_settings_to_path_with_backup(
    path: &Path,
    settings: &Settings,
    backup_suffix: &str,
) -> Result<Option<PathBuf>> {
    let backup_path = backup_settings_file(path, backup_suffix)?;
    write_settings_to_path(path, settings)?;
    Ok(backup_path)
}

/// Restores settings from a backup file.
///
/// Copies `{path}.{suffix}` back to `{path}`.
/// Returns `Ok(true)` if restored, `Ok(false)` if the backup doesn't exist.
#[instrument(level = Level::TRACE)]
pub fn restore_settings_from_backup(path: &Path, suffix: &str) -> Result<bool> {
    let backup_path = backup_path_for(path, suffix);

    if !backup_path.exists() {
        return Ok(false);
    }

    fs::copy(&backup_path, path).map_err(|e| match e.kind() {
        ErrorKind::PermissionDenied => SettingsError::PermissionDenied {
            path: path.to_path_buf(),
            source: e,
        },
        _ => SettingsError::WriteError {
            path: path.to_path_buf(),
            source: e,
        },
    })?;

    Ok(true)
}

/// Settings reader/writer that uses a PathResolver for path resolution.
#[derive(Debug, Clone)]
pub struct SettingsIO {
    resolver: PathResolver,
}

impl Default for SettingsIO {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsIO {
    /// Creates a new SettingsIO with default path resolution.
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        Self {
            resolver: PathResolver::new(),
        }
    }

    /// Creates a SettingsIO with a custom PathResolver.
    #[instrument(level = Level::TRACE)]
    pub fn with_resolver(resolver: PathResolver) -> Self {
        Self { resolver }
    }

    /// Returns a reference to the path resolver.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn resolver(&self) -> &PathResolver {
        &self.resolver
    }

    /// Reads settings from the specified level.
    ///
    /// Returns an error if the file doesn't exist.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn read(&self, level: SettingsLevel) -> Result<Settings> {
        let path = self.resolver.settings_path(level)?;
        read_settings_from_path(&path)
    }

    /// Reads settings from the specified level, returning None if not found.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn read_optional(&self, level: SettingsLevel) -> Result<Option<Settings>> {
        let path = self.resolver.settings_path(level)?;
        read_settings_from_path_optional(&path)
    }

    /// Writes settings to the specified level.
    ///
    /// Note: Writing to System level will return an error as those are read-only.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn write(&self, level: SettingsLevel, settings: &Settings) -> Result<()> {
        if level == SettingsLevel::System {
            return Err(SettingsError::SystemSettingsReadOnly);
        }

        let path = self.resolver.settings_path(level)?;
        write_settings_to_path(&path, settings)
    }

    /// Checks if settings exist at the specified level.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn exists(&self, level: SettingsLevel) -> Result<bool> {
        let path = self.resolver.settings_path(level)?;
        Ok(path.exists())
    }

    /// Deletes the settings file at the specified level.
    ///
    /// Note: Deleting System level will return an error as those are read-only.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn delete(&self, level: SettingsLevel) -> Result<()> {
        if level == SettingsLevel::System {
            return Err(SettingsError::SystemSettingsReadOnly);
        }

        let path = self.resolver.settings_path(level)?;

        if !path.exists() {
            return Ok(());
        }

        fs::remove_file(&path).map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => SettingsError::PermissionDenied { path, source: e },
            _ => SettingsError::WriteError { path, source: e },
        })
    }

    /// Reads all existing settings files and returns them with their levels.
    ///
    /// Returns settings in order of precedence (highest first).
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn read_all(&self) -> Result<Vec<(SettingsLevel, Settings)>> {
        let mut results = Vec::new();

        for (level, path) in self.resolver.all_settings_paths()? {
            if let Some(settings) = read_settings_from_path_optional(&path)? {
                results.push((level, settings));
            }
        }

        Ok(results)
    }

    /// Backs up settings at the specified level by copying to `{path}.{suffix}`.
    ///
    /// Returns the backup path on success, or `Ok(None)` if the settings file doesn't exist.
    ///
    /// Note: Backing up System level will return an error as those are read-only.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn backup(&self, level: SettingsLevel, suffix: &str) -> Result<Option<PathBuf>> {
        if level == SettingsLevel::System {
            return Err(SettingsError::SystemSettingsReadOnly);
        }

        let path = self.resolver.settings_path(level)?;
        backup_settings_file(&path, suffix)
    }

    /// Writes settings to the specified level, backing up the existing file first.
    ///
    /// If settings exist at this level, they will be copied to `{path}.{suffix}` before writing.
    /// Returns the backup path if a backup was created, or `None` if no file existed.
    ///
    /// Note: Writing to System level will return an error as those are read-only.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn write_with_backup(
        &self,
        level: SettingsLevel,
        settings: &Settings,
        backup_suffix: &str,
    ) -> Result<Option<PathBuf>> {
        if level == SettingsLevel::System {
            return Err(SettingsError::SystemSettingsReadOnly);
        }

        let path = self.resolver.settings_path(level)?;
        write_settings_to_path_with_backup(&path, settings, backup_suffix)
    }

    /// Restores settings at the specified level from a backup file.
    ///
    /// Copies `{path}.{suffix}` back to `{path}`.
    /// Returns `Ok(true)` if restored, `Ok(false)` if the backup doesn't exist.
    ///
    /// Note: Restoring System level will return an error as those are read-only.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn restore_from_backup(&self, level: SettingsLevel, suffix: &str) -> Result<bool> {
        if level == SettingsLevel::System {
            return Err(SettingsError::SystemSettingsReadOnly);
        }

        let path = self.resolver.settings_path(level)?;
        restore_settings_from_backup(&path, suffix)
    }

    /// Checks if a backup exists for the specified level and suffix.
    ///
    /// Returns `Ok(true)` if the backup file exists, `Ok(false)` otherwise.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn backup_exists(&self, level: SettingsLevel, suffix: &str) -> Result<bool> {
        let path = self.resolver.settings_path(level)?;
        let backup_path = backup_path_for(&path, suffix);
        Ok(backup_path.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PermissionSet;
    use tempfile::TempDir;

    fn setup_test_io() -> (TempDir, SettingsIO) {
        let temp = TempDir::new().unwrap();
        let resolver = PathResolver::new()
            .with_home(temp.path().join("home"))
            .with_project(temp.path().join("project"));

        // Create the directories
        fs::create_dir_all(temp.path().join("home/.claude")).unwrap();
        fs::create_dir_all(temp.path().join("project/.claude")).unwrap();

        (temp, SettingsIO::with_resolver(resolver))
    }

    #[test]
    fn test_write_and_read_user_settings() {
        let (_temp, io) = setup_test_io();

        let settings = Settings::new()
            .with_model("claude-opus-4-5-20251101")
            .with_permissions(PermissionSet::new().allow("Bash(git:*)"));

        io.write(SettingsLevel::User, &settings).unwrap();

        let read_settings = io.read(SettingsLevel::User).unwrap();
        assert_eq!(settings, read_settings);
    }

    #[test]
    fn test_write_and_read_project_settings() {
        let (_temp, io) = setup_test_io();

        let settings = Settings::new().with_model("claude-sonnet-4-20250514");

        io.write(SettingsLevel::Project, &settings).unwrap();

        let read_settings = io.read(SettingsLevel::Project).unwrap();
        assert_eq!(settings, read_settings);
    }

    #[test]
    fn test_read_optional_nonexistent() {
        let (_temp, io) = setup_test_io();

        let result = io.read_optional(SettingsLevel::User).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_exists() {
        let (_temp, io) = setup_test_io();

        assert!(!io.exists(SettingsLevel::User).unwrap());

        io.write(SettingsLevel::User, &Settings::new()).unwrap();

        assert!(io.exists(SettingsLevel::User).unwrap());
    }

    #[test]
    fn test_delete() {
        let (_temp, io) = setup_test_io();

        io.write(SettingsLevel::User, &Settings::new()).unwrap();
        assert!(io.exists(SettingsLevel::User).unwrap());

        io.delete(SettingsLevel::User).unwrap();
        assert!(!io.exists(SettingsLevel::User).unwrap());
    }

    #[test]
    fn test_system_settings_read_only() {
        let (_temp, io) = setup_test_io();

        let result = io.write(SettingsLevel::System, &Settings::new());
        assert!(matches!(result, Err(SettingsError::SystemSettingsReadOnly)));

        let result = io.delete(SettingsLevel::System);
        assert!(matches!(result, Err(SettingsError::SystemSettingsReadOnly)));
    }

    #[test]
    fn test_read_all() {
        let (_temp, io) = setup_test_io();

        let user_settings = Settings::new().with_model("user-model");
        let project_settings = Settings::new().with_model("project-model");

        io.write(SettingsLevel::User, &user_settings).unwrap();
        io.write(SettingsLevel::Project, &project_settings).unwrap();

        let all = io.read_all().unwrap();
        assert_eq!(all.len(), 2);

        // Project should come before User in precedence
        assert_eq!(all[0].0, SettingsLevel::Project);
        assert_eq!(all[1].0, SettingsLevel::User);
    }

    #[test]
    fn test_backup_creates_file() {
        let (_temp, io) = setup_test_io();

        let settings = Settings::new().with_model("original-model");
        io.write(SettingsLevel::User, &settings).unwrap();

        let backup_path = io.backup(SettingsLevel::User, "bak").unwrap();
        assert!(backup_path.is_some());

        let backup_path = backup_path.unwrap();
        assert!(backup_path.exists());
        assert!(backup_path.to_string_lossy().ends_with("settings.json.bak"));

        // Verify backup content matches original by reading both as Settings
        let backup_settings: Settings =
            serde_json::from_str(&fs::read_to_string(&backup_path).unwrap()).unwrap();
        assert_eq!(backup_settings.model.as_deref(), Some("original-model"));
    }

    #[test]
    fn test_backup_returns_none_when_missing() {
        let (_temp, io) = setup_test_io();

        let result = io.backup(SettingsLevel::User, "bak").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_write_with_backup() {
        let (_temp, io) = setup_test_io();

        // Write original settings
        let original = Settings::new().with_model("original-model");
        io.write(SettingsLevel::User, &original).unwrap();

        // Write new settings with backup
        let new_settings = Settings::new().with_model("new-model");
        let backup_path = io
            .write_with_backup(SettingsLevel::User, &new_settings, "bak")
            .unwrap();

        assert!(backup_path.is_some());

        // Verify new settings were written
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("new-model"));

        // Verify backup has original content
        let backup_path = backup_path.unwrap();
        let backup_settings: Settings =
            serde_json::from_str(&fs::read_to_string(&backup_path).unwrap()).unwrap();
        assert_eq!(backup_settings.model.as_deref(), Some("original-model"));
    }

    #[test]
    fn test_write_with_backup_no_existing() {
        let (_temp, io) = setup_test_io();

        // Write new settings with backup when no file exists
        let settings = Settings::new().with_model("new-model");
        let backup_path = io
            .write_with_backup(SettingsLevel::User, &settings, "bak")
            .unwrap();

        // No backup created since file didn't exist
        assert!(backup_path.is_none());

        // Verify settings were written
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("new-model"));
    }

    #[test]
    fn test_restore_from_backup() {
        let (_temp, io) = setup_test_io();

        // Write original and create backup
        let original = Settings::new().with_model("original-model");
        io.write(SettingsLevel::User, &original).unwrap();
        io.backup(SettingsLevel::User, "bak").unwrap();

        // Overwrite with new settings
        let new_settings = Settings::new().with_model("new-model");
        io.write(SettingsLevel::User, &new_settings).unwrap();

        // Verify new settings are active
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("new-model"));

        // Restore from backup
        let restored = io.restore_from_backup(SettingsLevel::User, "bak").unwrap();
        assert!(restored);

        // Verify original settings are back
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("original-model"));
    }

    #[test]
    fn test_restore_returns_false_when_no_backup() {
        let (_temp, io) = setup_test_io();

        // Write settings but don't create backup
        let settings = Settings::new().with_model("some-model");
        io.write(SettingsLevel::User, &settings).unwrap();

        // Attempt restore when no backup exists
        let restored = io.restore_from_backup(SettingsLevel::User, "bak").unwrap();
        assert!(!restored);

        // Original settings unchanged
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("some-model"));
    }

    #[test]
    fn test_backup_restore_roundtrip() {
        let (_temp, io) = setup_test_io();

        // Full cycle: write, backup via write_with_backup, modify, restore
        let original = Settings::new()
            .with_model("original")
            .with_permissions(PermissionSet::new().allow("Bash(git:*)"));
        io.write(SettingsLevel::User, &original).unwrap();

        // Write new settings with backup
        let modified = Settings::new()
            .with_model("modified")
            .with_permissions(PermissionSet::new().deny("Read(.env)"));
        io.write_with_backup(SettingsLevel::User, &modified, "backup")
            .unwrap();

        // Verify modified settings
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("modified"));

        // Restore
        io.restore_from_backup(SettingsLevel::User, "backup")
            .unwrap();

        // Verify original settings restored
        let current = io.read(SettingsLevel::User).unwrap();
        assert_eq!(current.model.as_deref(), Some("original"));
        assert!(current.permissions.is_allowed("Bash", Some("git status")));
    }

    #[test]
    fn test_backup_system_settings_read_only() {
        let (_temp, io) = setup_test_io();

        let result = io.backup(SettingsLevel::System, "bak");
        assert!(matches!(result, Err(SettingsError::SystemSettingsReadOnly)));

        let result = io.write_with_backup(SettingsLevel::System, &Settings::new(), "bak");
        assert!(matches!(result, Err(SettingsError::SystemSettingsReadOnly)));

        let result = io.restore_from_backup(SettingsLevel::System, "bak");
        assert!(matches!(result, Err(SettingsError::SystemSettingsReadOnly)));
    }

    #[test]
    fn test_backup_exists() {
        let (_temp, io) = setup_test_io();

        // No backup exists initially
        assert!(!io.backup_exists(SettingsLevel::User, "bak").unwrap());

        // Write settings and create backup
        let settings = Settings::new().with_model("test-model");
        io.write(SettingsLevel::User, &settings).unwrap();
        io.backup(SettingsLevel::User, "bak").unwrap();

        // Now backup exists
        assert!(io.backup_exists(SettingsLevel::User, "bak").unwrap());

        // Different suffix doesn't exist
        assert!(!io.backup_exists(SettingsLevel::User, "other").unwrap());
    }
}
