//! Error types for the Claude settings library.

use std::path::PathBuf;
use thiserror::Error;

use crate::types::SettingsLevel;

/// Errors that can occur when working with Claude Code settings.
#[derive(Error, Debug)]
pub enum SettingsError {
    /// Failed to read settings file.
    #[error("failed to read settings from {path}: {source}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to write settings file.
    #[error("failed to write settings to {path}: {source}")]
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse settings JSON.
    #[error("failed to parse settings from {path}: {source}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// Failed to serialize settings to JSON.
    #[error("failed to serialize settings: {0}")]
    SerializeError(#[from] serde_json::Error),

    /// Failed to determine home directory.
    #[error("could not determine home directory")]
    NoHomeDirectory,

    /// Failed to determine project directory.
    #[error("could not determine project directory: {0}")]
    NoProjectDirectory(String),

    /// Settings file not found.
    #[error("settings file not found at {0}")]
    NotFound(PathBuf),

    /// Permission denied when accessing settings.
    #[error("permission denied accessing settings at {path}: {source}")]
    PermissionDenied {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Cannot write to system-level settings (read-only).
    #[error("cannot write to system-level managed settings (read-only)")]
    SystemSettingsReadOnly,

    /// Invalid settings level for the operation.
    #[error("invalid settings level '{0:?}' for this operation")]
    InvalidLevel(SettingsLevel),

    /// Failed to create parent directory.
    #[error("failed to create directory {path}: {source}")]
    CreateDirError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Invalid permission pattern.
    #[error("invalid permission pattern: {0}")]
    InvalidPermission(String),

    /// Figment configuration error.
    #[error("configuration error: {0}")]
    FigmentError(#[source] Box<figment::Error>),
}

/// Result type alias for settings operations.
pub type Result<T> = std::result::Result<T, SettingsError>;

impl From<figment::Error> for SettingsError {
    fn from(err: figment::Error) -> Self {
        SettingsError::FigmentError(Box::new(err))
    }
}
