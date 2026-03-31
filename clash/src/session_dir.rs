//! Typed handle for a clash session directory.
//!
//! Centralizes the session directory layout so that path construction
//! lives in one place instead of being scattered across audit, trace,
//! settings, and session_policy modules.

use std::path::{Path, PathBuf};

use crate::settings::ClashSettings;

/// A session directory rooted at `~/.clash/sessions/<session_id>/`.
///
/// Every session-scoped file (stats, audit log, trace, policy) is
/// accessed through this struct, making the directory layout explicit
/// and easy to change in one place.
#[derive(Debug, Clone)]
pub struct SessionDir {
    root: PathBuf,
}

impl SessionDir {
    /// Build the session directory path for the given session ID.
    ///
    /// Stores sessions under `~/.clash/sessions/<id>/` so that logs
    /// persist across reboots (unlike `$TMPDIR`).
    pub fn new(session_id: &str) -> Self {
        let root = ClashSettings::settings_dir()
            .map(|d| d.join("sessions").join(session_id))
            .unwrap_or_else(|_| std::env::temp_dir().join(format!("clash-{session_id}")));
        Self { root }
    }

    /// The root directory path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `stats.json` — per-session decision counters.
    pub fn stats(&self) -> PathBuf {
        self.root.join("stats.json")
    }

    /// `audit.jsonl` — per-session audit log.
    pub fn audit_log(&self) -> PathBuf {
        self.root.join("audit.jsonl")
    }

    /// `trace.json` — session trace metadata + incremental state.
    pub fn trace_meta(&self) -> PathBuf {
        self.root.join("trace.json")
    }

    /// `trace.jsonl` — append-only toolpath steps.
    pub fn trace_steps(&self) -> PathBuf {
        self.root.join("trace.jsonl")
    }

    /// `policy.star` — session-level policy overrides.
    pub fn policy(&self) -> PathBuf {
        self.root.join("policy.star")
    }

    /// `metadata.json` — session metadata written at init.
    pub fn metadata(&self) -> PathBuf {
        self.root.join("metadata.json")
    }

    /// `pending/` — directory for pending session policy proposals.
    pub fn pending_dir(&self) -> PathBuf {
        self.root.join("pending")
    }
}
