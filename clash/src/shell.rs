//! Transactional policy editor — line-oriented protocol for pipe/interactive use.
//!
//! **Deprecated**: The policy shell relied on a legacy parsing format which has been
//! removed. Policies are now authored as Starlark (.star) files compiled to JSON. This module is retained as a stub
//! so that callers (`cmd::init`, `cmd::policy`, `main.rs`) still compile; every
//! entry point returns an error directing users to edit the JSON file directly.

use std::io::BufRead;
use std::path::PathBuf;

use anyhow::{Result, bail};

use crate::settings::{ClashSettings, PolicyLevel};

// ---------------------------------------------------------------------------
// Shell Session (stub)
// ---------------------------------------------------------------------------

/// In-memory policy editing session.
///
/// Retained for API compatibility; all operations now return an error.
pub struct ShellSession {
    /// File path to the policy file.
    pub path: PathBuf,
    /// Policy level being edited.
    pub level: PolicyLevel,
    /// Dry-run mode (no writes).
    pub dry_run: bool,
    /// Whether we're in interactive (TTY) mode.
    pub interactive: bool,
}

impl ShellSession {
    /// Create a new session for the given scope.
    pub fn new(scope: Option<&str>, dry_run: bool, interactive: bool) -> Result<Self> {
        let level = match scope {
            Some(s) => s
                .parse::<PolicyLevel>()
                .map_err(|e| anyhow::anyhow!("invalid --scope value: {e}"))?,
            None => ClashSettings::default_scope(),
        };

        let path = ClashSettings::policy_file_for_level(level)?;

        Ok(ShellSession {
            path,
            level,
            dry_run,
            interactive,
        })
    }

    /// Run in pipe mode — stub that returns an error.
    pub fn run_pipe<R: BufRead>(&mut self, _reader: R) -> Result<()> {
        bail!(
            "The policy shell has been removed. Policies are now JSON files.\n\
             Edit {} directly.",
            self.path.display()
        )
    }

    /// Run a single inline command — stub that returns an error.
    pub fn run_command(&mut self, _stmt: &str) -> Result<()> {
        bail!(
            "The policy shell has been removed. Policies are now JSON files.\n\
             Edit {} directly.",
            self.path.display()
        )
    }

    /// Run interactive REPL mode — stub that returns an error.
    pub fn run_interactive(&mut self) -> Result<()> {
        bail!(
            "The policy shell has been removed. Policies are now JSON files.\n\
             Edit {} directly.",
            self.path.display()
        )
    }

    /// Extract all policy block names — stub returns empty.
    pub fn extract_policy_names(&self) -> Vec<String> {
        vec![]
    }
}
