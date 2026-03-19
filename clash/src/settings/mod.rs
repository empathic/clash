//! Loading and resolving clash configuration and policy files.
//!
//! This module is the entry point for the settings system. It defines the core
//! [`ClashSettings`] struct and re-exports public items from submodules:
//!
//! - [`env`] — Environment variable checks for clash mode control.
//! - [`discovery`] — Policy file discovery, preset types, and default policy compilation.
//! - [`loader`] — Policy loading, compilation, and `ClashSettings` construction.

use std::path::PathBuf;

use crate::audit::AuditConfig;
use crate::notifications::NotificationConfig;
use crate::policy::match_tree::CompiledPolicy;

mod env;
mod discovery;
mod loader;

// Re-export all public items so existing `crate::settings::*` imports continue to work.
pub use env::{CLASH_DISABLE_ENV, CLASH_PASSTHROUGH_ENV, is_disabled, is_passthrough};
pub use discovery::{
    PolicyLevel,
    DEFAULT_POLICY_TEMPLATE, SANDBOX_PRESETS, SandboxPreset,
    compile_default_policy_to_json, compile_default_policy_to_json_with_preset,
    settings_dir, policy_file, project_policy_file, session_policy_file,
    evaluate_star_policy, evaluate_policy_file,
    parse_notification_config,
};


/// Session-level context from Claude Code hook input.
///
/// Carries runtime values that aren't available as standard environment
/// variables but are needed to resolve session-specific policy variables.
#[derive(Debug, Clone, Default)]
pub struct HookContext {
    /// Parent directory of the session transcript file. Agent output files
    /// are stored here and must always be readable.
    pub transcript_dir: Option<String>,
}

impl HookContext {
    /// Build from a transcript_path (as received in hook input).
    pub fn from_transcript_path(transcript_path: &str) -> Self {
        let transcript_dir = if transcript_path.is_empty() {
            None
        } else {
            std::path::Path::new(transcript_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
        };
        Self { transcript_dir }
    }
}

/// A policy source loaded from a specific level.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    /// Which level this policy came from.
    pub level: PolicyLevel,
    /// The file path it was loaded from.
    pub path: PathBuf,
    /// The raw source text.
    pub source: String,
}

#[derive(Debug, Default)]
pub struct ClashSettings {
    /// Pre-compiled policy tree for fast evaluation.
    compiled: Option<CompiledPolicy>,

    /// Policy sources loaded from each level (ordered by precedence, highest first).
    loaded_policies: Vec<LoadedPolicy>,

    /// Notification and external service configuration, loaded from policy.yaml.
    pub notifications: NotificationConfig,

    /// Warning message if parsing the notifications config failed or was incomplete.
    pub notification_warning: Option<String>,

    /// Audit logging configuration, loaded from policy.yaml.
    pub audit: AuditConfig,

    /// Error message if policy failed to parse or compile.
    policy_error: Option<String>,
}
