//! Debug tools for understanding and inspecting clash policy enforcement.
//!
//! Provides reusable building blocks for:
//! - Reading and filtering audit logs ([`log`])
//! - Replaying commands against the current policy ([`replay`])
//! - Inspecting sandbox enforcement details ([`sandbox`])
//!
//! These modules expose structured data types that can be consumed by
//! CLI commands, the statusline, or other integrations.

pub mod log;
pub mod replay;
pub mod sandbox;

use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// A parsed audit log entry (owned, for deserialization from audit.jsonl).
///
/// Mirrors the serialized `AuditEntry` format written by [`crate::audit::log_decision`],
/// but with all owned fields for convenient reading and filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    /// Session that produced this entry. May be empty for old entries
    /// written before session_id was added to the audit format.
    #[serde(default)]
    pub session_id: String,
    pub tool_name: String,
    pub tool_input_summary: String,
    pub decision: String,
    pub reason: Option<String>,
    pub matched_rules: usize,
    pub skipped_rules: usize,
    pub resolution: String,
}

impl AuditLogEntry {
    /// Parse the timestamp as seconds since epoch.
    pub fn timestamp_secs(&self) -> Option<f64> {
        self.timestamp.parse::<f64>().ok()
    }

    /// Stable 7-character hex identifier for this entry.
    ///
    /// Derived from the timestamp + tool name + input summary, so the
    /// same invocation always produces the same hash across runs.
    pub fn short_hash(&self) -> String {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.timestamp.hash(&mut hasher);
        self.tool_name.hash(&mut hasher);
        self.tool_input_summary.hash(&mut hasher);
        format!("{:07x}", hasher.finish() & 0x0FFF_FFFF)
    }
}
