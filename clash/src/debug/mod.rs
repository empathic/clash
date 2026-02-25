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

use serde::{Deserialize, Serialize};

/// A parsed audit log entry (owned, for deserialization from audit.jsonl).
///
/// Mirrors the serialized `AuditEntry` format written by [`crate::audit::log_decision`],
/// but with all owned fields for convenient reading and filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
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
}
