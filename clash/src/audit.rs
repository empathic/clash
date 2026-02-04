//! Structured audit logging for policy decisions.
//!
//! Writes JSON Lines entries to `~/.clash/audit.jsonl` (configurable via settings).
//! Each entry records the tool invocation and the policy decision.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;
use tracing::{Level, instrument, warn};

use crate::policy::Effect;
use crate::policy::ir::DecisionTrace;

/// A single audit log entry.
#[derive(Debug, Serialize)]
struct AuditEntry<'a> {
    /// Unix timestamp with millisecond precision (e.g. `1706123456.789`).
    timestamp: String,
    /// The tool that was invoked (e.g. "Bash", "Read").
    tool_name: &'a str,
    /// Summary of the tool input (truncated for large inputs).
    tool_input_summary: String,
    /// The policy decision effect.
    decision: &'a str,
    /// Human-readable reason, if any.
    reason: Option<&'a str>,
    /// Summary of matched rules.
    matched_rules: usize,
    /// Summary of skipped rules.
    skipped_rules: usize,
    /// How the decision was resolved.
    resolution: &'a str,
}

/// Configuration for audit logging.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the audit log file. Defaults to `~/.clash/audit.jsonl`.
    #[serde(default)]
    pub path: Option<String>,
}

impl AuditConfig {
    /// Resolve the audit log path.
    pub fn log_path(&self) -> PathBuf {
        if let Some(ref path) = self.path {
            PathBuf::from(path)
        } else {
            dirs::home_dir()
                .map(|h| h.join(".clash").join("audit.jsonl"))
                .unwrap_or_else(|| PathBuf::from("audit.jsonl"))
        }
    }
}

/// Write an audit log entry for a policy decision.
#[instrument(level = Level::TRACE, skip(trace, tool_input))]
pub fn log_decision(
    config: &AuditConfig,
    tool_name: &str,
    tool_input: &serde_json::Value,
    effect: Effect,
    reason: Option<&str>,
    trace: &DecisionTrace,
) {
    if !config.enabled {
        return;
    }

    let path = config.log_path();

    // Truncate tool_input for the log entry.
    let input_str = tool_input.to_string();
    let tool_input_summary = if input_str.len() > 200 {
        let truncate_at = input_str
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= 200)
            .last()
            .unwrap_or(0);
        format!("{}...", &input_str[..truncate_at])
    } else {
        input_str
    };

    let entry = AuditEntry {
        timestamp: chrono_timestamp(),
        tool_name,
        tool_input_summary,
        decision: effect_str(effect),
        reason,
        matched_rules: trace.matched_rules.len(),
        skipped_rules: trace.skipped_rules.len(),
        resolution: &trace.final_resolution,
    };

    if let Err(e) = append_entry(&path, &entry) {
        warn!(error = %e, path = %path.display(), "Failed to write audit log entry");
    }
}

fn effect_str(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
        Effect::Ask => "ask",
    }
}

fn chrono_timestamp() -> String {
    // Use std time — no chrono dependency needed.
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Format as simple unix timestamp with fractional seconds.
    let millis = duration.subsec_millis();
    format!("{}.{:03}", secs, millis)
}

fn append_entry(path: &std::path::Path, entry: &AuditEntry) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let json = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    writeln!(file, "{}", json)?;
    Ok(())
}
