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

/// Return the session-specific temp directory for the given session ID.
pub fn session_dir(session_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("clash-{}", session_id))
}

/// Initialize a per-session history directory.
///
/// Creates `/tmp/clash-<session_id>/` with a `metadata.json` containing
/// session info. Returns the session directory path on success.
pub fn init_session(
    session_id: &str,
    cwd: &str,
    source: Option<&str>,
    model: Option<&str>,
) -> std::io::Result<PathBuf> {
    let dir = session_dir(session_id);
    std::fs::create_dir_all(&dir)?;

    let metadata = serde_json::json!({
        "session_id": session_id,
        "cwd": cwd,
        "source": source,
        "model": model,
        "started_at": chrono_timestamp(),
    });

    let meta_path = dir.join("metadata.json");
    let mut f = std::fs::File::create(&meta_path)?;
    serde_json::to_writer_pretty(&mut f, &metadata).map_err(std::io::Error::other)?;

    Ok(dir)
}

/// Write an audit log entry for a policy decision.
///
/// Writes to the global audit log (if enabled) and to the session-specific
/// audit log in the session tempdir (if the directory exists).
#[instrument(level = Level::TRACE, skip(trace, tool_input))]
pub fn log_decision(
    config: &AuditConfig,
    session_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    effect: Effect,
    reason: Option<&str>,
    trace: &DecisionTrace,
) {
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

    // Write to global audit log if enabled.
    if config.enabled {
        let path = config.log_path();
        if let Err(e) = append_entry(&path, &entry) {
            warn!(error = %e, path = %path.display(), "Failed to write audit log entry");
        }
    }

    // Write to session-specific audit log if the session dir exists.
    let session_log = session_dir(session_id).join("audit.jsonl");
    if session_log.parent().is_some_and(|p| p.exists())
        && let Err(e) = append_entry(&session_log, &entry)
    {
        warn!(error = %e, path = %session_log.display(), "Failed to write session audit entry");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ir::{DecisionTrace, RuleMatch};

    fn mock_trace(matched: usize) -> DecisionTrace {
        DecisionTrace {
            matched_rules: (0..matched)
                .map(|i| RuleMatch {
                    rule_index: i,
                    description: format!("rule {}", i),
                    effect: Effect::Allow,
                })
                .collect(),
            skipped_rules: vec![],
            final_resolution: "test".into(),
        }
    }

    #[test]
    fn test_session_dir_uses_session_id() {
        let dir = session_dir("abc-123");
        assert!(dir.ends_with("clash-abc-123"));
    }

    #[test]
    fn test_init_session_creates_dir_and_metadata() {
        let id = format!("test-{}", std::process::id());
        let dir = session_dir(&id);
        // Clean up from previous runs.
        let _ = std::fs::remove_dir_all(&dir);

        let result = init_session(&id, "/tmp", Some("startup"), Some("claude-sonnet"));
        assert!(result.is_ok());

        let meta_path = dir.join("metadata.json");
        assert!(meta_path.exists(), "metadata.json should exist");

        let contents = std::fs::read_to_string(&meta_path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(json["session_id"], id);
        assert_eq!(json["cwd"], "/tmp");
        assert_eq!(json["source"], "startup");
        assert_eq!(json["model"], "claude-sonnet");

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_decision_writes_to_session_dir() {
        let id = format!("test-log-{}", std::process::id());
        let dir = session_dir(&id);
        let _ = std::fs::remove_dir_all(&dir);

        // Create session dir first.
        init_session(&id, "/tmp", None, None).unwrap();

        // Log a decision (global audit disabled, session dir exists).
        let config = AuditConfig {
            enabled: false,
            path: None,
        };
        log_decision(
            &config,
            &id,
            "Bash",
            &serde_json::json!({"command": "ls"}),
            Effect::Allow,
            Some("policy: allowed"),
            &mock_trace(1),
        );

        let session_log = dir.join("audit.jsonl");
        assert!(session_log.exists(), "session audit.jsonl should exist");

        let contents = std::fs::read_to_string(&session_log).unwrap();
        let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(entry["tool_name"], "Bash");
        assert_eq!(entry["decision"], "allow");
        assert_eq!(entry["matched_rules"], 1);

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_log_decision_skips_session_when_no_dir() {
        let id = "nonexistent-session-12345";
        let dir = session_dir(id);
        // Ensure no dir exists.
        let _ = std::fs::remove_dir_all(&dir);

        let config = AuditConfig {
            enabled: false,
            path: None,
        };

        // Should not panic or create the dir.
        log_decision(
            &config,
            id,
            "Read",
            &serde_json::json!({"file_path": "/tmp/x"}),
            Effect::Ask,
            None,
            &mock_trace(0),
        );

        assert!(
            !dir.exists(),
            "should not create session dir on log_decision"
        );
    }
}
