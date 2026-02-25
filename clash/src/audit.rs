//! Structured audit logging for policy decisions.
//!
//! Writes JSON Lines entries to `~/.clash/audit.jsonl` (configurable via settings).
//! Each entry records the tool invocation and the policy decision.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{Level, instrument, warn};

use crate::policy::Effect;
use crate::policy::ir::DecisionTrace;

/// A single audit log entry.
#[derive(Debug, Serialize)]
struct AuditEntry<'a> {
    /// Unix timestamp with millisecond precision (e.g. `1706123456.789`).
    timestamp: String,
    /// The session that produced this entry.
    session_id: &'a str,
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

/// Accumulated session statistics for the status line.
///
/// Pre-aggregated counters and last-decision metadata, serialized as JSON.
/// Updated atomically on every policy decision.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionStats {
    pub allowed: u64,
    pub denied: u64,
    pub asked: u64,
    pub last_tool: Option<String>,
    pub last_input_summary: Option<String>,
    pub last_effect: Option<Effect>,
    pub last_at: Option<String>,
    /// Suggested allow command when the last decision was deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_deny_hint: Option<String>,
}

/// Return the session-specific temp directory for the given session ID.
pub fn session_dir(session_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("clash-{}", session_id))
}

/// Path to the session stats sidecar file.
fn stats_path(session_id: &str) -> PathBuf {
    session_dir(session_id).join("stats.json")
}

/// Errors that can occur when reading session stats.
#[derive(Debug, thiserror::Error)]
pub enum StatsReadError {
    /// The stats file does not exist yet (no session initialized).
    #[error("stats file not found")]
    NotFound,
    /// The file exists but couldn't be read (permissions, etc.).
    #[error("failed to read stats: {0}")]
    Io(#[from] std::io::Error),
    /// The file exists but contains invalid JSON.
    #[error("malformed stats JSON: {0}")]
    Malformed(#[from] serde_json::Error),
}

/// Read the current session stats.
///
/// Distinguishes missing file, IO failure, and malformed JSON via
/// `StatsReadError` variants.
pub fn read_session_stats(session_id: &str) -> Result<SessionStats, StatsReadError> {
    let path = stats_path(session_id);
    let contents = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StatsReadError::NotFound
        } else {
            StatsReadError::Io(e)
        }
    })?;
    Ok(serde_json::from_str(&contents)?)
}

/// Record a policy decision in the session stats.
///
/// Increments the counter for `effect`, updates last-decision metadata,
/// and persists atomically. Must be called at most once per tool use.
pub fn update_session_stats(
    session_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    effect: Effect,
    cwd: &str,
) {
    let mut stats = match read_session_stats(session_id) {
        Ok(s) => s,
        Err(StatsReadError::NotFound) => SessionStats::default(),
        Err(e) => {
            warn!(error = %e, "Failed to read session stats, resetting");
            SessionStats::default()
        }
    };

    match effect {
        Effect::Allow => stats.allowed += 1,
        Effect::Deny => stats.denied += 1,
        Effect::Ask => stats.asked += 1,
    }

    stats.last_tool = Some(tool_name.to_string());
    stats.last_effect = Some(effect);
    stats.last_at = Some(chrono_timestamp());

    stats.last_input_summary = Some(tool_input_summary(tool_name, tool_input, cwd));

    stats.last_deny_hint = if effect == Effect::Deny {
        match deny_hint(tool_name, tool_input, cwd) {
            Ok(hint) => Some(hint),
            Err(e) => {
                warn!(error = %e, "Failed to generate deny hint");
                None
            }
        }
    } else {
        None
    };

    write_session_stats(session_id, &stats);
}

/// Persist stats atomically to prevent partial reads by concurrent renders.
fn write_session_stats(session_id: &str, stats: &SessionStats) {
    let path = stats_path(session_id);
    let tmp_path = session_dir(session_id).join(".stats.json.tmp");

    let json = match serde_json::to_string(stats) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "Failed to serialize session stats");
            return;
        }
    };

    if let Err(e) = std::fs::write(&tmp_path, &json) {
        warn!(error = %e, path = %tmp_path.display(), "Failed to write session stats temp file");
        return;
    }

    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        warn!(error = %e, "Failed to rename session stats temp file");
    }
}

/// Initialize a per-session history directory with session metadata.
///
/// Returns the directory path on success.
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
        session_id,
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

    // Always write to session-specific audit log so `clash debug log` has data.
    let session_log = session_dir(session_id).join("audit.jsonl");
    if let Err(e) = append_entry(&session_log, &entry) {
        warn!(error = %e, path = %session_log.display(), "Failed to write session audit entry");
    }
}

/// Generate the narrowest possible allow rule for a denied tool invocation.
///
/// Returns a `clash allow '(...)'` command with exact arguments matching
/// the denied capability. Errors if the tool produces no capability queries.
fn deny_hint(tool_name: &str, tool_input: &serde_json::Value, cwd: &str) -> Result<String, String> {
    use crate::policy::eval::{CapQuery, tool_to_queries};

    let queries = tool_to_queries(tool_name, tool_input, cwd);
    let query = queries
        .first()
        .ok_or_else(|| format!("tool_to_queries returned no queries for {tool_name}"))?;

    let rule = match query {
        CapQuery::Exec { bin, args } => {
            if args.is_empty() {
                format!("(exec \"{}\")", bin)
            } else {
                let quoted_args: Vec<String> = args.iter().map(|a| format!("\"{}\"", a)).collect();
                format!("(exec \"{}\" {})", bin, quoted_args.join(" "))
            }
        }
        CapQuery::Fs { op, path } => {
            format!("(fs {} \"{}\")", op, path)
        }
        CapQuery::Net { domain } => {
            format!("(net \"{}\")", domain)
        }
        CapQuery::Tool { name } => {
            format!("(tool \"{}\")", name)
        }
    };

    Ok(format!("clash allow '{}'", rule))
}

/// Concise, human-readable summary of a tool invocation for display.
fn tool_input_summary(tool_name: &str, input: &serde_json::Value, cwd: &str) -> String {
    use crate::policy::eval::{CapQuery, tool_to_queries};

    let queries = tool_to_queries(tool_name, input, cwd);
    let summary = match queries.first() {
        Some(CapQuery::Exec { bin, args }) => {
            if args.is_empty() {
                bin.clone()
            } else {
                format!("{} {}", bin, args.join(" "))
            }
        }
        Some(CapQuery::Fs { path, .. }) => shorten_path(path),
        Some(CapQuery::Net { domain }) => domain.clone(),
        Some(CapQuery::Tool { name }) => name.clone(),
        None => String::new(),
    };

    truncate_str(&summary, 60)
}

/// Shorten a file path to just the last two components.
fn shorten_path(path: &str) -> String {
    let p = std::path::Path::new(path);
    let components: Vec<_> = p.components().rev().take(2).collect();
    if components.len() == 2 {
        format!(
            "{}/{}",
            components[1].as_os_str().to_string_lossy(),
            components[0].as_os_str().to_string_lossy()
        )
    } else {
        p.file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string())
    }
}

/// Truncate a string to `max` chars, appending "..." if needed.
fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let truncate_at = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max)
        .last()
        .unwrap_or(0);
    format!("{}...", &s[..truncate_at])
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
                    has_active_constraints: false,
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
    fn test_log_decision_creates_session_dir_if_needed() {
        let id = format!("test-autocreate-{}", std::process::id());
        let dir = session_dir(&id);
        // Ensure no dir exists.
        let _ = std::fs::remove_dir_all(&dir);

        let config = AuditConfig {
            enabled: false,
            path: None,
        };

        log_decision(
            &config,
            &id,
            "Read",
            &serde_json::json!({"file_path": "/tmp/x"}),
            Effect::Ask,
            None,
            &mock_trace(0),
        );

        let session_log = dir.join("audit.jsonl");
        assert!(
            session_log.exists(),
            "session audit.jsonl should be created even without prior init"
        );

        // Clean up.
        let _ = std::fs::remove_dir_all(&dir);
    }
}
