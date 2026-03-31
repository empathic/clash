//! Structured audit logging for policy decisions.
//!
//! Writes JSON Lines entries to `~/.clash/audit.jsonl` (configurable via settings).
//! Each entry records the tool invocation and the policy decision.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tracing::{Level, instrument, warn};

use crate::policy::Effect;
use crate::policy::ir::DecisionTrace;
use crate::session_dir::SessionDir;

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
    /// The agent permission mode when the decision was made (e.g. "default", "plan").
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'a str>,
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
    SessionDir::new(session_id).root().to_path_buf()
}

/// Path to the session stats sidecar file.
fn stats_path(session_id: &str) -> PathBuf {
    SessionDir::new(session_id).stats()
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
    let tmp_path = SessionDir::new(session_id).root().join(".stats.json.tmp");

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
/// Also appends a record to `~/.clash/sessions.jsonl` (guarded by an
/// advisory file lock) so that every session is tracked in one place.
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

    // Upsert into the global session index with a file lock.
    if let Err(e) = upsert_session_index(session_id, &metadata) {
        warn!(error = %e, "Failed to update sessions.json");
    }

    Ok(dir)
}

/// Upsert a session record into `~/.clash/sessions.json`, protected by
/// an advisory file lock so concurrent clash processes don't corrupt it.
///
/// The file is a single JSON object keyed by session ID, so re-initing
/// the same session just overwrites its entry rather than duplicating it.
fn upsert_session_index(session_id: &str, metadata: &serde_json::Value) -> std::io::Result<()> {
    let index_path = crate::settings::ClashSettings::settings_dir()
        .map(|d| d.join("sessions.json"))
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&index_path)?;

    // Acquire an exclusive advisory lock — blocks until available.
    file.lock_exclusive()?;

    // Read existing index (or start empty).
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents)?;
    let mut index: serde_json::Map<String, serde_json::Value> = if contents.trim().is_empty() {
        serde_json::Map::new()
    } else {
        serde_json::from_str(&contents).unwrap_or_default()
    };

    // Upsert this session.
    index.insert(session_id.to_string(), metadata.clone());

    // Rewrite the file from the beginning.
    file.set_len(0)?;
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0))?;
    let json = serde_json::to_string_pretty(&index).map_err(std::io::Error::other)?;
    write!(file, "{}", json)?;

    // Lock is released when `file` is dropped, but be explicit.
    file.unlock()?;
    Ok(())
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
    mode: Option<&str>,
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
        mode,
    };

    // Write to global audit log if enabled.
    if config.enabled {
        let path = config.log_path();
        if let Err(e) = append_entry(&path, &entry) {
            warn!(error = %e, path = %path.display(), "Failed to write audit log entry");
        }
    }

    // Always write to session-specific audit log so `clash debug log` has data.
    let session_log = SessionDir::new(session_id).audit_log();
    if let Err(e) = append_entry(&session_log, &entry) {
        warn!(error = %e, path = %session_log.display(), "Failed to write session audit entry");
    }
}

/// A single sandbox violation captured from the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxViolation {
    /// The Seatbelt operation that was denied (e.g. "file-write-create").
    pub operation: String,
    /// The filesystem path that was blocked.
    pub path: String,
}

/// An audit log entry for sandbox violations (separate from policy decisions).
#[derive(Debug, Serialize)]
struct SandboxViolationEntry<'a> {
    timestamp: String,
    session_id: &'a str,
    tool_name: &'a str,
    tool_use_id: &'a str,
    decision: &'a str, // always "sandbox_violation"
    tool_input_summary: &'a str,
    violations: &'a [SandboxViolation],
    /// Suggested policy rules to fix the violations.
    suggested_rules: Vec<String>,
}

/// Write sandbox violation entries to the session audit log.
///
/// Called by `clash sandbox exec` after the sandboxed child exits and
/// violations have been captured from the unified log.
pub fn log_sandbox_violations(
    session_id: &str,
    tool_name: &str,
    tool_use_id: &str,
    tool_input_summary: &str,
    violations: &[SandboxViolation],
) {
    if violations.is_empty() {
        return;
    }

    let suggested_rules: Vec<String> = deduplicated_suggestions(violations);

    let entry = SandboxViolationEntry {
        timestamp: chrono_timestamp(),
        session_id,
        tool_name,
        tool_use_id,
        decision: "sandbox_violation",
        tool_input_summary,
        violations,
        suggested_rules,
    };

    let session_log = SessionDir::new(session_id).audit_log();
    if let Some(parent) = session_log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string(&entry) {
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&session_log)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, "Failed to open session audit log for sandbox violations");
                return;
            }
        };
        let _ = writeln!(file, "{}", json);
    }
}

/// Read sandbox violations for a specific tool_use_id from the session audit log.
///
/// Returns the violations array from the most recent `sandbox_violation` entry
/// matching the given tool_use_id.
pub fn read_sandbox_violations(session_id: &str, tool_use_id: &str) -> Vec<SandboxViolation> {
    let session_log = SessionDir::new(session_id).audit_log();
    let content = match std::fs::read_to_string(&session_log) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Search backwards for the most recent matching entry.
    for line in content.lines().rev() {
        if !line.contains("sandbox_violation") {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line)
            && entry.get("decision").and_then(|v| v.as_str()) == Some("sandbox_violation")
            && entry.get("tool_use_id").and_then(|v| v.as_str()) == Some(tool_use_id)
            && let Some(violations) = entry.get("violations")
        {
            return serde_json::from_value(violations.clone()).unwrap_or_default();
        }
    }

    Vec::new()
}

/// Deduplicate violations by parent directory and generate suggested policy rules.
fn deduplicated_suggestions(violations: &[SandboxViolation]) -> Vec<String> {
    let mut seen_dirs = std::collections::BTreeSet::new();
    let mut suggestions = Vec::new();

    for v in violations {
        let dir = parent_dir_suggestion(&v.path);
        if seen_dirs.insert(dir.clone()) {
            suggestions.push(format!(
                "path(\"{}\").allow(read=True, write=True, create=True)",
                dir
            ));
        }
    }

    suggestions
}

/// Suggest the parent directory for a path. For dotfile directories under $HOME
/// (e.g. ~/.fly/perms.123), suggest the dotfile dir (~/.fly). Otherwise suggest
/// the immediate parent.
fn parent_dir_suggestion(path: &str) -> String {
    let p = std::path::Path::new(path);

    if let Some(home) = dirs::home_dir()
        && let Ok(rel) = p.strip_prefix(&home)
    {
        // Check if it's a dotfile directory like .fly/something
        let mut components = rel.components();
        if let Some(first) = components.next() {
            let first_str = first.as_os_str().to_string_lossy();
            if first_str.starts_with('.') && components.next().is_some() {
                return home.join(first_str.as_ref()).to_string_lossy().into_owned();
            }
        }
    }

    p.parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

/// Generate the narrowest possible allow rule for a denied tool invocation.
///
/// Returns a `clash allow '...'` command string. Uses the v5 match-tree
/// suggestion format (e.g. `exe("git")`, `tool("Read")`).
fn deny_hint(tool_name: &str, tool_input: &serde_json::Value, cwd: &str) -> Result<String, String> {
    let rule = crate::session_policy::suggest_rule_description(tool_name, tool_input, cwd)
        .ok_or_else(|| format!("cannot generate hint for {tool_name}"))?;
    Ok(format!("clash allow '{}'", rule))
}

/// Concise, human-readable summary of a tool invocation for display.
fn tool_input_summary(tool_name: &str, input: &serde_json::Value, _cwd: &str) -> String {
    let noun = crate::permissions::extract_noun(tool_name, input);
    truncate_str(&noun, 60)
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
                    node_id: None,
                })
                .collect(),
            skipped_rules: vec![],
            final_resolution: "test".into(),
        }
    }

    #[test]
    fn test_session_dir_uses_session_id() {
        let dir = session_dir("abc-123");
        // Sessions now live under ~/.clash/sessions/<id>/.
        assert!(
            dir.ends_with("sessions/abc-123") || dir.ends_with("clash-abc-123"),
            "unexpected session dir: {}",
            dir.display()
        );
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
            None,
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
            None,
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
