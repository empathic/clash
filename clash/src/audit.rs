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
/// Written atomically to `/tmp/clash-<session_id>/stats.json` on every
/// policy decision so the `clash statusline render` command can read it
/// cheaply without parsing the full audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub allowed: u64,
    pub denied: u64,
    pub asked: u64,
    pub last_tool: Option<String>,
    pub last_input_summary: Option<String>,
    pub last_effect: Option<String>,
    pub last_at: Option<String>,
    pub default_effect: String,
    /// Suggested allow command when the last decision was deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_deny_hint: Option<String>,
}

impl Default for SessionStats {
    fn default() -> Self {
        Self {
            allowed: 0,
            denied: 0,
            asked: 0,
            last_tool: None,
            last_input_summary: None,
            last_effect: None,
            last_at: None,
            default_effect: "deny".into(),
            last_deny_hint: None,
        }
    }
}

/// Return the session-specific temp directory for the given session ID.
pub fn session_dir(session_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("clash-{}", session_id))
}

/// Path to the session stats sidecar file.
fn stats_path(session_id: &str) -> PathBuf {
    session_dir(session_id).join("stats.json")
}

/// Read the current session stats, returning defaults if missing or malformed.
pub fn read_session_stats(session_id: &str) -> SessionStats {
    let path = stats_path(session_id);
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => SessionStats::default(),
    }
}

/// Write initial session stats with zero counters.
///
/// Called from `init_session()` to seed the stats file so the status line
/// can display the policy posture even before any decisions are made.
fn init_session_stats(session_id: &str, default_effect: Option<&str>) {
    let stats = SessionStats {
        default_effect: default_effect.unwrap_or("deny").into(),
        ..Default::default()
    };
    write_session_stats(session_id, &stats);
}

/// Update session stats after a policy decision.
///
/// Reads the current stats, increments the appropriate counter, updates
/// the last-decision fields, and writes back atomically.
///
/// Called from the PreToolUse hook handler (not from `log_decision`) to
/// avoid double-counting when PermissionRequest re-evaluates the same tool.
pub fn update_session_stats(
    session_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    effect: Effect,
) {
    let mut stats = read_session_stats(session_id);

    match effect {
        Effect::Allow => stats.allowed += 1,
        Effect::Deny => stats.denied += 1,
        Effect::Ask => stats.asked += 1,
    }

    stats.last_tool = Some(tool_name.to_string());
    stats.last_effect = Some(effect_str(effect).to_string());
    stats.last_at = Some(chrono_timestamp());

    stats.last_input_summary = Some(tool_input_summary(tool_name, tool_input));

    stats.last_deny_hint = if effect == Effect::Deny {
        Some(deny_hint(tool_name, tool_input))
    } else {
        None
    };

    write_session_stats(session_id, &stats);
}

/// Atomically write stats to the session directory.
///
/// Writes to a temp file then renames to prevent partial reads.
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

/// Initialize a per-session history directory.
///
/// Creates `/tmp/clash-<session_id>/` with a `metadata.json` containing
/// session info. Returns the session directory path on success.
pub fn init_session(
    session_id: &str,
    cwd: &str,
    source: Option<&str>,
    model: Option<&str>,
    default_effect: Option<&str>,
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

    // Seed the stats sidecar so the status line works before any decisions.
    init_session_stats(session_id, default_effect);

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

/// Suggest the narrowest possible allow command for a denied tool.
fn deny_hint(tool_name: &str, tool_input: &serde_json::Value) -> String {
    match tool_name {
        "Bash" => {
            let cmd = tool_input["command"].as_str().unwrap_or("");
            // Extract the binary name (first word).
            let bin = cmd.split_whitespace().next().unwrap_or("*");
            format!("clash allow '(exec \"{}\" *)'", bin)
        }
        "Read" | "Glob" | "Grep" => {
            if let Some(path) = tool_input["file_path"]
                .as_str()
                .or_else(|| tool_input["path"].as_str())
            {
                // Suggest allowing reads under the parent directory.
                let parent = std::path::Path::new(path)
                    .parent()
                    .map(|p| p.to_string_lossy())
                    .unwrap_or_else(|| path.into());
                format!("clash allow '(fs read (subpath \"{}\"))'", parent)
            } else {
                "clash allow read".into()
            }
        }
        "Write" | "Edit" | "NotebookEdit" => {
            if let Some(path) = tool_input["file_path"].as_str() {
                let parent = std::path::Path::new(path)
                    .parent()
                    .map(|p| p.to_string_lossy())
                    .unwrap_or_else(|| path.into());
                format!("clash allow '(fs write (subpath \"{}\"))'", parent)
            } else {
                "clash allow edit".into()
            }
        }
        "WebFetch" => {
            if let Some(url) = tool_input["url"].as_str() {
                // Extract domain from URL without a url crate dependency.
                let host = url
                    .strip_prefix("https://")
                    .or_else(|| url.strip_prefix("http://"))
                    .and_then(|rest| rest.split('/').next());
                if let Some(domain) = host {
                    return format!("clash allow '(net \"{}\")'", domain);
                }
            }
            "clash allow web".into()
        }
        "WebSearch" => "clash allow '(net \"*\")'".into(),
        _ => format!("clash allow '(tool \"{}\")'", tool_name),
    }
}

/// Extract a concise, human-readable summary from tool input JSON.
fn tool_input_summary(tool_name: &str, input: &serde_json::Value) -> String {
    let raw = match tool_name {
        "Bash" => input["command"].as_str().map(str::to_string),
        "Read" | "Write" => input["file_path"].as_str().map(shorten_path),
        "Edit" => input["file_path"].as_str().map(shorten_path),
        "Glob" => input["pattern"].as_str().map(str::to_string),
        "Grep" => input["pattern"].as_str().map(str::to_string),
        "WebFetch" | "WebSearch" => input["url"]
            .as_str()
            .or_else(|| input["query"].as_str())
            .map(str::to_string),
        "Task" => input["description"].as_str().map(str::to_string),
        _ => None,
    };

    let s = raw.unwrap_or_else(|| {
        // Fallback: grab the first string value from the object.
        input
            .as_object()
            .and_then(|obj| obj.values().find_map(|v| v.as_str().map(str::to_string)))
            .unwrap_or_default()
    });

    truncate_str(&s, 60)
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

        let result = init_session(&id, "/tmp", Some("startup"), Some("claude-sonnet"), None);
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
        init_session(&id, "/tmp", None, None, None).unwrap();

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
