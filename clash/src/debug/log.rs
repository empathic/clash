//! Audit log reading, filtering, and display.
//!
//! Reads JSON Lines audit entries from session or global logs and provides
//! structured filtering and formatted output.

use std::path::Path;

use anyhow::{Context, Result};

use crate::audit;
use crate::debug::AuditLogEntry;
use crate::settings::ClashSettings;
use crate::style;

/// Filter criteria for audit log entries.
#[derive(Debug, Default)]
pub struct LogFilter {
    /// Only include entries with this effect (allow/deny/ask).
    pub effect: Option<String>,
    /// Only include entries for this tool name.
    pub tool: Option<String>,
    /// Only include entries after this timestamp (seconds since epoch).
    pub since: Option<f64>,
    /// Maximum number of entries to return.
    pub limit: usize,
}

/// Read and parse audit log entries from a file.
pub fn read_log_file(path: &Path) -> Result<Vec<AuditLogEntry>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read audit log: {}", path.display()))?;
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditLogEntry>(line) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                tracing::debug!(error = %e, line = line, "skipping malformed audit log entry");
            }
        }
    }
    Ok(entries)
}

/// Read audit log entries for a specific session.
pub fn read_session_log(session_id: &str) -> Result<Vec<AuditLogEntry>> {
    let path = audit::session_dir(session_id).join("audit.jsonl");
    if !path.exists() {
        anyhow::bail!(
            "no audit log found for session {session_id} (expected {})",
            path.display()
        );
    }
    read_log_file(&path)
}

/// Read the global audit log.
pub fn read_global_log() -> Result<Vec<AuditLogEntry>> {
    let path = dirs::home_dir()
        .map(|h| h.join(".clash").join("audit.jsonl"))
        .unwrap_or_else(|| std::path::PathBuf::from("audit.jsonl"));
    if !path.exists() {
        anyhow::bail!(
            "no global audit log found at {} (enable audit logging in policy.yaml)",
            path.display()
        );
    }
    read_log_file(&path)
}

/// Resolve the session ID: use explicit value, or fall back to active session.
///
/// Returns `Ok(Some(id))` when a session is found, `Ok(None)` when no
/// explicit session was given and no active session exists (caller should
/// fall back to all sessions).
pub fn resolve_session_id(explicit: Option<&str>) -> Result<Option<String>> {
    if let Some(id) = explicit {
        return Ok(Some(id.to_string()));
    }
    match ClashSettings::active_session_id() {
        Ok(id) => Ok(Some(id)),
        Err(_) => Ok(None),
    }
}

/// Read audit log entries from all known sessions, sorted by timestamp.
pub fn read_all_session_logs() -> Result<Vec<AuditLogEntry>> {
    let tmp = std::env::temp_dir();
    let mut all_entries = Vec::new();

    if let Ok(readdir) = std::fs::read_dir(&tmp) {
        for entry in readdir.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("clash-") {
                let log_path = entry.path().join("audit.jsonl");
                if log_path.exists() {
                    match read_log_file(&log_path) {
                        Ok(entries) => all_entries.extend(entries),
                        Err(e) => {
                            tracing::debug!(
                                path = %log_path.display(),
                                error = %e,
                                "skipping unreadable session log"
                            );
                        }
                    }
                }
            }
        }
    }

    // Sort by timestamp so entries from different sessions interleave correctly.
    all_entries.sort_by(|a, b| {
        a.timestamp_secs()
            .partial_cmp(&b.timestamp_secs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(all_entries)
}

/// Filter audit log entries by the given criteria.
pub fn filter_entries(entries: Vec<AuditLogEntry>, filter: &LogFilter) -> Vec<AuditLogEntry> {
    let mut filtered: Vec<AuditLogEntry> = entries
        .into_iter()
        .filter(|e| {
            if let Some(ref effect) = filter.effect
                && !e.decision.eq_ignore_ascii_case(effect) {
                    return false;
                }
            if let Some(ref tool) = filter.tool
                && !e.tool_name.eq_ignore_ascii_case(tool) {
                    return false;
                }
            if let Some(since) = filter.since
                && let Some(ts) = e.timestamp_secs()
                    && ts < since {
                        return false;
                    }
            true
        })
        .collect();

    // Return the last N entries (most recent).
    if filter.limit > 0 && filtered.len() > filter.limit {
        filtered = filtered.split_off(filtered.len() - filter.limit);
    }
    filtered
}

/// Parse a human-friendly duration string like "5m", "1h", "30s" into seconds.
pub fn parse_duration(s: &str) -> Result<f64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration string");
    }

    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('s') {
        (stripped, 1.0)
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 60.0)
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 3600.0)
    } else if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 86400.0)
    } else {
        // Default to seconds if no unit.
        (s, 1.0)
    };

    let num: f64 = num_str
        .trim()
        .parse()
        .with_context(|| format!("invalid duration: '{s}' (expected e.g. '5m', '1h', '30s')"))?;
    Ok(num * unit)
}

/// Format a unix timestamp as a human-readable relative time or clock time.
fn format_timestamp(ts: &str) -> String {
    let secs: f64 = match ts.parse() {
        Ok(s) => s,
        Err(_) => return ts.to_string(),
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    let ago = now - secs;
    if ago < 60.0 {
        format!("{:.0}s ago", ago)
    } else if ago < 3600.0 {
        format!("{:.0}m ago", ago / 60.0)
    } else if ago < 86400.0 {
        format!("{:.1}h ago", ago / 3600.0)
    } else {
        format!("{:.1}d ago", ago / 86400.0)
    }
}

/// Map a decision string to a colored symbol.
fn effect_symbol(decision: &str) -> String {
    match decision {
        "allow" => style::green("\u{2713}"),
        "deny" => style::red("\u{2717}"),
        "ask" => style::yellow("?"),
        _ => decision.to_string(),
    }
}

/// Format audit log entries as a compact table for terminal display.
pub fn format_table(entries: &[AuditLogEntry]) -> String {
    if entries.is_empty() {
        return style::dim("No audit log entries found.").to_string();
    }

    let mut lines = Vec::new();

    // Header
    lines.push(format!(
        "  {} {:>8}  {:<6}  {:<50}  {}",
        style::dim(""),
        style::dim("when"),
        style::dim("tool"),
        style::dim("subject"),
        style::dim("resolution"),
    ));

    for entry in entries {
        let symbol = effect_symbol(&entry.decision);
        let when = format_timestamp(&entry.timestamp);
        let subject = truncate(&entry.tool_input_summary, 50);
        let resolution = truncate(&entry.resolution, 40);

        lines.push(format!(
            "  {} {:>8}  {:<6}  {:<50}  {}",
            symbol,
            style::dim(&when),
            entry.tool_name,
            subject,
            style::dim(&resolution),
        ));
    }

    let total = entries.len();
    let denials = entries.iter().filter(|e| e.decision == "deny").count();
    if denials > 0 {
        lines.push(String::new());
        lines.push(format!(
            "  {} {total} entries, {} denied. Use {} to understand a denial.",
            style::dim("\u{2139}"),
            style::red(&denials.to_string()),
            style::cyan("clash debug replay bash \"<command>\""),
        ));
    }

    lines.join("\n")
}

/// Format audit log entries as JSON.
pub fn format_json(entries: &[AuditLogEntry]) -> Result<String> {
    serde_json::to_string_pretty(entries).context("failed to serialize audit entries as JSON")
}

/// Truncate a string with "..." if it exceeds max length.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let cut = s
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max.saturating_sub(3))
            .last()
            .unwrap_or(0);
        format!("{}...", &s[..cut])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        assert!((parse_duration("30s").unwrap() - 30.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert!((parse_duration("5m").unwrap() - 300.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_duration_hours() {
        assert!((parse_duration("2h").unwrap() - 7200.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_duration_days() {
        assert!((parse_duration("1d").unwrap() - 86400.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_duration_no_unit_defaults_to_seconds() {
        assert!((parse_duration("45").unwrap() - 45.0).abs() < 0.001);
    }

    #[test]
    fn test_parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn test_filter_by_effect() {
        let entries = vec![
            AuditLogEntry {
                timestamp: "1000.0".into(),
                tool_name: "Bash".into(),
                tool_input_summary: "ls".into(),
                decision: "allow".into(),
                reason: None,
                matched_rules: 1,
                skipped_rules: 0,
                resolution: "result: allow".into(),
            },
            AuditLogEntry {
                timestamp: "1001.0".into(),
                tool_name: "Bash".into(),
                tool_input_summary: "rm -rf /".into(),
                decision: "deny".into(),
                reason: None,
                matched_rules: 1,
                skipped_rules: 0,
                resolution: "result: deny".into(),
            },
        ];

        let filter = LogFilter {
            effect: Some("deny".into()),
            ..Default::default()
        };
        let filtered = filter_entries(entries, &filter);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].decision, "deny");
    }

    #[test]
    fn test_filter_by_tool() {
        let entries = vec![
            AuditLogEntry {
                timestamp: "1000.0".into(),
                tool_name: "Bash".into(),
                tool_input_summary: "ls".into(),
                decision: "allow".into(),
                reason: None,
                matched_rules: 1,
                skipped_rules: 0,
                resolution: "result: allow".into(),
            },
            AuditLogEntry {
                timestamp: "1001.0".into(),
                tool_name: "Read".into(),
                tool_input_summary: "/tmp/file".into(),
                decision: "allow".into(),
                reason: None,
                matched_rules: 1,
                skipped_rules: 0,
                resolution: "result: allow".into(),
            },
        ];

        let filter = LogFilter {
            tool: Some("Read".into()),
            ..Default::default()
        };
        let filtered = filter_entries(entries, &filter);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tool_name, "Read");
    }

    #[test]
    fn test_filter_limit_takes_last() {
        let entries: Vec<AuditLogEntry> = (0..10)
            .map(|i| AuditLogEntry {
                timestamp: format!("{}.0", 1000 + i),
                tool_name: "Bash".into(),
                tool_input_summary: format!("cmd {i}"),
                decision: "allow".into(),
                reason: None,
                matched_rules: 1,
                skipped_rules: 0,
                resolution: "result: allow".into(),
            })
            .collect();

        let filter = LogFilter {
            limit: 3,
            ..Default::default()
        };
        let filtered = filter_entries(entries, &filter);
        assert_eq!(filtered.len(), 3);
        assert_eq!(filtered[0].tool_input_summary, "cmd 7");
        assert_eq!(filtered[2].tool_input_summary, "cmd 9");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world!", 8), "hello...");
    }
}
