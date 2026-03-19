use anyhow::{Context, Result};
use clap::Subcommand;

use crate::audit::{self, SessionStats};
use crate::settings::ClashSettings;
use crate::style;

/// Subcommands for `clash session`.
#[derive(Subcommand, Debug)]
pub enum SessionCmd {
    /// List sessions (20 most recent by default)
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Maximum sessions to show (default: 20)
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// Show all sessions (ignores --limit)
        #[arg(long)]
        all: bool,
    },
    /// Print the session directory path (for shell composition)
    Dir {
        /// Session ID (defaults to active session)
        session: Option<String>,
    },
    /// Show detailed info for a session
    Show {
        /// Session ID (defaults to active session)
        session: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn run(cmd: SessionCmd) -> Result<()> {
    match cmd {
        SessionCmd::List { json, limit, all } => run_list(json, limit, all),
        SessionCmd::Dir { session } => run_dir(session),
        SessionCmd::Show { session, json } => run_show(session, json),
    }
}

// ---------------------------------------------------------------------------
// Session discovery
// ---------------------------------------------------------------------------

struct SessionInfo {
    session_id: String,
    dir: std::path::PathBuf,
    cwd: Option<String>,
    source: Option<String>,
    model: Option<String>,
    started_at: Option<f64>,
    started_at_raw: Option<String>,
    last_active: Option<std::time::SystemTime>,
    stats: Option<SessionStats>,
}

/// Scan $TMPDIR for `clash-*` directories with valid metadata.json.
fn discover_sessions() -> Vec<SessionInfo> {
    let tmp = std::env::temp_dir();
    let mut sessions = Vec::new();

    let readdir = match std::fs::read_dir(&tmp) {
        Ok(rd) => rd,
        Err(_) => return sessions,
    };

    for entry in readdir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let session_id = match name.strip_prefix("clash-") {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => continue,
        };

        let dir = entry.path();
        let meta_path = dir.join("metadata.json");
        let meta_str = match std::fs::read_to_string(&meta_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let meta: serde_json::Value = match serde_json::from_str(&meta_str) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let cwd = meta.get("cwd").and_then(|v| v.as_str()).map(String::from);
        let source = meta
            .get("source")
            .and_then(|v| v.as_str())
            .map(String::from);
        let model = meta.get("model").and_then(|v| v.as_str()).map(String::from);
        let started_at_raw = meta
            .get("started_at")
            .and_then(|v| v.as_str())
            .map(String::from);
        let started_at = started_at_raw
            .as_deref()
            .and_then(|s| s.parse::<f64>().ok());

        let stats = audit::read_session_stats(&session_id).ok();

        let last_active = dir
            .join("trace.jsonl")
            .metadata()
            .and_then(|m| m.modified())
            .ok();

        sessions.push(SessionInfo {
            session_id,
            dir,
            cwd,
            source,
            model,
            started_at,
            started_at_raw,
            last_active,
            stats,
        });
    }

    // Sort by most recently active (trace.jsonl mtime), fall back to started_at.
    sessions.sort_by(|a, b| {
        b.last_active.cmp(&a.last_active).then_with(|| {
            b.started_at
                .partial_cmp(&a.started_at)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    sessions
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_session(session: Option<String>) -> Result<String> {
    match session {
        Some(id) => Ok(id),
        None => ClashSettings::active_session_id(),
    }
}

fn tilde_contract(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home_str.as_ref()) {
            if rest.is_empty() {
                return "~".to_string();
            }
            if rest.starts_with('/') {
                return format!("~{rest}");
            }
        }
    }
    path.to_string()
}

fn format_relative_time(ts_str: &str) -> String {
    let secs: f64 = match ts_str.parse() {
        Ok(s) => s,
        Err(_) => return ts_str.to_string(),
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

/// Shorten a path vim-style: `/Users/ben/empathic/oss/clash` → `~/e/o/clash`.
/// Progressively shortens components from the left until it fits `max` chars,
/// always keeping the last component intact.
fn shorten_path(path: &str, max: usize) -> String {
    if path.len() <= max {
        return path.to_string();
    }

    let (prefix, rest) = if let Some(stripped) = path.strip_prefix("~/") {
        ("~/", stripped)
    } else if let Some(stripped) = path.strip_prefix('/') {
        ("/", stripped)
    } else {
        ("", path)
    };

    let parts: Vec<&str> = rest.split('/').collect();
    if parts.is_empty() {
        return path.to_string();
    }

    // Shorten components left-to-right (except the last) until it fits.
    for i in 0..parts.len().saturating_sub(1) {
        let mut candidate = String::from(prefix);
        for (j, part) in parts.iter().enumerate() {
            if j > 0 {
                candidate.push('/');
            }
            if j <= i {
                // Take first char of this component.
                candidate.extend(part.chars().take(1));
            } else {
                candidate.push_str(part);
            }
        }
        if candidate.len() <= max {
            return candidate;
        }
    }

    // Even fully shortened doesn't fit — return it anyway.
    let mut result = String::from(prefix);
    for (j, part) in parts.iter().enumerate() {
        if j > 0 {
            result.push('/');
        }
        if j < parts.len() - 1 {
            result.extend(part.chars().take(1));
        } else {
            result.push_str(part);
        }
    }
    result
}

fn pad(s: &str, w: usize) -> String {
    if s.len() >= w {
        s[..w].to_string()
    } else {
        format!("{s:<w$}")
    }
}

fn pad_right(s: &str, w: usize) -> String {
    if s.len() >= w {
        s[..w].to_string()
    } else {
        format!("{s:>w$}")
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn run_list(json: bool, limit: usize, all: bool) -> Result<()> {
    let active_id = ClashSettings::active_session_id().ok();
    let mut sessions = discover_sessions();

    if !all {
        sessions.truncate(limit);
    }

    if json {
        print_list_json(&sessions, &active_id)?;
    } else {
        print_list_human(&sessions, &active_id);
    }

    Ok(())
}

fn print_list_json(sessions: &[SessionInfo], active_id: &Option<String>) -> Result<()> {
    let arr: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            let is_active = active_id.as_deref() == Some(&s.session_id);
            let stats = s.stats.as_ref().map(|st| {
                serde_json::json!({
                    "allowed": st.allowed,
                    "denied": st.denied,
                    "asked": st.asked,
                })
            });
            serde_json::json!({
                "session_id": s.session_id,
                "dir": s.dir.to_string_lossy(),
                "active": is_active,
                "cwd": s.cwd,
                "source": s.source,
                "model": s.model,
                "started_at": s.started_at_raw,
                "stats": stats,
            })
        })
        .collect();

    let output = serde_json::to_string_pretty(&arr).context("serializing session list")?;
    println!("{output}");
    Ok(())
}

fn print_list_human(sessions: &[SessionInfo], active_id: &Option<String>) {
    if sessions.is_empty() {
        println!("  {}", style::dim("No sessions found."));
        return;
    }

    // Header.
    println!(
        "    {} {} {} {}",
        style::dim(&pad("SESSION", 36)),
        style::dim(&pad_right("LAST ACTIVE", 11)),
        style::dim(&pad("CWD", 24)),
        style::dim("HISTORY"),
    );

    for s in sessions {
        let is_active = active_id.as_deref() == Some(&s.session_id);
        let marker = if is_active { "*" } else { " " };

        let active = s
            .last_active
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| format_relative_time(&format!("{:.3}", d.as_secs_f64())))
            .or_else(|| s.started_at_raw.as_deref().map(format_relative_time))
            .unwrap_or_else(|| "—".to_string());

        let cwd = s
            .cwd
            .as_deref()
            .map(|p| shorten_path(&tilde_contract(p), 24))
            .unwrap_or_else(|| "—".to_string());

        let history = match &s.stats {
            Some(st) => format!(
                "{}{} {}{} {}{}",
                style::green("\u{2713}"),
                st.allowed,
                style::red("\u{2717}"),
                st.denied,
                style::yellow("?"),
                st.asked,
            ),
            None => style::dim("—").to_string(),
        };

        println!(
            "  {} {} {} {} {}",
            if is_active {
                style::green(marker)
            } else {
                marker.to_string()
            },
            pad(&s.session_id, 36),
            style::dim(&pad_right(&active, 11)),
            pad(&cwd, 24),
            history,
        );
    }
}

// ---------------------------------------------------------------------------
// dir
// ---------------------------------------------------------------------------

fn run_dir(session: Option<String>) -> Result<()> {
    let session_id = resolve_session(session)?;
    let dir = crate::session_dir::SessionDir::new(&session_id).root().to_path_buf();
    if !dir.exists() {
        anyhow::bail!("session directory does not exist: {}", dir.display());
    }
    println!("{}", dir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

fn run_show(session: Option<String>, json: bool) -> Result<()> {
    let session_id = resolve_session(session)?;
    let dir = crate::session_dir::SessionDir::new(&session_id).root().to_path_buf();

    let meta_path = dir.join("metadata.json");
    let meta_str = std::fs::read_to_string(&meta_path)
        .with_context(|| format!("failed to read metadata for session {session_id}"))?;
    let meta: serde_json::Value =
        serde_json::from_str(&meta_str).context("failed to parse session metadata")?;

    let stats = audit::read_session_stats(&session_id).ok();

    // Sync trace so we pick up recent conversation entries.
    let _ = crate::trace::sync_trace(&session_id, None);
    let last_message = crate::trace::last_user_message(&session_id);

    if json {
        let mut output = meta.clone();
        output["dir"] = serde_json::Value::String(dir.to_string_lossy().into_owned());
        if let Some(st) = &stats {
            output["stats"] = serde_json::json!({
                "allowed": st.allowed,
                "denied": st.denied,
                "asked": st.asked,
                "last_tool": st.last_tool,
                "last_effect": st.last_effect,
            });
        }
        if let Some(ref msg) = last_message {
            output["last_message"] = serde_json::Value::String(msg.clone());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serializing session info")?
        );
        return Ok(());
    }

    // Human-readable output.
    let cwd = meta
        .get("cwd")
        .and_then(|v| v.as_str())
        .map(tilde_contract)
        .unwrap_or_else(|| "—".to_string());
    let source = meta.get("source").and_then(|v| v.as_str()).unwrap_or("—");
    let model = meta.get("model").and_then(|v| v.as_str()).unwrap_or("—");
    let started = meta
        .get("started_at")
        .and_then(|v| v.as_str())
        .map(format_relative_time)
        .unwrap_or_else(|| "—".to_string());

    println!();
    println!("  {} {}", style::bold("Session"), session_id);
    println!();
    println!("  {}   {}", style::dim("Directory  "), dir.display());
    println!("  {}   {}", style::dim("Working dir"), cwd);
    println!("  {}   {}", style::dim("Source     "), source);
    println!("  {}   {}", style::dim("Model      "), model);
    println!("  {}   {}", style::dim("Started    "), started);

    if let Some(st) = &stats {
        println!();
        println!("  {}", style::bold("Stats"));
        println!("    {}   {}", style::dim("Allowed"), st.allowed);
        println!(
            "    {}    {}",
            style::dim("Denied"),
            if st.denied > 0 {
                style::red(&st.denied.to_string())
            } else {
                st.denied.to_string()
            }
        );
        println!(
            "    {}     {}",
            style::dim("Asked"),
            if st.asked > 0 {
                style::yellow(&st.asked.to_string())
            } else {
                st.asked.to_string()
            }
        );
        if let (Some(tool), Some(effect)) = (&st.last_tool, &st.last_effect) {
            println!(
                "    {} {} — {}",
                style::dim("Last tool"),
                tool,
                style::effect(&format!("{effect:?}").to_lowercase())
            );
        }
    }

    if let Some(msg) = &last_message {
        println!();
        println!("  {}", style::bold("Last message"));
        println!("    {}", style::dim(msg));
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tilde_contract_home_path() {
        if let Some(home) = dirs::home_dir() {
            let home_str = home.to_string_lossy();
            let input = format!("{home_str}/projects/foo");
            assert_eq!(tilde_contract(&input), "~/projects/foo");
        }
    }

    #[test]
    fn test_tilde_contract_non_home_path() {
        assert_eq!(tilde_contract("/tmp/something"), "/tmp/something");
    }

    #[test]
    fn test_tilde_contract_home_only() {
        if let Some(home) = dirs::home_dir() {
            let home_str = home.to_string_lossy().to_string();
            assert_eq!(tilde_contract(&home_str), "~");
        }
    }

    #[test]
    fn test_shorten_path_no_op() {
        assert_eq!(shorten_path("~/foo/bar", 24), "~/foo/bar");
    }

    #[test]
    fn test_shorten_path_progressive() {
        assert_eq!(shorten_path("~/aaa/bbb/ccc", 16), "~/aaa/bbb/ccc");
        assert_eq!(shorten_path("~/aaa/bbb/ccc", 12), "~/a/bbb/ccc");
        assert_eq!(shorten_path("~/aaa/bbb/ccc", 10), "~/a/b/ccc");
    }

    #[test]
    fn test_shorten_path_absolute() {
        assert_eq!(shorten_path("/aaa/bbb/ccc/ddd", 13), "/a/b/ccc/ddd");
    }

    #[test]
    fn test_format_relative_time_seconds() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let ts = format!("{:.3}", now - 30.0);
        let result = format_relative_time(&ts);
        assert!(result.contains("s ago"), "expected seconds, got: {result}");
    }

    #[test]
    fn test_format_relative_time_minutes() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let ts = format!("{:.3}", now - 300.0);
        let result = format_relative_time(&ts);
        assert!(result.contains("m ago"), "expected minutes, got: {result}");
    }

    #[test]
    fn test_format_relative_time_hours() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let ts = format!("{:.3}", now - 7200.0);
        let result = format_relative_time(&ts);
        assert!(result.contains("h ago"), "expected hours, got: {result}");
    }

    #[test]
    fn test_format_relative_time_days() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let ts = format!("{:.3}", now - 172800.0);
        let result = format_relative_time(&ts);
        assert!(result.contains("d ago"), "expected days, got: {result}");
    }

    #[test]
    fn test_format_relative_time_invalid() {
        assert_eq!(format_relative_time("not-a-number"), "not-a-number");
    }
}
