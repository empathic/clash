//! `clash statusline` — ambient policy enforcement visibility.
//!
//! Renders a compact scoreboard for the Claude Code status line showing
//! policy decision counts and the last action taken.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Deserialize;

use crate::audit::{SessionStats, StatsReadError, read_session_stats};
use crate::policy::Effect;
use crate::style;

/// Subcommands for `clash statusline`.
#[derive(Subcommand, Debug)]
pub enum StatuslineCmd {
    /// Render status line (reads JSON from stdin, prints formatted output)
    Render {
        /// Output format: "compact" (default) or "full"
        #[arg(long, default_value = "compact")]
        format: String,
    },
    /// Install the status line into Claude Code settings
    Install,
    /// Remove the status line from Claude Code settings
    Uninstall,
}

/// JSON payload received on stdin from Claude Code.
#[derive(Deserialize)]
struct StdinPayload {
    session_id: String,
}

pub fn run(cmd: StatuslineCmd) -> Result<()> {
    match cmd {
        StatuslineCmd::Render { format } => render(&format),
        StatuslineCmd::Install => install(),
        StatuslineCmd::Uninstall => uninstall(),
    }
}

/// Render the status line to stdout.
///
/// Expects a JSON payload with `session_id` on stdin. Prints an
/// ANSI-colored scoreboard, or a diagnostic to stderr on stats errors.
fn render(format: &str) -> Result<()> {
    // Claude Code supports ANSI colors in status lines, but stdout is piped
    // so the console crate would suppress them. Force colors on.
    console::set_colors_enabled(true);

    let payload: StdinPayload = serde_json::from_reader(std::io::stdin().lock())
        .context("Failed to read JSON from stdin")?;

    let stats = match read_session_stats(&payload.session_id) {
        Ok(s) => s,
        Err(StatsReadError::NotFound) => SessionStats::default(),
        Err(StatsReadError::Io(e)) => {
            eprint!("{}clash: stats unreadable: {e}", style::cyan("⚡"));
            return Ok(());
        }
        Err(StatsReadError::Malformed(e)) => {
            eprint!("{}clash: stats corrupted: {e}", style::cyan("⚡"));
            return Ok(());
        }
    };
    let output = format_stats(&stats, format);
    print!("{}", output);
    Ok(())
}

/// Format session stats into a status line string.
fn format_stats(stats: &SessionStats, _format: &str) -> String {
    let prefix = format!("{}clash", style::cyan("⚡"));
    let total = stats.allowed + stats.denied + stats.asked;

    if total == 0 {
        return format!("{} ready", prefix);
    }

    let counts = format!(
        "{}{} {}{} {}{}",
        effect_symbol(Effect::Allow),
        stats.allowed,
        effect_symbol(Effect::Deny),
        stats.denied,
        effect_symbol(Effect::Ask),
        stats.asked,
    );

    let last = match (&stats.last_effect, &stats.last_tool) {
        (Some(eff), Some(tool)) => {
            let symbol = effect_symbol(*eff);
            let summary = stats
                .last_input_summary
                .as_deref()
                .filter(|s| !s.is_empty() && *s != "{}" && *s != "null")
                .map(|s| format!("({})", s))
                .unwrap_or_default();
            format!(" · {} {}{}", symbol, tool, summary)
        }
        _ => String::new(),
    };

    let last_was_deny = stats.last_effect == Some(Effect::Deny);

    let hint = match &stats.last_deny_hint {
        Some(cmd) if last_was_deny => {
            format!("\n  {} {}", style::dim("allow with:"), style::dim(cmd))
        }
        _ => String::new(),
    };

    format!("{} {}{}{}", prefix, counts, last, hint)
}

/// Map an effect to its colored symbol.
fn effect_symbol(effect: Effect) -> String {
    match effect {
        Effect::Allow => style::green("✓"),
        Effect::Deny => style::red("✗"),
        Effect::Ask => style::yellow("?"),
    }
}

/// Install the clash status line into Claude Code user settings.
fn install() -> Result<()> {
    let cs = claude_settings::ClaudeSettings::new();

    // Check if statusLine is already set.
    let current = cs.read_or_default(claude_settings::SettingsLevel::User)?;
    if current.extra.contains_key("statusLine") {
        let existing = &current.extra["statusLine"];
        let is_clash = existing
            .get("command")
            .and_then(|v| v.as_str())
            .is_some_and(|c| c.contains("clash statusline"));

        if is_clash {
            println!(
                "{} Status line is already installed.",
                style::green_bold("✓")
            );
            return Ok(());
        }

        println!(
            "{} A statusLine is already configured in your Claude Code settings.",
            style::yellow_bold("⚠")
        );
        println!("  Current: {}", existing);
        println!("  To use clash, remove the existing statusLine first, or manually set:");
        println!(
            "  {}",
            style::dim(
                r#"  "statusLine": {"type": "command", "command": "clash statusline render"}"#
            )
        );
        return Ok(());
    }

    cs.update(claude_settings::SettingsLevel::User, |s| {
        s.extra.insert(
            "statusLine".into(),
            serde_json::json!({
                "type": "command",
                "command": "clash statusline render"
            }),
        );
    })?;

    println!(
        "{} Status line installed. It will appear in your next Claude Code session.",
        style::green_bold("✓")
    );
    Ok(())
}

/// Remove the clash status line from Claude Code user settings.
fn uninstall() -> Result<()> {
    let cs = claude_settings::ClaudeSettings::new();
    let current = cs.read_or_default(claude_settings::SettingsLevel::User)?;

    match current.extra.get("statusLine") {
        None => {
            println!("{} No statusLine is configured.", style::dim("ℹ"));
        }
        Some(val) => {
            let is_clash = val
                .get("command")
                .and_then(|v| v.as_str())
                .is_some_and(|c| c.contains("clash statusline"));

            if !is_clash {
                println!(
                    "{} The current statusLine was not installed by clash. Remove it manually.",
                    style::yellow_bold("⚠")
                );
                return Ok(());
            }

            cs.update(claude_settings::SettingsLevel::User, |s| {
                s.extra.remove("statusLine");
            })?;

            println!(
                "{} Status line removed from Claude Code settings.",
                style::green_bold("✓")
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_with(allowed: u64, denied: u64, asked: u64) -> SessionStats {
        SessionStats {
            allowed,
            denied,
            asked,

            ..Default::default()
        }
    }

    #[test]
    fn test_zero_decisions_shows_ready() {
        let stats = stats_with(0, 0, 0);
        let output = format_stats(&stats, "compact");
        assert!(output.contains("ready"), "got: {output}");
    }

    #[test]
    fn test_nonzero_decisions_shows_counts() {
        let stats = stats_with(5, 2, 1);
        let output = format_stats(&stats, "compact");
        // The output has ANSI color codes, so check for the numbers.
        assert!(
            output.contains('5'),
            "should contain allowed count, got: {output}"
        );
        assert!(
            output.contains('2'),
            "should contain denied count, got: {output}"
        );
        assert!(
            output.contains('1'),
            "should contain asked count, got: {output}"
        );
    }

    #[test]
    fn test_includes_last_action() {
        let stats = SessionStats {
            allowed: 3,
            denied: 0,
            asked: 0,
            last_tool: Some("Bash".into()),
            last_input_summary: Some("git status".into()),
            last_effect: Some(Effect::Allow),
            last_at: Some("1706123456.789".into()),

            last_deny_hint: None,
        };
        let output = format_stats(&stats, "compact");
        assert!(
            output.contains("Bash"),
            "should contain tool name, got: {output}"
        );
        assert!(
            output.contains("git status"),
            "should contain summary, got: {output}"
        );
    }

    #[test]
    fn test_prefix_contains_clash() {
        let stats = stats_with(1, 0, 0);
        let output = format_stats(&stats, "compact");
        assert!(
            output.contains("clash"),
            "should contain 'clash' prefix, got: {output}"
        );
    }
}
