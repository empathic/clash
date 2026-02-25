//! `clash debug` — composable debugging tools for policy enforcement.
//!
//! Provides subcommands to view audit logs, replay commands against
//! the current policy, and inspect sandbox enforcement details.

use anyhow::Result;
use clap::Subcommand;
use tracing::{Level, instrument};

/// Subcommands for `clash debug`.
#[derive(Subcommand, Debug)]
pub enum DebugCmd {
    /// View audit log entries
    Log {
        /// Only show entries from sessions matching this substring
        #[arg(long)]
        session: Option<String>,

        /// Exclude entries from sessions matching this substring
        #[arg(long)]
        exclude_session: Option<String>,

        /// Show entries from the last duration (e.g., "5m", "1h", "30s")
        #[arg(long)]
        since: Option<String>,

        /// Filter by effect: allow, deny, or ask
        #[arg(long)]
        effect: Option<String>,

        /// Filter by tool name (e.g., Bash, Read)
        #[arg(long)]
        tool: Option<String>,

        /// Maximum number of entries to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Re-evaluate a command against the current policy
    Replay {
        /// Tool type: bash, read, write, edit (or full name like Bash, Read, etc.)
        tool: Option<String>,

        /// The command, file path, or noun to check (remaining args joined)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Replay the last logged command
        #[arg(long)]
        last: bool,

        /// Only consider entries from sessions matching this substring (for --last)
        #[arg(long)]
        session: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show sandbox enforcement details for a command
    Sandbox {
        /// Tool type: bash, read, write, edit (or full name)
        tool: String,

        /// The command, file path, or noun to inspect (remaining args joined)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn run(cmd: DebugCmd) -> Result<()> {
    match cmd {
        DebugCmd::Log {
            session,
            exclude_session,
            since,
            effect,
            tool,
            limit,
            json,
        } => run_log(session, exclude_session, since, effect, tool, limit, json),
        DebugCmd::Replay {
            tool,
            args,
            last,
            session,
            json,
        } => run_replay(tool, args, last, session, json),
        DebugCmd::Sandbox { tool, args, json } => run_sandbox(tool, args, json),
    }
}

#[instrument(level = Level::TRACE)]
fn run_log(
    session: Option<String>,
    exclude_session: Option<String>,
    since: Option<String>,
    effect: Option<String>,
    tool: Option<String>,
    limit: usize,
    json: bool,
) -> Result<()> {
    use crate::debug::log;

    // Always read all sessions — filtering happens via LogFilter.
    let entries = log::read_all_session_logs()?;

    let since_ts = if let Some(ref dur) = since {
        let duration_secs = log::parse_duration(dur)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Some(now - duration_secs)
    } else {
        None
    };

    let filter = log::LogFilter {
        effect,
        tool,
        session,
        exclude_session,
        since: since_ts,
        limit,
    };

    let filtered = log::filter_entries(entries, &filter);

    if json {
        println!("{}", log::format_json(&filtered)?);
    } else {
        println!("{}", log::format_table(&filtered));
    }

    Ok(())
}

#[instrument(level = Level::TRACE)]
fn run_replay(
    tool: Option<String>,
    args: Vec<String>,
    last: bool,
    session: Option<String>,
    json: bool,
) -> Result<()> {
    use crate::debug::replay;

    let result = if last {
        replay::replay_last(session.as_deref())?
    } else {
        let tool = tool.ok_or_else(|| {
            anyhow::anyhow!(
                "specify a tool to replay, e.g.: clash debug replay bash \"git push\"\n\
                 or pass an id from `clash debug log`: clash debug replay <id>\n\
                 or use --last to replay the most recent logged command"
            )
        })?;

        // If the argument looks like a hex hash and there are no extra args,
        // look it up in the audit log.
        if args.is_empty() && tool.len() <= 7 && tool.chars().all(|c| c.is_ascii_hexdigit()) {
            replay::replay_hash(&tool)?
        } else {
            let input = if args.is_empty() {
                None
            } else {
                Some(args.join(" "))
            };
            let cwd = std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            replay::replay_from_args(&tool, input.as_deref(), &cwd)?
        }
    };

    if json {
        println!("{}", result.format_json()?);
    } else {
        println!("{}", result.format_human());
    }

    Ok(())
}

#[instrument(level = Level::TRACE)]
fn run_sandbox(tool: String, args: Vec<String>, json: bool) -> Result<()> {
    use crate::debug::sandbox;

    let input = if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    };

    let report = sandbox::inspect(&tool, input.as_deref())?;

    if json {
        println!("{}", report.format_json()?);
    } else {
        println!("{}", report.format_human());
    }

    Ok(())
}
