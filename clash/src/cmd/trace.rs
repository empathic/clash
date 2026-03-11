use anyhow::{Context, Result};
use clap::Subcommand;

use crate::settings::ClashSettings;

/// Subcommands for `clash trace`.
#[derive(Subcommand, Debug)]
pub enum TraceCmd {
    /// Export the toolpath trace as a JSON document
    Export {
        /// Session ID (defaults to the active session)
        #[arg(long)]
        session: Option<String>,
    },
}

pub fn run(cmd: TraceCmd) -> Result<()> {
    match cmd {
        TraceCmd::Export { session } => run_export(session),
    }
}

fn run_export(session: Option<String>) -> Result<()> {
    let session_id = match session {
        Some(id) => id,
        None => ClashSettings::active_session_id()?,
    };

    // Sync before export to pick up any new conversation entries.
    crate::trace::sync_trace(&session_id, None).context("syncing trace before export")?;

    let doc = crate::trace::export_trace(&session_id)?;
    let json = doc.to_json().context("serializing trace")?;
    println!("{json}");
    Ok(())
}
