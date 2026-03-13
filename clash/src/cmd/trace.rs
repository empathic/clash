use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    /// Render the session trace as a visual graph and open it
    Graph {
        /// Session ID (defaults to the active session)
        #[arg(long)]
        session: Option<String>,
        /// Write SVG to this path instead of a temp file
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// Don't auto-open the SVG after rendering
        #[arg(long)]
        no_open: bool,
        /// Show filenames in step nodes
        #[arg(long)]
        show_files: bool,
        /// Show timestamps in step nodes
        #[arg(long)]
        show_timestamps: bool,
    },
}

pub fn run(cmd: TraceCmd) -> Result<()> {
    match cmd {
        TraceCmd::Export { session } => run_export(session),
        TraceCmd::Graph {
            session,
            output,
            no_open,
            show_files,
            show_timestamps,
        } => run_graph(session, output, no_open, show_files, show_timestamps),
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

fn run_graph(
    session: Option<String>,
    output: Option<PathBuf>,
    no_open: bool,
    show_files: bool,
    show_timestamps: bool,
) -> Result<()> {
    let session_id = match session {
        Some(id) => id,
        None => ClashSettings::active_session_id()?,
    };

    crate::trace::sync_trace(&session_id, None).context("syncing trace before export")?;
    let doc = crate::trace::export_trace(&session_id)?;

    let options = toolpath_dot::RenderOptions {
        show_files,
        show_timestamps,
        highlight_dead_ends: true,
    };
    let dot_text = toolpath_dot::render(&doc, &options);

    let dot_bin = find_dot()?;

    let svg_path = match output {
        Some(p) => p,
        None => std::env::temp_dir().join(format!("clash-trace-{session_id}.svg")),
    };

    let mut child = Command::new(&dot_bin)
        .args(["-Tsvg", "-o"])
        .arg(&svg_path)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run: {}", dot_bin.display()))?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(dot_text.as_bytes())
            .context("writing DOT to stdin")?;
    }

    let status = child.wait().context("waiting for dot")?;
    if !status.success() {
        anyhow::bail!("dot exited with status {status}");
    }

    println!("{}", svg_path.display());

    if !no_open {
        open_file(&svg_path);
    }

    Ok(())
}

/// Locate the `dot` binary (Graphviz), or return a helpful error.
fn find_dot() -> Result<PathBuf> {
    which::which("dot").map_err(|_| {
        anyhow::anyhow!(
            "graphviz is not installed (the `dot` command was not found)\n\n  \
             Install it with one of:\n    \
             brew install graphviz\n    \
             apt install graphviz\n    \
             dnf install graphviz\n\n  \
             See https://graphviz.org/download/"
        )
    })
}

/// Best-effort open a file with the system viewer.
fn open_file(path: &PathBuf) {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = Command::new(cmd).arg(path).spawn();
}
