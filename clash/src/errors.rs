//! User-facing error display.
//!
//! Formats anyhow errors with causal chains, colored output, and actionable
//! help hints extracted from domain-specific error types.

use std::io::{IsTerminal, Write};

use crate::policy::error::{CompileError, PolicyParseError};

/// Display a user-facing error to stderr with optional verbose output.
///
/// Format:
///   error: top-level message
///     caused by: chain item 1
///     caused by: chain item 2
///
///   hint: actionable suggestion (if available)
///
/// When verbose is false and there's a deeper chain, appends:
///   run with --verbose for full details
///
/// When verbose is true, appends the full Debug representation.
pub fn display_error(err: &anyhow::Error, verbose: bool) {
    let color = use_color();
    let mut stderr = std::io::stderr().lock();

    // Top-level error message.
    if color {
        let _ = write!(stderr, "\x1b[1;31merror\x1b[0m: {}", err);
    } else {
        let _ = write!(stderr, "error: {}", err);
    }
    let _ = writeln!(stderr);

    // Causal chain (skip the root error itself).
    let chain: Vec<_> = err.chain().skip(1).collect();
    if chain.len() == 1 {
        if color {
            let _ = writeln!(stderr, "  \x1b[2mcaused by: {}\x1b[0m", chain[0]);
        } else {
            let _ = writeln!(stderr, "  caused by: {}", chain[0]);
        }
    } else {
        for (i, cause) in chain.iter().enumerate() {
            if color {
                let _ = writeln!(stderr, "  \x1b[2m{}: {}\x1b[0m", i + 1, cause);
            } else {
                let _ = writeln!(stderr, "  {}: {}", i + 1, cause);
            }
        }
    }

    // Extract a help hint from the first matching domain error in the chain.
    let hint = err.chain().find_map(|cause| {
        if let Some(e) = cause.downcast_ref::<PolicyParseError>() {
            return e.help();
        }
        if let Some(e) = cause.downcast_ref::<CompileError>() {
            return e.help();
        }
        None
    });

    if let Some(hint) = hint {
        if color {
            let _ = writeln!(stderr, "\n  \x1b[1;36mhint\x1b[0m: {}", hint);
        } else {
            let _ = writeln!(stderr, "\n  hint: {}", hint);
        }
    }

    if verbose {
        let _ = writeln!(stderr, "\nFull error chain:\n{:?}", err);
    } else if !chain.is_empty() {
        let _ = writeln!(stderr, "\n  run with --verbose for full details");
    }
}

fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err() && std::io::stderr().is_terminal()
}
