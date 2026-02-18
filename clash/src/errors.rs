//! User-facing error display.
//!
//! Formats anyhow errors with causal chains, colored output, and actionable
//! help hints extracted from domain-specific error types.

use std::io::Write;

use crate::policy::error::{CompileError, PolicyParseError};
use crate::style;

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
    let mut stderr = std::io::stderr().lock();

    // Top-level error message.
    let _ = write!(stderr, "{}: {}", style::err_red_bold("error"), err);
    let _ = writeln!(stderr);

    // Causal chain (skip the root error itself).
    let chain: Vec<_> = err.chain().skip(1).collect();
    if chain.len() == 1 {
        let _ = writeln!(
            stderr,
            "  {}",
            style::err_dim(&format!("caused by: {}", chain[0]))
        );
    } else {
        for (i, cause) in chain.iter().enumerate() {
            let _ = writeln!(
                stderr,
                "  {}",
                style::err_dim(&format!("{}: {}", i + 1, cause))
            );
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
        let _ = writeln!(stderr, "\n  {}: {}", style::err_cyan_bold("hint"), hint);
    }

    if verbose {
        let _ = writeln!(stderr, "\nFull error chain:\n{:?}", err);
    } else if !chain.is_empty() {
        let _ = writeln!(
            stderr,
            "\n  {}",
            style::err_dim("run with --verbose for full details")
        );
    }
}
