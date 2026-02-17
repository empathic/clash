//! TTY-aware color and styling helpers for human-friendly CLI output.
//!
//! All helpers check whether stdout/stderr is a terminal and respect the
//! `NO_COLOR` environment variable (<https://no-color.org/>). When color is
//! disabled, every function returns the input string unchanged.

use std::io::IsTerminal;

// ---------------------------------------------------------------------------
// TTY + NO_COLOR detection
// ---------------------------------------------------------------------------

/// Returns `true` when **stdout** is a TTY and `NO_COLOR` is unset.
pub fn use_color_stdout() -> bool {
    std::env::var("NO_COLOR").is_err() && std::io::stdout().is_terminal()
}

/// Returns `true` when **stderr** is a TTY and `NO_COLOR` is unset.
pub fn use_color_stderr() -> bool {
    std::env::var("NO_COLOR").is_err() && std::io::stderr().is_terminal()
}

// ---------------------------------------------------------------------------
// ANSI escape helpers – each returns a pre-formatted `String`.
// ---------------------------------------------------------------------------

/// Wrap `text` in the given ANSI SGR code sequence, resetting afterwards.
fn styled(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

// -- Semantic styles (stdout) -----------------------------------------------

/// Bold text (for headers/titles).
pub fn bold(text: &str) -> String {
    styled(text, "1", use_color_stdout())
}

/// Dim / muted text (for secondary information).
pub fn dim(text: &str) -> String {
    styled(text, "2", use_color_stdout())
}

/// Bold cyan – section headers.
pub fn header(text: &str) -> String {
    styled(text, "1;36", use_color_stdout())
}

/// Green – allow / success.
pub fn green(text: &str) -> String {
    styled(text, "32", use_color_stdout())
}

/// Bold green – emphasized success.
pub fn green_bold(text: &str) -> String {
    styled(text, "1;32", use_color_stdout())
}

/// Red – deny / error.
pub fn red(text: &str) -> String {
    styled(text, "31", use_color_stdout())
}

/// Bold red.
pub fn red_bold(text: &str) -> String {
    styled(text, "1;31", use_color_stdout())
}

/// Yellow – ask / warning.
pub fn yellow(text: &str) -> String {
    styled(text, "33", use_color_stdout())
}

/// Bold yellow.
pub fn yellow_bold(text: &str) -> String {
    styled(text, "1;33", use_color_stdout())
}

/// Cyan (for labels, tags).
pub fn cyan(text: &str) -> String {
    styled(text, "36", use_color_stdout())
}

/// Magenta (for accents).
pub fn magenta(text: &str) -> String {
    styled(text, "35", use_color_stdout())
}

/// Bold white.
pub fn white_bold(text: &str) -> String {
    styled(text, "1;37", use_color_stdout())
}

// -- Stderr variants (for permission denials, errors) -----------------------

/// Bold red on stderr.
pub fn err_red_bold(text: &str) -> String {
    styled(text, "1;31", use_color_stderr())
}

/// Dim on stderr.
pub fn err_dim(text: &str) -> String {
    styled(text, "2", use_color_stderr())
}

/// Bold cyan on stderr (hints).
pub fn err_cyan_bold(text: &str) -> String {
    styled(text, "1;36", use_color_stderr())
}

/// Yellow on stderr (suggestions).
pub fn err_yellow(text: &str) -> String {
    styled(text, "33", use_color_stderr())
}

// -- Semantic: effect coloring ----------------------------------------------

/// Colorize a policy effect string (allow/deny/ask).
pub fn effect(effect: &str) -> String {
    match effect.to_lowercase().as_str() {
        "allow" => green(effect),
        "deny" => red(effect),
        "ask" => yellow(effect),
        _ => effect.to_string(),
    }
}

/// Colorize a policy effect for stderr.
pub fn effect_stderr(effect: &str) -> String {
    match effect.to_lowercase().as_str() {
        "allow" => styled(effect, "32", use_color_stderr()),
        "deny" => styled(effect, "31", use_color_stderr()),
        "ask" => styled(effect, "33", use_color_stderr()),
        _ => effect.to_string(),
    }
}

// ---------------------------------------------------------------------------
// ASCII art banner
// ---------------------------------------------------------------------------

/// A small, whimsical banner for `clash status` and friends.
///
/// The shield motif reflects clash's role as a safety harness.
pub fn banner() -> String {
    if use_color_stdout() {
        "\
\x1b[36m    ┌───┐\x1b[0m
\x1b[36m    │\x1b[1;33m ⚡ \x1b[0;36m│\x1b[0m  \x1b[1;37mclash\x1b[0m \x1b[2m· command-line agent safety harness\x1b[0m
\x1b[36m    └───┘\x1b[0m"
            .to_string()
    } else {
        "\
    ┌───┐
    │ ! │  clash · command-line agent safety harness
    └───┘"
            .to_string()
    }
}

/// A compact one-line motif for rule confirmations.
pub fn shield() -> String {
    if use_color_stdout() {
        "\x1b[36m⛨\x1b[0m".to_string()
    } else {
        "*".to_string()
    }
}
