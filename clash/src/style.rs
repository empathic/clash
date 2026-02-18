//! TTY-aware color and styling helpers for human-friendly CLI output.
//!
//! Built on the [`console`] crate which automatically detects whether
//! stdout/stderr is a terminal and respects the `NO_COLOR` environment
//! variable (<https://no-color.org/>).

use console::{Emoji, Style};

// ---------------------------------------------------------------------------
// Lazy style constructors
// ---------------------------------------------------------------------------

/// A `Style` targeting **stdout** (auto-detects TTY + NO_COLOR).
fn out() -> Style {
    Style::new()
}

/// A `Style` targeting **stderr** (auto-detects TTY + NO_COLOR).
fn err() -> Style {
    Style::new().for_stderr()
}

// ---------------------------------------------------------------------------
// Semantic styles (stdout)
// ---------------------------------------------------------------------------

/// Bold text (for headers/titles).
pub fn bold(text: &str) -> String {
    out().bold().apply_to(text).to_string()
}

/// Dim / muted text (for secondary information).
pub fn dim(text: &str) -> String {
    out().dim().apply_to(text).to_string()
}

/// Bold cyan – section headers.
pub fn header(text: &str) -> String {
    out().cyan().bold().apply_to(text).to_string()
}

/// Green – allow / success.
pub fn green(text: &str) -> String {
    out().green().apply_to(text).to_string()
}

/// Bold green – emphasized success.
pub fn green_bold(text: &str) -> String {
    out().green().bold().apply_to(text).to_string()
}

/// Red – deny / error.
pub fn red(text: &str) -> String {
    out().red().apply_to(text).to_string()
}

/// Bold red.
pub fn red_bold(text: &str) -> String {
    out().red().bold().apply_to(text).to_string()
}

/// Yellow – ask / warning.
pub fn yellow(text: &str) -> String {
    out().yellow().apply_to(text).to_string()
}

/// Bold yellow.
pub fn yellow_bold(text: &str) -> String {
    out().yellow().bold().apply_to(text).to_string()
}

/// Cyan (for labels, tags).
pub fn cyan(text: &str) -> String {
    out().cyan().apply_to(text).to_string()
}

/// Magenta (for accents).
pub fn magenta(text: &str) -> String {
    out().magenta().apply_to(text).to_string()
}

/// Bold white.
pub fn white_bold(text: &str) -> String {
    out().white().bold().apply_to(text).to_string()
}

// ---------------------------------------------------------------------------
// Stderr variants (for permission denials, errors)
// ---------------------------------------------------------------------------

/// Bold red on stderr.
pub fn err_red_bold(text: &str) -> String {
    err().red().bold().apply_to(text).to_string()
}

/// Dim on stderr.
pub fn err_dim(text: &str) -> String {
    err().dim().apply_to(text).to_string()
}

/// Bold cyan on stderr (hints).
pub fn err_cyan_bold(text: &str) -> String {
    err().cyan().bold().apply_to(text).to_string()
}

/// Yellow on stderr (suggestions).
pub fn err_yellow(text: &str) -> String {
    err().yellow().apply_to(text).to_string()
}

// ---------------------------------------------------------------------------
// Semantic: effect coloring
// ---------------------------------------------------------------------------

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
        "allow" => err().green().apply_to(effect).to_string(),
        "deny" => err().red().apply_to(effect).to_string(),
        "ask" => err().yellow().apply_to(effect).to_string(),
        _ => effect.to_string(),
    }
}

// ---------------------------------------------------------------------------
// ASCII art banner
// ---------------------------------------------------------------------------

static LIGHTNING: Emoji<'_, '_> = Emoji("⚡ ", "! ");

/// A small, whimsical banner for `clash status` and friends.
///
/// The shield motif reflects clash's role as a safety harness.
pub fn banner() -> String {
    let s = out();
    let box_style = s.clone().cyan();
    let bolt = s.clone().yellow().bold().apply_to(LIGHTNING);
    let title = s.clone().white().bold().apply_to("clash");
    let tagline = s.dim().apply_to("· command-line agent safety harness");

    let top = box_style.apply_to("    ┌───┐");
    let left = box_style.apply_to("    │");
    let right = box_style.apply_to("│");
    let bot = box_style.apply_to("    └───┘");

    format!("{top}\n{left}{bolt}{right}  {title} {tagline}\n{bot}")
}

static SHIELD: Emoji<'_, '_> = Emoji("⛨", "*");

/// A compact one-line motif for rule confirmations.
pub fn shield() -> String {
    cyan(&SHIELD.to_string())
}
