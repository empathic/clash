//! Interactive prompt helpers wrapping [`dialoguer`].
//!
//! Centralises the confirm/select patterns used by `clash init`, `clash uninstall`,
//! and `clash update` so each callsite gets consistent error messages and
//! non-interactive fallback behaviour.

use anyhow::{Context, Result};

use crate::style;

/// Yes/no confirmation prompt.
///
/// If `yes_flag` is `true` the prompt is skipped and `true` is returned,
/// enabling non-interactive (`--yes`) mode. On interaction failure (e.g. no
/// TTY) returns `false` so the caller can treat it as a cancellation.
pub fn confirm(prompt: &str, yes_flag: bool) -> Result<bool> {
    if yes_flag {
        return Ok(true);
    }
    dialoguer::Confirm::new()
        .with_prompt(prompt)
        .default(true)
        .interact()
        .context("failed to read confirmation (hint: pass --yes for non-interactive mode)")
}

/// Single-choice selection menu.
///
/// `items` is a slice of `(name, description)` pairs. Each item is rendered
/// as `bold(name)  — dim(description)`. Returns the index of the selected item.
pub fn select(prompt: &str, items: &[(&str, &str)]) -> Result<usize> {
    let formatted: Vec<String> = items
        .iter()
        .map(|(name, desc)| {
            format!(
                "{}  {}",
                style::bold(name),
                style::dim(&format!("— {}", desc))
            )
        })
        .collect();

    dialoguer::Select::new()
        .with_prompt(prompt)
        .items(&formatted)
        .default(0)
        .interact()
        .context(
            "failed to read selection (hint: pass the value as an argument for non-interactive mode)",
        )
}
