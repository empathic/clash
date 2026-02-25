//! Ratatui style constants for the TUI.
//!
//! Uses terminal-relative styling (DIM, REVERSED, BOLD) rather than hardcoded
//! ANSI colors where possible, so the TUI looks correct on any color scheme
//! including solarized dark/light and other remapped palettes.

use ratatui::style::{Color, Modifier, Style};

use crate::policy::Effect;

/// Style for allow effect.
pub const ALLOW: Style = Style::new().fg(Color::Green);

/// Style for deny effect.
pub const DENY: Style = Style::new().fg(Color::Red);

/// Style for ask effect.
pub const ASK: Style = Style::new().fg(Color::Yellow);

/// Style for the selected/highlighted row.
pub const SELECTED: Style = Style::new().add_modifier(Modifier::REVERSED);

/// Style for domain headers.
pub const DOMAIN: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);

/// Style for binary/command names.
pub const BINARY: Style = Style::new().add_modifier(Modifier::BOLD);

/// Style for pattern text (args, paths, etc.) — use terminal default fg.
pub const PATTERN: Style = Style::new();

/// Dim style for secondary info — uses terminal's own dimming.
pub const DIM: Style = Style::new().add_modifier(Modifier::DIM);

/// Style for level/policy tags.
pub const TAG: Style = Style::new().fg(Color::Cyan);

/// Style for the header bar.
pub const HEADER: Style = Style::new()
    .add_modifier(Modifier::BOLD)
    .add_modifier(Modifier::REVERSED);

/// Style for the status/key hints bar.
pub const STATUS_BAR: Style = Style::new().add_modifier(Modifier::DIM);

/// Style for tree connector lines.
pub const CONNECTOR: Style = Style::new().add_modifier(Modifier::DIM);

/// Style for the border.
pub const BORDER: Style = Style::new().add_modifier(Modifier::DIM);

/// Return the style for an effect.
pub fn effect_style(effect: Effect) -> Style {
    match effect {
        Effect::Allow => ALLOW,
        Effect::Deny => DENY,
        Effect::Ask => ASK,
    }
}
