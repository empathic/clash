//! Full-screen TUI for browsing and editing clash policies.

mod app;
mod editor;
mod input;
mod render;
pub mod style;
pub mod tree;

use std::io;

use anyhow::{Context, Result};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::settings::ClashSettings;

use self::app::App;

/// Entry point: launch the TUI.
pub fn run() -> Result<()> {
    let settings = ClashSettings::load_or_create().context("failed to load policy settings")?;
    let policies = settings.loaded_policies();

    let mut app = App::new(policies);

    // Setup terminal
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    // Run the app
    let result = app.run(&mut terminal);

    // Restore terminal — always attempt even if app errored
    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    result
}
