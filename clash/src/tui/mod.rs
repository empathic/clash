//! Interactive policy editor TUI.
//!
//! Launches a ratatui-based terminal UI for browsing and editing policy.json.
//! Uses the Elm Architecture (TEA) pattern: `Model -> update(Msg) -> view(Model)`.

pub mod app;
pub mod builder_view;
pub mod includes_view;
pub mod inline_form;
pub mod sandbox_view;
pub mod settings_view;
pub mod tea;
pub mod tool_registry;
pub mod tree_view;
pub mod widgets;

use std::path::Path;

use anyhow::{Context, Result};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::policy_loader;

/// Launch the interactive policy editor TUI.
pub fn run(path: &Path) -> Result<()> {
    let manifest = policy_loader::read_manifest(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let mut app = app::App::new(path.to_path_buf(), manifest)?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run the app (errors will be handled after cleanup)
    let result = app.run(&mut terminal);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}
