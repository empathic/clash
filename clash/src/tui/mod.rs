//! Interactive policy editor TUI.
//!
//! Launches a ratatui-based terminal UI for browsing and editing policy.star.
//! Uses the Elm Architecture (TEA) pattern: `Model -> update(Msg) -> view(Model)`.

pub mod app;
pub mod includes_view;
pub mod inline_form;
pub mod sandbox_view;
pub mod settings_view;
pub mod tea;
pub mod test_panel;
pub mod theme;
pub mod tool_registry;
pub mod tree_view;
pub mod walkthrough;
pub mod widgets;

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use crossterm::cursor::Show;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use clash_starlark::codegen::StarDocument;

use crate::policy_loader::legacy_json_error;

/// Outcome of running the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiOutcome {
    /// User finished normally (saved, quit after editing, etc.).
    Completed,
    /// User aborted during onboarding — caller should skip remaining setup.
    Aborted,
}

/// Restore the terminal to its normal state.
///
/// Idempotent — safe to call even if the terminal was never fully initialised.
/// Ignores errors so it works as best-effort cleanup in panic hooks.
pub(crate) fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        std::io::stdout(),
        LeaveAlternateScreen,
        DisableMouseCapture,
        Show
    );
}

/// Launch the interactive policy editor TUI.
pub fn run(path: &Path) -> Result<TuiOutcome> {
    run_with_options(path, false, false)
}

/// Launch the TUI with options.
pub fn run_with_options(
    path: &Path,
    show_test_panel: bool,
    onboarding: bool,
) -> Result<TuiOutcome> {
    let is_star = path.extension().is_some_and(|ext| ext == "star");
    if !is_star {
        if path.file_name().and_then(|n| n.to_str()) == Some("policy.json") {
            return Err(anyhow!(legacy_json_error(path)));
        }
        return Err(anyhow!(
            "TUI only supports `.star` policies; got `{}`",
            path.display()
        ));
    }

    let doc =
        StarDocument::open(path).with_context(|| format!("failed to parse {}", path.display()))?;
    let mut app = app::App::new_star(doc)?;
    if show_test_panel {
        app.show_test_panel();
    }
    if onboarding {
        app.start_walkthrough();
    }

    // Install a panic hook that restores the terminal so the user isn't left
    // with an unusable shell if the TUI panics.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original_hook(info);
    }));

    let result = setup_and_run(&mut app);

    // Restore the previous panic hook now that the TUI is done.
    let _ = std::panic::take_hook();

    result
}

/// Set up the terminal, run the TUI, and always restore before returning.
fn setup_and_run(app: &mut app::App) -> Result<TuiOutcome> {
    enable_raw_mode()?;

    // Once raw mode is active we must restore no matter what, so run the rest
    // inside a closure — any early `?` returns land here, not the caller.
    let result = (|| {
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        app.run(&mut terminal)
    })();

    // Always restore, whether the app succeeded or returned an error.
    restore_terminal();

    result
}
