//! Key event handling and mode transitions.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{
    AddRuleStep, App, ConfirmAction, DOMAIN_NAMES, EFFECT_DISPLAY, EFFECT_NAMES, FS_OPS, Mode,
};
use super::editor::TextInputAction;

/// Result of handling a key event.
pub enum InputResult {
    /// Continue the event loop.
    Continue,
    /// Quit the TUI.
    Quit,
}

/// Handle a key event, dispatching based on current mode.
pub fn handle_key(app: &mut App, key: KeyEvent) -> InputResult {
    // Help overlay intercepts all keys
    if app.show_help {
        app.show_help = false;
        return InputResult::Continue;
    }

    // Clear status message on any keypress (except in text-input modes)
    if matches!(
        app.mode,
        Mode::Normal | Mode::Confirm(_) | Mode::ConfirmSave(_) | Mode::SelectEffect(_)
    ) {
        app.status_message = None;
    }

    match &app.mode {
        Mode::Normal => handle_normal(app, key),
        Mode::Confirm(_) => handle_confirm(app, key),
        Mode::ConfirmSave(_) => handle_confirm_save(app, key),
        Mode::AddRule(_) => handle_add_rule(app, key),
        Mode::EditRule(_) => handle_edit_rule(app, key),
        Mode::SelectEffect(_) => handle_select_effect(app, key),
        Mode::Search => handle_search(app, key),
    }
}

// ---------------------------------------------------------------------------
// Normal mode
// ---------------------------------------------------------------------------

fn handle_normal(app: &mut App, key: KeyEvent) -> InputResult {
    match key.code {
        // Quit (with unsaved-changes check)
        KeyCode::Char('q') => return app.start_quit(),
        KeyCode::Esc => {
            if app.search.query.is_some() {
                app.clear_search();
            } else {
                return app.start_quit();
            }
        }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return app.start_quit();
        }

        // Help
        KeyCode::Char('?') => app.show_help = true,

        // Navigation
        KeyCode::Char('j') | KeyCode::Down => app.move_cursor_down(),
        KeyCode::Char('k') | KeyCode::Up => app.move_cursor_up(),

        // Collapse / expand
        KeyCode::Char('h') | KeyCode::Left => app.collapse_or_parent(),
        KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => app.expand(),

        // Jump to top/bottom
        KeyCode::Char('g') => app.cursor_to_top(),
        KeyCode::Char('G') => app.cursor_to_bottom(),

        // Page up/down
        KeyCode::PageUp => app.page_up(),
        KeyCode::PageDown => app.page_down(),

        // Toggle expand
        KeyCode::Char(' ') => app.toggle_expand(),

        // Editing
        KeyCode::Tab => app.start_select_effect(),
        KeyCode::Char('d') => app.start_delete(),
        KeyCode::Char('w') => app.save_all(),
        KeyCode::Char('u') => app.undo(),
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => app.redo(),

        // Fold level / subtree / all
        KeyCode::Char('z') => app.toggle_fold_level(),
        KeyCode::Char('Z') => app.toggle_fold_recursive(),
        KeyCode::Char('[') => app.collapse_all(),
        KeyCode::Char(']') => app.expand_all(),

        // Add / Edit / Search
        KeyCode::Char('a') => app.start_add_rule(),
        KeyCode::Char('e') => app.start_edit_rule(),
        KeyCode::Char('/') => app.start_search(),

        // Search navigation
        KeyCode::Char('n') => app.next_search_match(),
        KeyCode::Char('N') => app.prev_search_match(),

        _ => {}
    }
    InputResult::Continue
}

// ---------------------------------------------------------------------------
// Confirm mode
// ---------------------------------------------------------------------------

fn handle_confirm(app: &mut App, key: KeyEvent) -> InputResult {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            let mode = std::mem::replace(&mut app.mode, Mode::Normal);
            match mode {
                Mode::Confirm(ConfirmAction::DeleteRule {
                    level,
                    policy,
                    rule_text,
                }) => {
                    app.confirm_delete(level, policy, rule_text);
                    InputResult::Continue
                }
                Mode::Confirm(ConfirmAction::DeleteSandboxRule {
                    level,
                    policy,
                    sandbox_rule_text,
                    parent_rule,
                }) => {
                    app.confirm_delete_sandbox_rule(level, policy, sandbox_rule_text, parent_rule);
                    InputResult::Continue
                }
                Mode::Confirm(ConfirmAction::DeleteBranch { leaves, .. }) => {
                    app.confirm_delete_branch(leaves);
                    InputResult::Continue
                }
                Mode::Confirm(ConfirmAction::QuitUnsaved) => InputResult::Quit,
                _ => InputResult::Continue,
            }
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.mode = Mode::Normal;
            app.status_message = None;
            InputResult::Continue
        }
        _ => InputResult::Continue,
    }
}

// ---------------------------------------------------------------------------
// Confirm save mode
// ---------------------------------------------------------------------------

fn handle_confirm_save(app: &mut App, key: KeyEvent) -> InputResult {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            app.mode = Mode::Normal;
            app.confirm_save();
            InputResult::Continue
        }
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
            app.mode = Mode::Normal;
            app.status_message = None;
            InputResult::Continue
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if let Mode::ConfirmSave(diff) = &mut app.mode {
                diff.scroll = diff.scroll.saturating_add(1);
            }
            InputResult::Continue
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if let Mode::ConfirmSave(diff) = &mut app.mode {
                diff.scroll = diff.scroll.saturating_sub(1);
            }
            InputResult::Continue
        }
        _ => InputResult::Continue,
    }
}

// ---------------------------------------------------------------------------
// Add rule mode
// ---------------------------------------------------------------------------

fn handle_add_rule(app: &mut App, key: KeyEvent) -> InputResult {
    let Mode::AddRule(form) = &mut app.mode else {
        return InputResult::Continue;
    };

    // Determine what kind of step we're on and the selector count (if selector).
    let action = match form.step {
        AddRuleStep::SelectDomain => selector_key(key, &mut form.domain_index, DOMAIN_NAMES.len()),
        AddRuleStep::SelectFsOp => selector_key(key, &mut form.fs_op_index, FS_OPS.len()),
        AddRuleStep::SelectEffect => selector_key(key, &mut form.effect_index, EFFECT_NAMES.len()),
        AddRuleStep::SelectLevel => {
            let len = form.available_levels.len();
            selector_key(key, &mut form.level_index, len)
        }
        AddRuleStep::EnterBinary
        | AddRuleStep::EnterArgs
        | AddRuleStep::EnterPath
        | AddRuleStep::EnterNetDomain
        | AddRuleStep::EnterToolName => text_input_key(key, form),
    };

    match action {
        StepAction::Advance => app.advance_add_rule(),
        StepAction::Cancel => app.mode = Mode::Normal,
        StepAction::None => {}
    }

    InputResult::Continue
}

/// Action returned from a step's key handler.
enum StepAction {
    Advance,
    Cancel,
    None,
}

/// Handle key for a selector step. Returns whether to advance/cancel/stay.
fn selector_key(key: KeyEvent, index: &mut usize, count: usize) -> StepAction {
    match key.code {
        KeyCode::Left | KeyCode::Char('h') => {
            if *index > 0 {
                *index -= 1;
            }
            StepAction::None
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if *index < count.saturating_sub(1) {
                *index += 1;
            }
            StepAction::None
        }
        KeyCode::Tab => {
            if count > 0 {
                *index = (*index + 1) % count;
            }
            StepAction::None
        }
        KeyCode::Enter => StepAction::Advance,
        KeyCode::Esc => StepAction::Cancel,
        _ => StepAction::None,
    }
}

/// Handle key for a text input step.
fn text_input_key(key: KeyEvent, form: &mut super::app::AddRuleForm) -> StepAction {
    if let Some(input) = form.active_text_input() {
        match input.handle_key(key) {
            TextInputAction::Submit => StepAction::Advance,
            TextInputAction::Cancel => StepAction::Cancel,
            TextInputAction::Changed => {
                form.error = None;
                StepAction::None
            }
            _ => StepAction::None,
        }
    } else {
        StepAction::None
    }
}

// ---------------------------------------------------------------------------
// Edit rule mode
// ---------------------------------------------------------------------------

fn handle_edit_rule(app: &mut App, key: KeyEvent) -> InputResult {
    let Mode::EditRule(state) = &mut app.mode else {
        return InputResult::Continue;
    };
    match state.input.handle_key(key) {
        TextInputAction::Submit => app.complete_edit_rule(),
        TextInputAction::Cancel => app.mode = Mode::Normal,
        TextInputAction::Changed => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.error = None;
            }
        }
        _ => {}
    }
    InputResult::Continue
}

// ---------------------------------------------------------------------------
// Select effect mode
// ---------------------------------------------------------------------------

fn handle_select_effect(app: &mut App, key: KeyEvent) -> InputResult {
    let Mode::SelectEffect(state) = &mut app.mode else {
        return InputResult::Continue;
    };
    match key.code {
        KeyCode::Left | KeyCode::Char('h') => {
            if state.effect_index > 0 {
                state.effect_index -= 1;
            }
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if state.effect_index < EFFECT_DISPLAY.len() - 1 {
                state.effect_index += 1;
            }
        }
        KeyCode::Tab => {
            state.effect_index = (state.effect_index + 1) % EFFECT_DISPLAY.len();
        }
        KeyCode::Enter => app.confirm_select_effect(),
        KeyCode::Esc => app.mode = Mode::Normal,
        _ => {}
    }
    InputResult::Continue
}

// ---------------------------------------------------------------------------
// Search mode
// ---------------------------------------------------------------------------

fn handle_search(app: &mut App, key: KeyEvent) -> InputResult {
    match app.search.input.handle_key(key) {
        TextInputAction::Submit => app.commit_search(),
        TextInputAction::Cancel => app.cancel_search(),
        TextInputAction::Changed => app.update_search_live(),
        _ => {}
    }
    InputResult::Continue
}
