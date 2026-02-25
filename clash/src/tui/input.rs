//! Key event handling and mode transitions.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{
    AddRuleStep, App, ConfirmAction, DOMAIN_NAMES, EFFECT_DISPLAY, EFFECT_NAMES, Mode,
};

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
        Mode::Normal | Mode::Confirm(_) | Mode::SelectEffect(_)
    ) {
        app.status_message = None;
    }

    match &app.mode {
        Mode::Normal => handle_normal(app, key),
        Mode::Confirm(_) => handle_confirm(app, key),
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
            if app.search_query.is_some() {
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
// Add rule mode
// ---------------------------------------------------------------------------

fn handle_add_rule(app: &mut App, key: KeyEvent) -> InputResult {
    let Mode::AddRule(form) = &mut app.mode else {
        return InputResult::Continue;
    };

    match form.step {
        AddRuleStep::SelectDomain => match key.code {
            KeyCode::Left | KeyCode::Char('h') => {
                if form.domain_index > 0 {
                    form.domain_index -= 1;
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if form.domain_index < DOMAIN_NAMES.len() - 1 {
                    form.domain_index += 1;
                }
            }
            KeyCode::Tab => {
                form.domain_index = (form.domain_index + 1) % DOMAIN_NAMES.len();
            }
            KeyCode::Enter => app.advance_add_rule(),
            KeyCode::Esc => app.mode = Mode::Normal,
            _ => {}
        },

        AddRuleStep::EnterMatcher => match key.code {
            KeyCode::Enter => app.advance_add_rule(),
            KeyCode::Esc => app.mode = Mode::Normal,
            KeyCode::Backspace => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.backspace();
                form.error = None;
            }
            KeyCode::Delete => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.delete();
            }
            KeyCode::Left => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.move_left();
            }
            KeyCode::Right => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.move_right();
            }
            KeyCode::Home => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.home();
            }
            KeyCode::End => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.end();
            }
            KeyCode::Char(c) => {
                let Mode::AddRule(form) = &mut app.mode else {
                    return InputResult::Continue;
                };
                form.matcher_input.insert_char(c);
                form.error = None;
            }
            _ => {}
        },

        AddRuleStep::SelectEffect => match key.code {
            KeyCode::Left | KeyCode::Char('h') => {
                if form.effect_index > 0 {
                    form.effect_index -= 1;
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if form.effect_index < EFFECT_NAMES.len() - 1 {
                    form.effect_index += 1;
                }
            }
            KeyCode::Tab => {
                form.effect_index = (form.effect_index + 1) % EFFECT_NAMES.len();
            }
            KeyCode::Enter => app.advance_add_rule(),
            KeyCode::Esc => app.mode = Mode::Normal,
            _ => {}
        },

        AddRuleStep::SelectLevel => match key.code {
            KeyCode::Left | KeyCode::Char('h') => {
                if form.level_index > 0 {
                    form.level_index -= 1;
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if form.level_index < form.available_levels.len().saturating_sub(1) {
                    form.level_index += 1;
                }
            }
            KeyCode::Tab => {
                let len = form.available_levels.len();
                if len > 0 {
                    form.level_index = (form.level_index + 1) % len;
                }
            }
            KeyCode::Enter => app.advance_add_rule(),
            KeyCode::Esc => app.mode = Mode::Normal,
            _ => {}
        },
    }

    InputResult::Continue
}

// ---------------------------------------------------------------------------
// Edit rule mode
// ---------------------------------------------------------------------------

fn handle_edit_rule(app: &mut App, key: KeyEvent) -> InputResult {
    match key.code {
        KeyCode::Enter => app.complete_edit_rule(),
        KeyCode::Esc => app.mode = Mode::Normal,
        KeyCode::Backspace => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.backspace();
                state.error = None;
            }
        }
        KeyCode::Delete => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.delete();
            }
        }
        KeyCode::Left => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.move_left();
            }
        }
        KeyCode::Right => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.move_right();
            }
        }
        KeyCode::Home => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.home();
            }
        }
        KeyCode::End => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.end();
            }
        }
        KeyCode::Char(c) => {
            if let Mode::EditRule(state) = &mut app.mode {
                state.input.insert_char(c);
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
    match key.code {
        KeyCode::Enter => app.commit_search(),
        KeyCode::Esc => app.cancel_search(),
        KeyCode::Backspace => {
            app.search_input.backspace();
            app.update_search_live();
        }
        KeyCode::Delete => {
            app.search_input.delete();
            app.update_search_live();
        }
        KeyCode::Left => app.search_input.move_left(),
        KeyCode::Right => app.search_input.move_right(),
        KeyCode::Home => app.search_input.home(),
        KeyCode::End => app.search_input.end(),
        KeyCode::Char(c) => {
            app.search_input.insert_char(c);
            app.update_search_live();
        }
        _ => {}
    }
    InputResult::Continue
}
