//! Text input widget and form state for editing operations.

use crossterm::event::{KeyCode, KeyEvent};

/// Result of `TextInput::handle_key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextInputAction {
    /// Enter was pressed — caller should commit.
    Submit,
    /// Esc was pressed — caller should cancel.
    Cancel,
    /// Content was modified (char typed, backspace, delete).
    Changed,
    /// Cursor moved but content unchanged.
    Moved,
    /// Key was not handled by the text input.
    Ignored,
}

/// A single-line text input with cursor.
#[derive(Debug, Clone)]
pub struct TextInput {
    content: String,
    cursor: usize, // char position
}

impl TextInput {
    pub fn new(initial: &str) -> Self {
        let cursor = initial.chars().count();
        Self {
            content: initial.to_string(),
            cursor,
        }
    }

    pub fn empty() -> Self {
        Self {
            content: String::new(),
            cursor: 0,
        }
    }

    pub fn value(&self) -> &str {
        &self.content
    }

    pub fn cursor_pos(&self) -> usize {
        self.cursor
    }

    pub fn char_count(&self) -> usize {
        self.content.chars().count()
    }

    pub fn insert_char(&mut self, ch: char) {
        let byte_pos = self.byte_offset(self.cursor);
        self.content.insert(byte_pos, ch);
        self.cursor += 1;
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            let start = self.byte_offset(self.cursor - 1);
            let end = self.byte_offset(self.cursor);
            self.content.drain(start..end);
            self.cursor -= 1;
        }
    }

    pub fn delete(&mut self) {
        let len = self.char_count();
        if self.cursor < len {
            let start = self.byte_offset(self.cursor);
            let end = self.byte_offset(self.cursor + 1);
            self.content.drain(start..end);
        }
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        let len = self.char_count();
        if self.cursor < len {
            self.cursor += 1;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.char_count();
    }

    pub fn clear(&mut self) {
        self.content.clear();
        self.cursor = 0;
    }

    /// Handle a key event, returning what action the caller should take.
    pub fn handle_key(&mut self, key: KeyEvent) -> TextInputAction {
        match key.code {
            KeyCode::Enter => TextInputAction::Submit,
            KeyCode::Esc => TextInputAction::Cancel,
            KeyCode::Backspace => {
                self.backspace();
                TextInputAction::Changed
            }
            KeyCode::Delete => {
                self.delete();
                TextInputAction::Changed
            }
            KeyCode::Left => {
                self.move_left();
                TextInputAction::Moved
            }
            KeyCode::Right => {
                self.move_right();
                TextInputAction::Moved
            }
            KeyCode::Home => {
                self.home();
                TextInputAction::Moved
            }
            KeyCode::End => {
                self.end();
                TextInputAction::Moved
            }
            KeyCode::Char(c) => {
                self.insert_char(c);
                TextInputAction::Changed
            }
            _ => TextInputAction::Ignored,
        }
    }

    /// Byte offset for the given char position.
    fn byte_offset(&self, char_pos: usize) -> usize {
        self.content
            .char_indices()
            .nth(char_pos)
            .map(|(i, _)| i)
            .unwrap_or(self.content.len())
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn empty_input() {
        let input = TextInput::empty();
        assert_eq!(input.value(), "");
        assert_eq!(input.cursor_pos(), 0);
        assert_eq!(input.char_count(), 0);
    }

    #[test]
    fn new_with_initial() {
        let input = TextInput::new("hello");
        assert_eq!(input.value(), "hello");
        assert_eq!(input.cursor_pos(), 5);
        assert_eq!(input.char_count(), 5);
    }

    #[test]
    fn insert_chars() {
        let mut input = TextInput::empty();
        input.insert_char('a');
        input.insert_char('b');
        input.insert_char('c');
        assert_eq!(input.value(), "abc");
        assert_eq!(input.cursor_pos(), 3);
    }

    #[test]
    fn backspace() {
        let mut input = TextInput::new("abc");
        input.backspace();
        assert_eq!(input.value(), "ab");
        assert_eq!(input.cursor_pos(), 2);
    }

    #[test]
    fn backspace_at_start() {
        let mut input = TextInput::new("abc");
        input.home();
        input.backspace();
        assert_eq!(input.value(), "abc");
        assert_eq!(input.cursor_pos(), 0);
    }

    #[test]
    fn delete_at_cursor() {
        let mut input = TextInput::new("abc");
        input.home();
        input.delete();
        assert_eq!(input.value(), "bc");
        assert_eq!(input.cursor_pos(), 0);
    }

    #[test]
    fn delete_at_end() {
        let mut input = TextInput::new("abc");
        input.delete();
        assert_eq!(input.value(), "abc");
        assert_eq!(input.cursor_pos(), 3);
    }

    #[test]
    fn move_left_right() {
        let mut input = TextInput::new("abc");
        input.move_left();
        assert_eq!(input.cursor_pos(), 2);
        input.move_left();
        assert_eq!(input.cursor_pos(), 1);
        input.move_right();
        assert_eq!(input.cursor_pos(), 2);
        // Can't go past end
        input.move_right();
        input.move_right();
        assert_eq!(input.cursor_pos(), 3);
    }

    #[test]
    fn home_end() {
        let mut input = TextInput::new("hello world");
        input.home();
        assert_eq!(input.cursor_pos(), 0);
        input.end();
        assert_eq!(input.cursor_pos(), 11);
    }

    #[test]
    fn clear() {
        let mut input = TextInput::new("hello");
        input.clear();
        assert_eq!(input.value(), "");
        assert_eq!(input.cursor_pos(), 0);
    }

    #[test]
    fn unicode_handling() {
        let mut input = TextInput::new("café");
        assert_eq!(input.char_count(), 4);
        assert_eq!(input.cursor_pos(), 4);

        // Backspace removes last char (é)
        input.backspace();
        assert_eq!(input.value(), "caf");
        assert_eq!(input.cursor_pos(), 3);

        // Insert multi-byte
        input.insert_char('ñ');
        assert_eq!(input.value(), "cafñ");
        assert_eq!(input.char_count(), 4);

        // Navigate and delete in the middle
        input.home();
        input.move_right(); // after 'c'
        input.delete(); // delete 'a'
        assert_eq!(input.value(), "cfñ");
        assert_eq!(input.cursor_pos(), 1);
    }

    #[test]
    fn insert_in_middle() {
        let mut input = TextInput::new("ac");
        input.home();
        input.move_right(); // after 'a'
        input.insert_char('b');
        assert_eq!(input.value(), "abc");
        assert_eq!(input.cursor_pos(), 2);
    }

    // -------------------------------------------------------------------
    // handle_key tests
    // -------------------------------------------------------------------

    #[test]
    fn handle_key_enter_submits() {
        let mut input = TextInput::new("hello");
        assert_eq!(
            input.handle_key(key(KeyCode::Enter)),
            TextInputAction::Submit
        );
    }

    #[test]
    fn handle_key_esc_cancels() {
        let mut input = TextInput::new("hello");
        assert_eq!(input.handle_key(key(KeyCode::Esc)), TextInputAction::Cancel);
    }

    #[test]
    fn handle_key_char_inserts_and_returns_changed() {
        let mut input = TextInput::empty();
        assert_eq!(
            input.handle_key(key(KeyCode::Char('x'))),
            TextInputAction::Changed
        );
        assert_eq!(input.value(), "x");
    }

    #[test]
    fn handle_key_backspace_returns_changed() {
        let mut input = TextInput::new("ab");
        assert_eq!(
            input.handle_key(key(KeyCode::Backspace)),
            TextInputAction::Changed
        );
        assert_eq!(input.value(), "a");
    }

    #[test]
    fn handle_key_delete_returns_changed() {
        let mut input = TextInput::new("ab");
        input.home();
        assert_eq!(
            input.handle_key(key(KeyCode::Delete)),
            TextInputAction::Changed
        );
        assert_eq!(input.value(), "b");
    }

    #[test]
    fn handle_key_arrows_return_moved() {
        let mut input = TextInput::new("abc");
        assert_eq!(input.handle_key(key(KeyCode::Left)), TextInputAction::Moved);
        assert_eq!(input.cursor_pos(), 2);
        assert_eq!(
            input.handle_key(key(KeyCode::Right)),
            TextInputAction::Moved
        );
        assert_eq!(input.cursor_pos(), 3);
    }

    #[test]
    fn handle_key_home_end_return_moved() {
        let mut input = TextInput::new("abc");
        assert_eq!(input.handle_key(key(KeyCode::Home)), TextInputAction::Moved);
        assert_eq!(input.cursor_pos(), 0);
        assert_eq!(input.handle_key(key(KeyCode::End)), TextInputAction::Moved);
        assert_eq!(input.cursor_pos(), 3);
    }

    #[test]
    fn handle_key_unknown_returns_ignored() {
        let mut input = TextInput::new("abc");
        assert_eq!(
            input.handle_key(key(KeyCode::F(1))),
            TextInputAction::Ignored
        );
        assert_eq!(input.value(), "abc");
    }
}
