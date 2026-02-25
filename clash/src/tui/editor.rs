//! Text input widget and form state for editing operations.

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

    /// Byte offset for the given char position.
    fn byte_offset(&self, char_pos: usize) -> usize {
        self.content
            .char_indices()
            .nth(char_pos)
            .map(|(i, _)| i)
            .unwrap_or(self.content.len())
    }
}
