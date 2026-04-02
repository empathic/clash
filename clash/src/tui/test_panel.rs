//! Test console panel — a persistent side panel for testing tool invocations
//! against the current policy in real-time.
//!
//! The panel maintains a history of test cases. When the policy is modified,
//! all cases are re-evaluated and changed results are flagged.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::theme::Theme;
use crate::policy::Effect;
use crate::policy::match_tree::CompiledPolicy;
use crate::policy::test_eval;

/// A single test case in the console history.
#[derive(Debug, Clone)]
pub struct TestCase {
    /// The raw input string the user typed.
    pub input: String,
    /// The resolved tool name.
    pub tool_name: String,
    /// The resolved tool input JSON.
    pub tool_input: serde_json::Value,
    /// The most recent evaluation result.
    pub effect: Effect,
    /// Short summary of the decision.
    pub summary: String,
    /// Whether this test case is pinned (always visible).
    pub pinned: bool,
    /// Whether the result changed on the last re-evaluation.
    pub changed: bool,
    /// The previous effect before re-evaluation (for change detection).
    prev_effect: Option<Effect>,
}

/// Messages for the TestPanel component.
#[derive(Debug)]
pub enum Msg {
    ScrollUp,
    ScrollDown,
    JumpTop,
    JumpBottom,
    TogglePin,
    DeleteCase,
    ClearHistory,
    /// A character typed into the input line.
    InputChar(char),
    InputBackspace,
    InputDelete,
    InputLeft,
    InputRight,
    InputHome,
    InputEnd,
    InputSubmit,
    InputClear,
}

pub struct TestPanel {
    /// Test case history (newest last).
    cases: Vec<TestCase>,
    /// Currently selected case in the history.
    selected: usize,
    /// Scroll offset for the history view.
    scroll_offset: usize,
    /// Whether the input line is focused (vs history navigation).
    pub input_active: bool,
    /// The current input line text.
    input_line: String,
    /// Cursor position in the input line.
    input_cursor: usize,
    /// Whether the panel is visible.
    pub visible: bool,
    /// Flash message (error from last submit).
    flash: Option<String>,
    /// Active permission mode for test evaluation (e.g. "plan", "edit").
    mode: Option<String>,
}

impl Default for TestPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPanel {
    pub fn new() -> Self {
        TestPanel {
            cases: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            input_active: true,
            input_line: String::new(),
            input_cursor: 0,
            visible: true,
            flash: None,
            mode: Some("default".into()),
        }
    }

    /// Toggle panel visibility.
    pub fn toggle(&mut self) {
        self.visible = !self.visible;
        if self.visible {
            self.input_active = true;
        }
    }

    /// Handle a key event, returning a message if applicable.
    pub fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        if self.input_active {
            // Input mode keys
            match key.code {
                KeyCode::Enter => Some(Msg::InputSubmit),
                KeyCode::Backspace => Some(Msg::InputBackspace),
                KeyCode::Delete => Some(Msg::InputDelete),
                KeyCode::Left => Some(Msg::InputLeft),
                KeyCode::Right => Some(Msg::InputRight),
                KeyCode::Home => Some(Msg::InputHome),
                KeyCode::End => Some(Msg::InputEnd),
                KeyCode::Esc => Some(Msg::InputClear),
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    Some(Msg::InputClear)
                }
                KeyCode::Char(c) => Some(Msg::InputChar(c)),
                _ => None,
            }
        } else {
            // History navigation mode
            match key.code {
                KeyCode::Char('k') | KeyCode::Up => Some(Msg::ScrollUp),
                KeyCode::Char('j') | KeyCode::Down => Some(Msg::ScrollDown),
                KeyCode::Char('g') => Some(Msg::JumpTop),
                KeyCode::Char('G') => Some(Msg::JumpBottom),
                KeyCode::Char('p') => Some(Msg::TogglePin),
                KeyCode::Char('d') => Some(Msg::DeleteCase),
                KeyCode::Char('x') => Some(Msg::ClearHistory),
                KeyCode::Char('i') | KeyCode::Enter => {
                    // Switch to input mode — handled by returning None and letting
                    // the caller set input_active
                    None
                }
                _ => None,
            }
        }
    }

    /// Process a message and update state. Returns true if a flash should be shown.
    pub fn update(&mut self, msg: Msg, policy: Option<&CompiledPolicy>) -> TestPanelAction {
        match msg {
            Msg::ScrollUp => {
                self.selected = self.selected.saturating_sub(1);
                TestPanelAction::None
            }
            Msg::ScrollDown => {
                if !self.cases.is_empty() {
                    self.selected = (self.selected + 1).min(self.cases.len() - 1);
                }
                TestPanelAction::None
            }
            Msg::JumpTop => {
                self.selected = 0;
                TestPanelAction::None
            }
            Msg::JumpBottom => {
                if !self.cases.is_empty() {
                    self.selected = self.cases.len() - 1;
                }
                TestPanelAction::None
            }
            Msg::TogglePin => {
                if let Some(case) = self.cases.get_mut(self.selected) {
                    case.pinned = !case.pinned;
                }
                TestPanelAction::None
            }
            Msg::DeleteCase => {
                if self.selected < self.cases.len() {
                    self.cases.remove(self.selected);
                    if self.selected >= self.cases.len() && !self.cases.is_empty() {
                        self.selected = self.cases.len() - 1;
                    }
                }
                TestPanelAction::None
            }
            Msg::ClearHistory => {
                // Keep pinned cases
                self.cases.retain(|c| c.pinned);
                self.selected = 0;
                TestPanelAction::None
            }
            Msg::InputChar(c) => {
                self.flash = None;
                self.input_line.insert(self.input_cursor, c);
                self.input_cursor += c.len_utf8();
                TestPanelAction::None
            }
            Msg::InputBackspace => {
                if self.input_cursor > 0 {
                    let prev = self.input_line[..self.input_cursor]
                        .chars()
                        .last()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.input_cursor -= prev;
                    self.input_line.remove(self.input_cursor);
                }
                TestPanelAction::None
            }
            Msg::InputDelete => {
                if self.input_cursor < self.input_line.len() {
                    self.input_line.remove(self.input_cursor);
                }
                TestPanelAction::None
            }
            Msg::InputLeft => {
                if self.input_cursor > 0 {
                    let prev = self.input_line[..self.input_cursor]
                        .chars()
                        .last()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.input_cursor -= prev;
                }
                TestPanelAction::None
            }
            Msg::InputRight => {
                if self.input_cursor < self.input_line.len() {
                    let next = self.input_line[self.input_cursor..]
                        .chars()
                        .next()
                        .map(|c| c.len_utf8())
                        .unwrap_or(0);
                    self.input_cursor += next;
                }
                TestPanelAction::None
            }
            Msg::InputHome => {
                self.input_cursor = 0;
                TestPanelAction::None
            }
            Msg::InputEnd => {
                self.input_cursor = self.input_line.len();
                TestPanelAction::None
            }
            Msg::InputSubmit => {
                let input = self.input_line.trim().to_string();
                if input.is_empty() {
                    return TestPanelAction::None;
                }

                // Handle "mode <name>" command
                if let Some(mode_arg) = input.strip_prefix("mode") {
                    let mode_arg = mode_arg.trim();
                    if mode_arg.is_empty() {
                        let current = self.mode.as_deref().unwrap_or("(none)");
                        self.flash = Some(format!("mode: {current}"));
                        self.input_line.clear();
                        self.input_cursor = 0;
                        return TestPanelAction::Flash(format!("mode: {current}"));
                    } else if mode_arg == "none" || mode_arg == "clear" {
                        self.mode = None;
                        self.flash = Some("mode cleared".into());
                        self.input_line.clear();
                        self.input_cursor = 0;
                        return TestPanelAction::Flash("mode cleared".into());
                    } else {
                        self.mode = Some(mode_arg.to_string());
                        self.flash = Some(format!("mode: {mode_arg}"));
                        self.input_line.clear();
                        self.input_cursor = 0;
                        return TestPanelAction::Flash(format!("mode: {mode_arg}"));
                    }
                }

                let Some(policy) = policy else {
                    self.flash = Some("No policy loaded".into());
                    return TestPanelAction::Flash("No policy loaded".into());
                };

                match test_eval::evaluate_test_with_mode(&input, policy, self.mode.as_deref()) {
                    Ok(result) => {
                        let effect = result.effect();
                        let summary = result.summary();
                        let case = TestCase {
                            input: input.clone(),
                            tool_name: result.tool_name,
                            tool_input: result.tool_input,
                            effect,
                            summary,
                            pinned: false,
                            changed: false,
                            prev_effect: None,
                        };
                        self.cases.push(case);
                        self.selected = self.cases.len() - 1;
                        self.input_line.clear();
                        self.input_cursor = 0;
                        self.flash = None;
                        TestPanelAction::None
                    }
                    Err(e) => {
                        let msg = format!("Parse error: {e:#}");
                        self.flash = Some(msg.clone());
                        TestPanelAction::Flash(msg)
                    }
                }
            }
            Msg::InputClear => {
                self.input_line.clear();
                self.input_cursor = 0;
                self.flash = None;
                TestPanelAction::None
            }
        }
    }

    /// Re-evaluate all test cases against a new policy.
    /// Called whenever the policy is modified.
    pub fn re_evaluate(&mut self, policy: &CompiledPolicy) {
        for case in &mut self.cases {
            let new_decision =
                policy.evaluate_with_mode(&case.tool_name, &case.tool_input, self.mode.as_deref());
            let new_effect = new_decision.effect;
            let new_summary = match &new_decision.reason {
                Some(reason) => format!("{} ({reason})", effect_str(new_effect)),
                None => effect_str(new_effect).to_string(),
            };

            // Detect changes: compare new effect against current effect
            let old_effect = case.effect;
            case.changed = new_effect != old_effect;
            case.prev_effect = Some(old_effect);
            case.effect = new_effect;
            case.summary = new_summary;
        }
    }

    /// Switch focus between input and history.
    pub fn toggle_input_focus(&mut self) {
        self.input_active = !self.input_active;
    }

    /// Render the test panel into the given area.
    pub fn view(&self, frame: &mut Frame, area: Rect, t: &Theme) {
        self.view_with_focus(frame, area, true, t)
    }

    /// Render the test panel, with focus indicator.
    pub fn view_with_focus(&self, frame: &mut Frame, area: Rect, focused: bool, t: &Theme) {
        let border_style = if focused {
            t.border_active
        } else {
            t.border_unfocused
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Test Console ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.height < 3 {
            return;
        }

        // Split: history area + input line (2 rows: prompt + hint)
        let chunks = Layout::vertical([
            Constraint::Min(1),    // history
            Constraint::Length(2), // input + hint
        ])
        .split(inner);

        self.render_history(frame, chunks[0], t);
        self.render_input(frame, chunks[1], t);
    }

    fn render_history(&self, frame: &mut Frame, area: Rect, t: &Theme) {
        if self.cases.is_empty() {
            let empty = Paragraph::new(Line::from(Span::styled(
                " Type a test below...",
                t.text_disabled,
            )));
            frame.render_widget(empty, area);
            return;
        }

        let visible_height = area.height as usize;

        // Adjust scroll to keep selected visible
        let scroll = if self.selected < self.scroll_offset {
            self.selected
        } else if self.selected >= self.scroll_offset + visible_height {
            self.selected.saturating_sub(visible_height - 1)
        } else {
            self.scroll_offset
        };

        // Separate pinned from unpinned for rendering
        let mut lines: Vec<Line> = Vec::new();

        // Render unpinned cases first, then pinned section
        let has_pinned = self.cases.iter().any(|c| c.pinned);

        for (i, case) in self
            .cases
            .iter()
            .enumerate()
            .skip(scroll)
            .take(visible_height)
        {
            if case.pinned && has_pinned {
                continue; // Render pinned separately below
            }
            lines.push(self.render_case(i, case, t));
        }

        // Pinned divider + pinned cases
        if has_pinned {
            let pinned_cases: Vec<(usize, &TestCase)> = self
                .cases
                .iter()
                .enumerate()
                .filter(|(_, c)| c.pinned)
                .collect();

            if !pinned_cases.is_empty() && lines.len() + 1 < visible_height {
                lines.push(Line::from(Span::styled(" ┄┄ pinned ┄┄", t.text_disabled)));
                for (i, case) in pinned_cases {
                    if lines.len() >= visible_height {
                        break;
                    }
                    lines.push(self.render_case(i, case, t));
                }
            }
        }

        let para = Paragraph::new(lines);
        frame.render_widget(para, area);
    }

    fn render_case(&self, index: usize, case: &TestCase, t: &Theme) -> Line<'static> {
        let is_selected = index == self.selected && !self.input_active;
        let pin_marker = if case.pinned { "* " } else { "  " };
        let changed_badge = if case.changed { " [CHG]" } else { "" };

        let effect_icon = match case.effect {
            Effect::Allow => "✓",
            Effect::Deny => "✗",
            Effect::Ask => "?",
        };

        let effect_style = t.policy_effect(case.effect);

        let style = if is_selected { t.selection } else { Style::default() };

        let mut spans = vec![
            Span::styled(pin_marker.to_string(), style),
            Span::styled(
                format!("{effect_icon} "),
                if is_selected { style } else { effect_style },
            ),
            Span::styled(truncate_input(&case.input, 20), style.patch(t.text_primary)),
            Span::styled(
                format!(" {}", case.summary),
                if is_selected { style } else { effect_style },
            ),
        ];

        if !changed_badge.is_empty() {
            spans.push(Span::styled(changed_badge.to_string(), t.test_changed_badge));
        }

        Line::from(spans)
    }

    fn render_input(&self, frame: &mut Frame, area: Rect, t: &Theme) {
        if area.height < 1 {
            return;
        }

        // Input line
        let prompt_style = if self.input_active {
            t.test_input_active
        } else {
            t.test_input_inactive
        };

        let input_display = if self.input_line.is_empty() && self.input_active {
            "tool args — e.g. bash git status".to_string()
        } else {
            self.input_line.clone()
        };

        let input_style = if self.input_line.is_empty() && self.input_active {
            t.text_disabled
        } else if self.input_active {
            t.text_primary
        } else {
            t.text_disabled
        };

        let input_line = Line::from(vec![
            Span::styled(" > ", prompt_style),
            Span::styled(input_display, input_style),
        ]);

        let mut lines = vec![input_line];

        // Flash/error message or hint
        if area.height >= 2 {
            if let Some(ref flash) = self.flash {
                lines.push(Line::from(Span::styled(
                    format!("   {flash}"),
                    t.test_error,
                )));
            } else {
                let hint = match &self.mode {
                    Some(m) => format!("   mode: {m}  |  Tab: history  p: pin"),
                    None => "   mode <name> to set  |  Tab: history  p: pin".to_string(),
                };
                lines.push(Line::from(Span::styled(hint, t.text_disabled)));
            }
        }

        let para = Paragraph::new(lines);
        frame.render_widget(para, area);

        // Show cursor in input when active
        if self.input_active {
            let cursor_x = area.x + 3 + self.input_cursor as u16;
            let cursor_y = area.y;
            if cursor_x < area.x + area.width {
                frame.set_cursor_position((cursor_x, cursor_y));
            }
        }
    }
}

/// Action returned from TestPanel::update.
pub enum TestPanelAction {
    None,
    Flash(String),
}

fn effect_str(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
        Effect::Ask => "ask",
    }
}

fn truncate_input(input: &str, max: usize) -> String {
    if input.len() <= max {
        input.to_string()
    } else {
        format!("{}…", &input[..max - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::manifest_edit;
    use crate::policy::match_tree::*;
    use std::collections::HashMap;

    fn empty_policy() -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![],
            default_effect: Effect::Deny,
            default_sandbox: None,
        }
    }

    fn policy_allowing_read() -> CompiledPolicy {
        let mut manifest = PolicyManifest {
            includes: vec![],
            policy: empty_policy(),
        };
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Read", Decision::Allow(None)),
        );
        manifest.policy
    }

    #[test]
    fn test_submit_and_evaluate() {
        let mut panel = TestPanel::new();
        let policy = policy_allowing_read();

        // Type "Read /tmp/foo"
        for c in "Read /tmp/foo".chars() {
            panel.update(Msg::InputChar(c), Some(&policy));
        }
        panel.update(Msg::InputSubmit, Some(&policy));

        assert_eq!(panel.cases.len(), 1);
        assert_eq!(panel.cases[0].effect, Effect::Allow);
        assert!(panel.input_line.is_empty());
    }

    #[test]
    fn test_re_evaluate_detects_changes() {
        let mut panel = TestPanel::new();
        let policy = policy_allowing_read();

        // Submit a test
        panel.input_line = r#"Read { "file_path": "/tmp/foo" }"#.to_string();
        panel.input_cursor = panel.input_line.len();
        panel.update(Msg::InputSubmit, Some(&policy));

        assert_eq!(panel.cases[0].effect, Effect::Allow);

        // Re-evaluate against a deny-all policy
        let deny_policy = empty_policy();
        panel.re_evaluate(&deny_policy);

        assert_eq!(panel.cases[0].effect, Effect::Deny);
        assert!(panel.cases[0].changed);
    }

    #[test]
    fn test_pin_toggle() {
        let mut panel = TestPanel::new();
        let policy = empty_policy();

        panel.input_line = "bash ls".to_string();
        panel.input_cursor = panel.input_line.len();
        panel.update(Msg::InputSubmit, Some(&policy));

        assert!(!panel.cases[0].pinned);

        panel.input_active = false;
        panel.update(Msg::TogglePin, None);
        assert!(panel.cases[0].pinned);

        // Clear should keep pinned
        panel.update(Msg::ClearHistory, None);
        assert_eq!(panel.cases.len(), 1);
    }

    #[test]
    fn test_delete_case() {
        let mut panel = TestPanel::new();
        let policy = empty_policy();

        panel.input_line = "bash ls".to_string();
        panel.input_cursor = panel.input_line.len();
        panel.update(Msg::InputSubmit, Some(&policy));

        panel.input_line = "bash pwd".to_string();
        panel.input_cursor = panel.input_line.len();
        panel.update(Msg::InputSubmit, Some(&policy));

        assert_eq!(panel.cases.len(), 2);

        panel.input_active = false;
        panel.selected = 0;
        panel.update(Msg::DeleteCase, None);
        assert_eq!(panel.cases.len(), 1);
    }

    #[test]
    fn test_no_policy_flash() {
        let mut panel = TestPanel::new();
        panel.input_line = "bash ls".to_string();
        panel.input_cursor = panel.input_line.len();

        let action = panel.update(Msg::InputSubmit, None);
        assert!(matches!(action, TestPanelAction::Flash(_)));
        assert!(panel.cases.is_empty());
    }
}
