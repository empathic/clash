//! Includes view component for managing policy include entries.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::tea::{Action, Component, FormRequest};
use crate::policy::match_tree::PolicyManifest;

pub struct IncludesView {
    pub selected: usize,
}

#[derive(Debug)]
pub enum Msg {
    MoveUp,
    MoveDown,
    JumpTop,
    JumpBottom,
    Add,
    Delete,
    MoveItemUp,
    MoveItemDown,
}

impl Default for IncludesView {
    fn default() -> Self {
        Self::new()
    }
}

impl IncludesView {
    pub fn new() -> Self {
        IncludesView { selected: 0 }
    }
}

impl Component for IncludesView {
    type Msg = Msg;

    fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Msg::MoveDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Msg::MoveUp),
            KeyCode::Char('g') => Some(Msg::JumpTop),
            KeyCode::Char('G') => Some(Msg::JumpBottom),
            KeyCode::Char('a') => Some(Msg::Add),
            KeyCode::Char('d') => Some(Msg::Delete),
            KeyCode::Char('J') => Some(Msg::MoveItemDown),
            KeyCode::Char('K') => Some(Msg::MoveItemUp),
            _ => None,
        }
    }

    fn update(&mut self, msg: Msg, manifest: &mut PolicyManifest) -> Action {
        let len = manifest.includes.len();
        match msg {
            Msg::MoveDown => {
                if len > 0 {
                    self.selected = (self.selected + 1).min(len - 1);
                }
                Action::None
            }
            Msg::MoveUp => {
                self.selected = self.selected.saturating_sub(1);
                Action::None
            }
            Msg::JumpTop => {
                self.selected = 0;
                Action::None
            }
            Msg::JumpBottom => {
                if len > 0 {
                    self.selected = len - 1;
                }
                Action::None
            }
            Msg::Add => Action::RunForm(FormRequest::AddInclude),
            Msg::Delete => {
                if self.selected < len {
                    manifest.includes.remove(self.selected);
                    if self.selected >= manifest.includes.len() && !manifest.includes.is_empty() {
                        self.selected = manifest.includes.len() - 1;
                    }
                    return Action::Modified;
                }
                Action::None
            }
            Msg::MoveItemUp => {
                if self.selected > 0 && self.selected < len {
                    manifest.includes.swap(self.selected, self.selected - 1);
                    self.selected -= 1;
                    return Action::Modified;
                }
                Action::None
            }
            Msg::MoveItemDown => {
                if self.selected + 1 < len {
                    manifest.includes.swap(self.selected, self.selected + 1);
                    self.selected += 1;
                    return Action::Modified;
                }
                Action::None
            }
        }
    }

    fn view(&self, frame: &mut Frame, area: Rect, manifest: &PolicyManifest) {
        let block = Block::default()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if manifest.includes.is_empty() {
            let empty = Paragraph::new(Line::from(vec![
                Span::styled(
                    "  No includes. Press ",
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    "a",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" to add one.", Style::default().fg(Color::DarkGray)),
            ]));
            frame.render_widget(empty, inner);
            return;
        }

        let lines: Vec<Line> = manifest
            .includes
            .iter()
            .enumerate()
            .map(|(i, include)| {
                let style = if i == self.selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };

                let priority = format!("[{}]", i + 1);
                Line::from(vec![
                    Span::styled(
                        format!("  {priority} "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(&include.path, style),
                ])
            })
            .collect();

        let para = Paragraph::new(lines);
        frame.render_widget(para, inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::match_tree::*;
    use std::collections::HashMap;

    fn manifest_with_includes() -> PolicyManifest {
        PolicyManifest {
            includes: vec![
                IncludeEntry {
                    path: "a.star".into(),
                },
                IncludeEntry {
                    path: "b.star".into(),
                },
                IncludeEntry {
                    path: "c.star".into(),
                },
            ],
            policy: CompiledPolicy {
                sandboxes: HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        }
    }

    #[test]
    fn test_reorder_includes() {
        let mut manifest = manifest_with_includes();
        let mut view = IncludesView::new();

        // Select second item and move it up
        view.selected = 1;
        view.update(Msg::MoveItemUp, &mut manifest);
        assert_eq!(view.selected, 0);
        assert_eq!(manifest.includes[0].path, "b.star");
        assert_eq!(manifest.includes[1].path, "a.star");

        // Move it back down
        view.update(Msg::MoveItemDown, &mut manifest);
        assert_eq!(view.selected, 1);
        assert_eq!(manifest.includes[0].path, "a.star");
        assert_eq!(manifest.includes[1].path, "b.star");
    }

    #[test]
    fn test_delete_include() {
        let mut manifest = manifest_with_includes();
        let mut view = IncludesView::new();
        view.selected = 1;

        let action = view.update(Msg::Delete, &mut manifest);
        assert!(matches!(action, Action::Modified));
        assert_eq!(manifest.includes.len(), 2);
        assert_eq!(manifest.includes[0].path, "a.star");
        assert_eq!(manifest.includes[1].path, "c.star");
    }
}
