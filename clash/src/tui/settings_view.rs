//! Settings view component for editing default_effect and default_sandbox.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::tea::{Action, Component};
use super::theme::ViewContext;
use crate::policy::Effect;
use crate::policy::match_tree::PolicyManifest;

pub struct SettingsView {
    pub selected_field: usize,
}

#[derive(Debug)]
pub enum Msg {
    MoveUp,
    MoveDown,
    CycleValue,
}

impl Default for SettingsView {
    fn default() -> Self {
        Self::new()
    }
}

impl SettingsView {
    pub fn new() -> Self {
        SettingsView { selected_field: 0 }
    }

    /// Number of editable fields.
    const FIELD_COUNT: usize = 2;
}

impl Component for SettingsView {
    type Msg = Msg;

    fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Msg::MoveDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Msg::MoveUp),
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char(' ') => Some(Msg::CycleValue),
            _ => None,
        }
    }

    fn update(&mut self, msg: Msg, manifest: &mut PolicyManifest) -> Action {
        match msg {
            Msg::MoveDown => {
                self.selected_field = (self.selected_field + 1).min(Self::FIELD_COUNT - 1);
                Action::None
            }
            Msg::MoveUp => {
                self.selected_field = self.selected_field.saturating_sub(1);
                Action::None
            }
            Msg::CycleValue => {
                match self.selected_field {
                    0 => {
                        // Cycle default_effect: allow -> deny -> ask -> allow
                        manifest.policy.default_effect = match manifest.policy.default_effect {
                            Effect::Allow => Effect::Deny,
                            Effect::Deny => Effect::Ask,
                            Effect::Ask => Effect::Allow,
                        };
                        Action::Modified
                    }
                    1 => {
                        // Cycle default_sandbox through sandbox names + None
                        let names: Vec<String> = {
                            let mut n: Vec<String> =
                                manifest.policy.sandboxes.keys().cloned().collect();
                            n.sort();
                            n
                        };

                        if names.is_empty() {
                            manifest.policy.default_sandbox = None;
                            return Action::Flash("No sandboxes defined".into());
                        }

                        let current = manifest.policy.default_sandbox.as_deref();
                        let next = match current {
                            None => Some(names[0].clone()),
                            Some(name) => {
                                if let Some(pos) = names.iter().position(|n| n == name) {
                                    if pos + 1 < names.len() {
                                        Some(names[pos + 1].clone())
                                    } else {
                                        None // wrap back to None
                                    }
                                } else {
                                    Some(names[0].clone())
                                }
                            }
                        };
                        manifest.policy.default_sandbox = next;
                        Action::Modified
                    }
                    _ => Action::None,
                }
            }
        }
    }

    fn view(&self, frame: &mut Frame, area: Rect, ctx: &ViewContext) {
        let t = ctx.theme;
        let manifest = ctx.manifest;
        let block = Block::default()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(t.border_unfocused);

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let effect_str = manifest.policy.default_effect.to_string();
        let effect_style = t.policy_effect(manifest.policy.default_effect);

        let sandbox_str = manifest
            .policy
            .default_sandbox
            .as_deref()
            .unwrap_or("(none)");

        let fields = [
            ("default_effect", effect_str.as_str(), effect_style),
            ("default_sandbox", sandbox_str, t.detail_value),
        ];

        let lines: Vec<Line> = fields
            .iter()
            .enumerate()
            .flat_map(|(i, (label, value, base_style))| {
                let selected = i == self.selected_field;
                let label_style = if selected {
                    t.field_label_active
                } else {
                    t.field_label_inactive
                };
                let value_style = if selected {
                    base_style.add_modifier(Modifier::BOLD).patch(t.selection)
                } else {
                    *base_style
                };

                let hint = if selected {
                    " (Enter/Space to cycle)"
                } else {
                    ""
                };

                vec![
                    Line::from(""),
                    Line::from(vec![
                        Span::styled(format!("  {label}: "), label_style),
                        Span::styled(*value, value_style),
                        Span::styled(hint, t.text_disabled),
                    ]),
                ]
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

    fn empty_manifest() -> PolicyManifest {
        PolicyManifest {
            includes: vec![],
            policy: CompiledPolicy {
                sandboxes: HashMap::new(),
                tree: vec![],
                default_effect: Effect::Deny,
                default_sandbox: None,
            },
        }
    }

    #[test]
    fn test_cycle_default_effect() {
        let mut manifest = empty_manifest();
        let mut view = SettingsView::new();

        assert_eq!(manifest.policy.default_effect, Effect::Deny);

        view.update(Msg::CycleValue, &mut manifest);
        assert_eq!(manifest.policy.default_effect, Effect::Ask);

        view.update(Msg::CycleValue, &mut manifest);
        assert_eq!(manifest.policy.default_effect, Effect::Allow);

        view.update(Msg::CycleValue, &mut manifest);
        assert_eq!(manifest.policy.default_effect, Effect::Deny);
    }

    #[test]
    fn test_cycle_default_sandbox() {
        let mut manifest = empty_manifest();
        manifest.policy.sandboxes.insert(
            "alpha".into(),
            crate::policy::sandbox_types::SandboxPolicy {
                default: crate::policy::sandbox_types::Cap::READ,
                rules: vec![],
                network: crate::policy::sandbox_types::NetworkPolicy::Deny,
                doc: None,
            },
        );
        manifest.policy.sandboxes.insert(
            "beta".into(),
            crate::policy::sandbox_types::SandboxPolicy {
                default: crate::policy::sandbox_types::Cap::READ,
                rules: vec![],
                network: crate::policy::sandbox_types::NetworkPolicy::Deny,
                doc: None,
            },
        );

        let mut view = SettingsView::new();
        view.selected_field = 1; // default_sandbox

        assert_eq!(manifest.policy.default_sandbox, None);

        view.update(Msg::CycleValue, &mut manifest);
        assert_eq!(manifest.policy.default_sandbox.as_deref(), Some("alpha"));

        view.update(Msg::CycleValue, &mut manifest);
        assert_eq!(manifest.policy.default_sandbox.as_deref(), Some("beta"));

        view.update(Msg::CycleValue, &mut manifest);
        assert_eq!(manifest.policy.default_sandbox, None);
    }
}
