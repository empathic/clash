//! Sandbox view component for browsing and editing sandbox definitions.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::tea::{Action, Component, FormRequest};
use crate::policy::match_tree::{CompiledPolicy, PolicyManifest};
use crate::policy::sandbox_types::{RuleEffect, SandboxPolicy};

pub struct SandboxView {
    sandbox_names: Vec<String>,
    /// Names of sandboxes from includes — these are read-only.
    included_names: HashSet<String>,
    /// Merged sandbox policies (inline + included) for display.
    all_sandboxes: std::collections::HashMap<String, SandboxPolicy>,
    selected_sandbox: usize,
    selected_rule: usize,
    focus: Focus,
}

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    SandboxList,
    RuleList,
}

#[derive(Debug)]
pub enum Msg {
    MoveUp,
    MoveDown,
    JumpTop,
    JumpBottom,
    FocusRules,
    FocusSandboxes,
    AddSandbox,
    AddRule,
    Edit,
    Delete,
    CopyToInline,
}

impl SandboxView {
    pub fn new(manifest: &PolicyManifest, included: &CompiledPolicy) -> Self {
        let mut view = SandboxView {
            sandbox_names: Vec::new(),
            included_names: HashSet::new(),
            all_sandboxes: std::collections::HashMap::new(),
            selected_sandbox: 0,
            selected_rule: 0,
            focus: Focus::SandboxList,
        };
        view.rebuild_with_included(manifest, included);
        view
    }

    pub fn rebuild(&mut self, manifest: &PolicyManifest) {
        self.rebuild_with_included(
            manifest,
            &CompiledPolicy {
                sandboxes: std::collections::HashMap::new(),
                tree: vec![],
                default_effect: manifest.policy.default_effect.clone(),
                default_sandbox: None,
            },
        );
    }

    pub fn rebuild_with_included(&mut self, manifest: &PolicyManifest, included: &CompiledPolicy) {
        let old_name = self.sandbox_names.get(self.selected_sandbox).cloned();

        // Merge inline + included sandboxes (inline wins on conflict)
        self.all_sandboxes = manifest.policy.sandboxes.clone();
        self.included_names.clear();
        for (k, v) in &included.sandboxes {
            if !manifest.policy.sandboxes.contains_key(k) {
                self.all_sandboxes.insert(k.clone(), v.clone());
                self.included_names.insert(k.clone());
            }
        }

        self.sandbox_names = self.all_sandboxes.keys().cloned().collect();
        self.sandbox_names.sort();

        // Try to keep the same sandbox selected
        if let Some(name) = old_name {
            if let Some(pos) = self.sandbox_names.iter().position(|n| *n == name) {
                self.selected_sandbox = pos;
            } else if self.selected_sandbox >= self.sandbox_names.len()
                && !self.sandbox_names.is_empty()
            {
                self.selected_sandbox = self.sandbox_names.len() - 1;
            }
        }
    }

    fn is_selected_read_only(&self) -> bool {
        self.sandbox_names
            .get(self.selected_sandbox)
            .is_some_and(|name| self.included_names.contains(name))
    }

    fn current_sandbox(&self) -> Option<(&str, &SandboxPolicy)> {
        let name = self.sandbox_names.get(self.selected_sandbox)?;
        self.all_sandboxes
            .get(name.as_str())
            .map(move |sb| (name.as_str(), sb))
    }

    fn current_sandbox_rule_count(&self) -> usize {
        self.current_sandbox()
            .map(|(_, sb)| sb.rules.len())
            .unwrap_or(0)
    }
}

impl Component for SandboxView {
    type Msg = Msg;

    fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Msg::MoveDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Msg::MoveUp),
            KeyCode::Char('g') => Some(Msg::JumpTop),
            KeyCode::Char('G') => Some(Msg::JumpBottom),
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => Some(Msg::FocusRules),
            KeyCode::Char('h') | KeyCode::Left | KeyCode::Esc => Some(Msg::FocusSandboxes),
            KeyCode::Char('a') => match self.focus {
                Focus::SandboxList => Some(Msg::AddSandbox),
                Focus::RuleList => Some(Msg::AddRule),
            },
            KeyCode::Char('e') => Some(Msg::Edit),
            KeyCode::Char('d') => Some(Msg::Delete),
            KeyCode::Char('c') => Some(Msg::CopyToInline),
            _ => None,
        }
    }

    fn update(&mut self, msg: Msg, manifest: &mut PolicyManifest) -> Action {
        match msg {
            Msg::MoveDown => {
                match self.focus {
                    Focus::SandboxList => {
                        if !self.sandbox_names.is_empty() {
                            self.selected_sandbox =
                                (self.selected_sandbox + 1).min(self.sandbox_names.len() - 1);
                            self.selected_rule = 0;
                        }
                    }
                    Focus::RuleList => {
                        let count = self.current_sandbox_rule_count();
                        if count > 0 {
                            self.selected_rule = (self.selected_rule + 1).min(count - 1);
                        }
                    }
                }
                Action::None
            }
            Msg::MoveUp => {
                match self.focus {
                    Focus::SandboxList => {
                        self.selected_sandbox = self.selected_sandbox.saturating_sub(1);
                        self.selected_rule = 0;
                    }
                    Focus::RuleList => {
                        self.selected_rule = self.selected_rule.saturating_sub(1);
                    }
                }
                Action::None
            }
            Msg::JumpTop => {
                match self.focus {
                    Focus::SandboxList => {
                        self.selected_sandbox = 0;
                        self.selected_rule = 0;
                    }
                    Focus::RuleList => self.selected_rule = 0,
                }
                Action::None
            }
            Msg::JumpBottom => {
                match self.focus {
                    Focus::SandboxList => {
                        if !self.sandbox_names.is_empty() {
                            self.selected_sandbox = self.sandbox_names.len() - 1;
                            self.selected_rule = 0;
                        }
                    }
                    Focus::RuleList => {
                        let count = self.current_sandbox_rule_count();
                        if count > 0 {
                            self.selected_rule = count - 1;
                        }
                    }
                }
                Action::None
            }
            Msg::FocusRules => {
                if self.current_sandbox().is_some() {
                    self.focus = Focus::RuleList;
                    self.selected_rule = 0;
                }
                Action::None
            }
            Msg::FocusSandboxes => {
                self.focus = Focus::SandboxList;
                Action::None
            }
            Msg::AddSandbox => Action::RunForm(FormRequest::AddSandbox),
            Msg::Edit => {
                if self.is_selected_read_only() {
                    return Action::Flash("Included sandboxes are read-only".into());
                }
                match self.focus {
                    Focus::SandboxList => {
                        if let Some(name) = self.sandbox_names.get(self.selected_sandbox).cloned() {
                            Action::RunForm(FormRequest::EditSandbox { sandbox_name: name })
                        } else {
                            Action::Flash("No sandbox selected".into())
                        }
                    }
                    Focus::RuleList => {
                        if let Some(name) = self.sandbox_names.get(self.selected_sandbox).cloned() {
                            Action::RunForm(FormRequest::EditSandboxRule {
                                sandbox_name: name,
                                rule_index: self.selected_rule,
                            })
                        } else {
                            Action::Flash("No sandbox selected".into())
                        }
                    }
                }
            }
            Msg::AddRule => {
                if self.is_selected_read_only() {
                    return Action::Flash("Included sandboxes are read-only".into());
                }
                if let Some(name) = self.sandbox_names.get(self.selected_sandbox).cloned() {
                    Action::RunForm(FormRequest::AddSandboxRule { sandbox_name: name })
                } else {
                    Action::Flash("No sandbox selected".into())
                }
            }
            Msg::Delete => {
                if self.is_selected_read_only() {
                    return Action::Flash("Included sandboxes are read-only".into());
                }
                match self.focus {
                    Focus::SandboxList => {
                        if let Some(name) = self.sandbox_names.get(self.selected_sandbox).cloned() {
                            if crate::policy::sandbox_edit::delete_sandbox(manifest, &name).is_ok()
                            {
                                self.rebuild(manifest);
                                return Action::Modified;
                            }
                        }
                    }
                    Focus::RuleList => {
                        if let Some((name, sb)) = self.current_sandbox() {
                            if let Some(rule) = sb.rules.get(self.selected_rule) {
                                let path = rule.path.clone();
                                let name = name.to_string();
                                if crate::policy::sandbox_edit::remove_rule(manifest, &name, &path)
                                    .unwrap_or(false)
                                {
                                    self.selected_rule = self.selected_rule.saturating_sub(1);
                                    return Action::Modified;
                                }
                            }
                        }
                    }
                }
                Action::None
            }
            Msg::CopyToInline => {
                if !self.is_selected_read_only() {
                    return Action::Flash("Already an inline sandbox".into());
                }
                let Some(name) = self.sandbox_names.get(self.selected_sandbox).cloned() else {
                    return Action::None;
                };
                let Some(sb) = self.all_sandboxes.get(&name).cloned() else {
                    return Action::None;
                };
                manifest.policy.sandboxes.insert(name.clone(), sb);
                self.rebuild(manifest);
                Action::Modified
            }
        }
    }

    fn view(&self, frame: &mut Frame, area: Rect, _manifest: &PolicyManifest) {
        let chunks = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        // Left pane: sandbox list
        self.render_sandbox_list(frame, chunks[0]);

        // Right pane: sandbox detail + rules
        self.render_sandbox_detail(frame, chunks[1]);
    }
}

impl SandboxView {
    fn render_sandbox_list(&self, frame: &mut Frame, area: Rect) {
        let border_color = if self.focus == Focus::SandboxList {
            Color::Blue
        } else {
            Color::DarkGray
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(" Sandboxes ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        if self.sandbox_names.is_empty() {
            let empty = Paragraph::new(Line::from(vec![
                Span::styled(
                    "  No sandboxes. Press ",
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

        let lines: Vec<Line> = self
            .sandbox_names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let is_included = self.included_names.contains(name);
                let display = if is_included {
                    format!("  {name} [included]")
                } else {
                    format!("  {name}")
                };
                let style = if i == self.selected_sandbox && self.focus == Focus::SandboxList {
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else if i == self.selected_sandbox {
                    Style::default().fg(Color::Cyan)
                } else if is_included {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::DIM)
                } else {
                    Style::default().fg(Color::White)
                };
                Line::from(Span::styled(display, style))
            })
            .collect();

        let para = Paragraph::new(lines);
        frame.render_widget(para, inner);
    }

    fn render_sandbox_detail(&self, frame: &mut Frame, area: Rect) {
        let border_color = if self.focus == Focus::RuleList {
            Color::Blue
        } else {
            Color::DarkGray
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color))
            .title(" Details ");

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let Some((_name, sb)) = self.current_sandbox() else {
            return;
        };

        let mut lines = Vec::new();

        // Header info
        lines.push(Line::from(vec![
            Span::styled("  Default: ", Style::default().fg(Color::DarkGray)),
            Span::styled(sb.default.display(), Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Network: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format_network(&sb.network),
                Style::default().fg(Color::Cyan),
            ),
        ]));
        if let Some(doc) = &sb.doc {
            lines.push(Line::from(Span::styled(
                format!("  Doc: {doc}"),
                Style::default().fg(Color::DarkGray),
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Rules:",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )));

        if sb.rules.is_empty() {
            lines.push(Line::from(Span::styled(
                "    (no rules)",
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            for (i, rule) in sb.rules.iter().enumerate() {
                let effect_color = match rule.effect {
                    RuleEffect::Allow => Color::Green,
                    RuleEffect::Deny => Color::Red,
                };
                let selected = i == self.selected_rule && self.focus == Focus::RuleList;
                let style = if selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(effect_color)
                };
                let effect_str = match rule.effect {
                    RuleEffect::Allow => "allow",
                    RuleEffect::Deny => "deny",
                };
                lines.push(Line::from(Span::styled(
                    format!(
                        "    {effect_str} {} in {} ({})",
                        rule.caps.display(),
                        rule.path,
                        format!("{:?}", rule.path_match).to_lowercase()
                    ),
                    style,
                )));
            }
        }

        let para = Paragraph::new(lines);
        frame.render_widget(para, inner);
    }
}

fn format_network(net: &crate::policy::sandbox_types::NetworkPolicy) -> String {
    use crate::policy::sandbox_types::NetworkPolicy;
    match net {
        NetworkPolicy::Deny => "deny".into(),
        NetworkPolicy::Allow => "allow".into(),
        NetworkPolicy::Localhost => "localhost".into(),
        NetworkPolicy::AllowDomains(domains) => format!("allow [{}]", domains.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::match_tree::*;
    use crate::policy::sandbox_edit;
    use crate::policy::sandbox_types::{Cap, NetworkPolicy};
    use std::collections::HashMap;

    fn empty_manifest() -> PolicyManifest {
        PolicyManifest {
            includes: vec![],
            policy: CompiledPolicy {
                sandboxes: HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        }
    }

    fn empty_included() -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![],
            default_effect: crate::policy::Effect::Deny,
            default_sandbox: None,
        }
    }

    #[test]
    fn test_sandbox_navigation() {
        let mut manifest = empty_manifest();
        sandbox_edit::create_sandbox(&mut manifest, "alpha", Cap::READ, NetworkPolicy::Deny, None)
            .unwrap();
        sandbox_edit::create_sandbox(&mut manifest, "beta", Cap::READ, NetworkPolicy::Allow, None)
            .unwrap();

        let mut view = SandboxView::new(&manifest, &empty_included());
        assert_eq!(view.sandbox_names.len(), 2);
        assert_eq!(view.selected_sandbox, 0);

        view.update(Msg::MoveDown, &mut manifest);
        assert_eq!(view.selected_sandbox, 1);

        view.update(Msg::MoveUp, &mut manifest);
        assert_eq!(view.selected_sandbox, 0);
    }

    #[test]
    fn test_edit_sandbox_from_list() {
        let mut manifest = empty_manifest();
        sandbox_edit::create_sandbox(&mut manifest, "dev", Cap::READ, NetworkPolicy::Deny, None)
            .unwrap();

        let mut view = SandboxView::new(&manifest, &empty_included());
        let action = view.update(Msg::Edit, &mut manifest.clone());
        match action {
            Action::RunForm(FormRequest::EditSandbox { sandbox_name }) => {
                assert_eq!(sandbox_name, "dev");
            }
            _ => panic!("Expected RunForm(EditSandbox), got {:?}", "other"),
        }
    }

    #[test]
    fn test_edit_sandbox_rule() {
        let mut manifest = empty_manifest();
        sandbox_edit::create_sandbox(&mut manifest, "dev", Cap::READ, NetworkPolicy::Deny, None)
            .unwrap();
        sandbox_edit::add_rule(
            &mut manifest,
            "dev",
            crate::policy::sandbox_types::RuleEffect::Allow,
            Cap::READ | Cap::WRITE,
            "$PWD".into(),
            crate::policy::sandbox_types::PathMatch::Subpath,
            None,
        )
        .unwrap();

        let mut view = SandboxView::new(&manifest, &empty_included());
        // Focus on rules
        view.update(Msg::FocusRules, &mut manifest);
        let action = view.update(Msg::Edit, &mut manifest.clone());
        match action {
            Action::RunForm(FormRequest::EditSandboxRule {
                sandbox_name,
                rule_index,
            }) => {
                assert_eq!(sandbox_name, "dev");
                assert_eq!(rule_index, 0);
            }
            _ => panic!("Expected RunForm(EditSandboxRule)"),
        }
    }

    #[test]
    fn test_edit_read_only_sandbox_blocked() {
        let mut manifest = empty_manifest();
        let mut included = empty_included();
        included.sandboxes.insert(
            "from_star".into(),
            SandboxPolicy {
                default: Cap::READ,
                rules: vec![],
                network: NetworkPolicy::Deny,
                doc: None,
            },
        );

        let mut view = SandboxView::new(&manifest, &included);
        let action = view.update(Msg::Edit, &mut manifest);
        assert!(matches!(action, Action::Flash(_)));
    }

    #[test]
    fn test_delete_sandbox() {
        let mut manifest = empty_manifest();
        sandbox_edit::create_sandbox(&mut manifest, "test", Cap::READ, NetworkPolicy::Deny, None)
            .unwrap();

        let mut view = SandboxView::new(&manifest, &empty_included());
        let action = view.update(Msg::Delete, &mut manifest);
        assert!(matches!(action, Action::Modified));
        assert!(manifest.policy.sandboxes.is_empty());
    }
}
