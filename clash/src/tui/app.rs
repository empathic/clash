//! App — the root TUI component that manages tabs, overlays, and the event loop.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use similar::TextDiff;

use crate::policy::match_tree::{CompiledPolicy, Node, PolicyManifest};
use crate::policy_loader;

use super::includes_view::IncludesView;
use super::inline_form::{FormEvent, FormState};
use super::sandbox_view::SandboxView;
use super::settings_view::SettingsView;
use super::tea::{Action, Component};
use super::test_panel::{self, TestPanel, TestPanelAction};
use super::tree_view::TreeView;
use super::widgets::{self, DiffLine};

/// Which tab is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Tree,
    Sandboxes,
    Includes,
    Settings,
}

/// Overlay mode the app can be in.
enum Mode {
    Normal,
    Help,
    Confirm(ConfirmAction),
    SaveReview(DiffState),
    Form(FormState),
}

/// What action to take after confirmation.
enum ConfirmAction {
    Quit,
}

/// State for the diff review overlay.
struct DiffState {
    lines: Vec<DiffLine>,
    scroll: usize,
}

/// Messages for the App component.
pub enum Msg {
    SwitchTab(Tab),
    NextTab,
    PrevTab,
    Save,
    Quit,
    ToggleHelp,
    ToggleTestPanel,
    ToggleTestFocus,
    ConfirmYes,
    ConfirmNo,
    DiffScrollDown,
    DiffScrollUp,
    TreeMsg(<TreeView as Component>::Msg),
    SandboxMsg(<SandboxView as Component>::Msg),
    IncludesMsg(<IncludesView as Component>::Msg),
    SettingsMsg(<SettingsView as Component>::Msg),
    TestPanelMsg(test_panel::Msg),
}

pub struct App {
    manifest: PolicyManifest,
    /// Content resolved from `includes` entries — shown as read-only.
    included: CompiledPolicy,
    original_json: String,
    path: PathBuf,
    active_tab: Tab,
    tree_view: TreeView,
    sandbox_view: SandboxView,
    includes_view: IncludesView,
    settings_view: SettingsView,
    test_panel: TestPanel,
    /// Whether the test panel currently has keyboard focus.
    test_focused: bool,
    mode: Mode,
    dirty: bool,
    flash: Option<(String, Instant)>,
}

impl App {
    pub fn new(path: PathBuf, manifest: PolicyManifest) -> Result<Self> {
        let original_json = serde_json::to_string_pretty(&manifest)?;

        // Resolve includes to show their rules/sandboxes as read-only
        let base_dir = path.parent().unwrap_or(std::path::Path::new("."));
        let (included, include_warnings) =
            match policy_loader::resolve_includes(&manifest, base_dir) {
                Ok((cp, warnings)) => (cp, warnings),
                Err(e) => (
                    CompiledPolicy {
                        sandboxes: std::collections::HashMap::new(),
                        tree: vec![],
                        default_effect: manifest.policy.default_effect,
                        default_sandbox: None,
                    },
                    vec![format!("{e}")],
                ),
            };

        let tree_view = TreeView::new(&manifest, &included);
        let sandbox_view = SandboxView::new(&manifest, &included);
        let includes_view = IncludesView::new();
        let settings_view = SettingsView::new();

        // Surface include errors loudly
        let flash = if !include_warnings.is_empty() {
            Some((
                format!("Include errors: {}", include_warnings.join("; ")),
                Instant::now(),
            ))
        } else {
            None
        };

        Ok(App {
            manifest,
            included,
            original_json,
            path,
            active_tab: Tab::Tree,
            tree_view,
            sandbox_view,
            includes_view,
            settings_view,
            test_panel: TestPanel::new(),
            test_focused: false,
            mode: Mode::Normal,
            dirty: false,
            flash,
        })
    }

    /// Show the test panel and focus it (called by --test flag).
    pub fn show_test_panel(&mut self) {
        self.test_panel.visible = true;
        self.test_panel.input_active = true;
        self.test_focused = true;
    }

    /// Run the main event loop.
    pub fn run<B: Backend<Error: Send + Sync + 'static>>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> Result<()> {
        loop {
            // Clone manifest for view to avoid borrow issues
            let manifest_snapshot = self.manifest.clone();
            terminal.draw(|frame| self.view(frame, frame.area(), &manifest_snapshot))?;

            let event = event::read()?;
            if let Event::Key(key) = event {
                // Form mode handles keys directly — not via Msg
                if matches!(self.mode, Mode::Form(_)) {
                    let FormHandled::Continue = self.handle_form_key(key);
                    continue;
                }

                // Test panel focused: route keys to the test panel.
                // Esc returns focus to the left pane. Tab toggles input/history.
                if self.test_panel.visible
                    && self.test_focused
                    && matches!(self.mode, Mode::Normal)
                {
                    match key.code {
                        KeyCode::Esc => {
                            // Return focus to the left pane
                            self.test_focused = false;
                            continue;
                        }
                        KeyCode::Tab => {
                            // Toggle between input and history within test panel
                            self.test_panel.toggle_input_focus();
                            continue;
                        }
                        _ => {
                            if let Some(msg) = self.test_panel.handle_key(key) {
                                let compiled = self.current_compiled_policy();
                                match self.test_panel.update(msg, compiled.as_ref()) {
                                    TestPanelAction::Flash(s) => {
                                        self.flash = Some((s, Instant::now()));
                                    }
                                    TestPanelAction::None => {}
                                }
                            }
                            continue;
                        }
                    }
                }

                if let Some(msg) = self.handle_key(key) {
                    let action = self.update_msg(msg);
                    match action {
                        Action::Quit => break,
                        Action::Modified => {
                            self.dirty = true;
                            self.rebuild_views();
                        }
                        Action::RunForm(req) => {
                            let form =
                                FormState::from_request(&req, &self.manifest, Some(&self.included));
                            self.mode = Mode::Form(form);
                        }
                        Action::Flash(s) => {
                            self.flash = Some((s, Instant::now()));
                        }
                        Action::None => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle a key event when in Form mode.
    fn handle_form_key(&mut self, key: KeyEvent) -> FormHandled {
        let Mode::Form(ref form) = self.mode else {
            return FormHandled::Continue;
        };

        // 'a' in an edit form → close and open AddChild for the same path.
        // Only when active field is a Select (not typing in a Text field).
        if key.code == KeyCode::Char('a') && form.active_field_is_select() {
            let add_path = match &form.kind {
                super::inline_form::FormKind::EditDecision { path }
                | super::inline_form::FormKind::EditCondition { path } => {
                    // For EditDecision on an inline leaf, the path points to the
                    // Condition node — use it directly as the parent.
                    // For a bare Decision, go up to the parent Condition.
                    let tree = &self.manifest.policy.tree;
                    if TreeView::get_node_at_path_ref(tree, path)
                        .is_some_and(|n| matches!(n, Node::Condition { .. }))
                    {
                        Some(path.clone())
                    } else if path.len() >= 2 {
                        Some(path[..path.len() - 1].to_vec())
                    } else {
                        None
                    }
                }
                _ => None,
            };

            if let Some(parent_path) = add_path {
                let req = super::tea::FormRequest::AddChild { parent_path };
                let new_form = FormState::from_request(&req, &self.manifest, Some(&self.included));
                self.mode = Mode::Form(new_form);
                return FormHandled::Continue;
            }
        }

        let Mode::Form(ref mut form) = self.mode else {
            return FormHandled::Continue;
        };

        match form.handle_key(key) {
            FormEvent::Continue => FormHandled::Continue,
            FormEvent::Cancel => {
                self.mode = Mode::Normal;
                FormHandled::Continue
            }
            FormEvent::Submit => {
                // Take the form out of mode so we can use it
                let Mode::Form(form) = std::mem::replace(&mut self.mode, Mode::Normal) else {
                    return FormHandled::Continue;
                };
                match form.apply(&mut self.manifest) {
                    Ok(true) => {
                        self.dirty = true;
                        self.rebuild_views();
                        self.flash = Some(("Added".into(), Instant::now()));
                    }
                    Ok(false) => {}
                    Err(msg) => {
                        self.flash = Some((msg, Instant::now()));
                    }
                }
                FormHandled::Continue
            }
        }
    }

    fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        // Mode-specific key handling
        match &self.mode {
            Mode::Help => return Some(Msg::ToggleHelp), // any key closes help
            Mode::Confirm(_) => {
                return match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => Some(Msg::ConfirmYes),
                    _ => Some(Msg::ConfirmNo),
                };
            }
            Mode::SaveReview(_) => {
                return match key.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => Some(Msg::ConfirmYes),
                    KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Some(Msg::ConfirmNo),
                    KeyCode::Char('j') | KeyCode::Down => Some(Msg::DiffScrollDown),
                    KeyCode::Char('k') | KeyCode::Up => Some(Msg::DiffScrollUp),
                    _ => None,
                };
            }
            Mode::Form(_) => return None, // handled separately
            Mode::Normal => {}
        }

        // Global keys
        match key.code {
            KeyCode::Char('q') => return Some(Msg::Quit),
            KeyCode::Char('s') => return Some(Msg::Save),
            KeyCode::Char('t') => return Some(Msg::ToggleTestPanel),
            KeyCode::Char('?') => return Some(Msg::ToggleHelp),
            KeyCode::Char('1') => return Some(Msg::SwitchTab(Tab::Tree)),
            KeyCode::Char('2') => return Some(Msg::SwitchTab(Tab::Sandboxes)),
            KeyCode::Char('3') => return Some(Msg::SwitchTab(Tab::Includes)),
            KeyCode::Char('4') => return Some(Msg::SwitchTab(Tab::Settings)),
            KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                return Some(Msg::PrevTab);
            }
            KeyCode::BackTab => return Some(Msg::PrevTab),
            KeyCode::Tab => return Some(Msg::NextTab),
            _ => {}
        }

        // Delegate to active tab
        match self.active_tab {
            Tab::Tree => self.tree_view.handle_key(key).map(Msg::TreeMsg),
            Tab::Sandboxes => self.sandbox_view.handle_key(key).map(Msg::SandboxMsg),
            Tab::Includes => self.includes_view.handle_key(key).map(Msg::IncludesMsg),
            Tab::Settings => self.settings_view.handle_key(key).map(Msg::SettingsMsg),
        }
    }

    /// Process a message and return an action.
    fn update_msg(&mut self, msg: Msg) -> Action {
        match msg {
            Msg::SwitchTab(tab) => {
                self.active_tab = tab;
                Action::None
            }
            Msg::NextTab => {
                self.active_tab = match self.active_tab {
                    Tab::Tree => Tab::Sandboxes,
                    Tab::Sandboxes => Tab::Includes,
                    Tab::Includes => Tab::Settings,
                    Tab::Settings => Tab::Tree,
                };
                Action::None
            }
            Msg::PrevTab => {
                self.active_tab = match self.active_tab {
                    Tab::Tree => Tab::Settings,
                    Tab::Sandboxes => Tab::Tree,
                    Tab::Includes => Tab::Sandboxes,
                    Tab::Settings => Tab::Includes,
                };
                Action::None
            }
            Msg::Save => {
                if !self.dirty {
                    return Action::Flash("No changes to save".into());
                }
                let new_json = serde_json::to_string_pretty(&self.manifest).unwrap_or_default();
                let diff_lines = compute_diff(&self.original_json, &new_json);
                self.mode = Mode::SaveReview(DiffState {
                    lines: diff_lines,
                    scroll: 0,
                });
                Action::None
            }
            Msg::Quit => {
                if self.dirty {
                    self.mode = Mode::Confirm(ConfirmAction::Quit);
                    Action::None
                } else {
                    Action::Quit
                }
            }
            Msg::ToggleHelp => {
                self.mode = match self.mode {
                    Mode::Help => Mode::Normal,
                    _ => Mode::Help,
                };
                Action::None
            }
            Msg::ConfirmYes => {
                let mode = std::mem::replace(&mut self.mode, Mode::Normal);
                match mode {
                    Mode::Confirm(ConfirmAction::Quit) => Action::Quit,
                    Mode::SaveReview(_) => {
                        // Actually save
                        match policy_loader::write_manifest(&self.path, &self.manifest) {
                            Ok(()) => {
                                self.original_json = serde_json::to_string_pretty(&self.manifest)
                                    .unwrap_or_default();
                                self.dirty = false;

                                // Post-save validation
                                let new_json = serde_json::to_string_pretty(&self.manifest)
                                    .unwrap_or_default();
                                match crate::policy::compile::compile_to_tree(&new_json) {
                                    Ok(policy) => {
                                        let warnings = policy.platform_warnings();
                                        if warnings.is_empty() {
                                            Action::Flash("Saved".into())
                                        } else {
                                            Action::Flash(format!(
                                                "Saved (warnings: {})",
                                                warnings.join("; ")
                                            ))
                                        }
                                    }
                                    Err(e) => {
                                        Action::Flash(format!("Saved (validation error: {e})"))
                                    }
                                }
                            }
                            Err(e) => Action::Flash(format!("Save failed: {e}")),
                        }
                    }
                    _ => Action::None,
                }
            }
            Msg::ConfirmNo => {
                self.mode = Mode::Normal;
                Action::None
            }
            Msg::DiffScrollDown => {
                if let Mode::SaveReview(ref mut state) = self.mode
                    && state.scroll + 1 < state.lines.len()
                {
                    state.scroll += 1;
                }
                Action::None
            }
            Msg::DiffScrollUp => {
                if let Mode::SaveReview(ref mut state) = self.mode {
                    state.scroll = state.scroll.saturating_sub(1);
                }
                Action::None
            }
            Msg::ToggleTestPanel => {
                if self.test_panel.visible {
                    // Panel visible: toggle focus to test panel
                    self.test_focused = true;
                    self.test_panel.input_active = true;
                } else {
                    // Panel hidden: show it and focus it
                    self.test_panel.visible = true;
                    self.test_focused = true;
                    self.test_panel.input_active = true;
                }
                Action::None
            }
            Msg::ToggleTestFocus => {
                self.test_panel.toggle_input_focus();
                Action::None
            }
            Msg::TreeMsg(m) => self.tree_view.update(m, &mut self.manifest),
            Msg::SandboxMsg(m) => self.sandbox_view.update(m, &mut self.manifest),
            Msg::IncludesMsg(m) => self.includes_view.update(m, &mut self.manifest),
            Msg::SettingsMsg(m) => self.settings_view.update(m, &mut self.manifest),
            Msg::TestPanelMsg(m) => {
                let compiled = self.current_compiled_policy();
                match self.test_panel.update(m, compiled.as_ref()) {
                    TestPanelAction::Flash(s) => Action::Flash(s),
                    TestPanelAction::None => Action::None,
                }
            }
        }
    }

    /// Build a merged compiled policy (inline + included) for test evaluation.
    fn current_compiled_policy(&self) -> Option<CompiledPolicy> {
        let mut merged = self.manifest.policy.clone();
        // Append included rules so tests see the full picture
        merged.tree.extend(self.included.tree.clone());
        for (k, v) in &self.included.sandboxes {
            merged.sandboxes.entry(k.clone()).or_insert_with(|| v.clone());
        }
        Some(merged)
    }

    fn rebuild_views(&mut self) {
        self.tree_view
            .rebuild_with_included(&self.manifest, &self.included);
        self.sandbox_view
            .rebuild_with_included(&self.manifest, &self.included);

        // Re-evaluate test cases against updated policy
        if self.test_panel.visible {
            if let Some(compiled) = self.current_compiled_policy() {
                self.test_panel.re_evaluate(&compiled);
            }
        }
    }

    fn view(&self, frame: &mut Frame, area: Rect, manifest: &PolicyManifest) {
        let chunks = Layout::vertical([
            Constraint::Length(2), // title + tab bar
            Constraint::Min(3),    // content
            Constraint::Length(1), // status bar
        ])
        .split(area);

        // Title bar
        let title = Line::from(vec![
            Span::styled(
                " clash policy editor ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("-- {} ", self.path.display()),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(title).alignment(Alignment::Left),
            Rect::new(chunks[0].x, chunks[0].y, chunks[0].width, 1),
        );

        // Tab bar
        widgets::render_tab_bar(
            frame,
            Rect::new(chunks[0].x, chunks[0].y + 1, chunks[0].width, 1),
            &self.active_tab,
            self.dirty,
        );

        // Content area — split horizontally if test panel is visible
        let (content_area, test_area) = if self.test_panel.visible {
            let split = Layout::horizontal([
                Constraint::Percentage(68),
                Constraint::Percentage(32),
            ])
            .split(chunks[1]);
            (split[0], Some(split[1]))
        } else {
            (chunks[1], None)
        };

        // Active tab content
        match self.active_tab {
            Tab::Tree => self.tree_view.view(frame, content_area, manifest),
            Tab::Sandboxes => self.sandbox_view.view(frame, content_area, manifest),
            Tab::Includes => self.includes_view.view(frame, content_area, manifest),
            Tab::Settings => self.settings_view.view(frame, content_area, manifest),
        }

        // Test panel (side panel)
        if let Some(area) = test_area {
            self.test_panel.view_with_focus(frame, area, self.test_focused);
        }

        // Status bar
        let flash_msg = self.flash.as_ref().and_then(|(msg, instant)| {
            if instant.elapsed().as_secs() < 3 {
                Some(msg.as_str())
            } else {
                None
            }
        });

        let test_hint = if self.test_focused {
            ("Esc", "back to editor")
        } else {
            ("t", "test console")
        };

        let hints: &[(&str, &str)] = match self.active_tab {
            Tab::Tree => &[
                ("j/k", "move"),
                ("h/l", "collapse/expand"),
                ("e", "edit"),
                ("a", "add"),
                ("d", "delete"),
                ("c", "copy to inline"),
                test_hint,
                ("s", "save"),
            ],
            Tab::Sandboxes => &[
                ("j/k", "move"),
                ("l/h", "focus rules/back"),
                ("a", "add"),
                ("e", "edit"),
                ("d", "delete"),
                ("c", "copy to inline"),
                test_hint,
                ("s", "save"),
            ],
            Tab::Includes => &[
                ("j/k", "move"),
                ("J/K", "reorder"),
                ("a", "add"),
                ("d", "delete"),
                test_hint,
                ("s", "save"),
            ],
            Tab::Settings => &[("j/k", "move"), ("Enter", "cycle"), test_hint, ("s", "save")],
        };

        widgets::render_status_bar(frame, chunks[2], hints, flash_msg);

        // Overlays
        match &self.mode {
            Mode::Help => widgets::render_help_overlay(frame, area),
            Mode::Confirm(ConfirmAction::Quit) => {
                widgets::render_confirm_overlay(frame, area, "Unsaved changes. Quit anyway?");
            }
            Mode::SaveReview(state) => {
                widgets::render_diff_overlay(frame, area, &state.lines, state.scroll);
            }
            Mode::Form(form) => {
                form.view(frame, area);
            }
            Mode::Normal => {}
        }
    }
}

/// Internal result from handling a form key.
enum FormHandled {
    Continue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Effect;
    use crate::policy::match_tree::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
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

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    /// Simulate pressing a key and rendering the result.
    /// Panics if the render crashes.
    fn press_and_render(app: &mut App, terminal: &mut Terminal<TestBackend>, key_event: KeyEvent) {
        // Handle key
        if matches!(app.mode, Mode::Form(_)) {
            let FormHandled::Continue = app.handle_form_key(key_event);
        } else if let Some(msg) = app.handle_key(key_event) {
            let action = app.update_msg(msg);
            match action {
                Action::Quit => {}
                Action::Modified => {
                    app.dirty = true;
                    app.rebuild_views();
                }
                Action::RunForm(req) => {
                    let form = FormState::from_request(&req, &app.manifest, Some(&app.included));
                    app.mode = Mode::Form(form);
                }
                Action::Flash(s) => {
                    app.flash = Some((s, Instant::now()));
                }
                Action::None => {}
            }
        }

        // Render — this is what we're testing doesn't panic
        let manifest_snapshot = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &manifest_snapshot))
            .unwrap();
    }

    #[test]
    fn test_edit_on_root_renders_without_crash() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Initial render
        let snap = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &snap))
            .unwrap();

        // Press 'e' on root (selected=0)
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('e')));

        // Press another key — should still render fine
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('j')));
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('k')));
    }

    #[test]
    fn test_delete_on_root_renders_without_crash() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        let snap = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &snap))
            .unwrap();

        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('d')));
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('j')));
    }

    #[test]
    fn test_add_on_root_opens_form_and_renders() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        let snap = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &snap))
            .unwrap();

        // Press 'a' on root — should open Add Rule form
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('a')));
        assert!(matches!(app.mode, Mode::Form(_)));

        // Render form overlay
        press_and_render(&mut app, &mut terminal, key(KeyCode::Esc));
        assert!(matches!(app.mode, Mode::Normal));
    }
}

/// Compute a diff between two strings, returning colored diff lines.
fn compute_diff(old: &str, new: &str) -> Vec<DiffLine> {
    let diff = TextDiff::from_lines(old, new);
    let mut lines = Vec::new();

    for (idx, group) in diff.grouped_ops(3).iter().enumerate() {
        if idx > 0 {
            lines.push(DiffLine::Header("---".into()));
        }
        for op in group {
            for change in diff.iter_changes(op) {
                let line_content = change.to_string_lossy();
                let s = line_content.trim_end_matches('\n').to_string();
                match change.tag() {
                    similar::ChangeTag::Equal => lines.push(DiffLine::Context(format!("  {s}"))),
                    similar::ChangeTag::Insert => lines.push(DiffLine::Add(format!("+ {s}"))),
                    similar::ChangeTag::Delete => lines.push(DiffLine::Remove(format!("- {s}"))),
                }
            }
        }
    }

    if lines.is_empty() {
        lines.push(DiffLine::Context("(no changes)".into()));
    }

    lines
}
