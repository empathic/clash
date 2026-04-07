//! App — the root TUI component that manages tabs, overlays, and the event loop.

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context as _, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use similar::TextDiff;

use crate::policy::match_tree::{CompiledPolicy, Node, PolicyManifest};
use crate::policy_loader;
use clash_starlark::codegen::StarDocument;

use super::TuiOutcome;
use super::includes_view::IncludesView;
use super::inline_form::{FormEvent, FormState};
use super::sandbox_view::SandboxView;
use super::settings_view::SettingsView;
use super::tea::{Action, Component};
use super::test_panel::{self, TestPanel, TestPanelAction};
use super::theme::{Theme, ViewContext};
use super::tree_view::TreeView;
use super::walkthrough::{self, WalkthroughState, WalkthroughStep};
use super::widgets::{self, ClickAction, ClickRegions, DiffLine, ScrollState};

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
    Help(ScrollState),
    Confirm(ConfirmAction),
    SaveReview(DiffState),
    Form(FormState),
    Walkthrough,
}

/// What action to take after confirmation.
enum ConfirmAction {
    Quit,
    SkipWalkthrough,
    /// Quit the editor entirely during walkthrough, discarding any changes.
    QuitWalkthrough,
}

/// State for the diff review overlay.
struct DiffState {
    lines: Vec<DiffLine>,
    scroll: ScrollState,
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
    HelpScrollDown,
    HelpScrollUp,
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
    /// When editing a `.star` file, holds the parsed document for round-trip.
    star_doc: Option<StarDocument>,
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
    /// Onboarding walkthrough state — persists across Mode transitions.
    walkthrough: Option<WalkthroughState>,
    /// Mouse click targets populated each frame during `view()`.
    click_regions: ClickRegions,
    /// Visual theme for all TUI rendering.
    theme: Theme,
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
                        on_sandbox_violation: Default::default(),
                        harness_defaults: None,
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
            star_doc: None,
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
            walkthrough: None,
            click_regions: ClickRegions::default(),
            theme: Theme::from_env(),
        })
    }

    /// Create an App from a parsed `.star` document.
    ///
    /// Evaluates the Starlark source to derive the initial `PolicyManifest`,
    /// then delegates to `App::new()` and attaches the star document.
    pub fn new_star(doc: StarDocument) -> Result<Self> {
        let json = doc
            .evaluate_to_json()
            .context("failed to evaluate .star policy")?;
        let manifest: PolicyManifest =
            serde_json::from_str(&json).context("failed to parse evaluated policy JSON")?;
        let path = doc.path.clone();
        let mut app = Self::new(path, manifest)?;
        app.star_doc = Some(doc);
        Ok(app)
    }

    /// Show the test panel and focus it (called by --test flag).
    pub fn show_test_panel(&mut self) {
        self.test_panel.visible = true;
        self.test_panel.input_active = true;
        self.test_focused = true;
    }

    /// Start the onboarding walkthrough.
    pub fn start_walkthrough(&mut self) {
        self.walkthrough = Some(WalkthroughState::new());
        self.mode = Mode::Walkthrough;
    }

    /// Run the main event loop.
    pub fn run<B: Backend<Error: Send + Sync + 'static>>(
        &mut self,
        terminal: &mut Terminal<B>,
    ) -> Result<TuiOutcome> {
        let mut outcome = TuiOutcome::Completed;
        loop {
            // Clone manifest for view to avoid borrow issues
            let manifest_snapshot = self.manifest.clone();
            terminal.draw(|frame| self.view(frame, frame.area(), &manifest_snapshot))?;

            let event = event::read()?;
            if matches!(event, Event::Resize(_, _)) {
                continue; // redraw with new dimensions
            }
            // Mouse events: handle scroll in overlay modes, click on regions,
            // skip everything else to avoid busy-redraw loops from MouseEventKind::Moved.
            let mut synth_key: Option<KeyEvent> = None;
            if let Event::Mouse(mouse) = &event {
                match mouse.kind {
                    MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
                        let down = matches!(mouse.kind, MouseEventKind::ScrollDown);
                        match &mut self.mode {
                            Mode::Help(scroll) => {
                                if down {
                                    scroll.scroll_down();
                                } else {
                                    scroll.scroll_up();
                                }
                            }
                            Mode::SaveReview(state) => {
                                if down {
                                    state.scroll.scroll_down();
                                } else {
                                    state.scroll.scroll_up();
                                }
                            }
                            Mode::Walkthrough => {
                                if let Some(wt) = &mut self.walkthrough {
                                    if down {
                                        wt.scroll.scroll_down();
                                    } else {
                                        wt.scroll.scroll_up();
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    MouseEventKind::Down(MouseButton::Left) => {
                        if let Some(action) = self.click_regions.hit(mouse.column, mouse.row) {
                            match action {
                                ClickAction::Key(kc) => {
                                    synth_key = Some(KeyEvent::new(*kc, KeyModifiers::empty()));
                                }
                                &ClickAction::FormField(vi) => {
                                    if let Mode::Form(ref mut form) = self.mode {
                                        form.set_active(vi);
                                    }
                                }
                                &ClickAction::SelectOption { field, option } => {
                                    if let Mode::Form(ref mut form) = self.mode {
                                        form.set_active_for_field(field);
                                        form.set_select_option(field, option);
                                    }
                                }
                                &ClickAction::ToggleMultiSelect { field, option } => {
                                    if let Mode::Form(ref mut form) = self.mode {
                                        form.set_active_for_field(field);
                                        form.toggle_multi(field, option);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
                if synth_key.is_none() {
                    continue;
                }
            }

            let key = if let Some(sk) = synth_key {
                sk
            } else if let Event::Key(k) = event {
                k
            } else {
                continue;
            };

            // Walkthrough mode intercepts keys to advance steps.
            if matches!(self.mode, Mode::Walkthrough) {
                if let Some(ref mut wt) = self.walkthrough {
                    match key.code {
                        KeyCode::Char('q') => {
                            self.mode = Mode::Confirm(ConfirmAction::QuitWalkthrough);
                        }
                        KeyCode::Esc => {
                            self.mode = Mode::Confirm(ConfirmAction::SkipWalkthrough);
                        }
                        // j/k/arrows scroll the walkthrough overlay
                        KeyCode::Char('j') | KeyCode::Down => {
                            wt.scroll.scroll_down();
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            wt.scroll.scroll_up();
                        }
                        KeyCode::Char('b') => {
                            wt.go_back();
                        }
                        KeyCode::Enter
                            if matches!(
                                wt.step,
                                WalkthroughStep::Welcome | WalkthroughStep::BaseTools
                            ) =>
                        {
                            wt.advance();
                        }
                        KeyCode::Char('a') if wt.step == WalkthroughStep::AddRule => {
                            wt.step = WalkthroughStep::FillForm;
                            let form = FormState::new_add_rule_prefilled(
                                &self.manifest,
                                Some(&self.included),
                            );
                            self.mode = Mode::Form(form);
                        }
                        KeyCode::Char('t') if wt.step == WalkthroughStep::TestIt => {
                            wt.step = WalkthroughStep::TypeTest;
                            self.test_panel.visible = true;
                            self.test_panel.input_active = true;
                            self.test_focused = true;
                            self.mode = Mode::Normal;
                        }
                        KeyCode::Char('s') if wt.step == WalkthroughStep::SaveFinish => {
                            wt.step = WalkthroughStep::Done;
                            self.mode = Mode::Normal;
                            // Trigger the save flow
                            if self.dirty {
                                self.sync_manifest_to_star();
                                let diff_lines = if let Some(ref doc) = self.star_doc {
                                    let new_source = doc.to_source();
                                    compute_diff(&doc.original_source, &new_source)
                                } else {
                                    let new_json = serde_json::to_string_pretty(&self.manifest)
                                        .unwrap_or_default();
                                    compute_diff(&self.original_json, &new_json)
                                };
                                let len = diff_lines.len();
                                self.mode = Mode::SaveReview(DiffState {
                                    lines: diff_lines,
                                    scroll: ScrollState::new(len),
                                });
                            } else {
                                self.walkthrough = None;
                                self.flash = Some((
                                    "No changes to save — walkthrough complete!".into(),
                                    Instant::now(),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }

            // Form mode handles keys directly — not via Msg
            if matches!(self.mode, Mode::Form(_)) {
                let FormHandled::Continue = self.handle_form_key(key);
                continue;
            }

            // Test panel focused: route keys to the test panel.
            // Esc returns focus to the left pane. Tab toggles input/history.
            if self.test_panel.visible && self.test_focused && matches!(self.mode, Mode::Normal) {
                match key.code {
                    KeyCode::Esc => {
                        // During walkthrough, Esc from test panel cancels walkthrough
                        if self.walkthrough.is_some() {
                            self.walkthrough = None;
                            self.test_focused = false;
                            self.flash = Some((
                                "Walkthrough skipped — press ? for help".into(),
                                Instant::now(),
                            ));
                        } else {
                            // Return focus to the left pane
                            self.test_focused = false;
                        }
                        continue;
                    }
                    KeyCode::Tab => {
                        // Toggle between input and history within test panel
                        self.test_panel.toggle_input_focus();
                        continue;
                    }
                    _ => {
                        if let Some(msg) = self.test_panel.handle_key(key) {
                            let is_submit = matches!(msg, test_panel::Msg::InputSubmit);
                            let compiled = self.current_compiled_policy();
                            match self.test_panel.update(msg, compiled.as_ref()) {
                                TestPanelAction::Flash(s) => {
                                    self.flash = Some((s, Instant::now()));
                                }
                                TestPanelAction::None => {}
                            }
                            // Advance walkthrough from TypeTest → SaveFinish on submit
                            if is_submit
                                && let Some(ref mut wt) = self.walkthrough
                                && wt.step == WalkthroughStep::TypeTest
                            {
                                wt.step = WalkthroughStep::SaveFinish;
                                self.test_focused = false;
                                self.mode = Mode::Walkthrough;
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
                    Action::Abort => {
                        outcome = TuiOutcome::Aborted;
                        break;
                    }
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
        Ok(outcome)
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
                // If walkthrough is active, Esc from form cancels the walkthrough too
                if self.walkthrough.is_some() {
                    self.walkthrough = None;
                    self.mode = Mode::Normal;
                    self.flash = Some((
                        "Walkthrough skipped — press ? for help".into(),
                        Instant::now(),
                    ));
                } else {
                    self.mode = Mode::Normal;
                }
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
                        // Advance walkthrough from FillForm → TestIt
                        if let Some(ref mut wt) = self.walkthrough {
                            if wt.step == WalkthroughStep::FillForm {
                                wt.step = WalkthroughStep::TestIt;
                                self.mode = Mode::Walkthrough;
                                self.flash = Some(("Rule added!".into(), Instant::now()));
                            } else {
                                self.flash = Some(("Added".into(), Instant::now()));
                            }
                        } else {
                            self.flash = Some(("Added".into(), Instant::now()));
                        }
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
            Mode::Help(_) => {
                return match key.code {
                    KeyCode::Char('j') | KeyCode::Down => Some(Msg::HelpScrollDown),
                    KeyCode::Char('k') | KeyCode::Up => Some(Msg::HelpScrollUp),
                    _ => Some(Msg::ToggleHelp),
                };
            }
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
            Mode::Form(_) => return None,     // handled separately
            Mode::Walkthrough => return None, // handled in event loop
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
                // Sync manifest into star doc if editing .star
                self.sync_manifest_to_star();
                let diff_lines = if let Some(ref doc) = self.star_doc {
                    let new_source = doc.to_source();
                    compute_diff(&doc.original_source, &new_source)
                } else {
                    let new_json = serde_json::to_string_pretty(&self.manifest).unwrap_or_default();
                    compute_diff(&self.original_json, &new_json)
                };
                let len = diff_lines.len();
                self.mode = Mode::SaveReview(DiffState {
                    lines: diff_lines,
                    scroll: ScrollState::new(len),
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
                    Mode::Help(_) => Mode::Normal,
                    _ => Mode::Help(ScrollState::new(widgets::help_content(&self.theme).len())),
                };
                Action::None
            }
            Msg::HelpScrollDown => {
                if let Mode::Help(scroll) = &mut self.mode {
                    scroll.scroll_down();
                }
                Action::None
            }
            Msg::HelpScrollUp => {
                if let Mode::Help(scroll) = &mut self.mode {
                    scroll.scroll_up();
                }
                Action::None
            }
            Msg::ConfirmYes => {
                let mode = std::mem::replace(&mut self.mode, Mode::Normal);
                match mode {
                    Mode::Confirm(ConfirmAction::Quit) => Action::Quit,
                    Mode::Confirm(ConfirmAction::QuitWalkthrough) => {
                        self.walkthrough = None;
                        Action::Abort
                    }
                    Mode::Confirm(ConfirmAction::SkipWalkthrough) => {
                        self.walkthrough = None;
                        Action::Flash("Walkthrough skipped — press ? for help".into())
                    }
                    Mode::SaveReview(_) => {
                        // Actually save
                        // Sync manifest into star doc if editing .star
                        self.sync_manifest_to_star();
                        let save_result = if let Some(ref mut doc) = self.star_doc {
                            doc.save()
                        } else {
                            Err(anyhow::anyhow!(
                                "TUI save requires a `.star` document"
                            ))
                        };
                        match save_result {
                            Ok(()) => {
                                if self.star_doc.is_none() {
                                    self.original_json =
                                        serde_json::to_string_pretty(&self.manifest)
                                            .unwrap_or_default();
                                }
                                self.dirty = false;

                                // Clear walkthrough on successful save
                                let was_walkthrough = self.walkthrough.is_some();
                                self.walkthrough = None;

                                // Post-save validation
                                let new_json = serde_json::to_string_pretty(&self.manifest)
                                    .unwrap_or_default();
                                match crate::policy::compile::compile_to_tree(&new_json) {
                                    Ok(policy) => {
                                        let warnings = policy.platform_warnings();
                                        if warnings.is_empty() {
                                            if was_walkthrough {
                                                Action::Flash("Saved — setup complete! Press q to exit or keep editing.".into())
                                            } else {
                                                Action::Flash("Saved".into())
                                            }
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
                match &self.mode {
                    Mode::Confirm(
                        ConfirmAction::SkipWalkthrough | ConfirmAction::QuitWalkthrough,
                    ) => {
                        self.mode = Mode::Walkthrough;
                    }
                    _ => {
                        self.mode = Mode::Normal;
                    }
                }
                Action::None
            }
            Msg::DiffScrollDown => {
                if let Mode::SaveReview(state) = &mut self.mode {
                    state.scroll.scroll_down();
                }
                Action::None
            }
            Msg::DiffScrollUp => {
                if let Mode::SaveReview(state) = &mut self.mode {
                    state.scroll.scroll_up();
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
            merged
                .sandboxes
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        Some(merged)
    }

    /// Sync the current manifest state into the star document's AST.
    ///
    /// Called before save and diff when editing a `.star` file. Replaces the
    /// rules, sandboxes, and settings in the AST with values derived from the
    /// manifest, preserving load statements, comments, and file structure.
    fn sync_manifest_to_star(&mut self) {
        if let Some(ref mut doc) = self.star_doc {
            // Serialize manifest to JSON so we can use the JSON-based sync
            let manifest_json = serde_json::to_value(&self.manifest.policy).unwrap_or_default();
            let tree = manifest_json
                .get("tree")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let sandboxes = manifest_json
                .get("sandboxes")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            let default_effect = manifest_json
                .get("default_effect")
                .and_then(|v| v.as_str())
                .unwrap_or("ask");
            let default_sandbox = manifest_json
                .get("default_sandbox")
                .and_then(|v| v.as_str());

            clash_starlark::codegen::from_manifest::sync_manifest_to_ast(
                &mut doc.stmts,
                &tree,
                &sandboxes,
                default_effect,
                default_sandbox,
            );
        }
    }

    fn rebuild_views(&mut self) {
        self.tree_view
            .rebuild_with_included(&self.manifest, &self.included);
        self.sandbox_view
            .rebuild_with_included(&self.manifest, &self.included);

        // Re-evaluate test cases against updated policy
        if self.test_panel.visible
            && let Some(compiled) = self.current_compiled_policy()
        {
            self.test_panel.re_evaluate(&compiled);
        }
    }

    fn view(&mut self, frame: &mut Frame, area: Rect, manifest: &PolicyManifest) {
        let t = &self.theme;
        let ctx = ViewContext { manifest, theme: t };

        let chunks = Layout::vertical([
            Constraint::Length(2), // title + tab bar
            Constraint::Min(3),    // content
            Constraint::Length(1), // status bar
        ])
        .split(area);

        // Title bar
        let title = Line::from(vec![
            Span::styled(" clash policy editor ", t.text_emphasis),
            Span::styled(format!("-- {} ", self.path.display()), t.text_disabled),
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
            t,
        );

        // Content area — split horizontally if test panel is visible
        let (content_area, test_area) = if self.test_panel.visible {
            let split =
                Layout::horizontal([Constraint::Percentage(68), Constraint::Percentage(32)])
                    .split(chunks[1]);
            (split[0], Some(split[1]))
        } else {
            (chunks[1], None)
        };

        // Active tab content
        match self.active_tab {
            Tab::Tree => self.tree_view.view(frame, content_area, &ctx),
            Tab::Sandboxes => self.sandbox_view.view(frame, content_area, &ctx),
            Tab::Includes => self.includes_view.view(frame, content_area, &ctx),
            Tab::Settings => self.settings_view.view(frame, content_area, &ctx),
        }

        // Test panel (side panel)
        if let Some(area) = test_area {
            self.test_panel
                .view_with_focus(frame, area, self.test_focused, t);
        }

        // Status bar
        let flash_msg = self.flash.as_ref().and_then(|(msg, instant)| {
            if instant.elapsed().as_secs() < 3 {
                Some(msg.as_str())
            } else {
                None
            }
        });

        // Status bar — use walkthrough hints when active
        let wt_hints;
        let hints: &[(&str, &str)] = if let Some(ref wt) = self.walkthrough {
            wt_hints = walkthrough::walkthrough_status_hints(wt.step);
            &wt_hints
        } else {
            let test_hint = if self.test_focused {
                ("Esc", "back to editor")
            } else {
                ("t", "test console")
            };

            match self.active_tab {
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
                Tab::Settings => &[
                    ("j/k", "move"),
                    ("Enter", "cycle"),
                    test_hint,
                    ("s", "save"),
                ],
            }
        };

        widgets::render_status_bar(frame, chunks[2], hints, flash_msg, t);

        // Overlays — take click_regions out to avoid double-borrow with &mut self.mode
        let mut clicks = std::mem::take(&mut self.click_regions);
        clicks.clear();

        match &mut self.mode {
            Mode::Help(scroll) => {
                let inner = widgets::render_help_overlay(frame, area, scroll, t);
                for (rect, kc) in &inner.footer_buttons {
                    clicks.push(*rect, ClickAction::Key(*kc));
                }
            }
            Mode::Confirm(action) => {
                let prompt = match action {
                    ConfirmAction::Quit => "Unsaved changes. Quit anyway?",
                    ConfirmAction::SkipWalkthrough => "Skip the walkthrough?",
                    ConfirmAction::QuitWalkthrough => {
                        "Quit without saving? Your policy will remain unchanged."
                    }
                };
                let inner = widgets::render_confirm_overlay(frame, area, prompt, t);
                for (rect, kc) in &inner.footer_buttons {
                    clicks.push(*rect, ClickAction::Key(*kc));
                }
            }
            Mode::SaveReview(state) => {
                let inner =
                    widgets::render_diff_overlay(frame, area, &state.lines, &mut state.scroll, t);
                for (rect, kc) in &inner.footer_buttons {
                    clicks.push(*rect, ClickAction::Key(*kc));
                }
            }
            Mode::Form(form) => {
                form.view(frame, area, &mut clicks, t);
            }
            Mode::Walkthrough => {
                if let Some(wt) = &mut self.walkthrough {
                    walkthrough::render_walkthrough_overlay(
                        frame,
                        area,
                        wt.step,
                        &mut wt.scroll,
                        &mut clicks,
                        t,
                    );
                }
            }
            Mode::Normal => {}
        }

        self.click_regions = clicks;
    }
}

/// Internal result from handling a form key.
enum FormHandled {
    Continue,
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
                on_sandbox_violation: Default::default(),
                harness_defaults: None,
            },
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    /// Simulate pressing a key and rendering the result.
    /// Panics if the render crashes.
    fn press_and_render(app: &mut App, terminal: &mut Terminal<TestBackend>, key_event: KeyEvent) {
        // Handle key — mirror the event loop dispatch order
        if matches!(app.mode, Mode::Walkthrough) {
            if let Some(ref mut wt) = app.walkthrough {
                match key_event.code {
                    KeyCode::Char('q') => {
                        app.mode = Mode::Confirm(ConfirmAction::QuitWalkthrough);
                    }
                    KeyCode::Esc => {
                        app.mode = Mode::Confirm(ConfirmAction::SkipWalkthrough);
                    }
                    KeyCode::Char('j') | KeyCode::Down => wt.scroll.scroll_down(),
                    KeyCode::Char('k') | KeyCode::Up => wt.scroll.scroll_up(),
                    KeyCode::Char('b') => wt.go_back(),
                    KeyCode::Enter
                        if matches!(
                            wt.step,
                            WalkthroughStep::Welcome | WalkthroughStep::BaseTools
                        ) =>
                    {
                        wt.advance();
                    }
                    _ => {}
                }
            }
        } else if matches!(app.mode, Mode::Form(_)) {
            let FormHandled::Continue = app.handle_form_key(key_event);
        } else if let Some(msg) = app.handle_key(key_event) {
            let action = app.update_msg(msg);
            match action {
                Action::Quit | Action::Abort => {}
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

    // -- Click region tests ---------------------------------------------------

    /// Helper: render app to populate click_regions, then return a reference-safe
    /// snapshot of the regions for assertions.
    fn render_and_snapshot_clicks(
        app: &mut App,
        terminal: &mut Terminal<TestBackend>,
    ) -> Vec<(Rect, String)> {
        let snap = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &snap))
            .unwrap();
        // Convert to owned descriptions for assertions
        app.click_regions
            .0
            .iter()
            .map(|(r, a)| (*r, format!("{a:?}")))
            .collect()
    }

    #[test]
    fn confirm_overlay_populates_footer_click_regions() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        app.dirty = true; // so quit triggers confirm
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Press 'q' to trigger confirm dialog
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('q')));
        assert!(matches!(app.mode, Mode::Confirm(ConfirmAction::Quit)));

        // Render to populate click regions
        let clicks = render_and_snapshot_clicks(&mut app, &mut terminal);

        // Should have at least the "y" and "n" footer buttons
        let y_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.contains("Key(Char('y'))"))
            .collect();
        let n_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.contains("Key(Char('n'))"))
            .collect();
        assert_eq!(y_regions.len(), 1, "should have one 'y' click region");
        assert_eq!(n_regions.len(), 1, "should have one 'n' click region");
    }

    #[test]
    fn synth_key_from_confirm_click_dismisses_dialog() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        app.dirty = true;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Open confirm dialog
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('q')));
        assert!(matches!(app.mode, Mode::Confirm(ConfirmAction::Quit)));

        // Render to populate click regions
        let snap = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &snap))
            .unwrap();

        // Find the "n" button rect
        let n_rect = app
            .click_regions
            .0
            .iter()
            .find(|(_, a)| matches!(a, ClickAction::Key(KeyCode::Char('n'))))
            .map(|(r, _)| *r)
            .expect("should find 'n' click region");

        // Simulate a click at the center of the "n" button
        let hit = app.click_regions.hit(n_rect.x + n_rect.width / 2, n_rect.y);
        assert!(
            matches!(hit, Some(ClickAction::Key(KeyCode::Char('n')))),
            "hit-testing 'n' button center should return Key('n')"
        );

        // Feeding the synth key 'n' through handle_key should dismiss the confirm
        let msg = app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()));
        assert!(matches!(msg, Some(Msg::ConfirmNo)));
        app.update_msg(msg.unwrap());
        assert!(
            matches!(app.mode, Mode::Normal),
            "mode should be Normal after 'n' dismisses confirm"
        );
    }

    #[test]
    fn form_overlay_populates_field_and_option_click_regions() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();

        // Open add-rule form
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('a')));
        assert!(matches!(app.mode, Mode::Form(_)));

        // Render to populate click regions
        let clicks = render_and_snapshot_clicks(&mut app, &mut terminal);

        // Should have FormField regions (at least for each visible field)
        let field_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.starts_with("FormField"))
            .collect();
        assert!(
            field_regions.len() >= 2,
            "form should have at least 2 field click regions, got {}",
            field_regions.len()
        );

        // The "Rule type" field (field index 0) is inline-select → should have
        // SelectOption regions for its 3 options
        let select_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.contains("SelectOption { field: 0"))
            .collect();
        assert_eq!(
            select_regions.len(),
            3,
            "inline select should have 3 option click regions, got {}",
            select_regions.len()
        );

        // Footer should have Enter, Tab, Esc buttons
        let enter_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.contains("Key(Enter)"))
            .collect();
        let esc_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.contains("Key(Esc)"))
            .collect();
        assert_eq!(enter_regions.len(), 1, "should have Enter footer button");
        assert_eq!(esc_regions.len(), 1, "should have Esc footer button");
    }

    #[test]
    fn help_overlay_populates_no_clickable_buttons() {
        // Help footer is ["j/k scroll", "any key close"] — neither is parseable
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Open help
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('?')));
        assert!(matches!(app.mode, Mode::Help(_)));

        let clicks = render_and_snapshot_clicks(&mut app, &mut terminal);

        // No parseable single-key hints in the help footer
        assert!(
            clicks.is_empty(),
            "help overlay should have 0 click regions since no hints are single-key parseable"
        );
    }

    // -- Walkthrough quit tests -----------------------------------------------

    #[test]
    fn walkthrough_q_opens_quit_confirm() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        app.start_walkthrough();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Initial render
        let snap = app.manifest.clone();
        terminal
            .draw(|frame| app.view(frame, frame.area(), &snap))
            .unwrap();

        assert!(matches!(app.mode, Mode::Walkthrough));

        // Press 'q' → should open QuitWalkthrough confirm
        press_and_render(&mut app, &mut terminal, key(KeyCode::Char('q')));
        assert!(matches!(
            app.mode,
            Mode::Confirm(ConfirmAction::QuitWalkthrough)
        ));
    }

    #[test]
    fn walkthrough_quit_confirm_yes_exits() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        app.start_walkthrough();

        // Simulate 'q' → opens confirm
        app.mode = Mode::Confirm(ConfirmAction::QuitWalkthrough);

        // 'y' → should trigger Abort action
        let msg = app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::empty()));
        assert!(matches!(msg, Some(Msg::ConfirmYes)));
        let action = app.update_msg(msg.unwrap());
        assert!(matches!(action, Action::Abort));
        assert!(app.walkthrough.is_none(), "walkthrough should be cleared");
    }

    #[test]
    fn walkthrough_quit_confirm_no_returns_to_walkthrough() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        app.start_walkthrough();

        // Simulate 'q' → opens confirm
        app.mode = Mode::Confirm(ConfirmAction::QuitWalkthrough);

        // 'n' → should return to walkthrough
        let msg = app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()));
        assert!(matches!(msg, Some(Msg::ConfirmNo)));
        app.update_msg(msg.unwrap());
        assert!(
            matches!(app.mode, Mode::Walkthrough),
            "should return to walkthrough after 'n'"
        );
        assert!(
            app.walkthrough.is_some(),
            "walkthrough state should be preserved"
        );
    }

    #[test]
    fn walkthrough_q_clickable_in_footer() {
        let manifest = empty_manifest();
        let mut app = App::new(PathBuf::from("/tmp/test.json"), manifest).unwrap();
        app.start_walkthrough();
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        // Render to populate click regions
        let clicks = render_and_snapshot_clicks(&mut app, &mut terminal);

        // Should have a 'q' click region from the left footer
        let q_regions: Vec<_> = clicks
            .iter()
            .filter(|(_, desc)| desc.contains("Key(Char('q'))"))
            .collect();
        assert_eq!(
            q_regions.len(),
            1,
            "walkthrough overlay should have a 'q' click region"
        );
    }
}
