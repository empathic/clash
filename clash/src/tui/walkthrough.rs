//! Guided walkthrough for first-time onboarding.
//!
//! A lightweight state machine that renders coach-mark overlays inside the
//! policy editor TUI, guiding the user through base tools, adding a "git"
//! rule, testing it, and saving.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::Theme;
use super::widgets::{ClickAction, ClickRegions, ModalHeight, ModalOverlay, ScrollState};

/// Sequential steps of the onboarding walkthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkthroughStep {
    /// Introduction — explain what the editor is.
    Welcome,
    /// Explain pre-configured base tool rules (Read, Write, Edit, Glob, Grep).
    BaseTools,
    /// Prompt the user to press `a` to add a rule.
    AddRule,
    /// Form is open and pre-filled — user reviews and submits.
    FillForm,
    /// Prompt the user to press `t` to open the test console.
    TestIt,
    /// Prompt the user to type a test command and press Enter.
    TypeTest,
    /// Prompt the user to press `s` to save.
    SaveFinish,
    /// Walkthrough complete.
    Done,
}

impl WalkthroughStep {
    pub fn next(self) -> Self {
        match self {
            Self::Welcome => Self::BaseTools,
            Self::BaseTools => Self::AddRule,
            Self::AddRule => Self::FillForm,
            Self::FillForm => Self::TestIt,
            Self::TestIt => Self::TypeTest,
            Self::TypeTest => Self::SaveFinish,
            Self::SaveFinish => Self::Done,
            Self::Done => Self::Done,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Self::Welcome => Self::Welcome,
            Self::BaseTools => Self::Welcome,
            Self::AddRule => Self::BaseTools,
            Self::FillForm => Self::AddRule,
            Self::TestIt => Self::FillForm,
            Self::TypeTest => Self::TestIt,
            Self::SaveFinish => Self::TypeTest,
            Self::Done => Self::SaveFinish,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalkthroughState {
    pub step: WalkthroughStep,
    pub scroll: ScrollState,
}

impl Default for WalkthroughState {
    fn default() -> Self {
        Self {
            step: WalkthroughStep::Welcome,
            scroll: ScrollState::new(0),
        }
    }
}

impl WalkthroughState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn advance(&mut self) {
        self.step = self.step.next();
        self.scroll = ScrollState::new(0);
    }

    pub fn go_back(&mut self) {
        self.step = self.step.prev();
        self.scroll = ScrollState::new(0);
    }
}

type HintSlice = &'static [(&'static str, &'static str)];

/// Render the walkthrough coach-mark overlay for the current step.
///
/// Only renders for steps that show an overlay (not FillForm — that's
/// handled by the form itself, and not Done).
pub fn render_walkthrough_overlay(
    frame: &mut Frame,
    area: Rect,
    step: WalkthroughStep,
    scroll: &mut ScrollState,
    clicks: &mut ClickRegions,
    t: &Theme,
) {
    let (content, footer, footer_left): (Vec<Line>, HintSlice, HintSlice) = match step {
        WalkthroughStep::Welcome => (
            vec![
                styled_title("Welcome to the Policy Editor", t),
                Line::from(""),
                Line::from("Your policy controls what Claude can do."),
                Line::from("It starts with a sensible default: ask for"),
                Line::from("anything not explicitly allowed."),
                Line::from(""),
                Line::from("Let's walk through your starter policy."),
            ],
            &[("Esc", "skip"), ("Enter", "continue")],
            &[("q", "quit")],
        ),
        WalkthroughStep::BaseTools => (
            vec![
                styled_title("Base Tools — Pre-configured", t),
                Line::from(""),
                Line::from("Your policy already allows the tools Claude"),
                Line::from("uses most: Read, Write, Edit, Glob, and Grep."),
                Line::from(""),
                Line::from("These run inside a sandbox that limits file"),
                Line::from("access to your project and temp directories."),
                Line::from(""),
                Line::from("Shell commands are more nuanced. Take git:"),
                Line::from("status and log are read-only, commit writes"),
                Line::from("locally, but push needs network access."),
                Line::from(""),
                Line::from("For now we'll allow all of git. Over time you"),
                Line::from("can add sandboxes for finer-grained control."),
            ],
            &[("Esc", "skip"), ("b", "back"), ("Enter", "continue")],
            &[("q", "quit")],
        ),
        WalkthroughStep::AddRule => (
            vec![
                styled_title("Step 1: Allow git", t),
                Line::from(""),
                Line::from("Let's add a rule that allows all git commands."),
                Line::from("You can refine this later — e.g. deny push"),
                Line::from("--force or sandbox network-dependent ops."),
                Line::from(""),
                key_hint("a", "add a new rule", t),
            ],
            &[("Esc", "skip"), ("b", "back"), ("a", "add rule")],
            &[("q", "quit")],
        ),
        WalkthroughStep::FillForm => {
            // Overlay not rendered — form is visible with its own hints.
            return;
        }
        WalkthroughStep::TestIt => (
            vec![
                styled_title("Step 2: Test Your Rule", t),
                Line::from(""),
                Line::from("The test console lets you check how your"),
                Line::from("policy handles different commands."),
                Line::from(""),
                Line::from("Type a tool name followed by its arguments:"),
                dim_hint("  bash git status", t),
                dim_hint("  Read /etc/hosts", t),
                Line::from(""),
                key_hint("t", "open the test console", t),
            ],
            &[("Esc", "skip"), ("b", "back"), ("t", "test console")],
            &[("q", "quit")],
        ),
        WalkthroughStep::TypeTest => {
            // Test panel is focused — don't overlay, just let status bar guide.
            return;
        }
        WalkthroughStep::SaveFinish => (
            vec![
                styled_title("Step 3: Save", t),
                Line::from(""),
                Line::from("Your rule is ready. Save your policy to"),
                Line::from("start using it in Claude Code."),
                Line::from(""),
                key_hint("s", "save your policy", t),
                Line::from(""),
                dim_hint("Come back anytime with: clash policy edit", t),
            ],
            &[("Esc", "skip"), ("b", "back"), ("s", "save")],
            &[("q", "quit")],
        ),
        WalkthroughStep::Done => return,
    };

    // Derive content length from the actual content — no hand-counted constants.
    scroll.set_content_len(content.len());

    let modal = ModalOverlay {
        width_pct: 50,
        height: ModalHeight::Percent(45),
        border_style: t.border_focused,
        title: "Walkthrough",
        footer,
        footer_left,
        footer_right: None,
        scroll: Some(scroll.to_modal_scroll()),
        theme: Some(t),
    };
    let inner = modal.render_chrome(frame, area);
    for (rect, kc) in &inner.footer_buttons {
        clicks.push(*rect, ClickAction::Key(*kc));
    }
    scroll.update_viewport(inner.area.height as usize);

    let visible: Vec<Line> = content
        .into_iter()
        .skip(scroll.offset)
        .take(inner.area.height as usize)
        .collect();

    let para = Paragraph::new(visible).alignment(Alignment::Center);
    frame.render_widget(para, inner.area);
}

/// Status bar hints for each walkthrough step.
pub fn walkthrough_status_hints(step: WalkthroughStep) -> Vec<(&'static str, &'static str)> {
    match step {
        WalkthroughStep::Welcome => vec![
            ("q", "quit"),
            ("Esc", "skip walkthrough"),
            ("Enter", "continue"),
        ],
        WalkthroughStep::BaseTools => {
            vec![
                ("q", "quit"),
                ("Esc", "skip walkthrough"),
                ("b", "back"),
                ("Enter", "continue"),
            ]
        }
        WalkthroughStep::AddRule => {
            vec![
                ("q", "quit"),
                ("Esc", "skip walkthrough"),
                ("b", "back"),
                ("a", "add rule"),
            ]
        }
        WalkthroughStep::FillForm => vec![
            ("Tab", "next field"),
            ("←/→", "cycle options"),
            ("Enter", "submit"),
            ("Esc", "skip walkthrough"),
        ],
        WalkthroughStep::TestIt => {
            vec![
                ("q", "quit"),
                ("Esc", "skip walkthrough"),
                ("b", "back"),
                ("t", "test console"),
            ]
        }
        WalkthroughStep::TypeTest => vec![
            ("try", "bash git status"),
            ("Enter", "run test"),
            ("Esc", "skip walkthrough"),
        ],
        WalkthroughStep::SaveFinish => {
            vec![
                ("q", "quit"),
                ("Esc", "skip walkthrough"),
                ("b", "back"),
                ("s", "save"),
            ]
        }
        WalkthroughStep::Done => vec![],
    }
}

fn styled_title<'a>(text: &'a str, t: &Theme) -> Line<'a> {
    Line::from(Span::styled(text, t.walkthrough_title))
}

fn key_hint<'a>(key: &'a str, description: &'a str, t: &Theme) -> Line<'a> {
    Line::from(vec![
        Span::raw("Press "),
        Span::styled(key, t.hint_key),
        Span::raw(format!(" to {description}")),
    ])
}

fn dim_hint<'a>(text: &'a str, t: &Theme) -> Line<'a> {
    Line::from(Span::styled(text, t.text_disabled))
}
