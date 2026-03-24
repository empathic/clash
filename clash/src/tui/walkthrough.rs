//! Guided walkthrough for first-time onboarding.
//!
//! A lightweight state machine that renders coach-mark overlays inside the
//! policy editor TUI, guiding the user through adding a "git" rule, testing
//! it, and saving.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::widgets::centered_rect;

/// Sequential steps of the onboarding walkthrough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkthroughStep {
    /// Introduction — explain what the editor is.
    Welcome,
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
            Self::Welcome => Self::AddRule,
            Self::AddRule => Self::FillForm,
            Self::FillForm => Self::TestIt,
            Self::TestIt => Self::TypeTest,
            Self::TypeTest => Self::SaveFinish,
            Self::SaveFinish => Self::Done,
            Self::Done => Self::Done,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalkthroughState {
    pub step: WalkthroughStep,
}

impl WalkthroughState {
    pub fn new() -> Self {
        Self {
            step: WalkthroughStep::Welcome,
        }
    }

    pub fn advance(&mut self) {
        self.step = self.step.next();
    }
}

/// Render the walkthrough coach-mark overlay for the current step.
///
/// Only renders for steps that show an overlay (not FillForm — that's
/// handled by the form itself, and not Done).
pub fn render_walkthrough_overlay(frame: &mut Frame, area: Rect, step: WalkthroughStep) {
    let lines = match step {
        WalkthroughStep::Welcome => vec![
            styled_title("Welcome to the Policy Editor"),
            Line::from(""),
            Line::from("Your policy controls what Claude can do."),
            Line::from("It starts with a sensible default: ask for"),
            Line::from("anything not explicitly allowed."),
            Line::from(""),
            Line::from("Let's add your first rule — allowing git."),
            Line::from(""),
            dim_hint("Press any key to continue  •  Esc to skip"),
        ],
        WalkthroughStep::AddRule => vec![
            styled_title("Step 1: Add a Rule"),
            Line::from(""),
            Line::from("Rules define what commands are allowed,"),
            Line::from("denied, or require confirmation."),
            Line::from(""),
            key_hint("a", "add a new rule"),
            Line::from(""),
            dim_hint("Esc to skip walkthrough"),
        ],
        WalkthroughStep::FillForm => {
            // Overlay not rendered — form is visible with its own hints.
            return;
        }
        WalkthroughStep::TestIt => vec![
            styled_title("Step 2: Test Your Rule"),
            Line::from(""),
            Line::from("The test console lets you check how your"),
            Line::from("policy handles different commands."),
            Line::from(""),
            key_hint("t", "open the test console"),
            Line::from(""),
            dim_hint("Esc to skip walkthrough"),
        ],
        WalkthroughStep::TypeTest => {
            // Test panel is focused — don't overlay, just let status bar guide.
            return;
        }
        WalkthroughStep::SaveFinish => vec![
            styled_title("Step 3: Save"),
            Line::from(""),
            Line::from("Your rule is ready. Save your policy to"),
            Line::from("start using it in Claude Code."),
            Line::from(""),
            key_hint("s", "save your policy"),
            Line::from(""),
            dim_hint("Come back anytime with: clash policy edit"),
        ],
        WalkthroughStep::Done => return,
    };

    let popup = centered_rect(50, 45, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Walkthrough ");

    let para = Paragraph::new(lines)
        .block(block)
        .alignment(Alignment::Center);
    frame.render_widget(para, popup);
}

/// Status bar hints for each walkthrough step.
pub fn walkthrough_status_hints(step: WalkthroughStep) -> Vec<(&'static str, &'static str)> {
    match step {
        WalkthroughStep::Welcome => vec![("any key", "continue"), ("Esc", "skip walkthrough")],
        WalkthroughStep::AddRule => vec![("a", "add rule"), ("Esc", "skip walkthrough")],
        WalkthroughStep::FillForm => vec![
            ("Tab", "next field"),
            ("←/→", "cycle options"),
            ("Enter", "submit"),
            ("Esc", "skip walkthrough"),
        ],
        WalkthroughStep::TestIt => vec![("t", "test console"), ("Esc", "skip walkthrough")],
        WalkthroughStep::TypeTest => vec![
            ("type", "bash git status"),
            ("Enter", "run test"),
            ("Esc", "skip walkthrough"),
        ],
        WalkthroughStep::SaveFinish => vec![("s", "save"), ("Esc", "skip walkthrough")],
        WalkthroughStep::Done => vec![],
    }
}

fn styled_title(text: &str) -> Line<'_> {
    Line::from(Span::styled(
        text,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

fn key_hint<'a>(key: &'a str, description: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::raw("Press "),
        Span::styled(
            key,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" to {description}")),
    ])
}

fn dim_hint(text: &str) -> Line<'_> {
    Line::from(Span::styled(text, Style::default().fg(Color::DarkGray)))
}
