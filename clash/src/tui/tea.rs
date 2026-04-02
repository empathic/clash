//! The Elm Architecture (TEA) trait for TUI components.
//!
//! Every tab/component implements [`Component`], enabling testable state
//! transitions and composable rendering.

use crossterm::event::KeyEvent;
use ratatui::Frame;
use ratatui::layout::Rect;

use super::theme::ViewContext;
use crate::policy::match_tree::PolicyManifest;

/// An action returned from [`Component::update`] to signal the parent.
pub enum Action {
    /// No action needed.
    None,
    /// The component wants to quit.
    Quit,
    /// The user aborted the onboarding walkthrough — caller should skip
    /// remaining setup steps.
    Abort,
    /// The manifest was modified — mark dirty.
    Modified,
    /// Request a dialoguer form (exits raw mode).
    RunForm(FormRequest),
    /// Show a flash message in the status bar.
    Flash(String),
}

/// Requests for inline form overlays.
pub enum FormRequest {
    /// Add a new tree rule (tool or exec).
    AddRule,
    /// Add a new sandbox definition.
    AddSandbox,
    /// Add a rule to an existing sandbox.
    AddSandboxRule { sandbox_name: String },
    /// Add an include entry.
    AddInclude,
    /// Edit an existing condition node's observable and pattern.
    EditCondition { path: Vec<usize> },
    /// Edit an existing decision node's effect and sandbox.
    EditDecision { path: Vec<usize> },
    /// Edit an inline leaf rule (condition + decision together).
    EditRule { path: Vec<usize> },
    /// Add a child node under an existing condition.
    AddChild { parent_path: Vec<usize> },
    /// Edit an existing sandbox's properties (caps, network).
    EditSandbox { sandbox_name: String },
    /// Edit an existing sandbox rule.
    EditSandboxRule {
        sandbox_name: String,
        rule_index: usize,
    },
}

/// The Elm Architecture trait. Each tab/component implements this.
pub trait Component {
    /// The message type this component handles.
    type Msg;

    /// Map a crossterm KeyEvent to a message (or None to ignore).
    fn handle_key(&self, key: KeyEvent) -> Option<Self::Msg>;

    /// Pure state transition: apply a message, return an Action for the parent.
    fn update(&mut self, msg: Self::Msg, manifest: &mut PolicyManifest) -> Action;

    /// Render the component into a ratatui Frame area.
    fn view(&self, frame: &mut Frame, area: Rect, ctx: &ViewContext);
}
