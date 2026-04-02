//! Semantic theme system for the TUI.
//!
//! Every style token describes *what it means*, not what it looks like.
//! Components never reference `Color::` directly — they use `Theme` fields.

use ratatui::style::{Color, Modifier, Style};

/// A complete visual theme for the TUI.
///
/// Field names are semantic — they describe purpose, not appearance.
#[derive(Debug, Clone)]
pub struct Theme {
    // -- Text hierarchy -------------------------------------------------------
    /// Primary text (default foreground).
    pub text_primary: Style,
    /// Disabled / placeholder text.
    pub text_disabled: Style,
    /// Emphasized text (bold headings, titles).
    pub text_emphasis: Style,

    // -- Semantic effects (Allow / Deny / Ask) --------------------------------
    pub effect_allow: Style,
    pub effect_deny: Style,
    pub effect_ask: Style,

    // -- Interactive elements -------------------------------------------------
    /// Selected / highlighted row.
    pub selection: Style,
    /// Keybind hints in status/footer bars.
    pub hint_key: Style,
    /// Description text next to keybind hints.
    pub hint_desc: Style,
    /// Text cursor (e.g. in text fields).
    pub cursor: Style,

    // -- Borders & chrome -----------------------------------------------------
    /// Focused panel / modal border.
    pub border_focused: Style,
    /// Unfocused / inactive border.
    pub border_unfocused: Style,
    /// Active / focused panel border (e.g. test panel, sandbox panes).
    pub border_active: Style,

    // -- Tab bar --------------------------------------------------------------
    pub tab_active: Style,
    pub tab_inactive: Style,
    pub tab_separator: Style,
    /// Background for the tab bar and status bar.
    pub bar_bg: Style,

    // -- Status bar -----------------------------------------------------------
    pub flash_message: Style,

    // -- Diff view ------------------------------------------------------------
    pub diff_add: Style,
    pub diff_remove: Style,
    pub diff_context: Style,
    pub diff_header: Style,

    // -- Modal overlays -------------------------------------------------------
    pub modal_confirm_border: Style,

    // -- Walkthrough ----------------------------------------------------------
    pub walkthrough_title: Style,

    // -- Form fields ----------------------------------------------------------
    pub field_label_active: Style,
    pub field_label_inactive: Style,
    pub field_value_active: Style,
    pub field_value_inactive: Style,
    pub field_value_placeholder: Style,
    /// Currently selected inline-select option.
    pub field_option_selected: Style,
    /// Unselected inline-select option.
    pub field_option_unselected: Style,
    /// Select arrows when active.
    pub field_arrows_active: Style,
    /// Select arrows when inactive.
    pub field_arrows_inactive: Style,
    /// Multiselect cursor (highlighted checkbox).
    pub field_multi_cursor: Style,
    /// Multiselect checked item.
    pub field_multi_checked: Style,
    /// Multiselect unchecked item.
    pub field_multi_unchecked: Style,

    // -- Test panel -----------------------------------------------------------
    pub test_input_active: Style,
    pub test_input_inactive: Style,
    pub test_error: Style,
    pub test_changed_badge: Style,

    // -- Scrollbar ------------------------------------------------------------
    pub scrollbar_thumb: Style,
    pub scrollbar_track: Style,

    // -- Miscellaneous --------------------------------------------------------
    /// Provenance / source annotations (e.g. "(rules.star)").
    pub provenance: Style,
    /// Section headers within views (e.g. "Rules:").
    pub section_header: Style,
    /// Label-value pairs in detail views (label portion).
    pub detail_label: Style,
    /// Label-value pairs in detail views (value portion).
    pub detail_value: Style,
}

impl Theme {
    /// The default dark theme — matches the original hardcoded palette.
    pub fn default_dark() -> Self {
        Theme {
            // Text hierarchy
            text_primary: Style::default().fg(Color::White),
            text_disabled: Style::default().fg(Color::DarkGray),
            text_emphasis: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),

            // Effects
            effect_allow: Style::default().fg(Color::Green),
            effect_deny: Style::default().fg(Color::Red),
            effect_ask: Style::default().fg(Color::Yellow),

            // Interactive
            selection: Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            hint_key: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            hint_desc: Style::default().fg(Color::Gray),
            cursor: Style::default().fg(Color::Black).bg(Color::White),

            // Borders
            border_focused: Style::default().fg(Color::Cyan),
            border_unfocused: Style::default().fg(Color::DarkGray),
            border_active: Style::default().fg(Color::Blue),

            // Tab bar
            tab_active: Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
            tab_inactive: Style::default().fg(Color::Gray),
            tab_separator: Style::default().fg(Color::DarkGray),
            bar_bg: Style::default().bg(Color::Black),

            // Status bar
            flash_message: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),

            // Diff
            diff_add: Style::default().fg(Color::Green),
            diff_remove: Style::default().fg(Color::Red),
            diff_context: Style::default().fg(Color::Gray),
            diff_header: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),

            // Modals
            modal_confirm_border: Style::default().fg(Color::Yellow),

            // Walkthrough
            walkthrough_title: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),

            // Form fields
            field_label_active: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            field_label_inactive: Style::default().fg(Color::Gray),
            field_value_active: Style::default().fg(Color::White),
            field_value_inactive: Style::default().fg(Color::Cyan),
            field_value_placeholder: Style::default().fg(Color::DarkGray),
            field_option_selected: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
            field_option_unselected: Style::default().fg(Color::DarkGray),
            field_arrows_active: Style::default().fg(Color::Yellow),
            field_arrows_inactive: Style::default().fg(Color::DarkGray),
            field_multi_cursor: Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
            field_multi_checked: Style::default().fg(Color::Green),
            field_multi_unchecked: Style::default().fg(Color::DarkGray),

            // Test panel
            test_input_active: Style::default().fg(Color::Cyan),
            test_input_inactive: Style::default().fg(Color::DarkGray),
            test_error: Style::default().fg(Color::Red),
            test_changed_badge: Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),

            // Scrollbar
            scrollbar_thumb: Style::default().fg(Color::Cyan),
            scrollbar_track: Style::default().fg(Color::DarkGray),

            // Misc
            provenance: Style::default().fg(Color::DarkGray),
            detail_label: Style::default().fg(Color::DarkGray),
            detail_value: Style::default().fg(Color::Cyan),
            section_header: Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        }
    }

    /// An adaptive theme that uses terminal ANSI colors, inheriting the user's
    /// palette. Works well on solarized, dracula, gruvbox, etc.
    pub fn adaptive() -> Self {
        // Start from default_dark and override colors that conflict with
        // common terminal palettes. The key insight: avoid Color::DarkGray
        // for important elements (it maps to "bright black" which is invisible
        // on many dark backgrounds) and avoid Color::Black for backgrounds
        // (it clashes with light terminal themes).
        Theme {
            // Text — use Reset to inherit terminal fg
            text_primary: Style::default(),
            text_disabled: Style::default().add_modifier(Modifier::DIM),
            text_emphasis: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),

            // Effects — ANSI colors adapt to the palette
            effect_allow: Style::default().fg(Color::Green),
            effect_deny: Style::default().fg(Color::Red),
            effect_ask: Style::default().fg(Color::Yellow),

            // Interactive
            selection: Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
            hint_key: Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            hint_desc: Style::default().add_modifier(Modifier::DIM),
            cursor: Style::default().fg(Color::Black).bg(Color::White),

            // Borders — use DIM instead of DarkGray for unfocused
            border_focused: Style::default().fg(Color::Cyan),
            border_unfocused: Style::default().add_modifier(Modifier::DIM),
            border_active: Style::default().fg(Color::Blue),

            // Tab bar — no explicit bg, inherit terminal
            tab_active: Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
            tab_inactive: Style::default().add_modifier(Modifier::DIM),
            tab_separator: Style::default().add_modifier(Modifier::DIM),
            bar_bg: Style::default(),

            // Status
            flash_message: Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),

            // Diff
            diff_add: Style::default().fg(Color::Green),
            diff_remove: Style::default().fg(Color::Red),
            diff_context: Style::default().add_modifier(Modifier::DIM),
            diff_header: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),

            // Modals
            modal_confirm_border: Style::default().fg(Color::Yellow),

            // Walkthrough
            walkthrough_title: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),

            // Form fields
            field_label_active: Style::default().add_modifier(Modifier::BOLD),
            field_label_inactive: Style::default().add_modifier(Modifier::DIM),
            field_value_active: Style::default(),
            field_value_inactive: Style::default().fg(Color::Cyan),
            field_value_placeholder: Style::default().add_modifier(Modifier::DIM),
            field_option_selected: Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
            field_option_unselected: Style::default().add_modifier(Modifier::DIM),
            field_arrows_active: Style::default().fg(Color::Yellow),
            field_arrows_inactive: Style::default().add_modifier(Modifier::DIM),
            field_multi_cursor: Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
            field_multi_checked: Style::default().fg(Color::Green),
            field_multi_unchecked: Style::default().add_modifier(Modifier::DIM),

            // Test panel
            test_input_active: Style::default().fg(Color::Cyan),
            test_input_inactive: Style::default().add_modifier(Modifier::DIM),
            test_error: Style::default().fg(Color::Red),
            test_changed_badge: Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),

            // Scrollbar
            scrollbar_thumb: Style::default().fg(Color::Cyan),
            scrollbar_track: Style::default().add_modifier(Modifier::DIM),

            // Misc
            provenance: Style::default().add_modifier(Modifier::DIM),
            detail_label: Style::default().add_modifier(Modifier::DIM),
            detail_value: Style::default().fg(Color::Cyan),
            section_header: Style::default().add_modifier(Modifier::BOLD),
        }
    }

    /// Select a theme from the `CLASH_THEME` environment variable.
    ///
    /// Supported values: `dark`, `adaptive`. Defaults to `adaptive`.
    pub fn from_env() -> Self {
        match std::env::var("CLASH_THEME").as_deref() {
            Ok("dark") => Self::default_dark(),
            _ => Self::adaptive(),
        }
    }

    // -- Convenience helpers for compound styles ------------------------------

    /// Style for a decision effect (Allow/Deny/Ask/None).
    pub fn effect(&self, decision: Option<&crate::policy::match_tree::Decision>) -> Style {
        match decision {
            Some(crate::policy::match_tree::Decision::Allow(_)) => self.effect_allow,
            Some(crate::policy::match_tree::Decision::Deny) => self.effect_deny,
            Some(crate::policy::match_tree::Decision::Ask(_)) => self.effect_ask,
            None => self.text_primary,
        }
    }

    /// Style for a policy effect (Allow/Deny/Ask).
    pub fn policy_effect(&self, effect: crate::policy::Effect) -> Style {
        match effect {
            crate::policy::Effect::Allow => self.effect_allow,
            crate::policy::Effect::Deny => self.effect_deny,
            crate::policy::Effect::Ask => self.effect_ask,
        }
    }

    /// Style for a sandbox rule effect (Allow/Deny).
    pub fn sandbox_effect(&self, effect: crate::policy::sandbox_types::RuleEffect) -> Style {
        match effect {
            crate::policy::sandbox_types::RuleEffect::Allow => self.effect_allow,
            crate::policy::sandbox_types::RuleEffect::Deny => self.effect_deny,
        }
    }

    /// Effect style for read-only / included items (dimmed decision color).
    pub fn effect_read_only(
        &self,
        decision: Option<&crate::policy::match_tree::Decision>,
    ) -> Style {
        self.effect(decision).add_modifier(Modifier::DIM)
    }
}

/// Read-only rendering context passed to every [`Component::view`].
pub struct ViewContext<'a> {
    pub manifest: &'a crate::policy::match_tree::PolicyManifest,
    pub theme: &'a Theme,
}
