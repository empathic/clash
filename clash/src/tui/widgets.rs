//! Shared ratatui widgets: tab bar, status bar, overlays.

use crossterm::event::KeyCode;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use super::app::Tab;
use super::theme::Theme;

// ---------------------------------------------------------------------------
// Click regions — mouse click targets populated each frame during render
// ---------------------------------------------------------------------------

/// An action that a mouse click can trigger.
#[derive(Debug)]
pub enum ClickAction {
    /// Simulate pressing a key (for footer buttons).
    Key(KeyCode),
    /// Activate a form field by its visible-index.
    FormField(usize),
    /// Select an inline-select option directly.
    SelectOption { field: usize, option: usize },
    /// Toggle a multiselect checkbox.
    ToggleMultiSelect { field: usize, option: usize },
}

/// Clickable regions for the current frame.
#[derive(Default)]
pub struct ClickRegions(pub(crate) Vec<(Rect, ClickAction)>);

impl ClickRegions {
    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn push(&mut self, area: Rect, action: ClickAction) {
        self.0.push((area, action));
    }

    /// Return the action for the *most specific* (last-added) region containing (col, row).
    /// More-specific regions (inline options) are pushed after less-specific ones (field rows),
    /// so searching in reverse gives correct precedence.
    pub fn hit(&self, col: u16, row: u16) -> Option<&ClickAction> {
        self.0
            .iter()
            .rev()
            .find(|(r, _)| r.contains(Position { x: col, y: row }))
            .map(|(_, a)| a)
    }
}

/// Try to parse a footer key-hint string into a single `KeyCode`.
/// Returns `None` for multi-key combos like `"j/k"`, `"←/→"`, `"any key"`, `"try"`.
fn parse_hint_key(s: &str) -> Option<KeyCode> {
    match s {
        "Enter" => Some(KeyCode::Enter),
        "Esc" => Some(KeyCode::Esc),
        "Tab" => Some(KeyCode::Tab),
        _ => {
            let chars: Vec<char> = s.chars().collect();
            if chars.len() == 1 {
                Some(KeyCode::Char(chars[0]))
            } else {
                None
            }
        }
    }
}

/// Render the tab bar at the top of the screen.
pub fn render_tab_bar(frame: &mut Frame, area: Rect, active_tab: &Tab, dirty: bool, t: &Theme) {
    let tabs = [
        (Tab::Tree, "Tree"),
        (Tab::Sandboxes, "Sandboxes"),
        (Tab::Includes, "Includes"),
        (Tab::Settings, "Settings"),
    ];

    let mut spans = Vec::new();
    spans.push(Span::raw("  "));
    for (i, (tab, label)) in tabs.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", t.tab_separator));
        }
        if tab == active_tab {
            spans.push(Span::styled(format!(" {label} "), t.tab_active));
        } else {
            spans.push(Span::styled(format!(" {label} "), t.tab_inactive));
        }
    }

    let dirty_indicator = if dirty { " [modified]" } else { "" };
    spans.push(Span::styled(
        format!("    ? help{dirty_indicator}"),
        t.text_disabled,
    ));

    let bar = Paragraph::new(Line::from(spans)).style(t.bar_bg);
    frame.render_widget(bar, area);
}

/// Render the status/hint bar at the bottom.
pub fn render_status_bar(
    frame: &mut Frame,
    area: Rect,
    hints: &[(&str, &str)],
    flash: Option<&str>,
    t: &Theme,
) {
    let line = if let Some(msg) = flash {
        Line::from(Span::styled(format!("  {msg}"), t.flash_message))
    } else {
        let spans: Vec<Span> = hints
            .iter()
            .enumerate()
            .flat_map(|(i, (key, desc))| {
                let mut s = Vec::new();
                if i > 0 {
                    s.push(Span::styled("  ", t.text_disabled));
                }
                s.push(Span::styled(key.to_string(), t.hint_key));
                s.push(Span::styled(format!(" {desc}"), t.hint_desc));
                s
            })
            .collect();
        Line::from(spans)
    };

    let bar = Paragraph::new(line).style(t.bar_bg);
    frame.render_widget(bar, area);
}

/// Build the help content lines.  Used both for rendering and for deriving
/// the content length when constructing `ScrollState`.
pub fn help_content(t: &Theme) -> Vec<Line<'static>> {
    let key = t.hint_key;
    vec![
        Line::from(Span::styled("Keybindings", t.text_emphasis)),
        Line::from(""),
        Line::from(vec![
            Span::styled("1-5    ", key),
            Span::raw("Switch tabs"),
        ]),
        Line::from(vec![
            Span::styled("j/k    ", key),
            Span::raw("Move down/up"),
        ]),
        Line::from(vec![
            Span::styled("h/l    ", key),
            Span::raw("Collapse/expand (tree) or focus (sandboxes)"),
        ]),
        Line::from(vec![
            Span::styled("g/G    ", key),
            Span::raw("Jump to top/bottom"),
        ]),
        Line::from(vec![
            Span::styled("Space  ", key),
            Span::raw("Toggle expand/collapse"),
        ]),
        Line::from(vec![
            Span::styled("e/Tab  ", key),
            Span::raw("Cycle effect on selected rule"),
        ]),
        Line::from(vec![
            Span::styled("a      ", key),
            Span::raw("Add new item"),
        ]),
        Line::from(vec![
            Span::styled("d      ", key),
            Span::raw("Delete selected item"),
        ]),
        Line::from(vec![
            Span::styled("J/K    ", key),
            Span::raw("Move item up/down (includes)"),
        ]),
        Line::from(vec![
            Span::styled("t      ", key),
            Span::raw("Toggle test console panel"),
        ]),
        Line::from(vec![
            Span::styled("s      ", key),
            Span::raw("Save (review diff first)"),
        ]),
        Line::from(vec![
            Span::styled("q/Esc  ", key),
            Span::raw("Quit (confirms if unsaved)"),
        ]),
        Line::from(vec![
            Span::styled("?      ", key),
            Span::raw("Toggle this help"),
        ]),
    ]
}

/// Render a centered help popup listing all keybindings.
pub fn render_help_overlay(
    frame: &mut Frame,
    area: Rect,
    scroll: &mut ScrollState,
    t: &Theme,
) -> ModalInner {
    let help_lines = help_content(t);

    let modal = ModalOverlay {
        width_pct: 60,
        height: ModalHeight::Percent(70),
        border_style: t.border_focused,
        title: "Help",
        footer: &[("j/k", "scroll"), ("any key", "close")],
        footer_left: &[],
        footer_right: None,
        scroll: Some(scroll.to_modal_scroll()),
        theme: Some(t),
    };
    let inner = modal.render_chrome(frame, area);
    scroll.update_viewport(inner.area.height as usize);

    let visible: Vec<Line> = help_lines
        .into_iter()
        .skip(scroll.offset)
        .take(inner.area.height as usize)
        .collect();

    let para = Paragraph::new(visible).alignment(Alignment::Left);
    frame.render_widget(para, inner.area);
    inner
}

/// Render a confirmation dialog.
pub fn render_confirm_overlay(
    frame: &mut Frame,
    area: Rect,
    prompt: &str,
    t: &Theme,
) -> ModalInner {
    let modal = ModalOverlay {
        width_pct: 50,
        height: ModalHeight::Percent(20),
        border_style: t.modal_confirm_border,
        title: "Confirm",
        footer: &[("y", "yes"), ("n", "no")],
        footer_left: &[],
        footer_right: None,
        scroll: None,
        theme: Some(t),
    };
    let inner = modal.render_chrome(frame, area);

    let text = vec![Line::from(""), Line::from(Span::raw(prompt))];

    let para = Paragraph::new(text).alignment(Alignment::Center);
    frame.render_widget(para, inner.area);
    inner
}

/// Render a scrollable diff overlay for save review.
pub fn render_diff_overlay(
    frame: &mut Frame,
    area: Rect,
    diff_lines: &[DiffLine],
    scroll: &mut ScrollState,
    t: &Theme,
) -> ModalInner {
    let total = diff_lines.len();
    let viewport = scroll.viewport();
    let scroll_info = if total > viewport && viewport > 0 {
        Some(format!(
            "[{}-{}/{}]",
            scroll.offset + 1,
            (scroll.offset + viewport).min(total),
            total
        ))
    } else {
        None
    };

    let modal = ModalOverlay {
        width_pct: 80,
        height: ModalHeight::Percent(80),
        border_style: t.border_focused,
        title: "Save Review",
        footer: &[("y", "confirm"), ("n", "cancel"), ("j/k", "scroll")],
        footer_left: &[],
        footer_right: scroll_info,
        scroll: Some(scroll.to_modal_scroll()),
        theme: Some(t),
    };
    let inner = modal.render_chrome(frame, area);
    scroll.update_viewport(inner.area.height as usize);

    let visible_height = inner.area.height as usize;
    let visible_lines: Vec<Line> = diff_lines
        .iter()
        .skip(scroll.offset)
        .take(visible_height)
        .map(|dl| match dl {
            DiffLine::Context(s) => Line::from(Span::styled(s.as_str(), t.diff_context)),
            DiffLine::Add(s) => Line::from(Span::styled(s.as_str(), t.diff_add)),
            DiffLine::Remove(s) => Line::from(Span::styled(s.as_str(), t.diff_remove)),
            DiffLine::Header(s) => Line::from(Span::styled(s.as_str(), t.diff_header)),
        })
        .collect();

    let para = Paragraph::new(visible_lines);
    frame.render_widget(para, inner.area);
    inner
}

/// A line in a diff display.
pub enum DiffLine {
    Context(String),
    Add(String),
    Remove(String),
    Header(String),
}

// ---------------------------------------------------------------------------
// ModalOverlay — unified chrome for all popup modals
// ---------------------------------------------------------------------------

const MIN_INNER_WIDTH: u16 = 30;
const MIN_INNER_HEIGHT: u16 = 6;

/// How the modal's height is determined.
pub enum ModalHeight {
    /// Fixed percentage of the terminal height.
    Percent(u16),
    /// Fit to content with floor/ceiling bounds.
    FitContent {
        lines: u16,
        floor_pct: u16,
        ceil_pct: u16,
    },
}

/// Scroll state for a modal — enables the scrollbar when present.
pub struct ModalScroll {
    /// Current scroll offset (0-based line index at top of viewport).
    pub offset: usize,
    /// Total number of content lines.
    pub total: usize,
}

/// Configuration for a modal popup's chrome (border, title, footer).
pub struct ModalOverlay<'a> {
    pub width_pct: u16,
    pub height: ModalHeight,
    pub border_style: Style,
    pub title: &'a str,
    /// Key-hint pairs rendered right-aligned in the bottom border; empty = no footer.
    pub footer: &'a [(&'a str, &'a str)],
    /// Optional right-aligned footer text, e.g. scroll position "[3-10/20]".
    pub footer_right: Option<String>,
    /// Key-hint pairs rendered left-aligned in the bottom border.
    pub footer_left: &'a [(&'a str, &'a str)],
    /// When set, a vertical scrollbar is rendered on the right edge if content overflows.
    pub scroll: Option<ModalScroll>,
    /// Optional theme for styling footer hints and scrollbar.
    pub theme: Option<&'a Theme>,
}

/// The inner area returned by [`ModalOverlay::render_chrome`].
pub struct ModalInner {
    pub area: Rect,
    /// (rect, key_code) for each parseable footer button.
    pub footer_buttons: Vec<(Rect, KeyCode)>,
}

// ---------------------------------------------------------------------------
// ScrollState — single source of truth for scroll offset clamping
// ---------------------------------------------------------------------------

/// Owns a scroll offset, the total content length, and the last-known viewport
/// height.  All mutations go through [`scroll_down`] / [`scroll_up`] which
/// clamp to `content_len - viewport` so the offset never overshoots.
#[derive(Debug, Clone)]
pub struct ScrollState {
    pub offset: usize,
    content_len: usize,
    viewport: usize,
}

impl ScrollState {
    pub fn new(content_len: usize) -> Self {
        Self {
            offset: 0,
            content_len,
            viewport: 0,
        }
    }

    /// Maximum scroll offset given current content and viewport.
    pub fn max_offset(&self) -> usize {
        self.content_len.saturating_sub(self.viewport)
    }

    pub fn scroll_down(&mut self) {
        self.offset = (self.offset + 1).min(self.max_offset());
    }

    pub fn scroll_up(&mut self) {
        self.offset = self.offset.saturating_sub(1);
    }

    /// Called by render functions once the real viewport height is known.
    /// Re-clamps offset in case the terminal was resized.
    pub fn update_viewport(&mut self, viewport: usize) {
        self.viewport = viewport;
        self.offset = self.offset.min(self.max_offset());
    }

    pub fn content_len(&self) -> usize {
        self.content_len
    }

    pub fn viewport(&self) -> usize {
        self.viewport
    }

    /// Update content length (e.g. when walkthrough step changes) and re-clamp.
    pub fn set_content_len(&mut self, len: usize) {
        self.content_len = len;
        self.offset = self.offset.min(self.max_offset());
    }

    pub fn to_modal_scroll(&self) -> ModalScroll {
        ModalScroll {
            offset: self.offset,
            total: self.content_len,
        }
    }
}

impl ModalOverlay<'_> {
    /// Render the modal border, title, and footer, returning the inner content area.
    pub fn render_chrome(&self, frame: &mut Frame, area: Rect) -> ModalInner {
        // Compute effective height percentage
        let height_pct = match &self.height {
            ModalHeight::Percent(p) => *p,
            ModalHeight::FitContent {
                lines,
                floor_pct,
                ceil_pct,
            } => {
                // +2 for top/bottom border
                let needed = *lines + 2;
                let pct = ((needed as f32 / area.height as f32) * 100.0).ceil() as u16;
                pct.clamp(*floor_pct, *ceil_pct)
            }
        };

        let mut popup = centered_rect(self.width_pct, height_pct, area);

        // Enforce minimum inner dimensions by expanding + re-centering
        let inner_w = popup.width.saturating_sub(2); // -2 for left/right border
        let inner_h = popup.height.saturating_sub(2); // -2 for top/bottom border
        if inner_w < MIN_INNER_WIDTH || inner_h < MIN_INNER_HEIGHT {
            let needed_w = popup.width.max(MIN_INNER_WIDTH + 2);
            let needed_h = popup.height.max(MIN_INNER_HEIGHT + 2);
            // Clamp to terminal area
            let w = needed_w.min(area.width);
            let h = needed_h.min(area.height);
            let x = area.x + area.width.saturating_sub(w) / 2;
            let y = area.y + area.height.saturating_sub(h) / 2;
            popup = Rect::new(x, y, w, h);
        }

        frame.render_widget(Clear, popup);

        let mut footer_buttons: Vec<(Rect, KeyCode)> = Vec::new();

        // Build footer line from key-hint pairs
        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_style(self.border_style)
            .title(format!(" {} ", self.title));

        // Track button char offsets (from the start of the footer text) so we
        // can compute screen rects after we know the right-aligned x origin.
        // Each entry: (offset_in_footer, width, KeyCode).
        let mut button_offsets: Vec<(u16, u16, KeyCode)> = Vec::new();

        // Resolve theme-aware styles (fall back to hardcoded defaults when no theme is provided,
        // keeping the test suite working without requiring a Theme everywhere).
        let hint_key_style = self
            .theme
            .map(|t| t.hint_key)
            .unwrap_or_else(|| Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        let hint_desc_style = self
            .theme
            .map(|t| t.text_disabled)
            .unwrap_or_else(|| Style::default().fg(Color::DarkGray));

        if !self.footer.is_empty() || self.footer_right.is_some() {
            let mut spans: Vec<Span> = Vec::new();
            let mut char_offset: u16 = 0;

            spans.push(Span::raw(" "));
            char_offset += 1;

            for (i, (key, desc)) in self.footer.iter().enumerate() {
                if i > 0 {
                    spans.push(Span::styled("  ", hint_desc_style));
                    char_offset += 2;
                }
                let button_text = format!("{key} {desc}");
                let button_width = button_text.len() as u16;
                if let Some(kc) = parse_hint_key(key) {
                    button_offsets.push((char_offset, button_width, kc));
                }
                spans.push(Span::styled(*key, hint_key_style));
                char_offset += key.len() as u16;
                spans.push(Span::styled(format!(" {desc}"), hint_desc_style));
                char_offset += 1 + desc.len() as u16;
            }
            if let Some(ref right) = self.footer_right {
                let right_text = format!(" {right}");
                spans.push(Span::styled(right_text.clone(), hint_desc_style));
                char_offset += right_text.len() as u16;
            }
            spans.push(Span::raw(" "));
            char_offset += 1;

            // The footer is right-aligned: ratatui places it so the last char
            // sits just inside the right border.
            // footer_x = popup.x + popup.width - 1 (right border) - char_offset
            let total_footer_width = char_offset;
            let footer_x = popup
                .x
                .saturating_add(popup.width.saturating_sub(1 + total_footer_width));
            let footer_y = popup.y + popup.height.saturating_sub(1);

            // Convert button offsets to screen-space Rects
            for (off, w, kc) in &button_offsets {
                footer_buttons.push((Rect::new(footer_x + off, footer_y, *w, 1), *kc));
            }

            block = block.title_bottom(Line::from(spans).alignment(Alignment::Right));
        }

        // Left-aligned footer hints
        if !self.footer_left.is_empty() {
            let mut spans: Vec<Span> = Vec::new();
            let mut char_offset: u16 = 0;

            spans.push(Span::raw(" "));
            char_offset += 1;

            for (i, (key, desc)) in self.footer_left.iter().enumerate() {
                if i > 0 {
                    spans.push(Span::styled("  ", hint_desc_style));
                    char_offset += 2;
                }
                let button_text = format!("{key} {desc}");
                let button_width = button_text.len() as u16;
                if let Some(kc) = parse_hint_key(key) {
                    // Left-aligned: x starts at popup.x + 1 (inside left border)
                    let btn_x = popup.x + 1 + char_offset;
                    let btn_y = popup.y + popup.height.saturating_sub(1);
                    footer_buttons.push((Rect::new(btn_x, btn_y, button_width, 1), kc));
                }
                spans.push(Span::styled(*key, hint_key_style));
                char_offset += key.len() as u16;
                spans.push(Span::styled(format!(" {desc}"), hint_desc_style));
                char_offset += 1 + desc.len() as u16;
            }
            spans.push(Span::raw(" "));

            block = block.title_bottom(Line::from(spans).alignment(Alignment::Left));
        }

        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        // Render scrollbar if content overflows
        let content_area = if let Some(ref sc) = self.scroll {
            let viewport = inner.height as usize;
            if sc.total > viewport && inner.width > 1 {
                let thumb_style = self
                    .theme
                    .map(|t| t.scrollbar_thumb)
                    .unwrap_or(self.border_style);
                let track_style = self
                    .theme
                    .map(|t| t.scrollbar_track)
                    .unwrap_or_else(|| Style::default().fg(Color::DarkGray));
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .thumb_style(thumb_style)
                    .track_style(track_style)
                    .begin_symbol(None)
                    .end_symbol(None);
                // Ratatui positions the thumb at the bottom only when
                // position == content_length - 1. Our offset maxes out at
                // total - viewport, so we remap to the full 0..total-1 range.
                let max_offset = sc.total.saturating_sub(viewport);
                let sb_position = if max_offset == 0 {
                    0
                } else {
                    sc.offset * sc.total.saturating_sub(1) / max_offset
                };
                let mut sb_state = ScrollbarState::new(sc.total)
                    .position(sb_position)
                    .viewport_content_length(viewport);
                frame.render_stateful_widget(scrollbar, inner, &mut sb_state);
                // Shrink content area by 1 column on the right to avoid overlap
                Rect::new(inner.x, inner.y, inner.width - 1, inner.height)
            } else {
                inner
            }
        } else {
            inner
        };

        ModalInner {
            area: content_area,
            footer_buttons,
        }
    }
}

/// Compute a centered rect within `area`.
pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    // -- parse_hint_key -------------------------------------------------------

    #[test]
    fn parse_hint_key_single_char() {
        assert!(matches!(parse_hint_key("y"), Some(KeyCode::Char('y'))));
        assert!(matches!(parse_hint_key("n"), Some(KeyCode::Char('n'))));
        assert!(matches!(parse_hint_key("a"), Some(KeyCode::Char('a'))));
        assert!(matches!(parse_hint_key("s"), Some(KeyCode::Char('s'))));
        assert!(matches!(parse_hint_key("b"), Some(KeyCode::Char('b'))));
        assert!(matches!(parse_hint_key("t"), Some(KeyCode::Char('t'))));
        assert!(matches!(parse_hint_key("?"), Some(KeyCode::Char('?'))));
    }

    #[test]
    fn parse_hint_key_named_keys() {
        assert!(matches!(parse_hint_key("Enter"), Some(KeyCode::Enter)));
        assert!(matches!(parse_hint_key("Esc"), Some(KeyCode::Esc)));
        assert!(matches!(parse_hint_key("Tab"), Some(KeyCode::Tab)));
    }

    #[test]
    fn parse_hint_key_multi_key_returns_none() {
        assert!(parse_hint_key("j/k").is_none());
        assert!(parse_hint_key("←/→").is_none());
        assert!(parse_hint_key("any key").is_none());
        assert!(parse_hint_key("try").is_none());
        assert!(parse_hint_key("J/K").is_none());
    }

    // -- ClickRegions::hit ----------------------------------------------------

    #[test]
    fn hit_returns_none_when_empty() {
        let cr = ClickRegions::default();
        assert!(cr.hit(10, 10).is_none());
    }

    #[test]
    fn hit_returns_action_when_inside_region() {
        let mut cr = ClickRegions::default();
        cr.push(Rect::new(5, 5, 10, 1), ClickAction::Key(KeyCode::Char('y')));
        // Inside
        assert!(matches!(
            cr.hit(5, 5),
            Some(ClickAction::Key(KeyCode::Char('y')))
        ));
        assert!(matches!(
            cr.hit(14, 5),
            Some(ClickAction::Key(KeyCode::Char('y')))
        ));
        // Outside
        assert!(cr.hit(4, 5).is_none());
        assert!(cr.hit(15, 5).is_none());
        assert!(cr.hit(10, 4).is_none());
        assert!(cr.hit(10, 6).is_none());
    }

    #[test]
    fn hit_returns_most_specific_last_added_region() {
        let mut cr = ClickRegions::default();
        // Broad region first (field row)
        cr.push(Rect::new(0, 10, 80, 1), ClickAction::FormField(0));
        // Narrow region second (inline option)
        cr.push(
            Rect::new(20, 10, 8, 1),
            ClickAction::SelectOption {
                field: 0,
                option: 1,
            },
        );

        // Click inside the narrow region → gets the more-specific action
        assert!(matches!(
            cr.hit(22, 10),
            Some(ClickAction::SelectOption {
                field: 0,
                option: 1
            })
        ));
        // Click outside the narrow region but inside the broad one → gets FormField
        assert!(matches!(cr.hit(5, 10), Some(ClickAction::FormField(0))));
    }

    #[test]
    fn hit_clear_removes_all_regions() {
        let mut cr = ClickRegions::default();
        cr.push(Rect::new(0, 0, 80, 24), ClickAction::Key(KeyCode::Enter));
        assert!(cr.hit(10, 10).is_some());
        cr.clear();
        assert!(cr.hit(10, 10).is_none());
    }

    // -- Footer button rects via render_chrome --------------------------------

    #[test]
    fn render_chrome_produces_footer_buttons_for_parseable_hints() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                let area = frame.area();
                let modal = ModalOverlay {
                    width_pct: 50,
                    height: ModalHeight::Percent(20),
                    border_style: Style::default().fg(Color::Yellow),
                    title: "Test",
                    footer: &[("y", "yes"), ("n", "no")],
                    footer_left: &[],
                    footer_right: None,
                    scroll: None,
                    theme: None,
                };
                let inner = modal.render_chrome(frame, area);

                // Both "y" and "n" are parseable single-char keys
                assert_eq!(inner.footer_buttons.len(), 2);

                let (rect_y, kc_y) = &inner.footer_buttons[0];
                assert!(matches!(kc_y, KeyCode::Char('y')));

                let (rect_n, kc_n) = &inner.footer_buttons[1];
                assert!(matches!(kc_n, KeyCode::Char('n')));

                // Both rects should be on the same row (the bottom border)
                assert_eq!(rect_y.y, rect_n.y, "both buttons on same row");
                // The row should be within the terminal area
                assert!(rect_y.y < area.height, "button row within terminal");

                // Rects should have width matching "y yes" (5) and "n no" (4)
                assert_eq!(rect_y.width, 5, "y-button width = 'y yes'");
                assert_eq!(rect_n.width, 4, "n-button width = 'n no'");

                // n-button should start after y-button + 2-char separator
                assert_eq!(
                    rect_n.x,
                    rect_y.x + rect_y.width + 2,
                    "n-button follows y-button with separator gap"
                );
            })
            .unwrap();
    }

    #[test]
    fn render_chrome_skips_unparseable_footer_hints() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                let area = frame.area();
                let modal = ModalOverlay {
                    width_pct: 60,
                    height: ModalHeight::Percent(70),
                    border_style: Style::default().fg(Color::Cyan),
                    title: "Help",
                    footer: &[("j/k", "scroll"), ("any key", "close")],
                    footer_left: &[],
                    footer_right: None,
                    scroll: None,
                    theme: None,
                };
                let inner = modal.render_chrome(frame, area);

                // Neither "j/k" nor "any key" is parseable → no buttons
                assert_eq!(inner.footer_buttons.len(), 0);
            })
            .unwrap();
    }

    #[test]
    fn render_chrome_mixed_parseable_and_unparseable() {
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                let area = frame.area();
                let modal = ModalOverlay {
                    width_pct: 80,
                    height: ModalHeight::Percent(80),
                    border_style: Style::default().fg(Color::Cyan),
                    title: "Save Review",
                    footer: &[("y", "confirm"), ("n", "cancel"), ("j/k", "scroll")],
                    footer_left: &[],
                    footer_right: None,
                    scroll: None,
                    theme: None,
                };
                let inner = modal.render_chrome(frame, area);

                // Only "y" and "n" are parseable; "j/k" is not
                assert_eq!(inner.footer_buttons.len(), 2);
                assert!(matches!(inner.footer_buttons[0].1, KeyCode::Char('y')));
                assert!(matches!(inner.footer_buttons[1].1, KeyCode::Char('n')));
            })
            .unwrap();
    }

    #[test]
    fn footer_button_rects_are_hittable_by_click_regions() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| {
                let area = frame.area();
                let modal = ModalOverlay {
                    width_pct: 50,
                    height: ModalHeight::Percent(20),
                    border_style: Style::default().fg(Color::Yellow),
                    title: "Confirm",
                    footer: &[("y", "yes"), ("n", "no")],
                    footer_left: &[],
                    footer_right: None,
                    scroll: None,
                    theme: None,
                };
                let inner = modal.render_chrome(frame, area);

                // Feed the footer buttons into a ClickRegions
                let mut clicks = ClickRegions::default();
                for (rect, kc) in &inner.footer_buttons {
                    clicks.push(*rect, ClickAction::Key(*kc));
                }

                // The "y" button rect should be hittable at its midpoint
                let (ry, _) = &inner.footer_buttons[0];
                let hit = clicks.hit(ry.x + ry.width / 2, ry.y);
                assert!(
                    matches!(hit, Some(ClickAction::Key(KeyCode::Char('y')))),
                    "clicking center of y-button should yield Key('y')"
                );

                // The "n" button rect should be hittable
                let (rn, _) = &inner.footer_buttons[1];
                let hit = clicks.hit(rn.x + rn.width / 2, rn.y);
                assert!(
                    matches!(hit, Some(ClickAction::Key(KeyCode::Char('n')))),
                    "clicking center of n-button should yield Key('n')"
                );

                // Clicking outside both buttons on the same row → no hit
                let outside_x = if ry.x > 0 { ry.x - 1 } else { rn.x + rn.width };
                assert!(
                    clicks.hit(outside_x, ry.y).is_none(),
                    "clicking outside footer buttons should miss"
                );
            })
            .unwrap();
    }
}
