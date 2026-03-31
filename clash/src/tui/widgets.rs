//! Shared ratatui widgets: tab bar, status bar, overlays.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};

use super::app::Tab;

/// Render the tab bar at the top of the screen.
pub fn render_tab_bar(frame: &mut Frame, area: Rect, active_tab: &Tab, dirty: bool) {
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
            spans.push(Span::styled("  ", Style::default().fg(Color::DarkGray)));
        }
        if tab == active_tab {
            spans.push(Span::styled(
                format!(" {label} "),
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {label} "),
                Style::default().fg(Color::Gray),
            ));
        }
    }

    let dirty_indicator = if dirty { " [modified]" } else { "" };
    spans.push(Span::styled(
        format!("    ? help{dirty_indicator}"),
        Style::default().fg(Color::DarkGray),
    ));

    let bar = Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::Black));
    frame.render_widget(bar, area);
}

/// Render the status/hint bar at the bottom.
pub fn render_status_bar(
    frame: &mut Frame,
    area: Rect,
    hints: &[(&str, &str)],
    flash: Option<&str>,
) {
    let line = if let Some(msg) = flash {
        Line::from(Span::styled(
            format!("  {msg}"),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        let spans: Vec<Span> = hints
            .iter()
            .enumerate()
            .flat_map(|(i, (key, desc))| {
                let mut s = Vec::new();
                if i > 0 {
                    s.push(Span::styled("  ", Style::default().fg(Color::DarkGray)));
                }
                s.push(Span::styled(
                    key.to_string(),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ));
                s.push(Span::styled(
                    format!(" {desc}"),
                    Style::default().fg(Color::Gray),
                ));
                s
            })
            .collect();
        Line::from(spans)
    };

    let bar = Paragraph::new(line).style(Style::default().bg(Color::Black));
    frame.render_widget(bar, area);
}

/// Build the help content lines.  Used both for rendering and for deriving
/// the content length when constructing `ScrollState`.
pub fn help_content() -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            "Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("1-5    ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch tabs"),
        ]),
        Line::from(vec![
            Span::styled("j/k    ", Style::default().fg(Color::Yellow)),
            Span::raw("Move down/up"),
        ]),
        Line::from(vec![
            Span::styled("h/l    ", Style::default().fg(Color::Yellow)),
            Span::raw("Collapse/expand (tree) or focus (sandboxes)"),
        ]),
        Line::from(vec![
            Span::styled("g/G    ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to top/bottom"),
        ]),
        Line::from(vec![
            Span::styled("Space  ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle expand/collapse"),
        ]),
        Line::from(vec![
            Span::styled("e/Tab  ", Style::default().fg(Color::Yellow)),
            Span::raw("Cycle effect on selected rule"),
        ]),
        Line::from(vec![
            Span::styled("a      ", Style::default().fg(Color::Yellow)),
            Span::raw("Add new item"),
        ]),
        Line::from(vec![
            Span::styled("d      ", Style::default().fg(Color::Yellow)),
            Span::raw("Delete selected item"),
        ]),
        Line::from(vec![
            Span::styled("J/K    ", Style::default().fg(Color::Yellow)),
            Span::raw("Move item up/down (includes)"),
        ]),
        Line::from(vec![
            Span::styled("t      ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle test console panel"),
        ]),
        Line::from(vec![
            Span::styled("s      ", Style::default().fg(Color::Yellow)),
            Span::raw("Save (review diff first)"),
        ]),
        Line::from(vec![
            Span::styled("q/Esc  ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit (confirms if unsaved)"),
        ]),
        Line::from(vec![
            Span::styled("?      ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle this help"),
        ]),
    ]
}

/// Render a centered help popup listing all keybindings.
pub fn render_help_overlay(frame: &mut Frame, area: Rect, scroll: &mut ScrollState) {
    let help_lines = help_content();

    let modal = ModalOverlay {
        width_pct: 60,
        height: ModalHeight::Percent(70),
        border_color: Color::Cyan,
        title: "Help",
        footer: &[("j/k", "scroll"), ("any key", "close")],
        footer_right: None,
        scroll: Some(scroll.to_modal_scroll()),
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
}

/// Render a confirmation dialog.
pub fn render_confirm_overlay(frame: &mut Frame, area: Rect, prompt: &str) {
    let modal = ModalOverlay {
        width_pct: 50,
        height: ModalHeight::Percent(20),
        border_color: Color::Yellow,
        title: "Confirm",
        footer: &[("y", "yes"), ("n", "no")],
        footer_right: None,
        scroll: None,
    };
    let inner = modal.render_chrome(frame, area);

    let text = vec![Line::from(""), Line::from(Span::raw(prompt))];

    let para = Paragraph::new(text).alignment(Alignment::Center);
    frame.render_widget(para, inner.area);
}

/// Render a scrollable diff overlay for save review.
pub fn render_diff_overlay(
    frame: &mut Frame,
    area: Rect,
    diff_lines: &[DiffLine],
    scroll: &mut ScrollState,
) {
    let total = diff_lines.len();
    // Use the previous frame's real viewport for scroll_info (avoids estimate).
    // On the very first frame viewport is 0, so scroll_info won't show — that's
    // a single-frame cosmetic gap, far better than a permanent estimate error.
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
        border_color: Color::Cyan,
        title: "Save Review",
        footer: &[("y", "confirm"), ("n", "cancel"), ("j/k", "scroll")],
        footer_right: scroll_info,
        scroll: Some(scroll.to_modal_scroll()),
    };
    let inner = modal.render_chrome(frame, area);
    scroll.update_viewport(inner.area.height as usize);

    let visible_height = inner.area.height as usize;
    let visible_lines: Vec<Line> = diff_lines
        .iter()
        .skip(scroll.offset)
        .take(visible_height)
        .map(|dl| match dl {
            DiffLine::Context(s) => {
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Gray)))
            }
            DiffLine::Add(s) => {
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Green)))
            }
            DiffLine::Remove(s) => {
                Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Red)))
            }
            DiffLine::Header(s) => Line::from(Span::styled(
                s.as_str(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        })
        .collect();

    let para = Paragraph::new(visible_lines);
    frame.render_widget(para, inner.area);
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
    pub border_color: Color,
    pub title: &'a str,
    /// Key-hint pairs rendered as `title_bottom`; empty slice = no footer.
    pub footer: &'a [(&'a str, &'a str)],
    /// Optional right-aligned footer text, e.g. scroll position "[3-10/20]".
    pub footer_right: Option<String>,
    /// When set, a vertical scrollbar is rendered on the right edge if content overflows.
    pub scroll: Option<ModalScroll>,
}

/// The inner area returned by [`ModalOverlay::render_chrome`].
pub struct ModalInner {
    pub area: Rect,
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

        // Build footer line from key-hint pairs
        let mut block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.border_color))
            .title(format!(" {} ", self.title));

        if !self.footer.is_empty() || self.footer_right.is_some() {
            let mut spans: Vec<Span> = Vec::new();
            spans.push(Span::raw(" "));
            for (i, (key, desc)) in self.footer.iter().enumerate() {
                if i > 0 {
                    spans.push(Span::styled("  ", Style::default().fg(Color::DarkGray)));
                }
                spans.push(Span::styled(
                    *key,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ));
                spans.push(Span::styled(
                    format!(" {desc}"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            if let Some(ref right) = self.footer_right {
                spans.push(Span::styled(
                    format!(" {right}"),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            spans.push(Span::raw(" "));
            block = block.title_bottom(Line::from(spans).alignment(Alignment::Right));
        }

        let inner = block.inner(popup);
        frame.render_widget(block, popup);

        // Render scrollbar if content overflows
        let content_area = if let Some(ref sc) = self.scroll {
            if sc.total > inner.height as usize && inner.width > 1 {
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .thumb_style(Style::default().fg(self.border_color))
                    .track_style(Style::default().fg(Color::DarkGray))
                    .begin_symbol(None)
                    .end_symbol(None);
                let mut sb_state = ScrollbarState::new(sc.total)
                    .position(sc.offset)
                    .viewport_content_length(inner.height as usize);
                frame.render_stateful_widget(scrollbar, inner, &mut sb_state);
                // Shrink content area by 1 column on the right to avoid overlap
                Rect::new(inner.x, inner.y, inner.width - 1, inner.height)
            } else {
                inner
            }
        } else {
            inner
        };

        ModalInner { area: content_area }
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
