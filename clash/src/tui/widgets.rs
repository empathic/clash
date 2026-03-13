//! Shared ratatui widgets: tab bar, status bar, overlays.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

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

/// Render a centered help popup listing all keybindings.
pub fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(60, 70, area);
    frame.render_widget(Clear, popup);

    let help_text = vec![
        Line::from(Span::styled(
            "Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("1-4    ", Style::default().fg(Color::Yellow)),
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
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Help ");

    let para = Paragraph::new(help_text)
        .block(block)
        .alignment(Alignment::Left);
    frame.render_widget(para, popup);
}

/// Render a confirmation dialog.
pub fn render_confirm_overlay(frame: &mut Frame, area: Rect, prompt: &str) {
    let popup = centered_rect(50, 20, area);
    frame.render_widget(Clear, popup);

    let text = vec![
        Line::from(""),
        Line::from(Span::raw(prompt)),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                "y",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" yes  "),
            Span::styled(
                "n",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" no"),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Confirm ");

    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    frame.render_widget(para, popup);
}

/// Render a scrollable diff overlay for save review.
pub fn render_diff_overlay(frame: &mut Frame, area: Rect, diff_lines: &[DiffLine], scroll: usize) {
    let popup = centered_rect(80, 80, area);
    frame.render_widget(Clear, popup);

    let visible_height = popup.height.saturating_sub(4) as usize; // borders + title + footer
    let visible_lines: Vec<Line> = diff_lines
        .iter()
        .skip(scroll)
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

    let scroll_info = if diff_lines.len() > visible_height {
        format!(
            " [{}-{}/{}] ",
            scroll + 1,
            (scroll + visible_height).min(diff_lines.len()),
            diff_lines.len()
        )
    } else {
        String::new()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Save Review — y to confirm, n/Esc to cancel ")
        .title_bottom(Line::from(format!(" j/k scroll{scroll_info}")).alignment(Alignment::Right));

    let para = Paragraph::new(visible_lines).block(block);
    frame.render_widget(para, popup);
}

/// A line in a diff display.
pub enum DiffLine {
    Context(String),
    Add(String),
    Remove(String),
    Header(String),
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
