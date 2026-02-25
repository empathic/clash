//! All ratatui rendering: tree widget, description pane, header, status bar.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::policy::Effect;
use crate::wizard::describe_rule;

use super::app::{
    AddRuleStep, App, ConfirmAction, DOMAIN_HINTS, DOMAIN_NAMES, EFFECT_DISPLAY, EFFECT_NAMES, Mode,
};
use super::style as tui_style;
use super::tree::{FlatRow, TreeNodeKind};

/// Format an effect for display: "ask", "auto allow", "auto deny".
fn effect_display(effect: Effect) -> &'static str {
    match effect {
        Effect::Ask => "ask",
        Effect::Allow => "auto allow",
        Effect::Deny => "auto deny",
    }
}

/// Render the entire TUI layout.
pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header
            Constraint::Min(5),    // Tree view
            Constraint::Length(5), // Description pane
            Constraint::Length(1), // Key hints / search bar
        ])
        .split(f.area());

    render_header(f, app, chunks[0]);
    render_tree(f, app, chunks[1]);
    render_description(f, app, chunks[2]);

    if matches!(app.mode, Mode::Search) {
        render_search_bar(f, app, chunks[3]);
    } else {
        render_keyhints(f, app, chunks[3]);
    }

    // Overlays
    if app.show_help {
        render_help_overlay(f, f.area());
    }
    if let Mode::Confirm(action) = &app.mode {
        render_confirm_overlay(f, f.area(), action);
    }
    if matches!(app.mode, Mode::AddRule(_)) {
        render_add_rule_overlay(f, app, f.area());
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let levels: Vec<String> = app.levels.iter().map(|ls| ls.level.to_string()).collect();
    let level_text = if levels.is_empty() {
        "no policies loaded".to_string()
    } else {
        levels.join(" + ")
    };

    let modified = if app.has_unsaved_changes() {
        " [modified]"
    } else {
        ""
    };

    let pos = if app.flat_rows.is_empty() {
        String::new()
    } else {
        format!("  {}/{}", app.cursor + 1, app.flat_rows.len())
    };

    let left = format!(" clash tui  {level_text}{modified}{pos}");
    let right = "? help ";
    let width = area.width as usize;
    let pad = width.saturating_sub(left.len() + right.len());

    let line = Line::from(vec![
        Span::styled(&left, tui_style::HEADER),
        Span::styled(" ".repeat(pad), tui_style::HEADER),
        Span::styled(right, tui_style::DIM.add_modifier(Modifier::REVERSED)),
    ]);

    let header = Paragraph::new(line).style(tui_style::HEADER);
    f.render_widget(header, area);
}

// ---------------------------------------------------------------------------
// Tree view
// ---------------------------------------------------------------------------

fn render_tree(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::LEFT | Borders::RIGHT)
        .border_style(tui_style::BORDER);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible_height = inner.height as usize;
    if app.flat_rows.is_empty() {
        let msg = Paragraph::new("  No policy rules loaded. Run `clash init` to create a policy.")
            .style(tui_style::DIM);
        f.render_widget(msg, inner);
        return;
    }

    let scroll = app.scroll_offset(visible_height);
    let end = (scroll + visible_height).min(app.flat_rows.len());
    let mut lines: Vec<Line> = Vec::new();

    let selecting = if let Mode::SelectEffect(state) = &app.mode {
        Some(state.effect_index)
    } else {
        None
    };

    for i in scroll..end {
        let row = &app.flat_rows[i];
        let is_selected = i == app.cursor;
        let is_match = app.search_matches.contains(&i);
        let inline_select = if is_selected { selecting } else { None };
        let line = render_row(row, is_selected, is_match, inline_select);
        lines.push(line);
    }

    let tree_widget = Paragraph::new(lines);
    f.render_widget(tree_widget, inner);
}

fn render_row(
    row: &FlatRow,
    is_selected: bool,
    is_search_match: bool,
    inline_select: Option<usize>,
) -> Line<'static> {
    let mut spans: Vec<Span> = Vec::new();

    // Indent with tree connector lines
    spans.push(Span::raw(" "));
    for d in 0..row.depth {
        if d < row.connectors.len() && row.connectors[d] {
            spans.push(Span::styled("│ ", tui_style::CONNECTOR));
        } else {
            spans.push(Span::raw("  "));
        }
    }

    // Expand/collapse indicator
    if row.has_children {
        let arrow = if row.expanded { "▼ " } else { "▶ " };
        spans.push(Span::styled(arrow, tui_style::DIM));
    } else if row.depth > 0 {
        spans.push(Span::raw("  "));
    }

    // Node content
    match &row.kind {
        TreeNodeKind::Domain(domain) => {
            spans.push(Span::styled(domain.to_string(), tui_style::DOMAIN));
            if !row.expanded {
                let count = count_display(row);
                spans.push(Span::styled(count, tui_style::DIM));
            }
        }
        TreeNodeKind::PolicyBlock { name, level } => {
            spans.push(Span::styled(format!("{name} "), tui_style::BINARY));
            spans.push(Span::styled(format!("[{level}]"), tui_style::TAG));
        }
        TreeNodeKind::Binary(text) => {
            spans.push(Span::styled(text.clone(), tui_style::BINARY));
        }
        TreeNodeKind::Arg(text) => {
            spans.push(Span::styled(text.clone(), tui_style::PATTERN));
        }
        TreeNodeKind::HasMarker => {
            spans.push(Span::styled(":has", tui_style::DIM));
        }
        TreeNodeKind::HasArg(text) => {
            spans.push(Span::styled(text.clone(), tui_style::PATTERN));
        }
        TreeNodeKind::PathNode(text) => {
            spans.push(Span::styled(text.clone(), tui_style::PATTERN));
        }
        TreeNodeKind::FsOp(text) => {
            spans.push(Span::styled(text.clone(), tui_style::PATTERN));
        }
        TreeNodeKind::NetDomain(text) => {
            spans.push(Span::styled(text.clone(), tui_style::PATTERN));
        }
        TreeNodeKind::ToolName(text) => {
            spans.push(Span::styled(text.clone(), tui_style::PATTERN));
        }
        TreeNodeKind::Leaf {
            effect,
            level,
            policy,
            ..
        } => {
            if let Some(sel_idx) = inline_select {
                for (i, &name) in EFFECT_DISPLAY.iter().enumerate() {
                    if i > 0 {
                        spans.push(Span::raw(" "));
                    }
                    let style = if i == sel_idx {
                        Style::default()
                            .add_modifier(Modifier::REVERSED)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        tui_style::DIM
                    };
                    spans.push(Span::styled(format!(" {name} "), style));
                }
            } else {
                let effect_text = format!("{:<10}", effect_display(*effect));
                spans.push(Span::styled(effect_text, tui_style::effect_style(*effect)));
            }

            spans.push(Span::styled(
                format!("  [{level}:{policy}]"),
                tui_style::TAG,
            ));
        }
    }

    let style = if is_selected {
        tui_style::SELECTED
    } else if is_search_match {
        Style::default().add_modifier(Modifier::UNDERLINED)
    } else {
        Style::default()
    };

    Line::from(spans).style(style)
}

fn count_display(row: &FlatRow) -> String {
    // We estimate rule count from children info. Since we only show this
    // for collapsed nodes, use the tree_path to look up the actual node.
    // However we don't have access to roots here, so we just show a
    // generic indicator. The breadcrumb covers detailed info.
    if row.has_children && !row.expanded {
        "  ...".to_string()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Description pane
// ---------------------------------------------------------------------------

fn render_description(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
        .border_style(tui_style::BORDER);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // In edit-rule mode, show the editor
    if let Mode::EditRule(state) = &app.mode {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Edit rule: ", tui_style::DIM),
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(" confirm  ", tui_style::DIM),
                Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(" cancel", tui_style::DIM),
            ]),
            Line::from(vec![
                Span::raw("> "),
                Span::styled(state.input.value(), Style::default()),
                Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            ]),
        ];
        if let Some(err) = &state.error {
            lines.push(Line::from(Span::styled(
                err.as_str(),
                tui_style::DENY.add_modifier(Modifier::BOLD),
            )));
        }
        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        f.render_widget(para, inner);
        return;
    }

    let mut lines = if let Some(row) = app.flat_rows.get(app.cursor) {
        description_for_row(row)
    } else {
        vec![Line::from(Span::styled("No selection", tui_style::DIM))]
    };

    // Breadcrumb trail
    if let Some(crumb) = app.breadcrumb() {
        lines.push(Line::from(Span::styled(crumb, tui_style::DIM)));
    }

    // Show status message
    if let Some(status) = &app.status_message {
        let style = if status.is_error {
            tui_style::DENY.add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        };
        lines.push(Line::from(Span::styled(&status.text, style)));
    }

    let desc = Paragraph::new(lines).wrap(Wrap { trim: true });
    f.render_widget(desc, inner);
}

fn description_for_row(row: &FlatRow) -> Vec<Line<'static>> {
    match &row.kind {
        TreeNodeKind::Leaf {
            effect,
            rule,
            level,
            policy,
        } => {
            let desc = describe_rule(rule);
            let rule_text = rule.to_string();
            vec![
                Line::from(vec![
                    Span::styled(
                        effect_display(*effect).to_uppercase(),
                        tui_style::effect_style(*effect).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::styled(desc, Style::default()),
                ]),
                Line::from(vec![
                    Span::styled("Source: ", tui_style::DIM),
                    Span::styled(format!("{policy} [{level}]"), tui_style::TAG),
                ]),
                Line::from(vec![
                    Span::styled("Rule: ", tui_style::DIM),
                    Span::raw(format!(
                        "({} {})",
                        effect,
                        rule_text
                            .trim_start_matches(&format!("({effect} "))
                            .trim_end_matches(')')
                    )),
                ]),
            ]
        }
        TreeNodeKind::Domain(domain) => {
            vec![Line::from(Span::styled(
                format!("{domain} capability rules"),
                tui_style::DOMAIN,
            ))]
        }
        TreeNodeKind::Binary(bin) => {
            vec![Line::from(vec![
                Span::styled("Binary: ", tui_style::DIM),
                Span::styled(bin.clone(), tui_style::BINARY),
            ])]
        }
        TreeNodeKind::Arg(arg) => {
            vec![Line::from(vec![
                Span::styled("Positional arg: ", tui_style::DIM),
                Span::styled(arg.clone(), tui_style::PATTERN),
            ])]
        }
        TreeNodeKind::HasMarker => {
            vec![Line::from(Span::styled(
                "Orderless argument matching (:has) — patterns below match args in any position",
                tui_style::DIM,
            ))]
        }
        TreeNodeKind::HasArg(arg) => {
            vec![Line::from(vec![
                Span::styled("Orderless arg: ", tui_style::DIM),
                Span::styled(arg.clone(), tui_style::PATTERN),
            ])]
        }
        TreeNodeKind::PathNode(path) => {
            vec![Line::from(vec![
                Span::styled("Path filter: ", tui_style::DIM),
                Span::styled(path.clone(), tui_style::PATTERN),
            ])]
        }
        TreeNodeKind::FsOp(op) => {
            vec![Line::from(vec![
                Span::styled("Operation: ", tui_style::DIM),
                Span::styled(op.clone(), tui_style::PATTERN),
            ])]
        }
        TreeNodeKind::NetDomain(domain) => {
            vec![Line::from(vec![
                Span::styled("Domain pattern: ", tui_style::DIM),
                Span::styled(domain.clone(), tui_style::PATTERN),
            ])]
        }
        TreeNodeKind::ToolName(name) => {
            vec![Line::from(vec![
                Span::styled("Tool: ", tui_style::DIM),
                Span::styled(name.clone(), tui_style::PATTERN),
            ])]
        }
        TreeNodeKind::PolicyBlock { name, level } => {
            vec![Line::from(vec![
                Span::styled("Policy: ", tui_style::DIM),
                Span::styled(format!("{name} [{level}]"), tui_style::TAG),
            ])]
        }
    }
}

// ---------------------------------------------------------------------------
// Key hints
// ---------------------------------------------------------------------------

fn render_keyhints(f: &mut Frame, app: &App, area: Rect) {
    let hints = context_hints(app);
    let mut spans: Vec<Span> = Vec::new();
    for (i, (key, desc)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled("  ", tui_style::DIM));
        }
        spans.push(Span::styled(
            *key,
            Style::default().add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!(" {desc}"), tui_style::DIM));
    }

    let line = Line::from(spans);
    let bar = Paragraph::new(line).style(tui_style::STATUS_BAR);
    f.render_widget(bar, area);
}

fn context_hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let mut hints = vec![];
    let row = app.flat_rows.get(app.cursor);

    match row {
        Some(row) => {
            hints.push(("j/k", "move"));

            match &row.kind {
                TreeNodeKind::Domain(_)
                | TreeNodeKind::Binary(_)
                | TreeNodeKind::Arg(_)
                | TreeNodeKind::HasArg(_)
                | TreeNodeKind::PathNode(_)
                | TreeNodeKind::FsOp(_)
                | TreeNodeKind::NetDomain(_)
                | TreeNodeKind::ToolName(_)
                | TreeNodeKind::PolicyBlock { .. } => {
                    if row.has_children {
                        if row.expanded {
                            hints.push(("h", "collapse"));
                        } else {
                            hints.push(("l", "expand"));
                        }
                    }
                }
                TreeNodeKind::Leaf { .. } => {
                    hints.push(("Tab", "effect"));
                    hints.push(("e", "edit"));
                    hints.push(("d", "delete"));
                }
                TreeNodeKind::HasMarker => {}
            }
        }
        None => {
            hints.push(("j/k", "move"));
        }
    }

    hints.push(("[/]", "all"));
    hints.push(("a", "add"));
    hints.push(("/", "search"));
    if app.search_query.is_some() {
        hints.push(("n/N", "next/prev"));
    }
    hints.push(("w", "save"));
    hints.push(("?", "help"));
    hints.push(("q", "quit"));
    hints
}

// ---------------------------------------------------------------------------
// Search bar
// ---------------------------------------------------------------------------

fn render_search_bar(f: &mut Frame, app: &App, area: Rect) {
    let match_info = if app.search_matches.is_empty() {
        if app.search_input.value().is_empty() {
            String::new()
        } else {
            " (no matches)".to_string()
        }
    } else {
        format!(
            " ({}/{})",
            app.search_match_cursor + 1,
            app.search_matches.len()
        )
    };

    let line = Line::from(vec![
        Span::styled("/", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(app.search_input.value()),
        Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        Span::styled(match_info, tui_style::DIM),
    ]);

    let bar = Paragraph::new(line);
    f.render_widget(bar, area);
}

// ---------------------------------------------------------------------------
// Help overlay
// ---------------------------------------------------------------------------

fn render_help_overlay(f: &mut Frame, area: Rect) {
    let width = 50u16.min(area.width.saturating_sub(4));
    let height = 31u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let overlay = Rect::new(x, y, width, height);

    f.render_widget(Clear, overlay);

    let block = Block::default()
        .title(" Keyboard Shortcuts ")
        .borders(Borders::ALL)
        .border_style(tui_style::DOMAIN);
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let bold = Style::default().add_modifier(Modifier::BOLD);

    let lines = vec![
        Line::from(""),
        help_line(bold, "  j / Down    ", "Move cursor down"),
        help_line(bold, "  k / Up      ", "Move cursor up"),
        help_line(bold, "  l / Right   ", "Expand node or enter children"),
        help_line(bold, "  h / Left    ", "Collapse node or go to parent"),
        help_line(bold, "  Enter       ", "Expand node or enter children"),
        help_line(bold, "  Space       ", "Toggle expand/collapse"),
        help_line(bold, "  g           ", "Jump to top"),
        help_line(bold, "  G           ", "Jump to bottom"),
        help_line(bold, "  PgUp/PgDn   ", "Page up/down"),
        Line::from(""),
        help_line(bold, "  Tab         ", "Select effect (dropdown)"),
        help_line(bold, "  e           ", "Edit rule at cursor"),
        help_line(bold, "  a           ", "Add a new rule"),
        help_line(bold, "  d           ", "Delete rule at cursor"),
        help_line(bold, "  w           ", "Save all changes"),
        help_line(bold, "  u           ", "Undo last edit"),
        help_line(bold, "  Ctrl+r      ", "Redo"),
        Line::from(""),
        help_line(bold, "  [           ", "Collapse all"),
        help_line(bold, "  ]           ", "Expand all"),
        Line::from(""),
        help_line(bold, "  /           ", "Search"),
        help_line(bold, "  n / N       ", "Next / previous match"),
        help_line(bold, "  Esc         ", "Clear search / quit"),
        help_line(bold, "  ?           ", "Toggle this help"),
        help_line(bold, "  q           ", "Quit (confirms if unsaved)"),
        Line::from(""),
        Line::from(Span::styled("  Press any key to close", tui_style::DIM)),
    ];

    let help = Paragraph::new(lines);
    f.render_widget(help, inner);
}

fn help_line<'a>(key_style: Style, key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(key, key_style),
        Span::styled(desc, Style::default()),
    ])
}

// ---------------------------------------------------------------------------
// Confirm overlay
// ---------------------------------------------------------------------------

fn render_confirm_overlay(f: &mut Frame, area: Rect, action: &ConfirmAction) {
    let (title, message) = match action {
        ConfirmAction::DeleteRule { rule_text, .. } => (
            " Confirm Delete ",
            format!("Delete rule?\n\n  {rule_text}\n\ny/n"),
        ),
        ConfirmAction::QuitUnsaved => (
            " Unsaved Changes ",
            "You have unsaved changes.\n\nQuit without saving?\n\ny/n".to_string(),
        ),
    };

    let width = 50u16.min(area.width.saturating_sub(4));
    let height = 9u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let overlay = Rect::new(x, y, width, height);

    f.render_widget(Clear, overlay);

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let para = Paragraph::new(message).wrap(Wrap { trim: false });
    f.render_widget(para, inner);
}

// ---------------------------------------------------------------------------
// Add rule overlay
// ---------------------------------------------------------------------------

fn render_add_rule_overlay(f: &mut Frame, app: &App, area: Rect) {
    let Mode::AddRule(form) = &app.mode else {
        return;
    };

    let width = 56u16.min(area.width.saturating_sub(4));
    let height = 16u16.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let overlay = Rect::new(x, y, width, height);

    f.render_widget(Clear, overlay);

    let block = Block::default()
        .title(" Add Rule ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let bold = Style::default().add_modifier(Modifier::BOLD);
    let dim = tui_style::DIM;
    let active_step = form.step;

    let mut lines: Vec<Line> = Vec::new();

    // Step 1: Domain
    let domain_label = step_label(
        "1. Domain",
        matches!(active_step, AddRuleStep::SelectDomain),
    );
    let domain_choices = selector_line(
        DOMAIN_NAMES,
        form.domain_index,
        matches!(active_step, AddRuleStep::SelectDomain),
    );
    lines.push(domain_label);
    lines.push(domain_choices);
    lines.push(Line::from(""));

    // Step 2: Matcher
    let matcher_label = step_label(
        "2. Matcher",
        matches!(active_step, AddRuleStep::EnterMatcher),
    );
    lines.push(matcher_label);
    if matches!(active_step, AddRuleStep::EnterMatcher) {
        lines.push(Line::from(vec![
            Span::styled("   > ", dim),
            Span::raw(form.matcher_input.value()),
            Span::styled("_", bold),
        ]));
        lines.push(Line::from(Span::styled(
            format!("   e.g. {}", DOMAIN_HINTS[form.domain_index]),
            dim,
        )));
    } else {
        let val = form.matcher_input.value();
        let display = if val.is_empty() { "(empty)" } else { val };
        lines.push(Line::from(Span::styled(format!("   {display}"), dim)));
    }
    lines.push(Line::from(""));

    // Step 3: Effect
    let effect_label = step_label(
        "3. Effect",
        matches!(active_step, AddRuleStep::SelectEffect),
    );
    let effect_choices = selector_line(
        EFFECT_NAMES,
        form.effect_index,
        matches!(active_step, AddRuleStep::SelectEffect),
    );
    lines.push(effect_label);
    lines.push(effect_choices);
    lines.push(Line::from(""));

    // Step 4: Level
    let level_label = step_label("4. Level", matches!(active_step, AddRuleStep::SelectLevel));
    let level_names: Vec<String> = form
        .available_levels
        .iter()
        .map(|l| l.to_string())
        .collect();
    let level_strs: Vec<&str> = level_names.iter().map(|s| s.as_str()).collect();
    let level_choices = selector_line(
        &level_strs,
        form.level_index,
        matches!(active_step, AddRuleStep::SelectLevel),
    );
    lines.push(level_label);
    lines.push(level_choices);

    // Error
    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err.as_str(),
            tui_style::DENY.add_modifier(Modifier::BOLD),
        )));
    }

    let para = Paragraph::new(lines);
    f.render_widget(para, inner);
}

fn step_label(label: &str, is_active: bool) -> Line<'static> {
    let style = if is_active {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        tui_style::DIM
    };
    Line::from(Span::styled(format!(" {label}"), style))
}

fn selector_line(options: &[&str], selected: usize, is_active: bool) -> Line<'static> {
    let mut spans = vec![Span::raw("   ")];
    for (i, opt) in options.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("  "));
        }
        let style = if i == selected && is_active {
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .add_modifier(Modifier::BOLD)
        } else if i == selected {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            tui_style::DIM
        };
        spans.push(Span::styled(format!(" {opt} "), style));
    }
    if is_active {
        spans.push(Span::styled("  ←/→ Tab Enter", tui_style::DIM));
    }
    Line::from(spans)
}
