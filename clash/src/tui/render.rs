//! All ratatui rendering: tree widget, description pane, header, status bar.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::policy::Effect;
use crate::policy::ast::{PathExpr, PathFilter, SandboxRef};
use crate::wizard::describe_rule;

use super::app::{
    AddRuleStep, App, COMMON_ENV_VARS, ConfirmAction, DOMAIN_NAMES, DiffLine, EFFECT_DISPLAY,
    EFFECT_NAMES, FS_OPS, Mode, PATH_SOURCES, PATH_TYPES, WORKTREE_OPTIONS,
};
use super::editor::TextInput;
use super::style as tui_style;
use super::tree::{self as tui_tree, FlatRow, NodeId, TreeArena, TreeNodeKind};

/// Format an effect for display: "ask", "auto allow", "auto deny".
pub(crate) fn effect_display(effect: Effect) -> &'static str {
    match effect {
        Effect::Ask => "ask",
        Effect::Allow => "auto allow",
        Effect::Deny => "auto deny",
    }
}

/// Render the entire TUI layout.
pub fn render(f: &mut Frame, app: &App) {
    render_base(f, app);
    let area = f.area();
    for overlay in active_overlays(app) {
        overlay.render(f, area, app);
    }
}

/// Render the base layout (header, tree, description, key hints).
fn render_base(f: &mut Frame, app: &App) {
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
}

// ---------------------------------------------------------------------------
// Overlay system
// ---------------------------------------------------------------------------

/// An overlay that renders on top of the base layout.
enum Overlay<'a> {
    Help,
    Confirm(&'a ConfirmAction),
    AddRule,
    SaveDiff,
}

impl Overlay<'_> {
    fn render(&self, f: &mut Frame, area: Rect, app: &App) {
        match self {
            Overlay::Help => render_help_overlay(f, area),
            Overlay::Confirm(action) => render_confirm_overlay(f, area, action),
            Overlay::AddRule => render_add_rule_overlay(f, app, area),
            Overlay::SaveDiff => render_save_diff_overlay(f, app, area),
        }
    }
}

/// Derive the active overlay stack from the current app state.
fn active_overlays(app: &App) -> Vec<Overlay<'_>> {
    let mut overlays = Vec::new();
    match &app.mode {
        Mode::Confirm(action) => overlays.push(Overlay::Confirm(action)),
        Mode::AddRule(_) => overlays.push(Overlay::AddRule),
        Mode::ConfirmSave(_) => overlays.push(Overlay::SaveDiff),
        _ => {}
    }
    if app.show_help {
        overlays.push(Overlay::Help);
    }
    overlays
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

    let pos = if app.tree.flat_rows.is_empty() {
        String::new()
    } else {
        format!("  {}/{}", app.tree.cursor + 1, app.tree.flat_rows.len())
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

/// Inline editing state for a single row.
pub(crate) enum InlineEdit<'a> {
    /// No inline edit active.
    None,
    /// Effect selector (for leaf or branch).
    EffectSelect(usize),
    /// Text input (for Binary, Arg, HasArg, PathNode, NetDomain, ToolName).
    TextInput(&'a TextInput),
    /// FsOp selector.
    FsOpSelect(usize),
}

fn render_tree(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::LEFT | Borders::RIGHT)
        .border_style(tui_style::BORDER);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let visible_height = inner.height as usize;
    if app.tree.flat_rows.is_empty() {
        let msg = Paragraph::new("  No policy rules loaded. Run `clash init` to create a policy.")
            .style(tui_style::DIM);
        f.render_widget(msg, inner);
        return;
    }

    let scroll = app.tree.scroll_offset(visible_height);
    let end = (scroll + visible_height).min(app.tree.flat_rows.len());
    let mut lines: Vec<Line> = Vec::new();

    let selecting = match &app.mode {
        Mode::SelectEffect(state) => Some(state.effect_index),
        _ => None,
    };
    let branch_selecting = match &app.mode {
        Mode::SelectBranchEffect(state) => Some(state.effect_index),
        _ => None,
    };

    for i in scroll..end {
        let row = &app.tree.flat_rows[i];
        let is_selected = i == app.tree.cursor;
        let is_match = app.search.matches.contains(&i);

        // Determine inline edit state for this row
        let inline_edit = if is_selected {
            match &app.mode {
                Mode::EditNodeText(state) if state.node_id == row.node_id => {
                    InlineEdit::TextInput(&state.input)
                }
                Mode::SelectFsOp(state) if state.node_id == row.node_id => {
                    InlineEdit::FsOpSelect(state.op_index)
                }
                _ => {
                    let kind = &app.tree.arena[row.node_id].kind;
                    match kind {
                        TreeNodeKind::Leaf { .. } | TreeNodeKind::SandboxLeaf { .. } => {
                            match selecting {
                                Some(idx) => InlineEdit::EffectSelect(idx),
                                None => InlineEdit::None,
                            }
                        }
                        _ => match branch_selecting {
                            Some(idx) => InlineEdit::EffectSelect(idx),
                            None => InlineEdit::None,
                        },
                    }
                }
            }
        } else {
            InlineEdit::None
        };

        let summary = if !row.expanded && row.has_children {
            collapsed_summary(&app.tree.arena, row.node_id)
        } else {
            Vec::new()
        };
        let kind = &app.tree.arena[row.node_id].kind;
        let line = render_row(row, kind, is_selected, is_match, &inline_edit, &summary);
        lines.push(line);
    }

    let tree_widget = Paragraph::new(lines);
    f.render_widget(tree_widget, inner);
}

pub(crate) fn collapsed_summary(arena: &TreeArena, node_id: NodeId) -> Vec<Span<'static>> {
    let (allow, deny, ask) = arena.effect_counts(node_id);
    let mut spans = Vec::new();
    spans.push(Span::styled("  ", tui_style::DIM));
    let mut first = true;
    if allow > 0 {
        spans.push(Span::styled(
            format!("{allow} auto allow"),
            tui_style::ALLOW,
        ));
        first = false;
    }
    if deny > 0 {
        if !first {
            spans.push(Span::styled(" · ", tui_style::DIM));
        }
        spans.push(Span::styled(format!("{deny} auto deny"), tui_style::DENY));
        first = false;
    }
    if ask > 0 {
        if !first {
            spans.push(Span::styled(" · ", tui_style::DIM));
        }
        spans.push(Span::styled(format!("{ask} ask"), tui_style::ASK));
    }
    spans
}

pub(crate) fn render_row(
    row: &FlatRow,
    kind: &TreeNodeKind,
    is_selected: bool,
    is_search_match: bool,
    inline_edit: &InlineEdit<'_>,
    summary: &[Span<'static>],
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

    // Inline text input replaces node label for text-editable nodes
    if let InlineEdit::TextInput(input) = inline_edit {
        let val = input.value();
        let pos = input.cursor_pos();
        let before: String = val.chars().take(pos).collect();
        let after: String = val.chars().skip(pos).collect();
        spans.push(Span::raw(before));
        spans.push(Span::styled(
            "_",
            Style::default().add_modifier(Modifier::SLOW_BLINK),
        ));
        spans.push(Span::raw(after));

        let style = if is_selected {
            tui_style::SELECTED
        } else {
            Style::default()
        };
        return Line::from(spans).style(style);
    }

    // Inline FsOp selector replaces node label for FsOp nodes
    if let InlineEdit::FsOpSelect(sel_idx) = inline_edit {
        for (i, &name) in FS_OPS.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" "));
            }
            let style = if i == *sel_idx {
                Style::default()
                    .add_modifier(Modifier::REVERSED)
                    .add_modifier(Modifier::BOLD)
            } else {
                tui_style::DIM
            };
            spans.push(Span::styled(format!(" {name} "), style));
        }

        let style = if is_selected {
            tui_style::SELECTED
        } else {
            Style::default()
        };
        return Line::from(spans).style(style);
    }

    let inline_select = match inline_edit {
        InlineEdit::EffectSelect(idx) => Some(*idx),
        _ => None,
    };

    // Node content
    match kind {
        TreeNodeKind::Domain(domain) => {
            spans.push(Span::styled(domain.to_string(), tui_style::DOMAIN));
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
        TreeNodeKind::PathNode(pf) => {
            spans.push(Span::styled(
                tui_tree::display_path_filter_short(pf),
                tui_style::PATTERN,
            ));
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
            rule,
            level,
            policy,
            is_shadowed,
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
                let style = if *is_shadowed {
                    tui_style::SHADOWED
                } else {
                    tui_style::effect_style(*effect)
                };
                spans.push(Span::styled(effect_text, style));
            }

            spans.push(Span::styled(
                format!("  [{level}:{policy}]"),
                tui_style::TAG,
            ));

            match &rule.sandbox {
                Some(SandboxRef::Named(name)) => {
                    spans.push(Span::styled(
                        format!("  sandbox: \"{name}\""),
                        tui_style::DIM,
                    ));
                }
                Some(SandboxRef::Inline(_)) => {
                    spans.push(Span::styled("  sandboxed", tui_style::DIM));
                }
                None => {}
            }

            if *is_shadowed {
                spans.push(Span::styled("  [shadowed]", tui_style::SHADOWED));
            }
        }
        TreeNodeKind::SandboxLeaf { effect, .. } => {
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
            spans.push(Span::styled("  [sandbox]", tui_style::TAG));
        }
        TreeNodeKind::SandboxGroup => {
            spans.push(Span::styled("Sandbox", tui_style::DOMAIN));
        }
        TreeNodeKind::SandboxName(name) => {
            spans.push(Span::styled("sandbox: ", tui_style::DIM));
            spans.push(Span::styled(format!("\"{name}\""), tui_style::PATTERN));
        }
    }

    // Show inline effect selector on branch nodes during branch effect change
    if let Some(sel_idx) = inline_select
        && !matches!(
            kind,
            TreeNodeKind::Leaf { .. } | TreeNodeKind::SandboxLeaf { .. }
        )
    {
        spans.push(Span::raw("  "));
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
    }

    // Append collapsed summary for any non-leaf collapsed node
    if inline_select.is_none() && !row.expanded && row.has_children {
        spans.extend(summary.iter().cloned());
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

// ---------------------------------------------------------------------------
// Description pane
// ---------------------------------------------------------------------------

/// Return `(label, hint)` for the inline edit description pane based on node kind.
fn edit_node_hint(kind: &TreeNodeKind) -> (&str, &str) {
    match kind {
        TreeNodeKind::Binary(_) => ("command", "* any  /regex/  or literal name"),
        TreeNodeKind::Arg(_) => ("argument", "* any  /regex/  or literal value"),
        TreeNodeKind::HasArg(_) => ("argument", "* any  /regex/  or literal value"),
        TreeNodeKind::NetDomain(_) => ("domain", "* any  /regex/  or domain name"),
        TreeNodeKind::ToolName(_) => ("tool", "* any  /regex/  or tool name"),
        TreeNodeKind::PathNode(_) => (
            "path",
            "s-expr e.g. (subpath (env PWD))  \"/exact/path\"  /regex/",
        ),
        _ => ("node", ""),
    }
}

fn render_description(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
        .border_style(tui_style::BORDER);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // In edit-rule or edit-sandbox-rule mode, show the editor
    let edit_state = match &app.mode {
        Mode::EditRule(state) => {
            let label = match &state.target {
                super::app::RuleTarget::Regular { .. } => "Edit rule: ",
                super::app::RuleTarget::Sandbox { .. } => "Edit sandbox rule: ",
            };
            Some((label, &state.input, &state.error))
        }
        _ => None,
    };
    if let Some((label, input, error)) = edit_state {
        let mut lines = vec![
            Line::from(vec![
                Span::styled(label, tui_style::DIM),
                Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(" confirm  ", tui_style::DIM),
                Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(" cancel", tui_style::DIM),
            ]),
            {
                let val = input.value();
                let pos = input.cursor_pos();
                let before: String = val.chars().take(pos).collect();
                let after: String = val.chars().skip(pos).collect();
                Line::from(vec![
                    Span::raw("> "),
                    Span::raw(before),
                    Span::styled("_", Style::default().add_modifier(Modifier::SLOW_BLINK)),
                    Span::raw(after),
                ])
            },
        ];
        if let Some(err) = error {
            lines.push(Line::from(Span::styled(
                err.as_str(),
                tui_style::DENY.add_modifier(Modifier::BOLD),
            )));
        }
        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        f.render_widget(para, inner);
        return;
    }

    // In inline node text edit mode, show help in description pane
    if let Mode::EditNodeText(state) = &app.mode {
        let (label, hint) = edit_node_hint(&app.tree.arena[state.node_id].kind);
        let mut lines = vec![Line::from(vec![
            Span::styled(format!("Edit {label}: "), tui_style::DIM),
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" confirm  ", tui_style::DIM),
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" cancel", tui_style::DIM),
        ])];
        lines.push(Line::from(Span::styled(hint, tui_style::DIM)));
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

    // In FsOp selector mode, show help in description pane
    if matches!(&app.mode, Mode::SelectFsOp(_)) {
        let lines = vec![Line::from(vec![
            Span::styled("Select operation: ", tui_style::DIM),
            Span::styled("Tab/←/→", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" cycle  ", tui_style::DIM),
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" confirm  ", tui_style::DIM),
            Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(" cancel", tui_style::DIM),
        ])];
        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        f.render_widget(para, inner);
        return;
    }

    let mut lines = if let Some(row) = app.tree.flat_rows.get(app.tree.cursor) {
        let kind = &app.tree.arena[row.node_id].kind;
        let mut desc = description_for_row(kind);
        // Append rule counts for structural (non-leaf) nodes
        if !matches!(
            kind,
            TreeNodeKind::Leaf { .. }
                | TreeNodeKind::SandboxLeaf { .. }
                | TreeNodeKind::HasMarker
                | TreeNodeKind::SandboxName(_)
        ) {
            let count = app.tree.arena.rule_count(row.node_id);
            if count > 0 {
                let (allow, deny, ask) = app.tree.arena.effect_counts(row.node_id);
                let mut parts = Vec::new();
                if allow > 0 {
                    parts.push(format!("{allow} auto allow"));
                }
                if deny > 0 {
                    parts.push(format!("{deny} auto deny"));
                }
                if ask > 0 {
                    parts.push(format!("{ask} ask"));
                }
                desc.push(Line::from(Span::styled(
                    format!(
                        "{count} rule{}: {}",
                        if count == 1 { "" } else { "s" },
                        parts.join(", ")
                    ),
                    tui_style::DIM,
                )));
            }
        }
        desc
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

pub(crate) fn description_for_row(kind: &TreeNodeKind) -> Vec<Line<'static>> {
    match kind {
        TreeNodeKind::Leaf {
            effect,
            rule,
            level,
            policy,
            is_shadowed,
        } => {
            let desc = describe_rule(rule);
            let rule_text = rule.to_string();
            let mut lines = vec![
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
            ];
            if *is_shadowed {
                lines.push(Line::from(Span::styled(
                    "This rule is shadowed by a higher-precedence rule at another level.",
                    tui_style::SHADOWED,
                )));
            }
            lines
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
        TreeNodeKind::PathNode(pf) => {
            let short = tui_tree::display_path_filter_short(pf);
            let sexpr = pf.to_string();
            let mut lines = vec![Line::from(vec![
                Span::styled("Path: ", tui_style::DIM),
                Span::styled(short.clone(), tui_style::PATTERN),
            ])];
            lines.push(Line::from(Span::styled(
                describe_path_filter(pf),
                Style::default(),
            )));
            if sexpr != short {
                lines.push(Line::from(vec![
                    Span::styled("s-expr: ", tui_style::DIM),
                    Span::raw(sexpr),
                ]));
            }
            lines
        }
        TreeNodeKind::FsOp(op) => {
            let explanation = match op.as_str() {
                "read" => "Matches filesystem read operations (file reads, directory listings).",
                "write" => "Matches filesystem write operations (file modifications).",
                "create" => "Matches filesystem create operations (new files, directories).",
                "delete" => "Matches filesystem delete operations (file/directory removal).",
                "*" => "Matches all filesystem operations.",
                _ => "Matches this filesystem operation.",
            };
            vec![
                Line::from(vec![
                    Span::styled("Operation: ", tui_style::DIM),
                    Span::styled(op.clone(), tui_style::PATTERN),
                ]),
                Line::from(Span::styled(explanation.to_string(), Style::default())),
            ]
        }
        TreeNodeKind::NetDomain(domain) => {
            vec![
                Line::from(vec![
                    Span::styled("Domain: ", tui_style::DIM),
                    Span::styled(domain.clone(), tui_style::PATTERN),
                ]),
                Line::from(Span::styled(
                    format!("Matches network requests to {domain}."),
                    Style::default(),
                )),
            ]
        }
        TreeNodeKind::ToolName(name) => {
            vec![
                Line::from(vec![
                    Span::styled("Tool: ", tui_style::DIM),
                    Span::styled(name.clone(), tui_style::PATTERN),
                ]),
                Line::from(Span::styled(
                    format!("Matches use of the {name} tool."),
                    Style::default(),
                )),
            ]
        }
        TreeNodeKind::PolicyBlock { name, level } => {
            vec![Line::from(vec![
                Span::styled("Policy: ", tui_style::DIM),
                Span::styled(format!("{name} [{level}]"), tui_style::TAG),
            ])]
        }
        TreeNodeKind::SandboxLeaf {
            effect,
            sandbox_rule,
            parent_rule,
            ..
        } => {
            vec![
                Line::from(vec![
                    Span::styled("Sandbox: ", tui_style::DIM),
                    Span::styled(
                        effect_display(*effect).to_uppercase(),
                        tui_style::effect_style(*effect).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::styled(sandbox_rule.to_string(), Style::default()),
                ]),
                Line::from(vec![
                    Span::styled("Parent rule: ", tui_style::DIM),
                    Span::raw(parent_rule.to_string()),
                ]),
            ]
        }
        TreeNodeKind::SandboxGroup => {
            vec![Line::from(Span::styled(
                "Sandbox permissions for this exec rule",
                tui_style::DOMAIN,
            ))]
        }
        TreeNodeKind::SandboxName(name) => {
            vec![Line::from(vec![
                Span::styled("Named sandbox policy: ", tui_style::DIM),
                Span::styled(format!("\"{name}\""), tui_style::PATTERN),
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

pub(crate) fn context_hints(app: &App) -> Vec<(&'static str, &'static str)> {
    let mut hints = vec![];
    let row = app.tree.flat_rows.get(app.tree.cursor);

    match row {
        Some(row) => {
            hints.push(("j/k", "move"));

            match &app.tree.arena[row.node_id].kind {
                TreeNodeKind::Binary(_)
                | TreeNodeKind::Arg(_)
                | TreeNodeKind::HasArg(_)
                | TreeNodeKind::PathNode(_)
                | TreeNodeKind::FsOp(_)
                | TreeNodeKind::NetDomain(_)
                | TreeNodeKind::ToolName(_) => {
                    if row.has_children {
                        if row.expanded {
                            hints.push(("h", "collapse"));
                        } else {
                            hints.push(("l", "expand"));
                        }
                        hints.push(("z/Z", "fold"));
                    }
                    hints.push(("Tab", "effect"));
                    hints.push(("e", "edit"));
                    hints.push(("d", "delete"));
                }
                TreeNodeKind::Domain(_) | TreeNodeKind::PolicyBlock { .. } => {
                    if row.has_children {
                        if row.expanded {
                            hints.push(("h", "collapse"));
                        } else {
                            hints.push(("l", "expand"));
                        }
                        hints.push(("z/Z", "fold"));
                    }
                    hints.push(("Tab", "effect"));
                    hints.push(("d", "delete"));
                }
                TreeNodeKind::Leaf { .. } => {
                    if row.has_children {
                        if row.expanded {
                            hints.push(("h", "collapse"));
                        } else {
                            hints.push(("l", "expand"));
                        }
                    }
                    hints.push(("Tab", "effect"));
                    hints.push(("e", "edit"));
                    hints.push(("E", "edit rule"));
                    hints.push(("d", "delete"));
                }
                TreeNodeKind::SandboxLeaf { .. } => {
                    hints.push(("Tab", "effect"));
                    hints.push(("e", "edit"));
                    hints.push(("E", "edit rule"));
                    hints.push(("d", "delete"));
                }
                TreeNodeKind::SandboxGroup => {
                    if row.has_children {
                        if row.expanded {
                            hints.push(("h", "collapse"));
                        } else {
                            hints.push(("l", "expand"));
                        }
                        hints.push(("z/Z", "fold"));
                    }
                }
                TreeNodeKind::HasMarker | TreeNodeKind::SandboxName(_) => {}
            }
        }
        None => {
            hints.push(("j/k", "move"));
        }
    }

    hints.push(("[/]", "all"));
    hints.push(("a", "add"));
    hints.push(("/", "search"));
    if app.search.query.is_some() {
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
    let match_info = if app.search.matches.is_empty() {
        if app.search.input.value().is_empty() {
            String::new()
        } else {
            " (no matches)".to_string()
        }
    } else {
        format!(
            " ({}/{} fuzzy)",
            app.search.match_cursor + 1,
            app.search.matches.len()
        )
    };

    let line = Line::from(vec![
        Span::styled("/", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(app.search.input.value()),
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
    let height = 34u16.min(area.height.saturating_sub(4));
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
        help_line(bold, "  e           ", "Edit node value inline"),
        help_line(bold, "  E           ", "Edit full rule s-expr"),
        help_line(bold, "  a           ", "Add a new rule"),
        help_line(bold, "  d           ", "Delete rule at cursor"),
        help_line(bold, "  w           ", "Save all changes"),
        help_line(bold, "  u           ", "Undo last edit"),
        help_line(bold, "  Ctrl+r      ", "Redo"),
        Line::from(""),
        help_line(bold, "  z           ", "Fold/unfold children"),
        help_line(bold, "  Z           ", "Fold/unfold subtree"),
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
        ConfirmAction::DeleteSandboxRule {
            sandbox_rule_text, ..
        } => (
            " Confirm Delete Sandbox Rule ",
            format!("Delete sandbox sub-rule?\n\n  {sandbox_rule_text}\n\ny/n"),
        ),
        ConfirmAction::DeleteBranch { label, leaves } => (
            " Confirm Branch Delete ",
            format!(
                "Delete {} rule{} under {}?\n\ny/n",
                leaves.len(),
                if leaves.len() == 1 { "" } else { "s" },
                label,
            ),
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
// Save diff overlay
// ---------------------------------------------------------------------------

fn render_save_diff_overlay(f: &mut Frame, app: &App, area: Rect) {
    let Mode::ConfirmSave(diff) = &app.mode else {
        return;
    };

    let width = 64u16.min(area.width.saturating_sub(4));
    let height = (area.height - 4).max(10).min(area.height.saturating_sub(2));
    let x = (area.width.saturating_sub(width)) / 2;
    let y = (area.height.saturating_sub(height)) / 2;
    let overlay = Rect::new(x, y, width, height);

    f.render_widget(Clear, overlay);

    let block = Block::default()
        .title(" Review Changes ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let mut lines: Vec<Line> = Vec::new();
    for hunk in &diff.hunks {
        lines.push(Line::from(Span::styled(
            format!("  {} policy:", hunk.level),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for dl in &hunk.lines {
            let (prefix, text, style) = match dl {
                DiffLine::Context(t) => ("  ", t.as_str(), tui_style::DIM),
                DiffLine::Added(t) => ("+ ", t.as_str(), Style::default().fg(Color::Green)),
                DiffLine::Removed(t) => ("- ", t.as_str(), Style::default().fg(Color::Red)),
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {prefix}"), style),
                Span::styled(text.to_string(), style),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::from(vec![
        Span::styled("  Save? ", tui_style::DIM),
        Span::styled("y", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(" confirm  ", tui_style::DIM),
        Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled("/", tui_style::DIM),
        Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(" cancel  ", tui_style::DIM),
        Span::styled("j/k", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(" scroll", tui_style::DIM),
    ]));

    let total = lines.len();
    let visible = inner.height as usize;
    let max_scroll = total.saturating_sub(visible);
    let scroll = diff.scroll.min(max_scroll);

    let para = Paragraph::new(lines)
        .scroll((scroll as u16, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(para, inner);
}

// ---------------------------------------------------------------------------
// Path filter description helper
// ---------------------------------------------------------------------------

/// Produce a human-readable explanation for a PathFilter.
fn describe_path_filter(pf: &PathFilter) -> String {
    match pf {
        PathFilter::Subpath(expr, worktree) => {
            let target = describe_path_expr(expr);
            let worktree_note = if *worktree {
                " (including git worktree directories)"
            } else {
                ""
            };
            format!(
                "Matches files recursively under {target} and all subdirectories{worktree_note}."
            )
        }
        PathFilter::Literal(s) => {
            format!("Matches the exact path \"{s}\".")
        }
        PathFilter::Regex(r) => {
            format!("Matches paths matching the regex /{r}/.")
        }
        PathFilter::Not(inner) => {
            let inner_desc = describe_path_filter(inner);
            format!("Negation: excludes paths where: {inner_desc}")
        }
        PathFilter::Or(filters) => {
            format!(
                "Matches any of {} alternative path patterns.",
                filters.len()
            )
        }
    }
}

/// Produce a human-readable description for a PathExpr.
fn describe_path_expr(expr: &PathExpr) -> String {
    match expr {
        PathExpr::Static(s) => format!("\"{s}\""),
        PathExpr::Env(name) => format!("the ${name} environment variable"),
        PathExpr::Join(parts) => {
            let descs: Vec<String> = parts.iter().map(describe_path_expr).collect();
            descs.join(" + ")
        }
    }
}

// ---------------------------------------------------------------------------
// Add rule overlay
// ---------------------------------------------------------------------------

fn render_add_rule_overlay(f: &mut Frame, app: &App, area: Rect) {
    let Mode::AddRule(form) = &app.mode else {
        return;
    };

    let width = 58u16.min(area.width.saturating_sub(4));
    // Dynamic height based on domain and path type
    let base_height: u16 = match form.domain_index {
        1 => {
            let path_steps: u16 = match form.path_type_index {
                0 => 9, // subpath: type + source + env/path + worktree
                1 => 3, // exact: type + path input
                2 => 3, // regex: type + regex input
                3 => 1, // any: just type selector
                _ => 3, // raw: type + text input
            };
            20 + path_steps
        }
        _ => 23,
    };
    let height = base_height.min(area.height.saturating_sub(4));
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

    // Copy all needed form data to avoid borrow issues with `app`
    let step = form.step;
    let domain_index = form.domain_index;
    let effect_index = form.effect_index;
    let level_index = form.level_index;
    let fs_op_index = form.fs_op_index;
    let path_type_index = form.path_type_index;
    let path_source_index = form.path_source_index;
    let env_var_index = form.env_var_index;
    let worktree = form.worktree;
    let binary_val = form.binary_input.value().to_string();
    let args_val = form.args_input.value().to_string();
    let path_val = form.path_input.value().to_string();
    let net_domain_val = form.net_domain_input.value().to_string();
    let tool_name_val = form.tool_name_input.value().to_string();
    let custom_env_val = form.custom_env_input.value().to_string();
    let static_path_val = form.static_path_input.value().to_string();
    let regex_path_val = form.regex_path_input.value().to_string();
    let level_names: Vec<String> = form
        .available_levels
        .iter()
        .map(|l| l.to_string())
        .collect();
    let error = form.error.clone();

    let mut lines: Vec<Line> = Vec::new();
    let mut step_num = 1;

    // 1. Command
    lines.push(step_label(
        &format!("{step_num}. Command"),
        matches!(step, AddRuleStep::EnterBinary),
    ));
    render_text_step(
        &mut lines,
        &binary_val,
        matches!(step, AddRuleStep::EnterBinary),
        "e.g. cargo, *, blank=any command",
        bold,
        dim,
    );
    lines.push(Line::from(""));
    step_num += 1;

    // 2. Args
    lines.push(step_label(
        &format!("{step_num}. Args"),
        matches!(step, AddRuleStep::EnterArgs),
    ));
    render_text_step(
        &mut lines,
        &args_val,
        matches!(step, AddRuleStep::EnterArgs),
        "space-separated, blank=any",
        bold,
        dim,
    );
    lines.push(Line::from(""));
    step_num += 1;

    // 3. Domain
    lines.push(step_label(
        &format!("{step_num}. Domain"),
        matches!(step, AddRuleStep::SelectDomain),
    ));
    lines.push(selector_line(
        DOMAIN_NAMES,
        domain_index,
        matches!(step, AddRuleStep::SelectDomain),
    ));
    lines.push(Line::from(""));
    step_num += 1;

    // 4. Permissions (domain-specific)
    match domain_index {
        0 => {
            // Exec: command+args already cover it
            lines.push(step_label(&format!("{step_num}. Permissions"), false));
            lines.push(Line::from(Span::styled(
                "   (covered by command + args)",
                dim,
            )));
            lines.push(Line::from(""));
            step_num += 1;
        }
        1 => {
            // Fs: Operation
            lines.push(step_label(
                &format!("{step_num}. Operation"),
                matches!(step, AddRuleStep::SelectFsOp),
            ));
            lines.push(selector_line(
                FS_OPS,
                fs_op_index,
                matches!(step, AddRuleStep::SelectFsOp),
            ));
            lines.push(Line::from(""));
            step_num += 1;

            // Path type selector
            lines.push(step_label(
                &format!("{step_num}. Path type"),
                matches!(step, AddRuleStep::SelectPathType),
            ));
            lines.push(selector_line(
                PATH_TYPES,
                path_type_index,
                matches!(step, AddRuleStep::SelectPathType),
            ));
            lines.push(Line::from(""));
            step_num += 1;

            // Conditional sub-steps based on path type
            match path_type_index {
                0 => {
                    // subpath: source → env/static → worktree
                    lines.push(step_label(
                        &format!("{step_num}. Path source"),
                        matches!(step, AddRuleStep::SelectPathSource),
                    ));
                    lines.push(selector_line(
                        PATH_SOURCES,
                        path_source_index,
                        matches!(step, AddRuleStep::SelectPathSource),
                    ));
                    lines.push(Line::from(""));
                    step_num += 1;

                    match path_source_index {
                        0 => {
                            // env variable
                            lines.push(step_label(
                                &format!("{step_num}. Env variable"),
                                matches!(step, AddRuleStep::SelectEnvVar),
                            ));
                            lines.push(selector_line(
                                COMMON_ENV_VARS,
                                env_var_index,
                                matches!(step, AddRuleStep::SelectEnvVar),
                            ));
                            lines.push(Line::from(""));
                            step_num += 1;

                            if env_var_index == COMMON_ENV_VARS.len() - 1 {
                                // custom env var
                                lines.push(step_label(
                                    &format!("{step_num}. Custom env var"),
                                    matches!(step, AddRuleStep::EnterCustomEnvVar),
                                ));
                                render_text_step(
                                    &mut lines,
                                    &custom_env_val,
                                    matches!(step, AddRuleStep::EnterCustomEnvVar),
                                    "e.g. VIRTUAL_ENV",
                                    bold,
                                    dim,
                                );
                                lines.push(Line::from(""));
                                step_num += 1;
                            }
                        }
                        _ => {
                            // static path
                            lines.push(step_label(
                                &format!("{step_num}. Static path"),
                                matches!(step, AddRuleStep::EnterStaticPath),
                            ));
                            render_text_step(
                                &mut lines,
                                &static_path_val,
                                matches!(step, AddRuleStep::EnterStaticPath),
                                "e.g. /tmp, /home/user/.config",
                                bold,
                                dim,
                            );
                            lines.push(Line::from(""));
                            step_num += 1;
                        }
                    }

                    // Worktree toggle
                    let wt_idx = if worktree { 1 } else { 0 };
                    lines.push(step_label(
                        &format!("{step_num}. Worktree?"),
                        matches!(step, AddRuleStep::ToggleWorktree),
                    ));
                    lines.push(selector_line(
                        WORKTREE_OPTIONS,
                        wt_idx,
                        matches!(step, AddRuleStep::ToggleWorktree),
                    ));
                    lines.push(Line::from(""));
                    step_num += 1;
                }
                1 => {
                    // exact: static path input
                    lines.push(step_label(
                        &format!("{step_num}. Exact path"),
                        matches!(step, AddRuleStep::EnterStaticPath),
                    ));
                    render_text_step(
                        &mut lines,
                        &static_path_val,
                        matches!(step, AddRuleStep::EnterStaticPath),
                        "e.g. /etc/passwd, /tmp/file.txt",
                        bold,
                        dim,
                    );
                    lines.push(Line::from(""));
                    step_num += 1;
                }
                2 => {
                    // regex: regex input
                    lines.push(step_label(
                        &format!("{step_num}. Regex pattern"),
                        matches!(step, AddRuleStep::EnterRegexPath),
                    ));
                    render_text_step(
                        &mut lines,
                        &regex_path_val,
                        matches!(step, AddRuleStep::EnterRegexPath),
                        "e.g. .*\\.rs, /tmp/.*",
                        bold,
                        dim,
                    );
                    lines.push(Line::from(""));
                    step_num += 1;
                }
                3 => {
                    // any: no extra steps
                }
                _ => {
                    // raw s-expr: legacy text input
                    lines.push(step_label(
                        &format!("{step_num}. Path (s-expr)"),
                        matches!(step, AddRuleStep::EnterPath),
                    ));
                    render_text_step(
                        &mut lines,
                        &path_val,
                        matches!(step, AddRuleStep::EnterPath),
                        "e.g. (subpath (env PWD)), blank=any",
                        bold,
                        dim,
                    );
                    lines.push(Line::from(""));
                    step_num += 1;
                }
            }
        }
        2 => {
            // Net: host
            lines.push(step_label(
                &format!("{step_num}. Host"),
                matches!(step, AddRuleStep::EnterNetDomain),
            ));
            render_text_step(
                &mut lines,
                &net_domain_val,
                matches!(step, AddRuleStep::EnterNetDomain),
                "e.g. example.com, *, blank=any",
                bold,
                dim,
            );
            lines.push(Line::from(""));
            step_num += 1;
        }
        _ => {
            // Tool: name
            lines.push(step_label(
                &format!("{step_num}. Tool name"),
                matches!(step, AddRuleStep::EnterToolName),
            ));
            render_text_step(
                &mut lines,
                &tool_name_val,
                matches!(step, AddRuleStep::EnterToolName),
                "e.g. Bash, *, blank=any",
                bold,
                dim,
            );
            lines.push(Line::from(""));
            step_num += 1;
        }
    }

    // Effect
    lines.push(step_label(
        &format!("{step_num}. Effect"),
        matches!(step, AddRuleStep::SelectEffect),
    ));
    lines.push(selector_line(
        EFFECT_NAMES,
        effect_index,
        matches!(step, AddRuleStep::SelectEffect),
    ));
    lines.push(Line::from(""));
    step_num += 1;

    // Level
    lines.push(step_label(
        &format!("{step_num}. Level"),
        matches!(step, AddRuleStep::SelectLevel),
    ));
    let level_strs: Vec<&str> = level_names.iter().map(|s| s.as_str()).collect();
    lines.push(selector_line(
        &level_strs,
        level_index,
        matches!(step, AddRuleStep::SelectLevel),
    ));

    // Error
    if let Some(err) = error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            err,
            tui_style::DENY.add_modifier(Modifier::BOLD),
        )));
    }

    let para = Paragraph::new(lines);
    f.render_widget(para, inner);
}

/// Render a text input step: shows the input value (with cursor when active) and a hint line.
fn render_text_step(
    lines: &mut Vec<Line<'static>>,
    value: &str,
    is_active: bool,
    hint: &str,
    bold: Style,
    dim: Style,
) {
    if is_active {
        lines.push(Line::from(vec![
            Span::styled("   > ", dim),
            Span::raw(value.to_string()),
            Span::styled("_", bold),
        ]));
        lines.push(Line::from(Span::styled(format!("   {hint}"), dim)));
    } else {
        let display = if value.is_empty() {
            "(empty)".to_string()
        } else {
            value.to_string()
        };
        lines.push(Line::from(Span::styled(format!("   {display}"), dim)));
    }
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

pub(crate) fn selector_line(options: &[&str], selected: usize, is_active: bool) -> Line<'static> {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::policy::Effect;
    use crate::policy::ast::Rule;
    use crate::settings::{LoadedPolicy, PolicyLevel};
    use crate::tui::app::{App, ConfirmAction, Mode, parse_rule_text};
    use crate::tui::tree::DomainKind;

    fn test_policy(level: PolicyLevel, source: &str) -> LoadedPolicy {
        LoadedPolicy {
            level,
            path: PathBuf::from("/tmp/test"),
            source: source.to_string(),
        }
    }

    fn make_app(source: &str) -> App {
        let policy = test_policy(PolicyLevel::User, source);
        App::new(&[policy])
    }

    /// Build a FlatRow with a dummy node_id (only useful for depth/expanded/connectors).
    /// Tests that call render_row or description_for_row pass the kind separately.
    fn make_leaf_row_parts(
        effect: Effect,
        rule: Rule,
        level: PolicyLevel,
        policy: &str,
    ) -> (TreeNodeKind, FlatRow) {
        let kind = TreeNodeKind::Leaf {
            effect,
            rule,
            level,
            policy: policy.to_string(),
            is_shadowed: false,
        };
        // We use a dummy NodeId(0) — only the depth/expanded/connectors matter for render_row.
        let row = FlatRow {
            node_id: NodeId::dummy(),
            depth: 2,
            expanded: false,
            has_children: false,
            connectors: vec![false, false],
        };
        (kind, row)
    }

    fn make_binary_row_parts(name: &str, expanded: bool) -> (TreeNodeKind, FlatRow) {
        let kind = TreeNodeKind::Binary(name.to_string());
        let row = FlatRow {
            node_id: NodeId::dummy(),
            depth: 0,
            expanded,
            has_children: true,
            connectors: vec![],
        };
        (kind, row)
    }

    fn render_to_string(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| render(f, app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // -----------------------------------------------------------------------
    // Unit tests on pure functions
    // -----------------------------------------------------------------------

    #[test]
    fn effect_display_values() {
        assert_eq!(effect_display(Effect::Ask), "ask");
        assert_eq!(effect_display(Effect::Allow), "auto allow");
        assert_eq!(effect_display(Effect::Deny), "auto deny");
    }

    #[test]
    fn render_row_leaf_shows_effect() {
        let rule = parse_rule_text("(allow (exec \"git\"))").unwrap();
        let (kind, row) = make_leaf_row_parts(Effect::Allow, rule, PolicyLevel::User, "main");
        let line = render_row(&row, &kind, false, false, &InlineEdit::None, &[]);

        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            text.contains("auto allow"),
            "line should contain effect: {text}"
        );
    }

    #[test]
    fn render_row_binary_node() {
        let (kind, row) = make_binary_row_parts("git", true);
        let line = render_row(&row, &kind, false, false, &InlineEdit::None, &[]);

        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            text.contains("git"),
            "line should contain binary name: {text}"
        );
    }

    #[test]
    fn render_row_collapsed_shows_summary() {
        let summary = vec![
            Span::styled("  ", tui_style::DIM),
            Span::styled("1 auto allow", tui_style::ALLOW),
        ];
        let (kind, row) = make_binary_row_parts("git", false);
        let line = render_row(&row, &kind, false, false, &InlineEdit::None, &summary);

        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            text.contains("1 auto allow"),
            "collapsed row should show summary: {text}"
        );
    }

    #[test]
    fn render_row_selected_styling() {
        let (kind, row) = make_binary_row_parts("git", true);
        let line = render_row(&row, &kind, true, false, &InlineEdit::None, &[]);

        assert_eq!(line.style, tui_style::SELECTED);
    }

    #[test]
    fn render_row_search_match_styling() {
        let (kind, row) = make_binary_row_parts("git", true);
        let line = render_row(&row, &kind, false, true, &InlineEdit::None, &[]);

        assert!(
            line.style.add_modifier.contains(Modifier::UNDERLINED),
            "search match row should be underlined"
        );
    }

    #[test]
    fn description_for_row_leaf() {
        let rule = parse_rule_text("(allow (exec \"git\"))").unwrap();
        let (kind, _row) = make_leaf_row_parts(Effect::Allow, rule, PolicyLevel::User, "main");
        let lines = description_for_row(&kind);

        assert!(lines.len() >= 2);
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(text.contains("AUTO ALLOW"), "should contain effect: {text}");
        assert!(text.contains("main"), "should contain policy name: {text}");
    }

    #[test]
    fn description_for_row_binary() {
        let (kind, _row) = make_binary_row_parts("git", true);
        let lines = description_for_row(&kind);

        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(text.contains("Binary:"), "should say Binary: {text}");
        assert!(text.contains("git"));
    }

    #[test]
    fn description_for_row_domain() {
        let kind = TreeNodeKind::Domain(DomainKind::Exec);
        let lines = description_for_row(&kind);

        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter().map(|s| s.content.to_string()))
            .collect();
        assert!(
            text.contains("Exec capability rules"),
            "should describe domain: {text}"
        );
    }

    #[test]
    fn context_hints_on_leaf() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.expand_all();

        // Move cursor to the leaf
        app.tree.cursor_to_bottom();
        let hints = context_hints(&app);

        let keys: Vec<&str> = hints.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"Tab"), "leaf should have Tab hint");
        assert!(keys.contains(&"e"), "leaf should have e hint");
        assert!(keys.contains(&"d"), "leaf should have d hint");
    }

    #[test]
    fn context_hints_on_branch() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.expand_all();
        app.tree.cursor_to_top(); // root is a branch

        let hints = context_hints(&app);
        let keys: Vec<&str> = hints.iter().map(|(k, _)| *k).collect();
        // Should have collapse hint since it's expanded
        assert!(keys.contains(&"h"), "expanded branch should have h hint");
    }

    #[test]
    fn context_hints_on_sandbox_leaf() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs))))"#);
        app.expand_all();

        // Find the SandboxLeaf row
        let sbx_idx = app.tree.flat_rows.iter().position(|r| {
            matches!(
                &app.tree.arena[r.node_id].kind,
                TreeNodeKind::SandboxLeaf { .. }
            )
        });
        assert!(sbx_idx.is_some(), "should have a SandboxLeaf row");
        app.tree.cursor = sbx_idx.unwrap();

        let hints = context_hints(&app);
        let keys: Vec<&str> = hints.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"Tab"), "sandbox leaf should have Tab hint");
        assert!(keys.contains(&"e"), "sandbox leaf should have e hint");
        assert!(keys.contains(&"d"), "sandbox leaf should have d hint");
    }

    #[test]
    fn context_hints_with_search() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.search.query = Some("git".to_string());

        let hints = context_hints(&app);
        let keys: Vec<&str> = hints.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"n/N"), "active search should show n/N hint");
    }

    #[test]
    fn selector_line_active() {
        let line = selector_line(&["a", "b", "c"], 1, true);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            text.contains("←/→ Tab Enter"),
            "active should show navigation hints: {text}"
        );
    }

    #[test]
    fn selector_line_inactive() {
        let line = selector_line(&["a", "b", "c"], 1, false);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            !text.contains("←/→"),
            "inactive should not show navigation hints: {text}"
        );

        // Selected item (index 1 = "b") should be bold.
        // Spans: [0]="   ", [1]=" a ", [2]="  ", [3]=" b ", [4]="  ", [5]=" c "
        let selected_span = &line.spans[3];
        assert!(
            selected_span.style.add_modifier.contains(Modifier::BOLD),
            "selected span should be bold, got style {:?} for {:?}",
            selected_span.style,
            selected_span.content
        );
    }

    // -----------------------------------------------------------------------
    // TestBackend integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn render_empty_policy() {
        let app = make_app("");
        let output = render_to_string(&app, 80, 24);
        assert!(
            output.contains("No policy rules loaded"),
            "empty policy should show message: {output}"
        );
    }

    #[test]
    fn render_header_shows_level() {
        let app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        let output = render_to_string(&app, 80, 24);
        assert!(
            output.contains("user"),
            "header should contain level name: {output}"
        );
        assert!(
            output.contains("? help"),
            "header should contain help hint: {output}"
        );
    }

    #[test]
    fn render_tree_shows_binary() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.expand_all();
        let output = render_to_string(&app, 80, 24);
        assert!(
            output.contains("git"),
            "tree should contain binary name: {output}"
        );
    }

    #[test]
    fn render_add_rule_overlay_visible() {
        let mut app = make_app(r#"(policy "main")"#);
        app.start_add_rule();
        let output = render_to_string(&app, 80, 40);
        assert!(
            output.contains("Add Rule"),
            "add rule overlay should be visible: {output}"
        );
    }

    #[test]
    fn render_confirm_overlay_delete() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.mode = Mode::Confirm(ConfirmAction::DeleteRule {
            level: PolicyLevel::User,
            policy: "main".to_string(),
            rule_text: "(allow (exec \"git\"))".to_string(),
        });
        let output = render_to_string(&app, 80, 24);
        assert!(
            output.contains("Confirm Delete"),
            "confirm delete overlay should be visible: {output}"
        );
    }

    #[test]
    fn render_help_overlay() {
        let mut app = make_app("");
        app.show_help = true;
        let output = render_to_string(&app, 80, 40);
        assert!(
            output.contains("Keyboard Shortcuts"),
            "help overlay should be visible: {output}"
        );
    }

    #[test]
    fn render_row_sandbox_leaf() {
        let parent_rule = parse_rule_text(r#"(ask (exec "ls") :sandbox (allow (fs)))"#).unwrap();
        let sandbox_rule = parse_rule_text("(allow (fs))").unwrap();
        let kind = TreeNodeKind::SandboxLeaf {
            effect: Effect::Allow,
            sandbox_rule,
            parent_rule,
            level: PolicyLevel::User,
            policy: "main".to_string(),
        };
        let row = FlatRow {
            node_id: NodeId::dummy(),
            depth: 3,
            expanded: false,
            has_children: false,
            connectors: vec![false, false, false],
        };
        let line = render_row(&row, &kind, false, false, &InlineEdit::None, &[]);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            text.contains("auto allow"),
            "sandbox leaf should show effect: {text}"
        );
        assert!(
            text.contains("[sandbox]"),
            "sandbox leaf should show [sandbox] tag: {text}"
        );
    }

    #[test]
    fn render_row_leaf_sandbox_indicator() {
        let rule = parse_rule_text(r#"(ask (exec "ls" "-lha") :sandbox (allow (fs)))"#).unwrap();
        let kind = TreeNodeKind::Leaf {
            effect: Effect::Ask,
            rule,
            level: PolicyLevel::User,
            policy: "main".to_string(),
            is_shadowed: false,
        };
        let row = FlatRow {
            node_id: NodeId::dummy(),
            depth: 2,
            expanded: false,
            has_children: true,
            connectors: vec![false, false],
        };
        let line = render_row(&row, &kind, false, false, &InlineEdit::None, &[]);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(
            text.contains("sandboxed"),
            "leaf with inline sandbox should show 'sandboxed': {text}"
        );
    }

    // -----------------------------------------------------------------------
    // Snapshot tests (insta)
    // -----------------------------------------------------------------------

    const REALISTIC_POLICY: &str = r#"(policy "main"
  (allow (exec "git" *))
  (deny (exec "rm" "-rf" *))
  (ask (exec "sudo" *))
  (allow (fs read (subpath (env PWD))))
  (deny (net "evil.com"))
  (ask (tool "Bash"))
)"#;

    const SANDBOX_POLICY: &str = r#"(policy "main"
  (ask (exec "ls" "-lha") :sandbox (allow (fs read)) (deny (net *)))
  (allow (exec "cargo" *) :sandbox "cargo-env")
)"#;

    #[test]
    fn snapshot_collapsed_tree() {
        let app = make_app(REALISTIC_POLICY);
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_expanded_tree() {
        let mut app = make_app(REALISTIC_POLICY);
        app.expand_all();
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_search_active() {
        let mut app = make_app(REALISTIC_POLICY);
        app.start_search();
        app.search.input = super::super::editor::TextInput::new("git");
        app.update_search_live();
        app.mode = Mode::Search;
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_add_rule_overlay() {
        let mut app = make_app(REALISTIC_POLICY);
        app.start_add_rule();
        let output = render_to_string(&app, 80, 40);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_confirm_delete_overlay() {
        let mut app = make_app(REALISTIC_POLICY);
        app.mode = Mode::Confirm(ConfirmAction::DeleteRule {
            level: PolicyLevel::User,
            policy: "main".to_string(),
            rule_text: r#"(allow (exec "git" *))"#.to_string(),
        });
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_help_overlay() {
        let mut app = make_app(REALISTIC_POLICY);
        app.show_help = true;
        let output = render_to_string(&app, 80, 40);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_edit_rule_mode() {
        let mut app = make_app(REALISTIC_POLICY);
        app.expand_all();
        app.tree.cursor_to_bottom();
        app.start_edit_rule();
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_sandbox_expanded() {
        let mut app = make_app(SANDBOX_POLICY);
        app.expand_all();
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_empty_policy() {
        let app = make_app("");
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_save_diff_overlay() {
        let mut app = make_app(REALISTIC_POLICY);
        // Make a change so save_all produces a diff
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = super::super::editor::TextInput::new("cargo");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.save_all();
        assert!(matches!(app.mode, Mode::ConfirmSave(_)));
        let output = render_to_string(&app, 80, 30);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_multi_level() {
        let user = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git" *)))"#,
        );
        let project = test_policy(
            PolicyLevel::Project,
            r#"(policy "main" (deny (exec "git" "push" *)))"#,
        );
        let mut app = App::new(&[user, project]);
        app.expand_all();
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn snapshot_shadowed_rule() {
        let user = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git" *)))"#,
        );
        let project = test_policy(
            PolicyLevel::Project,
            r#"(policy "main" (deny (exec "git" *)))"#,
        );
        let mut app = App::new(&[user, project]);
        app.expand_all();
        // Move cursor to the shadowed User leaf
        for (i, row) in app.tree.flat_rows.iter().enumerate() {
            if let TreeNodeKind::Leaf {
                is_shadowed: true, ..
            } = &app.tree.arena[row.node_id].kind
            {
                app.tree.cursor = i;
                break;
            }
        }
        let output = render_to_string(&app, 80, 24);
        insta::assert_snapshot!(output);
    }
}
