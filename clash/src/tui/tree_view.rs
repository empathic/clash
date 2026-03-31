//! Tree view component for browsing and editing policy rules.

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::tea::{Action, Component, FormRequest};
use crate::policy::format::{format_condition, format_decision};
use crate::policy::match_tree::{CompiledPolicy, MatchVerdict, Node, PolicyManifest};

/// A flattened node in the tree for display purposes.
pub struct FlatNode {
    /// Indentation depth.
    pub depth: usize,
    /// Display label for this node.
    pub label: String,
    /// Path of child indices from root to this node.
    /// Empty `node_path` means this is the synthetic root.
    pub node_path: Vec<usize>,
    /// Whether this node is a leaf (Decision or inline condition->decision).
    pub is_leaf: bool,
    /// Whether this node has children (for expand/collapse).
    pub has_children: bool,
    /// The decision at this node, if it's a leaf.
    pub decision: Option<MatchVerdict>,
    /// Whether this is the synthetic root node.
    pub is_root: bool,
    /// Whether this node came from an include file (read-only).
    pub read_only: bool,
    /// Source provenance for included rules (e.g. "rules.star").
    pub source: Option<String>,
}

pub struct TreeView {
    flat_nodes: Vec<FlatNode>,
    pub selected: usize,
    scroll_offset: usize,
    collapsed: HashSet<Vec<usize>>,
    /// Snapshot of included rules for rebuild after collapse/expand.
    included: CompiledPolicy,
}

#[derive(Debug)]
pub enum Msg {
    MoveUp,
    MoveDown,
    JumpTop,
    JumpBottom,
    Expand,
    Collapse,
    ToggleExpand,
    ExpandAll,
    CollapseAll,
    Edit,
    Delete,
    Add,
    CopyToInline,
}

impl TreeView {
    /// Sentinel path used for the "included" section header so it can be
    /// independently collapsed/expanded.
    const INCLUDED_SECTION_PATH: [usize; 1] = [usize::MAX];

    pub fn new(manifest: &PolicyManifest, included: &CompiledPolicy) -> Self {
        let mut collapsed = HashSet::new();
        // Default the included section to collapsed so new users focus on
        // their own rules first.
        collapsed.insert(Self::INCLUDED_SECTION_PATH.to_vec());
        let mut view = TreeView {
            flat_nodes: Vec::new(),
            selected: 0,
            scroll_offset: 0,
            collapsed,
            included: included.clone(),
        };
        view.rebuild(manifest);
        view
    }

    /// Rebuild the flat node list from the manifest's tree.
    pub fn rebuild(&mut self, manifest: &PolicyManifest) {
        let included = self.included.clone();
        self.rebuild_inner(manifest, &included);
    }

    /// Update the included snapshot and rebuild.
    pub fn rebuild_with_included(&mut self, manifest: &PolicyManifest, included: &CompiledPolicy) {
        self.included = included.clone();
        self.rebuild_inner(manifest, included);
    }

    fn rebuild_inner(&mut self, manifest: &PolicyManifest, included: &CompiledPolicy) {
        self.flat_nodes.clear();

        let has_any = !manifest.policy.tree.is_empty() || !included.tree.is_empty();

        // Synthetic root node
        let root_collapsed = self.collapsed.contains(&vec![]);
        self.flat_nodes.push(FlatNode {
            depth: 0,
            label: "rules".to_string(),
            node_path: vec![],
            is_leaf: false,
            has_children: has_any,
            decision: None,
            is_root: true,
            read_only: false,
            source: None,
        });

        if !root_collapsed {
            for (i, node) in manifest.policy.tree.iter().enumerate() {
                self.flatten_node(node, 1, vec![i], false);
            }

            // Append included rules as read-only, collapsible section
            if !included.tree.is_empty() {
                let included_path = Self::INCLUDED_SECTION_PATH.to_vec();
                let included_collapsed = self.collapsed.contains(&included_path);

                let label = if included_collapsed && !manifest.includes.is_empty() {
                    let files: Vec<&str> = manifest
                        .includes
                        .iter()
                        .map(|inc| {
                            // Show just the filename, stripping @clash// prefix and directory
                            inc.path.rsplit('/').next().unwrap_or(&inc.path)
                        })
                        .collect();
                    format!("── included ({}) ──", files.join(", "))
                } else {
                    "── included ──".to_string()
                };

                self.flat_nodes.push(FlatNode {
                    depth: 1,
                    label,
                    node_path: included_path,
                    is_leaf: false,
                    has_children: true,
                    decision: None,
                    is_root: false,
                    read_only: true,
                    source: None,
                });

                if !included_collapsed {
                    for (i, node) in included.tree.iter().enumerate() {
                        // Use a high offset so paths don't collide with inline nodes
                        self.flatten_node(node, 2, vec![10000 + i], true);
                    }
                }
            }
        }

        if self.selected >= self.flat_nodes.len() && !self.flat_nodes.is_empty() {
            self.selected = self.flat_nodes.len() - 1;
        }
    }

    fn flatten_node(&mut self, node: &Node, depth: usize, path: Vec<usize>, read_only: bool) {
        match node {
            Node::Decision(d) => {
                self.flat_nodes.push(FlatNode {
                    depth,
                    label: format_decision(d),
                    node_path: path,
                    is_leaf: true,
                    has_children: false,
                    decision: Some(d.clone()),
                    is_root: false,
                    read_only,
                    source: None,
                });
            }
            Node::Condition {
                observe,
                pattern,
                children,
                source,
                ..
            } => {
                let label = format_condition(observe, pattern);
                let has_children = !children.is_empty();

                // Check if this is a single-decision child (inline display)
                let is_inline_leaf =
                    children.len() == 1 && matches!(&children[0], Node::Decision(_));
                let decision = if is_inline_leaf {
                    if let Node::Decision(d) = &children[0] {
                        Some(d.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };

                let display_label = if let Some(ref d) = decision {
                    format!("{label} -> {}", format_decision(d))
                } else {
                    label
                };

                let is_collapsed = self.collapsed.contains(&path);
                self.flat_nodes.push(FlatNode {
                    depth,
                    label: display_label,
                    node_path: path.clone(),
                    is_leaf: is_inline_leaf,
                    has_children: has_children && !is_inline_leaf,
                    decision,
                    is_root: false,
                    read_only,
                    source: source.clone(),
                });

                // If it's an inline leaf (condition -> decision), don't recurse
                if is_inline_leaf {
                    return;
                }

                // Only show children if not collapsed
                if !is_collapsed {
                    for (i, child) in children.iter().enumerate() {
                        let mut child_path = path.clone();
                        child_path.push(i);
                        self.flatten_node(child, depth + 1, child_path, read_only);
                    }
                }
            }
        }
    }

    /// Remove a node at a given path from the tree.
    fn remove_node_at_path(tree: &mut Vec<Node>, path: &[usize]) {
        if path.is_empty() {
            return;
        }
        if path.len() == 1 {
            if path[0] < tree.len() {
                tree.remove(path[0]);
            }
            return;
        }
        let parent_path = &path[..path.len() - 1];
        // Safety: path.len() >= 2 since the len()==1 case returned above.
        let child_idx = *path.last().expect("path is non-empty");
        if let Some(parent) = Self::get_node_at_path_mut(tree, parent_path)
            && let Node::Condition { children, .. } = parent
            && child_idx < children.len()
        {
            children.remove(child_idx);
        }
    }

    /// Get a mutable node at a given path in the tree.
    fn get_node_at_path_mut<'a>(tree: &'a mut [Node], path: &[usize]) -> Option<&'a mut Node> {
        if path.is_empty() {
            return None;
        }
        let mut current = tree.get_mut(path[0])?;
        for &idx in &path[1..] {
            match current {
                Node::Condition { children, .. } => {
                    current = children.get_mut(idx)?;
                }
                Node::Decision(_) => return None,
            }
        }
        Some(current)
    }

    pub fn get_node_at_path_ref<'a>(tree: &'a [Node], path: &[usize]) -> Option<&'a Node> {
        if path.is_empty() {
            return None;
        }
        let mut current = tree.get(path[0])?;
        for &idx in &path[1..] {
            match current {
                Node::Condition { children, .. } => {
                    current = children.get(idx)?;
                }
                Node::Decision(_) => return None,
            }
        }
        Some(current)
    }
}

impl Component for TreeView {
    type Msg = Msg;

    fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => Some(Msg::MoveDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Msg::MoveUp),
            KeyCode::Char('g') => Some(Msg::JumpTop),
            KeyCode::Char('G') => Some(Msg::JumpBottom),
            KeyCode::Char('h') | KeyCode::Left => Some(Msg::Collapse),
            KeyCode::Char('l') | KeyCode::Right => Some(Msg::Expand),
            KeyCode::Char(' ') => Some(Msg::ToggleExpand),
            KeyCode::Char('[') => Some(Msg::CollapseAll),
            KeyCode::Char(']') => Some(Msg::ExpandAll),
            KeyCode::Char('e') => Some(Msg::Edit),
            KeyCode::Char('d') => Some(Msg::Delete),
            KeyCode::Char('a') => Some(Msg::Add),
            KeyCode::Char('c') => Some(Msg::CopyToInline),
            _ => None,
        }
    }

    fn update(&mut self, msg: Msg, manifest: &mut PolicyManifest) -> Action {
        match msg {
            Msg::MoveDown => {
                if !self.flat_nodes.is_empty() {
                    self.selected = (self.selected + 1).min(self.flat_nodes.len() - 1);
                }
                Action::None
            }
            Msg::MoveUp => {
                self.selected = self.selected.saturating_sub(1);
                Action::None
            }
            Msg::JumpTop => {
                self.selected = 0;
                Action::None
            }
            Msg::JumpBottom => {
                if !self.flat_nodes.is_empty() {
                    self.selected = self.flat_nodes.len() - 1;
                }
                Action::None
            }
            Msg::Collapse => {
                if let Some(node) = self.flat_nodes.get(self.selected)
                    && node.has_children
                {
                    self.collapsed.insert(node.node_path.clone());
                    self.rebuild_preserve_selection(manifest);
                }
                Action::None
            }
            Msg::Expand => {
                if let Some(node) = self.flat_nodes.get(self.selected) {
                    self.collapsed.remove(&node.node_path);
                    self.rebuild_preserve_selection(manifest);
                }
                Action::None
            }
            Msg::ToggleExpand => {
                if let Some(node) = self.flat_nodes.get(self.selected) {
                    let path = node.node_path.clone();
                    if self.collapsed.contains(&path) {
                        self.collapsed.remove(&path);
                    } else if node.has_children {
                        self.collapsed.insert(path);
                    }
                    self.rebuild_preserve_selection(manifest);
                }
                Action::None
            }
            Msg::ExpandAll => {
                self.collapsed.clear();
                self.rebuild_preserve_selection(manifest);
                Action::None
            }
            Msg::CollapseAll => {
                // Collapse all condition nodes that have expandable children
                for i in 0..manifest.policy.tree.len() {
                    if let Node::Condition { children, .. } = &manifest.policy.tree[i]
                        && (children.len() > 1
                            || (children.len() == 1 && !matches!(&children[0], Node::Decision(_))))
                    {
                        self.collapsed.insert(vec![i]);
                    }
                }
                self.rebuild_preserve_selection(manifest);
                Action::None
            }
            Msg::Edit => {
                let Some(node) = self.flat_nodes.get(self.selected) else {
                    return Action::None;
                };
                if node.is_root {
                    return Action::Flash("Use 'a' to add rules".into());
                }
                if node.read_only {
                    return Action::Flash("Included rules are read-only".into());
                }
                let path = node.node_path.clone();
                if node.is_leaf {
                    // Check if this is an inline leaf (Condition→Decision) or a
                    // bare Decision node.
                    let is_condition = Self::get_node_at_path_ref(&manifest.policy.tree, &path)
                        .is_some_and(|n| matches!(n, Node::Condition { .. }));

                    if is_condition {
                        // Inline leaf: edit the full rule (match + effect).
                        Action::RunForm(FormRequest::EditRule { path })
                    } else {
                        // Bare decision: edit effect only.
                        Action::RunForm(FormRequest::EditDecision { path })
                    }
                } else {
                    // Non-leaf condition: edit the observable/pattern.
                    Action::RunForm(FormRequest::EditCondition { path })
                }
            }
            Msg::Delete => {
                let Some(node) = self.flat_nodes.get(self.selected) else {
                    return Action::None;
                };
                if node.is_root {
                    return Action::Flash("Cannot delete root node".into());
                }
                if node.read_only {
                    return Action::Flash("Included rules are read-only".into());
                }
                let path = node.node_path.clone();
                if path.len() == 1 {
                    // Top-level node — remove directly
                    if path[0] < manifest.policy.tree.len() {
                        manifest.policy.tree.remove(path[0]);
                        self.rebuild(manifest);
                        return Action::Modified;
                    }
                } else if path.len() >= 2 {
                    // Child node — remove from parent's children
                    let parent_path = &path[..path.len() - 1];
                    // Safety: path.len() >= 2 guarantees non-empty.
                    let child_idx = *path.last().expect("path is non-empty");
                    if let Some(parent) =
                        Self::get_node_at_path_mut(&mut manifest.policy.tree, parent_path)
                        && let Node::Condition { children, .. } = parent
                        && child_idx < children.len()
                    {
                        children.remove(child_idx);
                        // If parent has no children left, remove the parent too
                        if children.is_empty() {
                            Self::remove_node_at_path(&mut manifest.policy.tree, parent_path);
                        }
                        self.rebuild(manifest);
                        return Action::Modified;
                    }
                }
                Action::None
            }
            Msg::Add => {
                let Some(node) = self.flat_nodes.get(self.selected) else {
                    return Action::None;
                };
                if node.is_root {
                    // Add a new top-level rule
                    return Action::RunForm(FormRequest::AddRule);
                }
                if node.read_only {
                    return Action::Flash("Cannot add to included rules".into());
                }
                let path = node.node_path.clone();
                if let Some(tree_node) =
                    Self::get_node_at_path_mut(&mut manifest.policy.tree, &path)
                    && matches!(tree_node, Node::Condition { .. })
                {
                    // Condition node (including inline leaves) — add child
                    return Action::RunForm(FormRequest::AddChild { parent_path: path });
                }
                // Bare Decision — add a sibling by targeting the parent condition
                if path.len() >= 2 {
                    let parent_path = path[..path.len() - 1].to_vec();
                    return Action::RunForm(FormRequest::AddChild { parent_path });
                }
                Action::Flash("Select a condition node or root to add children".into())
            }
            Msg::CopyToInline => {
                let Some(node) = self.flat_nodes.get(self.selected) else {
                    return Action::None;
                };
                if node.is_root {
                    return Action::Flash("Cannot copy root node".into());
                }
                let path = &node.node_path;
                // Look up the node in included tree (paths >= 10000) or inline tree
                let cloned = if path.first().is_some_and(|&i| i >= 10000) {
                    let idx = path[0] - 10000;
                    let tree = &self.included.tree;
                    if path.len() == 1 {
                        tree.get(idx).cloned()
                    } else {
                        let sub_path: Vec<usize> = std::iter::once(idx)
                            .chain(path[1..].iter().copied())
                            .collect();
                        Self::get_node_at_path_ref(tree, &sub_path).cloned()
                    }
                } else {
                    Self::get_node_at_path_ref(&manifest.policy.tree, path).cloned()
                };

                match cloned {
                    Some(mut copied) => {
                        // Strip source provenance — it's now an inline rule
                        if let Node::Condition { ref mut source, .. } = copied {
                            *source = None;
                        }
                        manifest.policy.tree.push(copied);
                        self.rebuild(manifest);
                        Action::Modified
                    }
                    None => Action::Flash("Could not copy node".into()),
                }
            }
        }
    }

    fn view(&self, frame: &mut Frame, area: Rect, _manifest: &PolicyManifest) {
        let block = Block::default()
            .borders(Borders::LEFT | Borders::RIGHT)
            .border_style(Style::default().fg(Color::DarkGray));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let visible_height = inner.height as usize;
        // Adjust scroll offset to keep selected visible
        let scroll = if self.selected < self.scroll_offset {
            self.selected
        } else if self.selected >= self.scroll_offset + visible_height {
            self.selected - visible_height + 1
        } else {
            self.scroll_offset
        };

        let lines: Vec<Line> = self
            .flat_nodes
            .iter()
            .enumerate()
            .skip(scroll)
            .take(visible_height)
            .map(|(i, node)| {
                let indent = if node.depth > 0 {
                    "  ".repeat(node.depth)
                } else {
                    String::new()
                };
                let marker = if node.is_root {
                    if node.has_children {
                        if self.collapsed.contains(&node.node_path) {
                            "▶ "
                        } else {
                            "▼ "
                        }
                    } else {
                        "  "
                    }
                } else if node.has_children {
                    if self.collapsed.contains(&node.node_path) {
                        "▶ "
                    } else {
                        "▼ "
                    }
                } else {
                    "  "
                };

                let style = if i == self.selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else if node.is_root {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else if node.read_only {
                    // Included rules are dimmed
                    decision_style(node.decision.as_ref()).add_modifier(Modifier::DIM)
                } else {
                    decision_style(node.decision.as_ref())
                };

                let mut spans = vec![Span::styled(
                    format!("  {indent}{marker}{}", node.label),
                    style,
                )];
                if let Some(ref src) = node.source {
                    spans.push(Span::styled(
                        format!("  ({src})"),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                Line::from(spans)
            })
            .collect();

        let para = Paragraph::new(lines);
        frame.render_widget(para, inner);
    }
}

impl TreeView {
    fn rebuild_preserve_selection(&mut self, manifest: &PolicyManifest) {
        let old_path = self
            .flat_nodes
            .get(self.selected)
            .map(|n| n.node_path.clone());
        self.rebuild(manifest);
        // Try to find the same path
        if let Some(path) = old_path
            && let Some(pos) = self.flat_nodes.iter().position(|n| n.node_path == path)
        {
            self.selected = pos;
        }
    }
}

fn decision_style(decision: Option<&MatchVerdict>) -> Style {
    match decision {
        Some(MatchVerdict::Allow(_)) => Style::default().fg(Color::Green),
        Some(MatchVerdict::Deny) => Style::default().fg(Color::Red),
        Some(MatchVerdict::Ask(_)) => Style::default().fg(Color::Yellow),
        None => Style::default().fg(Color::White),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::manifest_edit;
    use crate::policy::match_tree::*;
    use std::collections::HashMap;

    fn empty_manifest() -> PolicyManifest {
        PolicyManifest {
            includes: vec![],
            policy: CompiledPolicy {
                sandboxes: HashMap::new(),
                tree: vec![],
                default_effect: crate::policy::Effect::Deny,
                default_sandbox: None,
            },
        }
    }

    fn empty_included() -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![],
            default_effect: crate::policy::Effect::Deny,
            default_sandbox: None,
        }
    }

    #[test]
    fn test_root_node_always_present() {
        let manifest = empty_manifest();
        let view = TreeView::new(&manifest, &empty_included());
        assert_eq!(view.flat_nodes.len(), 1);
        assert!(view.flat_nodes[0].is_root);
        assert_eq!(view.flat_nodes[0].label, "rules");
    }

    #[test]
    fn test_root_node_with_children() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Read", MatchVerdict::Allow(None)),
        );

        let view = TreeView::new(&manifest, &empty_included());
        assert_eq!(view.flat_nodes.len(), 2); // root + one rule
        assert!(view.flat_nodes[0].is_root);
        assert!(view.flat_nodes[0].has_children);
        assert!(!view.flat_nodes[1].is_root);
    }

    #[test]
    fn test_edit_inline_leaf_opens_edit_rule_form() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Read", MatchVerdict::Allow(None)),
        );

        let mut view = TreeView::new(&manifest, &empty_included());
        // Select the rule node (index 1, after root) — it's an inline leaf
        view.selected = 1;
        assert!(view.flat_nodes[1].is_leaf);

        let action = view.update(Msg::Edit, &mut manifest);
        assert!(matches!(
            action,
            Action::RunForm(FormRequest::EditRule { .. })
        ));
    }

    #[test]
    fn test_edit_on_root_flashes() {
        let mut manifest = empty_manifest();
        let mut view = TreeView::new(&manifest, &empty_included());
        view.selected = 0; // root

        let action = view.update(Msg::Edit, &mut manifest);
        assert!(matches!(action, Action::Flash(_)));
    }

    #[test]
    fn test_edit_condition_opens_edit_form() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_exec_rule("gh", &["pr"], MatchVerdict::Allow(None)),
        );

        let mut view = TreeView::new(&manifest, &empty_included());
        // Select the condition (index 1, after synthetic root)
        view.selected = 1;
        assert!(!view.flat_nodes[1].is_leaf);

        let action = view.update(Msg::Edit, &mut manifest);
        assert!(matches!(
            action,
            Action::RunForm(FormRequest::EditCondition { .. })
        ));
    }

    #[test]
    fn test_add_on_root_opens_add_rule_form() {
        let mut manifest = empty_manifest();
        let mut view = TreeView::new(&manifest, &empty_included());
        view.selected = 0; // root

        let action = view.update(Msg::Add, &mut manifest);
        assert!(matches!(action, Action::RunForm(FormRequest::AddRule)));
    }

    #[test]
    fn test_add_on_condition_opens_add_child_form() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_exec_rule("gh", &["pr"], MatchVerdict::Allow(None)),
        );

        let mut view = TreeView::new(&manifest, &empty_included());
        // Select the Bash condition (index 1)
        view.selected = 1;

        let action = view.update(Msg::Add, &mut manifest);
        assert!(matches!(
            action,
            Action::RunForm(FormRequest::AddChild { .. })
        ));
    }

    #[test]
    fn test_delete_rule() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Read", MatchVerdict::Allow(None)),
        );

        let mut view = TreeView::new(&manifest, &empty_included());
        assert_eq!(view.flat_nodes.len(), 2); // root + rule
        view.selected = 1; // select the rule

        let action = view.update(Msg::Delete, &mut manifest);
        assert!(matches!(action, Action::Modified));
        assert_eq!(view.flat_nodes.len(), 1); // just root
        assert!(manifest.policy.tree.is_empty());
    }

    #[test]
    fn test_delete_root_blocked() {
        let mut manifest = empty_manifest();
        let mut view = TreeView::new(&manifest, &empty_included());
        view.selected = 0;

        let action = view.update(Msg::Delete, &mut manifest);
        assert!(matches!(action, Action::Flash(_)));
    }

    #[test]
    fn test_delete_child_node() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_exec_rule("gh", &[], MatchVerdict::Allow(None)),
        );
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_exec_rule("rm", &[], MatchVerdict::Deny),
        );

        let mut view = TreeView::new(&manifest, &empty_included());

        // Find the "gh" node
        let gh_idx = view
            .flat_nodes
            .iter()
            .position(|n| n.label.contains("gh"))
            .expect("should find gh node");
        view.selected = gh_idx;

        let action = view.update(Msg::Delete, &mut manifest);
        assert!(matches!(action, Action::Modified));

        let has_gh = view.flat_nodes.iter().any(|n| n.label.contains("gh"));
        assert!(!has_gh, "gh node should be deleted");
        let has_rm = view.flat_nodes.iter().any(|n| n.label.contains("rm"));
        assert!(has_rm, "rm node should still exist");
    }

    #[test]
    fn test_navigation() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Read", MatchVerdict::Allow(None)),
        );
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Write", MatchVerdict::Deny),
        );

        let mut view = TreeView::new(&manifest, &empty_included());
        assert_eq!(view.selected, 0);

        view.update(Msg::MoveDown, &mut manifest);
        assert_eq!(view.selected, 1);

        view.update(Msg::MoveUp, &mut manifest);
        assert_eq!(view.selected, 0);

        view.update(Msg::JumpBottom, &mut manifest);
        assert_eq!(view.selected, view.flat_nodes.len() - 1);

        view.update(Msg::JumpTop, &mut manifest);
        assert_eq!(view.selected, 0);
    }
}
