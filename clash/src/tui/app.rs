//! App state, main event loop, dispatch input.

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use crossterm::event::{self, Event, MouseEvent, MouseEventKind};

use crate::policy::Effect;
use crate::policy::ast::{PolicyItem, Rule, TopLevel};
use crate::policy::compile::compile_policy;
use crate::policy::edit;
use crate::policy::parse;
use crate::settings::{LoadedPolicy, PolicyLevel};

use super::editor::TextInput;
use super::input::{self, InputResult};
use super::render;
use super::tree::{self, FlatRow, TreeNode, TreeNodeKind};

// ---------------------------------------------------------------------------
// Mode and related types
// ---------------------------------------------------------------------------

/// Current interaction mode.
pub enum Mode {
    Normal,
    Confirm(ConfirmAction),
    AddRule(AddRuleForm),
    EditRule(EditRuleState),
    SelectEffect(SelectEffectState),
    Search,
}

/// What a confirmation dialog is confirming.
pub enum ConfirmAction {
    DeleteRule {
        level: PolicyLevel,
        policy: String,
        rule_text: String,
    },
    QuitUnsaved,
}

/// Step-by-step add-rule form.
pub struct AddRuleForm {
    pub step: AddRuleStep,
    pub domain_index: usize,
    pub effect_index: usize,
    pub level_index: usize,
    pub fs_op_index: usize,
    pub binary_input: TextInput,
    pub args_input: TextInput,
    pub path_input: TextInput,
    pub net_domain_input: TextInput,
    pub tool_name_input: TextInput,
    pub available_levels: Vec<PolicyLevel>,
    pub error: Option<String>,
}

impl AddRuleForm {
    /// Returns a mutable reference to the text input for the current step, if any.
    pub fn active_text_input(&mut self) -> Option<&mut TextInput> {
        match self.step {
            AddRuleStep::EnterBinary => Some(&mut self.binary_input),
            AddRuleStep::EnterArgs => Some(&mut self.args_input),
            AddRuleStep::EnterPath => Some(&mut self.path_input),
            AddRuleStep::EnterNetDomain => Some(&mut self.net_domain_input),
            AddRuleStep::EnterToolName => Some(&mut self.tool_name_input),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub enum AddRuleStep {
    SelectDomain,
    EnterBinary,
    EnterArgs,
    SelectFsOp,
    EnterPath,
    EnterNetDomain,
    EnterToolName,
    SelectEffect,
    SelectLevel,
}

/// State for inline rule editing.
pub struct EditRuleState {
    pub input: TextInput,
    pub original_rule_text: String,
    pub level: PolicyLevel,
    pub policy: String,
    pub error: Option<String>,
}

/// State for the effect selector dropdown.
pub struct SelectEffectState {
    pub effect_index: usize,
    pub rule: Rule,
    pub level: PolicyLevel,
    pub policy: String,
}

// ---------------------------------------------------------------------------
// Per-level editing state
// ---------------------------------------------------------------------------

/// Editing state for a single policy level.
pub struct LevelState {
    pub level: PolicyLevel,
    pub path: PathBuf,
    pub source: String,
    pub original_source: String,
}

impl LevelState {
    pub fn is_modified(&self) -> bool {
        self.source != self.original_source
    }
}

// ---------------------------------------------------------------------------
// Undo/redo
// ---------------------------------------------------------------------------

struct UndoEntry {
    sources: Vec<(PolicyLevel, String)>,
    cursor: usize,
}

// ---------------------------------------------------------------------------
// Status message
// ---------------------------------------------------------------------------

pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

/// Application state for the TUI.
pub struct App {
    /// The visual tree roots.
    pub roots: Vec<TreeNode>,
    /// Flattened rows for rendering.
    pub flat_rows: Vec<FlatRow>,
    /// Current cursor position (index into flat_rows).
    pub cursor: usize,
    /// Per-level editing state.
    pub levels: Vec<LevelState>,
    /// Viewport height (updated each frame).
    pub viewport_height: usize,
    /// Whether to show the help overlay.
    pub show_help: bool,
    /// Current interaction mode.
    pub mode: Mode,
    /// Transient status message.
    pub status_message: Option<StatusMessage>,
    /// Undo stack.
    undo_stack: Vec<UndoEntry>,
    /// Redo stack.
    redo_stack: Vec<UndoEntry>,
    /// Search text input.
    pub search_input: TextInput,
    /// Active search query (after Enter).
    pub search_query: Option<String>,
    /// Flat row indices that match the search.
    pub search_matches: Vec<usize>,
    /// Current position in search_matches.
    pub search_match_cursor: usize,
}

impl App {
    /// Create a new app from loaded policies.
    pub fn new(policies: &[LoadedPolicy]) -> Self {
        let levels: Vec<LevelState> = policies
            .iter()
            .map(|p| {
                let source = edit::normalize(&p.source).unwrap_or_else(|_| p.source.clone());
                LevelState {
                    level: p.level,
                    path: p.path.clone(),
                    original_source: source.clone(),
                    source,
                }
            })
            .collect();

        let loaded = Self::to_loaded_policies(&levels);
        let mut roots = tree::build_tree(&loaded);
        // Start fully collapsed
        fn collapse(node: &mut TreeNode) {
            node.expanded = false;
            for child in &mut node.children {
                collapse(child);
            }
        }
        for root in &mut roots {
            collapse(root);
        }
        let flat_rows = tree::flatten(&roots);

        Self {
            roots,
            flat_rows,
            cursor: 0,
            levels,
            viewport_height: 20,
            show_help: false,
            mode: Mode::Normal,
            status_message: None,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            search_input: TextInput::empty(),
            search_query: None,
            search_matches: Vec::new(),
            search_match_cursor: 0,
        }
    }

    fn to_loaded_policies(levels: &[LevelState]) -> Vec<LoadedPolicy> {
        levels
            .iter()
            .map(|ls| LoadedPolicy {
                level: ls.level,
                path: ls.path.clone(),
                source: ls.source.clone(),
            })
            .collect()
    }

    /// Whether any level has unsaved changes.
    pub fn has_unsaved_changes(&self) -> bool {
        self.levels.iter().any(|ls| ls.is_modified())
    }

    /// Available policy levels for editing.
    pub fn available_levels(&self) -> Vec<PolicyLevel> {
        self.levels.iter().map(|ls| ls.level).collect()
    }

    /// Rebuild tree from current level sources, preserving cursor bounds.
    pub fn rebuild_tree(&mut self) {
        let loaded = Self::to_loaded_policies(&self.levels);
        self.roots = tree::build_tree(&loaded);
        self.flat_rows = tree::flatten(&self.roots);
        if self.cursor >= self.flat_rows.len() && !self.flat_rows.is_empty() {
            self.cursor = self.flat_rows.len() - 1;
        }
        self.update_search_matches();
    }

    /// Rebuild flat_rows from existing tree (for expand/collapse).
    pub fn rebuild_flat(&mut self) {
        self.flat_rows = tree::flatten(&self.roots);
        if self.cursor >= self.flat_rows.len() && !self.flat_rows.is_empty() {
            self.cursor = self.flat_rows.len() - 1;
        }
        self.update_search_matches();
    }

    /// Move cursor to a leaf matching the given rule text, expanding ancestors as needed.
    fn cursor_to_rule(&mut self, rule_text: &str) {
        // Search the tree (which is fully expanded after rebuild_tree) for a matching leaf.
        let find = |rows: &[FlatRow]| -> Option<usize> {
            rows.iter()
                .position(|row| matches!(&row.kind, TreeNodeKind::Leaf { rule, .. } if rule.to_string() == rule_text))
        };

        let Some(i) = find(&self.flat_rows) else {
            return;
        };

        // Ensure ancestors are expanded
        let tree_path = self.flat_rows[i].tree_path.clone();
        for prefix_len in 1..tree_path.len() {
            if let Some(node) = tree::node_at_path_mut(&mut self.roots, &tree_path[..prefix_len]) {
                node.expanded = true;
            }
        }
        self.rebuild_flat();

        // Re-find after re-flatten (indices may have shifted)
        self.cursor = find(&self.flat_rows).unwrap_or(i);
    }

    /// Compute scroll offset to keep cursor visible.
    pub fn scroll_offset(&self, visible_height: usize) -> usize {
        if visible_height == 0 || self.flat_rows.is_empty() {
            return 0;
        }
        if self.cursor < visible_height / 3 {
            0
        } else if self.cursor > self.flat_rows.len().saturating_sub(visible_height * 2 / 3) {
            self.flat_rows.len().saturating_sub(visible_height)
        } else {
            self.cursor.saturating_sub(visible_height / 3)
        }
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    pub fn move_cursor_down(&mut self) {
        if !self.flat_rows.is_empty() && self.cursor < self.flat_rows.len() - 1 {
            self.cursor += 1;
        }
    }

    pub fn move_cursor_up(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn cursor_to_top(&mut self) {
        self.cursor = 0;
    }

    pub fn cursor_to_bottom(&mut self) {
        if !self.flat_rows.is_empty() {
            self.cursor = self.flat_rows.len() - 1;
        }
    }

    pub fn page_up(&mut self) {
        let page = self.viewport_height.max(1);
        self.cursor = self.cursor.saturating_sub(page);
    }

    pub fn page_down(&mut self) {
        if self.flat_rows.is_empty() {
            return;
        }
        let page = self.viewport_height.max(1);
        self.cursor = (self.cursor + page).min(self.flat_rows.len() - 1);
    }

    /// Collapse the current node, or move to its parent.
    pub fn collapse_or_parent(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };

        if row.has_children && row.expanded {
            // Collapse this node
            let path = row.tree_path.clone();
            if let Some(node) = tree::node_at_path_mut(&mut self.roots, &path) {
                node.expanded = false;
            }
            self.rebuild_flat();
        } else if row.depth > 0 {
            // Move to parent: find the nearest row with depth - 1
            let parent_depth = row.depth - 1;
            for i in (0..self.cursor).rev() {
                if self.flat_rows[i].depth == parent_depth {
                    self.cursor = i;
                    break;
                }
            }
        }
    }

    /// Expand the current node.
    pub fn expand(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };

        if row.has_children && !row.expanded {
            let path = row.tree_path.clone();
            if let Some(node) = tree::node_at_path_mut(&mut self.roots, &path) {
                node.expanded = true;
            }
            self.rebuild_flat();
        } else if row.has_children && row.expanded {
            // Already expanded — move to first child
            if self.cursor + 1 < self.flat_rows.len() {
                self.cursor += 1;
            }
        }
    }

    /// Collapse all tree nodes.
    pub fn collapse_all(&mut self) {
        fn collapse_recursive(node: &mut TreeNode) {
            node.expanded = false;
            for child in &mut node.children {
                collapse_recursive(child);
            }
        }
        for root in &mut self.roots {
            collapse_recursive(root);
        }
        self.rebuild_flat();
    }

    /// Expand all tree nodes.
    pub fn expand_all(&mut self) {
        fn expand_recursive(node: &mut TreeNode) {
            node.expanded = true;
            for child in &mut node.children {
                expand_recursive(child);
            }
        }
        for root in &mut self.roots {
            expand_recursive(root);
        }
        self.rebuild_flat();
    }

    /// Handle a mouse click at the given terminal row.
    pub fn handle_mouse_click(&mut self, row: u16) {
        // Tree view starts at y=1 (after 1-line header), no top border
        let tree_y = 1u16;
        let visible_height = self.viewport_height;
        let scroll = self.scroll_offset(visible_height);

        let row_in_tree = row.saturating_sub(tree_y) as usize;
        if row_in_tree >= visible_height {
            return;
        }

        let flat_idx = scroll + row_in_tree;
        if flat_idx < self.flat_rows.len() {
            self.cursor = flat_idx;
        }
    }

    /// Build a breadcrumb string for the current cursor position.
    pub fn breadcrumb(&self) -> Option<String> {
        let row = self.flat_rows.get(self.cursor)?;
        if row.tree_path.is_empty() {
            return None;
        }

        let mut parts: Vec<String> = Vec::new();
        let mut current_roots = &self.roots[..];

        for &idx in &row.tree_path {
            let node = current_roots.get(idx)?;
            let label = match &node.kind {
                TreeNodeKind::Domain(d) => d.to_string(),
                TreeNodeKind::PolicyBlock { name, .. } => name.clone(),
                TreeNodeKind::Binary(s)
                | TreeNodeKind::Arg(s)
                | TreeNodeKind::HasArg(s)
                | TreeNodeKind::PathNode(s)
                | TreeNodeKind::FsOp(s)
                | TreeNodeKind::NetDomain(s)
                | TreeNodeKind::ToolName(s) => s.clone(),
                TreeNodeKind::HasMarker => ":has".into(),
                TreeNodeKind::Leaf { effect, .. } => effect.to_string(),
            };
            parts.push(label);
            current_roots = &node.children;
        }

        Some(parts.join(" > "))
    }

    /// Toggle fold on the current node.
    pub fn toggle_fold_level(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        if !row.has_children {
            return;
        }
        let path = row.tree_path.clone();
        let Some(node) = tree::node_at_path_mut(&mut self.roots, &path) else {
            return;
        };
        node.expanded = !node.expanded;
        self.rebuild_flat();
    }

    /// Toggle fold on the entire subtree under the current node.
    pub fn toggle_fold_recursive(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        if !row.has_children {
            return;
        }
        let path = row.tree_path.clone();
        let Some(node) = tree::node_at_path_mut(&mut self.roots, &path) else {
            return;
        };
        // If the node or any descendant is expanded, collapse all; otherwise expand all
        fn any_expanded(node: &TreeNode) -> bool {
            (node.expanded && !node.children.is_empty()) || node.children.iter().any(any_expanded)
        }
        fn set_recursive(node: &mut TreeNode, expanded: bool) {
            if !node.children.is_empty() {
                node.expanded = expanded;
            }
            for child in &mut node.children {
                set_recursive(child, expanded);
            }
        }
        let expand = !any_expanded(node);
        set_recursive(node, expand);
        self.rebuild_flat();
    }

    /// Toggle expand/collapse on the current node.
    pub fn toggle_expand(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };

        if row.has_children {
            let path = row.tree_path.clone();
            let expanded = row.expanded;
            if let Some(node) = tree::node_at_path_mut(&mut self.roots, &path) {
                node.expanded = !expanded;
            }
            self.rebuild_flat();
        }
    }

    // -----------------------------------------------------------------------
    // Editing
    // -----------------------------------------------------------------------

    /// Snapshot current sources for undo.
    fn push_undo(&mut self) {
        let sources: Vec<(PolicyLevel, String)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.clone()))
            .collect();
        self.undo_stack.push(UndoEntry {
            sources,
            cursor: self.cursor,
        });
        self.redo_stack.clear();
    }

    /// Undo the last editing action.
    pub fn undo(&mut self) {
        let Some(entry) = self.undo_stack.pop() else {
            self.set_status("Nothing to undo", true);
            return;
        };
        // Save current state to redo
        let current: Vec<(PolicyLevel, String)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.clone()))
            .collect();
        self.redo_stack.push(UndoEntry {
            sources: current,
            cursor: self.cursor,
        });
        // Restore
        for (level, source) in &entry.sources {
            if let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == *level) {
                ls.source = source.clone();
            }
        }
        self.cursor = entry.cursor;
        self.rebuild_tree();
        self.set_status("Undone", false);
    }

    /// Redo the last undone action.
    pub fn redo(&mut self) {
        let Some(entry) = self.redo_stack.pop() else {
            self.set_status("Nothing to redo", true);
            return;
        };
        let current: Vec<(PolicyLevel, String)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.clone()))
            .collect();
        self.undo_stack.push(UndoEntry {
            sources: current,
            cursor: self.cursor,
        });
        for (level, source) in &entry.sources {
            if let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == *level) {
                ls.source = source.clone();
            }
        }
        self.cursor = entry.cursor;
        self.rebuild_tree();
        self.set_status("Redone", false);
    }

    fn set_status(&mut self, text: &str, is_error: bool) {
        self.status_message = Some(StatusMessage {
            text: text.to_string(),
            is_error,
        });
    }

    /// Open the effect selector dropdown on the focused leaf.
    pub fn start_select_effect(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        let TreeNodeKind::Leaf {
            effect,
            rule,
            level,
            policy,
        } = &row.kind
        else {
            self.set_status("Not a rule leaf", true);
            return;
        };

        self.mode = Mode::SelectEffect(SelectEffectState {
            effect_index: effect_to_display_index(*effect),
            rule: rule.clone(),
            level: *level,
            policy: policy.clone(),
        });
    }

    /// Apply the selected effect from the dropdown.
    pub fn confirm_select_effect(&mut self) {
        let Mode::SelectEffect(state) = &self.mode else {
            return;
        };

        let effect_index = state.effect_index;
        let new_effect = effect_from_display_index(effect_index);
        let old_rule = state.rule.clone();
        let level = state.level;
        let policy = state.policy.clone();

        if new_effect == old_rule.effect {
            self.mode = Mode::Normal;
            return;
        }

        let new_rule = Rule {
            effect: new_effect,
            matcher: old_rule.matcher.clone(),
            sandbox: old_rule.sandbox.clone(),
        };
        let old_rule_text = old_rule.to_string();
        let display_name = EFFECT_DISPLAY[effect_index].to_string();

        self.mode = Mode::Normal;
        self.push_undo();

        let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == level) else {
            self.undo_stack.pop();
            self.set_status("Policy level not found", true);
            return;
        };

        let result = edit::remove_rule(&ls.source, &policy, &old_rule_text)
            .and_then(|s| edit::add_rule(&s, &policy, &new_rule));

        match result {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.undo_stack.pop();
                    self.set_status(&format!("Invalid: {e}"), true);
                    return;
                }
                ls.source = new_source;
                self.rebuild_tree();
                self.set_status(&format!("Changed to {display_name}"), false);
            }
            Err(e) => {
                self.undo_stack.pop();
                self.set_status(&format!("Edit failed: {e}"), true);
            }
        }
    }

    /// Initiate deletion of the focused rule (enters Confirm mode).
    pub fn start_delete(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        let TreeNodeKind::Leaf {
            rule,
            level,
            policy,
            ..
        } = &row.kind
        else {
            self.set_status("Not a rule leaf", true);
            return;
        };

        self.mode = Mode::Confirm(ConfirmAction::DeleteRule {
            level: *level,
            policy: policy.clone(),
            rule_text: rule.to_string(),
        });
    }

    /// Execute a confirmed delete.
    pub fn confirm_delete(&mut self, level: PolicyLevel, policy: String, rule_text: String) {
        // Push undo before borrowing levels mutably
        self.push_undo();

        let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == level) else {
            self.undo_stack.pop();
            self.set_status("Policy level not found", true);
            return;
        };

        match edit::remove_rule(&ls.source, &policy, &rule_text) {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.undo_stack.pop();
                    self.set_status(&format!("Invalid after delete: {e}"), true);
                    return;
                }
                ls.source = new_source;
                self.rebuild_tree();
                self.set_status("Rule deleted", false);
            }
            Err(e) => {
                self.undo_stack.pop();
                self.set_status(&format!("Delete failed: {e}"), true);
            }
        }
    }

    /// Save all modified levels to disk.
    pub fn save_all(&mut self) {
        if !self.has_unsaved_changes() {
            self.set_status("No changes to save", false);
            return;
        }

        let mut saved = 0;
        for ls in &mut self.levels {
            if !ls.is_modified() {
                continue;
            }
            // Validate before writing
            if let Err(e) = compile_policy(&ls.source) {
                self.status_message = Some(StatusMessage {
                    text: format!("Validation failed for {}: {e}", ls.level),
                    is_error: true,
                });
                return;
            }
            if let Some(parent) = ls.path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to create directory: {e}"),
                    is_error: true,
                });
                return;
            }
            if let Err(e) = fs::write(&ls.path, &ls.source) {
                self.status_message = Some(StatusMessage {
                    text: format!("Failed to write {}: {e}", ls.path.display()),
                    is_error: true,
                });
                return;
            }
            ls.original_source = ls.source.clone();
            saved += 1;
        }

        self.set_status(
            &format!(
                "Saved {saved} policy file{}",
                if saved == 1 { "" } else { "s" }
            ),
            false,
        );
    }

    /// Start quit flow — enters Confirm if unsaved, otherwise returns Quit.
    pub fn start_quit(&mut self) -> InputResult {
        if self.has_unsaved_changes() {
            self.mode = Mode::Confirm(ConfirmAction::QuitUnsaved);
            InputResult::Continue
        } else {
            InputResult::Quit
        }
    }

    // -----------------------------------------------------------------------
    // Add rule
    // -----------------------------------------------------------------------

    /// Enter add-rule mode with step-by-step form.
    pub fn start_add_rule(&mut self) {
        let available = self.available_levels();
        if available.is_empty() {
            self.set_status("No policy levels available", true);
            return;
        }
        self.mode = Mode::AddRule(AddRuleForm {
            step: AddRuleStep::EnterBinary,
            domain_index: 0,
            effect_index: 0,
            level_index: 0,
            fs_op_index: 0,
            binary_input: TextInput::empty(),
            args_input: TextInput::empty(),
            path_input: TextInput::empty(),
            net_domain_input: TextInput::empty(),
            tool_name_input: TextInput::empty(),
            available_levels: available,
            error: None,
        });
    }

    /// Advance the add-rule form to the next step, or complete it.
    ///
    /// Flow: Command → Args → Domain → Permissions → Effect → Level
    pub fn advance_add_rule(&mut self) {
        let Mode::AddRule(form) = &mut self.mode else {
            return;
        };
        form.error = None;
        match form.step {
            AddRuleStep::EnterBinary => {
                // Auto-select exec if user entered a specific command
                let bin = form.binary_input.value().trim();
                if !bin.is_empty() && bin != "*" {
                    form.domain_index = 0; // exec
                }
                form.step = AddRuleStep::EnterArgs;
            }
            AddRuleStep::EnterArgs => {
                form.step = AddRuleStep::SelectDomain;
            }
            AddRuleStep::SelectDomain => {
                // Domain index: 0=exec, 1=fs, 2=net, 3=tool
                form.step = match form.domain_index {
                    0 => AddRuleStep::SelectEffect, // exec: no extra permissions
                    1 => AddRuleStep::SelectFsOp,
                    2 => AddRuleStep::EnterNetDomain,
                    _ => AddRuleStep::EnterToolName,
                };
            }
            AddRuleStep::SelectFsOp => {
                form.step = AddRuleStep::EnterPath;
            }
            AddRuleStep::EnterPath => {
                form.step = AddRuleStep::SelectEffect;
            }
            AddRuleStep::EnterNetDomain => {
                form.step = AddRuleStep::SelectEffect;
            }
            AddRuleStep::EnterToolName => {
                form.step = AddRuleStep::SelectEffect;
            }
            AddRuleStep::SelectEffect => {
                form.step = AddRuleStep::SelectLevel;
            }
            AddRuleStep::SelectLevel => {
                self.complete_add_rule();
            }
        }
    }

    /// Complete the add-rule form: build s-expression from structured fields, parse, validate, add.
    fn complete_add_rule(&mut self) {
        let Mode::AddRule(form) = &self.mode else {
            return;
        };

        let effect = EFFECT_NAMES[form.effect_index];
        let level = form.available_levels[form.level_index];

        // Build the domain-specific matcher s-expression
        let rule_text = match form.domain_index {
            0 => {
                // Exec: ({effect} (exec {binary} {args...}))
                let binary_raw = form.binary_input.value().trim().to_string();
                let binary = if binary_raw.is_empty() {
                    "*"
                } else {
                    &binary_raw
                };
                let args = form.args_input.value().trim().to_string();
                let binary_tok = quote_token_if_needed(binary);
                let mut parts = vec![format!("({effect} (exec {binary_tok}")];
                if !args.is_empty() {
                    for arg in args.split_whitespace() {
                        parts.push(format!(" {}", quote_token_if_needed(arg)));
                    }
                }
                parts.push("))".to_string());
                parts.join("")
            }
            1 => {
                // Fs: ({effect} (fs {op} {path}))
                let op = FS_OPS[form.fs_op_index];
                let path = form.path_input.value().trim().to_string();
                if op == "*" && path.is_empty() {
                    format!("({effect} (fs))")
                } else if path.is_empty() {
                    format!("({effect} (fs {op}))")
                } else {
                    format!("({effect} (fs {op} {path}))")
                }
            }
            2 => {
                // Net: ({effect} (net {domain}))
                let domain = form.net_domain_input.value().trim().to_string();
                if domain.is_empty() || domain == "*" {
                    format!("({effect} (net))")
                } else {
                    let tok = quote_token_if_needed(&domain);
                    format!("({effect} (net {tok}))")
                }
            }
            _ => {
                // Tool: ({effect} (tool {name}))
                let name = form.tool_name_input.value().trim().to_string();
                if name.is_empty() || name == "*" {
                    format!("({effect} (tool))")
                } else {
                    let tok = quote_token_if_needed(&name);
                    format!("({effect} (tool {tok}))")
                }
            }
        };

        let rule = match parse_rule_text(&rule_text) {
            Ok(r) => r,
            Err(e) => {
                if let Mode::AddRule(form) = &mut self.mode {
                    form.error = Some(format!("Parse error: {e}"));
                }
                return;
            }
        };

        // Find the level and its active policy
        let Some(ls) = self.levels.iter().find(|ls| ls.level == level) else {
            self.mode = Mode::Normal;
            self.set_status("Level not found", true);
            return;
        };
        let policy_name = match edit::active_policy(&ls.source) {
            Ok(name) => name,
            Err(_) => "main".to_string(),
        };

        self.push_undo();

        let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == level) else {
            self.undo_stack.pop();
            self.mode = Mode::Normal;
            self.set_status("Level not found", true);
            return;
        };

        // Ensure the policy block exists, then add the rule
        let result = edit::ensure_policy_block(
            &ls.source,
            &policy_name,
            &format!("(policy \"{policy_name}\")"),
        )
        .and_then(|s| edit::add_rule(&s, &policy_name, &rule));

        match result {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.undo_stack.pop();
                    if let Mode::AddRule(form) = &mut self.mode {
                        form.error = Some(format!("Validation: {e}"));
                    }
                    return;
                }
                ls.source = new_source;
                let rule_text = rule.to_string();
                self.mode = Mode::Normal;
                self.rebuild_tree();
                self.cursor_to_rule(&rule_text);
                self.set_status("Rule added", false);
            }
            Err(e) => {
                self.undo_stack.pop();
                if let Mode::AddRule(form) = &mut self.mode {
                    form.error = Some(format!("Failed: {e}"));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Edit rule (inline)
    // -----------------------------------------------------------------------

    /// Enter edit mode for the focused leaf rule.
    pub fn start_edit_rule(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        let TreeNodeKind::Leaf {
            rule,
            level,
            policy,
            ..
        } = &row.kind
        else {
            self.set_status("Not a rule leaf", true);
            return;
        };

        self.mode = Mode::EditRule(EditRuleState {
            input: TextInput::new(&rule.to_string()),
            original_rule_text: rule.to_string(),
            level: *level,
            policy: policy.clone(),
            error: None,
        });
    }

    /// Complete inline edit: parse new text, remove old, add new.
    pub fn complete_edit_rule(&mut self) {
        let Mode::EditRule(state) = &self.mode else {
            return;
        };

        let new_text = state.input.value().to_string();
        let original = state.original_rule_text.clone();
        let level = state.level;
        let policy = state.policy.clone();

        // Parse the new rule
        let new_rule = match parse_rule_text(&new_text) {
            Ok(r) => r,
            Err(e) => {
                if let Mode::EditRule(state) = &mut self.mode {
                    state.error = Some(format!("Parse error: {e}"));
                }
                return;
            }
        };

        self.push_undo();

        let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == level) else {
            self.undo_stack.pop();
            self.mode = Mode::Normal;
            self.set_status("Level not found", true);
            return;
        };

        let result = edit::remove_rule(&ls.source, &policy, &original)
            .and_then(|s| edit::add_rule(&s, &policy, &new_rule));

        match result {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.undo_stack.pop();
                    if let Mode::EditRule(state) = &mut self.mode {
                        state.error = Some(format!("Validation: {e}"));
                    }
                    return;
                }
                ls.source = new_source;
                self.mode = Mode::Normal;
                self.rebuild_tree();
                self.set_status("Rule updated", false);
            }
            Err(e) => {
                self.undo_stack.pop();
                if let Mode::EditRule(state) = &mut self.mode {
                    state.error = Some(format!("Edit failed: {e}"));
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Search
    // -----------------------------------------------------------------------

    /// Enter search mode.
    pub fn start_search(&mut self) {
        self.search_input = TextInput::empty();
        self.mode = Mode::Search;
    }

    /// Commit the search query and jump to first match.
    pub fn commit_search(&mut self) {
        let query = self.search_input.value().to_string();
        if query.is_empty() {
            self.search_query = None;
            self.search_matches.clear();
        } else {
            self.search_query = Some(query);
            self.update_search_matches();
            // Jump to first match
            if let Some(&idx) = self.search_matches.first() {
                self.cursor = idx;
                self.search_match_cursor = 0;
            }
        }
        self.mode = Mode::Normal;
    }

    /// Cancel search mode without applying.
    pub fn cancel_search(&mut self) {
        self.mode = Mode::Normal;
    }

    /// Clear the active search.
    pub fn clear_search(&mut self) {
        self.search_query = None;
        self.search_matches.clear();
        self.search_match_cursor = 0;
    }

    /// Jump to the next search match.
    pub fn next_search_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        self.search_match_cursor = (self.search_match_cursor + 1) % self.search_matches.len();
        self.cursor = self.search_matches[self.search_match_cursor];
    }

    /// Jump to the previous search match.
    pub fn prev_search_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        if self.search_match_cursor == 0 {
            self.search_match_cursor = self.search_matches.len() - 1;
        } else {
            self.search_match_cursor -= 1;
        }
        self.cursor = self.search_matches[self.search_match_cursor];
    }

    /// Live-update search matches as the user types.
    pub fn update_search_live(&mut self) {
        let query = self.search_input.value().to_string();
        if query.is_empty() {
            self.search_query = None;
            self.search_matches.clear();
        } else {
            self.search_query = Some(query);
            self.update_search_matches();
        }
    }

    fn update_search_matches(&mut self) {
        self.search_matches.clear();
        self.search_match_cursor = 0;

        let Some(query) = &self.search_query else {
            return;
        };
        let query_lower = query.to_lowercase();
        if query_lower.is_empty() {
            return;
        }

        for (i, row) in self.flat_rows.iter().enumerate() {
            let text = row_search_text(&row.kind);
            if text.to_lowercase().contains(&query_lower) {
                self.search_matches.push(i);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Event loop
    // -----------------------------------------------------------------------

    pub fn run<B>(&mut self, terminal: &mut ratatui::Terminal<B>) -> Result<()>
    where
        B: ratatui::backend::Backend,
        B::Error: Send + Sync + 'static,
    {
        loop {
            terminal.draw(|f| {
                self.viewport_height = f.area().height.saturating_sub(7) as usize;
                render::render(f, self);
            })?;

            let ev = event::read()?;
            match ev {
                Event::Key(key) => match input::handle_key(self, key) {
                    InputResult::Continue => {}
                    InputResult::Quit => break,
                },
                Event::Mouse(MouseEvent {
                    kind: MouseEventKind::ScrollUp,
                    ..
                }) => self.move_cursor_up(),
                Event::Mouse(MouseEvent {
                    kind: MouseEventKind::ScrollDown,
                    ..
                }) => self.move_cursor_down(),
                Event::Mouse(MouseEvent {
                    kind: MouseEventKind::Down(_),
                    row,
                    ..
                }) => {
                    if matches!(self.mode, Mode::Normal) {
                        self.handle_mouse_click(row);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Constants for the add-rule form
// ---------------------------------------------------------------------------

pub const DOMAIN_NAMES: &[&str] = &["exec", "fs", "net", "tool"];
pub const EFFECT_NAMES: &[&str] = &["allow", "deny", "ask"];
pub const EFFECT_DISPLAY: &[&str] = &["ask", "auto allow", "auto deny"];
pub const FS_OPS: &[&str] = &["*", "read", "write", "create", "delete"];

fn effect_from_display_index(index: usize) -> Effect {
    match index {
        0 => Effect::Ask,
        1 => Effect::Allow,
        _ => Effect::Deny,
    }
}

fn effect_to_display_index(effect: Effect) -> usize {
    match effect {
        Effect::Ask => 0,
        Effect::Allow => 1,
        Effect::Deny => 2,
    }
}

/// Quote a token with double quotes if it's not `*` and not already a parenthesized expression.
fn quote_token_if_needed(token: &str) -> String {
    if token == "*" || token.starts_with('(') || token.starts_with('"') {
        token.to_string()
    } else {
        format!("\"{token}\"")
    }
}

/// Parse a single rule from its s-expression text.
fn parse_rule_text(rule_text: &str) -> Result<Rule> {
    let source = format!("(policy \"_tmp\" {rule_text})");
    let top_levels = parse::parse(&source)?;
    for tl in top_levels {
        if let TopLevel::Policy { body, .. } = tl {
            for item in body {
                if let PolicyItem::Rule(rule) = item {
                    return Ok(rule);
                }
            }
        }
    }
    anyhow::bail!("no rule found in input")
}

/// Extract searchable text from a node kind.
fn row_search_text(kind: &TreeNodeKind) -> String {
    match kind {
        TreeNodeKind::Domain(d) => d.to_string(),
        TreeNodeKind::PolicyBlock { name, level } => format!("{name} {level}"),
        TreeNodeKind::Binary(s)
        | TreeNodeKind::Arg(s)
        | TreeNodeKind::HasArg(s)
        | TreeNodeKind::PathNode(s)
        | TreeNodeKind::FsOp(s)
        | TreeNodeKind::NetDomain(s)
        | TreeNodeKind::ToolName(s) => s.clone(),
        TreeNodeKind::HasMarker => ":has".into(),
        TreeNodeKind::Leaf {
            effect,
            rule,
            policy,
            ..
        } => format!("{effect} {rule} {policy}"),
    }
}
