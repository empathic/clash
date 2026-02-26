//! App state, main event loop, dispatch input.

use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use crossterm::event::{self, Event, MouseEvent, MouseEventKind};

use crate::policy::Effect;
use crate::policy::ast::{PolicyItem, Rule, SandboxRef, TopLevel};
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
    SelectSandboxEffect(SelectSandboxEffectState),
    EditSandboxRule(EditSandboxRuleState),
    Search,
}

/// What a confirmation dialog is confirming.
pub enum ConfirmAction {
    DeleteRule {
        level: PolicyLevel,
        policy: String,
        rule_text: String,
    },
    DeleteSandboxRule {
        level: PolicyLevel,
        policy: String,
        sandbox_rule_text: String,
        parent_rule: Rule,
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

/// State for sandbox effect selector dropdown.
pub struct SelectSandboxEffectState {
    pub effect_index: usize,
    pub sandbox_rule: Rule,
    pub parent_rule: Rule,
    pub level: PolicyLevel,
    pub policy: String,
}

/// State for inline sandbox rule editing.
pub struct EditSandboxRuleState {
    pub input: TextInput,
    pub original_sandbox_rule: Rule,
    pub parent_rule: Rule,
    pub level: PolicyLevel,
    pub policy: String,
    pub error: Option<String>,
}

/// How to mutate a sandbox sub-rule within its parent.
enum SandboxMutation {
    Delete,
    Replace(Rule),
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

    /// Move cursor to a leaf matching the given rule text, level, and policy,
    /// expanding ancestors as needed. Returns `true` if the leaf was found.
    fn cursor_to_rule(
        &mut self,
        rule_text: &str,
        target_level: PolicyLevel,
        target_policy: &str,
    ) -> bool {
        // Search the tree for a matching leaf by rule text, level, and policy.
        let find = |rows: &[FlatRow]| -> Option<usize> {
            rows.iter().position(|row| {
                matches!(
                    &row.kind,
                    TreeNodeKind::Leaf { rule, level, policy, .. }
                        if rule.to_string() == rule_text
                            && *level == target_level
                            && policy == target_policy
                )
            })
        };

        let Some(i) = find(&self.flat_rows) else {
            return false;
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
        true
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
                TreeNodeKind::SandboxLeaf { effect, .. } => {
                    format!("{effect} [sandbox]")
                }
                TreeNodeKind::SandboxGroup => "Sandbox".into(),
                TreeNodeKind::SandboxName(name) => format!("sandbox: \"{name}\""),
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

    /// Open the effect selector dropdown on the focused leaf or sandbox leaf.
    pub fn start_select_effect(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        match &row.kind {
            TreeNodeKind::Leaf {
                effect,
                rule,
                level,
                policy,
            } => {
                self.mode = Mode::SelectEffect(SelectEffectState {
                    effect_index: effect_to_display_index(*effect),
                    rule: rule.clone(),
                    level: *level,
                    policy: policy.clone(),
                });
            }
            TreeNodeKind::SandboxLeaf {
                effect,
                sandbox_rule,
                parent_rule,
                level,
                policy,
            } => {
                self.mode = Mode::SelectSandboxEffect(SelectSandboxEffectState {
                    effect_index: effect_to_display_index(*effect),
                    sandbox_rule: sandbox_rule.clone(),
                    parent_rule: parent_rule.clone(),
                    level: *level,
                    policy: policy.clone(),
                });
            }
            _ => {
                self.set_status("Not a rule leaf", true);
            }
        }
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

    /// Apply the selected effect from the sandbox dropdown.
    pub fn confirm_select_sandbox_effect(&mut self) {
        let Mode::SelectSandboxEffect(state) = &self.mode else {
            return;
        };

        let new_effect = effect_from_display_index(state.effect_index);
        let old_sandbox_rule = state.sandbox_rule.clone();
        let parent_rule = state.parent_rule.clone();
        let level = state.level;
        let policy = state.policy.clone();

        if new_effect == old_sandbox_rule.effect {
            self.mode = Mode::Normal;
            return;
        }

        let new_sandbox_rule = Rule {
            effect: new_effect,
            ..old_sandbox_rule.clone()
        };

        self.mode = Mode::Normal;
        self.mutate_sandbox_rule(
            level,
            &policy,
            &parent_rule,
            &old_sandbox_rule,
            SandboxMutation::Replace(new_sandbox_rule),
            "Effect changed",
        );
    }

    /// Initiate deletion of the focused rule or sandbox sub-rule (enters Confirm mode).
    pub fn start_delete(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        match &row.kind {
            TreeNodeKind::Leaf {
                rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::Confirm(ConfirmAction::DeleteRule {
                    level: *level,
                    policy: policy.clone(),
                    rule_text: rule.to_string(),
                });
            }
            TreeNodeKind::SandboxLeaf {
                sandbox_rule,
                parent_rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::Confirm(ConfirmAction::DeleteSandboxRule {
                    level: *level,
                    policy: policy.clone(),
                    sandbox_rule_text: sandbox_rule.to_string(),
                    parent_rule: parent_rule.clone(),
                });
            }
            _ => {
                self.set_status("Not a rule leaf", true);
            }
        }
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

    /// Execute a confirmed sandbox sub-rule delete.
    pub fn confirm_delete_sandbox_rule(
        &mut self,
        level: PolicyLevel,
        policy: String,
        sandbox_rule_text: String,
        parent_rule: Rule,
    ) {
        // Parse the sandbox sub-rule text to find the rule to remove
        let sandbox_rule = match parse_rule_text(&sandbox_rule_text) {
            Ok(r) => r,
            Err(e) => {
                self.set_status(&format!("Parse error: {e}"), true);
                return;
            }
        };
        self.mutate_sandbox_rule(
            level,
            &policy,
            &parent_rule,
            &sandbox_rule,
            SandboxMutation::Delete,
            "Sandbox rule deleted",
        );
    }

    /// Shared helper: modify a sandbox sub-rule within its parent rule.
    ///
    /// Removes the old parent rule and adds the new one with the sandbox
    /// mutation applied.
    fn mutate_sandbox_rule(
        &mut self,
        level: PolicyLevel,
        policy: &str,
        parent_rule: &Rule,
        target_sandbox_rule: &Rule,
        mutation: SandboxMutation,
        success_msg: &str,
    ) {
        self.push_undo();

        let Some(SandboxRef::Inline(sandbox_rules)) = &parent_rule.sandbox else {
            self.undo_stack.pop();
            self.set_status("Parent rule has no inline sandbox", true);
            return;
        };

        // Build new sandbox rules list with the mutation applied
        let mut new_sandbox_rules: Vec<Rule> = Vec::new();
        let target_text = target_sandbox_rule.to_string();
        let mut found = false;

        for r in sandbox_rules {
            if r.to_string() == target_text && !found {
                found = true;
                match &mutation {
                    SandboxMutation::Delete => {} // skip it
                    SandboxMutation::Replace(new_rule) => {
                        new_sandbox_rules.push(new_rule.clone());
                    }
                }
            } else {
                new_sandbox_rules.push(r.clone());
            }
        }

        if !found {
            self.undo_stack.pop();
            self.set_status("Sandbox sub-rule not found in parent", true);
            return;
        }

        // Build the new parent rule
        let new_parent = Rule {
            effect: parent_rule.effect,
            matcher: parent_rule.matcher.clone(),
            sandbox: if new_sandbox_rules.is_empty() {
                None
            } else {
                Some(SandboxRef::Inline(new_sandbox_rules))
            },
        };

        let old_parent_text = parent_rule.to_string();

        let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == level) else {
            self.undo_stack.pop();
            self.set_status("Policy level not found", true);
            return;
        };

        let result = edit::remove_rule(&ls.source, policy, &old_parent_text)
            .and_then(|s| edit::add_rule(&s, policy, &new_parent));

        match result {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.undo_stack.pop();
                    self.set_status(&format!("Invalid: {e}"), true);
                    return;
                }
                ls.source = new_source;
                self.rebuild_tree();
                self.set_status(success_msg, false);
            }
            Err(e) => {
                self.undo_stack.pop();
                self.set_status(&format!("Edit failed: {e}"), true);
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

        // Auto-select exec if user entered a specific command
        if form.step == AddRuleStep::EnterBinary {
            let bin = form.binary_input.value().trim();
            if !bin.is_empty() && bin != "*" {
                form.domain_index = 0; // exec
            }
        }

        let next = next_add_rule_step(form.step, form.domain_index);
        if let Some(step) = next {
            form.step = step;
        } else {
            self.complete_add_rule();
        }
    }

    /// Complete the add-rule form: build s-expression from structured fields, parse, validate, add.
    fn complete_add_rule(&mut self) {
        let Mode::AddRule(form) = &self.mode else {
            return;
        };

        let level = form.available_levels[form.level_index];
        let rule_text = build_rule_text(form);

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

        // Check for a conflicting rule (same matcher, different effect) — replace it
        let conflicting = edit::find_conflicting_rule(&ls.source, &policy_name, &rule)
            .ok()
            .flatten();
        let replaced = conflicting.is_some();

        // Build the edit pipeline: optionally remove conflicting rule, ensure policy block, add
        let result = if let Some(ref old_text) = conflicting {
            edit::remove_rule(&ls.source, &policy_name, old_text)
                .and_then(|s| {
                    edit::ensure_policy_block(
                        &s,
                        &policy_name,
                        &format!("(policy \"{policy_name}\")"),
                    )
                })
                .and_then(|s| edit::add_rule(&s, &policy_name, &rule))
        } else {
            edit::ensure_policy_block(
                &ls.source,
                &policy_name,
                &format!("(policy \"{policy_name}\")"),
            )
            .and_then(|s| edit::add_rule(&s, &policy_name, &rule))
        };

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
                if !self.cursor_to_rule(&rule_text, level, &policy_name) {
                    // Fallback: try matching by rule text alone (ignoring level/policy)
                    let fallback = self.flat_rows.iter().position(|row| {
                        matches!(&row.kind, TreeNodeKind::Leaf { rule: r, .. } if r.to_string() == rule_text)
                    });
                    if let Some(idx) = fallback {
                        self.cursor = idx;
                    }
                }
                self.set_status(
                    if replaced {
                        "Rule replaced"
                    } else {
                        "Rule added"
                    },
                    false,
                );
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

    /// Enter edit mode for the focused leaf rule or sandbox sub-rule.
    pub fn start_edit_rule(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };
        match &row.kind {
            TreeNodeKind::Leaf {
                rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::EditRule(EditRuleState {
                    input: TextInput::new(&rule.to_string()),
                    original_rule_text: rule.to_string(),
                    level: *level,
                    policy: policy.clone(),
                    error: None,
                });
            }
            TreeNodeKind::SandboxLeaf {
                sandbox_rule,
                parent_rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::EditSandboxRule(EditSandboxRuleState {
                    input: TextInput::new(&sandbox_rule.to_string()),
                    original_sandbox_rule: sandbox_rule.clone(),
                    parent_rule: parent_rule.clone(),
                    level: *level,
                    policy: policy.clone(),
                    error: None,
                });
            }
            _ => {
                self.set_status("Not a rule leaf", true);
            }
        }
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

    /// Complete inline edit of a sandbox sub-rule.
    pub fn complete_edit_sandbox_rule(&mut self) {
        let Mode::EditSandboxRule(state) = &self.mode else {
            return;
        };

        let new_text = state.input.value().to_string();
        let original_sandbox_rule = state.original_sandbox_rule.clone();
        let parent_rule = state.parent_rule.clone();
        let level = state.level;
        let policy = state.policy.clone();

        // Parse the new sandbox sub-rule
        let new_rule = match parse_rule_text(&new_text) {
            Ok(r) => r,
            Err(e) => {
                if let Mode::EditSandboxRule(state) = &mut self.mode {
                    state.error = Some(format!("Parse error: {e}"));
                }
                return;
            }
        };

        self.mode = Mode::Normal;
        self.mutate_sandbox_rule(
            level,
            &policy,
            &parent_rule,
            &original_sandbox_rule,
            SandboxMutation::Replace(new_rule),
            "Sandbox rule updated",
        );
    }

    // -----------------------------------------------------------------------
    // Search
    // -----------------------------------------------------------------------

    /// Enter search mode.
    pub fn start_search(&mut self) {
        self.search_input.clear();
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

/// Compute the next step in the add-rule flow, or `None` if the form is complete.
pub(crate) fn next_add_rule_step(step: AddRuleStep, domain_index: usize) -> Option<AddRuleStep> {
    match step {
        AddRuleStep::EnterBinary => Some(AddRuleStep::EnterArgs),
        AddRuleStep::EnterArgs => Some(AddRuleStep::SelectDomain),
        AddRuleStep::SelectDomain => Some(match domain_index {
            0 => AddRuleStep::SelectEffect,
            1 => AddRuleStep::SelectFsOp,
            2 => AddRuleStep::EnterNetDomain,
            _ => AddRuleStep::EnterToolName,
        }),
        AddRuleStep::SelectFsOp => Some(AddRuleStep::EnterPath),
        AddRuleStep::EnterPath => Some(AddRuleStep::SelectEffect),
        AddRuleStep::EnterNetDomain => Some(AddRuleStep::SelectEffect),
        AddRuleStep::EnterToolName => Some(AddRuleStep::SelectEffect),
        AddRuleStep::SelectEffect => Some(AddRuleStep::SelectLevel),
        AddRuleStep::SelectLevel => None,
    }
}

/// Build the capability-specific part of the rule (without effect or exec wrapper).
fn build_cap_text(form: &AddRuleForm) -> String {
    match form.domain_index {
        1 => {
            let op = FS_OPS[form.fs_op_index];
            let path = form.path_input.value().trim().to_string();
            if op == "*" && path.is_empty() {
                "(fs)".to_string()
            } else if path.is_empty() {
                format!("(fs {op})")
            } else {
                format!("(fs {op} {path})")
            }
        }
        2 => {
            let domain = form.net_domain_input.value().trim().to_string();
            if domain.is_empty() || domain == "*" {
                "(net)".to_string()
            } else {
                let tok = quote_token_if_needed(&domain);
                format!("(net {tok})")
            }
        }
        _ => {
            let name = form.tool_name_input.value().trim().to_string();
            if name.is_empty() || name == "*" {
                "(tool)".to_string()
            } else {
                let tok = quote_token_if_needed(&name);
                format!("(tool {tok})")
            }
        }
    }
}

/// Build the rule s-expression text from an add-rule form.
pub(crate) fn build_rule_text(form: &AddRuleForm) -> String {
    let effect = EFFECT_NAMES[form.effect_index];
    let binary_raw = form.binary_input.value().trim().to_string();
    let has_command = !binary_raw.is_empty() && binary_raw != "*";

    if has_command && form.domain_index != 0 {
        // Sandboxed exec: ({effect} (exec {binary} {args} :sandbox (allow {cap})))
        let binary_tok = quote_token_if_needed(&binary_raw);
        let args = form.args_input.value().trim().to_string();
        let mut exec_part = format!("({effect} (exec {binary_tok}");
        for arg in args.split_whitespace() {
            exec_part.push_str(&format!(" {}", quote_token_if_needed(arg)));
        }
        let cap = build_cap_text(form);
        format!("{exec_part}) :sandbox (allow {cap}))")
    } else if form.domain_index == 0 {
        // Plain exec: ({effect} (exec {binary} {args...}))
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
    } else {
        // Standalone capability rule (no command): ({effect} {cap})
        let cap = build_cap_text(form);
        format!("({effect} {cap})")
    }
}

/// Quote a token with double quotes if it's not `*` and not already a parenthesized expression.
pub(crate) fn quote_token_if_needed(token: &str) -> String {
    if token == "*" || token.starts_with('(') || token.starts_with('"') {
        token.to_string()
    } else {
        format!("\"{token}\"")
    }
}

/// Parse a single rule from its s-expression text.
pub(crate) fn parse_rule_text(rule_text: &str) -> Result<Rule> {
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
pub(crate) fn row_search_text(kind: &TreeNodeKind) -> String {
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
        TreeNodeKind::SandboxLeaf { sandbox_rule, .. } => format!("sandbox {sandbox_rule}"),
        TreeNodeKind::SandboxGroup => "sandbox".into(),
        TreeNodeKind::SandboxName(name) => format!("sandbox {name}"),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::settings::{LoadedPolicy, PolicyLevel};

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

    fn make_app_multi(policies: &[LoadedPolicy]) -> App {
        App::new(policies)
    }

    // -----------------------------------------------------------------------
    // Pure function tests: quote_token_if_needed
    // -----------------------------------------------------------------------

    #[test]
    fn quote_token_star() {
        assert_eq!(quote_token_if_needed("*"), "*");
    }

    #[test]
    fn quote_token_parens() {
        assert_eq!(
            quote_token_if_needed("(subpath \"/tmp\")"),
            "(subpath \"/tmp\")"
        );
    }

    #[test]
    fn quote_token_word() {
        assert_eq!(quote_token_if_needed("git"), "\"git\"");
    }

    #[test]
    fn quote_token_already_quoted() {
        assert_eq!(quote_token_if_needed("\"git\""), "\"git\"");
    }

    // -----------------------------------------------------------------------
    // Pure function tests: parse_rule_text
    // -----------------------------------------------------------------------

    #[test]
    fn parse_rule_text_valid_exec() {
        let rule = parse_rule_text("(allow (exec \"git\"))").unwrap();
        assert_eq!(rule.effect, Effect::Allow);
    }

    #[test]
    fn parse_rule_text_invalid() {
        assert!(parse_rule_text("not a rule").is_err());
    }

    // -----------------------------------------------------------------------
    // Pure function tests: next_add_rule_step
    // -----------------------------------------------------------------------

    #[test]
    fn next_step_binary_to_args() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::EnterBinary, 0),
            Some(AddRuleStep::EnterArgs)
        );
    }

    #[test]
    fn next_step_args_to_domain() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::EnterArgs, 0),
            Some(AddRuleStep::SelectDomain)
        );
    }

    #[test]
    fn next_step_domain_exec_to_effect() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::SelectDomain, 0),
            Some(AddRuleStep::SelectEffect)
        );
    }

    #[test]
    fn next_step_domain_fs_to_fsop() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::SelectDomain, 1),
            Some(AddRuleStep::SelectFsOp)
        );
    }

    #[test]
    fn next_step_domain_net_to_netdomain() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::SelectDomain, 2),
            Some(AddRuleStep::EnterNetDomain)
        );
    }

    #[test]
    fn next_step_domain_tool_to_toolname() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::SelectDomain, 3),
            Some(AddRuleStep::EnterToolName)
        );
    }

    #[test]
    fn next_step_fsop_to_path() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::SelectFsOp, 0),
            Some(AddRuleStep::EnterPath)
        );
    }

    #[test]
    fn next_step_path_to_effect() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::EnterPath, 0),
            Some(AddRuleStep::SelectEffect)
        );
    }

    #[test]
    fn next_step_netdomain_to_effect() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::EnterNetDomain, 0),
            Some(AddRuleStep::SelectEffect)
        );
    }

    #[test]
    fn next_step_toolname_to_effect() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::EnterToolName, 0),
            Some(AddRuleStep::SelectEffect)
        );
    }

    #[test]
    fn next_step_effect_to_level() {
        assert_eq!(
            next_add_rule_step(AddRuleStep::SelectEffect, 0),
            Some(AddRuleStep::SelectLevel)
        );
    }

    #[test]
    fn next_step_level_completes() {
        assert_eq!(next_add_rule_step(AddRuleStep::SelectLevel, 0), None);
    }

    // -----------------------------------------------------------------------
    // Pure function tests: build_rule_text
    // -----------------------------------------------------------------------

    fn make_form(domain_index: usize) -> AddRuleForm {
        AddRuleForm {
            step: AddRuleStep::SelectLevel,
            domain_index,
            effect_index: 0, // allow
            level_index: 0,
            fs_op_index: 0,
            binary_input: TextInput::empty(),
            args_input: TextInput::empty(),
            path_input: TextInput::empty(),
            net_domain_input: TextInput::empty(),
            tool_name_input: TextInput::empty(),
            available_levels: vec![PolicyLevel::User],
            error: None,
        }
    }

    #[test]
    fn build_rule_text_exec_basic() {
        let mut form = make_form(0);
        form.binary_input = TextInput::new("git");
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (exec \"git\"))");
    }

    #[test]
    fn build_rule_text_exec_wildcard() {
        let mut form = make_form(0);
        form.binary_input = TextInput::new("*");
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (exec *))");
    }

    #[test]
    fn build_rule_text_exec_empty_binary() {
        let form = make_form(0);
        let text = build_rule_text(&form);
        // Empty binary defaults to *
        assert_eq!(text, "(allow (exec *))");
    }

    #[test]
    fn build_rule_text_exec_with_args() {
        let mut form = make_form(0);
        form.binary_input = TextInput::new("git");
        form.args_input = TextInput::new("push origin");
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (exec \"git\" \"push\" \"origin\"))");
    }

    #[test]
    fn build_rule_text_fs_wildcard() {
        let form = make_form(1);
        let text = build_rule_text(&form);
        // fs_op_index=0 is "*", path is empty
        assert_eq!(text, "(allow (fs))");
    }

    #[test]
    fn build_rule_text_fs_with_op_and_path() {
        let mut form = make_form(1);
        form.fs_op_index = 1; // "read"
        form.path_input = TextInput::new("/tmp");
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (fs read /tmp))");
    }

    #[test]
    fn build_rule_text_net_wildcard() {
        let form = make_form(2);
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (net))");
    }

    #[test]
    fn build_rule_text_net_with_domain() {
        let mut form = make_form(2);
        form.net_domain_input = TextInput::new("example.com");
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (net \"example.com\"))");
    }

    #[test]
    fn build_rule_text_tool_wildcard() {
        let form = make_form(3);
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (tool))");
    }

    #[test]
    fn build_rule_text_tool_with_name() {
        let mut form = make_form(3);
        form.tool_name_input = TextInput::new("Bash");
        let text = build_rule_text(&form);
        assert_eq!(text, "(allow (tool \"Bash\"))");
    }

    // -----------------------------------------------------------------------
    // Integration tests: App state
    // -----------------------------------------------------------------------

    #[test]
    fn app_new_empty() {
        let app = make_app("");
        assert!(app.flat_rows.is_empty());
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn app_new_with_rules() {
        let app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // Tree starts collapsed, so only root visible
        assert!(!app.flat_rows.is_empty());
    }

    #[test]
    fn add_rule_cursor_lands_on_exec() {
        let app_source = r#"(policy "main")"#;
        let mut app = make_app(app_source);

        app.start_add_rule();
        // Set binary to "ls"
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }

        // Step through: binary -> args -> domain -> effect -> level -> complete
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain (auto-selects exec)
        app.advance_add_rule(); // domain -> effect (exec skips to effect)
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));

        // Cursor should be on a leaf with the new rule
        let row = &app.flat_rows[app.cursor];
        assert!(
            matches!(&row.kind, TreeNodeKind::Leaf { rule, level, .. }
                if rule.to_string().contains("exec") && *level == PolicyLevel::User),
            "cursor should be on the new exec leaf, got {:?}",
            row.kind
        );
    }

    #[test]
    fn add_rule_cursor_lands_on_fs() {
        let mut app = make_app(r#"(policy "main")"#);
        app.start_add_rule();

        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("*");
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain

        // Select fs domain
        if let Mode::AddRule(form) = &mut app.mode {
            form.domain_index = 1;
        }
        app.advance_add_rule(); // domain -> fs_op
        app.advance_add_rule(); // fs_op -> path
        app.advance_add_rule(); // path -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));
        let row = &app.flat_rows[app.cursor];
        assert!(
            matches!(&row.kind, TreeNodeKind::Leaf { .. }),
            "cursor should be on the new fs leaf"
        );
    }

    #[test]
    fn add_rule_cursor_lands_on_net() {
        let mut app = make_app(r#"(policy "main")"#);
        app.start_add_rule();

        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("*");
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain

        if let Mode::AddRule(form) = &mut app.mode {
            form.domain_index = 2;
        }
        app.advance_add_rule(); // domain -> net_domain
        if let Mode::AddRule(form) = &mut app.mode {
            form.net_domain_input = TextInput::new("example.com");
        }
        app.advance_add_rule(); // net_domain -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));
        let row = &app.flat_rows[app.cursor];
        assert!(matches!(&row.kind, TreeNodeKind::Leaf { .. }));
    }

    #[test]
    fn add_rule_cursor_lands_on_tool() {
        let mut app = make_app(r#"(policy "main")"#);
        app.start_add_rule();

        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("*");
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain

        if let Mode::AddRule(form) = &mut app.mode {
            form.domain_index = 3;
        }
        app.advance_add_rule(); // domain -> tool_name
        if let Mode::AddRule(form) = &mut app.mode {
            form.tool_name_input = TextInput::new("Bash");
        }
        app.advance_add_rule(); // tool_name -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));
        let row = &app.flat_rows[app.cursor];
        assert!(matches!(&row.kind, TreeNodeKind::Leaf { .. }));
    }

    #[test]
    fn add_rule_multi_level_cursor_correct() {
        // Create policies at both User and Project levels with the same rule
        let user = test_policy(PolicyLevel::User, r#"(policy "main" (allow (exec "git")))"#);
        let project = test_policy(PolicyLevel::Project, r#"(policy "main")"#);
        let mut app = make_app_multi(&[user, project]);

        // Add a rule to the project level
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("git");
            form.level_index = 1; // Project level
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level

        // Confirm level is Project
        if let Mode::AddRule(form) = &mut app.mode {
            form.level_index = 1;
        }
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));

        // The cursor should be on the Project-level leaf, not the User-level one
        let row = &app.flat_rows[app.cursor];
        assert!(
            matches!(
                &row.kind,
                TreeNodeKind::Leaf {
                    level: PolicyLevel::Project,
                    ..
                }
            ),
            "cursor should be on the Project leaf, got {:?}",
            row.kind
        );
    }

    #[test]
    fn undo_restores_previous_state() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        let original_source = app.levels[0].source.clone();

        // Add a rule
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        // Source should have changed
        assert_ne!(app.levels[0].source, original_source);

        // Undo
        app.undo();
        assert_eq!(app.levels[0].source, original_source);
    }

    #[test]
    fn redo_after_undo() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);

        // Add a rule
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        let after_add_source = app.levels[0].source.clone();

        app.undo();
        assert_ne!(app.levels[0].source, after_add_source);

        app.redo();
        assert_eq!(app.levels[0].source, after_add_source);
    }

    #[test]
    fn navigation_basics() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")) (deny (exec "rm")))"#);
        app.expand_all();

        let total = app.flat_rows.len();
        assert!(total > 1);

        app.cursor_to_top();
        assert_eq!(app.cursor, 0);

        app.cursor_to_bottom();
        assert_eq!(app.cursor, total - 1);

        app.cursor_to_top();
        app.move_cursor_down();
        assert_eq!(app.cursor, 1);

        app.move_cursor_up();
        assert_eq!(app.cursor, 0);

        // Can't go below 0
        app.move_cursor_up();
        assert_eq!(app.cursor, 0);
    }

    #[test]
    fn search_finds_matches() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")) (deny (exec "cargo")))"#);
        app.expand_all();

        app.start_search();
        app.search_input = TextInput::new("git");
        app.commit_search();

        assert!(!app.search_matches.is_empty());
        // Cursor should be on first match
        assert!(app.search_matches.contains(&app.cursor));
    }

    #[test]
    fn row_search_text_leaf() {
        let kind = TreeNodeKind::Leaf {
            effect: Effect::Allow,
            rule: parse_rule_text("(allow (exec \"git\"))").unwrap(),
            level: PolicyLevel::User,
            policy: "main".to_string(),
        };
        let text = row_search_text(&kind);
        assert!(text.contains("allow"));
        assert!(text.contains("main"));
    }

    #[test]
    fn row_search_text_binary() {
        let text = row_search_text(&TreeNodeKind::Binary("git".to_string()));
        assert_eq!(text, "git");
    }

    #[test]
    fn search_finds_sandbox_content() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls" "-lha") :sandbox (allow (fs))))"#);
        app.expand_all();

        // Search for "sandbox"
        app.search_query = Some("sandbox".to_string());
        app.update_search_matches();

        assert!(
            !app.search_matches.is_empty(),
            "search for 'sandbox' should find sandbox nodes"
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip pipeline tests: form -> build_rule_text -> parse ->
    // rule.to_string() -> add to source -> rebuild tree -> find leaf
    // -----------------------------------------------------------------------

    /// Helper: simulate the full add-rule pipeline and check that the leaf
    /// exists in the rebuilt tree with the expected rule text.
    fn assert_rule_round_trips(form: &AddRuleForm, existing_source: &str) {
        let rule_text = build_rule_text(form);
        let rule = parse_rule_text(&rule_text)
            .unwrap_or_else(|e| panic!("parse_rule_text failed for '{rule_text}': {e}"));
        let display = rule.to_string();

        let new_source = edit::ensure_policy_block(existing_source, "main", r#"(policy "main")"#)
            .and_then(|s| edit::add_rule(&s, "main", &rule))
            .unwrap_or_else(|e| panic!("add_rule failed: {e}"));

        let loaded = LoadedPolicy {
            level: PolicyLevel::User,
            path: PathBuf::from("/tmp/test"),
            source: new_source,
        };
        let roots = tree::build_tree(&[loaded]);
        let rows = tree::flatten(&roots);

        let all_leaves: Vec<String> = rows
            .iter()
            .filter_map(|r| match &r.kind {
                TreeNodeKind::Leaf { rule, .. } => Some(rule.to_string()),
                _ => None,
            })
            .collect();

        let found = rows.iter().any(|row| {
            matches!(
                &row.kind,
                TreeNodeKind::Leaf { rule, level, policy, .. }
                    if rule.to_string() == display
                        && *level == PolicyLevel::User
                        && policy == "main"
            )
        });

        assert!(
            found,
            "tree should contain leaf matching '{}'\n  build_rule_text: '{}'\n  all leaves: {:?}",
            display, rule_text, all_leaves
        );
    }

    #[test]
    fn round_trip_exec_basic() {
        let mut form = make_form(0);
        form.binary_input = TextInput::new("ls");
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_exec_wildcard() {
        let form = make_form(0); // empty binary -> wildcard
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_exec_with_args() {
        let mut form = make_form(0);
        form.binary_input = TextInput::new("git");
        form.args_input = TextInput::new("push origin");
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_fs_wildcard() {
        let form = make_form(1);
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_fs_with_op() {
        let mut form = make_form(1);
        form.fs_op_index = 1; // "read"
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_net_wildcard() {
        let form = make_form(2);
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_net_with_domain() {
        let mut form = make_form(2);
        form.net_domain_input = TextInput::new("example.com");
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_tool_wildcard() {
        let form = make_form(3);
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_tool_with_name() {
        let mut form = make_form(3);
        form.tool_name_input = TextInput::new("Bash");
        assert_rule_round_trips(&form, r#"(policy "main")"#);
    }

    #[test]
    fn round_trip_with_existing_rules() {
        let mut form = make_form(0);
        form.binary_input = TextInput::new("ls");
        assert_rule_round_trips(
            &form,
            r#"(policy "main" (allow (exec "git")) (deny (exec "rm")))"#,
        );
    }

    /// Verify that cursor_to_rule finds the leaf at the exact correct index
    /// after adding to a pre-populated tree.
    #[test]
    fn cursor_to_rule_finds_exact_leaf() {
        let mut app = make_app(
            r#"(policy "main" (allow (exec "git")) (deny (exec "rm")) (ask (exec "cargo")))"#,
        );

        // Add "ls" rule
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete successfully"
        );

        // The cursor must be on a leaf whose rule contains "ls"
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, .. } => {
                assert!(
                    rule.to_string().contains("\"ls\""),
                    "cursor should be on the 'ls' rule, got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }

        // Also verify the leaf exists somewhere in flat_rows (in case cursor is wrong
        // but the leaf was added correctly)
        let all_leaves: Vec<(usize, String)> = app
            .flat_rows
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match &r.kind {
                TreeNodeKind::Leaf { rule, .. } => Some((i, rule.to_string())),
                _ => None,
            })
            .collect();
        let expected_idx = all_leaves
            .iter()
            .find(|(_, r)| r.contains("\"ls\""))
            .map(|(i, _)| *i);
        assert_eq!(
            Some(app.cursor),
            expected_idx,
            "cursor {} should match leaf index\nall leaves: {:?}",
            app.cursor,
            all_leaves
        );
    }

    /// Adding a conflicting rule (same binary, different effect) should surface
    /// a validation error and stay in AddRule mode.
    #[test]
    fn add_conflicting_rule_replaces_existing() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);

        // Add deny for git — should replace existing allow
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("git");
            form.effect_index = 1; // deny
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        // Should succeed — conflicting rule replaced
        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete (replace); mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!("AddRule(err={:?})", f.error),
                _ => "other".into(),
            }
        );

        // Cursor should be on the new deny rule
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, effect, .. } => {
                assert!(
                    rule.to_string().contains("\"git\"") && *effect == Effect::Deny,
                    "cursor should be on (deny (exec \"git\")), got: {} (effect={})",
                    rule,
                    effect,
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }

        // The old allow rule should be gone
        let has_allow_git = app.flat_rows.iter().any(|r| {
            matches!(&r.kind, TreeNodeKind::Leaf { rule, effect, .. }
                if rule.to_string().contains("\"git\"") && *effect == Effect::Allow)
        });
        assert!(
            !has_allow_git,
            "old (allow (exec \"git\")) should be removed"
        );
    }

    /// Adding a different binary with a different effect should succeed and
    /// place cursor on the new leaf.
    #[test]
    fn add_different_binary_different_effect() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);

        // Add deny for rm (different binary, no conflict)
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("rm");
            form.effect_index = 1; // deny
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));

        // Cursor should be on the DENY rm leaf
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { effect, rule, .. } => {
                assert_eq!(
                    *effect,
                    Effect::Deny,
                    "cursor should be on the deny rule, got {} with rule: {}",
                    effect,
                    rule
                );
                assert!(
                    rule.to_string().contains("\"rm\""),
                    "cursor should be on rm rule, got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    /// Verify cursor placement when adding to a tree that has rules from
    /// multiple domains (exec + fs + net) all under wildcard.
    #[test]
    fn add_exec_wildcard_with_mixed_domains() {
        let mut app = make_app(r#"(policy "main" (allow (fs)) (deny (net)) (ask (tool "Bash")))"#);

        // Add a wildcard exec rule
        app.start_add_rule();
        // leave binary empty -> wildcard
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain (domain stays exec=0)
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));

        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, .. } => {
                let text = rule.to_string();
                assert!(
                    text.contains("exec"),
                    "cursor should be on the exec leaf, got: {text}"
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Realistic scenario tests with DEFAULT_POLICY
    // -----------------------------------------------------------------------

    #[test]
    fn add_rule_to_default_policy() {
        use crate::settings::DEFAULT_POLICY;
        let policy = test_policy(PolicyLevel::User, DEFAULT_POLICY);
        let mut app = App::new(&[policy]);

        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("git");
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete successfully; mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!("AddRule(error={:?}, step={:?})", f.error, f.step),
                _ => "other".to_string(),
            }
        );

        // Cursor should be on the new exec leaf for git
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf {
                rule,
                level,
                policy,
                ..
            } => {
                assert!(
                    rule.to_string().contains("exec") && rule.to_string().contains("\"git\""),
                    "cursor should be on exec git leaf, got rule={}, level={level}, policy={policy}",
                    rule
                );
            }
            other => panic!(
                "cursor should be on a leaf, got: {other:?}\nall rows: {:?}",
                app.flat_rows
                    .iter()
                    .map(|r| format!("{:?}", r.kind))
                    .collect::<Vec<_>>()
            ),
        }
    }

    #[test]
    fn add_rule_to_default_policy_with_two_levels() {
        use crate::settings::DEFAULT_POLICY;
        let user = test_policy(PolicyLevel::User, DEFAULT_POLICY);
        let project = test_policy(PolicyLevel::Project, DEFAULT_POLICY);
        let mut app = App::new(&[user, project]);

        // Add a rule to the Project level
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("cargo");
            form.level_index = 1; // Project
        }
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> effect
        app.advance_add_rule(); // effect -> level

        // Ensure level_index is set to Project
        if let Mode::AddRule(form) = &mut app.mode {
            form.level_index = 1;
        }
        app.advance_add_rule(); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete successfully; mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!("AddRule(error={:?}, step={:?})", f.error, f.step),
                _ => "other".to_string(),
            }
        );

        // Cursor should be on the Project-level leaf
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, level, .. } => {
                assert_eq!(
                    *level,
                    PolicyLevel::Project,
                    "cursor should be on Project level leaf, got level={level}, rule={rule}"
                );
                assert!(
                    rule.to_string().contains("cargo"),
                    "cursor should be on cargo rule, got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    /// Test cursor_to_rule directly to verify it finds/misses correctly.
    #[test]
    fn cursor_to_rule_returns_false_on_mismatch() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.expand_all();

        // Should find the existing rule
        let found = app.cursor_to_rule(
            &parse_rule_text(r#"(allow (exec "git"))"#)
                .unwrap()
                .to_string(),
            PolicyLevel::User,
            "main",
        );
        assert!(found, "should find existing rule");

        // Should NOT find a rule that doesn't exist
        let found = app.cursor_to_rule(
            &parse_rule_text(r#"(deny (exec "ls"))"#)
                .unwrap()
                .to_string(),
            PolicyLevel::User,
            "main",
        );
        assert!(!found, "should not find non-existent rule");

        // Should NOT find with wrong level
        let found = app.cursor_to_rule(
            &parse_rule_text(r#"(allow (exec "git"))"#)
                .unwrap()
                .to_string(),
            PolicyLevel::Project,
            "main",
        );
        assert!(!found, "should not find rule at wrong level");

        // Should NOT find with wrong policy
        let found = app.cursor_to_rule(
            &parse_rule_text(r#"(allow (exec "git"))"#)
                .unwrap()
                .to_string(),
            PolicyLevel::User,
            "other",
        );
        assert!(!found, "should not find rule in wrong policy");
    }

    /// Ensure that after add, the tree is expanded to show the new leaf
    /// even if the tree was previously collapsed.
    #[test]
    fn add_rule_expands_ancestors_of_new_leaf() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // Start collapsed
        app.collapse_all();
        let collapsed_count = app.flat_rows.len();

        // Add a rule
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        assert!(matches!(app.mode, Mode::Normal));

        // After adding, the tree should have more visible rows because
        // ancestors of the new leaf were expanded
        assert!(
            app.flat_rows.len() > collapsed_count,
            "tree should be expanded to show new leaf (collapsed={}, after={})",
            collapsed_count,
            app.flat_rows.len()
        );

        // And the cursor should be on a leaf
        let row = &app.flat_rows[app.cursor];
        assert!(
            matches!(&row.kind, TreeNodeKind::Leaf { rule, .. } if rule.to_string().contains("\"ls\"")),
            "cursor should be on the new ls leaf, got: {:?}",
            row.kind
        );
    }

    /// Detailed diagnostic: dump all flat_rows after add to verify
    /// what cursor_to_rule sees.
    #[test]
    fn add_rule_diagnostic_all_leaves() {
        let mut app = make_app(
            r#"(policy "main" (allow (exec "git")) (deny (exec "rm")) (allow (fs read)))"#,
        );

        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("cargo");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        assert!(matches!(app.mode, Mode::Normal));

        // Collect all leaves
        let leaves: Vec<(usize, String, PolicyLevel, String)> = app
            .flat_rows
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match &r.kind {
                TreeNodeKind::Leaf {
                    rule,
                    level,
                    policy,
                    ..
                } => Some((i, rule.to_string(), *level, policy.clone())),
                _ => None,
            })
            .collect();

        // There should be exactly 4 leaves (git, rm, fs read, cargo)
        assert_eq!(leaves.len(), 4, "expected 4 leaves, got: {leaves:?}");

        // The cargo leaf should exist and cursor should point to it
        let cargo_leaf = leaves.iter().find(|(_, r, _, _)| r.contains("cargo"));
        assert!(
            cargo_leaf.is_some(),
            "cargo leaf should exist in: {leaves:?}"
        );

        let (cargo_idx, _, _, _) = cargo_leaf.unwrap();
        assert_eq!(
            app.cursor, *cargo_idx,
            "cursor={} should be on cargo leaf at idx={}\nall leaves: {leaves:?}",
            app.cursor, cargo_idx
        );
    }

    // -----------------------------------------------------------------------
    // Key-event integration tests (simulate actual user input)
    // -----------------------------------------------------------------------

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_str(app: &mut App, s: &str) {
        for ch in s.chars() {
            input::handle_key(app, key(KeyCode::Char(ch)));
        }
    }

    fn press_enter(app: &mut App) {
        input::handle_key(app, key(KeyCode::Enter));
    }

    fn press_right(app: &mut App) {
        input::handle_key(app, key(KeyCode::Right));
    }

    /// Simulate adding "git" exec rule via actual key events.
    #[test]
    fn key_event_add_exec_rule() {
        let mut app = make_app(r#"(policy "main")"#);

        // Press 'a' to start add rule
        input::handle_key(&mut app, key(KeyCode::Char('a')));
        assert!(matches!(app.mode, Mode::AddRule(_)));

        // Type "git" for binary
        type_str(&mut app, "git");
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.binary_input.value(), "git");
            assert_eq!(form.step, AddRuleStep::EnterBinary);
        }

        // Enter -> args step
        press_enter(&mut app);
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::EnterArgs);
        }

        // Enter -> domain step (empty args)
        press_enter(&mut app);
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectDomain);
            assert_eq!(form.domain_index, 0, "should auto-select exec");
        }

        // Enter -> effect step (exec selected)
        press_enter(&mut app);
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectEffect);
            assert_eq!(form.effect_index, 0, "default effect should be allow");
        }

        // Enter -> level step
        press_enter(&mut app);
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectLevel);
        }

        // Enter -> complete
        press_enter(&mut app);
        assert!(matches!(app.mode, Mode::Normal), "should complete add rule");

        // Cursor should be on the new leaf
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, .. } => {
                assert!(
                    rule.to_string().contains("\"git\""),
                    "cursor should be on git leaf, got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    /// Simulate adding a deny rule by navigating effect with arrow keys.
    #[test]
    fn key_event_add_deny_rule() {
        let mut app = make_app(r#"(policy "main")"#);

        input::handle_key(&mut app, key(KeyCode::Char('a')));
        type_str(&mut app, "rm");
        press_enter(&mut app); // binary -> args
        press_enter(&mut app); // args -> domain
        press_enter(&mut app); // domain -> effect

        // Navigate to "deny" (index 1)
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectEffect);
            assert_eq!(form.effect_index, 0); // starts at "allow"
        }
        press_right(&mut app); // effect_index = 1 ("deny")
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.effect_index, 1);
        }

        press_enter(&mut app); // effect -> level
        press_enter(&mut app); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));

        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { effect, rule, .. } => {
                assert_eq!(
                    *effect,
                    Effect::Deny,
                    "should be deny, got {} with rule {}",
                    effect,
                    rule
                );
                assert!(
                    rule.to_string().contains("\"rm\""),
                    "should be rm rule, got: {}",
                    rule
                );
            }
            other => panic!("expected leaf, got: {other:?}"),
        }
    }

    /// Simulate adding an fs rule via key events with domain selection.
    #[test]
    fn key_event_add_fs_rule() {
        let mut app = make_app(r#"(policy "main")"#);

        input::handle_key(&mut app, key(KeyCode::Char('a')));
        // Leave binary empty -> wildcard, press Enter
        press_enter(&mut app); // binary -> args
        press_enter(&mut app); // args -> domain

        // Navigate to fs (index 1)
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectDomain);
        }
        press_right(&mut app); // domain_index = 1 (fs)
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.domain_index, 1);
        }

        press_enter(&mut app); // domain -> fs_op
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectFsOp);
        }

        // Select "read" (index 1)
        press_right(&mut app); // fs_op_index = 1 ("read")
        press_enter(&mut app); // fs_op -> path
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::EnterPath);
        }

        press_enter(&mut app); // path (empty) -> effect
        press_enter(&mut app); // effect -> level
        press_enter(&mut app); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete; mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!("AddRule(err={:?}, step={:?})", f.error, f.step),
                _ => "other".into(),
            }
        );

        let row = &app.flat_rows[app.cursor];
        assert!(
            matches!(&row.kind, TreeNodeKind::Leaf { rule, .. } if rule.to_string().contains("fs")),
            "cursor should be on fs leaf, got: {:?}",
            row.kind
        );
    }

    /// Simulate the complete flow with DEFAULT_POLICY via key events.
    #[test]
    fn key_event_add_to_default_policy() {
        use crate::settings::DEFAULT_POLICY;
        let policy = test_policy(PolicyLevel::User, DEFAULT_POLICY);
        let mut app = App::new(&[policy]);

        input::handle_key(&mut app, key(KeyCode::Char('a')));
        type_str(&mut app, "cargo");
        press_enter(&mut app); // binary -> args
        press_enter(&mut app); // args -> domain (auto-exec)
        press_enter(&mut app); // domain -> effect
        press_enter(&mut app); // effect -> level
        press_enter(&mut app); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete; mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!("AddRule(err={:?}, step={:?})", f.error, f.step),
                _ => "other".into(),
            }
        );

        // Verify cursor is on the new cargo leaf
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, .. } => {
                assert!(
                    rule.to_string().contains("cargo"),
                    "cursor should be on cargo leaf, got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    /// Simulate adding a rule to a specific level when multiple exist.
    #[test]
    fn key_event_add_to_project_level() {
        let user = test_policy(PolicyLevel::User, r#"(policy "main")"#);
        let project = test_policy(PolicyLevel::Project, r#"(policy "main")"#);
        let mut app = make_app_multi(&[user, project]);

        input::handle_key(&mut app, key(KeyCode::Char('a')));
        type_str(&mut app, "npm");
        press_enter(&mut app); // binary -> args
        press_enter(&mut app); // args -> domain
        press_enter(&mut app); // domain -> effect
        press_enter(&mut app); // effect -> level

        // Navigate to Project level (index 1)
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.step, AddRuleStep::SelectLevel);
            assert_eq!(form.level_index, 0); // default is User
        }
        press_right(&mut app); // level_index = 1 (Project)
        if let Mode::AddRule(form) = &app.mode {
            assert_eq!(form.level_index, 1);
        }

        press_enter(&mut app); // level -> complete

        assert!(matches!(app.mode, Mode::Normal));

        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, level, .. } => {
                assert_eq!(
                    *level,
                    PolicyLevel::Project,
                    "cursor should be on Project leaf, got level={level} rule={}",
                    rule
                );
                assert!(rule.to_string().contains("npm"), "got: {}", rule);
            }
            other => panic!("expected leaf, got: {other:?}"),
        }
    }

    /// User enters "ls" + "-lha", selects fs domain, effect=ask.
    /// Should produce a sandboxed exec rule: (ask (exec "ls" "-lha" :sandbox (allow (fs))))
    #[test]
    fn sandboxed_exec_ls_fs() {
        let source = r#"(policy "main"
            (allow (exec "ls" "-lha"))
            (allow (fs read))
            (ask (fs))
            (allow (net))
        )"#;
        let mut app = make_app(source);

        input::handle_key(&mut app, key(KeyCode::Char('a')));
        type_str(&mut app, "ls");
        press_enter(&mut app); // binary -> args
        type_str(&mut app, "-lha");
        press_enter(&mut app); // args -> domain
        // domain auto-selected to exec (0), user changes to fs (1)
        press_right(&mut app); // domain = fs
        press_enter(&mut app); // domain -> fs_op
        press_enter(&mut app); // fs_op (wildcard) -> path
        press_enter(&mut app); // path (empty) -> effect
        // Navigate to "ask" (index 2)
        press_right(&mut app); // deny
        press_right(&mut app); // ask
        press_enter(&mut app); // effect -> level
        press_enter(&mut app); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete; mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!(
                    "AddRule(step={:?}, err={:?}, rule={})",
                    f.step,
                    f.error,
                    build_rule_text(f)
                ),
                _ => "other".into(),
            }
        );

        // Cursor should be on the sandboxed exec leaf
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, effect, .. } => {
                let text = rule.to_string();
                assert!(
                    text.contains("\"ls\"") && text.contains(":sandbox") && *effect == Effect::Ask,
                    "expected sandboxed (ask (exec \"ls\" ... :sandbox ...)), got: {text}"
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    /// build_rule_text: command + fs domain = sandboxed exec rule
    #[test]
    fn build_rule_text_sandboxed_exec_fs() {
        let mut f = make_form(1); // fs
        f.binary_input = TextInput::new("ls");
        f.args_input = TextInput::new("-lha");
        f.effect_index = 2; // ask
        assert_eq!(
            build_rule_text(&f),
            r#"(ask (exec "ls" "-lha") :sandbox (allow (fs)))"#
        );
    }

    /// build_rule_text: command + net domain = sandboxed exec rule
    #[test]
    fn build_rule_text_sandboxed_exec_net() {
        let mut f = make_form(2); // net
        f.binary_input = TextInput::new("curl");
        f.effect_index = 0; // allow
        assert_eq!(
            build_rule_text(&f),
            r#"(allow (exec "curl") :sandbox (allow (net)))"#
        );
    }

    /// build_rule_text: no command + fs domain = standalone fs rule (not sandboxed)
    #[test]
    fn build_rule_text_standalone_fs_no_command() {
        let f = make_form(1); // fs, no binary
        assert_eq!(build_rule_text(&f), "(allow (fs))");
    }

    /// build_rule_text: wildcard command + fs domain = standalone fs rule
    #[test]
    fn build_rule_text_wildcard_command_fs() {
        let mut f = make_form(1); // fs
        f.binary_input = TextInput::new("*");
        assert_eq!(build_rule_text(&f), "(allow (fs))");
    }

    /// build_rule_text: command + exec domain = plain exec (no sandbox)
    #[test]
    fn build_rule_text_plain_exec_with_command() {
        let mut f = make_form(0); // exec
        f.binary_input = TextInput::new("git");
        f.effect_index = 1; // deny
        assert_eq!(build_rule_text(&f), r#"(deny (exec "git"))"#);
    }

    /// When (allow (fs)) already exists, adding it again is idempotent.
    /// cursor_to_rule should find the existing leaf.
    #[test]
    fn add_fs_rule_idempotent_cursor_correct() {
        let source = r#"(policy "main"
            (allow (exec "ls" "-lha"))
            (allow (fs read))
            (allow (fs))
            (allow (net))
        )"#;
        let mut app = make_app(source);

        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.domain_index = 1; // fs
        }
        // Skip binary/args since they're irrelevant for fs
        app.advance_add_rule(); // binary -> args
        app.advance_add_rule(); // args -> domain
        app.advance_add_rule(); // domain -> fs_op
        app.advance_add_rule(); // fs_op -> path
        app.advance_add_rule(); // path -> effect
        app.advance_add_rule(); // effect -> level
        app.advance_add_rule(); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete (idempotent)"
        );

        // Cursor should be on the (allow (fs)) leaf
        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, .. } => {
                assert_eq!(
                    rule.to_string(),
                    "(allow (fs))",
                    "cursor should be on (allow (fs)), got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    /// Non-conflicting fs add: add (allow (fs read)) to a policy without it.
    #[test]
    fn add_fs_read_rule_cursor_correct() {
        let source = r#"(policy "main"
            (allow (exec "ls"))
            (allow (net))
        )"#;
        let mut app = make_app(source);

        input::handle_key(&mut app, key(KeyCode::Char('a')));
        press_enter(&mut app); // binary (empty) -> args
        press_enter(&mut app); // args -> domain
        press_right(&mut app); // domain = fs
        press_enter(&mut app); // domain -> fs_op

        // Select "read" (index 1)
        press_right(&mut app); // fs_op = read
        press_enter(&mut app); // fs_op -> path
        press_enter(&mut app); // path (empty) -> effect
        press_enter(&mut app); // effect (allow) -> level
        press_enter(&mut app); // level -> complete

        assert!(
            matches!(app.mode, Mode::Normal),
            "should complete; mode = {:?}",
            match &app.mode {
                Mode::AddRule(f) => format!("AddRule(err={:?})", f.error),
                _ => "other".into(),
            }
        );

        let row = &app.flat_rows[app.cursor];
        match &row.kind {
            TreeNodeKind::Leaf { rule, .. } => {
                assert!(
                    rule.to_string().contains("fs") && rule.to_string().contains("read"),
                    "cursor should be on fs read leaf, got: {}",
                    rule
                );
            }
            other => panic!("cursor should be on a leaf, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Sandbox editing tests
    // -----------------------------------------------------------------------

    /// Helper: navigate to the first SandboxLeaf in a fully expanded app.
    fn cursor_to_sandbox_leaf(app: &mut App) -> bool {
        app.expand_all();
        for (i, row) in app.flat_rows.iter().enumerate() {
            if matches!(&row.kind, TreeNodeKind::SandboxLeaf { .. }) {
                app.cursor = i;
                return true;
            }
        }
        false
    }

    #[test]
    fn sandbox_effect_cycle() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs))))"#);
        assert!(
            cursor_to_sandbox_leaf(&mut app),
            "should find a sandbox leaf"
        );

        // Start effect select on sandbox leaf
        app.start_select_effect();
        assert!(
            matches!(app.mode, Mode::SelectSandboxEffect(_)),
            "should enter SelectSandboxEffect mode"
        );

        // Change to deny (index 2)
        if let Mode::SelectSandboxEffect(state) = &mut app.mode {
            state.effect_index = 2; // auto deny
        }
        app.confirm_select_sandbox_effect();

        assert!(matches!(app.mode, Mode::Normal));

        // Verify the sandbox sub-rule effect changed
        let status = app.status_message.as_ref().map(|s| s.text.as_str());
        assert_eq!(status, Some("Effect changed"));

        // The source should now contain "deny" in the sandbox
        let source = &app.levels[0].source;
        assert!(
            source.contains("deny") && source.contains(":sandbox"),
            "source should reflect changed sandbox effect: {source}"
        );
    }

    #[test]
    fn sandbox_delete() {
        let mut app =
            make_app(r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs)) (deny (net *))))"#);
        assert!(cursor_to_sandbox_leaf(&mut app));

        // Start delete on sandbox leaf
        app.start_delete();
        assert!(
            matches!(
                app.mode,
                Mode::Confirm(ConfirmAction::DeleteSandboxRule { .. })
            ),
            "should enter Confirm(DeleteSandboxRule) mode"
        );

        // Confirm the deletion
        let mode = std::mem::replace(&mut app.mode, Mode::Normal);
        if let Mode::Confirm(ConfirmAction::DeleteSandboxRule {
            level,
            policy,
            sandbox_rule_text,
            parent_rule,
        }) = mode
        {
            app.confirm_delete_sandbox_rule(level, policy, sandbox_rule_text, parent_rule);
        }

        let status = app.status_message.as_ref().map(|s| s.text.as_str());
        assert_eq!(status, Some("Sandbox rule deleted"));

        // The parent rule should still exist but with one fewer sandbox sub-rule
        let source = &app.levels[0].source;
        assert!(
            source.contains(":sandbox"),
            "parent rule should still have sandbox: {source}"
        );
    }

    #[test]
    fn sandbox_delete_last_removes_sandbox() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs))))"#);
        assert!(cursor_to_sandbox_leaf(&mut app));

        app.start_delete();
        let mode = std::mem::replace(&mut app.mode, Mode::Normal);
        if let Mode::Confirm(ConfirmAction::DeleteSandboxRule {
            level,
            policy,
            sandbox_rule_text,
            parent_rule,
        }) = mode
        {
            app.confirm_delete_sandbox_rule(level, policy, sandbox_rule_text, parent_rule);
        }

        // With only one sandbox sub-rule, deleting it should remove the sandbox entirely
        let source = &app.levels[0].source;
        assert!(
            !source.contains(":sandbox"),
            "deleting the last sandbox sub-rule should remove :sandbox from the parent: {source}"
        );
        // But the parent exec rule should still exist
        assert!(
            source.contains("exec") && source.contains("\"ls\""),
            "parent exec rule should still exist: {source}"
        );
    }

    #[test]
    fn sandbox_edit() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs))))"#);
        assert!(cursor_to_sandbox_leaf(&mut app));

        // Start edit on sandbox leaf
        app.start_edit_rule();
        assert!(
            matches!(app.mode, Mode::EditSandboxRule(_)),
            "should enter EditSandboxRule mode"
        );

        // Change the rule text to (deny (net *))
        if let Mode::EditSandboxRule(state) = &mut app.mode {
            state.input.clear();
            for c in "(deny (net *))".chars() {
                state.input.insert_char(c);
            }
        }
        app.complete_edit_sandbox_rule();

        assert!(matches!(app.mode, Mode::Normal));
        let status = app.status_message.as_ref().map(|s| s.text.as_str());
        assert_eq!(status, Some("Sandbox rule updated"));

        // Source should now contain "net" in the sandbox instead of "fs"
        let source = &app.levels[0].source;
        assert!(
            source.contains("net") && source.contains(":sandbox"),
            "source should reflect edited sandbox rule: {source}"
        );
    }

    #[test]
    fn search_finds_sandbox_leaf_content() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls") :sandbox (allow (fs))))"#);
        app.expand_all();

        // Search for "sandbox" should find SandboxLeaf nodes
        app.search_query = Some("sandbox".to_string());
        app.update_search_matches();

        assert!(
            !app.search_matches.is_empty(),
            "search for 'sandbox' should find sandbox leaf nodes"
        );
    }
}
