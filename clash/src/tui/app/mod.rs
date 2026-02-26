//! App state, main event loop, dispatch input.

mod edit;
mod search;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, MouseEvent, MouseEventKind};

use crate::policy::ast::Rule;
use crate::policy::compile::{compile_multi_level, detect_all_shadows};
use crate::policy::edit as policy_edit;
use crate::settings::{LoadedPolicy, PolicyLevel};

use super::editor::TextInput;
use super::input::{self, InputResult};
use super::render;
use super::tree::{self, FlatRow, LeafInfo, NodeId, TreeArena, TreeNodeKind};

// Re-export constants used by input.rs and render.rs
pub(crate) use self::edit::{DOMAIN_NAMES, EFFECT_DISPLAY, EFFECT_NAMES, FS_OPS};
// Re-export helpers used only by tests in other modules
#[cfg(test)]
pub(crate) use self::edit::{
    build_rule, build_rule_text, next_add_rule_step, parse_rule_text, quote_token_if_needed,
};

// ---------------------------------------------------------------------------
// Mode and form types
// ---------------------------------------------------------------------------

pub enum Mode {
    Normal,
    Confirm(ConfirmAction),
    ConfirmSave(SaveDiff),
    AddRule(AddRuleForm),
    EditRule(EditRuleState),
    SelectEffect(SelectEffectState),
    Search,
}

/// Diff information for the save confirmation overlay.
pub struct SaveDiff {
    pub hunks: Vec<DiffHunk>,
    /// Scroll position within the diff overlay.
    pub scroll: usize,
}

/// A diff hunk for one policy level.
pub struct DiffHunk {
    pub level: PolicyLevel,
    pub lines: Vec<DiffLine>,
}

/// A single line in a diff.
pub enum DiffLine {
    Context(String),
    Added(String),
    Removed(String),
}

pub enum RuleTarget {
    Regular {
        level: PolicyLevel,
        policy: String,
    },
    Sandbox {
        level: PolicyLevel,
        policy: String,
        parent_rule: Rule,
    },
}

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
    DeleteBranch {
        label: String,
        leaves: Vec<LeafInfo>,
    },
    QuitUnsaved,
}

#[derive(Debug)]
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
    /// Return the currently active text input for the current step, if any.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRuleStep {
    EnterBinary,
    EnterArgs,
    SelectDomain,
    SelectFsOp,
    EnterPath,
    EnterNetDomain,
    EnterToolName,
    SelectEffect,
    SelectLevel,
}

pub struct EditRuleState {
    pub input: TextInput,
    pub original_rule: Rule,
    pub target: RuleTarget,
    pub error: Option<String>,
}

pub struct SelectEffectState {
    pub effect_index: usize,
    pub rule: Rule,
    pub target: RuleTarget,
}

enum SandboxMutation {
    Delete,
    Replace(Rule),
}

// ---------------------------------------------------------------------------
// Level state
// ---------------------------------------------------------------------------

pub struct LevelState {
    pub level: PolicyLevel,
    pub path: PathBuf,
    pub original_source: String,
    pub source: String,
}

impl LevelState {
    pub fn is_modified(&self) -> bool {
        self.source != self.original_source
    }
}

// ---------------------------------------------------------------------------
// Edit history (undo/redo)
// ---------------------------------------------------------------------------

pub(super) struct UndoEntry {
    pub(super) sources: Vec<(PolicyLevel, String)>,
    pub(super) cursor: usize,
}

pub(super) struct EditHistory {
    pub undo_stack: Vec<UndoEntry>,
    pub redo_stack: Vec<UndoEntry>,
}

impl EditHistory {
    pub fn new() -> Self {
        Self {
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Status message
// ---------------------------------------------------------------------------

pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
    pub created_at: Instant,
}

/// How long status messages remain visible before auto-clearing.
const STATUS_MESSAGE_TTL: Duration = Duration::from_secs(3);

/// Tick interval for background housekeeping (status message expiry).
const TICK_INTERVAL: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// Search state
// ---------------------------------------------------------------------------

pub struct SearchState {
    /// Search text input.
    pub input: TextInput,
    /// Active search query (after Enter).
    pub query: Option<String>,
    /// Flat row indices that match the search.
    pub matches: Vec<usize>,
    /// Current position in matches.
    pub match_cursor: usize,
}

impl SearchState {
    pub fn new() -> Self {
        Self {
            input: TextInput::empty(),
            query: None,
            matches: Vec::new(),
            match_cursor: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Tree state
// ---------------------------------------------------------------------------

pub struct TreeState {
    pub arena: TreeArena,
    pub flat_rows: Vec<FlatRow>,
    pub cursor: usize,
    pub viewport_height: usize,
}

impl TreeState {
    pub fn new(arena: TreeArena) -> Self {
        let flat_rows = tree::flatten(&arena);
        Self {
            arena,
            flat_rows,
            cursor: 0,
            viewport_height: 20,
        }
    }

    /// Rebuild flat_rows from existing tree (for expand/collapse).
    /// Does NOT re-index search matches — caller must do that.
    pub fn rebuild_flat(&mut self) {
        self.flat_rows = tree::flatten(&self.arena);
        self.clamp_cursor();
    }

    /// Clamp cursor to valid range.
    fn clamp_cursor(&mut self) {
        if self.cursor >= self.flat_rows.len() && !self.flat_rows.is_empty() {
            self.cursor = self.flat_rows.len() - 1;
        }
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
        self.cursor = self.cursor.saturating_sub(self.viewport_height);
    }

    pub fn page_down(&mut self) {
        if !self.flat_rows.is_empty() {
            self.cursor = (self.cursor + self.viewport_height).min(self.flat_rows.len() - 1);
        }
    }

    pub fn collapse_or_parent(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };

        if row.has_children && row.expanded {
            self.arena[row.node_id].expanded = false;
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
            self.arena[row.node_id].expanded = true;
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
        self.arena.for_each_mut(|node| node.expanded = false);
        self.rebuild_flat();
    }

    /// Expand all tree nodes.
    pub fn expand_all(&mut self) {
        self.arena.for_each_mut(|node| node.expanded = true);
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
        let ancestors = self.arena.ancestors(row.node_id);
        if ancestors.is_empty() {
            return None;
        }

        let mut parts: Vec<String> = Vec::new();
        for &id in &ancestors {
            let node = &self.arena[id];
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
        let node_id = row.node_id;
        self.arena[node_id].expanded = !self.arena[node_id].expanded;
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
        let node_id = row.node_id;

        // Collect the node + all descendants, check if any expanded
        fn any_expanded(arena: &TreeArena, id: NodeId) -> bool {
            let node = &arena[id];
            (node.expanded && !node.children.is_empty())
                || node.children.iter().any(|&c| any_expanded(arena, c))
        }
        fn set_recursive(arena: &mut TreeArena, id: NodeId, expanded: bool) {
            let children: Vec<NodeId> = arena[id].children.clone();
            if !children.is_empty() {
                arena[id].expanded = expanded;
            }
            for c in children {
                set_recursive(arena, c, expanded);
            }
        }
        let expand = !any_expanded(&self.arena, node_id);
        set_recursive(&mut self.arena, node_id, expand);
        self.rebuild_flat();
    }

    /// Toggle expand/collapse on the current node.
    pub fn toggle_expand(&mut self) {
        let Some(row) = self.flat_rows.get(self.cursor) else {
            return;
        };

        if row.has_children {
            let node_id = row.node_id;
            self.arena[node_id].expanded = !self.arena[node_id].expanded;
            self.rebuild_flat();
        }
    }
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

pub struct App {
    pub tree: TreeState,
    pub levels: Vec<LevelState>,
    pub show_help: bool,
    pub mode: Mode,
    pub status_message: Option<StatusMessage>,
    pub(super) history: EditHistory,
    pub search: SearchState,
}

impl App {
    /// Create a new app from loaded policies.
    pub fn new(policies: &[LoadedPolicy]) -> Self {
        let levels: Vec<LevelState> = policies
            .iter()
            .map(|p| {
                let source = policy_edit::normalize(&p.source).unwrap_or_else(|_| p.source.clone());
                LevelState {
                    level: p.level,
                    path: p.path.clone(),
                    original_source: source.clone(),
                    source,
                }
            })
            .collect();

        let loaded = Self::to_loaded_policies(&levels);
        let mut arena = tree::build_tree(&loaded);

        // Compute shadow detection for multi-level policies
        if levels.len() > 1 {
            let level_pairs: Vec<(PolicyLevel, &str)> = levels
                .iter()
                .map(|ls| (ls.level, ls.source.as_str()))
                .collect();
            if let Ok(dt) = compile_multi_level(&level_pairs) {
                let all = detect_all_shadows(&dt);
                let mut shadowed = HashSet::new();
                for (rules, shadow_map) in [
                    (&dt.exec_rules, &all.exec),
                    (&dt.fs_rules, &all.fs),
                    (&dt.net_rules, &all.net),
                    (&dt.tool_rules, &all.tool),
                ] {
                    for &idx in shadow_map.keys() {
                        if let Some(rule) = rules.get(idx)
                            && let Some(level) = rule.origin_level
                        {
                            shadowed.insert((level, rule.source.to_string()));
                        }
                    }
                }
                Self::mark_shadows(&mut arena, &shadowed);
            }
        }

        // Start fully collapsed
        arena.for_each_mut(|node| node.expanded = false);

        Self {
            tree: TreeState::new(arena),
            levels,
            show_help: false,
            mode: Mode::Normal,
            status_message: None,
            history: EditHistory::new(),
            search: SearchState::new(),
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
        self.tree.arena = tree::build_tree(&loaded);

        // Compute shadow detection for multi-level policies
        if self.levels.len() > 1 {
            let shadowed = self.compute_shadowed_rules();
            Self::mark_shadows(&mut self.tree.arena, &shadowed);
        }

        self.tree.flat_rows = tree::flatten(&self.tree.arena);
        self.tree.clamp_cursor();
        self.update_search_matches();
    }

    /// Compute the set of (level, rule_text) pairs that are shadowed.
    fn compute_shadowed_rules(&self) -> HashSet<(PolicyLevel, String)> {
        let levels: Vec<(PolicyLevel, &str)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.as_str()))
            .collect();
        let Ok(tree) = compile_multi_level(&levels) else {
            return HashSet::new();
        };
        let all = detect_all_shadows(&tree);
        let mut shadowed = HashSet::new();
        for (rules, shadow_map) in [
            (&tree.exec_rules, &all.exec),
            (&tree.fs_rules, &all.fs),
            (&tree.net_rules, &all.net),
            (&tree.tool_rules, &all.tool),
        ] {
            for &idx in shadow_map.keys() {
                if let Some(rule) = rules.get(idx)
                    && let Some(level) = rule.origin_level
                {
                    shadowed.insert((level, rule.source.to_string()));
                }
            }
        }
        shadowed
    }

    /// Walk the arena and mark Leaf nodes as shadowed if they match.
    fn mark_shadows(arena: &mut TreeArena, shadowed: &HashSet<(PolicyLevel, String)>) {
        arena.for_each_mut(|node| {
            if let TreeNodeKind::Leaf {
                level,
                rule,
                is_shadowed,
                ..
            } = &mut node.kind
            {
                *is_shadowed = shadowed.contains(&(*level, rule.to_string()));
            }
        });
    }

    /// Rebuild flat_rows from existing tree, then re-index search matches.
    pub fn rebuild_flat(&mut self) {
        self.tree.rebuild_flat();
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
        let arena = &self.tree.arena;

        // Search the flat rows for a matching leaf.
        let find = |rows: &[FlatRow], arena: &TreeArena| -> Option<usize> {
            rows.iter().position(|row| {
                matches!(
                    &arena[row.node_id].kind,
                    TreeNodeKind::Leaf { rule, level, policy, .. }
                        if rule.to_string() == rule_text
                            && *level == target_level
                            && policy == target_policy
                )
            })
        };

        let Some(i) = find(&self.tree.flat_rows, arena) else {
            return false;
        };

        // Ensure ancestors are expanded
        let node_id = self.tree.flat_rows[i].node_id;
        let ancestors = self.tree.arena.ancestors(node_id);
        for &aid in &ancestors[..ancestors.len().saturating_sub(1)] {
            self.tree.arena[aid].expanded = true;
        }
        self.rebuild_flat();

        // Re-find after re-flatten (indices may have shifted)
        self.tree.cursor = find(&self.tree.flat_rows, &self.tree.arena).unwrap_or(i);
        true
    }

    // -----------------------------------------------------------------------
    // Navigation delegates
    // -----------------------------------------------------------------------

    pub fn move_cursor_down(&mut self) {
        self.tree.move_cursor_down();
    }

    pub fn move_cursor_up(&mut self) {
        self.tree.move_cursor_up();
    }

    pub fn cursor_to_top(&mut self) {
        self.tree.cursor_to_top();
    }

    pub fn cursor_to_bottom(&mut self) {
        self.tree.cursor_to_bottom();
    }

    pub fn page_up(&mut self) {
        self.tree.page_up();
    }

    pub fn page_down(&mut self) {
        self.tree.page_down();
    }

    pub fn collapse_or_parent(&mut self) {
        self.tree.collapse_or_parent();
    }

    pub fn expand(&mut self) {
        self.tree.expand();
    }

    pub fn collapse_all(&mut self) {
        self.tree.collapse_all();
    }

    pub fn expand_all(&mut self) {
        self.tree.expand_all();
    }

    pub fn breadcrumb(&self) -> Option<String> {
        self.tree.breadcrumb()
    }

    pub fn toggle_fold_level(&mut self) {
        self.tree.toggle_fold_level();
    }

    pub fn toggle_fold_recursive(&mut self) {
        self.tree.toggle_fold_recursive();
    }

    pub fn toggle_expand(&mut self) {
        self.tree.toggle_expand();
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
                self.tree.viewport_height = f.area().height.saturating_sub(7) as usize;
                render::render(f, self);
            })?;

            if event::poll(TICK_INTERVAL)? {
                match event::read()? {
                    Event::Key(key) => match input::handle_key(self, key) {
                        InputResult::Continue => {}
                        InputResult::Quit => break,
                    },
                    Event::Mouse(MouseEvent {
                        kind: MouseEventKind::ScrollUp,
                        ..
                    }) => self.tree.move_cursor_up(),
                    Event::Mouse(MouseEvent {
                        kind: MouseEventKind::ScrollDown,
                        ..
                    }) => self.tree.move_cursor_down(),
                    Event::Mouse(MouseEvent {
                        kind: MouseEventKind::Down(_),
                        row,
                        ..
                    }) => {
                        if matches!(self.mode, Mode::Normal) {
                            self.tree.handle_mouse_click(row);
                        }
                    }
                    _ => {}
                }
            } else {
                self.tick();
            }
        }
        Ok(())
    }

    /// Background tick: expire stale status messages.
    fn tick(&mut self) {
        if let Some(status) = &self.status_message
            && status.created_at.elapsed() >= STATUS_MESSAGE_TTL
        {
            self.status_message = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::policy::Effect;
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
        assert!(app.tree.flat_rows.is_empty());
        assert_eq!(app.tree.cursor, 0);
    }

    #[test]
    fn app_new_with_rules() {
        let app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // Tree starts collapsed, so only root visible
        assert!(!app.tree.flat_rows.is_empty());
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        let kind = &app.tree.arena[node_id].kind;
        assert!(
            matches!(kind, TreeNodeKind::Leaf { rule, level, .. }
                if rule.to_string().contains("exec") && *level == PolicyLevel::User),
            "cursor should be on the new exec leaf, got {:?}",
            kind
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        assert!(
            matches!(&app.tree.arena[node_id].kind, TreeNodeKind::Leaf { .. }),
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        assert!(matches!(
            &app.tree.arena[node_id].kind,
            TreeNodeKind::Leaf { .. }
        ));
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        assert!(matches!(
            &app.tree.arena[node_id].kind,
            TreeNodeKind::Leaf { .. }
        ));
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        let kind = &app.tree.arena[node_id].kind;
        assert!(
            matches!(
                kind,
                TreeNodeKind::Leaf {
                    level: PolicyLevel::Project,
                    ..
                }
            ),
            "cursor should be on the Project leaf, got {:?}",
            kind
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

        let total = app.tree.flat_rows.len();
        assert!(total > 1);

        app.tree.cursor_to_top();
        assert_eq!(app.tree.cursor, 0);

        app.tree.cursor_to_bottom();
        assert_eq!(app.tree.cursor, total - 1);

        app.tree.cursor_to_top();
        app.move_cursor_down();
        assert_eq!(app.tree.cursor, 1);

        app.move_cursor_up();
        assert_eq!(app.tree.cursor, 0);

        // Can't go below 0
        app.move_cursor_up();
        assert_eq!(app.tree.cursor, 0);
    }

    #[test]
    fn search_finds_matches() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")) (deny (exec "cargo")))"#);
        // App starts fully collapsed — search should auto-expand ancestors
        let initial_rows = app.tree.flat_rows.len();

        app.start_search();
        app.search.input = TextInput::new("git");
        app.commit_search();

        assert!(!app.search.matches.is_empty());
        // Cursor should be on first match
        assert!(app.search.matches.contains(&app.tree.cursor));
        // Ancestors should have been expanded, revealing more rows
        assert!(
            app.tree.flat_rows.len() > initial_rows,
            "search should auto-expand ancestors"
        );
    }

    #[test]
    fn node_search_text_leaf() {
        let kind = TreeNodeKind::Leaf {
            effect: Effect::Allow,
            rule: parse_rule_text("(allow (exec \"git\"))").unwrap(),
            level: PolicyLevel::User,
            policy: "main".to_string(),
            is_shadowed: false,
        };
        let text = tree::node_search_text(&kind);
        assert!(text.contains("allow"));
        assert!(text.contains("main"));
    }

    #[test]
    fn node_search_text_binary() {
        let text = tree::node_search_text(&TreeNodeKind::Binary("git".to_string()));
        assert_eq!(text, "git");
    }

    #[test]
    fn search_finds_sandbox_content() {
        let mut app = make_app(r#"(policy "main" (ask (exec "ls" "-lha") :sandbox (allow (fs))))"#);
        // App starts fully collapsed — search should auto-expand to find matches
        app.start_search();
        app.search.input = TextInput::new("sandbox");
        app.commit_search();

        assert!(
            !app.search.matches.is_empty(),
            "search for 'sandbox' should find sandbox nodes even when collapsed"
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

        let new_source =
            policy_edit::ensure_policy_block(existing_source, "main", r#"(policy "main")"#)
                .and_then(|s| policy_edit::add_rule(&s, "main", &rule))
                .unwrap_or_else(|e| panic!("add_rule failed: {e}"));

        let loaded = LoadedPolicy {
            level: PolicyLevel::User,
            path: PathBuf::from("/tmp/test"),
            source: new_source,
        };
        let arena = tree::build_tree(&[loaded]);
        let rows = tree::flatten(&arena);

        let all_leaves: Vec<String> = rows
            .iter()
            .filter_map(|r| match &arena[r.node_id].kind {
                TreeNodeKind::Leaf { rule, .. } => Some(rule.to_string()),
                _ => None,
            })
            .collect();

        let found = rows.iter().any(|row| {
            matches!(
                &arena[row.node_id].kind,
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
            .tree
            .flat_rows
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match &app.tree.arena[r.node_id].kind {
                TreeNodeKind::Leaf { rule, .. } => Some((i, rule.to_string())),
                _ => None,
            })
            .collect();
        let expected_idx = all_leaves
            .iter()
            .find(|(_, r)| r.contains("\"ls\""))
            .map(|(i, _)| *i);
        assert_eq!(
            Some(app.tree.cursor),
            expected_idx,
            "cursor {} should match leaf index\nall leaves: {:?}",
            app.tree.cursor,
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
        let has_allow_git = app.tree.flat_rows.iter().any(|r| {
            matches!(&app.tree.arena[r.node_id].kind, TreeNodeKind::Leaf { rule, effect, .. }
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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

        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
                app.tree
                    .flat_rows
                    .iter()
                    .map(|r| format!("{:?}", app.tree.arena[r.node_id].kind))
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
        let collapsed_count = app.tree.flat_rows.len();

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
            app.tree.flat_rows.len() > collapsed_count,
            "tree should be expanded to show new leaf (collapsed={}, after={})",
            collapsed_count,
            app.tree.flat_rows.len()
        );

        // And the cursor should be on a leaf
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        let kind = &app.tree.arena[node_id].kind;
        assert!(
            matches!(kind, TreeNodeKind::Leaf { rule, .. } if rule.to_string().contains("\"ls\"")),
            "cursor should be on the new ls leaf, got: {:?}",
            kind
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
            .tree
            .flat_rows
            .iter()
            .enumerate()
            .filter_map(|(i, r)| match &app.tree.arena[r.node_id].kind {
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
            app.tree.cursor, *cargo_idx,
            "cursor={} should be on cargo leaf at idx={}\nall leaves: {leaves:?}",
            app.tree.cursor, cargo_idx
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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

        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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

        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        let kind = &app.tree.arena[node_id].kind;
        assert!(
            matches!(kind, TreeNodeKind::Leaf { rule, .. } if rule.to_string().contains("fs")),
            "cursor should be on fs leaf, got: {:?}",
            kind
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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

        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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

    // -----------------------------------------------------------------------
    // build_rule equivalence tests: direct AST == parsed string for all paths
    // -----------------------------------------------------------------------

    /// Assert that build_rule(form) produces the same Rule as the string round-trip.
    fn assert_build_rule_equivalence(form: &AddRuleForm) {
        let direct = build_rule(form);
        let text = build_rule_text(form);
        let roundtrip = parse_rule_text(&text)
            .unwrap_or_else(|e| panic!("parse_rule_text failed for '{text}': {e}"));
        assert_eq!(
            direct.to_string(),
            roundtrip.to_string(),
            "build_rule and build_rule_text should produce equivalent rules\n  direct: {}\n  text: {}\n  roundtrip: {}",
            direct,
            text,
            roundtrip
        );
    }

    #[test]
    fn build_rule_equiv_exec_basic() {
        let mut f = make_form(0);
        f.binary_input = TextInput::new("git");
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_exec_wildcard() {
        let f = make_form(0);
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_exec_with_args() {
        let mut f = make_form(0);
        f.binary_input = TextInput::new("git");
        f.args_input = TextInput::new("push origin");
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_exec_star_binary() {
        let mut f = make_form(0);
        f.binary_input = TextInput::new("*");
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_fs_wildcard() {
        let f = make_form(1);
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_fs_read() {
        let mut f = make_form(1);
        f.fs_op_index = 1;
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_net_wildcard() {
        let f = make_form(2);
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_net_domain() {
        let mut f = make_form(2);
        f.net_domain_input = TextInput::new("example.com");
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_tool_wildcard() {
        let f = make_form(3);
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_tool_name() {
        let mut f = make_form(3);
        f.tool_name_input = TextInput::new("Bash");
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_sandboxed_exec_fs() {
        let mut f = make_form(1);
        f.binary_input = TextInput::new("ls");
        f.args_input = TextInput::new("-lha");
        f.effect_index = 2; // ask
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_sandboxed_exec_net() {
        let mut f = make_form(2);
        f.binary_input = TextInput::new("curl");
        assert_build_rule_equivalence(&f);
    }

    #[test]
    fn build_rule_equiv_all_effects() {
        for effect_idx in 0..3 {
            let mut f = make_form(0);
            f.binary_input = TextInput::new("git");
            f.effect_index = effect_idx;
            assert_build_rule_equivalence(&f);
        }
    }

    #[test]
    fn build_rule_equiv_all_fs_ops() {
        for op_idx in 0..5 {
            let mut f = make_form(1);
            f.fs_op_index = op_idx;
            assert_build_rule_equivalence(&f);
        }
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
        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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

        let node_id = app.tree.flat_rows[app.tree.cursor].node_id;
        match &app.tree.arena[node_id].kind {
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
        for (i, row) in app.tree.flat_rows.iter().enumerate() {
            if matches!(
                &app.tree.arena[row.node_id].kind,
                TreeNodeKind::SandboxLeaf { .. }
            ) {
                app.tree.cursor = i;
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
            matches!(app.mode, Mode::SelectEffect(_)),
            "should enter SelectEffect mode for sandbox leaf"
        );

        // Change to deny (index 2)
        if let Mode::SelectEffect(state) = &mut app.mode {
            state.effect_index = 2; // auto deny
        }
        app.confirm_select_effect();

        assert!(matches!(app.mode, Mode::Normal));

        // Verify the sandbox sub-rule effect changed
        let status = app.status_message.as_ref().map(|s| s.text.as_str());
        assert_eq!(status, Some("Changed to auto deny"));

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
            matches!(app.mode, Mode::EditRule(_)),
            "should enter EditRule mode for sandbox leaf"
        );

        // Change the rule text to (deny (net *))
        if let Mode::EditRule(state) = &mut app.mode {
            state.input.clear();
            for c in "(deny (net *))".chars() {
                state.input.insert_char(c);
            }
        }
        app.complete_edit_rule();

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
        // App starts fully collapsed — search should auto-expand
        app.start_search();
        app.search.input = TextInput::new("sandbox");
        app.commit_search();

        assert!(
            !app.search.matches.is_empty(),
            "search for 'sandbox' should find sandbox leaf nodes even when collapsed"
        );
    }

    #[test]
    fn search_expands_collapsed_ancestors() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")) (deny (exec "cargo")))"#);
        // App starts fully collapsed
        let initial_rows = app.tree.flat_rows.len();

        // Search for something deep in the tree
        app.start_search();
        app.search.input = TextInput::new("allow");
        app.commit_search();

        assert!(!app.search.matches.is_empty(), "should find 'allow' leaf");
        // More rows should now be visible due to auto-expansion
        assert!(
            app.tree.flat_rows.len() > initial_rows,
            "search should expand ancestors: had {initial_rows} rows, now {}",
            app.tree.flat_rows.len()
        );
    }

    #[test]
    fn search_live_expands_ancestors() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // App starts fully collapsed
        let initial_rows = app.tree.flat_rows.len();

        app.start_search();
        app.search.input = TextInput::new("git");
        app.update_search_live();

        // Live search should also expand ancestors
        assert!(
            !app.search.matches.is_empty(),
            "live search should find 'git'"
        );
        assert!(
            app.tree.flat_rows.len() > initial_rows,
            "live search should expand ancestors"
        );
    }

    // -----------------------------------------------------------------------
    // Shadow detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn shadow_detection_multi_level_marks_shadowed() {
        // Project-level rule shadows User-level rule for same matcher
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

        // Find all git leaf rows
        let git_leaves: Vec<(usize, PolicyLevel, bool)> = app
            .tree
            .flat_rows
            .iter()
            .enumerate()
            .filter_map(|(i, row)| {
                if let TreeNodeKind::Leaf {
                    level,
                    rule,
                    is_shadowed,
                    ..
                } = &app.tree.arena[row.node_id].kind
                {
                    if rule.to_string().contains("\"git\"") {
                        return Some((i, *level, *is_shadowed));
                    }
                }
                None
            })
            .collect();

        // The User-level rule should be shadowed by the Project-level rule
        let user_leaf = git_leaves.iter().find(|(_, l, _)| *l == PolicyLevel::User);
        let project_leaf = git_leaves
            .iter()
            .find(|(_, l, _)| *l == PolicyLevel::Project);

        assert!(
            user_leaf.is_some(),
            "should have a User leaf; all leaves: {git_leaves:?}"
        );
        assert!(
            project_leaf.is_some(),
            "should have a Project leaf; all leaves: {git_leaves:?}"
        );

        let (_, _, user_shadowed) = user_leaf.unwrap();
        let (_, _, project_shadowed) = project_leaf.unwrap();

        assert!(
            *user_shadowed,
            "User-level rule should be marked as shadowed"
        );
        assert!(
            !project_shadowed,
            "Project-level rule should NOT be shadowed"
        );
    }

    #[test]
    fn shadow_detection_single_level_no_shadows() {
        let app = make_app(r#"(policy "main" (allow (exec "git" *)) (deny (exec "rm" *)))"#);

        // Single-level: nothing should be shadowed
        let any_shadowed = app.tree.flat_rows.iter().any(|row| {
            matches!(
                &app.tree.arena[row.node_id].kind,
                TreeNodeKind::Leaf {
                    is_shadowed: true,
                    ..
                }
            )
        });
        assert!(!any_shadowed, "single-level policy should have no shadows");
    }

    #[test]
    fn shadow_detection_non_overlapping_not_shadowed() {
        // Project denies "rm", User allows "git" — no overlap
        let user = test_policy(
            PolicyLevel::User,
            r#"(policy "main" (allow (exec "git" *)))"#,
        );
        let project = test_policy(
            PolicyLevel::Project,
            r#"(policy "main" (deny (exec "rm" *)))"#,
        );
        let mut app = App::new(&[user, project]);
        app.expand_all();

        let any_shadowed = app.tree.flat_rows.iter().any(|row| {
            matches!(
                &app.tree.arena[row.node_id].kind,
                TreeNodeKind::Leaf {
                    is_shadowed: true,
                    ..
                }
            )
        });
        assert!(
            !any_shadowed,
            "non-overlapping rules should not shadow each other"
        );
    }

    // -----------------------------------------------------------------------
    // Save / ConfirmSave tests
    // -----------------------------------------------------------------------

    #[test]
    fn save_all_no_changes_stays_normal() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.save_all();
        assert!(
            matches!(app.mode, Mode::Normal),
            "should stay in Normal mode when no changes"
        );
        let status = app.status_message.as_ref().map(|s| s.text.as_str());
        assert_eq!(status, Some("No changes to save"));
    }

    #[test]
    fn save_all_with_changes_enters_confirm_save() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // Make a change
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        assert!(app.has_unsaved_changes());
        app.save_all();
        assert!(
            matches!(app.mode, Mode::ConfirmSave(_)),
            "should enter ConfirmSave mode"
        );

        // Check diff contents
        if let Mode::ConfirmSave(diff) = &app.mode {
            assert!(!diff.hunks.is_empty(), "should have at least one hunk");
            let total_lines: usize = diff.hunks.iter().map(|h| h.lines.len()).sum();
            assert!(total_lines > 0, "diff should have lines");

            // Should have some added lines (at minimum the new rule)
            let has_added = diff
                .hunks
                .iter()
                .any(|h| h.lines.iter().any(|l| matches!(l, DiffLine::Added(_))));
            assert!(has_added, "diff should contain added lines");
        }
    }

    #[test]
    fn confirm_save_writes_and_resets_modified() {
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // Make a change
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        assert!(app.has_unsaved_changes());

        // Can't actually write to disk in tests, but we can verify
        // confirm_save updates original_source to match source.
        // (fs::write will fail on /tmp/test, but original_source update
        // happens after the write. For a test with a real tempfile, see below.)
        // Instead, verify that save_all enters ConfirmSave with correct diff.
        app.save_all();
        assert!(matches!(app.mode, Mode::ConfirmSave(_)));

        // Cancel the save (simulate Esc)
        app.mode = Mode::Normal;
        // Changes should still be unsaved
        assert!(app.has_unsaved_changes());
    }

    #[test]
    fn confirm_save_key_y_writes() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        // Make a change
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        app.save_all();
        assert!(matches!(app.mode, Mode::ConfirmSave(_)));

        // Press 'n' to cancel
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert!(
            matches!(app.mode, Mode::Normal),
            "n should cancel ConfirmSave"
        );
    }

    #[test]
    fn confirm_save_scroll() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = make_app(r#"(policy "main" (allow (exec "git")))"#);
        app.start_add_rule();
        if let Mode::AddRule(form) = &mut app.mode {
            form.binary_input = TextInput::new("ls");
        }
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();
        app.advance_add_rule();

        app.save_all();
        assert!(matches!(app.mode, Mode::ConfirmSave(_)));

        // Scroll down
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE),
        );
        if let Mode::ConfirmSave(diff) = &app.mode {
            assert_eq!(diff.scroll, 1, "j should scroll down");
        }

        // Scroll up
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        if let Mode::ConfirmSave(diff) = &app.mode {
            assert_eq!(diff.scroll, 0, "k should scroll up");
        }

        // Scroll up past 0 stays at 0
        input::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE),
        );
        if let Mode::ConfirmSave(diff) = &app.mode {
            assert_eq!(diff.scroll, 0, "k should not go below 0");
        }
    }

    // -----------------------------------------------------------------------
    // Property-based tests: build_rule equivalence
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    /// Generate an arbitrary valid AddRuleForm.
    fn arb_add_rule_form() -> impl Strategy<Value = AddRuleForm> {
        (
            0..4usize,           // domain_index
            0..3usize,           // effect_index
            0..5usize,           // fs_op_index
            "[a-z]{1,8}",        // binary (may be empty for wildcard)
            "[a-z]{0,6}",        // args
            "[a-z]{0,6}",        // path
            "[a-z.]{0,10}",      // net domain
            "[A-Za-z]{0,8}",     // tool name
            proptest::bool::ANY, // has command
        )
            .prop_map(
                |(
                    domain_index,
                    effect_index,
                    fs_op_index,
                    binary,
                    args,
                    path,
                    net_domain,
                    tool_name,
                    has_command,
                )| {
                    let binary_input = if has_command {
                        TextInput::new(&binary)
                    } else {
                        TextInput::empty()
                    };
                    AddRuleForm {
                        step: AddRuleStep::SelectLevel,
                        domain_index,
                        effect_index,
                        level_index: 0,
                        fs_op_index,
                        binary_input,
                        args_input: if args.is_empty() {
                            TextInput::empty()
                        } else {
                            TextInput::new(&args)
                        },
                        path_input: if path.is_empty() {
                            TextInput::empty()
                        } else {
                            TextInput::new(&path)
                        },
                        net_domain_input: if net_domain.is_empty() {
                            TextInput::empty()
                        } else {
                            TextInput::new(&net_domain)
                        },
                        tool_name_input: if tool_name.is_empty() {
                            TextInput::empty()
                        } else {
                            TextInput::new(&tool_name)
                        },
                        available_levels: vec![PolicyLevel::User],
                        error: None,
                    }
                },
            )
    }

    proptest! {
        /// build_rule(form).to_string() should parse and re-display identically
        /// to the old build_rule_text(form) roundtrip.
        #[test]
        fn build_rule_matches_text_roundtrip(form in arb_add_rule_form()) {
            let direct_rule = build_rule(&form);
            let direct_display = direct_rule.to_string();

            // The direct rule should always parse back
            let reparsed = parse_rule_text(&direct_display);
            prop_assert!(reparsed.is_ok(),
                "build_rule produced unparseable rule: {}\n  error: {:?}",
                direct_display, reparsed.err());
            let reparsed = reparsed.unwrap();
            prop_assert_eq!(&direct_display, &reparsed.to_string(),
                "build_rule round-trip should be stable");
        }
    }
}
