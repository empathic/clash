//! Editing operations: undo/redo, effect selection, delete, add, edit, save.

use std::fs;

use similar::TextDiff;

use crate::policy::Effect;
use crate::policy::ast::{
    CapMatcher, ExecMatcher, FsMatcher, FsOp, NetMatcher, OpPattern, PathFilter, Pattern,
    PolicyItem, Rule, SandboxRef, ToolMatcher, TopLevel,
};
use crate::policy::compile::compile_policy;
use crate::policy::edit;
use crate::policy::parse;
use crate::settings::PolicyLevel;

use super::super::editor::TextInput;
use super::super::input::InputResult;
use super::super::tree::{LeafInfo, TreeNodeKind};
use super::{
    AddRuleForm, AddRuleStep, App, DiffHunk, DiffLine, EditRuleState, Mode, RuleTarget,
    SandboxMutation, SaveDiff, SelectEffectState, StatusMessage,
};

// -----------------------------------------------------------------------
// Undo / Redo
// -----------------------------------------------------------------------

impl App {
    /// Snapshot current sources for undo.
    pub(super) fn push_undo(&mut self) {
        let sources: Vec<(PolicyLevel, String)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.clone()))
            .collect();
        self.history.undo_stack.push(super::UndoEntry {
            sources,
            cursor: self.tree.cursor,
        });
        self.history.redo_stack.clear();
    }

    /// Undo the last editing action.
    pub fn undo(&mut self) {
        let Some(entry) = self.history.undo_stack.pop() else {
            self.set_status("Nothing to undo", true);
            return;
        };
        // Save current state to redo
        let current: Vec<(PolicyLevel, String)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.clone()))
            .collect();
        self.history.redo_stack.push(super::UndoEntry {
            sources: current,
            cursor: self.tree.cursor,
        });
        // Restore
        for (level, source) in &entry.sources {
            if let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == *level) {
                ls.source = source.clone();
            }
        }
        self.tree.cursor = entry.cursor;
        self.rebuild_tree();
        self.set_status("Undone", false);
    }

    /// Redo the last undone action.
    pub fn redo(&mut self) {
        let Some(entry) = self.history.redo_stack.pop() else {
            self.set_status("Nothing to redo", true);
            return;
        };
        let current: Vec<(PolicyLevel, String)> = self
            .levels
            .iter()
            .map(|ls| (ls.level, ls.source.clone()))
            .collect();
        self.history.undo_stack.push(super::UndoEntry {
            sources: current,
            cursor: self.tree.cursor,
        });
        for (level, source) in &entry.sources {
            if let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == *level) {
                ls.source = source.clone();
            }
        }
        self.tree.cursor = entry.cursor;
        self.rebuild_tree();
        self.set_status("Redone", false);
    }

    pub(super) fn set_status(&mut self, text: &str, is_error: bool) {
        self.status_message = Some(StatusMessage {
            text: text.to_string(),
            is_error,
            created_at: std::time::Instant::now(),
        });
    }

    /// Apply an editing operation with undo/validate/rebuild protocol.
    ///
    /// 1. Pushes undo snapshot
    /// 2. Finds the LevelState for `level`
    /// 3. Calls `edit_fn` with current source text
    /// 4. Validates result with compile_policy
    /// 5. On success: applies new source, rebuilds tree, returns Ok
    /// 6. On failure: rolls back undo stack, returns Err with message
    pub(super) fn apply_edit<F>(&mut self, level: PolicyLevel, edit_fn: F) -> Result<(), String>
    where
        F: FnOnce(&str) -> anyhow::Result<String>,
    {
        self.push_undo();
        let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == level) else {
            self.history.undo_stack.pop();
            return Err("Policy level not found".into());
        };
        match edit_fn(&ls.source) {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.history.undo_stack.pop();
                    return Err(format!("Invalid: {e}"));
                }
                ls.source = new_source;
                self.rebuild_tree();
                Ok(())
            }
            Err(e) => {
                self.history.undo_stack.pop();
                Err(format!("Edit failed: {e}"))
            }
        }
    }

    // -------------------------------------------------------------------
    // Effect selection
    // -------------------------------------------------------------------

    /// Open the effect selector dropdown on the focused leaf or sandbox leaf.
    pub fn start_select_effect(&mut self) {
        let Some(row) = self.tree.flat_rows.get(self.tree.cursor) else {
            return;
        };
        match &self.tree.arena[row.node_id].kind {
            TreeNodeKind::Leaf {
                effect,
                rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::SelectEffect(SelectEffectState {
                    effect_index: effect_to_display_index(*effect),
                    rule: rule.clone(),
                    target: RuleTarget::Regular {
                        level: *level,
                        policy: policy.clone(),
                    },
                });
            }
            TreeNodeKind::SandboxLeaf {
                effect,
                sandbox_rule,
                parent_rule,
                level,
                policy,
            } => {
                self.mode = Mode::SelectEffect(SelectEffectState {
                    effect_index: effect_to_display_index(*effect),
                    rule: sandbox_rule.clone(),
                    target: RuleTarget::Sandbox {
                        level: *level,
                        policy: policy.clone(),
                        parent_rule: parent_rule.clone(),
                    },
                });
            }
            _ => {
                self.set_status("Not a rule leaf", true);
            }
        }
    }

    /// Apply the selected effect from the dropdown (regular or sandbox).
    pub fn confirm_select_effect(&mut self) {
        let Mode::SelectEffect(state) = &self.mode else {
            return;
        };

        let effect_index = state.effect_index;
        let new_effect = effect_from_display_index(effect_index);
        let old_rule = state.rule.clone();
        let target = std::mem::replace(
            &mut self.mode,
            Mode::Normal, // temporarily set to Normal; we'll extract target below
        );
        let Mode::SelectEffect(state) = target else {
            return;
        };
        let target = state.target;

        if new_effect == old_rule.effect {
            return;
        }

        let new_rule = Rule {
            effect: new_effect,
            matcher: old_rule.matcher.clone(),
            sandbox: old_rule.sandbox.clone(),
        };
        let display_name = EFFECT_DISPLAY[effect_index].to_string();

        match target {
            RuleTarget::Regular { level, policy } => {
                let old_rule_text = old_rule.to_string();
                match self.apply_edit(level, |src| {
                    edit::remove_rule(src, &policy, &old_rule_text)
                        .and_then(|s| edit::add_rule(&s, &policy, &new_rule))
                }) {
                    Ok(()) => self.set_status(&format!("Changed to {display_name}"), false),
                    Err(e) => self.set_status(&e, true),
                }
            }
            RuleTarget::Sandbox {
                level,
                policy,
                parent_rule,
            } => {
                self.mutate_sandbox_rule(
                    level,
                    &policy,
                    &parent_rule,
                    &old_rule,
                    SandboxMutation::Replace(new_rule),
                    &format!("Changed to {display_name}"),
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------

    /// Initiate deletion of the focused rule or sandbox sub-rule (enters Confirm mode).
    pub fn start_delete(&mut self) {
        let Some(row) = self.tree.flat_rows.get(self.tree.cursor) else {
            return;
        };
        match &self.tree.arena[row.node_id].kind {
            TreeNodeKind::Leaf {
                rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::Confirm(super::ConfirmAction::DeleteRule {
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
                self.mode = Mode::Confirm(super::ConfirmAction::DeleteSandboxRule {
                    level: *level,
                    policy: policy.clone(),
                    sandbox_rule_text: sandbox_rule.to_string(),
                    parent_rule: parent_rule.clone(),
                });
            }
            _ => {
                let node_id = row.node_id;
                let leaves = self.tree.arena.collect_leaves(node_id);
                if leaves.is_empty() {
                    self.set_status("No rules to delete", true);
                    return;
                }
                let label = self.tree.breadcrumb().unwrap_or_default();
                self.mode = Mode::Confirm(super::ConfirmAction::DeleteBranch { label, leaves });
            }
        }
    }

    /// Execute a confirmed branch delete (remove all leaves under a branch node).
    pub fn confirm_delete_branch(&mut self, leaves: Vec<LeafInfo>) {
        self.push_undo();
        let mut deleted = 0;
        let mut errors = Vec::new();

        for leaf in &leaves {
            let result = match leaf {
                LeafInfo::Regular {
                    level,
                    policy,
                    rule_text,
                } => {
                    let ls = self.levels.iter_mut().find(|ls| ls.level == *level);
                    if let Some(ls) = ls {
                        match edit::remove_rule(&ls.source, policy, rule_text) {
                            Ok(new_source) => {
                                ls.source = new_source;
                                Ok(())
                            }
                            Err(e) => Err(format!("remove rule: {e}")),
                        }
                    } else {
                        Err("level not found".into())
                    }
                }
                LeafInfo::Sandbox {
                    level,
                    policy,
                    sandbox_rule_text,
                    parent_rule,
                } => {
                    let sandbox_rule = match parse_rule_text(sandbox_rule_text) {
                        Ok(r) => r,
                        Err(e) => {
                            errors.push(format!("parse: {e}"));
                            continue;
                        }
                    };
                    self.mutate_sandbox_rule_raw(
                        *level,
                        policy,
                        parent_rule,
                        &sandbox_rule,
                        SandboxMutation::Delete,
                    )
                }
            };
            match result {
                Ok(()) => deleted += 1,
                Err(e) => errors.push(e),
            }
        }

        // Validate all modified sources
        let mut valid = true;
        for ls in &self.levels {
            if let Err(e) = compile_policy(&ls.source) {
                errors.push(format!("validation: {e}"));
                valid = false;
            }
        }

        if !valid {
            // Roll back
            if let Some(entry) = self.history.undo_stack.pop() {
                for (level, source) in &entry.sources {
                    if let Some(ls) = self.levels.iter_mut().find(|ls| ls.level == *level) {
                        ls.source = source.clone();
                    }
                }
            }
            self.set_status(&format!("Delete failed: {}", errors.join("; ")), true);
            return;
        }

        self.rebuild_tree();
        if errors.is_empty() {
            self.set_status(
                &format!(
                    "Deleted {deleted} rule{}",
                    if deleted == 1 { "" } else { "s" }
                ),
                false,
            );
        } else {
            self.set_status(
                &format!("Deleted {deleted}, errors: {}", errors.join("; ")),
                true,
            );
        }
    }

    /// Execute a confirmed delete, positioning cursor on nearest sibling or parent.
    pub fn confirm_delete(&mut self, level: PolicyLevel, policy: String, rule_text: String) {
        let anchor = self.delete_cursor_anchor();
        match self.apply_edit(level, |src| edit::remove_rule(src, &policy, &rule_text)) {
            Ok(()) => {
                self.restore_cursor_after_delete(&anchor);
                self.set_status("Rule deleted", false);
            }
            Err(e) => self.set_status(&e, true),
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
        let anchor = self.delete_cursor_anchor();
        self.mutate_sandbox_rule(
            level,
            &policy,
            &parent_rule,
            &sandbox_rule,
            SandboxMutation::Delete,
            "Sandbox rule deleted",
        );
        // Only reposition if the delete succeeded
        if self.status_message.as_ref().is_some_and(|s| !s.is_error) {
            self.restore_cursor_after_delete(&anchor);
        }
    }

    /// Shared helper: modify a sandbox sub-rule within its parent rule.
    ///
    /// Builds a new parent rule with the sandbox mutation applied, then uses
    /// `apply_edit` to swap old parent for new in the policy source.
    fn mutate_sandbox_rule(
        &mut self,
        level: PolicyLevel,
        policy: &str,
        parent_rule: &Rule,
        target_sandbox_rule: &Rule,
        mutation: SandboxMutation,
        success_msg: &str,
    ) {
        let Some(SandboxRef::Inline(sandbox_rules)) = &parent_rule.sandbox else {
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
        let policy = policy.to_string();

        match self.apply_edit(level, |src| {
            edit::remove_rule(src, &policy, &old_parent_text)
                .and_then(|s| edit::add_rule(&s, &policy, &new_parent))
        }) {
            Ok(()) => self.set_status(success_msg, false),
            Err(e) => self.set_status(&e, true),
        }
    }

    /// Modify a sandbox sub-rule without undo/rebuild — for batch operations.
    ///
    /// Returns Ok(()) on success, modifying `self.levels` in place.
    fn mutate_sandbox_rule_raw(
        &mut self,
        level: PolicyLevel,
        policy: &str,
        parent_rule: &Rule,
        target_sandbox_rule: &Rule,
        mutation: SandboxMutation,
    ) -> Result<(), String> {
        let Some(SandboxRef::Inline(sandbox_rules)) = &parent_rule.sandbox else {
            return Err("Parent rule has no inline sandbox".into());
        };

        let mut new_sandbox_rules: Vec<Rule> = Vec::new();
        let target_text = target_sandbox_rule.to_string();
        let mut found = false;

        for r in sandbox_rules {
            if r.to_string() == target_text && !found {
                found = true;
                match &mutation {
                    SandboxMutation::Delete => {}
                    SandboxMutation::Replace(new_rule) => {
                        new_sandbox_rules.push(new_rule.clone());
                    }
                }
            } else {
                new_sandbox_rules.push(r.clone());
            }
        }

        if !found {
            return Err("Sandbox sub-rule not found in parent".into());
        }

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
        let ls = self
            .levels
            .iter_mut()
            .find(|ls| ls.level == level)
            .ok_or_else(|| "Level not found".to_string())?;

        let new_source = edit::remove_rule(&ls.source, policy, &old_parent_text)
            .and_then(|s| edit::add_rule(&s, policy, &new_parent))
            .map_err(|e| format!("{e}"))?;
        ls.source = new_source;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Cursor tracking after delete
    // -------------------------------------------------------------------

    /// Capture anchor info before a delete for cursor repositioning.
    ///
    /// Returns the sibling node IDs (next, then previous) and the parent node ID
    /// at the same depth level, so we can find them after tree rebuild.
    fn delete_cursor_anchor(&self) -> DeleteAnchor {
        let cursor = self.tree.cursor;
        let rows = &self.tree.flat_rows;
        let Some(row) = rows.get(cursor) else {
            return DeleteAnchor::default();
        };
        let depth = row.depth;
        let parent = self.tree.arena[row.node_id].parent;

        // Find next sibling (next row at same depth with same parent)
        let next_sibling = rows[cursor + 1..]
            .iter()
            .enumerate()
            .find(|(_, r)| r.depth == depth && self.tree.arena[r.node_id].parent == parent)
            .map(|(offset, _)| cursor + 1 + offset);

        // Find prev sibling (prev row at same depth with same parent)
        let prev_sibling = rows[..cursor]
            .iter()
            .enumerate()
            .rev()
            .find(|(_, r)| r.depth == depth && self.tree.arena[r.node_id].parent == parent)
            .map(|(i, _)| i);

        // Find parent row
        let parent_row = parent.and_then(|pid| rows.iter().position(|r| r.node_id == pid));

        // Capture labels for lookup after rebuild (node IDs change)
        let label_at = |idx: usize| -> Option<String> {
            rows.get(idx)
                .map(|r| node_label(&self.tree.arena[r.node_id].kind))
        };

        DeleteAnchor {
            next_sibling_label: next_sibling.and_then(&label_at),
            prev_sibling_label: prev_sibling.and_then(&label_at),
            parent_label: parent_row.and_then(&label_at),
            depth,
            original_cursor: cursor,
        }
    }

    /// After a delete + rebuild, reposition cursor using the saved anchor.
    fn restore_cursor_after_delete(&mut self, anchor: &DeleteAnchor) {
        let rows = &self.tree.flat_rows;
        if rows.is_empty() {
            return;
        }

        // Try next sibling label at same depth
        if let Some(ref label) = anchor.next_sibling_label {
            if let Some(idx) = rows.iter().position(|r| {
                r.depth == anchor.depth && node_label(&self.tree.arena[r.node_id].kind) == *label
            }) {
                self.tree.cursor = idx;
                return;
            }
        }

        // Try prev sibling label at same depth
        if let Some(ref label) = anchor.prev_sibling_label {
            if let Some(idx) = rows.iter().position(|r| {
                r.depth == anchor.depth && node_label(&self.tree.arena[r.node_id].kind) == *label
            }) {
                self.tree.cursor = idx;
                return;
            }
        }

        // Try parent label at parent depth
        if let Some(ref label) = anchor.parent_label {
            if let Some(idx) = rows.iter().position(|r| {
                r.depth == anchor.depth.saturating_sub(1)
                    && node_label(&self.tree.arena[r.node_id].kind) == *label
            }) {
                self.tree.cursor = idx;
                return;
            }
        }

        // Fallback: stay near original position
        self.tree.cursor = anchor.original_cursor.min(rows.len().saturating_sub(1));
    }

    // -------------------------------------------------------------------
    // Save / Quit
    // -------------------------------------------------------------------

    /// Compute diffs and enter ConfirmSave mode, or report no changes.
    pub fn save_all(&mut self) {
        if !self.has_unsaved_changes() {
            self.set_status("No changes to save", false);
            return;
        }

        // Validate all modified levels before showing the diff
        for ls in &self.levels {
            if !ls.is_modified() {
                continue;
            }
            if let Err(e) = compile_policy(&ls.source) {
                self.set_status(&format!("Validation failed for {}: {e}", ls.level), true);
                return;
            }
        }

        // Compute diffs
        let mut hunks = Vec::new();
        for ls in &self.levels {
            if !ls.is_modified() {
                continue;
            }
            let diff = TextDiff::from_lines(&ls.original_source, &ls.source);
            let mut lines = Vec::new();
            for change in diff.iter_all_changes() {
                let text = change.to_string_lossy().trim_end().to_string();
                match change.tag() {
                    similar::ChangeTag::Equal => lines.push(DiffLine::Context(text)),
                    similar::ChangeTag::Insert => lines.push(DiffLine::Added(text)),
                    similar::ChangeTag::Delete => lines.push(DiffLine::Removed(text)),
                }
            }
            hunks.push(DiffHunk {
                level: ls.level,
                lines,
            });
        }

        self.mode = Mode::ConfirmSave(SaveDiff { hunks, scroll: 0 });
    }

    /// Actually write all modified levels to disk (called after user confirms).
    ///
    /// Uses two-phase write: first write all changes to temp files, then
    /// atomically rename them into place. On failure, temp files are cleaned up
    /// and no policy files are left partially written.
    pub fn confirm_save(&mut self) {
        // Phase 1: ensure directories exist and write temp files.
        let mut temp_files: Vec<(usize, std::path::PathBuf)> = Vec::new();

        for (i, ls) in self.levels.iter().enumerate() {
            if !ls.is_modified() {
                continue;
            }
            if let Some(parent) = ls.path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                Self::cleanup_temp_files(&temp_files);
                self.set_status(&format!("Failed to create directory: {e}"), true);
                return;
            }
            let temp_path = ls.path.with_extension(format!("clash-save-{i}.tmp"));
            if let Err(e) = fs::write(&temp_path, &ls.source) {
                Self::cleanup_temp_files(&temp_files);
                self.set_status(
                    &format!("Failed to write temp file {}: {e}", temp_path.display()),
                    true,
                );
                return;
            }
            temp_files.push((i, temp_path));
        }

        // Phase 2: rename all temp files into place (atomic on same filesystem).
        for &(i, ref temp_path) in &temp_files {
            let target = &self.levels[i].path;
            if let Err(e) = fs::rename(temp_path, target) {
                Self::cleanup_temp_files(&temp_files);
                self.set_status(&format!("Failed to rename {}: {e}", target.display()), true);
                return;
            }
        }

        // Phase 3: mark all saved levels as clean.
        let saved = temp_files.len();
        for &(i, _) in &temp_files {
            self.levels[i].original_source = self.levels[i].source.clone();
        }

        self.set_status(
            &format!(
                "Saved {saved} policy file{}",
                if saved == 1 { "" } else { "s" }
            ),
            false,
        );
    }

    /// Remove temp files left from a failed save attempt.
    fn cleanup_temp_files(temp_files: &[(usize, std::path::PathBuf)]) {
        for (_, path) in temp_files {
            let _ = fs::remove_file(path);
        }
    }

    /// Start quit flow — enters Confirm if unsaved, otherwise returns Quit.
    pub fn start_quit(&mut self) -> InputResult {
        if self.has_unsaved_changes() {
            self.mode = Mode::Confirm(super::ConfirmAction::QuitUnsaved);
            InputResult::Continue
        } else {
            InputResult::Quit
        }
    }

    // -------------------------------------------------------------------
    // Add rule
    // -------------------------------------------------------------------

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

    /// Go back to the previous step in the add-rule form.
    pub fn retreat_add_rule(&mut self) {
        let Mode::AddRule(form) = &mut self.mode else {
            return;
        };
        form.error = None;
        if let Some(prev) = prev_add_rule_step(form.step, form.domain_index) {
            form.step = prev;
        }
    }

    /// Complete the add-rule form: construct AST directly, validate, add.
    fn complete_add_rule(&mut self) {
        let Mode::AddRule(form) = &self.mode else {
            return;
        };

        let level = form.available_levels[form.level_index];
        let rule = build_rule(form);

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

        // Check for a conflicting rule before mutating
        let conflicting = edit::find_conflicting_rule(&ls.source, &policy_name, &rule)
            .ok()
            .flatten();
        let replaced = conflicting.is_some();

        self.mode = Mode::Normal;

        let rule_text = rule.to_string();
        match self.apply_edit(level, |src| {
            let s = if let Some(ref old_text) = conflicting {
                edit::remove_rule(src, &policy_name, old_text)?
            } else {
                src.to_string()
            };
            let s = edit::ensure_policy_block(
                &s,
                &policy_name,
                &format!("(policy \"{policy_name}\")"),
            )?;
            edit::add_rule(&s, &policy_name, &rule)
        }) {
            Ok(()) => {
                if !self.cursor_to_rule(&rule_text, level, &policy_name) {
                    let fallback = self.tree.flat_rows.iter().position(|row| {
                        matches!(&self.tree.arena[row.node_id].kind, TreeNodeKind::Leaf { rule: r, .. } if r.to_string() == rule_text)
                    });
                    if let Some(idx) = fallback {
                        self.tree.cursor = idx;
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
            Err(e) => self.set_status(&e, true),
        }
    }

    // -------------------------------------------------------------------
    // Edit rule (inline)
    // -------------------------------------------------------------------

    /// Enter edit mode for the focused leaf rule or sandbox sub-rule.
    pub fn start_edit_rule(&mut self) {
        let Some(row) = self.tree.flat_rows.get(self.tree.cursor) else {
            return;
        };
        match &self.tree.arena[row.node_id].kind {
            TreeNodeKind::Leaf {
                rule,
                level,
                policy,
                ..
            } => {
                self.mode = Mode::EditRule(EditRuleState {
                    input: TextInput::new(&rule.to_string()),
                    original_rule: rule.clone(),
                    target: RuleTarget::Regular {
                        level: *level,
                        policy: policy.clone(),
                    },
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
                self.mode = Mode::EditRule(EditRuleState {
                    input: TextInput::new(&sandbox_rule.to_string()),
                    original_rule: sandbox_rule.clone(),
                    target: RuleTarget::Sandbox {
                        level: *level,
                        policy: policy.clone(),
                        parent_rule: parent_rule.clone(),
                    },
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
        let original_rule = state.original_rule.clone();

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

        // Take ownership of the target by swapping mode to Normal
        let old_mode = std::mem::replace(&mut self.mode, Mode::Normal);
        let Mode::EditRule(state) = old_mode else {
            return;
        };

        let new_rule_text = new_rule.to_string();
        match state.target {
            RuleTarget::Regular { level, policy } => {
                let original = original_rule.to_string();
                match self.apply_edit(level, |src| {
                    edit::remove_rule(src, &policy, &original)
                        .and_then(|s| edit::add_rule(&s, &policy, &new_rule))
                }) {
                    Ok(()) => {
                        self.cursor_to_rule(&new_rule_text, level, &policy);
                        self.set_status("Rule updated", false);
                    }
                    Err(e) => self.set_status(&e, true),
                }
            }
            RuleTarget::Sandbox {
                level,
                policy,
                parent_rule,
            } => {
                self.mutate_sandbox_rule(
                    level,
                    &policy,
                    &parent_rule,
                    &original_rule,
                    SandboxMutation::Replace(new_rule),
                    "Sandbox rule updated",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cursor tracking helpers
// ---------------------------------------------------------------------------

#[derive(Default)]
struct DeleteAnchor {
    next_sibling_label: Option<String>,
    prev_sibling_label: Option<String>,
    parent_label: Option<String>,
    depth: usize,
    original_cursor: usize,
}

/// Extract a label string from a node kind for cursor tracking.
fn node_label(kind: &TreeNodeKind) -> String {
    match kind {
        TreeNodeKind::Domain(d) => d.to_string(),
        TreeNodeKind::PolicyBlock { name, level } => format!("{name}[{level}]"),
        TreeNodeKind::Binary(s)
        | TreeNodeKind::Arg(s)
        | TreeNodeKind::HasArg(s)
        | TreeNodeKind::PathNode(s)
        | TreeNodeKind::FsOp(s)
        | TreeNodeKind::NetDomain(s)
        | TreeNodeKind::ToolName(s) => s.clone(),
        TreeNodeKind::HasMarker => ":has".into(),
        TreeNodeKind::Leaf {
            rule,
            level,
            policy,
            ..
        } => format!("{}|{}|{}", rule, level, policy),
        TreeNodeKind::SandboxLeaf {
            sandbox_rule,
            level,
            policy,
            ..
        } => format!("sbx:{}|{}|{}", sandbox_rule, level, policy),
        TreeNodeKind::SandboxGroup => "SandboxGroup".into(),
        TreeNodeKind::SandboxName(name) => format!("sandbox:{name}"),
    }
}

// ---------------------------------------------------------------------------
// Constants for the add-rule form
// ---------------------------------------------------------------------------

pub const DOMAIN_NAMES: &[&str] = &["exec", "fs", "net", "tool"];
pub const EFFECT_NAMES: &[&str] = &["allow", "deny", "ask"];
pub const EFFECT_DISPLAY: &[&str] = &["ask", "auto allow", "auto deny"];
pub const FS_OPS: &[&str] = &["*", "read", "write", "create", "delete"];

/// Map form effect_index (EFFECT_NAMES order: allow=0, deny=1, ask=2) to Effect.
fn effect_from_form_index(index: usize) -> Effect {
    match index {
        0 => Effect::Allow,
        1 => Effect::Deny,
        _ => Effect::Ask,
    }
}

pub(super) fn effect_from_display_index(index: usize) -> Effect {
    match index {
        0 => Effect::Ask,
        1 => Effect::Allow,
        _ => Effect::Deny,
    }
}

pub(super) fn effect_to_display_index(effect: Effect) -> usize {
    match effect {
        Effect::Ask => 0,
        Effect::Allow => 1,
        Effect::Deny => 2,
    }
}

/// Compute the previous step in the add-rule flow, or `None` if already at the first step.
pub(crate) fn prev_add_rule_step(step: AddRuleStep, domain_index: usize) -> Option<AddRuleStep> {
    match step {
        AddRuleStep::EnterBinary => None,
        AddRuleStep::EnterArgs => Some(AddRuleStep::EnterBinary),
        AddRuleStep::SelectDomain => Some(AddRuleStep::EnterArgs),
        AddRuleStep::SelectFsOp => Some(AddRuleStep::SelectDomain),
        AddRuleStep::EnterPath => Some(AddRuleStep::SelectFsOp),
        AddRuleStep::EnterNetDomain => Some(AddRuleStep::SelectDomain),
        AddRuleStep::EnterToolName => Some(AddRuleStep::SelectDomain),
        AddRuleStep::SelectEffect => Some(match domain_index {
            0 => AddRuleStep::SelectDomain,
            1 => AddRuleStep::EnterPath,
            2 => AddRuleStep::EnterNetDomain,
            _ => AddRuleStep::EnterToolName,
        }),
        AddRuleStep::SelectLevel => Some(AddRuleStep::SelectEffect),
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
#[cfg(test)]
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
///
/// Kept for backward-compatibility verification in tests. The primary path
/// is `build_rule()` which constructs AST types directly.
#[cfg(test)]
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

// ---------------------------------------------------------------------------
// Direct AST construction from form fields (no string round-trip)
// ---------------------------------------------------------------------------

/// Build a `Rule` directly from form fields, bypassing string serialization.
///
/// This is the primary rule-construction path. It constructs AST types directly
/// from the form's structured fields, using `Display` only for display — never
/// as an intermediate step in rule creation.
pub(crate) fn build_rule(form: &AddRuleForm) -> Rule {
    let effect = effect_from_form_index(form.effect_index);
    let binary_raw = form.binary_input.value().trim().to_string();
    let has_command = !binary_raw.is_empty() && binary_raw != "*";

    if has_command && form.domain_index != 0 {
        // Sandboxed exec: the user specified a command + a non-exec capability domain.
        // Result: (effect (exec bin args...) :sandbox (allow (cap ...)))
        let exec = build_exec_matcher_from_form(form);
        let sandbox_cap = build_cap_matcher_from_form(form);
        let sandbox_rule = Rule {
            effect: Effect::Allow,
            matcher: sandbox_cap,
            sandbox: None,
        };
        Rule {
            effect,
            matcher: CapMatcher::Exec(exec),
            sandbox: Some(SandboxRef::Inline(vec![sandbox_rule])),
        }
    } else if form.domain_index == 0 {
        // Plain exec rule
        let exec = build_exec_matcher_from_form(form);
        Rule {
            effect,
            matcher: CapMatcher::Exec(exec),
            sandbox: None,
        }
    } else {
        // Standalone capability rule (no command)
        let cap = build_cap_matcher_from_form(form);
        Rule {
            effect,
            matcher: cap,
            sandbox: None,
        }
    }
}

/// Build an ExecMatcher from form fields (binary + args).
fn build_exec_matcher_from_form(form: &AddRuleForm) -> ExecMatcher {
    let binary_raw = form.binary_input.value().trim().to_string();
    let bin = if binary_raw.is_empty() || binary_raw == "*" {
        Pattern::Any
    } else {
        Pattern::Literal(binary_raw)
    };

    let args_raw = form.args_input.value().trim().to_string();
    let args: Vec<Pattern> = if args_raw.is_empty() {
        Vec::new()
    } else {
        args_raw
            .split_whitespace()
            .map(|arg| {
                if arg == "*" {
                    Pattern::Any
                } else {
                    Pattern::Literal(arg.to_string())
                }
            })
            .collect()
    };

    ExecMatcher {
        bin,
        args,
        has_args: Vec::new(),
    }
}

/// Build a CapMatcher for the selected non-exec domain from form fields.
fn build_cap_matcher_from_form(form: &AddRuleForm) -> CapMatcher {
    match form.domain_index {
        1 => CapMatcher::Fs(build_fs_matcher_from_form(form)),
        2 => CapMatcher::Net(build_net_matcher_from_form(form)),
        _ => CapMatcher::Tool(build_tool_matcher_from_form(form)),
    }
}

/// Build an FsMatcher from form fields (op + path).
fn build_fs_matcher_from_form(form: &AddRuleForm) -> FsMatcher {
    let op = match form.fs_op_index {
        0 => OpPattern::Any,
        1 => OpPattern::Single(FsOp::Read),
        2 => OpPattern::Single(FsOp::Write),
        3 => OpPattern::Single(FsOp::Create),
        _ => OpPattern::Single(FsOp::Delete),
    };

    let path_raw = form.path_input.value().trim().to_string();
    let path = if path_raw.is_empty() {
        None
    } else {
        // Path might be a complex s-expression like (subpath (env PWD)).
        // Try to parse it; if that fails, treat it as a literal path.
        match parse_path_filter(&path_raw) {
            Some(pf) => Some(pf),
            None => Some(PathFilter::Literal(path_raw)),
        }
    };

    FsMatcher { op, path }
}

/// Attempt to parse a path filter from user input.
/// The user may enter s-expression syntax like `(subpath (env PWD))` or a plain path.
fn parse_path_filter(input: &str) -> Option<PathFilter> {
    // Wrap in a dummy rule to parse via the policy parser
    let source = format!("(policy \"_tmp\" (allow (fs read {input})))");
    let top_levels = parse::parse(&source).ok()?;
    for tl in top_levels {
        if let TopLevel::Policy { body, .. } = tl {
            for item in body {
                if let PolicyItem::Rule(rule) = item
                    && let CapMatcher::Fs(m) = rule.matcher
                {
                    return m.path;
                }
            }
        }
    }
    None
}

/// Build a NetMatcher from form fields.
fn build_net_matcher_from_form(form: &AddRuleForm) -> NetMatcher {
    let domain_raw = form.net_domain_input.value().trim().to_string();
    let domain = if domain_raw.is_empty() || domain_raw == "*" {
        Pattern::Any
    } else {
        Pattern::Literal(domain_raw)
    };
    NetMatcher { domain, path: None }
}

/// Build a ToolMatcher from form fields.
fn build_tool_matcher_from_form(form: &AddRuleForm) -> ToolMatcher {
    let name_raw = form.tool_name_input.value().trim().to_string();
    let name = if name_raw.is_empty() || name_raw == "*" {
        Pattern::Any
    } else {
        Pattern::Literal(name_raw)
    };
    ToolMatcher { name }
}

/// Quote a token with double quotes if it's not `*` and not already a parenthesized expression.
#[cfg(test)]
pub(crate) fn quote_token_if_needed(token: &str) -> String {
    if token == "*" || token.starts_with('(') || token.starts_with('"') {
        token.to_string()
    } else {
        format!("\"{token}\"")
    }
}

/// Parse a single rule from its s-expression text.
pub(crate) fn parse_rule_text(rule_text: &str) -> anyhow::Result<Rule> {
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
