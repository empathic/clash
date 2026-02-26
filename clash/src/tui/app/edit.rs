//! Editing operations: undo/redo, effect selection, delete, add, edit, save.

use std::fs;

use crate::policy::Effect;
use crate::policy::ast::{PolicyItem, Rule, SandboxRef, TopLevel};
use crate::policy::compile::compile_policy;
use crate::policy::edit;
use crate::policy::parse;
use crate::settings::PolicyLevel;

use super::super::editor::TextInput;
use super::super::input::InputResult;
use super::super::tree::TreeNodeKind;
use super::{
    AddRuleForm, AddRuleStep, App, EditRuleState, Mode, RuleTarget, SandboxMutation,
    SelectEffectState, StatusMessage,
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
        self.undo_stack.push(super::UndoEntry {
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
        self.redo_stack.push(super::UndoEntry {
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
        self.undo_stack.push(super::UndoEntry {
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

    pub(super) fn set_status(&mut self, text: &str, is_error: bool) {
        self.status_message = Some(StatusMessage {
            text: text.to_string(),
            is_error,
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
            self.undo_stack.pop();
            return Err("Policy level not found".into());
        };
        match edit_fn(&ls.source) {
            Ok(new_source) => {
                if let Err(e) = compile_policy(&new_source) {
                    self.undo_stack.pop();
                    return Err(format!("Invalid: {e}"));
                }
                ls.source = new_source;
                self.rebuild_tree();
                Ok(())
            }
            Err(e) => {
                self.undo_stack.pop();
                Err(format!("Edit failed: {e}"))
            }
        }
    }

    // -------------------------------------------------------------------
    // Effect selection
    // -------------------------------------------------------------------

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
                self.set_status("Not a rule leaf", true);
            }
        }
    }

    /// Execute a confirmed delete.
    pub fn confirm_delete(&mut self, level: PolicyLevel, policy: String, rule_text: String) {
        match self.apply_edit(level, |src| edit::remove_rule(src, &policy, &rule_text)) {
            Ok(()) => self.set_status("Rule deleted", false),
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

    // -------------------------------------------------------------------
    // Save / Quit
    // -------------------------------------------------------------------

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
            Err(e) => self.set_status(&e, true),
        }
    }

    // -------------------------------------------------------------------
    // Edit rule (inline)
    // -------------------------------------------------------------------

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

        match state.target {
            RuleTarget::Regular { level, policy } => {
                let original = original_rule.to_string();
                match self.apply_edit(level, |src| {
                    edit::remove_rule(src, &policy, &original)
                        .and_then(|s| edit::add_rule(&s, &policy, &new_rule))
                }) {
                    Ok(()) => self.set_status("Rule updated", false),
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
// Constants for the add-rule form
// ---------------------------------------------------------------------------

pub const DOMAIN_NAMES: &[&str] = &["exec", "fs", "net", "tool"];
pub const EFFECT_NAMES: &[&str] = &["allow", "deny", "ask"];
pub const EFFECT_DISPLAY: &[&str] = &["ask", "auto allow", "auto deny"];
pub const FS_OPS: &[&str] = &["*", "read", "write", "create", "delete"];

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
