//! Inline ratatui form overlays — no raw-mode exit needed.
//!
//! Each form is a list of [`FormField`]s rendered as a centered popup.
//! Navigation: Tab/Shift-Tab between fields, type into text fields,
//! Left/Right to cycle selects, Space to toggle multi-selects.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::Theme;
use super::widgets::{ClickAction, ClickRegions, ModalHeight, ModalOverlay};

use crate::policy::manifest_edit;
use crate::policy::match_tree::{
    Decision, IncludeEntry, Node, Observable, Pattern, PolicyManifest, SandboxRef, Value,
};
use crate::policy::sandbox_edit;
use crate::policy::sandbox_types::{Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy};
use crate::tui::tool_registry;

use super::tea::FormRequest;

const PRELOADED_FUNCS: &[&str] = &[
    "match", "tool", "policy", "settings", "sandbox", "cwd", "home", "tempdir", "path", "regex",
    "domains", "domain", "allow", "deny", "ask",
];

// ---------------------------------------------------------------------------
// Field types
// ---------------------------------------------------------------------------

pub enum FormField {
    Text {
        label: String,
        value: String,
        cursor: usize,
        placeholder: String,
        hint: Option<&'static str>,
    },
    Select {
        label: String,
        options: Vec<String>,
        selected: usize,
        /// Per-option hints — `hints[selected]` is shown when this field is active.
        hints: Vec<String>,
    },
    MultiSelect {
        label: String,
        options: Vec<String>,
        toggled: Vec<bool>,
        cursor: usize,
        hint: Option<&'static str>,
    },
}

impl FormField {
    /// Returns the contextual hint for this field's current state.
    fn hint(&self) -> Option<&str> {
        match self {
            FormField::Text { hint, .. } => *hint,
            FormField::Select {
                hints, selected, ..
            } => {
                let h = hints.get(*selected).map(|s| s.as_str()).unwrap_or("");
                if h.is_empty() { None } else { Some(h) }
            }
            FormField::MultiSelect { hint, .. } => *hint,
        }
    }
}

// ---------------------------------------------------------------------------
// Form state
// ---------------------------------------------------------------------------

pub struct FormState {
    pub title: String,
    pub kind: FormKind,
    pub fields: Vec<FormField>,
    /// Indices into `fields` that are currently visible.
    visible: Vec<usize>,
    /// Index into `visible`.
    active: usize,
    /// Tool name context (from ancestor nodes or typed value), used to
    /// filter effects and validate observables.
    tool_context: Option<String>,
    /// Sandbox policies keyed by sandbox option index, for rendering
    /// entitlement summaries when a sandbox field is active.
    sandbox_summaries: Vec<Option<SandboxPolicy>>,
}

#[derive(Debug, Clone)]
pub enum FormKind {
    AddRule,
    AddSandbox,
    AddSandboxRule {
        sandbox_name: String,
    },
    AddInclude,
    EditCondition {
        path: Vec<usize>,
    },
    EditDecision {
        path: Vec<usize>,
    },
    AddChild {
        parent_path: Vec<usize>,
    },
    /// Edit an inline leaf rule (condition + decision together).
    EditRule {
        path: Vec<usize>,
    },
    EditSandbox {
        sandbox_name: String,
    },
    EditSandboxRule {
        sandbox_name: String,
        rule_index: usize,
    },
}

/// Result of processing a key event in the form.
pub enum FormEvent {
    /// Still editing.
    Continue,
    /// User submitted — apply changes.
    Submit,
    /// User cancelled.
    Cancel,
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl FormState {
    /// Create the appropriate form for the given request.
    ///
    /// `included` provides sandboxes from resolved `.star` includes so they
    /// appear in sandbox dropdowns (but are not editable).
    pub fn from_request(
        request: &FormRequest,
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> Self {
        match request {
            FormRequest::AddRule => Self::new_add_rule(manifest, included),
            FormRequest::AddSandbox => Self::new_add_sandbox(),
            FormRequest::AddSandboxRule { sandbox_name } => {
                Self::new_add_sandbox_rule(sandbox_name)
            }
            FormRequest::AddInclude => Self::new_add_include(),
            FormRequest::EditCondition { path } => Self::new_edit_condition(path, manifest),
            FormRequest::EditDecision { path } => Self::new_edit_decision(path, manifest, included),
            FormRequest::EditRule { path } => Self::new_edit_rule(path, manifest, included),
            FormRequest::AddChild { parent_path } => {
                Self::new_add_child(parent_path, manifest, included)
            }
            FormRequest::EditSandbox { sandbox_name } => {
                Self::new_edit_sandbox(sandbox_name, manifest)
            }
            FormRequest::EditSandboxRule {
                sandbox_name,
                rule_index,
            } => Self::new_edit_sandbox_rule(sandbox_name, *rule_index, manifest),
        }
    }

    fn new_add_rule(
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> Self {
        let (sandbox_opts, sandbox_policies, sb_default) =
            Self::build_sandbox_options_with_included(manifest, included);

        let fields = vec![
            FormField::Select {
                label: "Rule type".into(),
                options: vec![
                    "Tool rule".into(),
                    "Shell command".into(),
                    "Starlark expression".into(),
                ],
                selected: 0,
                hints: vec![
                    "Match a Claude tool like Read, Write, Bash, Edit".into(),
                    "Match a shell command like git, npm, curl".into(),
                    "Write a raw Starlark policy expression".into(),
                ],
            },
            FormField::Text {
                label: "Tool name".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. Read, Write, Bash, Edit".into(),
                hint: Some("e.g. Read, Write, Bash, Edit, Glob, Grep, WebSearch"),
            },
            FormField::Text {
                label: "Command".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. git, npm, gh, curl".into(),
                hint: Some("The program to match, e.g. git, npm, gh, curl"),
            },
            FormField::Text {
                label: "Arguments".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "optional, e.g. push --force".into(),
                hint: Some("Optional: only match when these args are used"),
            },
            FormField::Select {
                label: "When matched".into(),
                options: vec![
                    "auto allow".into(),
                    "auto deny".into(),
                    "ask (prompt)".into(),
                ],
                selected: 0,
                hints: vec![String::new(), String::new(), String::new()],
            },
            FormField::Select {
                label: "Sandbox".into(),
                options: sandbox_opts,
                selected: sb_default,
                hints: vec![],
            },
            // Field 6: Starlark expression (only visible when rule_type == 2)
            FormField::Text {
                label: "Expression".into(),
                value: String::new(),
                cursor: 0,
                placeholder: r#"e.g. match({"Bash": {"git": allow()}}), tool("Read").deny()"#
                    .into(),
                hint: Some("Starlark DSL expression — compiled and added to the policy tree"),
            },
        ];

        let mut form = FormState {
            title: "Add Rule".into(),
            kind: FormKind::AddRule,
            fields,
            visible: vec![],
            active: 0,
            tool_context: None,
            sandbox_summaries: sandbox_policies,
        };
        form.recompute_visible();
        form
    }

    /// Create an AddRule form pre-filled for the walkthrough (Shell command / git / allow).
    pub fn new_add_rule_prefilled(
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> Self {
        let (sandbox_opts, sandbox_policies, sb_default) =
            Self::build_sandbox_options_with_included(manifest, included);

        let fields = vec![
            FormField::Select {
                label: "Rule type".into(),
                options: vec![
                    "Tool rule".into(),
                    "Shell command".into(),
                    "Starlark expression".into(),
                ],
                selected: 1, // Shell command
                hints: vec![
                    "Match a Claude tool like Read, Write, Bash, Edit".into(),
                    "Match a shell command like git, npm, curl".into(),
                    "Write a raw Starlark policy expression".into(),
                ],
            },
            FormField::Text {
                label: "Tool name".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. Read, Write, Bash, Edit".into(),
                hint: Some("e.g. Read, Write, Bash, Edit, Glob, Grep, WebSearch"),
            },
            FormField::Text {
                label: "Command".into(),
                value: "git".into(),
                cursor: 3,
                placeholder: "e.g. git, npm, gh, curl".into(),
                hint: Some("This allows all git commands (status, commit, push, etc.)"),
            },
            FormField::Text {
                label: "Arguments".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "optional, e.g. push --force".into(),
                hint: Some("Leave empty to match all git subcommands"),
            },
            FormField::Select {
                label: "When matched".into(),
                options: vec![
                    "auto allow".into(),
                    "auto deny".into(),
                    "ask (prompt)".into(),
                ],
                selected: 0, // allow
                hints: vec![String::new(), String::new(), String::new()],
            },
            FormField::Select {
                label: "Sandbox".into(),
                options: sandbox_opts,
                selected: sb_default,
                hints: vec![],
            },
            FormField::Text {
                label: "Expression".into(),
                value: String::new(),
                cursor: 0,
                placeholder: r#"e.g. match({"Bash": {"git": allow()}}), tool("Read").deny()"#
                    .into(),
                hint: Some("Starlark DSL expression — compiled and added to the policy tree"),
            },
        ];

        let mut form = FormState {
            title: "Add Rule — allow git".into(),
            kind: FormKind::AddRule,
            fields,
            visible: vec![],
            active: 0,
            tool_context: None,
            sandbox_summaries: sandbox_policies,
        };
        form.recompute_visible();
        form
    }

    fn new_add_sandbox() -> Self {
        let fields = vec![
            FormField::Text {
                label: "Name".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. cwd, strict".into(),
                hint: Some("A short name for this sandbox profile"),
            },
            FormField::MultiSelect {
                label: "Default caps".into(),
                options: vec![
                    "read".into(),
                    "write".into(),
                    "create".into(),
                    "delete".into(),
                    "execute".into(),
                ],
                toggled: vec![true, false, false, false, true],
                cursor: 0,
                hint: Some("Default filesystem capabilities for this sandbox"),
            },
            FormField::Select {
                label: "Network".into(),
                options: vec!["deny".into(), "allow".into(), "localhost".into()],
                selected: 0,
                hints: vec![
                    "Block all network access".into(),
                    "Permit all network access".into(),
                    "Only allow connections to 127.0.0.1".into(),
                ],
            },
        ];

        FormState {
            title: "Add Sandbox".into(),
            kind: FormKind::AddSandbox,
            fields,
            visible: vec![0, 1, 2],
            active: 0,
            tool_context: None,
            sandbox_summaries: vec![],
        }
    }

    fn new_add_sandbox_rule(sandbox_name: &str) -> Self {
        let fields = vec![
            FormField::Select {
                label: "Effect".into(),
                options: vec!["allow".into(), "deny".into()],
                selected: 0,
                hints: vec![String::new(), String::new()],
            },
            FormField::MultiSelect {
                label: "Caps".into(),
                options: vec![
                    "read".into(),
                    "write".into(),
                    "create".into(),
                    "delete".into(),
                    "execute".into(),
                ],
                toggled: vec![true, true, false, false, false],
                cursor: 0,
                hint: None,
            },
            FormField::Text {
                label: "Path".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. $PWD, $HOME/.config".into(),
                hint: Some("The filesystem path this rule applies to"),
            },
            FormField::Select {
                label: "Path match".into(),
                options: vec!["literal".into(), "subpath".into(), "regex".into()],
                selected: 0,
                hints: vec![
                    "Match this exact path only".into(),
                    "Match this path and everything under it".into(),
                    "Match paths by regular expression".into(),
                ],
            },
        ];

        FormState {
            title: format!("Add Rule to '{sandbox_name}'"),
            kind: FormKind::AddSandboxRule {
                sandbox_name: sandbox_name.to_string(),
            },
            fields,
            visible: vec![0, 1, 2, 3],
            active: 0,
            tool_context: None,
            sandbox_summaries: vec![],
        }
    }

    fn new_edit_sandbox(sandbox_name: &str, manifest: &PolicyManifest) -> Self {
        let sb = manifest.policy.sandboxes.get(sandbox_name);

        let caps_toggled = if let Some(sb) = sb {
            vec![
                sb.default.contains(Cap::READ),
                sb.default.contains(Cap::WRITE),
                sb.default.contains(Cap::CREATE),
                sb.default.contains(Cap::DELETE),
                sb.default.contains(Cap::EXECUTE),
            ]
        } else {
            vec![true, false, false, false, true]
        };

        let network_idx = match sb.map(|s| &s.network) {
            Some(NetworkPolicy::Deny) | None => 0,
            Some(NetworkPolicy::Allow) => 1,
            Some(NetworkPolicy::Localhost) => 2,
            Some(NetworkPolicy::AllowDomains(_)) => 1, // approximate
        };

        let fields = vec![
            FormField::MultiSelect {
                label: "Default caps".into(),
                options: vec![
                    "read".into(),
                    "write".into(),
                    "create".into(),
                    "delete".into(),
                    "execute".into(),
                ],
                toggled: caps_toggled,
                cursor: 0,
                hint: Some("Default filesystem capabilities for this sandbox"),
            },
            FormField::Select {
                label: "Network".into(),
                options: vec!["deny".into(), "allow".into(), "localhost".into()],
                selected: network_idx,
                hints: vec![
                    "Block all network access".into(),
                    "Permit all network access".into(),
                    "Only allow connections to 127.0.0.1".into(),
                ],
            },
        ];

        FormState {
            title: format!("Edit Sandbox '{sandbox_name}'"),
            kind: FormKind::EditSandbox {
                sandbox_name: sandbox_name.to_string(),
            },
            fields,
            visible: vec![0, 1],
            active: 0,
            tool_context: None,
            sandbox_summaries: vec![],
        }
    }

    fn new_edit_sandbox_rule(
        sandbox_name: &str,
        rule_index: usize,
        manifest: &PolicyManifest,
    ) -> Self {
        let rule = manifest
            .policy
            .sandboxes
            .get(sandbox_name)
            .and_then(|sb| sb.rules.get(rule_index));

        let effect_idx = match rule.map(|r| &r.effect) {
            Some(RuleEffect::Allow) | None => 0,
            Some(RuleEffect::Deny) => 1,
        };

        let caps_toggled = if let Some(r) = rule {
            vec![
                r.caps.contains(Cap::READ),
                r.caps.contains(Cap::WRITE),
                r.caps.contains(Cap::CREATE),
                r.caps.contains(Cap::DELETE),
                r.caps.contains(Cap::EXECUTE),
            ]
        } else {
            vec![true, true, false, false, false]
        };

        let path_value = rule.map(|r| r.path.clone()).unwrap_or_default();
        let path_cursor = path_value.len();

        let path_match_idx = match rule.map(|r| &r.path_match) {
            Some(PathMatch::Literal) | None => 0,
            Some(PathMatch::Subpath) | Some(PathMatch::ChildOf) => 1,
            Some(PathMatch::Regex) => 2,
        };

        let fields = vec![
            FormField::Select {
                label: "Effect".into(),
                options: vec!["allow".into(), "deny".into()],
                selected: effect_idx,
                hints: vec![String::new(), String::new()],
            },
            FormField::MultiSelect {
                label: "Caps".into(),
                options: vec![
                    "read".into(),
                    "write".into(),
                    "create".into(),
                    "delete".into(),
                    "execute".into(),
                ],
                toggled: caps_toggled,
                cursor: 0,
                hint: None,
            },
            FormField::Text {
                label: "Path".into(),
                value: path_value,
                cursor: path_cursor,
                placeholder: "e.g. $PWD, $HOME/.config".into(),
                hint: Some("The filesystem path this rule applies to"),
            },
            FormField::Select {
                label: "Path match".into(),
                options: vec!["literal".into(), "subpath".into(), "regex".into()],
                selected: path_match_idx,
                hints: vec![
                    "Match this exact path only".into(),
                    "Match this path and everything under it".into(),
                    "Match paths by regular expression".into(),
                ],
            },
        ];

        FormState {
            title: format!("Edit Rule in '{sandbox_name}'"),
            kind: FormKind::EditSandboxRule {
                sandbox_name: sandbox_name.to_string(),
                rule_index,
            },
            fields,
            visible: vec![0, 1, 2, 3],
            active: 0,
            tool_context: None,
            sandbox_summaries: vec![],
        }
    }

    fn new_add_include() -> Self {
        let fields = vec![FormField::Text {
            label: "Include path".into(),
            value: String::new(),
            cursor: 0,
            placeholder: "e.g. rules.star, @clash//builtin.star".into(),
            hint: Some("e.g. rules.star, @clash//builtin.star"),
        }];

        FormState {
            title: "Add Include".into(),
            kind: FormKind::AddInclude,
            fields,
            visible: vec![0],
            active: 0,
            tool_context: None,
            sandbox_summaries: vec![],
        }
    }

    fn new_edit_condition(path: &[usize], manifest: &PolicyManifest) -> Self {
        let (obs_idx, pat_value) = Self::read_condition_at_path(&manifest.policy.tree, path);
        let title = Self::describe_condition_at_path(&manifest.policy.tree, path);

        let pat_type_idx = Self::pattern_type_index_at_path(&manifest.policy.tree, path);
        let fields = vec![
            FormField::Select {
                label: "Match on".into(),
                options: observable_options(),
                selected: obs_idx,
                hints: observable_option_hints(),
            },
            FormField::Text {
                label: "Which one".into(),
                value: Self::observable_param_at_path(&manifest.policy.tree, path),
                cursor: 0,
                placeholder: observable_param_placeholder(obs_idx).into(),
                hint: {
                    let h = observable_param_hint(obs_idx);
                    if h.is_empty() { None } else { Some(h) }
                },
            },
            FormField::Select {
                label: "Match type".into(),
                options: pattern_options(),
                selected: pat_type_idx,
                hints: pattern_option_hints(),
            },
            FormField::Text {
                label: "Match value".into(),
                value: pat_value,
                cursor: 0,
                placeholder: pattern_value_placeholder(obs_idx).into(),
                hint: {
                    let h = pattern_value_hint(pat_type_idx);
                    if h.is_empty() { None } else { Some(h) }
                },
            },
        ];

        let mut form = FormState {
            title,
            kind: FormKind::EditCondition {
                path: path.to_vec(),
            },
            fields,
            visible: vec![],
            active: 0,
            tool_context: Self::ancestor_tool_name(&manifest.policy.tree, path),
            sandbox_summaries: vec![],
        };
        form.recompute_visible();
        form
    }

    /// Edit an inline leaf rule: same layout as AddRule, pre-filled with the
    /// existing condition (observable + pattern) and decision (effect + sandbox).
    fn new_edit_rule(
        path: &[usize],
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> Self {
        let tree = &manifest.policy.tree;
        let (sandbox_opts, sandbox_policies, sb_default) =
            Self::build_sandbox_options_with_included(manifest, included);

        // Read condition info
        let (_obs_idx, pat_value) = Self::read_condition_at_path(tree, path);
        let pat_type_idx = Self::pattern_type_index_at_path(tree, path);

        // Determine if this is a tool rule (ToolName) or an exec rule inner node
        let is_tool_rule = matches!(
            Self::get_node_at_path(tree, path),
            Some(Node::Condition {
                observe: Observable::ToolName,
                ..
            })
        );

        // Read decision from the child
        let (effect_idx, sandbox_name) = Self::read_decision_at_path(tree, path);
        let sb_selected = if let Some(ref name) = sandbox_name {
            sandbox_opts
                .iter()
                .position(|s| s == name)
                .unwrap_or(sb_default)
        } else {
            sb_default
        };

        // Build the same field layout as AddRule
        let (rule_type_selected, tool_name_val, cmd_val, args_val) = if is_tool_rule {
            // Tool rule: pre-fill tool name with the pattern value
            (0, pat_value, String::new(), String::new())
        } else {
            // Exec/other rule: pre-fill the command field
            (1, String::new(), pat_value, String::new())
        };

        let tool_name_cursor = tool_name_val.len();
        let cmd_cursor = cmd_val.len();

        let fields = vec![
            FormField::Select {
                label: "Rule type".into(),
                options: vec![
                    "Tool rule".into(),
                    "Shell command".into(),
                    "Starlark expression".into(),
                ],
                selected: rule_type_selected,
                hints: vec![
                    "Match a Claude tool like Read, Write, Bash, Edit".into(),
                    "Match a shell command like git, npm, curl".into(),
                    "Write a raw Starlark policy expression".into(),
                ],
            },
            FormField::Text {
                label: "Tool name".into(),
                value: tool_name_val,
                cursor: tool_name_cursor,
                placeholder: "e.g. Read, Write, Bash, Edit".into(),
                hint: Some("e.g. Read, Write, Bash, Edit, Glob, Grep, WebSearch"),
            },
            FormField::Text {
                label: "Command".into(),
                value: cmd_val,
                cursor: cmd_cursor,
                placeholder: "e.g. git, npm, gh, curl".into(),
                hint: Some("The program to match, e.g. git, npm, gh, curl"),
            },
            FormField::Text {
                label: "Arguments".into(),
                value: args_val,
                cursor: 0,
                placeholder: "optional, e.g. push --force".into(),
                hint: Some("Optional: only match when these args are used"),
            },
            FormField::Select {
                label: "When matched".into(),
                options: vec![
                    "auto allow".into(),
                    "auto deny".into(),
                    "ask (prompt)".into(),
                ],
                selected: effect_idx,
                hints: vec![String::new(), String::new(), String::new()],
            },
            FormField::Select {
                label: "Sandbox".into(),
                options: sandbox_opts,
                selected: sb_selected,
                hints: vec![],
            },
            FormField::Text {
                label: "Expression".into(),
                value: String::new(),
                cursor: 0,
                placeholder: r#"e.g. exe("git").allow(), tool("Read").deny()"#.into(),
                hint: Some("Starlark DSL expression — compiled and added to the policy tree"),
            },
        ];

        let title = Self::describe_node_at_path(tree, path);

        let mut form = FormState {
            title: format!("Edit — {title}"),
            kind: FormKind::EditRule {
                path: path.to_vec(),
            },
            fields,
            visible: vec![],
            active: 0,
            tool_context: if is_tool_rule {
                // For tool rules, set the tool context from the pattern value
                let pat_str = pattern_to_value_string(&match Self::get_node_at_path(tree, path) {
                    Some(Node::Condition { pattern, .. }) => pattern.clone(),
                    _ => Pattern::Wildcard,
                });
                if pat_str.is_empty() {
                    None
                } else {
                    Some(pat_str)
                }
            } else {
                Self::ancestor_tool_name(tree, path)
            },
            sandbox_summaries: sandbox_policies,
        };
        // Set pat_type_idx on the hidden pattern type field if we're editing a
        // tool rule with a non-literal pattern (e.g. AnyOf).  The AddRule form
        // doesn't have a visible pattern-type selector, but build_tool_rule_from_text
        // handles comma-separated values, so we don't need one — just leave the
        // tool_context set.
        let _ = pat_type_idx; // suppress unused warning
        form.recompute_visible();
        form
    }

    fn new_edit_decision(
        path: &[usize],
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> Self {
        let (effect_idx, sandbox_name) = Self::read_decision_at_path(&manifest.policy.tree, path);
        let title = Self::describe_node_at_path(&manifest.policy.tree, path);
        let tool_ctx = Self::ancestor_tool_name(&manifest.policy.tree, path);

        let (effect_labels, effect_hints) =
            tool_registry::effect_options_for_tool(tool_ctx.as_deref());
        // Clamp effect_idx if it's beyond filtered options
        let selected_effect = effect_idx.min(effect_labels.len().saturating_sub(1));

        let (sandbox_opts, sandbox_policies, sb_default) =
            Self::build_sandbox_options_with_included(manifest, included);

        // Use existing sandbox if set, otherwise fall back to default
        let sb_selected = if let Some(ref name) = sandbox_name {
            sandbox_opts
                .iter()
                .position(|s| s == name)
                .unwrap_or(sb_default)
        } else {
            sb_default
        };

        let fields = vec![
            FormField::Select {
                label: "When matched".into(),
                options: effect_labels,
                selected: selected_effect,
                hints: effect_hints,
            },
            FormField::Select {
                label: "Sandbox".into(),
                options: sandbox_opts,
                selected: sb_selected,
                hints: vec![],
            },
        ];

        let mut form = FormState {
            title,
            kind: FormKind::EditDecision {
                path: path.to_vec(),
            },
            fields,
            visible: vec![],
            active: 0,
            tool_context: tool_ctx,
            sandbox_summaries: sandbox_policies,
        };
        form.recompute_visible();
        form
    }

    fn read_decision_at_path(tree: &[Node], path: &[usize]) -> (usize, Option<String>) {
        match Self::get_node_at_path(tree, path) {
            Some(Node::Decision(d)) => match d {
                Decision::Allow(sb) => (0, sb.as_ref().map(|s| s.0.clone())),
                Decision::Deny => (1, None),
                Decision::Ask(sb) => (2, sb.as_ref().map(|s| s.0.clone())),
            },
            // For inline leaves (Condition with single Decision child), read the child
            Some(Node::Condition { children, .. }) => {
                if let Some(Node::Decision(d)) = children.first() {
                    match d {
                        Decision::Allow(sb) => (0, sb.as_ref().map(|s| s.0.clone())),
                        Decision::Deny => (1, None),
                        Decision::Ask(sb) => (2, sb.as_ref().map(|s| s.0.clone())),
                    }
                } else {
                    (0, None)
                }
            }
            _ => (0, None),
        }
    }

    fn new_add_child(
        parent_path: &[usize],
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> Self {
        let parent_desc = Self::describe_condition_at_path(&manifest.policy.tree, parent_path);

        let (sandbox_opts, sandbox_policies, sb_default) =
            Self::build_sandbox_options_with_included(manifest, included);

        let fields = vec![
            FormField::Select {
                label: "Add".into(),
                options: vec!["Match condition".into(), "Effect (allow/deny/ask)".into()],
                selected: 0,
                hints: vec![
                    "Add a branch that narrows what this rule matches".into(),
                    "Add a final allow/deny/ask decision".into(),
                ],
            },
            FormField::Select {
                label: "Match on".into(),
                options: observable_options(),
                selected: 0,
                hints: observable_option_hints(),
            },
            FormField::Text {
                label: "Which one".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. 0, arg_name, field.path".into(),
                hint: None, // updated in recompute_visible
            },
            FormField::Select {
                label: "Match type".into(),
                options: pattern_options(),
                selected: 0,
                hints: pattern_option_hints(),
            },
            FormField::Text {
                label: "Match value".into(),
                value: String::new(),
                cursor: 0,
                placeholder: "e.g. Read, /^git.*/, $HOME".into(),
                hint: None, // updated in recompute_visible
            },
            FormField::Select {
                label: "When matched".into(),
                options: vec![
                    "auto allow".into(),
                    "auto deny".into(),
                    "ask (prompt)".into(),
                ],
                selected: 0,
                hints: vec![String::new(), String::new(), String::new()],
            },
            FormField::Select {
                label: "Sandbox".into(),
                options: sandbox_opts,
                selected: sb_default,
                hints: vec![],
            },
        ];

        let mut form = FormState {
            title: parent_desc,
            kind: FormKind::AddChild {
                parent_path: parent_path.to_vec(),
            },
            fields,
            visible: vec![],
            active: 0,
            tool_context: Self::ancestor_tool_name(&manifest.policy.tree, parent_path),
            sandbox_summaries: sandbox_policies,
        };
        form.recompute_visible();
        form
    }

    /// Build a human-readable title describing the condition node at this path.
    fn describe_condition_at_path(tree: &[Node], path: &[usize]) -> String {
        match Self::get_node_at_path(tree, path) {
            Some(Node::Condition {
                observe, pattern, ..
            }) => {
                let what = observable_short_desc(observe);
                let val = short_pattern_desc(pattern);
                format!("Edit: {what} = {val}")
            }
            _ => "Edit Condition".into(),
        }
    }

    /// Build a human-readable title describing any node at this path.
    fn describe_node_at_path(tree: &[Node], path: &[usize]) -> String {
        // Walk up from the node to build context breadcrumbs
        match Self::get_node_at_path(tree, path) {
            Some(Node::Decision(d)) => {
                // Try to describe the parent condition for context
                if path.len() >= 2 {
                    let parent_path = &path[..path.len() - 1];
                    if let Some(Node::Condition {
                        observe, pattern, ..
                    }) = Self::get_node_at_path(tree, parent_path)
                    {
                        let what = observable_short_desc(observe);
                        let val = short_pattern_desc(pattern);
                        return format!("Edit effect for {what} = {val}");
                    }
                }
                let effect = match d {
                    Decision::Allow(_) => "allow",
                    Decision::Deny => "deny",
                    Decision::Ask(_) => "ask",
                };
                format!("Edit effect (currently {effect})")
            }
            Some(Node::Condition {
                observe,
                pattern,
                children,
                ..
            }) => {
                // Inline leaf — show condition context + current effect
                if children.len() == 1
                    && let Node::Decision(d) = &children[0]
                {
                    let what = observable_short_desc(observe);
                    let val = short_pattern_desc(pattern);
                    let effect = match d {
                        Decision::Allow(_) => "allow",
                        Decision::Deny => "deny",
                        Decision::Ask(_) => "ask",
                    };
                    return format!("Edit: {what} = {val} (currently {effect})");
                }
                let what = observable_short_desc(observe);
                let val = short_pattern_desc(pattern);
                format!("Edit: {what} = {val}")
            }
            None => "Edit".into(),
        }
    }

    /// Read the observable index and pattern value from a node at a path.
    fn read_condition_at_path(tree: &[Node], path: &[usize]) -> (usize, String) {
        let node = Self::get_node_at_path(tree, path);
        match node {
            Some(Node::Condition {
                observe, pattern, ..
            }) => {
                let obs_idx = observable_to_index(observe);
                let pat_val = pattern_to_value_string(pattern);
                (obs_idx, pat_val)
            }
            _ => (0, String::new()),
        }
    }

    fn observable_param_at_path(tree: &[Node], path: &[usize]) -> String {
        match Self::get_node_at_path(tree, path) {
            Some(Node::Condition { observe, .. }) => match observe {
                Observable::PositionalArg(n) => n.to_string(),
                Observable::NamedArg(name) => name.clone(),
                Observable::NestedField(parts) => parts.join("."),
                _ => String::new(),
            },
            _ => String::new(),
        }
    }

    fn pattern_type_index_at_path(tree: &[Node], path: &[usize]) -> usize {
        match Self::get_node_at_path(tree, path) {
            Some(Node::Condition { pattern, .. }) => match pattern {
                Pattern::Literal(_) => 0,
                Pattern::Wildcard => 1,
                Pattern::Regex(_) => 2,
                Pattern::Prefix(_) => 3,
                Pattern::ChildOf(_) => 3,
                Pattern::AnyOf(_) => 4,
                _ => 0,
            },
            _ => 0,
        }
    }

    /// Build sandbox options list, per-option hint summaries, and default
    /// selection index.
    ///
    /// Includes sandboxes from both inline policy and resolved `.star` includes.
    /// Defaults to `default_sandbox` if set, otherwise "(none)".
    fn build_sandbox_options_with_included(
        manifest: &PolicyManifest,
        included: Option<&crate::policy::match_tree::CompiledPolicy>,
    ) -> (Vec<String>, Vec<Option<SandboxPolicy>>, usize) {
        let mut opts = vec!["(none)".to_string()];
        let mut policies: Vec<Option<SandboxPolicy>> = vec![None]; // no policy for "(none)"
        let mut names: Vec<String> = manifest.policy.sandboxes.keys().cloned().collect();
        // Add included sandbox names
        if let Some(inc) = included {
            for k in inc.sandboxes.keys() {
                if !manifest.policy.sandboxes.contains_key(k) {
                    names.push(k.clone());
                }
            }
        }
        names.sort();

        for name in &names {
            let sb = manifest
                .policy
                .sandboxes
                .get(name)
                .or_else(|| included.and_then(|inc| inc.sandboxes.get(name)));
            policies.push(sb.cloned());
        }
        opts.extend(names);

        let default_idx = manifest
            .policy
            .default_sandbox
            .as_ref()
            .and_then(|name| opts.iter().position(|s| s == name))
            .unwrap_or(0);

        (opts, policies, default_idx)
    }

    /// Walk ancestor nodes to find the nearest ToolName condition's pattern value.
    fn ancestor_tool_name(tree: &[Node], path: &[usize]) -> Option<String> {
        for len in (1..=path.len()).rev() {
            let sub_path = &path[..len];
            if let Some(Node::Condition {
                observe: Observable::ToolName,
                pattern,
                ..
            }) = Self::get_node_at_path(tree, sub_path)
            {
                return Some(pattern_to_value_string(pattern));
            }
        }
        None
    }

    fn get_node_at_path<'a>(tree: &'a [Node], path: &[usize]) -> Option<&'a Node> {
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

    /// Rebuild a Select field's options/hints to match allowed effects for a tool.
    fn rebuild_effect_select(field: &mut FormField, tool_name: Option<&str>) {
        if let FormField::Select {
            options,
            hints,
            selected,
            ..
        } = field
        {
            let (new_options, new_hints) = tool_registry::effect_options_for_tool(tool_name);
            if *options != new_options {
                *options = new_options;
                *hints = new_hints;
                if *selected >= options.len() {
                    *selected = options.len().saturating_sub(1);
                }
            }
        }
    }

    /// Set the label on a Select field based on whether the effect is "ask".
    fn set_sandbox_label(field: &mut FormField, is_ask: bool) {
        if let FormField::Select { label, .. } = field {
            if label == "Sandbox" || label == "Sandbox when allowed" {
                *label = if is_ask {
                    "Sandbox when allowed".into()
                } else {
                    "Sandbox".into()
                };
            }
        }
    }

    /// Set the hint on a Text field. No-op for other field types.
    fn set_text_hint(field: &mut FormField, h: &'static str) {
        if let FormField::Text { hint, .. } = field {
            *hint = if h.is_empty() { None } else { Some(h) };
        }
    }

    /// Recompute which field indices are visible based on current selections.
    fn recompute_visible(&mut self) {
        match &self.kind {
            FormKind::AddRule | FormKind::EditRule { .. } => {
                let rule_type = match &self.fields[0] {
                    FormField::Select { selected, .. } => *selected,
                    _ => 0,
                };

                // Starlark expression mode — only show type selector + expression field
                if rule_type == 2 {
                    self.tool_context = None;
                    self.visible = vec![0, 6];
                    return;
                }

                // Update tool context from typed tool name
                if rule_type == 0 {
                    let name = self.text_value(1);
                    self.tool_context = if name.is_empty() { None } else { Some(name) };
                } else {
                    self.tool_context = None;
                }

                // Rebuild effect options based on tool context
                Self::rebuild_effect_select(&mut self.fields[4], self.tool_context.as_deref());

                let effect = match &self.fields[4] {
                    FormField::Select { selected, .. } => *selected,
                    _ => 0,
                };
                let has_sandboxes = match &self.fields[5] {
                    FormField::Select { options, .. } => options.len() > 1,
                    _ => false,
                };

                let mut vis = vec![0]; // always show rule type
                if rule_type == 0 {
                    vis.push(1); // tool name
                } else {
                    vis.push(2); // binary
                    vis.push(3); // args
                }
                vis.push(4); // effect
                // Show sandbox only for allow/ask and when sandboxes exist
                let canonical = tool_registry::filtered_effect_to_canonical(
                    self.tool_context.as_deref(),
                    effect,
                );
                if canonical != 1 && has_sandboxes {
                    vis.push(5);
                }
                Self::set_sandbox_label(&mut self.fields[5], canonical == 2);
                self.visible = vis;
            }
            FormKind::EditCondition { .. } => {
                let obs_idx = self.select_value(0);
                let pat_idx = self.select_value(2);
                // Refresh dependent text hints
                Self::set_text_hint(&mut self.fields[1], observable_param_hint(obs_idx));
                Self::set_text_hint(&mut self.fields[3], pattern_value_hint(pat_idx));
                let mut vis = vec![0]; // observable
                if observable_needs_param(obs_idx) {
                    vis.push(1); // parameter
                }
                vis.push(2); // pattern type
                if pat_idx != 1 {
                    // not wildcard
                    vis.push(3); // pattern value
                }
                self.visible = vis;
            }
            FormKind::EditDecision { .. } => {
                let effect_idx = self.select_value(0);
                let canonical = tool_registry::filtered_effect_to_canonical(
                    self.tool_context.as_deref(),
                    effect_idx,
                );
                let has_sandboxes = match &self.fields[1] {
                    FormField::Select { options, .. } => options.len() > 1,
                    _ => false,
                };
                let mut vis = vec![0]; // effect
                // Show sandbox for allow/ask when sandboxes exist
                if canonical != 1 && has_sandboxes {
                    vis.push(1);
                }
                Self::set_sandbox_label(&mut self.fields[1], canonical == 2);
                self.visible = vis;
            }
            FormKind::AddChild { .. } => {
                let child_type = self.select_value(0);
                if child_type == 0 {
                    // Condition
                    let obs_idx = self.select_value(1);
                    let pat_idx = self.select_value(3);
                    // Refresh dependent text hints
                    Self::set_text_hint(&mut self.fields[2], observable_param_hint(obs_idx));
                    Self::set_text_hint(&mut self.fields[4], pattern_value_hint(pat_idx));
                    let mut vis = vec![0, 1]; // type, observable
                    if observable_needs_param(obs_idx) {
                        vis.push(2); // parameter
                    }
                    vis.push(3); // pattern type
                    if pat_idx != 1 {
                        // not wildcard
                        vis.push(4); // pattern value
                    }
                    self.visible = vis;
                } else {
                    // Decision — filter effects based on tool context
                    Self::rebuild_effect_select(&mut self.fields[5], self.tool_context.as_deref());
                    let effect_idx = self.select_value(5);
                    let canonical = tool_registry::filtered_effect_to_canonical(
                        self.tool_context.as_deref(),
                        effect_idx,
                    );
                    let has_sandboxes = match &self.fields[6] {
                        FormField::Select { options, .. } => options.len() > 1,
                        _ => false,
                    };
                    let mut vis = vec![0, 5]; // type, effect
                    if canonical != 1 && has_sandboxes {
                        vis.push(6); // sandbox
                    }
                    Self::set_sandbox_label(&mut self.fields[6], canonical == 2);
                    self.visible = vis;
                }
            }
            _ => {} // other forms have static visibility
        }

        // Clamp active
        if self.active >= self.visible.len() {
            self.active = self.visible.len().saturating_sub(1);
        }
    }

    fn active_field_index(&self) -> usize {
        self.visible[self.active]
    }

    /// Returns true if the currently active field is a Select (not a Text input).
    pub fn active_field_is_select(&self) -> bool {
        matches!(
            self.fields[self.active_field_index()],
            FormField::Select { .. }
        )
    }

    /// Whether field at index `fi` should render all options inline.
    fn is_inline_select(&self, fi: usize) -> bool {
        // The "Rule type" selector in AddRule shows all options at once
        matches!(
            (&self.kind, fi),
            (FormKind::AddRule | FormKind::EditRule { .. }, 0)
        )
    }

    // -- Public mutation API for mouse click dispatch -------------------------

    /// Activate a visible field by its visible-index.
    pub fn set_active(&mut self, vi: usize) {
        if vi < self.visible.len() {
            self.active = vi;
        }
    }

    /// Activate the visible field that corresponds to the raw field index `fi`.
    pub fn set_active_for_field(&mut self, fi: usize) {
        if let Some(vi) = self.visible.iter().position(|&f| f == fi) {
            self.active = vi;
        }
    }

    /// Select an option in a Select field by raw field index.
    pub fn set_select_option(&mut self, fi: usize, opt: usize) {
        if let FormField::Select {
            options, selected, ..
        } = &mut self.fields[fi]
            && opt < options.len()
        {
            *selected = opt;
            self.recompute_visible();
        }
    }

    /// Toggle a MultiSelect checkbox by raw field index.
    pub fn toggle_multi(&mut self, fi: usize, opt: usize) {
        if let FormField::MultiSelect { toggled, .. } = &mut self.fields[fi]
            && opt < toggled.len()
        {
            toggled[opt] = !toggled[opt];
        }
    }
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

impl FormState {
    /// Process a key event. Returns a FormEvent indicating what happened.
    pub fn handle_key(&mut self, key: KeyEvent) -> FormEvent {
        match key.code {
            KeyCode::Esc => return FormEvent::Cancel,
            // Submit: Ctrl+Enter or Enter when not on a text/multiselect field
            KeyCode::Enter
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    || key.modifiers.contains(KeyModifiers::ALT) =>
            {
                return FormEvent::Submit;
            }
            _ => {}
        }

        let fi = self.active_field_index();

        // Field-specific key handling
        match &mut self.fields[fi] {
            FormField::Text { value, cursor, .. } => match key.code {
                KeyCode::Char(c) => {
                    value.insert(*cursor, c);
                    *cursor += 1;
                    self.recompute_visible();
                }
                KeyCode::Backspace => {
                    if *cursor > 0 {
                        *cursor -= 1;
                        value.remove(*cursor);
                        self.recompute_visible();
                    }
                }
                KeyCode::Delete => {
                    if *cursor < value.len() {
                        value.remove(*cursor);
                        self.recompute_visible();
                    }
                }
                KeyCode::Left => {
                    *cursor = cursor.saturating_sub(1);
                }
                KeyCode::Right => {
                    *cursor = (*cursor + 1).min(value.len());
                }
                KeyCode::Home => {
                    *cursor = 0;
                }
                KeyCode::End => {
                    *cursor = value.len();
                }
                KeyCode::Enter => {
                    // Move to next field or submit
                    if self.active + 1 < self.visible.len() {
                        self.active += 1;
                    } else {
                        return FormEvent::Submit;
                    }
                }
                KeyCode::BackTab => {
                    self.active = self.active.saturating_sub(1);
                }
                KeyCode::Tab => {
                    if self.active + 1 < self.visible.len() {
                        self.active += 1;
                    }
                }
                KeyCode::Down => {
                    if self.active + 1 < self.visible.len() {
                        self.active += 1;
                    }
                }
                KeyCode::Up => {
                    self.active = self.active.saturating_sub(1);
                }
                _ => {}
            },
            FormField::Select {
                options, selected, ..
            } => {
                let len = options.len();
                match key.code {
                    KeyCode::Left | KeyCode::Char('h') => {
                        *selected = if *selected == 0 {
                            len - 1
                        } else {
                            *selected - 1
                        };
                        self.recompute_visible();
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        *selected = (*selected + 1) % len;
                        self.recompute_visible();
                    }
                    KeyCode::Tab => {
                        *selected = (*selected + 1) % len;
                        self.recompute_visible();
                    }
                    KeyCode::BackTab => {
                        *selected = if *selected == 0 {
                            len - 1
                        } else {
                            *selected - 1
                        };
                        self.recompute_visible();
                    }
                    KeyCode::Enter => {
                        if self.active + 1 < self.visible.len() {
                            self.active += 1;
                        } else {
                            return FormEvent::Submit;
                        }
                    }
                    KeyCode::Down => {
                        if self.active + 1 < self.visible.len() {
                            self.active += 1;
                        }
                    }
                    KeyCode::Up => {
                        self.active = self.active.saturating_sub(1);
                    }
                    _ => {}
                }
            }
            FormField::MultiSelect {
                options,
                toggled,
                cursor,
                ..
            } => match key.code {
                KeyCode::Left | KeyCode::Char('h') => {
                    *cursor = cursor.saturating_sub(1);
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    *cursor = (*cursor + 1).min(options.len().saturating_sub(1));
                }
                KeyCode::Char(' ') => {
                    if *cursor < toggled.len() {
                        toggled[*cursor] = !toggled[*cursor];
                    }
                }
                KeyCode::Tab => {
                    *cursor = (*cursor + 1).min(options.len().saturating_sub(1));
                }
                KeyCode::BackTab => {
                    *cursor = cursor.saturating_sub(1);
                }
                KeyCode::Enter => {
                    if self.active + 1 < self.visible.len() {
                        self.active += 1;
                    } else {
                        return FormEvent::Submit;
                    }
                }
                KeyCode::Down => {
                    if self.active + 1 < self.visible.len() {
                        self.active += 1;
                    }
                }
                KeyCode::Up => {
                    self.active = self.active.saturating_sub(1);
                }
                _ => {}
            },
        }

        FormEvent::Continue
    }
}

// ---------------------------------------------------------------------------
// Submission — apply form values to manifest
// ---------------------------------------------------------------------------

impl FormState {
    /// Apply the form values to the manifest. Returns true if modified, or an error message.
    pub fn apply(&self, manifest: &mut PolicyManifest) -> Result<bool, String> {
        match &self.kind {
            FormKind::AddRule => self.apply_add_rule(manifest),
            FormKind::AddSandbox => self.apply_add_sandbox(manifest),
            FormKind::AddSandboxRule { sandbox_name } => {
                self.apply_add_sandbox_rule(manifest, sandbox_name)
            }
            FormKind::AddInclude => self.apply_add_include(manifest),
            FormKind::EditCondition { path } => self.apply_edit_condition(manifest, path),
            FormKind::EditDecision { path } => self.apply_edit_decision(manifest, path),
            FormKind::AddChild { parent_path } => self.apply_add_child(manifest, parent_path),
            FormKind::EditSandbox { sandbox_name } => {
                self.apply_edit_sandbox(manifest, sandbox_name)
            }
            FormKind::EditRule { path } => self.apply_edit_rule(manifest, path),
            FormKind::EditSandboxRule {
                sandbox_name,
                rule_index,
            } => self.apply_edit_sandbox_rule(manifest, sandbox_name, *rule_index),
        }
    }

    fn apply_add_rule(&self, manifest: &mut PolicyManifest) -> Result<bool, String> {
        let rule_type = self.select_value(0);

        // Starlark expression mode
        if rule_type == 2 {
            return self.apply_add_starlark_rule(manifest);
        }

        let effect_idx = tool_registry::filtered_effect_to_canonical(
            self.tool_context.as_deref(),
            self.select_value(4),
        );

        // Build sandbox ref
        let sandbox_ref = if effect_idx != 1 {
            // not deny
            let sb_idx = self.select_value(5);
            if sb_idx > 0 {
                let sb_name = self.select_option_str(5, sb_idx);
                Some(SandboxRef(sb_name))
            } else {
                None
            }
        } else {
            None
        };

        let decision = match effect_idx {
            0 => Decision::Allow(sandbox_ref),
            1 => Decision::Deny,
            2 => Decision::Ask(sandbox_ref),
            _ => Decision::Deny,
        };

        let node = if rule_type == 0 {
            // Tool rule (supports comma-separated names for AnyOf)
            let tool_name = self.text_value(1);
            if tool_name.is_empty() {
                return Err("Tool name is required".into());
            }
            Self::build_tool_node(&tool_name, decision)
        } else {
            // Exec rule
            let bin = self.text_value(2);
            if bin.is_empty() {
                return Err("Binary name is required".into());
            }
            let args_str = self.text_value(3);
            let args: Vec<&str> = if args_str.is_empty() {
                vec![]
            } else {
                args_str.split_whitespace().collect()
            };
            manifest_edit::build_exec_rule(&bin, &args, decision)
        };

        manifest_edit::upsert_rule(manifest, node);
        Ok(true)
    }

    /// Build a tool-name rule node, supporting comma-separated names for AnyOf.
    fn build_tool_node(tool_name: &str, decision: Decision) -> Node {
        let names: Vec<&str> = tool_name
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let pattern = if names.len() == 1 {
            Pattern::Literal(Value::Literal(names[0].to_string()))
        } else {
            Pattern::AnyOf(
                names
                    .iter()
                    .map(|n| Pattern::Literal(Value::Literal(n.to_string())))
                    .collect(),
            )
        };
        Node::Condition {
            observe: Observable::ToolName,
            pattern,
            children: vec![Node::Decision(decision)],
            doc: None,
            source: None,
            terminal: false,
        }
    }

    fn apply_edit_rule(
        &self,
        manifest: &mut PolicyManifest,
        path: &[usize],
    ) -> Result<bool, String> {
        let rule_type = self.select_value(0);

        // Starlark not supported for edit-in-place
        if rule_type == 2 {
            return Err("Cannot convert an existing rule to Starlark".into());
        }

        let effect_idx = tool_registry::filtered_effect_to_canonical(
            self.tool_context.as_deref(),
            self.select_value(4),
        );

        let sandbox_ref = if effect_idx != 1 {
            let sb_idx = self.select_value(5);
            if sb_idx > 0 {
                let sb_name = self.select_option_str(5, sb_idx);
                Some(SandboxRef(sb_name))
            } else {
                None
            }
        } else {
            None
        };

        let decision = match effect_idx {
            0 => Decision::Allow(sandbox_ref),
            1 => Decision::Deny,
            2 => Decision::Ask(sandbox_ref),
            _ => Decision::Deny,
        };

        let new_node = if rule_type == 0 {
            let tool_name = self.text_value(1);
            if tool_name.is_empty() {
                return Err("Tool name is required".into());
            }
            Self::build_tool_node(&tool_name, decision)
        } else {
            let bin = self.text_value(2);
            if bin.is_empty() {
                return Err("Binary name is required".into());
            }
            let args_str = self.text_value(3);
            let args: Vec<&str> = if args_str.is_empty() {
                vec![]
            } else {
                args_str.split_whitespace().collect()
            };
            manifest_edit::build_exec_rule(&bin, &args, decision)
        };

        // Replace the node at path
        let target = Self::get_node_at_path_mut(&mut manifest.policy.tree, path)
            .ok_or_else(|| "Node not found".to_string())?;
        *target = new_node;
        manifest.policy.tree = Node::compact(std::mem::take(&mut manifest.policy.tree));
        Ok(true)
    }

    fn apply_add_starlark_rule(&self, manifest: &mut PolicyManifest) -> Result<bool, String> {
        let expr = self.text_value(6);
        if expr.is_empty() {
            return Err("Starlark expression is required".into());
        }

        // Build a minimal Starlark program wrapping the expression
        let starlark_source = {
            use clash_starlark::codegen::ast::{Expr, Stmt};
            use clash_starlark::codegen::builder::*;
            clash_starlark::codegen::serialize(&[
                load_std(PRELOADED_FUNCS),
                Stmt::Blank,
                Stmt::Expr(settings(deny(), None)),
                Stmt::Blank,
                Stmt::Expr(policy("tui", deny(), vec![Expr::raw(&expr)], None)),
            ])
        };

        let json = clash_starlark::evaluate(
            &starlark_source,
            "tui_expression.star",
            &std::path::PathBuf::from("."),
        )
        .map_err(|e| format!("Starlark error: {e:#}"))?;

        let compiled = crate::policy::compile::compile_to_tree(&json.json)
            .map_err(|e| format!("Compile error: {e:#}"))?;

        if compiled.tree.is_empty() {
            return Err("Expression produced no rules".into());
        }

        // Append compiled nodes to the manifest tree
        for node in compiled.tree {
            manifest.policy.tree.push(node);
        }
        // Merge any sandboxes defined in the expression
        for (name, sb) in compiled.sandboxes {
            manifest.policy.sandboxes.entry(name).or_insert(sb);
        }

        Ok(true)
    }

    fn apply_add_sandbox(&self, manifest: &mut PolicyManifest) -> Result<bool, String> {
        let name = self.text_value(0);
        if name.is_empty() {
            return Err("Sandbox name is required".into());
        }

        let caps = self.multi_select_caps(1);
        let network = match self.select_value(2) {
            0 => NetworkPolicy::Deny,
            1 => NetworkPolicy::Allow,
            2 => NetworkPolicy::Localhost,
            _ => NetworkPolicy::Deny,
        };

        sandbox_edit::create_sandbox(manifest, &name, caps, network, None)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }

    fn apply_add_sandbox_rule(
        &self,
        manifest: &mut PolicyManifest,
        sandbox_name: &str,
    ) -> Result<bool, String> {
        let effect = match self.select_value(0) {
            0 => RuleEffect::Allow,
            _ => RuleEffect::Deny,
        };
        let caps = self.multi_select_caps(1);
        let path = self.text_value(2);
        if path.is_empty() {
            return Err("Path is required".into());
        }
        let path_match = match self.select_value(3) {
            0 => PathMatch::Literal,
            1 => PathMatch::Subpath,
            2 => PathMatch::Regex,
            _ => PathMatch::Literal,
        };

        sandbox_edit::add_rule(manifest, sandbox_name, effect, caps, path, path_match, None)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }

    fn apply_add_include(&self, manifest: &mut PolicyManifest) -> Result<bool, String> {
        let path = self.text_value(0);
        if path.is_empty() {
            return Err("Include path is required".into());
        }
        manifest.includes.push(IncludeEntry { path });
        Ok(true)
    }

    fn apply_edit_condition(
        &self,
        manifest: &mut PolicyManifest,
        path: &[usize],
    ) -> Result<bool, String> {
        let observable = self.build_observable(0, 1)?;
        let pattern = self.build_pattern(2, 3)?;

        let node = Self::get_node_at_path_mut(&mut manifest.policy.tree, path)
            .ok_or_else(|| "Node not found".to_string())?;

        match node {
            Node::Condition {
                observe,
                pattern: pat,
                ..
            } => {
                *observe = observable;
                *pat = pattern;
                Ok(true)
            }
            _ => Err("Not a condition node".into()),
        }
    }

    fn apply_edit_decision(
        &self,
        manifest: &mut PolicyManifest,
        path: &[usize],
    ) -> Result<bool, String> {
        let effect_idx = tool_registry::filtered_effect_to_canonical(
            self.tool_context.as_deref(),
            self.select_value(0),
        );
        let sandbox_ref = if effect_idx != 1 {
            let sb_idx = self.select_value(1);
            if sb_idx > 0 {
                Some(SandboxRef(self.select_option_str(1, sb_idx)))
            } else {
                None
            }
        } else {
            None
        };
        let new_decision = match effect_idx {
            0 => Decision::Allow(sandbox_ref),
            1 => Decision::Deny,
            2 => Decision::Ask(sandbox_ref),
            _ => Decision::Deny,
        };

        let node = Self::get_node_at_path_mut(&mut manifest.policy.tree, path)
            .ok_or_else(|| "Node not found".to_string())?;

        match node {
            Node::Decision(d) => {
                *d = new_decision;
                Ok(true)
            }
            // Inline leaf: condition with a single decision child
            Node::Condition { children, .. } => {
                if let Some(Node::Decision(d)) = children.first_mut() {
                    *d = new_decision;
                    Ok(true)
                } else {
                    Err("Not a decision node".into())
                }
            }
        }
    }

    fn apply_edit_sandbox(
        &self,
        manifest: &mut PolicyManifest,
        sandbox_name: &str,
    ) -> Result<bool, String> {
        let caps = self.multi_select_caps(0);
        let network = match self.select_value(1) {
            0 => NetworkPolicy::Deny,
            1 => NetworkPolicy::Allow,
            2 => NetworkPolicy::Localhost,
            _ => NetworkPolicy::Deny,
        };

        let sb = manifest
            .policy
            .sandboxes
            .get_mut(sandbox_name)
            .ok_or_else(|| format!("Sandbox '{sandbox_name}' not found"))?;
        sb.default = caps;
        sb.network = network;
        Ok(true)
    }

    fn apply_edit_sandbox_rule(
        &self,
        manifest: &mut PolicyManifest,
        sandbox_name: &str,
        rule_index: usize,
    ) -> Result<bool, String> {
        let effect = match self.select_value(0) {
            0 => RuleEffect::Allow,
            _ => RuleEffect::Deny,
        };
        let caps = self.multi_select_caps(1);
        let path = self.text_value(2);
        if path.is_empty() {
            return Err("Path is required".into());
        }
        let path_match = match self.select_value(3) {
            0 => PathMatch::Literal,
            1 => PathMatch::Subpath,
            2 => PathMatch::Regex,
            _ => PathMatch::Literal,
        };

        let sb = manifest
            .policy
            .sandboxes
            .get_mut(sandbox_name)
            .ok_or_else(|| format!("Sandbox '{sandbox_name}' not found"))?;
        let rule = sb
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("Rule index {rule_index} out of range"))?;
        rule.effect = effect;
        rule.caps = caps;
        rule.path = path;
        rule.path_match = path_match;
        Ok(true)
    }

    fn apply_add_child(
        &self,
        manifest: &mut PolicyManifest,
        parent_path: &[usize],
    ) -> Result<bool, String> {
        let child_type = self.select_value(0);

        let child = if child_type == 0 {
            // Condition
            let observable = self.build_observable(1, 2)?;
            let pattern = self.build_pattern(3, 4)?;
            Node::Condition {
                observe: observable,
                pattern,
                children: vec![Node::Decision(Decision::Ask(None))],
                doc: None,
                source: None,
                terminal: false,
            }
        } else {
            // Decision
            let effect_idx = tool_registry::filtered_effect_to_canonical(
                self.tool_context.as_deref(),
                self.select_value(5),
            );
            let sandbox_ref = if effect_idx != 1 {
                let sb_idx = self.select_value(6);
                if sb_idx > 0 {
                    Some(SandboxRef(self.select_option_str(6, sb_idx)))
                } else {
                    None
                }
            } else {
                None
            };
            let decision = match effect_idx {
                0 => Decision::Allow(sandbox_ref),
                1 => Decision::Deny,
                2 => Decision::Ask(sandbox_ref),
                _ => Decision::Deny,
            };
            Node::Decision(decision)
        };

        let parent = Self::get_node_at_path_mut(&mut manifest.policy.tree, parent_path)
            .ok_or_else(|| "Parent node not found".to_string())?;

        match parent {
            Node::Condition { children, .. } => {
                children.push(child);
                Ok(true)
            }
            _ => Err("Parent is not a condition node".into()),
        }
    }

    /// Build an Observable from field indices for observable-type select and param text.
    fn build_observable(&self, obs_field: usize, param_field: usize) -> Result<Observable, String> {
        let obs_idx = self.select_value(obs_field);
        let param = self.text_value(param_field);
        index_to_observable(obs_idx, &param)
    }

    /// Build a Pattern from field indices for pattern-type select and value text.
    fn build_pattern(&self, type_field: usize, value_field: usize) -> Result<Pattern, String> {
        let pat_idx = self.select_value(type_field);
        let value = self.text_value(value_field);
        index_to_pattern(pat_idx, &value)
    }

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

    // --- Helpers to extract field values ---

    fn text_value(&self, field_idx: usize) -> String {
        match &self.fields[field_idx] {
            FormField::Text { value, .. } => value.trim().to_string(),
            _ => String::new(),
        }
    }

    fn select_value(&self, field_idx: usize) -> usize {
        match &self.fields[field_idx] {
            FormField::Select { selected, .. } => *selected,
            _ => 0,
        }
    }

    fn select_option_str(&self, field_idx: usize, option_idx: usize) -> String {
        match &self.fields[field_idx] {
            FormField::Select { options, .. } => {
                options.get(option_idx).cloned().unwrap_or_default()
            }
            _ => String::new(),
        }
    }

    fn multi_select_caps(&self, field_idx: usize) -> Cap {
        match &self.fields[field_idx] {
            FormField::MultiSelect { toggled, .. } => {
                let mut caps = Cap::empty();
                let all = [
                    Cap::READ,
                    Cap::WRITE,
                    Cap::CREATE,
                    Cap::DELETE,
                    Cap::EXECUTE,
                ];
                for (i, &on) in toggled.iter().enumerate() {
                    if on && let Some(&cap) = all.get(i) {
                        caps |= cap;
                    }
                }
                if caps.is_empty() {
                    Cap::READ // fallback
                } else {
                    caps
                }
            }
            _ => Cap::READ,
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

impl FormState {
    /// Return the contextual hint for the given raw field index.
    fn field_hint(&self, field_idx: usize) -> Option<&str> {
        self.fields[field_idx].hint()
    }

    /// If `field_idx` is a sandbox Select and a sandbox is selected, return
    /// styled lines showing its full entitlements (matching the Sandboxes tab).
    fn sandbox_hint_lines(&self, field_idx: usize, t: &Theme) -> Option<Vec<Line<'static>>> {
        let FormField::Select {
            label, selected, ..
        } = &self.fields[field_idx]
        else {
            return None;
        };
        if !label.starts_with("Sandbox") {
            return None;
        }
        let sb = self.sandbox_summaries.get(*selected)?.as_ref()?;

        let mut out = Vec::new();

        // Default capabilities
        out.push(Line::from(vec![
            Span::styled("    Default: ", t.detail_label),
            Span::styled(sb.default.display(), t.detail_value),
        ]));

        // Network policy
        let net_str = match &sb.network {
            NetworkPolicy::Deny => "deny".to_string(),
            NetworkPolicy::Allow => "allow".to_string(),
            NetworkPolicy::Localhost => "localhost".to_string(),
            NetworkPolicy::AllowDomains(d) => format!("[{}]", d.join(", ")),
        };
        let net_style = match &sb.network {
            NetworkPolicy::Deny => t.effect_deny,
            NetworkPolicy::Allow => t.effect_allow,
            _ => t.detail_value,
        };
        out.push(Line::from(vec![
            Span::styled("    Network: ", t.detail_label),
            Span::styled(net_str, net_style),
        ]));

        // Rules
        if !sb.rules.is_empty() {
            for rule in &sb.rules {
                let effect_str = match rule.effect {
                    RuleEffect::Allow => "allow",
                    RuleEffect::Deny => "deny",
                };
                out.push(Line::from(Span::styled(
                    format!(
                        "    {effect_str} {} in {} ({})",
                        rule.caps.short(),
                        rule.path,
                        format!("{:?}", rule.path_match).to_lowercase()
                    ),
                    t.sandbox_effect(rule.effect),
                )));
            }
        }

        Some(out)
    }

    /// Return the section name for a field, if this form uses sections.
    /// Returns None for forms that don't need section headers.
    fn field_section(&self, field_idx: usize) -> Option<&'static str> {
        match &self.kind {
            FormKind::AddRule | FormKind::EditRule { .. } => {
                match field_idx {
                    // Field 4 = "When matched", field 5 = "Sandbox"
                    4 | 5 => Some("Decide"),
                    // Field 6 = Expression (starlark mode, no sections)
                    6 => None,
                    _ => Some("Match"),
                }
            }
            FormKind::AddChild { .. } => {
                // Field 0 = "Add type" (no section), 1-4 = match, 5-6 = decide
                match field_idx {
                    0 => None,
                    5 | 6 => Some("Decide"),
                    _ => Some("Match"),
                }
            }
            FormKind::EditDecision { .. } => {
                // All fields are decide (effect + sandbox), no section header needed
                None
            }
            _ => None,
        }
    }

    pub fn view(&self, frame: &mut Frame, area: Rect, clicks: &mut ClickRegions, t: &Theme) {
        // Use max possible field count for forms that change visibility dynamically,
        // so the popup stays in a fixed position when cycling options.
        let field_count = match &self.kind {
            FormKind::AddRule | FormKind::EditRule { .. } => self.fields.len().max(5), // stable at max visible fields
            FormKind::AddChild { .. } => self.fields.len().max(5),
            _ => self.visible.len(),
        };
        let content_lines = (field_count as u16 * 3) + 6; // fields + hint + spacing + title + footer

        let modal = ModalOverlay {
            width_pct: 60,
            height: ModalHeight::FitContent {
                lines: content_lines,
                floor_pct: 30,
                ceil_pct: 80,
            },
            border_style: t.border_focused,
            title: &self.title,
            footer: &[
                ("Enter", "submit"),
                ("Tab", "next field"),
                ("Esc", "cancel"),
            ],
            footer_left: &[],
            footer_right: None,
            scroll: None,
            theme: Some(t),
        };
        let inner = modal.render_chrome(frame, area);

        // Push footer button click regions
        for (rect, kc) in &inner.footer_buttons {
            clicks.push(*rect, ClickAction::Key(*kc));
        }

        let mut lines: Vec<Line> = Vec::new();

        // Track current_y for click region placement.
        let mut current_y = inner.area.y;
        let inner_width = inner.area.width;
        let inner_x = inner.area.x;
        let mut current_section: Option<&str> = None;

        for (vi, &fi) in self.visible.iter().enumerate() {
            let is_active = vi == self.active;
            let field = &self.fields[fi];

            // Insert section header when the section changes
            if let Some(section) = self.field_section(fi) {
                if current_section != Some(section) {
                    // Pad between sections
                    if current_section.is_some() {
                        lines.push(Line::from(""));
                        current_y += 1;
                    }
                    // ── Section ────────
                    let label = format!(" {section} ");
                    let rule_len = (inner_width as usize).saturating_sub(2 + label.len());
                    let rule = "─".repeat(rule_len);
                    lines.push(Line::from(vec![
                        Span::styled("  ──", t.text_disabled),
                        Span::styled(label, t.text_emphasis),
                        Span::styled(rule, t.text_disabled),
                    ]));
                    current_y += 1;
                    current_section = Some(section);
                }
            }

            // Push a click region for the entire field row (less specific).
            clicks.push(
                Rect::new(inner_x, current_y, inner_width, 1),
                ClickAction::FormField(vi),
            );

            match field {
                FormField::Text {
                    label,
                    value,
                    cursor,
                    placeholder,
                    ..
                } => {
                    let label_style = if is_active {
                        t.field_label_active
                    } else {
                        t.field_label_inactive
                    };

                    let display_value = if value.is_empty() && !is_active {
                        placeholder.as_str()
                    } else if value.is_empty() {
                        ""
                    } else {
                        value.as_str()
                    };

                    let value_style = if value.is_empty() && !is_active {
                        t.field_value_placeholder
                    } else if is_active {
                        t.field_value_active
                    } else {
                        t.field_value_inactive
                    };

                    if is_active && !value.is_empty() {
                        // Render with cursor
                        let before = &value[..*cursor];
                        let cursor_char = value.chars().nth(*cursor).unwrap_or(' ');
                        let after = if *cursor < value.len() {
                            &value[*cursor + cursor_char.len_utf8()..]
                        } else {
                            ""
                        };
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {label}: "), label_style),
                            Span::styled(before, value_style),
                            Span::styled(cursor_char.to_string(), t.cursor),
                            Span::styled(after, value_style),
                        ]));
                    } else if is_active && value.is_empty() {
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {label}: "), label_style),
                            Span::styled(" ", t.cursor),
                        ]));
                    } else {
                        lines.push(Line::from(vec![
                            Span::styled(format!("  {label}: "), label_style),
                            Span::styled(display_value, value_style),
                        ]));
                    }
                }
                FormField::Select {
                    label,
                    options,
                    selected,
                    ..
                } => {
                    let label_style = if is_active {
                        t.field_label_active
                    } else {
                        t.field_label_inactive
                    };

                    if self.is_inline_select(fi) {
                        // Inline mode: show all options, highlight selected.
                        let label_prefix = format!("  {label}: ");
                        let mut x_off = inner_x + label_prefix.len() as u16;

                        let mut spans = vec![Span::styled(label_prefix, label_style)];
                        for (i, opt) in options.iter().enumerate() {
                            if i > 0 {
                                spans.push(Span::styled("  ", t.field_option_unselected));
                                x_off += 2;
                            }
                            let style = if i == *selected {
                                t.field_option_selected
                            } else {
                                t.field_option_unselected
                            };
                            let opt_width = opt.len() as u16;
                            clicks.push(
                                Rect::new(x_off, current_y, opt_width, 1),
                                ClickAction::SelectOption {
                                    field: fi,
                                    option: i,
                                },
                            );
                            spans.push(Span::styled(opt.as_str(), style));
                            x_off += opt_width;
                        }
                        if is_active {
                            spans.push(Span::styled("  ←/→", t.text_disabled));
                        }
                        lines.push(Line::from(spans));
                    } else {
                        // Default mode: show < selected >
                        let option = &options[*selected];
                        let arrows = if is_active {
                            ("< ", " >")
                        } else {
                            ("  ", "  ")
                        };
                        let value_style = if is_active {
                            t.field_value_inactive.add_modifier(Modifier::BOLD)
                        } else {
                            t.field_value_inactive
                        };
                        let arrow_style = if is_active {
                            t.field_arrows_active
                        } else {
                            t.field_arrows_inactive
                        };

                        lines.push(Line::from(vec![
                            Span::styled(format!("  {label}: "), label_style),
                            Span::styled(arrows.0, arrow_style),
                            Span::styled(option.as_str(), value_style),
                            Span::styled(arrows.1, arrow_style),
                        ]));
                    }
                }
                FormField::MultiSelect {
                    label,
                    options,
                    toggled,
                    cursor,
                    ..
                } => {
                    let label_style = if is_active {
                        t.field_label_active
                    } else {
                        t.field_label_inactive
                    };

                    let label_prefix = format!("  {label}: ");
                    let mut x_off = inner_x + label_prefix.len() as u16;
                    let mut spans = vec![Span::styled(label_prefix, label_style)];

                    for (i, opt) in options.iter().enumerate() {
                        let checked = if toggled[i] { "[x]" } else { "[ ]" };
                        let is_cursor = is_active && i == *cursor;
                        let style = if is_cursor {
                            t.field_multi_cursor
                        } else if toggled[i] {
                            t.field_multi_checked
                        } else {
                            t.field_multi_unchecked
                        };
                        let item_text = format!("{checked} {opt}");
                        let item_width = item_text.len() as u16;
                        clicks.push(
                            Rect::new(x_off, current_y, item_width, 1),
                            ClickAction::ToggleMultiSelect {
                                field: fi,
                                option: i,
                            },
                        );
                        spans.push(Span::styled(item_text, style));
                        x_off += item_width;
                        if i + 1 < options.len() {
                            spans.push(Span::raw("  "));
                            x_off += 2;
                        }
                    }

                    lines.push(Line::from(spans));
                }
            }

            current_y += 1; // the field value line

            // Context hint for active field — use rich sandbox summary if available
            if is_active {
                if let Some(sb_lines) = self.sandbox_hint_lines(fi, t) {
                    let count = sb_lines.len();
                    lines.extend(sb_lines);
                    current_y += count as u16;
                } else if let Some(hint) = self.field_hint(fi) {
                    lines.push(Line::from(Span::styled(
                        format!("    {hint}"),
                        t.text_disabled,
                    )));
                    current_y += 1;
                }
            }

            // Spacing between fields
            lines.push(Line::from(""));
            current_y += 1;
        }

        let para = Paragraph::new(lines);
        frame.render_widget(para, inner.area);
    }
}

// ---------------------------------------------------------------------------
// Observable / Pattern helpers
// ---------------------------------------------------------------------------

/// Short human description of a pattern value, for use in titles.
fn short_pattern_desc(pat: &Pattern) -> String {
    match pat {
        Pattern::Wildcard => "*".into(),
        Pattern::Literal(v) => {
            let s = v.resolve();
            if s.len() > 30 {
                format!("\"{}...\"", &s[..27])
            } else {
                format!("\"{s}\"")
            }
        }
        Pattern::Regex(re) => format!("/{}/", re.as_str()),
        Pattern::Prefix(v) => format!("{}/**", v.resolve()),
        Pattern::ChildOf(v) => format!("{}/*", v.resolve()),
        Pattern::AnyOf(pats) => format!("[{} values]", pats.len()),
        Pattern::Not(inner) => format!("not {}", short_pattern_desc(inner)),
    }
}

// ---------------------------------------------------------------------------
// Observable registry — single source of truth for UI ↔ enum mapping
// ---------------------------------------------------------------------------

/// Declares an ordered registry of Observable variants with their UI metadata.
/// Generates: observable_options(), observable_to_index(), index_to_observable(),
/// observable_needs_param(), observable_hint(), observable_param_hint(),
/// observable_param_placeholder(), pattern_value_placeholder().
///
/// Simple variants use `param: none`. Parameterized variants specify hint,
/// placeholder, and a parse block that receives `_param: &str` and returns
/// `Result<Observable, String>`.
macro_rules! observable_registry {
    // Entry: split into simple (param: none) and parameterized variants.
    (
        $( $variant:ident {
            label: $label:expr,
            hint: $hint:expr,
            value_placeholder: $val_ph:expr,
            param_hint: $ph:expr,
            param_placeholder: $pp:expr,
            parse($param_name:ident): $parse:expr,
        } ),* $(,)?
    ) => {
        fn observable_options() -> Vec<String> {
            vec![ $( $label.into() ),* ]
        }

        /// Per-option hint strings, parallel to `observable_options()`.
        fn observable_option_hints() -> Vec<String> {
            vec![ $( String::from($hint) ),* ]
        }

        fn observable_to_index(obs: &Observable) -> usize {
            let mut _i = 0usize;
            $(
                if observable_registry!(@matches obs, $variant) { return _i; }
                _i += 1;
            )*
            unreachable!("all Observable variants covered")
        }

        #[allow(dead_code)]
        fn observable_hint(idx: usize) -> &'static str {
            const HINTS: &[&str] = &[ $( $hint ),* ];
            HINTS.get(idx).copied().unwrap_or("")
        }

        fn observable_needs_param(idx: usize) -> bool {
            const FLAGS: &[bool] = &[ $( !$ph.is_empty() ),* ];
            FLAGS.get(idx).copied().unwrap_or(false)
        }

        fn observable_param_hint(idx: usize) -> &'static str {
            const HINTS: &[&str] = &[ $( $ph ),* ];
            HINTS.get(idx).copied().unwrap_or("")
        }

        fn observable_param_placeholder(idx: usize) -> &'static str {
            const PHS: &[&str] = &[ $( $pp ),* ];
            PHS.get(idx).copied().unwrap_or("")
        }

        fn pattern_value_placeholder(idx: usize) -> &'static str {
            const PHS: &[&str] = &[ $( $val_ph ),* ];
            PHS.get(idx).copied().unwrap_or("the value to match")
        }

        #[allow(unused_variables)]
        fn index_to_observable(idx: usize, _param: &str) -> Result<Observable, String> {
            let mut _i = 0usize;
            $(
                if idx == _i {
                    let $param_name: &str = _param;
                    return $parse;
                }
                _i += 1;
            )*
            Err("Unknown observable type".into())
        }
    };

    // --- internal helpers ---

    (@matches $obs:expr, ToolName) => { matches!($obs, Observable::ToolName) };
    (@matches $obs:expr, HookType) => { matches!($obs, Observable::HookType) };
    (@matches $obs:expr, AgentName) => { matches!($obs, Observable::AgentName) };
    (@matches $obs:expr, PositionalArg) => { matches!($obs, Observable::PositionalArg(_)) };
    (@matches $obs:expr, HasArg) => { matches!($obs, Observable::HasArg) };
    (@matches $obs:expr, NamedArg) => { matches!($obs, Observable::NamedArg(_)) };
    (@matches $obs:expr, NestedField) => { matches!($obs, Observable::NestedField(_)) };
    (@matches $obs:expr, FsOp) => { matches!($obs, Observable::FsOp) };
    (@matches $obs:expr, FsPath) => { matches!($obs, Observable::FsPath) };
    (@matches $obs:expr, NetDomain) => { matches!($obs, Observable::NetDomain) };

}

observable_registry! {
    ToolName {
        label: "Tool Name",
        hint: "Match by tool name: Read, Write, Bash, Edit, Glob, Grep, etc.",
        value_placeholder: "e.g. Read, Write, Bash, Edit",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::ToolName),
    },
    HookType {
        label: "Hook Type",
        hint: "Match by hook type: PreToolUse, PostToolUse, etc.",
        value_placeholder: "e.g. PreToolUse, PostToolUse",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::HookType),
    },
    AgentName {
        label: "Agent Name",
        hint: "Match by the name of the agent making the request",
        value_placeholder: "e.g. my-agent",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::AgentName),
    },
    PositionalArg {
        label: "Positional Arg",
        hint: "Match a positional argument (e.g. arg[0] is the command in Bash)",
        value_placeholder: "e.g. git, npm, gh",
        param_hint: "Argument index (0 = command, 1 = first arg, etc.)",
        param_placeholder: "e.g. 0 (command), 1 (first arg), 2 ...",
        parse(s): {
            let n: i32 = s.parse().map_err(|_| "Invalid arg index".to_string())?;
            Ok(Observable::PositionalArg(n))
        },
    },
    HasArg {
        label: "Has Arg",
        hint: "Match if any argument contains the pattern value",
        value_placeholder: "the value to match",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::HasArg),
    },
    NamedArg {
        label: "Named Arg",
        hint: "Match a specific named argument by key",
        value_placeholder: "the value to match",
        param_hint: "The argument key name to match against",
        param_placeholder: "e.g. file_path, content",
        parse(s): {
            if s.is_empty() {
                return Err("Named arg requires a name".into());
            }
            Ok(Observable::NamedArg(s.to_string()))
        },
    },
    NestedField {
        label: "Nested Field",
        hint: "Match a nested field in the tool's JSON input",
        value_placeholder: "the value to match",
        param_hint: "Dot-separated path into JSON, e.g. content.text",
        param_placeholder: "e.g. content.text, options.mode",
        parse(s): {
            if s.is_empty() {
                return Err("Nested field requires a path".into());
            }
            let parts: Vec<String> = s.split('.').map(|p| p.to_string()).collect();
            Ok(Observable::NestedField(parts))
        },
    },
    FsOp {
        label: "FS Operation",
        hint: "Match the filesystem operation type: read or write",
        value_placeholder: "e.g. read, write",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::FsOp),
    },
    FsPath {
        label: "FS Path",
        hint: "Match the filesystem path being accessed",
        value_placeholder: "e.g. /home/user/project, $PWD",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::FsPath),
    },
    NetDomain {
        label: "Net Domain",
        hint: "Match the network domain being accessed",
        value_placeholder: "e.g. github.com, api.example.com",
        param_hint: "",
        param_placeholder: "",
        parse(s): Ok(Observable::NetDomain),
    },
}

/// Short human description of an observable, for use in form titles.
/// This is outside the macro because it operates on `&Observable` (compiler-checked
/// exhaustive match) rather than on indices, so it doesn't have the fragility problem.
fn observable_short_desc(obs: &Observable) -> String {
    match obs {
        Observable::ToolName => "tool".into(),
        Observable::HookType => "hook".into(),
        Observable::AgentName => "agent".into(),
        Observable::PositionalArg(n) => format!("arg[{n}]"),
        Observable::HasArg => "any arg".into(),
        Observable::NamedArg(name) => format!("arg \"{name}\""),
        Observable::NestedField(parts) => format!("field {}", parts.join(".")),
        Observable::FsOp => "fs operation".into(),
        Observable::FsPath => "fs path".into(),
        Observable::NetDomain => "network domain".into(),
        Observable::Mode => "mode".into(),
    }
}

// ---------------------------------------------------------------------------
// Pattern registry — single source of truth for UI ↔ enum mapping
// ---------------------------------------------------------------------------

macro_rules! pattern_registry {
    (
        $( $name:ident {
            label: $label:expr,
            hint: $hint:expr,
            value_hint: $val_hint:expr,
            parse($param_name:ident): $parse:expr,
        } ),* $(,)?
    ) => {
        #[allow(dead_code)]
        fn pattern_options() -> Vec<String> {
            vec![ $( $label.into() ),* ]
        }

        /// Per-option hint strings, parallel to `pattern_options()`.
        #[allow(dead_code)]
        fn pattern_option_hints() -> Vec<String> {
            vec![ $( String::from($hint) ),* ]
        }

        #[allow(dead_code)]
        fn pattern_hint(idx: usize) -> &'static str {
            const HINTS: &[&str] = &[ $( $hint ),* ];
            HINTS.get(idx).copied().unwrap_or("")
        }

        fn pattern_value_hint(idx: usize) -> &'static str {
            const HINTS: &[&str] = &[ $( $val_hint ),* ];
            HINTS.get(idx).copied().unwrap_or("")
        }

        fn index_to_pattern(idx: usize, _value: &str) -> Result<Pattern, String> {
            let mut _i = 0usize;
            $(
                if idx == _i {
                    let $param_name: &str = _value;
                    return $parse;
                }
                _i += 1;
            )*
            Err("Unknown pattern type".into())
        }
    };
}

pattern_registry! {
    Literal {
        label: "exact value",
        hint: "literal: match an exact string value",
        value_hint: "The exact string to match",
        parse(v): {
            if v.is_empty() { return Err("Literal pattern requires a value".into()); }
            Ok(Pattern::Literal(Value::Literal(v.to_string())))
        },
    },
    Wildcard {
        label: "anything",
        hint: "wildcard: match anything (no value needed)",
        value_hint: "",
        parse(_v): Ok(Pattern::Wildcard),
    },
    Regex {
        label: "regex",
        hint: "regex: match against a regular expression",
        value_hint: "A regex, e.g. ^git.* or deploy|release",
        parse(v): {
            if v.is_empty() { return Err("Regex pattern requires a value".into()); }
            let re = regex::Regex::new(v).map_err(|e| format!("Invalid regex: {e}"))?;
            Ok(Pattern::Regex(std::sync::Arc::new(re)))
        },
    },
    Prefix {
        label: "path prefix",
        hint: "prefix: match a path and all its children",
        value_hint: "A path prefix, e.g. /home/user or $PWD",
        parse(v): {
            if v.is_empty() { return Err("Prefix pattern requires a value".into()); }
            Ok(Pattern::Prefix(Value::Literal(v.to_string())))
        },
    },
    ChildOf {
        label: "direct children",
        hint: "child-of: match direct children of a path (one level)",
        value_hint: "A parent path, e.g. /home/user or $HOME",
        parse(v): {
            if v.is_empty() { return Err("Child-of pattern requires a value".into()); }
            Ok(Pattern::ChildOf(Value::Literal(v.to_string())))
        },
    },
    AnyOf {
        label: "list of values",
        hint: "any-of: match any value in a comma-separated list",
        value_hint: "Comma-separated values, e.g. Read, Glob, Grep",
        parse(v): {
            if v.is_empty() { return Err("List requires at least one value".into()); }
            let pats: Vec<Pattern> = v
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| Pattern::Literal(Value::Literal(s.to_string())))
                .collect();
            if pats.is_empty() {
                return Err("List requires at least one value".into());
            }
            if pats.len() == 1 {
                Ok(pats.into_iter().next().unwrap())
            } else {
                Ok(Pattern::AnyOf(pats))
            }
        },
    },
}

fn pattern_to_value_string(pat: &Pattern) -> String {
    match pat {
        Pattern::Wildcard => String::new(),
        Pattern::Literal(v) => v.resolve(),
        Pattern::Regex(re) => re.as_str().to_string(),
        Pattern::Prefix(v) => v.resolve(),
        Pattern::ChildOf(v) => v.resolve(),
        Pattern::AnyOf(pats) => pats
            .iter()
            .map(pattern_to_value_string)
            .collect::<Vec<_>>()
            .join(", "),
        Pattern::Not(inner) => format!("!{}", pattern_to_value_string(inner)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::match_tree::*;
    use crossterm::event::{KeyEvent, KeyModifiers};
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

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    #[test]
    fn test_add_include_form() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddInclude, &manifest, None);

        // Type "test.star"
        for c in "test.star".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }

        // Submit
        let result = form.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, FormEvent::Submit));

        let mut manifest = empty_manifest();
        assert!(form.apply(&mut manifest).is_ok());
        assert_eq!(manifest.includes.len(), 1);
        assert_eq!(manifest.includes[0].path, "test.star");
    }

    #[test]
    fn test_add_tool_rule_form() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddRule, &manifest, None);

        // Field 0 is rule type select, default is "Tool rule" — press Enter to advance
        form.handle_key(key(KeyCode::Enter));

        // Field 1 is tool name text — type "Read"
        for c in "Read".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Enter));

        // Field 4 is effect select — default "allow", press Enter to advance
        // This should be the last visible field (no sandboxes defined) — submit
        let result = form.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, FormEvent::Submit));

        let mut manifest = empty_manifest();
        assert!(form.apply(&mut manifest).is_ok());
        assert!(!manifest.policy.tree.is_empty());
    }

    #[test]
    fn test_cancel_form() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddInclude, &manifest, None);

        let result = form.handle_key(key(KeyCode::Esc));
        assert!(matches!(result, FormEvent::Cancel));
    }

    #[test]
    fn test_text_field_editing() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddInclude, &manifest, None);

        // Type "hello"
        for c in "hello".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(form.text_value(0), "hello");

        // Backspace
        form.handle_key(key(KeyCode::Backspace));
        assert_eq!(form.text_value(0), "hell");

        // Left then insert
        form.handle_key(key(KeyCode::Left));
        form.handle_key(key(KeyCode::Char('X')));
        assert_eq!(form.text_value(0), "helXl");
    }

    #[test]
    fn test_empty_text_rejected() {
        let manifest = empty_manifest();
        let form = FormState::from_request(&FormRequest::AddInclude, &manifest, None);

        let mut manifest = empty_manifest();
        let result = form.apply(&mut manifest);
        assert!(result.is_err());
    }

    #[test]
    fn test_edit_condition_form() {
        use crate::policy::manifest_edit;

        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Read", Decision::Allow(None)),
        );

        // Create edit form for the root condition
        let mut form = FormState::from_request(
            &FormRequest::EditCondition { path: vec![0] },
            &manifest,
            None,
        );

        // Observable should be pre-filled as tool_name (index 0)
        assert_eq!(form.select_value(0), 0);
        // Pattern value should be pre-filled as "Read"
        assert_eq!(form.text_value(3), "Read");

        // Change pattern value to "Write"
        // Navigate to value field (field index 3)
        // Use Enter to advance past Select fields (Tab now cycles options)
        form.handle_key(key(KeyCode::Enter)); // -> pattern type
        form.handle_key(key(KeyCode::Enter)); // -> value

        // Clear existing text and type new value
        // Select all and delete by using Home then deleting forward
        form.handle_key(key(KeyCode::Home));
        for _ in 0..10 {
            form.handle_key(key(KeyCode::Delete));
        }
        for c in "Write".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }

        let result = form.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, FormEvent::Submit));

        assert!(form.apply(&mut manifest).is_ok());
        // Verify the condition was updated
        match &manifest.policy.tree[0] {
            Node::Condition { pattern, .. } => match pattern {
                Pattern::Literal(v) => assert_eq!(v.resolve(), "Write"),
                _ => panic!("Expected literal pattern"),
            },
            _ => panic!("Expected condition node"),
        }
    }

    #[test]
    fn test_add_child_decision_form() {
        use crate::policy::manifest_edit;

        let mut manifest = empty_manifest();
        // Create a condition with multiple children so it's expandable
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_exec_rule("gh", &["pr"], Decision::Allow(None)),
        );

        // Add a decision child under root (Bash condition)
        let mut form = FormState::from_request(
            &FormRequest::AddChild {
                parent_path: vec![0],
            },
            &manifest,
            None,
        );

        // Switch to Decision type
        form.handle_key(key(KeyCode::Right)); // type: Condition -> Decision

        // Effect should now be visible, default "allow"
        // Navigate to effect and change to "deny"
        form.handle_key(key(KeyCode::Enter)); // -> effect
        form.handle_key(key(KeyCode::Right)); // allow -> deny

        let result = form.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, FormEvent::Submit));

        assert!(form.apply(&mut manifest).is_ok());
        // Root condition should now have an extra child
        match &manifest.policy.tree[0] {
            Node::Condition { children, .. } => {
                let has_deny = children
                    .iter()
                    .any(|c| matches!(c, Node::Decision(Decision::Deny)));
                assert!(has_deny, "Should have a Deny decision child");
            }
            _ => panic!("Expected condition node"),
        }
    }

    #[test]
    fn test_add_sandbox_form() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddSandbox, &manifest, None);

        // Field 0: name text — type "dev"
        for c in "dev".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }
        form.handle_key(key(KeyCode::Tab));

        // Field 1: multi-select caps — defaults are read + execute, skip
        form.handle_key(key(KeyCode::Enter));

        // Field 2: network select — default "deny", submit
        let result = form.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, FormEvent::Submit));

        let mut manifest = empty_manifest();
        assert!(form.apply(&mut manifest).is_ok());
        assert!(manifest.policy.sandboxes.contains_key("dev"));
        let sb = &manifest.policy.sandboxes["dev"];
        assert_eq!(sb.default, Cap::READ | Cap::EXECUTE);
        assert_eq!(sb.network, NetworkPolicy::Deny);
    }

    #[test]
    fn test_bash_tool_hides_ask_effect() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddRule, &manifest, None);

        // Type "Bash" into tool name field (field 1)
        // First, advance to field 1 (it's a Text field, Tab advances)
        form.handle_key(key(KeyCode::Enter)); // past rule type select -> tool name
        for c in "Bash".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }

        // Effect field (field 4) should now only have 2 options
        match &form.fields[4] {
            FormField::Select { options, .. } => {
                assert_eq!(options.len(), 2, "Bash should only have allow/deny");
                assert!(options[0].contains("allow"));
                assert!(options[1].contains("deny"));
            }
            _ => panic!("Expected Select field"),
        }
    }

    #[test]
    fn test_non_bash_tool_has_ask_effect() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddRule, &manifest, None);

        // Type "Read" into tool name field
        form.handle_key(key(KeyCode::Enter));
        for c in "Read".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }

        // Effect field should have all 3 options
        match &form.fields[4] {
            FormField::Select { options, .. } => {
                assert_eq!(options.len(), 3, "Read should have allow/deny/ask");
            }
            _ => panic!("Expected Select field"),
        }
    }

    #[test]
    fn test_bash_add_rule_applies_deny() {
        let manifest = empty_manifest();
        let mut form = FormState::from_request(&FormRequest::AddRule, &manifest, None);

        // Type "Bash" tool name
        form.handle_key(key(KeyCode::Enter));
        for c in "Bash".chars() {
            form.handle_key(key(KeyCode::Char(c)));
        }

        // Advance to effect, select deny (index 1 in filtered = canonical 1)
        form.handle_key(key(KeyCode::Enter)); // -> effect
        form.handle_key(key(KeyCode::Right)); // allow -> deny

        // Submit
        let result = form.handle_key(key(KeyCode::Enter));
        assert!(matches!(result, FormEvent::Submit));

        let mut manifest = empty_manifest();
        assert!(form.apply(&mut manifest).is_ok());

        // Should have a Bash deny rule
        assert!(!manifest.policy.tree.is_empty());
    }

    #[test]
    fn test_edit_decision_under_bash_hides_ask() {
        use crate::policy::manifest_edit;

        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Bash", Decision::Allow(None)),
        );

        // The tool rule creates Condition(tool_name=Bash) -> Decision(Allow)
        // Edit the decision at path [0, 0] (child of root condition)
        let form = FormState::from_request(
            &FormRequest::EditDecision { path: vec![0, 0] },
            &manifest,
            None,
        );

        assert_eq!(form.tool_context.as_deref(), Some("Bash"));
        match &form.fields[0] {
            FormField::Select { options, .. } => {
                assert_eq!(options.len(), 2, "Under Bash, only allow/deny");
            }
            _ => panic!("Expected Select field"),
        }
    }

    #[test]
    fn test_edit_sandbox_prefills_and_applies() {
        let mut manifest = empty_manifest();
        sandbox_edit::create_sandbox(
            &mut manifest,
            "dev",
            Cap::READ | Cap::WRITE,
            NetworkPolicy::Localhost,
            None,
        )
        .unwrap();

        let form = FormState::from_request(
            &FormRequest::EditSandbox {
                sandbox_name: "dev".into(),
            },
            &manifest,
            None,
        );

        // Check prefilled caps: read=true, write=true, rest=false
        match &form.fields[0] {
            FormField::MultiSelect { toggled, .. } => {
                assert_eq!(toggled, &[true, true, false, false, false]);
            }
            _ => panic!("Expected MultiSelect"),
        }
        // Check prefilled network: localhost = index 2
        match &form.fields[1] {
            FormField::Select { selected, .. } => {
                assert_eq!(*selected, 2);
            }
            _ => panic!("Expected Select"),
        }

        // Apply should update the sandbox
        form.apply(&mut manifest).unwrap();
        let sb = &manifest.policy.sandboxes["dev"];
        assert_eq!(sb.default, Cap::READ | Cap::WRITE);
        assert_eq!(sb.network, NetworkPolicy::Localhost);
    }

    #[test]
    fn test_edit_sandbox_rule_prefills_and_applies() {
        let mut manifest = empty_manifest();
        sandbox_edit::create_sandbox(&mut manifest, "dev", Cap::READ, NetworkPolicy::Deny, None)
            .unwrap();
        sandbox_edit::add_rule(
            &mut manifest,
            "dev",
            RuleEffect::Deny,
            Cap::WRITE | Cap::DELETE,
            "/tmp".into(),
            PathMatch::Literal,
            None,
        )
        .unwrap();

        let form = FormState::from_request(
            &FormRequest::EditSandboxRule {
                sandbox_name: "dev".into(),
                rule_index: 0,
            },
            &manifest,
            None,
        );

        // Effect: deny = index 1
        assert_eq!(form.select_value(0), 1);
        // Caps: write + delete
        match &form.fields[1] {
            FormField::MultiSelect { toggled, .. } => {
                assert_eq!(toggled, &[false, true, false, true, false]);
            }
            _ => panic!("Expected MultiSelect"),
        }
        // Path prefilled
        match &form.fields[2] {
            FormField::Text { value, .. } => assert_eq!(value, "/tmp"),
            _ => panic!("Expected Text"),
        }
        // Path match: literal = index 0
        assert_eq!(form.select_value(3), 0);

        // Apply should update the rule
        form.apply(&mut manifest).unwrap();
        let rule = &manifest.policy.sandboxes["dev"].rules[0];
        assert_eq!(rule.effect, RuleEffect::Deny);
        assert_eq!(rule.caps, Cap::WRITE | Cap::DELETE);
        assert_eq!(rule.path, "/tmp");
        assert_eq!(rule.path_match, PathMatch::Literal);
    }
}
