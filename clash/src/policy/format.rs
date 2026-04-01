//! Human-readable formatting for policy IR types.
//!
//! Provides display rendering for [`CompiledPolicy`], [`Node`], [`Decision`],
//! [`Observable`], and [`Pattern`] — kept separate from the IR definitions so
//! `match_tree.rs` stays focused on types and evaluation.

use crate::policy::match_tree::{CompiledPolicy, Decision, Node, Observable, Pattern, SandboxRef};

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Format all rules in a policy as flat, denormalized lines.
pub fn format_rules(policy: &CompiledPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    for node in &policy.tree {
        format_node_flat(node, &mut Vec::new(), &mut lines);
    }
    lines
}

/// Format all rules in a policy as a tree with box-drawing characters.
pub fn format_tree(policy: &CompiledPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    let len = policy.tree.len();
    for (i, node) in policy.tree.iter().enumerate() {
        let is_last = i == len - 1;
        format_tree_node(node, "", is_last, true, &mut lines);
    }
    lines
}

// ---------------------------------------------------------------------------
// Node-level rendering
// ---------------------------------------------------------------------------

/// Recursively render a node as tree lines with box-drawing characters.
pub fn format_tree_node(
    node: &Node,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    lines: &mut Vec<String>,
) {
    let connector = if is_root {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };
    let child_prefix = if is_root {
        ""
    } else if is_last {
        "    "
    } else {
        "│   "
    };

    match node {
        Node::Decision(d) => {
            let effect = format_decision(d);
            lines.push(format!("{prefix}{connector}{effect}"));
        }
        Node::Condition {
            observe,
            pattern,
            children,
            doc,
            source,
            ..
        } => {
            let label = format_condition(observe, pattern);
            let doc_suffix = doc
                .as_deref()
                .map(|d| format!("  # {d}"))
                .unwrap_or_default();
            let source_suffix = if is_root {
                source
                    .as_deref()
                    .map(|s| format!("  [{s}]"))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            // Single decision child → show inline: "label → effect"
            if children.len() == 1
                && let Node::Decision(d) = &children[0]
            {
                let effect = format_decision(d);
                lines.push(format!(
                    "{prefix}{connector}{label} → {effect}{doc_suffix}{source_suffix}"
                ));
                return;
            }

            // Branch — show label, then children as sub-tree
            lines.push(format!(
                "{prefix}{connector}{label}{doc_suffix}{source_suffix}"
            ));
            let new_prefix = format!("{prefix}{child_prefix}");
            let child_count = children.len();
            for (i, child) in children.iter().enumerate() {
                let child_is_last = i == child_count - 1;
                format_tree_node(child, &new_prefix, child_is_last, false, lines);
            }
        }
    }
}

/// Recursively format a node as a flat, denormalized rule line.
fn format_node_flat(node: &Node, path: &mut Vec<String>, lines: &mut Vec<String>) {
    match node {
        Node::Decision(d) => {
            let effect = format_decision(d);
            if path.is_empty() {
                lines.push(format!("{effect} *"));
            } else {
                lines.push(format!("{effect} {}", path.join(" → ")));
            }
        }
        Node::Condition {
            observe,
            pattern,
            children,
            doc,
            ..
        } => {
            let segment = format_condition(observe, pattern);
            path.push(segment);
            if children.is_empty() {
                lines.push(format!("(no decision) {}", path.join(" → ")));
            } else {
                // Check if this is a leaf condition (all children are decisions)
                let is_leaf = children.iter().all(|c| matches!(c, Node::Decision(_)));
                for child in children {
                    format_node_flat(child, path, lines);
                }
                // Append doc to the last line if this is the innermost condition
                if is_leaf
                    && let Some(doc_text) = doc
                    && let Some(last) = lines.last_mut()
                {
                    last.push_str(&format!("  # {doc_text}"));
                }
            }
            path.pop();
        }
    }
}

// ---------------------------------------------------------------------------
// Primitive renderers (pub for use in tui and other display code)
// ---------------------------------------------------------------------------

/// Render a [`Decision`] leaf as a short string (e.g. `"allow"`, `"deny"`,
/// `"allow [sandbox: dev]"`).
pub fn format_decision(d: &Decision) -> String {
    match d {
        Decision::Allow(Some(SandboxRef(name))) => format!("allow [sandbox: {name}]"),
        Decision::Allow(None) => "allow".to_string(),
        Decision::Deny => "deny".to_string(),
        Decision::Ask(Some(SandboxRef(name))) => format!("ask [sandbox: {name}]"),
        Decision::Ask(None) => "ask".to_string(),
    }
}

/// Render an [`Observable`]+[`Pattern`] pair as a short condition string
/// (e.g. `"tool=\"Bash\""`, `"arg[0]=\"git\""`).
pub fn format_condition(obs: &Observable, pat: &Pattern) -> String {
    let obs_str = match obs {
        Observable::ToolName => "tool".to_string(),
        Observable::HookType => "hook".to_string(),
        Observable::AgentName => "agent".to_string(),
        Observable::PositionalArg(n) => format!("arg[{n}]"),
        Observable::HasArg => "has_arg".to_string(),
        Observable::NamedArg(name) => format!("named({name})"),
        Observable::NestedField(path) => format!("field({})", path.join(".")),
        Observable::FsOp => "fs_op".to_string(),
        Observable::FsPath => "fs_path".to_string(),
        Observable::NetDomain => "net_domain".to_string(),
        Observable::Mode => "mode".to_string(),
    };
    let pat_str = format_pattern(pat);
    format!("{obs_str}={pat_str}")
}

/// Render a [`Pattern`] as a short string (e.g. `"*"`, `"\"git\""`, `"/re/"`).
pub fn format_pattern(pat: &Pattern) -> String {
    match pat {
        Pattern::Wildcard => "*".to_string(),
        Pattern::Literal(v) => format!("\"{}\"", v.resolve()),
        Pattern::Regex(re) => format!("/{}/", re.as_str()),
        Pattern::AnyOf(pats) => {
            let items: Vec<_> = pats.iter().map(format_pattern).collect();
            format!("{{{}}}", items.join("|"))
        }
        Pattern::Not(inner) => format!("!{}", format_pattern(inner)),
        Pattern::Prefix(v) => format!("{}/**", v.resolve()),
        Pattern::ChildOf(v) => format!("{}/*", v.resolve()),
    }
}
