//! Interactive decision trace visualization for `clash explain --trace`.
//!
//! Walks the compiled policy tree and produces a color-coded, tree-style
//! rendering showing every rule considered, why each condition matched or
//! was skipped, and which rule ultimately won.

use crate::policy::format::format_condition;
use crate::policy::match_tree::{
    CompiledPolicy, Decision, Node, Observable, Pattern, QueryContext,
};
use crate::policy::Effect;
use crate::style;

/// A single condition step in the trace for a rule branch.
#[derive(Debug)]
struct ConditionTrace {
    /// Human-readable label for this condition (e.g. `arg[0]="git"`).
    label: String,
    /// Whether this condition matched.
    matched: bool,
    /// The value that was tested (if available).
    tested_value: Option<String>,
    /// How the pattern matched (e.g. "literal", "regex", "wildcard").
    match_kind: String,
}

/// The trace for a single root-level rule branch.
#[derive(Debug)]
struct RuleBranchTrace {
    /// 0-based index of this rule in the policy.
    rule_index: usize,
    /// Human-readable description (e.g. `exe("git", args=["push"])`).
    description: String,
    /// Per-condition trace entries.
    conditions: Vec<ConditionTrace>,
    /// The decision at the leaf, if all conditions matched.
    decision: Option<Decision>,
    /// Whether this rule was the winning (first-matched) rule.
    is_winner: bool,
    /// Whether this rule was skipped because a prior rule already won.
    skipped_by_prior: bool,
    /// Source provenance, if stamped.
    source: Option<String>,
}

/// Full trace result for display.
#[derive(Debug)]
pub struct PolicyTrace {
    branches: Vec<RuleBranchTrace>,
    default_effect: Effect,
    final_effect: Effect,
    final_resolution: String,
}

/// Build a detailed policy trace by walking the tree against a query context.
pub fn build_trace(policy: &CompiledPolicy, ctx: &QueryContext) -> PolicyTrace {
    let mut branches = Vec::new();
    let mut winner_found = false;

    for (i, node) in policy.tree.iter().enumerate() {
        let source = match node {
            Node::Condition { source, .. } => source.clone(),
            _ => None,
        };

        let mut conditions = Vec::new();
        let decision = trace_node(node, ctx, &mut conditions);

        let all_matched = conditions.iter().all(|c| c.matched);
        let is_winner = all_matched && decision.is_some() && !winner_found;

        let description = build_rule_description(node);

        let branch = RuleBranchTrace {
            rule_index: i + 1,
            description,
            conditions,
            decision: if all_matched { decision } else { None },
            is_winner,
            skipped_by_prior: winner_found && all_matched,
            source,
        };

        if is_winner {
            winner_found = true;
        }

        branches.push(branch);
    }

    let final_effect = if let Some(winner) = branches.iter().find(|b| b.is_winner) {
        winner
            .decision
            .as_ref()
            .map(|d| d.effect())
            .unwrap_or(policy.default_effect)
    } else {
        policy.default_effect
    };

    let final_resolution = if winner_found {
        format!("{}", final_effect)
    } else {
        format!("{} (no rules matched, default)", policy.default_effect)
    };

    PolicyTrace {
        branches,
        default_effect: policy.default_effect,
        final_effect,
        final_resolution,
    }
}

/// Recursively trace a node against the query context, collecting condition results.
/// Returns the leaf Decision if all conditions on the path matched.
fn trace_node(
    node: &Node,
    ctx: &QueryContext,
    conditions: &mut Vec<ConditionTrace>,
) -> Option<Decision> {
    match node {
        Node::Decision(d) => Some(d.clone()),
        Node::Condition {
            observe,
            pattern,
            children,
            terminal,
            ..
        } => {
            let values = extract_observable(ctx, observe);
            let tested_value = values.as_ref().map(|vs| vs.join(", "));
            let matched = matches_observable_check(observe, pattern, *terminal, ctx, &values);
            let match_kind = pattern_kind(pattern);
            let label = format_condition(observe, pattern);

            conditions.push(ConditionTrace {
                label,
                matched,
                tested_value,
                match_kind,
            });

            if matched {
                // Try children in order (DFS, first-match)
                for child in children {
                    let mut child_conditions = Vec::new();
                    if let Some(d) = trace_node(child, ctx, &mut child_conditions) {
                        conditions.extend(child_conditions);
                        return Some(d);
                    }
                    // If the child didn't match, include its conditions to show why
                    conditions.extend(child_conditions);
                }
                None
            } else {
                None
            }
        }
    }
}

/// Extract observable values from the context (mirrors QueryContext::extract).
fn extract_observable(ctx: &QueryContext, obs: &Observable) -> Option<Vec<String>> {
    match obs {
        Observable::ToolName => Some(vec![ctx.tool_name.clone()]),
        Observable::HookType => ctx.hook_type.clone().map(|h| vec![h]),
        Observable::AgentName => ctx.agent_name.clone().map(|a| vec![a]),
        Observable::PositionalArg(i) => {
            let idx = *i as usize;
            ctx.args.get(idx).map(|a| vec![a.clone()])
        }
        Observable::HasArg => Some(ctx.args.clone()),
        Observable::NamedArg(name) => ctx
            .tool_input
            .get(name)
            .and_then(|v| v.as_str())
            .map(|s| vec![s.to_string()]),
        Observable::NestedField(path) => {
            let mut current = &ctx.tool_input;
            for segment in path {
                current = current.get(segment)?;
            }
            current.as_str().map(|s| vec![s.to_string()])
        }
        Observable::FsOp => ctx.fs_op.clone().map(|op| vec![op]),
        Observable::FsPath => ctx.fs_path.clone().map(|p| vec![p]),
        Observable::NetDomain => ctx.net_domain.clone().map(|d| vec![d]),
    }
}

/// Check if an observable+pattern matches (mirrors matches_observable).
fn matches_observable_check(
    obs: &Observable,
    pattern: &Pattern,
    terminal: bool,
    ctx: &QueryContext,
    values: &Option<Vec<String>>,
) -> bool {
    match obs {
        Observable::HasArg => ctx.args.iter().any(|arg| pattern.matches(arg)),
        Observable::PositionalArg(i) if terminal => {
            let idx = *i as usize;
            match ctx.args.get(idx) {
                Some(val) if pattern.matches(val) => ctx.args.len() == idx + 1,
                _ => false,
            }
        }
        _ => {
            if let Some(vals) = values {
                vals.iter().any(|v| pattern.matches(v))
            } else {
                matches!(pattern, Pattern::Wildcard)
            }
        }
    }
}

/// Return a human-readable description of the pattern type.
fn pattern_kind(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Wildcard => "wildcard".to_string(),
        Pattern::Literal(_) => "literal".to_string(),
        Pattern::Regex(_) => "regex".to_string(),
        Pattern::AnyOf(_) => "any-of".to_string(),
        Pattern::Not(_) => "negation".to_string(),
        Pattern::Prefix(_) => "prefix".to_string(),
    }
}

/// Build a compact description of a root-level rule branch.
fn build_rule_description(node: &Node) -> String {
    let mut parts = Vec::new();
    collect_rule_path(node, &mut parts);
    parts.join(" + ")
}

fn collect_rule_path(node: &Node, parts: &mut Vec<String>) {
    match node {
        Node::Decision(d) => {
            let effect = crate::policy::format::format_decision(d);
            parts.push(format!(".{effect}()"));
        }
        Node::Condition {
            observe,
            pattern,
            children,
            ..
        } => {
            parts.push(format_condition(observe, pattern));
            if children.len() == 1 {
                collect_rule_path(&children[0], parts);
            } else if !children.is_empty() {
                // For branches with multiple children, just note the first leaf effect
                if let Some(d) = find_first_decision(children) {
                    let effect = crate::policy::format::format_decision(&d);
                    parts.push(format!(".{effect}()"));
                }
            }
        }
    }
}

fn find_first_decision(nodes: &[Node]) -> Option<Decision> {
    for node in nodes {
        match node {
            Node::Decision(d) => return Some(d.clone()),
            Node::Condition { children, .. } => {
                if let Some(d) = find_first_decision(children) {
                    return Some(d);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render a PolicyTrace as styled, tree-formatted lines for terminal output.
pub fn render_trace(trace: &PolicyTrace) -> Vec<String> {
    let mut lines = Vec::new();

    lines.push(style::header("Policy evaluation trace:").to_string());

    let default_label = format!("default: {}", trace.default_effect);

    // Policy header
    lines.push(format!(
        "  {} User policy {}",
        style::cyan("\u{250c}"),
        style::dim(&format!("({})", default_label))
    ));

    let branch_count = trace.branches.len();
    for (bi, branch) in trace.branches.iter().enumerate() {
        let is_last_branch = bi == branch_count - 1;
        let pipe = style::cyan("\u{2502}");

        // Rule header
        let source_suffix = branch
            .source
            .as_deref()
            .map(|s| format!("  {}", style::dim(&format!("[{}]", s))))
            .unwrap_or_default();

        lines.push(format!(
            "  {pipe}  Rule {}: {}{}",
            branch.rule_index,
            style::bold(&branch.description),
            source_suffix,
        ));

        // Condition details
        for cond in &branch.conditions {
            if branch.skipped_by_prior {
                lines.push(format!(
                    "  {pipe}    {} {}",
                    style::dim("\u{2298}"),
                    style::dim("skipped (prior rule already matched)"),
                ));
                break;
            }

            let (symbol, detail) = if cond.matched {
                let value_str = cond
                    .tested_value
                    .as_deref()
                    .map(|v| format!(" matches \"{}\"", v))
                    .unwrap_or_default();
                (
                    style::green("\u{2713}"),
                    format!(
                        "{}{} ({})",
                        style::green(&cond.label),
                        value_str,
                        cond.match_kind
                    ),
                )
            } else {
                let value_str = cond
                    .tested_value
                    .as_deref()
                    .map(|v| format!(" (got \"{}\")", v))
                    .unwrap_or_else(|| " (absent)".to_string());
                (
                    style::red("\u{2717}"),
                    format!(
                        "{} does not match{}",
                        style::red(&cond.label),
                        value_str
                    ),
                )
            };
            lines.push(format!("  {pipe}    {symbol} {detail}"));
        }

        // Decision line
        if branch.is_winner {
            if let Some(ref decision) = branch.decision {
                let effect = decision.effect();
                let effect_str = style::effect(&effect.to_string()).to_uppercase();
                lines.push(format!(
                    "  {pipe}    {} {} {} matched",
                    style::yellow("\u{2192}"),
                    effect_str,
                    style::yellow("\u{2190}"),
                ));
            }
        } else if branch.skipped_by_prior {
            // Already noted in condition loop
        } else if branch.conditions.iter().any(|c| !c.matched) {
            // Rule didn't match — already shown via red X conditions
        }

        if !is_last_branch {
            lines.push(format!("  {pipe}"));
        }
    }

    // Footer: result
    let result_effect = style::effect(&trace.final_resolution);
    lines.push(format!(
        "  {} Result: {}",
        style::cyan("\u{2514}"),
        style::bold(&result_effect),
    ));

    lines
}

/// Format a PolicyTrace as a JSON value.
pub fn trace_to_json(trace: &PolicyTrace) -> serde_json::Value {
    let branches: Vec<serde_json::Value> = trace
        .branches
        .iter()
        .map(|b| {
            let conditions: Vec<serde_json::Value> = b
                .conditions
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "label": c.label,
                        "matched": c.matched,
                        "tested_value": c.tested_value,
                        "match_kind": c.match_kind,
                    })
                })
                .collect();
            serde_json::json!({
                "rule_index": b.rule_index,
                "description": b.description,
                "conditions": conditions,
                "decision": b.decision.as_ref().map(|d| format!("{}", d.effect())),
                "is_winner": b.is_winner,
                "skipped_by_prior": b.skipped_by_prior,
            })
        })
        .collect();

    serde_json::json!({
        "branches": branches,
        "default_effect": format!("{}", trace.default_effect),
        "final_effect": format!("{}", trace.final_effect),
        "resolution": trace.final_resolution,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::match_tree::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_policy(tree: Vec<Node>) -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: HashMap::new(),
            tree,
            default_effect: Effect::Ask,
            default_sandbox: None,
        }
    }

    fn make_ctx(tool: &str, input: &serde_json::Value) -> QueryContext {
        QueryContext::from_tool(tool, input)
    }

    #[test]
    fn test_trace_simple_match() {
        // Rule: tool="Bash" + arg[0]="git" -> deny
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::PositionalArg(0),
                pattern: Pattern::Literal(Value::Literal("git".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }]);

        let input = serde_json::json!({"command": "git push"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);

        assert_eq!(trace.branches.len(), 1);
        assert!(trace.branches[0].is_winner);
        assert_eq!(trace.final_effect, Effect::Deny);
        assert_eq!(trace.branches[0].conditions.len(), 2);
        assert!(trace.branches[0].conditions[0].matched);
        assert!(trace.branches[0].conditions[1].matched);
    }

    #[test]
    fn test_trace_no_match_falls_to_default() {
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Read".into())),
            children: vec![Node::Decision(Decision::Deny)],
            doc: None,
            source: None,
            terminal: false,
        }]);

        let input = serde_json::json!({"command": "ls"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);

        assert_eq!(trace.branches.len(), 1);
        assert!(!trace.branches[0].is_winner);
        assert_eq!(trace.final_effect, Effect::Ask);
        assert!(trace.final_resolution.contains("no rules matched"));
    }

    #[test]
    fn test_trace_second_rule_skipped_by_prior() {
        // Rule 1: tool="Bash" -> deny
        // Rule 2: tool="Bash" -> allow
        let policy = make_policy(vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            },
        ]);

        let input = serde_json::json!({"command": "ls"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);

        assert_eq!(trace.branches.len(), 2);
        assert!(trace.branches[0].is_winner);
        assert!(trace.branches[1].skipped_by_prior);
        assert_eq!(trace.final_effect, Effect::Deny);
    }

    #[test]
    fn test_trace_render_produces_output() {
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }]);

        let input = serde_json::json!({"command": "ls"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);
        let lines = render_trace(&trace);

        assert!(!lines.is_empty());
        // Should contain the header
        assert!(lines.iter().any(|l| l.contains("Policy evaluation trace")));
        // Should contain Result
        assert!(lines.iter().any(|l| l.contains("Result")));
    }

    #[test]
    fn test_trace_json_output() {
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Decision(Decision::Deny)],
            doc: None,
            source: None,
            terminal: false,
        }]);

        let input = serde_json::json!({"command": "git push"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);
        let json = trace_to_json(&trace);

        assert_eq!(json["final_effect"], "deny");
        assert_eq!(json["branches"][0]["is_winner"], true);
        assert_eq!(json["branches"][0]["conditions"][0]["matched"], true);
    }

    #[test]
    fn test_trace_wildcard_pattern() {
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Wildcard,
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }]);

        let input = serde_json::json!({"command": "anything"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);

        assert!(trace.branches[0].is_winner);
        assert_eq!(trace.branches[0].conditions[0].match_kind, "wildcard");
    }

    #[test]
    fn test_trace_regex_pattern() {
        let re = regex::Regex::new("^git$").unwrap();
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Regex(Arc::new(re)),
            children: vec![Node::Decision(Decision::Deny)],
            doc: None,
            source: None,
            terminal: false,
        }]);

        let input = serde_json::json!({});
        let ctx = make_ctx("git", &input);
        let trace = build_trace(&policy, &ctx);

        assert!(trace.branches[0].conditions[0].matched);
        assert_eq!(trace.branches[0].conditions[0].match_kind, "regex");
    }

    #[test]
    fn test_trace_partial_match_shows_failure_point() {
        // Rule: tool="Bash" + arg[0]="git" + arg[1]="push" -> deny
        let policy = make_policy(vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::PositionalArg(0),
                pattern: Pattern::Literal(Value::Literal("git".into())),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(1),
                    pattern: Pattern::Literal(Value::Literal("push".into())),
                    children: vec![Node::Decision(Decision::Deny)],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }]);

        // "git pull" instead of "git push"
        let input = serde_json::json!({"command": "git pull"});
        let ctx = make_ctx("Bash", &input);
        let trace = build_trace(&policy, &ctx);

        assert!(!trace.branches[0].is_winner);
        // First two conditions match, third doesn't
        assert!(trace.branches[0].conditions[0].matched); // tool="Bash"
        assert!(trace.branches[0].conditions[1].matched); // arg[0]="git"
        assert!(!trace.branches[0].conditions[2].matched); // arg[1]="push" fails
    }
}
