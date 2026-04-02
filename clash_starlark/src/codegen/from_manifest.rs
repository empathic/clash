//! Convert a compiled policy manifest back into Starlark AST.
//!
//! Used to sync manifest mutations (from the TUI) back into a StarDocument's
//! AST. Preserves the document's load statements and comments; replaces only
//! the policy rules, sandboxes, and settings.

use super::ast::{DictEntry, Expr, Stmt};
use super::builder;
use super::mutate;

/// Replace the policy rules, sandboxes, and settings in the AST with values
/// derived from the manifest JSON structures.
///
/// Preserves load statements, comments, blank lines, and other non-policy
/// statements. Only the `settings()` call, `sandbox()` statements, and
/// `policy()` call's `rules` and `default` kwargs are replaced.
pub fn sync_manifest_to_ast(
    stmts: &mut Vec<Stmt>,
    tree: &[serde_json::Value],
    sandboxes: &serde_json::Map<String, serde_json::Value>,
    default_effect: &str,
    default_sandbox: Option<&str>,
) {
    // 1. Update settings
    let effect = match default_effect {
        "allow" => mutate::Effect::Allow,
        "deny" => mutate::Effect::Deny,
        _ => mutate::Effect::Ask,
    };
    let _ = mutate::set_default_effect(stmts, effect);
    let _ = mutate::set_default_sandbox(stmts, default_sandbox);

    // 2. Remove existing sandbox statements and rebuild from manifest
    let existing_sandboxes = mutate::find_sandboxes(stmts);
    // Remove in reverse order to preserve indices
    for (idx, _) in existing_sandboxes.iter().rev() {
        stmts.remove(*idx);
        // Clean up trailing blank line
        if *idx < stmts.len() && matches!(stmts.get(*idx), Some(Stmt::Blank)) {
            stmts.remove(*idx);
        }
    }
    // Re-add sandboxes from manifest
    for (name, sb_value) in sandboxes {
        let expr = sandbox_json_to_expr(name, sb_value);
        let stmt = Stmt::Expr(expr);
        let insert_at = mutate::find_settings_call(stmts)
            .or_else(|| mutate::find_policy_call(stmts))
            .unwrap_or(stmts.len());
        if insert_at > 0 && !matches!(stmts.get(insert_at - 1), Some(Stmt::Blank)) {
            stmts.insert(insert_at, Stmt::Blank);
            stmts.insert(insert_at + 1, stmt);
        } else {
            stmts.insert(insert_at, stmt);
        }
        mutate::ensure_loaded(stmts, "sandbox");
    }

    // 3. Replace policy rules
    if let Some(rules) = mutate::policy_rules_mut(stmts) {
        *rules = tree.iter().map(node_json_to_expr).collect();
    }
}

/// Convert a single manifest tree node (as JSON) to a Starlark AST expression.
pub fn node_json_to_expr(node: &serde_json::Value) -> Expr {
    match node.get("condition") {
        Some(cond) => condition_to_expr(cond),
        None => {
            // Decision node
            if let Some(decision) = node.get("decision") {
                decision_to_effect_expr(decision)
            } else {
                Expr::raw(format!("# unknown node: {node}"))
            }
        }
    }
}

/// Convert a condition node to a Starlark expression.
///
/// Tries to reconstruct the most natural Starlark form:
/// - ToolName conditions → `when({"Name": effect()})` or `when({...})`
/// - PositionalArg chains → nested match dicts
fn condition_to_expr(cond: &serde_json::Value) -> Expr {
    let observe = cond
        .get("observe")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let children = cond
        .get("children")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    match observe {
        "tool_name" => {
            // Always use when({...}) dict syntax for tool rules
            let pattern = &cond["pattern"];
            let key = pattern_to_expr(pattern);
            let value = children_to_expr(&children);
            Expr::call("when", vec![Expr::dict(vec![DictEntry::new(key, value)])])
        }
        "positional_arg" => {
            let pattern = &cond["pattern"];
            let key = pattern_to_expr(pattern);
            let value = children_to_expr(&children);
            Expr::dict(vec![DictEntry::new(key, value)])
        }
        "has_arg" => {
            let pattern = &cond["pattern"];
            let key = pattern_to_expr(pattern);
            let value = children_to_expr(&children);
            Expr::dict(vec![DictEntry::new(key, value)])
        }
        _ => {
            // For other observables, emit as raw JSON comment
            Expr::raw(format!(
                "# {observe} rule (imported from JSON)",
            ))
        }
    }
}

/// Convert children nodes to an expression.
/// If there's a single decision child, return the effect expression.
/// If there are multiple condition children, return a nested dict.
fn children_to_expr(children: &[serde_json::Value]) -> Expr {
    if children.len() == 1 {
        if children[0].get("decision").is_some() {
            return decision_to_effect_expr(&children[0]["decision"]);
        }
        return node_json_to_expr(&children[0]);
    }

    // Multiple children → dict entries
    let entries: Vec<DictEntry> = children
        .iter()
        .filter_map(|child| {
            if let Some(cond) = child.get("condition") {
                let pattern = &cond["pattern"];
                let key = pattern_to_expr(pattern);
                let inner_children = cond
                    .get("children")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let value = children_to_expr(&inner_children);
                Some(DictEntry::new(key, value))
            } else if let Some(decision) = child.get("decision") {
                // Bare decision as a dict entry — shouldn't normally happen
                Some(DictEntry::new(
                    Expr::string("*"),
                    decision_to_effect_expr(decision),
                ))
            } else {
                None
            }
        })
        .collect();
    Expr::dict(entries)
}

/// Convert a Pattern JSON value to a dict key expression.
///
/// Pattern serializes as: `{"literal": <Value>}`, `{"any_of": [...]}`, `{"regex": "..."}`, `"wildcard"`.
/// Value serializes as: `{"literal": "string"}`, `{"env": "VAR"}`, `{"path": [...]}`.
fn pattern_to_expr(pattern: &serde_json::Value) -> Expr {
    if let Some(literal) = pattern.get("literal") {
        return value_to_expr(literal);
    }
    if let Some(any_of) = pattern.get("any_of") {
        if let Some(arr) = any_of.as_array() {
            let items: Vec<Expr> = arr.iter().map(pattern_to_expr).collect();
            if items.len() == 1 {
                return items.into_iter().next().unwrap();
            }
            return Expr::tuple(items);
        }
    }
    if let Some(regex) = pattern.get("regex") {
        if let Some(s) = regex.as_str() {
            return Expr::call("regex", vec![Expr::string(s)]);
        }
    }
    if pattern == "wildcard" || pattern.get("wildcard").is_some() {
        return Expr::string("*");
    }
    Expr::raw(format!("{pattern}"))
}

/// Convert a Value JSON to an expression.
///
/// Value serializes as: `{"literal": "string"}`, `{"env": "VAR"}`, `{"path": [...]}`.
fn value_to_expr(value: &serde_json::Value) -> Expr {
    // Direct string (shouldn't happen in normal serde, but handle gracefully)
    if let Some(s) = value.as_str() {
        return Expr::string(s);
    }
    if let Some(obj) = value.as_object() {
        if let Some(s) = obj.get("literal").and_then(|v| v.as_str()) {
            return Expr::string(s);
        }
        if let Some(env) = obj.get("env").and_then(|v| v.as_str()) {
            return Expr::raw(format!("${env}"));
        }
    }
    Expr::raw(format!("{value}"))
}

/// Convert a Decision JSON to an effect expression (for use as dict values).
fn decision_to_effect_expr(decision: &serde_json::Value) -> Expr {
    if let Some(allow) = decision.get("allow") {
        if let Some(sb) = allow.as_object().and_then(|o| o.get("0")).and_then(|v| v.as_str()) {
            return builder::allow_with_sandbox(Expr::string(sb));
        }
        return builder::allow();
    }
    if decision == "deny" || decision.get("deny").is_some() {
        return builder::deny();
    }
    if let Some(ask) = decision.get("ask") {
        if let Some(sb) = ask.as_object().and_then(|o| o.get("0")).and_then(|v| v.as_str()) {
            return builder::ask_with_sandbox(Expr::string(sb));
        }
        return builder::ask();
    }
    builder::ask()
}

/// Convert a sandbox JSON value to a `sandbox(name = "...", ...)` expression.
pub fn sandbox_json_to_expr(name: &str, sb: &serde_json::Value) -> Expr {
    let mut kwargs: Vec<(&str, Expr)> = vec![];

    // default caps
    if let Some(default) = sb.get("default") {
        if let Some(caps) = default.as_object() {
            let deny_all = caps.values().all(|v| v == false);
            if deny_all {
                kwargs.push(("default", builder::deny()));
            } else {
                kwargs.push(("default", builder::allow()));
            }
        }
    }

    // network
    if let Some(network) = sb.get("network").and_then(|v| v.as_str()) {
        match network {
            "allow" => kwargs.push(("net", builder::allow())),
            "deny" => kwargs.push(("net", builder::deny())),
            "localhost" => kwargs.push(("net", Expr::call("localhost", vec![]))),
            _ => {}
        }
    }

    builder::sandbox(name, kwargs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::parser::parse;
    use crate::codegen::serialize::serialize;

    #[test]
    fn sync_updates_rules() {
        let src = r#"load("@clash//std.star", "when", "policy", "settings", "allow", "deny")

# My policy comment
settings(default = deny())

policy("test", default = deny(), rules = [when({"Read": allow()})])
"#;
        let mut stmts = parse(src).unwrap();

        // Simulate a manifest with different rules
        let tree_json: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
                {"condition": {"observe": "tool_name", "pattern": {"literal": "Write"}, "children": [{"decision": {"allow": null}}]}}
            ]"#,
        ).unwrap();
        let sandboxes: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

        sync_manifest_to_ast(&mut stmts, &tree_json, &sandboxes, "ask", None);

        let result = serialize(&stmts);
        // Comment should be preserved
        assert!(result.contains("# My policy comment"), "got:\n{result}");
        // Rules should be updated
        assert!(result.contains("Write"), "got:\n{result}");
        assert!(!result.contains("Read"), "got:\n{result}");
        // Default should be updated
        assert!(result.contains("settings(default = ask())"), "got:\n{result}");
    }

    #[test]
    fn sync_preserves_load_statements() {
        let src = r#"load("@clash//std.star", "when", "policy", "settings", "allow", "deny")
load("./custom.star", "my_rules")

settings(default = deny())

policy("test", default = deny(), rules = [when({"Read": allow()})])
"#;
        let mut stmts = parse(src).unwrap();
        let tree_json: Vec<serde_json::Value> = vec![];
        let sandboxes = serde_json::Map::new();

        sync_manifest_to_ast(&mut stmts, &tree_json, &sandboxes, "deny", None);

        let result = serialize(&stmts);
        assert!(result.contains("custom.star"), "custom load preserved:\n{result}");
    }

    #[test]
    fn sync_tool_rule_with_sandbox() {
        let src = r#"load("@clash//std.star", "policy", "settings", "deny")

settings(default = deny())

policy("test", default = deny(), rules = [])
"#;
        let mut stmts = parse(src).unwrap();

        let tree_json: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
                {"condition": {"observe": "tool_name", "pattern": {"literal": "Bash"}, "children": [{"decision": {"allow": {"0": "dev"}}}]}}
            ]"#,
        ).unwrap();
        let sandboxes = serde_json::Map::new();

        sync_manifest_to_ast(&mut stmts, &tree_json, &sandboxes, "deny", None);

        let result = serialize(&stmts);
        assert!(result.contains("\"Bash\": allow(sandbox = \"dev\")"), "got:\n{result}");
    }

    #[test]
    fn sync_match_rule_nested() {
        let src = r#"load("@clash//std.star", "policy", "settings", "deny")

settings(default = deny())

policy("test", default = deny(), rules = [])
"#;
        let mut stmts = parse(src).unwrap();

        let tree_json: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
                {"condition": {"observe": "tool_name", "pattern": {"literal": "Bash"}, "children": [
                    {"condition": {"observe": "positional_arg", "pattern": {"literal": "git"}, "children": [
                        {"decision": {"allow": null}}
                    ]}}
                ]}}
            ]"#,
        ).unwrap();
        let sandboxes = serde_json::Map::new();

        sync_manifest_to_ast(&mut stmts, &tree_json, &sandboxes, "deny", None);

        let result = serialize(&stmts);
        assert!(result.contains("when("), "got:\n{result}");
        assert!(result.contains("\"Bash\""), "got:\n{result}");
        assert!(result.contains("\"git\""), "got:\n{result}");
    }
}
