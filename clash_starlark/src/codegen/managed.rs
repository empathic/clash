//! Managed section operations for CLI-driven rule mutations.
//!
//! Rules added by `clash policy allow/deny` are placed in a "managed section"
//! of the `.star` file, marked by a comment sentinel. Each managed rule is a
//! variable assignment (`_clash_rule_N = {Tool("Bash"): {...}}`) referenced as
//! an argument in the `policy()` call's `merge()` expression.
//!
//! This makes CLI-added rules easy to identify, upsert, and remove without
//! disturbing hand-written rules.

use super::ast::{DictEntry, Expr, Stmt};
use super::builder;
use super::mutate;

/// Comment sentinel marking the start of the managed section.
const MANAGED_COMMENT: &str = "clash-managed rules";

/// Prefix for managed rule variable names.
const MANAGED_PREFIX: &str = "_clash_rule_";

/// Result of a managed upsert operation.
#[derive(Debug, PartialEq, Eq)]
pub enum ManagedUpsertResult {
    /// A new managed rule was added.
    Inserted,
    /// An existing managed rule was replaced.
    Replaced,
}

/// Add or replace a managed exec rule in a `.star` AST.
///
/// If a managed rule with the same binary and args already exists, its effect
/// is replaced. Otherwise a new managed variable is created.
pub fn upsert_exec_rule(
    stmts: &mut Vec<Stmt>,
    binary: &str,
    args: &[&str],
    effect: mutate::Effect,
    sandbox: Option<&str>,
) -> Result<ManagedUpsertResult, String> {
    let new_expr = build_exec_dict_expr(binary, args, effect, sandbox);

    // Look for an existing managed rule with the same match key
    let match_key = exec_match_key(binary, args);
    if let Some((var_name, stmt_idx)) = find_managed_by_key(stmts, &match_key) {
        // Replace the existing assignment's value
        if let Some(Stmt::Assign { value, .. }) = stmts.get_mut(stmt_idx) {
            *value = new_expr;
        }
        // Variable is already referenced in policy() rules, so we're done
        let _ = var_name; // used for identification only
        return Ok(ManagedUpsertResult::Replaced);
    }

    // Insert new managed rule
    let var_name = next_managed_var(stmts);
    insert_managed_rule(stmts, &var_name, new_expr, &match_key)?;
    Ok(ManagedUpsertResult::Inserted)
}

/// Add or replace a managed tool rule in a `.star` AST.
pub fn upsert_tool_rule(
    stmts: &mut Vec<Stmt>,
    tool_name: &str,
    effect: mutate::Effect,
    sandbox: Option<&str>,
) -> Result<ManagedUpsertResult, String> {
    let effect_expr = build_effect_expr(effect, sandbox);
    let new_expr = Expr::dict(vec![DictEntry::new(
        Expr::call("Tool", vec![Expr::string(tool_name)]),
        effect_expr,
    )]);

    let match_key = tool_match_key(tool_name);
    if let Some((_var_name, stmt_idx)) = find_managed_by_key(stmts, &match_key) {
        if let Some(Stmt::Assign { value, .. }) = stmts.get_mut(stmt_idx) {
            *value = new_expr;
        }
        return Ok(ManagedUpsertResult::Replaced);
    }

    let var_name = next_managed_var(stmts);
    insert_managed_rule(stmts, &var_name, new_expr, &match_key)?;
    Ok(ManagedUpsertResult::Inserted)
}

/// Remove a managed exec rule by binary and args.
///
/// Returns `true` if a rule was found and removed.
pub fn remove_exec_rule(stmts: &mut Vec<Stmt>, binary: &str, args: &[&str]) -> bool {
    let match_key = exec_match_key(binary, args);
    remove_managed_by_key(stmts, &match_key)
}

/// Remove a managed tool rule by tool name.
///
/// Returns `true` if a rule was found and removed.
pub fn remove_tool_rule(stmts: &mut Vec<Stmt>, tool_name: &str) -> bool {
    let match_key = tool_match_key(tool_name);
    remove_managed_by_key(stmts, &match_key)
}

// ---------------------------------------------------------------------------
// Match keys — used to identify rules for upsert/remove
// ---------------------------------------------------------------------------

/// A string key that uniquely identifies a managed rule's match condition.
/// For exec rules: "exec:binary:arg1:arg2"
/// For tool rules: "tool:ToolName"
fn exec_match_key(binary: &str, args: &[&str]) -> String {
    let mut key = format!("exec:{binary}");
    for arg in args {
        key.push(':');
        key.push_str(arg);
    }
    key
}

fn tool_match_key(tool_name: &str) -> String {
    format!("tool:{tool_name}")
}

/// Extract a match key from a managed rule's comment.
/// Managed comments have the format: `clash-managed:key`
fn comment_match_key(comment: &str) -> Option<&str> {
    comment.strip_prefix("clash-managed:")
}

// ---------------------------------------------------------------------------
// Managed section manipulation
// ---------------------------------------------------------------------------

/// Find a managed rule assignment by its match key.
/// Returns `(variable_name, stmt_index)` if found.
fn find_managed_by_key(stmts: &[Stmt], match_key: &str) -> Option<(String, usize)> {
    for (i, stmt) in stmts.iter().enumerate() {
        if let Stmt::Comment(text) = stmt {
            if let Some(key) = comment_match_key(text) {
                if key == match_key {
                    // The assignment should be right after the comment
                    if let Some(Stmt::Assign { target, .. }) = stmts.get(i + 1) {
                        return Some((target.clone(), i + 1));
                    }
                }
            }
        }
    }
    None
}

/// Remove a managed rule by its match key.
/// Removes the comment, the assignment, and the reference in policy merge() args.
fn remove_managed_by_key(stmts: &mut Vec<Stmt>, match_key: &str) -> bool {
    // Find the comment + assignment pair
    let found = find_managed_by_key(stmts, match_key);
    let Some((var_name, assign_idx)) = found else {
        return false;
    };
    let comment_idx = assign_idx - 1;

    // Remove the reference from policy() merge() args
    if let Some(merge_args) = mutate::policy_merge_args_mut(stmts) {
        merge_args.retain(|expr| !is_ident_ref(expr, &var_name));
    }

    // Remove the assignment and comment (remove in reverse order to preserve indices)
    stmts.remove(assign_idx);
    stmts.remove(comment_idx);

    true
}

/// Insert a new managed rule: comment + assignment + add reference to policy merge() args.
fn insert_managed_rule(
    stmts: &mut Vec<Stmt>,
    var_name: &str,
    expr: Expr,
    match_key: &str,
) -> Result<(), String> {
    // Find or create managed section
    let insert_at = find_managed_section_end(stmts);

    // Insert comment and assignment
    stmts.insert(insert_at, Stmt::Comment(format!("clash-managed:{match_key}")));
    stmts.insert(insert_at + 1, Stmt::Assign {
        target: var_name.to_string(),
        value: expr,
    });

    // Add reference as last argument to policy() merge() call
    let merge_args = mutate::policy_merge_args_mut(stmts)
        .ok_or_else(|| "no policy() call with merge() found".to_string())?;
    merge_args.push(Expr::ident(var_name));

    Ok(())
}

/// Find the end of the managed section (insertion point for new managed rules).
/// If no managed section exists yet, returns the index just before the policy() call
/// and inserts the section header comment.
fn find_managed_section_end(stmts: &mut Vec<Stmt>) -> usize {
    // Look for the last managed assignment
    let mut last_managed_end = None;
    for (i, stmt) in stmts.iter().enumerate() {
        if let Stmt::Comment(text) = stmt {
            if text == MANAGED_COMMENT || comment_match_key(text).is_some() {
                // Track the end: comment + assignment = i + 2
                last_managed_end = Some(i + 2);
            }
        }
    }

    if let Some(end) = last_managed_end {
        return end.min(stmts.len());
    }

    // No managed section yet — create one before policy()
    let insert_at = mutate::find_policy_call(stmts)
        .unwrap_or(stmts.len());

    // Add the section header
    stmts.insert(insert_at, Stmt::Comment(MANAGED_COMMENT.to_string()));
    stmts.insert(insert_at + 1, Stmt::Blank);

    insert_at + 2
}

/// Generate the next available managed variable name.
fn next_managed_var(stmts: &[Stmt]) -> String {
    let mut max_n = -1i64;
    for stmt in stmts {
        if let Stmt::Assign { target, .. } = stmt {
            if let Some(rest) = target.strip_prefix(MANAGED_PREFIX) {
                if let Ok(n) = rest.parse::<i64>() {
                    max_n = max_n.max(n);
                }
            }
        }
    }
    format!("{MANAGED_PREFIX}{}", max_n + 1)
}

/// Check if an expression is an identifier reference to a specific variable.
fn is_ident_ref(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Ident(n) if n == name)
}

// ---------------------------------------------------------------------------
// Expression builders
// ---------------------------------------------------------------------------

fn build_exec_dict_expr(
    binary: &str,
    args: &[&str],
    effect: mutate::Effect,
    sandbox: Option<&str>,
) -> Expr {
    let effect_expr = build_effect_expr(effect, sandbox);

    // Build nested dict: binary -> arg1 -> arg2 -> ... -> effect
    let mut value = effect_expr;
    for arg in args.iter().rev() {
        value = Expr::dict(vec![DictEntry::new(Expr::string(*arg), value)]);
    }
    Expr::dict(vec![DictEntry::new(
        Expr::call("Tool", vec![Expr::string("Bash")]),
        Expr::dict(vec![DictEntry::new(Expr::string(binary), value)]),
    )])
}

fn build_effect_expr(effect: mutate::Effect, sandbox: Option<&str>) -> Expr {
    match (effect, sandbox) {
        (mutate::Effect::Allow, None) => builder::allow(),
        (mutate::Effect::Allow, Some(sb)) => builder::allow_with_sandbox(Expr::ident(sb)),
        (mutate::Effect::Deny, None) => builder::deny(),
        (mutate::Effect::Deny, Some(sb)) => builder::deny_with_sandbox(Expr::ident(sb)),
        (mutate::Effect::Ask, None) => builder::ask(),
        (mutate::Effect::Ask, Some(sb)) => builder::ask_with_sandbox(Expr::ident(sb)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::parser::parse;
    use crate::codegen::serialize::serialize;

    fn base_stmts() -> Vec<Stmt> {
        parse(r#"load("@clash//claude_compat.star", "from_claude_settings")

policy("test", merge(
    from_claude_settings(),
    {"Read": allow()},
))
"#).unwrap()
    }

    #[test]
    fn upsert_exec_inserts_new_rule() {
        let mut stmts = base_stmts();
        let result =
            upsert_exec_rule(&mut stmts, "git", &["push"], mutate::Effect::Deny, None).unwrap();
        assert_eq!(result, ManagedUpsertResult::Inserted);
        let src = serialize(&stmts);
        assert!(src.contains("_clash_rule_0"), "got:\n{src}");
        assert!(src.contains("\"git\""), "got:\n{src}");
        assert!(src.contains("deny()"), "got:\n{src}");
        assert!(
            src.contains("clash-managed:exec:git:push"),
            "got:\n{src}"
        );
    }

    #[test]
    fn upsert_exec_replaces_existing() {
        let mut stmts = base_stmts();
        upsert_exec_rule(&mut stmts, "git", &[], mutate::Effect::Allow, None).unwrap();
        let result =
            upsert_exec_rule(&mut stmts, "git", &[], mutate::Effect::Deny, None).unwrap();
        assert_eq!(result, ManagedUpsertResult::Replaced);
        let src = serialize(&stmts);
        // Only one managed rule should exist
        assert_eq!(src.matches("_clash_rule_0").count(), 2, "got:\n{src}"); // assignment + reference
        assert!(src.contains("deny()"), "got:\n{src}");
    }

    #[test]
    fn upsert_tool_inserts() {
        let mut stmts = base_stmts();
        let result =
            upsert_tool_rule(&mut stmts, "Write", mutate::Effect::Allow, None).unwrap();
        assert_eq!(result, ManagedUpsertResult::Inserted);
        let src = serialize(&stmts);
        assert!(src.contains("Tool(\"Write\"): allow()"), "got:\n{src}");
    }

    #[test]
    fn remove_exec_rule_works() {
        let mut stmts = base_stmts();
        upsert_exec_rule(&mut stmts, "git", &["push"], mutate::Effect::Deny, None).unwrap();
        let removed = remove_exec_rule(&mut stmts, "git", &["push"]);
        assert!(removed);
        let src = serialize(&stmts);
        assert!(!src.contains("_clash_rule_"), "got:\n{src}");
        assert!(!src.contains("clash-managed:exec"), "got:\n{src}");
    }

    #[test]
    fn remove_tool_rule_works() {
        let mut stmts = base_stmts();
        upsert_tool_rule(&mut stmts, "Write", mutate::Effect::Allow, None).unwrap();
        let removed = remove_tool_rule(&mut stmts, "Write");
        assert!(removed);
        let src = serialize(&stmts);
        assert!(!src.contains("_clash_rule_"), "got:\n{src}");
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut stmts = base_stmts();
        assert!(!remove_exec_rule(&mut stmts, "git", &["push"]));
        assert!(!remove_tool_rule(&mut stmts, "Write"));
    }

    #[test]
    fn multiple_managed_rules_coexist() {
        let mut stmts = base_stmts();
        upsert_exec_rule(&mut stmts, "git", &[], mutate::Effect::Allow, None).unwrap();
        upsert_exec_rule(&mut stmts, "cargo", &["build"], mutate::Effect::Allow, None).unwrap();
        upsert_tool_rule(&mut stmts, "Write", mutate::Effect::Deny, None).unwrap();

        let src = serialize(&stmts);
        assert!(src.contains("_clash_rule_0"), "got:\n{src}");
        assert!(src.contains("_clash_rule_1"), "got:\n{src}");
        assert!(src.contains("_clash_rule_2"), "got:\n{src}");
    }

    #[test]
    fn managed_rules_evaluate_correctly() {
        let mut stmts = base_stmts();
        upsert_exec_rule(&mut stmts, "git", &[], mutate::Effect::Allow, None).unwrap();
        upsert_tool_rule(&mut stmts, "Write", mutate::Effect::Deny, None).unwrap();

        let src = serialize(&stmts);
        let result = crate::evaluate(&src, "test.star", &std::path::PathBuf::from("."));
        assert!(
            result.is_ok(),
            "eval failed: {:?}\nsource:\n{src}",
            result.err()
        );
    }
}
