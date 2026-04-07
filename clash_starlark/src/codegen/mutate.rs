//! AST mutation operations for Starlark policy files.
//!
//! These functions operate on `Vec<Stmt>` to add, remove, and modify policy
//! rules, sandboxes, and settings — mirroring the TUI's form actions.

use super::ast::{DictEntry, Expr, Stmt};
use super::builder;

/// The effect to apply to a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

// ---------------------------------------------------------------------------
// Finders — locate structural elements in the AST
// ---------------------------------------------------------------------------

/// Find the index of the `policy(...)` call statement.
pub fn find_policy_call(stmts: &[Stmt]) -> Option<usize> {
    stmts.iter().position(|s| match s {
        Stmt::Expr(Expr::Call { func, .. }) => is_ident(func, "policy"),
        _ => false,
    })
}

/// Find the index of the `settings(...)` call statement.
pub fn find_settings_call(stmts: &[Stmt]) -> Option<usize> {
    stmts.iter().position(|s| match s {
        Stmt::Expr(Expr::Call { func, .. }) => is_ident(func, "settings"),
        _ => false,
    })
}

/// Find the index of the `load("@clash//std.star", ...)` statement.
pub fn find_std_load(stmts: &[Stmt]) -> Option<usize> {
    stmts
        .iter()
        .position(|s| matches!(s, Stmt::Load { module, .. } if module.contains("@clash//std.star")))
}

/// Find all `sandbox(...)` calls — either top-level expressions or assignments.
/// Returns `(stmt_index, sandbox_name)` pairs.
pub fn find_sandboxes(stmts: &[Stmt]) -> Vec<(usize, String)> {
    stmts
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            let call = match s {
                Stmt::Expr(expr) => Some(expr),
                Stmt::Assign { value, .. } => Some(value),
                _ => None,
            }?;
            if let Expr::Call { func, kwargs, .. } = call {
                if is_ident(func, "sandbox") {
                    let name = kwargs.iter().find_map(|(k, v)| {
                        if k == "name" {
                            if let Expr::String(s) = v {
                                Some(s.clone())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })?;
                    return Some((i, name));
                }
            }
            None
        })
        .collect()
}

/// Find the `fs = {...}` kwarg dict in a sandbox() call by name.
fn find_sandbox_fs_mut<'a>(stmts: &'a mut [Stmt], name: &str) -> Option<&'a mut Vec<DictEntry>> {
    let sandboxes = find_sandboxes(stmts);
    let (idx, _) = sandboxes.iter().find(|(_, n)| n == name)?;
    let idx = *idx;

    let call = match &mut stmts[idx] {
        Stmt::Expr(expr) => expr,
        Stmt::Assign { value, .. } => value,
        _ => return None,
    };

    if let Expr::Call { kwargs, .. } = call {
        for (key, value) in kwargs.iter_mut() {
            if key == "fs" {
                if let Expr::Dict(entries) = value {
                    return Some(entries);
                }
            }
        }
    }
    None
}

/// Get a mutable reference to the kwargs of a sandbox() call by name.
fn find_sandbox_kwargs_mut<'a>(
    stmts: &'a mut [Stmt],
    name: &str,
) -> Option<&'a mut Vec<(String, Expr)>> {
    let sandboxes = find_sandboxes(stmts);
    let (idx, _) = sandboxes.iter().find(|(_, n)| n == name)?;
    let idx = *idx;

    let call = match &mut stmts[idx] {
        Stmt::Expr(expr) => expr,
        Stmt::Assign { value, .. } => value,
        _ => return None,
    };

    if let Expr::Call { kwargs, .. } = call {
        Some(kwargs)
    } else {
        None
    }
}

/// Find the `rules = [...]` kwarg in a `policy()` call and return a mutable
/// reference to the list's items.
pub fn policy_rules_mut(stmts: &mut [Stmt]) -> Option<&mut Vec<Expr>> {
    let idx = find_policy_call(stmts)?;
    if let Stmt::Expr(Expr::Call { kwargs, .. }) = &mut stmts[idx] {
        for (key, value) in kwargs.iter_mut() {
            if key == "rules" {
                if let Expr::List(items) = value {
                    return Some(items);
                }
            }
        }
    }
    None
}

/// Find the `merge(...)` call inside `policy()` and return a mutable reference
/// to its argument list. Expects `policy("name", merge(...))` where `merge` is
/// the second positional argument.
pub fn policy_merge_args_mut(stmts: &mut [Stmt]) -> Option<&mut Vec<Expr>> {
    let policy_idx = find_policy_call(stmts)?;
    if let Stmt::Expr(Expr::Call { args, .. }) = &mut stmts[policy_idx] {
        if args.len() >= 2 {
            if let Expr::Call {
                func,
                args: merge_args,
                ..
            } = &mut args[1]
            {
                if matches!(func.as_ref(), Expr::Ident(n) if n == "merge") {
                    return Some(merge_args);
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Rule mutations
// ---------------------------------------------------------------------------

/// Add a tool rule: `when({"Name": allow()})` or `when({("A", "B"): allow()})`.
pub fn add_tool_rule(
    stmts: &mut Vec<Stmt>,
    tool_names: &[&str],
    effect: Effect,
    sandbox: Option<&str>,
) -> Result<(), String> {
    let effect_expr = build_effect_expr(effect, sandbox);
    let rule = builder::tool_match(tool_names, effect_expr);
    ensure_loaded(stmts, "when");
    append_rule(stmts, rule)
}

/// Add an exec/shell command rule: `when({"Bash": {"cmd": allow()}})`.
///
/// If `args` is non-empty, nests them as further dict levels.
pub fn add_exec_rule(
    stmts: &mut Vec<Stmt>,
    binary: &str,
    args: &[&str],
    effect: Effect,
    sandbox: Option<&str>,
) -> Result<(), String> {
    let effect_expr = build_effect_expr(effect, sandbox);

    // Build nested dict: binary -> arg1 -> arg2 -> ... -> effect
    let mut value = effect_expr;
    for arg in args.iter().rev() {
        value = Expr::dict(vec![DictEntry::new(Expr::string(*arg), value)]);
    }
    let dict = Expr::dict(vec![DictEntry::new(
        Expr::string("Bash"),
        Expr::dict(vec![DictEntry::new(Expr::string(binary), value)]),
    )]);
    let rule = Expr::call("when", vec![dict]);
    ensure_loaded(stmts, "when");
    append_rule(stmts, rule)
}

/// Add a raw Starlark expression as a rule.
pub fn add_raw_rule(stmts: &mut Vec<Stmt>, expr_text: &str) -> Result<(), String> {
    append_rule(stmts, Expr::raw(expr_text))
}

/// Remove a rule by index in the `policy()` rules list.
pub fn remove_rule(stmts: &mut [Stmt], rule_index: usize) -> Result<(), String> {
    let rules = policy_rules_mut(stmts).ok_or("no policy() call with rules= found")?;
    if rule_index >= rules.len() {
        return Err(format!(
            "rule index {rule_index} out of range ({})",
            rules.len()
        ));
    }
    rules.remove(rule_index);
    Ok(())
}

/// Replace a rule at a given index in the `policy()` rules list.
pub fn replace_rule(stmts: &mut [Stmt], rule_index: usize, new_rule: Expr) -> Result<(), String> {
    let rules = policy_rules_mut(stmts).ok_or("no policy() call with rules= found")?;
    if rule_index >= rules.len() {
        return Err(format!(
            "rule index {rule_index} out of range ({})",
            rules.len()
        ));
    }
    rules[rule_index] = new_rule;
    Ok(())
}

// ---------------------------------------------------------------------------
// Settings mutations
// ---------------------------------------------------------------------------

/// Set the default effect in the `settings()` call.
pub fn set_default_effect(stmts: &mut Vec<Stmt>, effect: Effect) -> Result<(), String> {
    let effect_expr = match effect {
        Effect::Allow => builder::allow(),
        Effect::Deny => builder::deny(),
        Effect::Ask => builder::ask(),
    };

    if let Some(idx) = find_settings_call(stmts) {
        if let Stmt::Expr(Expr::Call { kwargs, .. }) = &mut stmts[idx] {
            if let Some((_, val)) = kwargs.iter_mut().find(|(k, _)| k == "default") {
                *val = effect_expr;
            } else {
                kwargs.insert(0, ("default".to_string(), effect_expr));
            }
            return Ok(());
        }
    }
    Err("no settings() call found".to_string())
}

/// Set or remove the default sandbox in the `settings()` call.
pub fn set_default_sandbox(stmts: &mut Vec<Stmt>, sandbox: Option<&str>) -> Result<(), String> {
    if let Some(idx) = find_settings_call(stmts) {
        if let Stmt::Expr(Expr::Call { kwargs, .. }) = &mut stmts[idx] {
            // Remove existing default_sandbox kwarg
            kwargs.retain(|(k, _)| k != "default_sandbox");
            // Add new one if specified
            if let Some(name) = sandbox {
                kwargs.push(("default_sandbox".to_string(), Expr::string(name)));
            }
            return Ok(());
        }
    }
    Err("no settings() call found".to_string())
}

// ---------------------------------------------------------------------------
// Sandbox mutations
// ---------------------------------------------------------------------------

/// Add a new `sandbox(name = "...", ...)` call as a top-level statement.
///
/// Inserts before the `settings()` or `policy()` call so that sandbox
/// identifiers are defined before they're referenced.
pub fn add_sandbox(
    stmts: &mut Vec<Stmt>,
    name: &str,
    default_effect: Effect,
    net_allow: bool,
) -> Result<(), String> {
    // Check for duplicates
    if find_sandboxes(stmts).iter().any(|(_, n)| n == name) {
        return Err(format!("sandbox '{name}' already exists"));
    }

    let mut kw: Vec<(&str, Expr)> = vec![];
    let default_expr = match default_effect {
        Effect::Allow => builder::allow(),
        Effect::Deny => builder::deny(),
        Effect::Ask => builder::ask(),
    };
    kw.push(("default", default_expr));
    if net_allow {
        kw.push(("net", builder::allow()));
    } else {
        kw.push(("net", builder::deny()));
    }

    let sandbox_expr = builder::sandbox(name, kw);
    let stmt = Stmt::Expr(sandbox_expr);

    // Insert before settings() or policy(), whichever comes first
    let insert_at = find_settings_call(stmts)
        .or_else(|| find_policy_call(stmts))
        .unwrap_or(stmts.len());

    // Add a blank line before if previous stmt isn't blank
    if insert_at > 0 && !matches!(stmts.get(insert_at - 1), Some(Stmt::Blank)) {
        stmts.insert(insert_at, Stmt::Blank);
        stmts.insert(insert_at + 1, stmt);
    } else {
        stmts.insert(insert_at, stmt);
    }

    ensure_loaded(stmts, "sandbox");
    Ok(())
}

/// Remove a sandbox statement by name.
pub fn remove_sandbox(stmts: &mut Vec<Stmt>, name: &str) -> Result<(), String> {
    let sandboxes = find_sandboxes(stmts);
    let (idx, _) = sandboxes
        .iter()
        .find(|(_, n)| n == name)
        .ok_or_else(|| format!("sandbox '{name}' not found"))?;

    stmts.remove(*idx);
    // Clean up adjacent blank lines
    if *idx < stmts.len() && matches!(stmts.get(*idx), Some(Stmt::Blank)) {
        stmts.remove(*idx);
    }
    Ok(())
}

/// Add a filesystem rule to a sandbox's `fs = {...}` dict.
///
/// The path should be a glob pattern like `$HOME/.cache/**`.
/// Caps is a shorthand string like `"read"`, `"read + write"`, or `"rwc"`.
pub fn add_sandbox_rule(
    stmts: &mut Vec<Stmt>,
    sandbox_name: &str,
    path: &str,
    caps: &str,
) -> Result<(), String> {
    if !find_sandboxes(stmts).iter().any(|(_, n)| n == sandbox_name) {
        return Err(format!("sandbox '{sandbox_name}' not found"));
    }

    let key = Expr::call("glob", vec![Expr::string(path)]);
    let value = Expr::call("allow", vec![Expr::string(caps)]);
    let entry = DictEntry::new(key, value);

    // Try to add to existing fs dict
    if let Some(entries) = find_sandbox_fs_mut(stmts, sandbox_name) {
        entries.push(entry);
        return Ok(());
    }

    // No fs kwarg — create one
    let kwargs = find_sandbox_kwargs_mut(stmts, sandbox_name)
        .ok_or_else(|| format!("sandbox '{sandbox_name}' not found"))?;
    kwargs.push(("fs".to_string(), Expr::dict(vec![entry])));
    Ok(())
}

/// Remove a filesystem rule from a sandbox's `fs = {...}` dict by path.
///
/// Returns true if a rule was removed.
pub fn remove_sandbox_rule(
    stmts: &mut Vec<Stmt>,
    sandbox_name: &str,
    path: &str,
) -> Result<bool, String> {
    let entries = find_sandbox_fs_mut(stmts, sandbox_name)
        .ok_or_else(|| format!("sandbox '{sandbox_name}' not found or has no fs rules"))?;

    let before = entries.len();
    entries.retain(|e| {
        // Match glob("path"), subpath("path"), or literal("path") keys
        if let Expr::Call { func, args, .. } = &e.key {
            if let Expr::Ident(name) = func.as_ref() {
                if name == "glob" || name == "subpath" || name == "literal" {
                    if let Some(Expr::String(p)) = args.first() {
                        return p != path;
                    }
                }
            }
        }
        // Match bare string keys
        if let Expr::String(p) = &e.key {
            return p != path;
        }
        true
    });

    Ok(entries.len() < before)
}

// ---------------------------------------------------------------------------
// Include (load statement) mutations
// ---------------------------------------------------------------------------

/// Add a `load("path", ...)` statement at the top of the file.
pub fn add_load(stmts: &mut Vec<Stmt>, module: &str, names: &[&str]) {
    // Find the last existing load statement to insert after it
    let last_load = stmts.iter().rposition(|s| matches!(s, Stmt::Load { .. }));

    let stmt = Stmt::load(module, names);
    match last_load {
        Some(idx) => stmts.insert(idx + 1, stmt),
        None => stmts.insert(0, stmt),
    }
}

/// Remove a `load(...)` statement by module path.
pub fn remove_load(stmts: &mut Vec<Stmt>, module: &str) -> Result<(), String> {
    let idx = stmts
        .iter()
        .position(|s| matches!(s, Stmt::Load { module: m, .. } if m == module))
        .ok_or_else(|| format!("load(\"{module}\", ...) not found"))?;
    stmts.remove(idx);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Ensure a name is present in the `load("@clash//std.star", ...)` statement.
/// If the load statement doesn't exist, creates one.
pub fn ensure_loaded(stmts: &mut Vec<Stmt>, name: &str) {
    if let Some(idx) = find_std_load(stmts) {
        if let Stmt::Load { names, .. } = &mut stmts[idx] {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
        }
    } else {
        // No std load exists — create one
        stmts.insert(0, Stmt::load("@clash//std.star", &[name]));
    }
}

/// Append a rule expression to the `policy()` call's `rules = [...]` list.
fn append_rule(stmts: &mut Vec<Stmt>, rule: Expr) -> Result<(), String> {
    let rules = policy_rules_mut(stmts).ok_or("no policy() call with rules= found")?;
    rules.push(rule);
    Ok(())
}

/// Build an effect expression: `allow()`, `deny()`, or `ask()`,
/// optionally with a sandbox kwarg.
fn build_effect_expr(effect: Effect, sandbox: Option<&str>) -> Expr {
    match (effect, sandbox) {
        (Effect::Allow, None) => builder::allow(),
        (Effect::Allow, Some(sb)) => builder::allow_with_sandbox(Expr::ident(sb)),
        (Effect::Deny, None) => builder::deny(),
        (Effect::Deny, Some(sb)) => builder::deny_with_sandbox(Expr::ident(sb)),
        (Effect::Ask, None) => builder::ask(),
        (Effect::Ask, Some(sb)) => builder::ask_with_sandbox(Expr::ident(sb)),
    }
}

fn is_ident(expr: &Expr, name: &str) -> bool {
    matches!(expr, Expr::Ident(n) if n == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::parser::parse;
    use crate::codegen::serialize::serialize;

    fn policy_stmts() -> Vec<Stmt> {
        parse(
            r#"load("@clash//std.star", "when", "policy", "settings", "allow", "deny")

settings(default = deny())

policy("test", default = deny(), rules = [when({"Read": allow()})])
"#,
        )
        .unwrap()
    }

    #[test]
    fn add_tool_rule_appends() {
        let mut stmts = policy_stmts();
        add_tool_rule(&mut stmts, &["Write"], Effect::Allow, None).unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("\"Write\": allow()"), "got:\n{src}");
        // Original rule still there
        assert!(src.contains("\"Read\": allow()"), "got:\n{src}");
    }

    #[test]
    fn add_tool_rule_with_sandbox() {
        let mut stmts = policy_stmts();
        add_tool_rule(&mut stmts, &["Bash"], Effect::Allow, Some("_box")).unwrap();
        let src = serialize(&stmts);
        assert!(
            src.contains("\"Bash\": allow(sandbox = _box)"),
            "got:\n{src}"
        );
    }

    #[test]
    fn add_exec_rule_simple() {
        let mut stmts = policy_stmts();
        add_exec_rule(&mut stmts, "git", &[], Effect::Allow, None).unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("\"Bash\": {\"git\": allow()}"), "got:\n{src}");
    }

    #[test]
    fn add_exec_rule_nested() {
        let mut stmts = policy_stmts();
        add_exec_rule(&mut stmts, "git", &["push", "--force"], Effect::Deny, None).unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("\"git\""), "got:\n{src}");
        assert!(src.contains("\"push\""), "got:\n{src}");
        assert!(src.contains("\"--force\""), "got:\n{src}");
        assert!(src.contains("deny()"), "got:\n{src}");
    }

    #[test]
    fn remove_rule_by_index() {
        let mut stmts = policy_stmts();
        // There's one rule at index 0
        remove_rule(&mut stmts, 0).unwrap();
        let src = serialize(&stmts);
        assert!(!src.contains("Read"), "got:\n{src}");
        assert!(src.contains("rules = []"), "got:\n{src}");
    }

    #[test]
    fn remove_rule_out_of_range() {
        let mut stmts = policy_stmts();
        let err = remove_rule(&mut stmts, 5).unwrap_err();
        assert!(err.contains("out of range"), "got: {err}");
    }

    #[test]
    fn replace_rule_at_index() {
        let mut stmts = policy_stmts();
        let new_rule = builder::tool_match(&["Write"], builder::deny());
        replace_rule(&mut stmts, 0, new_rule).unwrap();
        let src = serialize(&stmts);
        assert!(!src.contains("Read"), "got:\n{src}");
        assert!(src.contains("\"Write\": deny()"), "got:\n{src}");
    }

    #[test]
    fn set_default_effect_changes_settings() {
        let mut stmts = policy_stmts();
        set_default_effect(&mut stmts, Effect::Ask).unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("settings(default = ask())"), "got:\n{src}");
        assert!(!src.contains("settings(default = deny())"), "got:\n{src}");
    }

    #[test]
    fn set_default_sandbox_adds_and_removes() {
        let mut stmts = policy_stmts();
        set_default_sandbox(&mut stmts, Some("_box")).unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("default_sandbox = \"_box\""), "got:\n{src}");

        set_default_sandbox(&mut stmts, None).unwrap();
        let src = serialize(&stmts);
        assert!(!src.contains("default_sandbox"), "got:\n{src}");
    }

    #[test]
    fn add_sandbox_inserts_before_settings() {
        let mut stmts = policy_stmts();
        add_sandbox(&mut stmts, "dev", Effect::Deny, true).unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("sandbox(name = \"dev\""), "got:\n{src}");
        // sandbox should appear before settings
        let sb_pos = src.find("sandbox(name").unwrap();
        let settings_pos = src.find("settings(").unwrap();
        assert!(
            sb_pos < settings_pos,
            "sandbox should be before settings:\n{src}"
        );
    }

    #[test]
    fn add_sandbox_duplicate_errors() {
        let mut stmts = policy_stmts();
        add_sandbox(&mut stmts, "dev", Effect::Deny, true).unwrap();
        let err = add_sandbox(&mut stmts, "dev", Effect::Deny, true).unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");
    }

    #[test]
    fn remove_sandbox_works() {
        let mut stmts = policy_stmts();
        add_sandbox(&mut stmts, "dev", Effect::Deny, true).unwrap();
        remove_sandbox(&mut stmts, "dev").unwrap();
        let src = serialize(&stmts);
        assert!(!src.contains("sandbox(name"), "got:\n{src}");
    }

    #[test]
    fn add_load_statement() {
        let mut stmts = policy_stmts();
        add_load(&mut stmts, "./my_rules.star", &["custom_rules"]);
        let src = serialize(&stmts);
        assert!(
            src.contains("load(\"./my_rules.star\", \"custom_rules\")"),
            "got:\n{src}"
        );
    }

    #[test]
    fn remove_load_statement() {
        let mut stmts = policy_stmts();
        add_load(&mut stmts, "./my_rules.star", &["custom_rules"]);
        remove_load(&mut stmts, "./my_rules.star").unwrap();
        let src = serialize(&stmts);
        assert!(!src.contains("my_rules"), "got:\n{src}");
    }

    #[test]
    fn ensure_loaded_adds_missing_name() {
        let mut stmts = policy_stmts();
        ensure_loaded(&mut stmts, "when");
        match &stmts[0] {
            Stmt::Load { names, .. } => {
                assert!(names.contains(&"when".to_string()));
            }
            other => panic!("expected Load, got {other:?}"),
        }
    }

    #[test]
    fn ensure_loaded_no_duplicate() {
        let mut stmts = policy_stmts();
        ensure_loaded(&mut stmts, "tool"); // not yet present, gets added once
        match &stmts[0] {
            Stmt::Load { names, .. } => {
                assert_eq!(names.iter().filter(|n| *n == "tool").count(), 1);
            }
            other => panic!("expected Load, got {other:?}"),
        }
    }

    #[test]
    fn add_raw_rule_appends() {
        let mut stmts = policy_stmts();
        add_raw_rule(&mut stmts, "when({\"Grep\": allow()})").unwrap();
        let src = serialize(&stmts);
        assert!(src.contains("when({\"Grep\": allow()})"), "got:\n{src}");
    }

    #[test]
    fn add_sandbox_rule_inserts() {
        let mut stmts = parse(
            r#"sandbox(name = "dev", default = deny(), fs = {glob("$PWD/**"): allow("rwc")})

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
        )
        .unwrap();
        add_sandbox_rule(&mut stmts, "dev", "$HOME/.cache/**", "read").unwrap();
        let src = serialize(&stmts);
        assert!(
            src.contains(".cache") && src.contains("allow(\"read\")"),
            "got:\n{src}"
        );
    }

    #[test]
    fn add_sandbox_rule_missing_sandbox_errors() {
        let mut stmts = policy_stmts();
        let err = add_sandbox_rule(&mut stmts, "nope", "$HOME/.cache/**", "read").unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn add_sandbox_rule_creates_fs_if_missing() {
        let mut stmts = parse(
            r#"sandbox(name = "net", default = deny(), net = allow())

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
        )
        .unwrap();
        add_sandbox_rule(&mut stmts, "net", "$HOME/.cache/**", "read + write").unwrap();
        let src = serialize(&stmts);
        assert!(
            src.contains("fs ="),
            "should have added fs kwarg, got:\n{src}"
        );
        assert!(src.contains(".cache"), "got:\n{src}");
    }

    #[test]
    fn remove_sandbox_rule_removes() {
        let mut stmts = parse(
            r#"sandbox(name = "dev", default = deny(), fs = {
    glob("$PWD/**"): allow("rwc"),
    glob("$HOME/.cache/**"): allow("read"),
})

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
        )
        .unwrap();
        let removed = remove_sandbox_rule(&mut stmts, "dev", "$HOME/.cache/**").unwrap();
        assert!(removed);
        let src = serialize(&stmts);
        assert!(!src.contains(".cache"), "got:\n{src}");
        assert!(src.contains("$PWD"), "should keep other rules, got:\n{src}");
    }

    #[test]
    fn remove_sandbox_rule_returns_false_when_no_match() {
        let mut stmts = parse(
            r#"sandbox(name = "dev", default = deny(), fs = {glob("$PWD/**"): allow("rwc")})

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
        )
        .unwrap();
        let removed = remove_sandbox_rule(&mut stmts, "dev", "$HOME/nope/**").unwrap();
        assert!(!removed);
    }

    #[test]
    fn mutations_produce_valid_starlark() {
        use crate::codegen::managed;

        let mut stmts = parse(
            r#"load("@clash//claude_compat.star", "from_claude_settings")

policy("test", merge(
    from_claude_settings(),
    {tool("Read"): allow()},
))
"#,
        )
        .unwrap();

        managed::upsert_tool_rule(&mut stmts, "Write", Effect::Allow, None).unwrap();
        managed::upsert_exec_rule(&mut stmts, "cargo", &["build"], Effect::Allow, None).unwrap();

        // The result should evaluate without error
        let src = serialize(&stmts);
        let result = crate::evaluate(&src, "test.star", &std::path::PathBuf::from("."));
        assert!(
            result.is_ok(),
            "eval failed: {:?}\nsource:\n{src}",
            result.err()
        );
    }
}
