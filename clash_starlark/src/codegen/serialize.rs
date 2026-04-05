//! Pretty-printer for Starlark AST nodes.
//!
//! Converts a `Vec<Stmt>` into formatted Starlark source text.

use std::fmt::Write;

use super::ast::{DictEntry, Expr, Param, Stmt};

const INDENT: &str = "    ";
const MAX_LINE: usize = 88;

/// Format a single expression as a Starlark source string.
pub fn expr_to_string(expr: &Expr) -> String {
    format_expr(expr, 0)
}

/// Serialize a list of statements into formatted Starlark source.
pub fn serialize(stmts: &[Stmt]) -> String {
    let mut out = String::new();
    for stmt in stmts {
        write_stmt(&mut out, stmt, 0);
    }
    out
}

fn write_stmt(out: &mut String, stmt: &Stmt, depth: usize) {
    let prefix = INDENT.repeat(depth);
    match stmt {
        Stmt::Load { module, names } => {
            write_load(out, module, names, &prefix);
        }
        Stmt::Assign { target, value } => {
            let rhs = format_expr(value, depth);
            out.push_str(&prefix);
            out.push_str(target);
            out.push_str(" = ");
            out.push_str(&rhs);
            out.push('\n');
        }
        Stmt::FuncDef { name, params, body } => {
            out.push_str(&prefix);
            out.push_str("def ");
            out.push_str(name);
            out.push('(');
            for (i, p) in params.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_param(out, p);
            }
            out.push_str("):\n");
            for s in body {
                write_stmt(out, s, depth + 1);
            }
        }
        Stmt::Return(expr) => {
            let val = format_expr(expr, depth);
            out.push_str(&prefix);
            out.push_str("return ");
            out.push_str(&val);
            out.push('\n');
        }
        Stmt::Expr(expr) => {
            out.push_str(&prefix);
            out.push_str(&format_expr(expr, depth));
            out.push('\n');
        }
        Stmt::Comment(text) => {
            out.push_str(&prefix);
            out.push_str("# ");
            out.push_str(text);
            out.push('\n');
        }
        Stmt::Blank => {
            out.push('\n');
        }
    }
}

fn write_load(out: &mut String, module: &str, names: &[String], prefix: &str) {
    // Try single line first
    let name_list: String = names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let oneline = format!("{prefix}load(\"{module}\", {name_list})\n");
    if oneline.len() <= MAX_LINE {
        out.push_str(&oneline);
        return;
    }
    // Multi-line
    out.push_str(prefix);
    let _ = writeln!(out, "load(\"{module}\",");
    let inner = format!("{prefix}{INDENT}");
    for name in names {
        out.push_str(&inner);
        let _ = writeln!(out, "\"{name}\",");
    }
    out.push_str(prefix);
    out.push_str(")\n");
}

fn write_param(out: &mut String, param: &Param) {
    out.push_str(&param.name);
    if let Some(default) = &param.default {
        out.push_str(" = ");
        out.push_str(&format_expr(default, 0));
    }
}

/// Format an expression as a string. `depth` is the current indentation level
/// used to decide whether to break into multiple lines.
fn format_expr(expr: &Expr, depth: usize) -> String {
    match expr {
        Expr::String(s) => format!("\"{}\"", escape_str(s)),
        Expr::Bool(true) => "True".to_string(),
        Expr::Bool(false) => "False".to_string(),
        Expr::Int(n) => n.to_string(),
        Expr::None => "None".to_string(),
        Expr::Ident(name) => name.clone(),
        Expr::Raw(s) => s.clone(),
        Expr::Commented { expr, .. } => {
            // The comment is handled by the list/call formatter. In raw
            // expression context we just emit the inner expression.
            format_expr(expr, depth)
        }
        Expr::List(items) => format_sequence(items, "[", "]", depth),
        Expr::Tuple(items) => {
            if items.len() == 1 {
                format!("({},)", format_expr(&items[0], depth))
            } else {
                format_sequence(items, "(", ")", depth)
            }
        }
        Expr::Dict(entries) => format_dict(entries, depth),
        Expr::Call { func, args, kwargs } => format_call(func, args, kwargs, depth),
        Expr::Attr { value, attr } => {
            format!("{}.{}", format_expr(value, depth), attr)
        }
    }
}

fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Format a bracketed sequence: `[a, b, c]` or multi-line.
fn format_sequence(items: &[Expr], open: &str, close: &str, depth: usize) -> String {
    if items.is_empty() {
        return format!("{open}{close}");
    }
    // Check if any items have comments — if so, force multi-line
    let has_comments = items.iter().any(|e| matches!(e, Expr::Commented { .. }));
    let inlined: Vec<String> = items.iter().map(|e| format_expr(e, depth + 1)).collect();
    if !has_comments {
        let oneline = format!("{open}{}{close}", inlined.join(", "));
        let approx_col = depth * INDENT.len() + oneline.len();
        if approx_col <= MAX_LINE && !oneline.contains('\n') {
            return oneline;
        }
    }
    // Multi-line
    let inner = INDENT.repeat(depth + 1);
    let outer = INDENT.repeat(depth);
    let mut out = format!("{open}\n");
    for (item, expr) in inlined.iter().zip(items.iter()) {
        // Emit comment line before the item if it's a Commented expression
        if let Expr::Commented { comment, .. } = expr {
            let _ = writeln!(out, "{inner}# {comment}");
        }
        write_indented_item(&mut out, item, &inner);
        out.push_str(",\n");
    }
    let _ = write!(out, "{outer}{close}");
    out
}

/// Format a dict literal, always multi-line for readability when nested.
fn format_dict(entries: &[DictEntry], depth: usize) -> String {
    if entries.is_empty() {
        return "{}".to_string();
    }
    let inner_depth = depth + 1;
    let inner = INDENT.repeat(inner_depth);
    let outer = INDENT.repeat(depth);

    // Try single-line first (unless forced multi-line)
    let parts: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{}: {}",
                format_expr(&e.key, inner_depth),
                format_expr(&e.value, inner_depth)
            )
        })
        .collect();
    let oneline = format!("{{{}}}", parts.join(", "));
    let approx_col = depth * INDENT.len() + oneline.len();
    if approx_col <= MAX_LINE && !oneline.contains('\n') {
        return oneline;
    }

    // Multi-line
    let mut out = "{\n".to_string();
    for e in entries {
        let k = format_expr(&e.key, inner_depth);
        let v = format_expr(&e.value, inner_depth);
        let _ = writeln!(out, "{inner}{k}: {v},");
    }
    let _ = write!(out, "{outer}}}");
    out
}

/// Format a function/method call, with single-line or multi-line layout.
fn format_call(func: &Expr, args: &[Expr], kwargs: &[(String, Expr)], depth: usize) -> String {
    let func_str = format_expr(func, depth);
    let all_args = format_arg_list(args, kwargs, depth);

    // Try single line (comments force multi-line)
    let has_commented_args = args
        .iter()
        .any(|e| matches!(e, Expr::Commented { .. }));
    let oneline = format!("{func_str}({all_args})");
    let approx_col = depth * INDENT.len() + oneline.len();
    if !has_commented_args && approx_col <= MAX_LINE && !oneline.contains('\n') {
        return oneline;
    }

    // Multi-line: each arg on its own line
    let inner = INDENT.repeat(depth + 1);
    let outer = INDENT.repeat(depth);
    let mut out = format!("{func_str}(\n");
    for a in args {
        // Emit comment line before the item if it's a Commented expression
        if has_commented_args {
            if let Expr::Commented { comment, .. } = a {
                let _ = writeln!(out, "{inner}# {comment}");
            }
        }
        write_indented_item(&mut out, &format_expr(a, depth + 1), &inner);
        out.push_str(",\n");
    }
    for (k, v) in kwargs {
        let formatted = format_expr(v, depth + 1);
        if formatted.contains('\n') {
            let _ = write!(out, "{inner}{k} = ");
            // First line of value is already on the same line as `key = `
            // Remaining lines are self-indented by format_expr
            out.push_str(&formatted);
            out.push_str(",\n");
        } else {
            let _ = writeln!(out, "{inner}{k} = {formatted},");
        }
    }
    let _ = write!(out, "{outer})");
    out
}

/// Write an expression as an indented list/call item. Multi-line expressions
/// already carry their own indentation for continuation lines.
fn write_indented_item(out: &mut String, formatted: &str, indent: &str) {
    if formatted.contains('\n') {
        // The expression's first line gets our indent; continuation lines
        // are already absolutely indented by format_expr.
        let mut first = true;
        for line in formatted.lines() {
            if first {
                let _ = write!(out, "{indent}{line}");
                first = false;
            } else {
                let _ = write!(out, "\n{line}");
            }
        }
    } else {
        let _ = write!(out, "{indent}{formatted}");
    }
}

fn format_arg_list(args: &[Expr], kwargs: &[(String, Expr)], depth: usize) -> String {
    let mut parts: Vec<String> = args.iter().map(|a| format_expr(a, depth)).collect();
    for (k, v) in kwargs {
        parts.push(format!("{k} = {}", format_expr(v, depth)));
    }
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::ast::*;
    use indoc::indoc;
    use pretty_assertions::assert_eq;

    #[test]
    fn load_single_line() {
        let stmts = vec![Stmt::load("@clash//std.star", &["when", "tool", "policy"])];
        let src = serialize(&stmts);
        assert_eq!(
            src,
            "load(\"@clash//std.star\", \"when\", \"tool\", \"policy\")\n"
        );
    }

    #[test]
    fn load_wraps_when_long() {
        let names: Vec<&str> = vec![
            "when", "tool", "policy", "sandbox", "cwd", "home", "tempdir", "path", "regex",
            "domains", "domain", "allow", "deny", "ask",
        ];
        let stmts = vec![Stmt::load("@clash//std.star", &names)];
        let src = serialize(&stmts);
        assert!(src.starts_with("load(\"@clash//std.star\",\n"));
        assert!(src.contains("    \"when\",\n"));
    }

    #[test]
    fn simple_function() {
        let stmts = vec![Stmt::def(
            "main",
            vec![Stmt::Return(Expr::call("policy", vec![]))],
        )];
        let src = serialize(&stmts);
        assert_eq!(src, "def main():\n    return policy()\n");
    }

    #[test]
    fn call_with_kwargs() {
        let expr = Expr::call_kwargs("allow", vec![], vec![("sandbox", Expr::ident("dev"))]);
        let s = format_expr(&expr, 0);
        assert_eq!(s, "allow(sandbox = dev)");
    }

    #[test]
    fn method_chain() {
        let expr = Expr::call("tool", vec![Expr::string("Read")])
            .sandbox(Expr::ident("_fs_box"))
            .allow();
        let s = format_expr(&expr, 0);
        assert_eq!(s, "tool(\"Read\").sandbox(_fs_box).allow()");
    }

    #[test]
    fn dict_nested() {
        let inner = Expr::dict(vec![DictEntry::new(
            Expr::string("push"),
            Expr::call("deny", vec![]),
        )]);
        let outer = Expr::dict(vec![DictEntry::new(Expr::string("git"), inner)]);
        let s = format_expr(&outer, 0);
        assert_eq!(s, r#"{"git": {"push": deny()}}"#);
    }

    #[test]
    fn assign_short_stays_single_line() {
        let stmts = vec![Stmt::assign(
            "_fs_box",
            Expr::call_kwargs(
                "sandbox",
                vec![],
                vec![
                    ("name", Expr::string("cwd")),
                    (
                        "fs",
                        Expr::list(vec![Expr::call("cwd", vec![]).recurse().allow()]),
                    ),
                ],
            ),
        )];
        let src = serialize(&stmts);
        assert_eq!(
            src,
            "_fs_box = sandbox(name = \"cwd\", fs = [cwd().recurse().allow()])\n"
        );
    }

    #[test]
    fn assign_long_goes_multiline() {
        let stmts = vec![Stmt::assign(
            "_fs_box",
            Expr::call_kwargs(
                "sandbox",
                vec![],
                vec![
                    ("name", Expr::string("cwd")),
                    (
                        "fs",
                        Expr::list(vec![
                            Expr::call_kwargs(
                                "cwd",
                                vec![],
                                vec![("follow_worktrees", Expr::bool(true))],
                            )
                            .recurse()
                            .allow_kwargs(vec![
                                ("read", Expr::bool(true)),
                                ("write", Expr::bool(true)),
                            ]),
                            Expr::call("home", vec![])
                                .child(".claude")
                                .recurse()
                                .allow_kwargs(vec![
                                    ("read", Expr::bool(true)),
                                    ("write", Expr::bool(true)),
                                ]),
                        ]),
                    ),
                ],
            ),
        )];
        let src = serialize(&stmts);
        assert!(
            src.contains("_fs_box = sandbox(\n"),
            "expected multi-line sandbox call"
        );
        assert!(src.contains("name = \"cwd\""), "expected name kwarg");
        assert!(
            src.contains("follow_worktrees = True"),
            "expected follow_worktrees"
        );
    }

    #[test]
    fn commented_items_in_list() {
        let stmts = vec![Stmt::Expr(Expr::list(vec![
            Expr::commented("first group", Expr::string("a")),
            Expr::commented("second group", Expr::string("b")),
        ]))];
        let src = serialize(&stmts);
        assert_eq!(
            src,
            "\
[
    # first group
    \"a\",
    # second group
    \"b\",
]
"
        );
    }

    #[test]
    fn load_multi_line_exact() {
        let names: Vec<&str> = vec![
            "when", "tool", "policy", "sandbox", "cwd", "home", "tempdir", "path", "regex",
            "domains", "domain", "allow", "deny", "ask",
        ];
        let stmts = vec![Stmt::load("@clash//std.star", &names)];
        let src = serialize(&stmts);
        assert_eq!(
            src,
            "\
load(\"@clash//std.star\",
    \"when\",
    \"tool\",
    \"policy\",
    \"sandbox\",
    \"cwd\",
    \"home\",
    \"tempdir\",
    \"path\",
    \"regex\",
    \"domains\",
    \"domain\",
    \"allow\",
    \"deny\",
    \"ask\",
)
"
        );
    }

    #[test]
    fn quick_policy_snapshot() {
        use crate::codegen::builder::*;

        let stmts = vec![
            Stmt::load(
                "@clash//std.star",
                &["policy", "settings", "allow", "ask"],
            ),
            Stmt::Blank,
            Stmt::Expr(settings(ask(), None)),
            Stmt::Blank,
            Stmt::Expr(policy(
                "test",
                ask(),
                vec![
                    crate::match_tree! {
                        "Bash" => {
                            ("git", "cargo") => allow(),
                        },
                    },
                    tool_match(&["Read"], allow()),
                    tool_match(&["Write"], allow()),
                ],
                None,
            )),
        ];
        let src = serialize(&stmts);
        assert_eq!(
            src,
            indoc! {r#"
                load("@clash//std.star", "policy", "settings", "allow", "ask")

                settings(default = ask())

                policy(
                    "test",
                    merge({"Bash": {("git", "cargo"): allow()}}, {"Read": allow()}, {"Write": allow()}),
                    default = ask(),
                )
            "#}
        );
    }

    #[test]
    fn tuple_key_single() {
        let s = format_expr(&Expr::tuple(vec![Expr::string("a")]), 0);
        assert_eq!(s, "(\"a\",)");
    }

    #[test]
    fn escape_strings() {
        let s = format_expr(&Expr::string("hello \"world\"\nnewline"), 0);
        assert_eq!(s, "\"hello \\\"world\\\"\\nnewline\"");
    }

    #[test]
    fn raw_and_none() {
        assert_eq!(
            format_expr(&Expr::raw("arbitrary code"), 0),
            "arbitrary code"
        );
        assert_eq!(format_expr(&Expr::None, 0), "None");
        assert_eq!(format_expr(&Expr::Int(42), 0), "42");
    }

    #[test]
    fn bool_values() {
        assert_eq!(format_expr(&Expr::bool(true), 0), "True");
        assert_eq!(format_expr(&Expr::bool(false), 0), "False");
    }
}
