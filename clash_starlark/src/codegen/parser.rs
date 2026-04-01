//! Tree-sitter-based parser for Starlark source into the codegen AST.
//!
//! Converts `.star` source text into `Vec<Stmt>` for round-trip editing.
//! Unsupported constructs (if/for/comprehensions/binary ops) are captured
//! as `Expr::Raw(source_text)` to preserve them through the round-trip.

use super::ast::{DictEntry, Expr, Param, Stmt};

/// Error returned when parsing fails.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("tree-sitter failed to parse source")]
    TreeSitter,
    #[error("parse error at byte {offset}: {message}")]
    Syntax { offset: usize, message: String },
}

/// Parse Starlark source text into a list of AST statements.
pub fn parse(source: &str) -> Result<Vec<Stmt>, ParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_starlark::LANGUAGE.into())
        .map_err(|_| ParseError::TreeSitter)?;
    let tree = parser.parse(source, None).ok_or(ParseError::TreeSitter)?;
    let root = tree.root_node();

    let mut stmts = Vec::new();
    let mut prev_end_row: Option<usize> = None;

    for i in 0..root.named_child_count() {
        let child = root.named_child(i).unwrap();
        let start_row = child.start_position().row;

        // Insert Stmt::Blank for each blank line gap between statements.
        if let Some(prev) = prev_end_row {
            for _ in 0..(start_row.saturating_sub(prev + 1)) {
                stmts.push(Stmt::Blank);
            }
        }

        convert_stmt(source, &child, &mut stmts);
        prev_end_row = Some(child.end_position().row);
    }

    Ok(stmts)
}

/// Convert a top-level CST node into one or more `Stmt`s.
fn convert_stmt(source: &str, node: &tree_sitter::Node, stmts: &mut Vec<Stmt>) {
    match node.kind() {
        "comment" => {
            let text = node_text(source, node);
            // Strip leading "# " or "#"
            let content = text
                .strip_prefix("# ")
                .or_else(|| text.strip_prefix('#'))
                .unwrap_or(&text);
            stmts.push(Stmt::Comment(content.to_string()));
        }
        "expression_statement" => {
            // An expression_statement wraps an expression, assignment, or augmented_assignment.
            if let Some(child) = node.named_child(0) {
                match child.kind() {
                    "assignment" => {
                        if let Some(s) = convert_assignment(source, &child) {
                            stmts.push(s);
                        } else {
                            stmts.push(Stmt::Expr(Expr::Raw(node_text(source, node))));
                        }
                    }
                    _ => {
                        let expr = convert_expr(source, &child);
                        // Detect load() calls and promote to Stmt::Load
                        if let Some(load) = try_extract_load(&expr) {
                            stmts.push(load);
                        } else {
                            stmts.push(Stmt::Expr(expr));
                        }
                    }
                }
            }
        }
        "function_definition" => {
            stmts.push(convert_func_def(source, node));
        }
        "return_statement" => {
            let expr = node
                .named_child(0)
                .map(|c| convert_expr(source, &c))
                .unwrap_or(Expr::None);
            stmts.push(Stmt::Return(expr));
        }
        // Catch-all: emit as Raw expression statement
        _ => {
            stmts.push(Stmt::Expr(Expr::Raw(node_text(source, node))));
        }
    }
}

/// Try to convert an assignment CST node to `Stmt::Assign`.
/// Returns None for complex patterns (tuple unpacking, etc.).
fn convert_assignment(source: &str, node: &tree_sitter::Node) -> Option<Stmt> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;

    // Only handle simple identifier = expr assignments.
    if left.kind() != "identifier" {
        return None;
    }

    let target = node_text(source, &left);
    let value = convert_expr(source, &right);
    Some(Stmt::Assign {
        target,
        value,
    })
}

/// Convert a function_definition CST node.
fn convert_func_def(source: &str, node: &tree_sitter::Node) -> Stmt {
    let name = node
        .child_by_field_name("name")
        .map(|n| node_text(source, &n))
        .unwrap_or_default();

    let params = node
        .child_by_field_name("parameters")
        .map(|p| convert_params(source, &p))
        .unwrap_or_default();

    let mut body = Vec::new();
    if let Some(body_node) = node.child_by_field_name("body") {
        let mut prev_end_row: Option<usize> = None;
        for i in 0..body_node.named_child_count() {
            let child = body_node.named_child(i).unwrap();
            let start_row = child.start_position().row;
            if let Some(prev) = prev_end_row {
                for _ in 0..(start_row.saturating_sub(prev + 1)) {
                    body.push(Stmt::Blank);
                }
            }
            convert_stmt(source, &child, &mut body);
            prev_end_row = Some(child.end_position().row);
        }
    }

    Stmt::FuncDef { name, params, body }
}

/// Convert a parameters CST node into a list of `Param`.
fn convert_params(source: &str, node: &tree_sitter::Node) -> Vec<Param> {
    let mut params = Vec::new();
    for i in 0..node.named_child_count() {
        let child = node.named_child(i).unwrap();
        match child.kind() {
            "identifier" => {
                params.push(Param {
                    name: node_text(source, &child),
                    default: None,
                });
            }
            "default_parameter" => {
                let name = child
                    .child_by_field_name("name")
                    .map(|n| node_text(source, &n))
                    .unwrap_or_default();
                let default = child
                    .child_by_field_name("value")
                    .map(|v| convert_expr(source, &v));
                params.push(Param { name, default });
            }
            // *args, **kwargs — capture as Raw
            _ => {
                params.push(Param {
                    name: node_text(source, &child),
                    default: None,
                });
            }
        }
    }
    params
}

/// Convert any expression CST node into an `Expr`.
fn convert_expr(source: &str, node: &tree_sitter::Node) -> Expr {
    match node.kind() {
        "identifier" => Expr::Ident(node_text(source, node)),
        "integer" => {
            let text = node_text(source, node);
            Expr::Int(text.parse().unwrap_or(0))
        }
        "true" => Expr::Bool(true),
        "false" => Expr::Bool(false),
        "none" => Expr::None,
        "string" => Expr::String(extract_string_content(source, node)),
        "concatenated_string" => {
            // Concatenated strings: "a" "b" → join contents
            let mut parts = Vec::new();
            for i in 0..node.named_child_count() {
                let child = node.named_child(i).unwrap();
                if child.kind() == "string" {
                    parts.push(extract_string_content(source, &child));
                }
            }
            Expr::String(parts.join(""))
        }
        "list" => {
            let items = convert_sequence_with_comments(source, node);
            Expr::List(items)
        }
        "tuple" => {
            let items = convert_sequence_with_comments(source, node);
            Expr::Tuple(items)
        }
        "dictionary" => {
            let entries = convert_dict_entries(source, node);
            Expr::Dict(entries)
        }
        "call" => convert_call(source, node),
        "attribute" => {
            let object = node
                .child_by_field_name("object")
                .map(|o| convert_expr(source, &o))
                .unwrap_or(Expr::None);
            let attr = node
                .child_by_field_name("attribute")
                .map(|a| node_text(source, &a))
                .unwrap_or_default();
            Expr::Attr {
                value: Box::new(object),
                attr,
            }
        }
        "parenthesized_expression" => {
            // Check if this is actually a tuple (has comma) or just grouping
            // If it has more than one expression child or contains list_splat, it's a tuple
            let exprs: Vec<_> = (0..node.named_child_count())
                .filter_map(|i| node.named_child(i))
                .filter(|c| c.kind() != "comment")
                .collect();

            if exprs.len() == 1 {
                // Check for trailing comma → tuple
                let text = node_text(source, node);
                if text.contains(',') {
                    Expr::Tuple(vec![convert_expr(source, &exprs[0])])
                } else {
                    convert_expr(source, &exprs[0])
                }
            } else {
                // Multiple expressions → tuple
                Expr::Tuple(exprs.iter().map(|e| convert_expr(source, e)).collect())
            }
        }
        "unary_operator" | "binary_operator" | "boolean_operator" | "comparison_operator"
        | "not_operator" | "conditional_expression" | "lambda" | "list_comprehension"
        | "dictionary_comprehension" | "set_comprehension" | "set" | "subscript"
        | "list_splat" | "dictionary_splat" | "named_expression" => {
            Expr::Raw(node_text(source, node))
        }
        // Catch-all for unknown expression types
        _ => Expr::Raw(node_text(source, node)),
    }
}

/// Convert a call expression.
fn convert_call(source: &str, node: &tree_sitter::Node) -> Expr {
    let func_node = match node.child_by_field_name("function") {
        Some(f) => f,
        None => return Expr::Raw(node_text(source, node)),
    };
    let func = convert_expr(source, &func_node);

    let mut args = Vec::new();
    let mut kwargs = Vec::new();

    if let Some(arg_list) = node.child_by_field_name("arguments") {
        // Walk all children to detect comments before arguments.
        let mut pending_comment: Option<String> = None;

        for i in 0..arg_list.named_child_count() {
            let child = arg_list.named_child(i).unwrap();
            match child.kind() {
                "comment" => {
                    let text = node_text(source, &child);
                    let content = text
                        .strip_prefix("# ")
                        .or_else(|| text.strip_prefix('#'))
                        .unwrap_or(&text);
                    pending_comment = Some(content.to_string());
                }
                "keyword_argument" => {
                    let name = child
                        .child_by_field_name("name")
                        .map(|n| node_text(source, &n))
                        .unwrap_or_default();
                    let value = child
                        .child_by_field_name("value")
                        .map(|v| convert_expr(source, &v))
                        .unwrap_or(Expr::None);
                    // Comments before kwargs are dropped (no Commented support for kwargs)
                    pending_comment = None;
                    kwargs.push((name, value));
                }
                _ => {
                    let mut expr = convert_expr(source, &child);
                    if let Some(comment) = pending_comment.take() {
                        expr = Expr::Commented {
                            comment,
                            expr: Box::new(expr),
                        };
                    }
                    args.push(expr);
                }
            }
        }
    }

    Expr::Call {
        func: Box::new(func),
        args,
        kwargs,
    }
}

/// Convert children of a list or tuple node, attaching comments to following items.
fn convert_sequence_with_comments(source: &str, node: &tree_sitter::Node) -> Vec<Expr> {
    let mut items = Vec::new();
    let mut pending_comment: Option<String> = None;

    for i in 0..node.named_child_count() {
        let child = node.named_child(i).unwrap();
        match child.kind() {
            "comment" => {
                let text = node_text(source, &child);
                let content = text
                    .strip_prefix("# ")
                    .or_else(|| text.strip_prefix('#'))
                    .unwrap_or(&text);
                pending_comment = Some(content.to_string());
            }
            _ => {
                let mut expr = convert_expr(source, &child);
                if let Some(comment) = pending_comment.take() {
                    expr = Expr::Commented {
                        comment,
                        expr: Box::new(expr),
                    };
                }
                items.push(expr);
            }
        }
    }
    items
}

/// Convert dictionary pair children into `DictEntry` items.
fn convert_dict_entries(source: &str, node: &tree_sitter::Node) -> Vec<DictEntry> {
    let mut entries = Vec::new();
    for i in 0..node.named_child_count() {
        let child = node.named_child(i).unwrap();
        if child.kind() == "pair" {
            let key = child
                .child_by_field_name("key")
                .map(|k| convert_expr(source, &k))
                .unwrap_or(Expr::None);
            let value = child
                .child_by_field_name("value")
                .map(|v| convert_expr(source, &v))
                .unwrap_or(Expr::None);
            entries.push(DictEntry::new(key, value));
        }
        // dictionary_splat → Raw
        else if child.kind() == "dictionary_splat" {
            // Can't represent splats in DictEntry, so we skip gracefully.
            // This is a limitation — complex dicts with **splat should use Raw at a higher level.
        }
    }
    entries
}

/// Try to extract a `Stmt::Load` from a call expression.
/// Returns `Some(Stmt::Load { .. })` if the expression is `load("module", "name1", ...)`.
fn try_extract_load(expr: &Expr) -> Option<Stmt> {
    if let Expr::Call { func, args, .. } = expr {
        if let Expr::Ident(name) = func.as_ref() {
            if name == "load" && !args.is_empty() {
                if let Expr::String(module) = &args[0] {
                    let names: Vec<String> = args[1..]
                        .iter()
                        .filter_map(|a| {
                            if let Expr::String(s) = a {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    return Some(Stmt::Load {
                        module: module.clone(),
                        names,
                    });
                }
            }
        }
    }
    None
}

/// Extract the unescaped content of a string CST node.
///
/// String nodes have structure: string_start, string_content?, string_end.
/// We extract the raw text between the quotes and unescape it.
fn extract_string_content(source: &str, node: &tree_sitter::Node) -> String {
    let full = node_text(source, node);
    // Handle triple-quoted strings
    if full.starts_with("\"\"\"") || full.starts_with("'''") {
        let q = &full[..3];
        let inner = full
            .strip_prefix(q)
            .and_then(|s| s.strip_suffix(q))
            .unwrap_or(&full[3..]);
        return inner.to_string();
    }
    // Handle single/double quoted strings (possibly with r/b prefix)
    let stripped = full
        .strip_prefix("r\"")
        .or_else(|| full.strip_prefix("r'"))
        .or_else(|| full.strip_prefix("b\""))
        .or_else(|| full.strip_prefix("b'"))
        .or_else(|| full.strip_prefix('"'))
        .or_else(|| full.strip_prefix('\''))
        .unwrap_or(&full);

    let stripped = stripped
        .strip_suffix('"')
        .or_else(|| stripped.strip_suffix('\''))
        .unwrap_or(stripped);

    unescape_string(stripped)
}

/// Unescape common Starlark/Python string escape sequences.
fn unescape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('0') => out.push('\0'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Get the source text for a CST node.
fn node_text(source: &str, node: &tree_sitter::Node) -> String {
    source[node.byte_range()].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::serialize::serialize;

    #[test]
    fn parse_load_statement() {
        let src = r#"load("@clash//std.star", "tool", "allow", "policy")"#;
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(
            stmts[0],
            Stmt::Load {
                module: "@clash//std.star".to_string(),
                names: vec![
                    "tool".to_string(),
                    "allow".to_string(),
                    "policy".to_string()
                ],
            }
        );
    }

    #[test]
    fn parse_assignment() {
        let src = r#"_box = sandbox(name = "dev")"#;
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Stmt::Assign { target, value } => {
                assert_eq!(target, "_box");
                match value {
                    Expr::Call { func, kwargs, .. } => {
                        assert_eq!(**func, Expr::Ident("sandbox".to_string()));
                        assert_eq!(kwargs[0].0, "name");
                        assert_eq!(kwargs[0].1, Expr::String("dev".to_string()));
                    }
                    other => panic!("expected Call, got {other:?}"),
                }
            }
            other => panic!("expected Assign, got {other:?}"),
        }
    }

    #[test]
    fn parse_method_chain() {
        let src = r#"tool(["Read"]).sandbox(_box).allow()"#;
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        // The expression should be a chain: tool(...).sandbox(...).allow()
        match &stmts[0] {
            Stmt::Expr(Expr::Call { func, args, .. }) => {
                // Outermost call is .allow()
                assert!(args.is_empty());
                match func.as_ref() {
                    Expr::Attr { attr, .. } => assert_eq!(attr, "allow"),
                    other => panic!("expected Attr, got {other:?}"),
                }
            }
            other => panic!("expected Expr(Call), got {other:?}"),
        }
    }

    #[test]
    fn parse_blank_lines() {
        let src = "x = 1\n\n\ny = 2\n";
        let stmts = parse(src).unwrap();
        // Should be: Assign(x), Blank, Blank, Assign(y)
        assert_eq!(stmts.len(), 4);
        assert!(matches!(stmts[0], Stmt::Assign { .. }));
        assert_eq!(stmts[1], Stmt::Blank);
        assert_eq!(stmts[2], Stmt::Blank);
        assert!(matches!(stmts[3], Stmt::Assign { .. }));
    }

    #[test]
    fn parse_comment() {
        let src = "# This is a comment\nx = 1\n";
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0], Stmt::Comment("This is a comment".to_string()));
    }

    #[test]
    fn parse_function_def() {
        let src = "def main(x, y = 1):\n    return x\n";
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Stmt::FuncDef { name, params, body } => {
                assert_eq!(name, "main");
                assert_eq!(params.len(), 2);
                assert_eq!(params[0].name, "x");
                assert!(params[0].default.is_none());
                assert_eq!(params[1].name, "y");
                assert_eq!(params[1].default, Some(Expr::Int(1)));
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], Stmt::Return(Expr::Ident(n)) if n == "x"));
            }
            other => panic!("expected FuncDef, got {other:?}"),
        }
    }

    #[test]
    fn parse_dict() {
        let src = r#"{"Bash": {"git": allow()}}"#;
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Stmt::Expr(Expr::Dict(entries)) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].key, Expr::String("Bash".to_string()));
                match &entries[0].value {
                    Expr::Dict(inner) => {
                        assert_eq!(inner.len(), 1);
                        assert_eq!(inner[0].key, Expr::String("git".to_string()));
                    }
                    other => panic!("expected inner Dict, got {other:?}"),
                }
            }
            other => panic!("expected Expr(Dict), got {other:?}"),
        }
    }

    #[test]
    fn parse_list_with_comments() {
        let src = r#"[
    # first group
    "a",
    # second group
    "b",
]"#;
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Stmt::Expr(Expr::List(items)) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], Expr::Commented { comment, .. } if comment == "first group"));
                assert!(matches!(&items[1], Expr::Commented { comment, .. } if comment == "second group"));
            }
            other => panic!("expected Expr(List), got {other:?}"),
        }
    }

    #[test]
    fn parse_tuple_key() {
        let src = r#"("a", "b")"#;
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 1);
        match &stmts[0] {
            Stmt::Expr(Expr::Tuple(items)) => {
                assert_eq!(items.len(), 2);
            }
            other => panic!("expected Expr(Tuple), got {other:?}"),
        }
    }

    #[test]
    fn parse_bool_none() {
        let src = "x = True\ny = False\nz = None\n";
        let stmts = parse(src).unwrap();
        assert_eq!(stmts.len(), 3);
        assert!(matches!(&stmts[0], Stmt::Assign { value: Expr::Bool(true), .. }));
        assert!(matches!(&stmts[1], Stmt::Assign { value: Expr::Bool(false), .. }));
        assert!(matches!(&stmts[2], Stmt::Assign { value: Expr::None, .. }));
    }

    #[test]
    fn parse_string_escapes() {
        let src = r#"x = "hello \"world\"\nnewline""#;
        let stmts = parse(src).unwrap();
        match &stmts[0] {
            Stmt::Assign { value: Expr::String(s), .. } => {
                assert_eq!(s, "hello \"world\"\nnewline");
            }
            other => panic!("expected string, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_policy() {
        let src = r#"load("@clash//std.star", "tool", "policy", "settings", "allow", "ask")

settings(default = ask())

policy(
    "test",
    default = ask(),
    rules = [
        tool(["Read"]).allow(),
        tool(["Write"]).allow(),
    ],
)
"#;
        let stmts = parse(src).unwrap();
        let reserialized = serialize(&stmts);
        // Parse again and compare ASTs
        let stmts2 = parse(&reserialized).unwrap();
        assert_eq!(stmts, stmts2, "AST round-trip mismatch:\noriginal:\n{src}\nreserialized:\n{reserialized}");
    }

    #[test]
    fn round_trip_with_sandbox() {
        let src = r#"load("@clash//std.star", "tool", "policy", "settings", "sandbox", "cwd", "allow", "deny")

_box = sandbox(name = "dev", fs = [cwd().recurse().allow()])

settings(default = deny())

policy("default", default = deny(), rules = [tool(["Read"]).sandbox(_box).allow()])
"#;
        let stmts = parse(src).unwrap();
        let reserialized = serialize(&stmts);
        let stmts2 = parse(&reserialized).unwrap();
        assert_eq!(stmts, stmts2, "AST round-trip mismatch:\nreserialized:\n{reserialized}");
    }

    #[test]
    fn parse_example_policy_structure() {
        // Verify we can parse a full policy with match rules
        let src = r#"load("@clash//std.star", "match", "tool", "policy", "settings", "allow", "ask")

settings(default = ask())

policy(
    "test",
    default = ask(),
    rules = [
        match({"Bash": {("git", "cargo"): allow()}}),
        tool(["Read"]).allow(),
        tool(["Write"]).allow(),
    ],
)
"#;
        let stmts = parse(src).unwrap();
        // Should have: Load, Blank, Expr(settings), Blank, Expr(policy)
        assert_eq!(stmts.len(), 5);
        assert!(matches!(&stmts[0], Stmt::Load { .. }));
        assert_eq!(stmts[1], Stmt::Blank);
        assert!(matches!(&stmts[2], Stmt::Expr(Expr::Call { .. })));
        assert_eq!(stmts[3], Stmt::Blank);
        assert!(matches!(&stmts[4], Stmt::Expr(Expr::Call { .. })));
    }

    /// Helper: parse source, serialize, re-parse, and assert AST equality.
    fn assert_round_trip(name: &str, src: &str) {
        let stmts = parse(src).unwrap_or_else(|e| panic!("{name}: parse failed: {e}"));
        let reserialized = serialize(&stmts);
        let stmts2 = parse(&reserialized)
            .unwrap_or_else(|e| panic!("{name}: re-parse failed: {e}\nreserialized:\n{reserialized}"));
        assert_eq!(stmts, stmts2, "{name}: AST round-trip mismatch.\nreserialized:\n{reserialized}");
    }

    #[test]
    fn round_trip_paranoid() {
        assert_round_trip("paranoid", include_str!("../../../examples/paranoid.star"));
    }

    #[test]
    fn round_trip_permissive() {
        assert_round_trip("permissive", include_str!("../../../examples/permissive.star"));
    }

    #[test]
    fn round_trip_node_dev() {
        assert_round_trip("node-dev", include_str!("../../../examples/node-dev.star"));
    }

    #[test]
    fn round_trip_rust_dev() {
        assert_round_trip("rust-dev", include_str!("../../../examples/rust-dev.star"));
    }

    #[test]
    fn round_trip_python_dev() {
        assert_round_trip("python-dev", include_str!("../../../examples/python-dev.star"));
    }

    #[test]
    fn parse_dict_with_call_keys() {
        // Real pattern from rust-dev.star: function calls as dict keys
        let src = r#"{subpath("$PWD"): allow("rwc"), glob("$TMPDIR/**"): allow()}"#;
        let stmts = parse(src).unwrap();
        match &stmts[0] {
            Stmt::Expr(Expr::Dict(entries)) => {
                assert_eq!(entries.len(), 2);
                // First key should be a Call (subpath)
                assert!(matches!(&entries[0].key, Expr::Call { func, .. } if matches!(func.as_ref(), Expr::Ident(n) if n == "subpath")));
                // Second key should be a Call (glob)
                assert!(matches!(&entries[1].key, Expr::Call { func, .. } if matches!(func.as_ref(), Expr::Ident(n) if n == "glob")));
            }
            other => panic!("expected Dict, got {other:?}"),
        }
    }

    #[test]
    fn parse_nested_dict_with_string_key_and_dict_value() {
        // Pattern from rust-dev.star: "$HOME": { ... }
        let src = r#"{"$HOME": {glob(".cargo/**"): allow("rwc")}}"#;
        let stmts = parse(src).unwrap();
        match &stmts[0] {
            Stmt::Expr(Expr::Dict(entries)) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].key, Expr::String("$HOME".to_string()));
                assert!(matches!(&entries[0].value, Expr::Dict(_)));
            }
            other => panic!("expected Dict, got {other:?}"),
        }
    }
}
