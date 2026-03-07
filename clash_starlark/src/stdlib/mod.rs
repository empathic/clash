//! Embedded prebuilt Starlark sandbox files.
//!
//! These are loaded via `load("@clash//rust.star", "rust_sandbox")` etc.

const RUST_STAR: &str = include_str!("rust.star");
const NODE_STAR: &str = include_str!("node.star");
const PYTHON_STAR: &str = include_str!("python.star");
const STD_STAR: &str = include_str!("std.star");
const MATCH_TREE_STAR: &str = include_str!("match_tree.star");

/// Look up an embedded stdlib module by path (e.g. `"rust.star"`).
pub fn get(name: &str) -> Option<&'static str> {
    match name {
        "rust.star" => Some(RUST_STAR),
        "node.star" => Some(NODE_STAR),
        "python.star" => Some(PYTHON_STAR),
        "std.star" => Some(STD_STAR),
        "match_tree.star" => Some(MATCH_TREE_STAR),
        _ => None,
    }
}

/// List all available stdlib modules.
pub fn list() -> Vec<&'static str> {
    vec![
        "rust.star",
        "node.star",
        "python.star",
        "std.star",
        "match_tree.star",
    ]
}
