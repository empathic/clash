//! Starlark policy evaluator for Clash.
//!
//! Evaluates `.star` policy files and compiles them to JSON `PolicyDocument` format.
//! This crate has no dependency on the `clash` crate — it outputs a JSON string
//! that the existing compile pipeline consumes.

mod builders;
pub mod codegen;
mod compile;
pub mod eval_context;
mod globals;
mod loader;
pub mod stdlib;

use std::path::Path;

use anyhow::{Context, Result};

/// Output from evaluating a `.star` policy file.
#[derive(Debug, Clone)]
pub struct EvalOutput {
    /// The compiled JSON policy document.
    pub json: String,
    /// Paths of all files loaded during evaluation.
    pub loaded_files: Vec<String>,
}

/// Evaluate a Starlark policy source and return a JSON policy document.
///
/// Top-level `policy()`, `sandbox()`, and `settings()` calls register into
/// an `EvalContext` attached to `evaluator.extra`. After module evaluation,
/// the context is assembled into a v5 JSON document.
///
/// - `source`: the `.star` file contents
/// - `filename`: display name for error messages (e.g. `"policy.star"`)
/// - `base_dir`: directory of the `.star` file, used to resolve relative `load()` paths
pub fn evaluate(source: &str, filename: &str, base_dir: &Path) -> Result<EvalOutput> {
    use starlark::environment::Module;
    use starlark::eval::Evaluator;
    use starlark::syntax::{AstModule, Dialect};

    let ast = AstModule::parse(filename, source.to_owned(), &Dialect::Standard)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let loader = loader::ClashLoader::new(base_dir.to_path_buf());
    let globals = globals::clash_globals();

    let ctx = eval_context::EvalContext::new();
    let module = Module::new();
    {
        let mut eval = Evaluator::new(&module);
        eval.set_loader(&loader);
        eval.extra = Some(&ctx);
        eval.eval_module(ast, &globals)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    let doc = ctx
        .assemble_document()
        .context("failed to assemble policy document")?;
    let json =
        serde_json::to_string_pretty(&doc).context("failed to serialize policy document")?;

    let loaded_files = loader.loaded_files();

    Ok(EvalOutput { json, loaded_files })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn eval_to_doc(source: &str) -> serde_json::Value {
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        serde_json::from_str(&result.json).unwrap()
    }

    #[test]
    fn test_simple_policy() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings")

settings(default = deny())
policy("test", rules = [tool().allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0]["condition"]["observe"], "tool_name");
        assert_eq!(tree[0]["condition"]["pattern"], "wildcard");
    }

    #[test]
    fn test_sandbox_policy() {
        let source = r#"
load("@clash//std.star", "allow", "deny", "match", "tool", "policy", "settings", "sandbox", "cwd")

sandbox(
    name = "test",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True),
    ],
    net = allow(),
)

settings(default = deny())

policy("test",
    rules = match({"Bash": {"git": allow(sandbox="test")}}) + [
        tool().allow(),
    ],
)
"#;
        let doc = eval_to_doc(source);
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_no_policy_errors() {
        let source = "x = 1";
        let result = evaluate(source, "test.star", &PathBuf::from("."));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("policy"),
            "expected error about missing policy(), got: {err}"
        );
    }

    #[test]
    fn test_tool_bindings() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings")

settings(default = deny())
policy("test", rules = [
    tool("WebSearch").allow(),
    tool("Bash").deny(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0]["condition"]["observe"], "tool_name");
        assert_eq!(
            tree[0]["condition"]["pattern"]["literal"]["literal"],
            "WebSearch"
        );
        assert_eq!(
            tree[1]["condition"]["pattern"]["literal"]["literal"],
            "Bash"
        );
    }

    #[test]
    fn test_match_multi_exe() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd")

sandbox(name = "test", default = deny(), fs = [cwd().allow(read = True)])

settings(default = deny())
policy("test",
    rules = match({"Bash": {("rustc", "cargo", "cargo-clippy"): allow(sandbox="test")}}),
)
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        let exe_node = &tree[0]["condition"];
        assert_eq!(exe_node["observe"], "tool_name");
        let children = exe_node["children"].as_array().unwrap();
        assert_eq!(children.len(), 3);
        for child in children {
            assert_eq!(child["condition"]["observe"]["positional_arg"], 0);
        }
    }

    #[test]
    fn test_domains_net() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "domains")

sandbox(
    name = "test",
    default = deny(),
    net = [
        domains({"github.com": allow(), "crates.io": allow()}),
    ],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"cargo": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_home_child() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "home")

sandbox(
    name = "test",
    default = deny(),
    fs = [
        home().child(".ssh").allow(read = True),
    ],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"git": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_wildcard_domain() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "domains")

sandbox(
    name = "test",
    default = deny(),
    net = [domains({"*.npmjs.org": allow()})],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"npm": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_cwd_worktree() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd")

sandbox(
    name = "test",
    default = deny(),
    fs = [cwd(follow_worktrees = True).allow(read = True, write = True)],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"git": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        assert!(!sandboxes.is_empty());
        let test_sandbox = &sandboxes["test"];
        let rules = test_sandbox["rules"].as_array().unwrap();
        assert!(!rules.is_empty());
        assert_eq!(rules[0]["follow_worktrees"], true);
    }

    #[test]
    fn test_cwd_without_worktree_omits_field() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd")

sandbox(
    name = "test",
    default = deny(),
    fs = [cwd().allow(read = True, write = True)],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"git": allow(sandbox="test")}}))
"#,
        );
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        let test_sandbox = &sandboxes["test"];
        let rules = test_sandbox["rules"].as_array().unwrap();
        assert!(!rules.is_empty());
        assert!(rules[0].get("follow_worktrees").is_none());
    }

    #[test]
    fn test_tempdir_path() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "tempdir")

sandbox(name = "test", default = deny(), fs = [tempdir().allow()])

settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_path_static() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "path")

sandbox(
    name = "test",
    default = deny(),
    fs = [path("/usr/local/bin").allow(read = True, execute = True)],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_path_env() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "path")

sandbox(
    name = "test",
    default = deny(),
    fs = [path(env = "CARGO_HOME").allow(read = True, write = True)],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"cargo": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_bare_path_in_sandbox_errors() {
        let source = r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd")

sandbox(name = "test", default = deny(), fs = [cwd()])
settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox="test")}}))
"#;
        let result = evaluate(source, "test.star", &PathBuf::from("."));
        assert!(result.is_err());
    }

    #[test]
    fn test_stdlib_load() {
        let doc = eval_to_doc(
            r#"
load("@clash//rust.star", "rust_sandbox")
load("@clash//std.star", "allow", "deny", "match", "policy", "settings")

settings(default = deny())
policy("test",
    rules = match({"Bash": {("rustc", "cargo"): allow(sandbox=rust_sandbox)}}),
)
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert!(!tree.is_empty());
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_stdlib_all_modules_load() {
        use crate::codegen::ast::{Expr, Stmt};
        use crate::codegen::builder::*;

        for module in &["rust.star", "node.star", "python.star"] {
            let sandbox_name = module.strip_suffix(".star").unwrap().to_string() + "_sandbox";
            let source = crate::codegen::serialize(&[
                Stmt::load(&format!("@clash//{module}"), &[&sandbox_name]),
                Stmt::load(
                    "@clash//std.star",
                    &["allow", "deny", "match", "policy", "settings"],
                ),
                Stmt::Blank,
                Stmt::Expr(settings(deny(), None)),
                Stmt::Expr(policy(
                    "test",
                    deny(),
                    vec![crate::match_tree! {
                        "Bash" => {
                            "test" => allow_with_sandbox(Expr::ident(&sandbox_name)),
                        },
                    }],
                    None,
                )),
            ]);
            let result = evaluate(&source, "test.star", &PathBuf::from("."))
                .unwrap_or_else(|e| panic!("failed to load @clash//{module}: {e}"));
            let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
            assert_eq!(doc["schema_version"], 5, "failed for {module}");
        }
    }

    #[test]
    fn test_relative_load() {
        let dir = tempfile::tempdir().unwrap();
        let helper_path = dir.path().join("helpers.star");
        std::fs::write(
            &helper_path,
            r#"
load("@clash//std.star", "deny", "sandbox", "cwd")

my_sandbox = sandbox(name = "test", default = deny(), fs = [cwd().allow(read = True)])
"#,
        )
        .unwrap();

        let source = r#"
load("helpers.star", "my_sandbox")
load("@clash//std.star", "allow", "deny", "match", "policy", "settings")

settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox=my_sandbox)}}))
"#;
        let result = evaluate(source, "policy.star", dir.path()).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        assert_eq!(doc["schema_version"], 5);
        assert!(!result.loaded_files.is_empty());
    }

    #[test]
    fn test_full_example() {
        let doc = eval_to_doc(
            r#"
load("@clash//rust.star", "rust_sandbox")
load("@clash//std.star", "allow", "deny", "match", "tool", "policy", "settings", "sandbox", "cwd", "home")

sandbox(
    name = "gitbox",
    default = deny(),
    fs = [
        cwd(follow_worktrees = True).allow(read = True, write = True, execute = True),
        home().child(".git").allow(),
        home().child(".ssh").allow(read = True),
    ],
    net = allow(),
)

settings(default = deny())

policy("test", rules = match({
    "Bash": {
        "git": allow(sandbox="gitbox"),
        ("rustc", "cargo"): allow(sandbox=rust_sandbox),
    },
}) + [
    tool().allow(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");

        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2, "expected 2 tree nodes, got {}", tree.len());

        for node in tree {
            assert!(node["condition"].is_object(), "expected condition node");
        }

        let sandboxes = doc["sandboxes"].as_object().unwrap();
        assert!(sandboxes.len() >= 2, "expected >= 2 sandboxes");
    }

    #[test]
    fn test_exe_regex_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "regex", "policy", "settings")

settings(default = deny())
policy("test", rules = match({
    "Bash": {regex("cargo.*"): allow()},
}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let exe_node = &tree[0]["condition"];
        let children = exe_node["children"].as_array().unwrap();
        let pos_arg = &children[0]["condition"];
        assert_eq!(pos_arg["pattern"]["regex"], "cargo.*");
    }

    #[test]
    fn test_exe_any_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "match", "policy", "settings")

settings(default = deny())
policy("test", rules = match({
    "Bash": deny(),
}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let exe_node = &tree[0]["condition"];
        assert_eq!(exe_node["observe"], "tool_name");
        let children = exe_node["children"].as_array().unwrap();
        assert!(
            children[0]["decision"].is_object() || children[0]["decision"].is_string(),
            "expected deny decision directly under ToolName=Bash"
        );
    }

    #[test]
    fn test_tool_regex_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "regex", "policy", "settings")

settings(default = deny())
policy("test", rules = [
    tool(regex("mcp__.*")).ask(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let node = &tree[0]["condition"];
        assert_eq!(node["observe"], "tool_name");
        assert_eq!(node["pattern"]["regex"], "mcp__.*");
        let children = node["children"].as_array().unwrap();
        assert!(
            children[0]["decision"]["ask"].is_null()
                || children[0]["decision"].get("ask").is_some()
        );
    }

    #[test]
    fn test_match_exes_with_regex() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "regex", "policy", "settings")

settings(default = deny())
policy("test", rules = match({
    "Bash": {("git", regex("gh.*")): allow()},
}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let exe_node = &tree[0]["condition"];
        let children = exe_node["children"].as_array().unwrap();
        assert_eq!(children.len(), 2);
        for child in children {
            assert_eq!(child["condition"]["observe"]["positional_arg"], 0);
        }
    }

    #[test]
    fn test_exe_with_args_deny() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "tool", "policy", "settings")

settings(default = deny())
policy("test", rules =
    match({"Bash": {"git": {"push": deny()}}}) +
    match({"Bash": {"git": allow()}}) +
    [tool("Read").allow()],
)
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 3);
        let exe_node = &tree[0]["condition"];
        let pos0 = &exe_node["children"].as_array().unwrap()[0]["condition"];
        assert_eq!(pos0["observe"]["positional_arg"], 0);
        let pos1 = &pos0["children"].as_array().unwrap()[0]["condition"];
        assert_eq!(pos1["observe"]["positional_arg"], 1);
        assert_eq!(pos1["pattern"]["literal"]["literal"], "push");
    }

    // -----------------------------------------------------------------------
    // Match tree builder tests (using match_tree.star directly)
    // -----------------------------------------------------------------------

    #[test]
    fn test_match_tree_simple() {
        let doc = eval_to_doc(
            r#"
load("@clash//match_tree.star", "exe", "tool", "allow", "deny", "policy")

policy(rules = [
    exe("git").allow(),
    tool().allow(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn test_match_tree_nested() {
        let doc = eval_to_doc(
            r#"
load("@clash//match_tree.star", "exe", "has_arg", "allow", "deny", "policy")

policy(rules = [
    exe("git").on([
        has_arg("--force").deny(),
        allow(),
    ]),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        let exe_node = &tree[0]["condition"];
        assert!(exe_node.is_object());
    }

    #[test]
    fn test_match_tree_with_sandbox() {
        let doc = eval_to_doc(
            r#"
load("@clash//match_tree.star", "exe", "tool", "allow", "deny", "policy")

policy(rules = [
    exe("cargo").allow(sandbox = "cwd_access"),
    tool().allow(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn test_match_tree_arg_and_named() {
        let doc = eval_to_doc(
            r#"
load("@clash//match_tree.star", "exe", "arg", "named", "allow", "deny", "policy")

policy(rules = [
    exe("git").on([
        arg(1, "push").deny(),
        allow(),
    ]),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
    }

    #[test]
    fn test_match_tree_load_module() {
        let doc = eval_to_doc(
            r#"
load("@clash//match_tree.star", "exe", "tool", "allow", "deny", "policy", "mt_regex")

policy(rules = [
    exe(mt_regex("cargo.*")).allow(),
    tool().deny(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
    }

    #[test]
    fn test_file_exact_match() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings", "cwd")

settings(default = deny())
policy("test", rules = [
    cwd().file(".env").deny(write = True),
    cwd().allow(read = True, write = True),
    tool().allow(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let fs_op = &tree[0]["condition"];
        assert_eq!(fs_op["observe"], "fs_op");
        let fs_path = &fs_op["children"].as_array().unwrap()[0]["condition"];
        assert_eq!(fs_path["observe"], "fs_path");
        assert!(
            fs_path["pattern"]["literal"].is_object(),
            "expected literal pattern for .file(), got {:?}",
            fs_path["pattern"]
        );
    }

    #[test]
    fn test_file_sandbox_match_type() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd")

sandbox(
    name = "test",
    default = deny(),
    fs = [
        cwd().file("config.json").allow(read = True),
        cwd().allow(read = True),
    ],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox="test")}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let sandbox = &doc["sandboxes"]["test"];
        let rules = sandbox["rules"].as_array().unwrap();
        assert_eq!(rules[0]["path_match"], "literal");
        assert_eq!(rules[1]["path_match"], "literal");
    }

    #[test]
    fn test_tool_on_with_path_entries() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings", "cwd")

settings(default = deny())
policy("test", rules = [
    tool("Glob").on([
        cwd().child("src").allow(read = True),
    ]),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        let tool_node = &tree[0]["condition"];
        assert_eq!(tool_node["observe"], "tool_name");
        let children = tool_node["children"].as_array().unwrap();
        assert!(!children.is_empty());
        assert_eq!(children[0]["condition"]["observe"], "fs_op");
    }

    #[test]
    fn test_tool_on_mixed_children() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings", "cwd")

settings(default = deny())
policy("test", rules = [
    tool("Read").on([
        cwd().file(".env").deny(read = True),
        cwd().allow(read = True),
    ]),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        let tool_node = &tree[0]["condition"];
        let children = tool_node["children"].as_array().unwrap();
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_path_match_with_regex() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings", "cwd", "regex")

settings(default = deny())
policy("test", rules = [
    cwd().match(regex(".*\\.log")).deny(write = True),
    tool().allow(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let fs_op = &tree[0]["condition"];
        let fs_path = &fs_op["children"].as_array().unwrap()[0]["condition"];
        assert!(
            fs_path["pattern"]["regex"].is_string(),
            "expected regex pattern for .match(), got {:?}",
            fs_path["pattern"]
        );
    }

    #[test]
    fn test_docstrings_persist_in_ir() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "tool", "policy", "settings", "sandbox", "cwd")

sandbox(
    name = "dev",
    doc = "Development sandbox",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True, doc = "Project files"),
    ],
)

settings(default = deny(), default_sandbox = "dev")
policy("test", rules = [
    tool("WebSearch", doc = "No external searches").deny(),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);

        let tree = doc["tree"].as_array().unwrap();
        let ws_node = &tree[0]["condition"];
        assert_eq!(
            ws_node["doc"], "No external searches",
            "tool doc should persist on condition"
        );

        let sandbox = &doc["sandboxes"]["dev"];
        assert_eq!(
            sandbox["doc"], "Development sandbox",
            "sandbox doc should persist"
        );

        let rules = sandbox["rules"].as_array().unwrap();
        let cwd_rule = rules
            .iter()
            .find(|r| r["path"].as_str().is_some_and(|p| p.starts_with("$PWD")));
        assert!(cwd_rule.is_some(), "should have a CWD rule");
        assert_eq!(
            cwd_rule.unwrap()["doc"],
            "Project files",
            "sandbox rule doc should persist"
        );
    }

    #[test]
    fn test_sandbox_merge_via_varargs() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd", "home", "tempdir", "domains")

fs_box = sandbox(
    name = "fs",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True),
    ],
)

net_box = sandbox(
    name = "net",
    default = deny(),
    net = [
        domains({"github.com": allow()}),
    ],
)

extra_fs = sandbox(
    name = "extra",
    default = deny(),
    fs = [
        home().child(".cargo").allow(read = True),
        tempdir().allow(),
    ],
)

merged = fs_box.update(net_box).update(extra_fs)

settings(default = deny())
policy("test",
    rules = match({"Bash": {"cargo": allow(sandbox=merged)}}),
)
"#,
        );
        assert_eq!(doc["schema_version"], 5);

        let sandboxes = doc["sandboxes"].as_object().unwrap();
        // Top-level sandbox() calls register all 3, plus merged reference adds "fs"
        // The policy rules sandbox list has "fs" (from merged), but the sandbox_map
        // deduplicates by name. We should have at least fs, net, extra from top-level.
        assert!(
            sandboxes.contains_key("fs"),
            "merged sandbox should keep first name"
        );

        let sb = &sandboxes["fs"];
        assert_ne!(
            sb["network"], "deny",
            "merged sandbox should have network from net_box"
        );

        let rules = sb["rules"].as_array().unwrap();
        let paths: Vec<&str> = rules.iter().filter_map(|r| r["path"].as_str()).collect();
        assert!(paths.iter().any(|p| p.starts_with("$PWD")));
        assert!(paths.iter().any(|p| p.contains(".cargo")));
        assert!(paths.iter().any(|p| p.starts_with("$TMPDIR")));
    }

    #[test]
    fn test_os_and_arch_constants() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "policy", "settings", "tool", "OS", "ARCH")

def _check():
    if not OS or not ARCH:
        fail("OS and ARCH must be non-empty")

_check()

settings(default = deny())
policy("test", rules = [tool().allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
    }

    #[test]
    fn test_os_matches_rust_const() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd", "OS")

sandbox(
    name = "test",
    default = deny(),
    fs = [cwd().allow(read = True)],
    doc = OS,
)

settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox="test")}}))
"#,
        );
        let sandbox = &doc["sandboxes"]["test"];
        assert_eq!(
            sandbox["doc"].as_str().unwrap(),
            std::env::consts::OS,
            "Starlark OS should match std::env::consts::OS"
        );
    }

    #[test]
    fn test_sandbox_auto_inject_platform_home_deny() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "match", "policy", "settings", "sandbox", "cwd")

sandbox(
    name = "test",
    default = deny(),
    fs = [cwd().allow(read = True)],
)

settings(default = deny())
policy("test", rules = match({"Bash": {"test": allow(sandbox="test")}}))
"#,
        );
        let sandbox = &doc["sandboxes"]["test"];
        let rules = sandbox["rules"].as_array().unwrap();
        let deny_paths: Vec<&str> = rules
            .iter()
            .filter(|r| r["effect"].as_str() == Some("deny"))
            .filter_map(|r| r["path"].as_str())
            .collect();

        let expected_home = if std::env::consts::OS == "macos" {
            "/Users"
        } else {
            "/home"
        };

        assert!(
            deny_paths.contains(&expected_home),
            "sandbox should deny {expected_home} on {}, got deny paths: {deny_paths:?}",
            std::env::consts::OS,
        );

        let wrong_home = if std::env::consts::OS == "macos" {
            "/home"
        } else {
            "/Users"
        };
        assert!(
            !deny_paths.contains(&wrong_home),
            "sandbox should NOT deny {wrong_home} on {}",
            std::env::consts::OS,
        );
    }
}
