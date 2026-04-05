//! Starlark policy evaluator for Clash.
//!
//! Evaluates `.star` policy files and compiles them to JSON `PolicyDocument` format.
//! This crate has no dependency on the `clash` crate — it outputs a JSON string
//! that the existing compile pipeline consumes.

mod builders;
pub mod codegen;
pub mod eval_context;
mod globals;
mod loader;
pub mod stdlib;
mod when;

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
    // Pre-inject std.star exports so users don't need load("@clash//std.star", ...).
    loader
        .inject_std(&module)
        .map_err(|e| anyhow::anyhow!("failed to load stdlib: {e}"))?;
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
    let json = serde_json::to_string_pretty(&doc).context("failed to serialize policy document")?;

    let loaded_files = loader.loaded_files();

    Ok(EvalOutput { json, loaded_files })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn eval_to_doc(source: &str) -> serde_json::Value {
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        serde_json::from_str(&result.json).unwrap()
    }

    #[test]
    fn test_simple_policy() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test", rules = when({None: allow()}))
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
    fn test_implicit_stdlib() {
        // No load() needed — std.star symbols are pre-injected
        let doc = eval_to_doc(
            r#"
settings(default = deny())
policy("test", rules = when({None: allow()}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");
        assert_eq!(doc["tree"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_policy_dict_with_mode() {
        let doc = eval_to_doc(
            r#"
_box = sandbox(name = "dev", fs = {subpath("$PWD"): allow("rwc")})

settings(default = deny())
policy("test", {
    mode("plan"): allow(sandbox = _box),
    mode("edit"): allow(sandbox = _box),
})
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2, "expected 2 mode rules");
        // Both should be mode conditions
        assert_eq!(tree[0]["condition"]["observe"], "mode");
        assert_eq!(tree[1]["condition"]["observe"], "mode");
        // Should have the sandbox
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_policy_dict_tuple_mode_keys_with_glob() {
        let doc = eval_to_doc(
            r#"
_box = sandbox(name = "dev", fs = {subpath("$PWD"): allow("rwc")})

settings(default = deny())
policy("test", {
    mode("plan"): {
        glob("**"): allow(sandbox = _box),
    },
    (mode("edit"), mode("default")): {
        glob("**"): allow(sandbox = _box),
    },
})
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        // 3 mode rules: plan, edit, default
        assert_eq!(tree.len(), 3, "expected 3 mode rules, got: {tree:?}");
    }

    #[test]
    fn test_policy_roundtrip_via_canonicalize() {
        // Simulates the TUI path: parse .star → canonicalize → serialize → re-evaluate
        let source = r#"load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "project", "workspace")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
        },
        (mode("edit"), mode("default")): {
            glob("**"): allow(sandbox=project),
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
"#;
        let doc =
            crate::codegen::StarDocument::from_source(source.into(), "test.star".into()).unwrap();
        let canonical = doc.to_source();
        eprintln!("canonical:\n{canonical}");
        let json = doc
            .evaluate_to_json()
            .expect("evaluate_to_json should succeed after canonicalize");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["schema_version"], 5);
    }

    #[test]
    fn test_policy_with_builtins_and_glob_dict() {
        let doc = eval_to_doc(
            r#"
load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "project", "workspace")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
        },
        (mode("edit"), mode("default")): {
            glob("**"): allow(sandbox=project),
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert!(
            tree.len() >= 4,
            "expected at least 4 mode rules, got {}",
            tree.len()
        );
    }

    #[test]
    fn test_sandbox_policy() {
        let source = r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True),
    ],
    net = allow(),
)

settings(default = deny())

policy("test",
    rules = when({"Bash": {"git": allow(sandbox=_box)}}) +
        when({None: allow()}),
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
load("@clash//std.star", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test", rules =
    when({"WebSearch": allow()}) +
    when({"Bash": deny()}),
)
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(name = "test", default = deny(), fs = [cwd().allow(read = True)])

settings(default = deny())
policy("test",
    rules = when({"Bash": {("rustc", "cargo", "cargo-clippy"): allow(sandbox=_box)}}),
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "domains")

_box = sandbox(
    name = "test",
    default = deny(),
    net = [
        domains({"github.com": allow(), "crates.io": allow()}),
    ],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"cargo": allow(sandbox=_box)}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_home_child() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "home")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [
        home().child(".ssh").allow(read = True),
    ],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"git": allow(sandbox=_box)}}))
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "domains")

_box = sandbox(
    name = "test",
    default = deny(),
    net = [domains({"*.npmjs.org": allow()})],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"npm": allow(sandbox=_box)}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_cwd_worktree() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [cwd(follow_worktrees = True).allow(read = True, write = True)],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"git": allow(sandbox=_box)}}))
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [cwd().allow(read = True, write = True)],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"git": allow(sandbox=_box)}}))
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "tempdir")

_box = sandbox(name = "test", default = deny(), fs = [tempdir().allow()])

settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=_box)}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_path_static() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "path")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [path("/usr/local/bin").allow(read = True, execute = True)],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=_box)}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_path_env() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "path")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [path(env = "CARGO_HOME").allow(read = True, write = True)],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"cargo": allow(sandbox=_box)}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_bare_path_in_sandbox_errors() {
        let source = r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(name = "test", default = deny(), fs = [cwd()])
settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=_box)}}))
"#;
        let result = evaluate(source, "test.star", &PathBuf::from("."));
        assert!(result.is_err());
    }

    #[test]
    fn test_stdlib_load() {
        let doc = eval_to_doc(
            r#"
load("@clash//rust.star", "rust_full")
load("@clash//std.star", "allow", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test",
    rules = when({"Bash": {("rustc", "cargo"): allow(sandbox=rust_full)}}),
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
            let sandbox_name = module.strip_suffix(".star").unwrap().to_string() + "_full";
            let source = crate::codegen::serialize(&[
                Stmt::load(&format!("@clash//{module}"), &[&sandbox_name]),
                Stmt::load(
                    "@clash//std.star",
                    &["allow", "deny", "when", "policy", "settings"],
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=my_sandbox)}}))
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
load("@clash//rust.star", "rust_full")
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd", "home")

_box = sandbox(
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

policy("test", rules = when({
    "Bash": {
        "git": allow(sandbox=_box),
        ("rustc", "cargo"): allow(sandbox=rust_full),
    },
}) +
    when({None: allow()}),
)
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");

        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2, "expected 2 tree nodes, got {}", tree.len());

        let sandboxes = doc["sandboxes"].as_object().unwrap();
        assert!(sandboxes.len() >= 2, "expected >= 2 sandboxes");
    }

    #[test]
    fn test_exe_regex_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "regex", "policy", "settings")

settings(default = deny())
policy("test", rules = when({
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
load("@clash//std.star", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test", rules = when({
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
load("@clash//std.star", "deny", "when", "regex", "policy", "settings")

settings(default = deny())
policy("test", rules = when({
    regex("mcp__.*"): ask(),
}))
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
load("@clash//std.star", "allow", "deny", "when", "regex", "policy", "settings")

settings(default = deny())
policy("test", rules = when({
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test", rules =
    when({"Bash": {"git": {"push": deny()}}}) +
    when({"Bash": {"git": allow()}}) +
    when({"Read": allow()}),
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

    #[test]
    fn test_file_exact_match() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "policy", "settings", "cwd")

settings(default = deny())
policy("test", rules = [
    cwd().file(".env").deny(write = True),
    cwd().allow(read = True, write = True),
] + when({None: allow()}))
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [
        cwd().file("config.json").allow(read = True),
        cwd().allow(read = True),
    ],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=_box)}}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let sandbox = &doc["sandboxes"]["test"];
        let rules = sandbox["rules"].as_array().unwrap();
        assert_eq!(rules[0]["path_match"], "literal");
        assert_eq!(rules[1]["path_match"], "literal");
    }

    #[test]
    fn test_tool_with_path_entries() {
        // Tool-scoped path rules: a match dict + path rules in the policy
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "when", "policy", "settings", "cwd")

settings(default = deny())
policy("test", rules = when({"Glob": allow()}) + [
    cwd().child("src").allow(read = True),
])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        // Tool rule + fs rule = 2 top-level nodes
        assert_eq!(tree.len(), 2);
        let tool_node = &tree[0]["condition"];
        assert_eq!(tool_node["observe"], "tool_name");
        let fs_node = &tree[1]["condition"];
        assert_eq!(fs_node["observe"], "fs_op");
    }

    #[test]
    fn test_mixed_path_children() {
        // Multiple path rules in the policy (deny .env, allow cwd)
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "when", "policy", "settings", "cwd")

settings(default = deny())
policy("test", rules = [
    cwd().file(".env").deny(read = True),
    cwd().allow(read = True),
] + when({"Read": allow()}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        // fs deny + fs allow + tool allow = 3 nodes
        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_path_match_with_regex() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "policy", "settings", "cwd", "regex")

settings(default = deny())
policy("test", rules = [
    cwd().match(regex(".*\\.log")).deny(write = True),
] + when({None: allow()}))
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
load("@clash//std.star", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(
    name = "dev",
    doc = "Development sandbox",
    default = deny(),
    fs = [
        cwd().allow(read = True, write = True, doc = "Project files"),
    ],
)

settings(default = deny(), default_sandbox = _box)
policy("test", rules = when({
    "WebSearch": deny(),
}), default_sandbox = _box)
"#,
        );
        assert_eq!(doc["schema_version"], 5);

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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd", "home", "tempdir", "domains")

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
    rules = when({"Bash": {"cargo": allow(sandbox=merged)}}),
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
load("@clash//std.star", "deny", "policy", "settings", "OS", "ARCH")

def _check():
    if not OS or not ARCH:
        fail("OS and ARCH must be non-empty")

_check()

settings(default = deny())
policy("test", rules = when({None: allow()}))
"#,
        );
        assert_eq!(doc["schema_version"], 5);
    }

    #[test]
    fn test_os_matches_rust_const() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd", "OS")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [cwd().allow(read = True)],
    doc = OS,
)

settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=_box)}}))
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
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "cwd")

_box = sandbox(
    name = "test",
    default = deny(),
    fs = [cwd().allow(read = True)],
)

settings(default = deny())
policy("test", rules = when({"Bash": {"test": allow(sandbox=_box)}}))
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

    #[test]
    fn settings_on_sandbox_violation() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox")

_box = sandbox(name="box", default=deny())
settings(default=deny(), on_sandbox_violation="workaround")
policy("test", when({"Bash": allow(sandbox=_box)}))
"#,
        );
        assert_eq!(doc["on_sandbox_violation"], "workaround");
    }

    #[test]
    fn settings_on_sandbox_violation_defaults_to_absent() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "deny", "when", "policy", "settings")

settings(default=deny())
policy("test", when({"Bash": deny()}))
"#,
        );
        assert!(doc.get("on_sandbox_violation").is_none());
    }

    #[test]
    fn settings_on_sandbox_violation_invalid_value() {
        let source = r#"
load("@clash//std.star", "deny", "when", "policy", "settings")

settings(default=deny(), on_sandbox_violation="invalid")
policy("test", when({"Bash": deny()}))
"#;
        let result = evaluate(source, "test.star", &PathBuf::from("."));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("on_sandbox_violation"),
            "expected error about on_sandbox_violation, got: {err}"
        );
    }

    #[test]
    fn settings_harness_defaults_false() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "policy", "settings")
settings(default=allow(), harness_defaults=False)
policy("test", rules=[])
"#,
        );
        assert_eq!(doc["harness_defaults"], serde_json::json!(false));
    }

    #[test]
    fn settings_harness_defaults_default_is_true() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "policy", "settings")
settings(default=allow())
policy("test", rules=[])
"#,
        );
        // When not specified, harness_defaults should not appear (defaults to true at runtime)
        assert!(doc.get("harness_defaults").is_none());
    }

    #[test]
    fn test_sandbox_localhost_ports() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "localhost")

_box = sandbox(
    name = "local_only",
    default = deny(),
    net = localhost(ports = [8080, 3000]),
)

settings(default = deny())
policy("test",
    rules = when({"Bash": {"curl": allow(sandbox = _box)}}),
)
"#,
        );
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        let sb = &sandboxes["local_only"];
        let network = &sb["network"];
        assert_eq!(network, &json!({"localhost": [8080, 3000]}));
    }

    #[test]
    fn test_sandbox_localhost_no_ports() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "allow", "deny", "when", "policy", "settings", "sandbox", "localhost")

_box = sandbox(
    name = "local_only",
    default = deny(),
    net = localhost(),
)

settings(default = deny())
policy("test",
    rules = when({"Bash": {"curl": allow(sandbox = _box)}}),
)
"#,
        );
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        let sb = &sandboxes["local_only"];
        assert_eq!(sb["network"], json!("localhost"));
    }

    #[test]
    fn test_git_safe_has_gh_config() {
        let doc = eval_to_doc(
            r#"
load("@clash//sandboxes.star", "git_safe")
load("@clash//std.star", "allow", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test",
    rules = when({"Bash": {"git": allow(sandbox=git_safe)}}),
)
"#,
        );
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        let sb = &sandboxes["git_safe"];
        let rules = sb["rules"].as_array().unwrap();
        let gh_rule = rules.iter().find(|r| {
            r["path"]
                .as_str()
                .map_or(false, |p| p.contains(".config/gh"))
        });
        assert!(
            gh_rule.is_some(),
            "git_safe sandbox should include .config/gh/** rule, got: {rules:?}"
        );
    }

    #[test]
    fn test_git_full_has_gh_config() {
        let doc = eval_to_doc(
            r#"
load("@clash//sandboxes.star", "git_full")
load("@clash//std.star", "allow", "deny", "when", "policy", "settings")

settings(default = deny())
policy("test",
    rules = when({"Bash": {"git": allow(sandbox=git_full)}}),
)
"#,
        );
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        let sb = &sandboxes["git_full"];
        let rules = sb["rules"].as_array().unwrap();
        let gh_rule = rules.iter().find(|r| {
            r["path"]
                .as_str()
                .map_or(false, |p| p.contains(".config/gh"))
        });
        assert!(
            gh_rule.is_some(),
            "git_full sandbox should include .config/gh/** rule, got: {rules:?}"
        );
    }
}
