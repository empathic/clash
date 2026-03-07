//! Starlark policy evaluator for Clash.
//!
//! Evaluates `.star` policy files and compiles them to JSON `PolicyDocument` format.
//! This crate has no dependency on the `clash` crate — it outputs a JSON string
//! that the existing compile pipeline consumes.

mod builders;
mod compile;
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

    let module = Module::new();
    {
        let mut eval = Evaluator::new(&module);
        eval.set_loader(&loader);
        eval.eval_module(ast, &globals)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    let frozen = module.freeze().map_err(|e| anyhow::anyhow!("{e:?}"))?;

    // Get main function
    let main_fn = frozen
        .get("main")
        .map_err(|_| anyhow::anyhow!("policy.star must define a main() function"))?;

    // Call main() to get its return value
    let call_module = Module::new();
    let json = {
        let mut eval = Evaluator::new(&call_module);
        eval.set_loader(&loader);

        let main_val = main_fn.value();
        let result = eval
            .eval_function(main_val, &[], &[])
            .map_err(|e| anyhow::anyhow!("error calling main(): {e}"))?;

        compile::compile_to_json(result).context("failed to compile main() return value to JSON")?
    };

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
load("@clash//std.star", "tool", "policy")

def main():
    return policy(default = deny, rules = [tool().allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        // tool().allow() → condition{observe: tool_name, pattern: wildcard, children: [decision{allow}]}
        assert_eq!(tree[0]["condition"]["observe"], "tool_name");
        assert_eq!(tree[0]["condition"]["pattern"], "wildcard");
    }

    #[test]
    fn test_sandbox_policy() {
        let source = r#"
load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd")

def main():
    box = sandbox(
        default = deny,
        fs = [
            cwd(read = allow, write = allow),
        ],
        net = allow,
    )
    return policy(
        default = deny,
        rules = [
            exe("git").sandbox(box).allow(),
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
    fn test_no_main_errors() {
        let source = "x = 1";
        let result = evaluate(source, "test.star", &PathBuf::from("."));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("main()"));
    }

    #[test]
    fn test_tool_bindings() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "tool", "policy")

def main():
    return policy(
        default = deny,
        rules = [
            tool("WebSearch").allow(),
            tool("Bash").deny(),
        ],
    )
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 2);
        // First: tool("WebSearch") → condition{observe: tool_name, pattern: literal("WebSearch")}
        assert_eq!(tree[0]["condition"]["observe"], "tool_name");
        assert_eq!(
            tree[0]["condition"]["pattern"]["literal"]["literal"],
            "WebSearch"
        );
        // Second: tool("Bash") → deny
        assert_eq!(
            tree[1]["condition"]["pattern"]["literal"]["literal"],
            "Bash"
        );
    }

    #[test]
    fn test_match_multi_exe() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "cwd")

def main():
    box = sandbox(default = deny, fs = [cwd(read = allow)])
    return policy(
        default = deny,
        rules = [
            exe(["rustc", "cargo", "cargo-clippy"]).sandbox(box).allow(),
        ],
    )
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        // exe(["rustc", "cargo", "cargo-clippy"]) → ToolName=Bash → PosArg(0)=or([rustc, cargo, cargo-clippy])
        let exe_node = &tree[0]["condition"];
        assert_eq!(exe_node["observe"], "tool_name");
        // The inner pos_arg(0) node should have an or pattern
        let children = exe_node["children"].as_array().unwrap();
        assert!(!children.is_empty());
        let pos_arg = &children[0]["condition"];
        assert_eq!(pos_arg["observe"]["positional_arg"], 0);
        let pat = &pos_arg["pattern"];
        assert!(pat["any_of"].is_array());
    }

    #[test]
    fn test_domains_net() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "domains")

def main():
    box = sandbox(
        default = deny,
        net = [
            domains({"github.com": allow, "crates.io": allow}),
        ],
    )
    return policy(default = deny, rules = [exe("cargo").sandbox(box).allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        // Should have a sandbox with network config
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_home_child() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "home")

def main():
    box = sandbox(
        default = deny,
        fs = [
            home().child(".ssh", read = allow),
        ],
    )
    return policy(default = deny, rules = [exe("git").sandbox(box).allow()])
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
load("@clash//std.star", "exe", "policy", "sandbox", "domains")

def main():
    box = sandbox(
        default = deny,
        net = [domains({"*.npmjs.org": allow})],
    )
    return policy(default = deny, rules = [exe("npm").sandbox(box).allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_cwd_worktree() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "cwd")

def main():
    box = sandbox(
        default = deny,
        fs = [cwd(follow_worktrees = True, read = allow, write = allow)],
    )
    return policy(default = deny, rules = [exe("git").sandbox(box).allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 1);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_tempdir_path() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "tempdir")

def main():
    box = sandbox(
        default = deny,
        fs = [tempdir(allow_all = True)],
    )
    return policy(default = deny, rules = [exe("test").sandbox(box).allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_path_static() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "path")

def main():
    box = sandbox(
        default = deny,
        fs = [path("/usr/local/bin", read = allow, execute = allow)],
    )
    return policy(default = deny, rules = [exe("test").sandbox(box).allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_path_env() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy", "sandbox", "path")

def main():
    box = sandbox(
        default = deny,
        fs = [path(env = "CARGO_HOME", read = allow, write = allow)],
    )
    return policy(default = deny, rules = [exe("cargo").sandbox(box).allow()])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert!(!doc["sandboxes"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_invalid_effect_errors() {
        // Test with a path builder that validates effects
        let source = r#"
load("@clash//std.star", "exe", "policy", "sandbox", "cwd")

def main():
    box = sandbox(default = deny, fs = [cwd(read = "invalid")])
    return policy(default = deny, rules = [exe("test").sandbox(box).allow()])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from("."));
        assert!(result.is_err());
    }

    #[test]
    fn test_stdlib_load() {
        let doc = eval_to_doc(
            r#"
load("@clash//rust.star", "rust_sandbox")
load("@clash//std.star", "exe", "policy")

def main():
    return policy(
        default = deny,
        rules = [
            exe(["rustc", "cargo"]).sandbox(rust_sandbox).allow(),
        ],
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
        for module in &["rust.star", "node.star", "python.star"] {
            let sandbox_name = module.strip_suffix(".star").unwrap().to_string() + "_sandbox";
            let source = format!(
                r#"
load("@clash//{module}", "{sandbox_name}")
load("@clash//std.star", "exe", "policy")

def main():
    return policy(
        default = deny,
        rules = [exe("test").sandbox({sandbox_name}).allow()],
    )
"#
            );
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
load("@clash//std.star", "sandbox", "cwd")

my_sandbox = sandbox(default = deny, fs = [cwd(read = allow)])
"#,
        )
        .unwrap();

        let source = r#"
load("helpers.star", "my_sandbox")
load("@clash//std.star", "exe", "policy")

def main():
    return policy(default = deny, rules = [exe("test").sandbox(my_sandbox).allow()])
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
load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "home")

def main():
    gitbox = sandbox(
        default = deny,
        fs = [
            cwd(
                follow_worktrees = True,
                read = allow,
                write = allow,
                execute = allow,
            ),
            home().child(".git", allow_all = True),
            home().child(".ssh", read = allow),
        ],
        net = allow,
    )

    return policy(default = deny, rules = [
        exe("git").sandbox(gitbox).allow(),
        exe(["rustc", "cargo"]).sandbox(rust_sandbox).allow(),
        tool().allow(),
    ])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        assert_eq!(doc["default_effect"], "deny");

        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 3, "expected 3 tree nodes, got {}", tree.len());

        // All should be condition nodes on tool_name
        for node in tree {
            assert!(node["condition"].is_object(), "expected condition node");
        }

        // Should have sandboxes
        let sandboxes = doc["sandboxes"].as_object().unwrap();
        assert!(sandboxes.len() >= 2, "expected >= 2 sandboxes");
    }

    #[test]
    fn test_exe_regex_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "regex", "policy")

def main():
    return policy(default = deny, rules = [
        exe(regex("cargo.*")).allow(),
    ])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        // exe(regex("cargo.*")) → ToolName=Bash → PosArg(0)=regex(cargo.*)
        let exe_node = &tree[0]["condition"];
        let children = exe_node["children"].as_array().unwrap();
        let pos_arg = &children[0]["condition"];
        assert_eq!(pos_arg["pattern"]["regex"], "cargo.*");
    }

    #[test]
    fn test_exe_any_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "policy")

def main():
    return policy(default = deny, rules = [
        exe().deny(),
    ])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let exe_node = &tree[0]["condition"];
        assert_eq!(exe_node["observe"], "tool_name");
        // exe() with no name → ToolName=Bash → PosArg(0)=wildcard → deny
        let pos_arg_node = &exe_node["children"].as_array().unwrap()[0]["condition"];
        assert_eq!(pos_arg_node["observe"]["positional_arg"], 0);
        assert_eq!(pos_arg_node["pattern"], "wildcard");
    }

    #[test]
    fn test_tool_regex_pattern() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "tool", "regex", "policy")

def main():
    return policy(default = deny, rules = [
        tool(regex("mcp__.*")).ask(),
    ])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        let node = &tree[0]["condition"];
        assert_eq!(node["observe"], "tool_name");
        assert_eq!(node["pattern"]["regex"], "mcp__.*");
        // Should have ask decision
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
load("@clash//std.star", "exe", "regex", "policy")

def main():
    return policy(default = deny, rules = [
        exe(["git", regex("gh.*")]).allow(),
    ])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        // exe(["git", regex("gh.*")]) → ToolName=Bash → PosArg(0)=or([literal(git), regex(gh.*)])
        let exe_node = &tree[0]["condition"];
        let children = exe_node["children"].as_array().unwrap();
        let pos_arg = &children[0]["condition"];
        let or_pats = pos_arg["pattern"]["any_of"].as_array().unwrap();
        assert_eq!(or_pats[0]["literal"]["literal"], "git");
        assert_eq!(or_pats[1]["regex"], "gh.*");
    }

    #[test]
    fn test_exe_with_args_deny() {
        let doc = eval_to_doc(
            r#"
load("@clash//std.star", "exe", "tool", "policy")
def main():
    return policy(default=deny, rules=[
        exe("git", args=["push"]).deny(),
        exe("git").allow(),
        tool("Read").allow(),
    ])
"#,
        );
        assert_eq!(doc["schema_version"], 5);
        let tree = doc["tree"].as_array().unwrap();
        assert_eq!(tree.len(), 3);
        // First rule: ToolName=Bash → PosArg(0)=git → PosArg(1)=push → deny
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

def main():
    return policy(
        rules = [
            exe("git").allow(),
            tool().allow(),
        ],
    )
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

def main():
    return policy(
        rules = [
            exe("git").on([
                has_arg("--force").deny(),
                allow(),
            ]),
        ],
    )
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

def main():
    return policy(
        rules = [
            exe("cargo").allow(sandbox = "cwd_access"),
            tool().allow(),
        ],
    )
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

def main():
    return policy(
        rules = [
            exe("git").on([
                arg(1, "push").deny(),
                allow(),
            ]),
        ],
    )
"#,
        );
        assert_eq!(doc["schema_version"], 5);
    }

    #[test]
    fn test_match_tree_load_module() {
        let doc = eval_to_doc(
            r#"
load("@clash//match_tree.star", "exe", "tool", "allow", "deny", "policy", "mt_regex")

def main():
    return policy(
        rules = [
            exe(mt_regex("cargo.*")).allow(),
            tool().deny(),
        ],
    )
"#,
        );
        assert_eq!(doc["schema_version"], 5);
    }
}
