//! Starlark policy evaluator for Clash.
//!
//! Evaluates `.star` policy files and compiles them to JSON `PolicyDocument` format.
//! This crate has no dependency on the `clash` crate — it outputs a JSON string
//! that the existing compile pipeline consumes.

mod builders;
mod cache;
mod compile;
mod globals;
mod import_json;
mod loader;
pub mod stdlib;

use std::path::Path;

use anyhow::{Context, Result};

pub use cache::StarCache;

/// Output from evaluating a `.star` policy file.
#[derive(Debug, Clone)]
pub struct EvalOutput {
    /// The compiled JSON policy document.
    pub json: String,
    /// Paths of all files loaded during evaluation (for cache invalidation).
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

    #[test]
    fn test_simple_policy() {
        let source = r#"
load("@clash//std.star", "tool")

def main():
    return policy(default = deny, rules = [tool().allow()])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        assert_eq!(doc["schema_version"], 4);
        assert_eq!(doc["use"], "main");
        assert_eq!(doc["default_effect"], "deny");
    }

    #[test]
    fn test_sandbox_policy() {
        let source = r#"
load("@clash//std.star", "exe", "tool")

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
            exe("git").allow().sandbox(box),
            tool().allow(),
        ],
    )
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let policies = doc["policies"].as_array().unwrap();
        // Should have a sandbox policy + main
        assert!(policies.len() >= 2);
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
        let source = r#"
load("@clash//std.star", "tool")

def main():
    return policy(
        default = deny,
        rules = [
            tool("WebSearch").allow(),
            tool("Bash").deny(),
        ],
    )
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let main_body = &doc["policies"][0]["body"];
        assert_eq!(main_body.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_match_multi_exe() {
        let source = r#"
load("@clash//std.star", "match_exes")

def main():
    box = sandbox(default = deny, fs = [cwd(read = allow)])
    return policy(
        default = deny,
        rules = [
            match_exes(["rustc", "cargo", "cargo-clippy"]).allow().sandbox(box),
        ],
    )
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        // Check that the exec rule has an "or" pattern
        let main_pol = doc["policies"].as_array().unwrap().last().unwrap();
        let rule = &main_pol["body"][0]["rule"];
        assert!(rule["exec"]["bin"]["or"].is_array());
    }

    #[test]
    fn test_extend_pattern() {
        let source = r#"
load("@clash//std.star", "exe", "tool")

def main():
    base = policy(default = deny, rules = [tool().allow()])
    base = base.extend(exe("git").allow())
    return base
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let main_body = doc["policies"][0]["body"].as_array().unwrap();
        assert_eq!(main_body.len(), 2); // tool().allow() + exe
    }

    #[test]
    fn test_domains_net() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        net = [
            domains({"github.com": allow, "crates.io": allow}),
        ],
    )
    return policy(default = deny, rules = [exe("cargo").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        // Should have a sandbox with net rules
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        let net_rules: Vec<_> = body
            .iter()
            .filter(|r| r["rule"]["net"].is_object())
            .collect();
        assert_eq!(net_rules.len(), 2);
    }

    #[test]
    fn test_home_child() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        fs = [
            home().child(".ssh", read = allow),
        ],
    )
    return policy(default = deny, rules = [exe("git").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        // The sandbox should have an fs rule with a join path
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        assert!(!body.is_empty());
    }

    #[test]
    fn test_import_json_and_extend() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("base.json");
        std::fs::write(
            &json_path,
            r#"{
            "schema_version": 4,
            "use": "main",
            "default_effect": "deny",
            "policies": [
                {"name": "main", "body": [
                    {"rule": {"effect": "allow", "tool": {"name": {"any": null}}}}
                ]}
            ]
        }"#,
        )
        .unwrap();

        let source = format!(
            r#"
load("@clash//std.star", "exe")

def main():
    base = import_json("{}")
    base = base.extend(exe("git").allow())
    return base
"#,
            json_path.display()
        );

        let result = evaluate(&source, "test.star", dir.path()).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let main_body = doc["policies"].as_array().unwrap().last().unwrap();
        let body = main_body["body"].as_array().unwrap();
        // Should have tool rule from base + exe rule from extend
        assert_eq!(body.len(), 2);
    }

    #[test]
    fn test_wildcard_domain() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        net = [domains({"*.npmjs.org": allow})],
    )
    return policy(default = deny, rules = [exe("npm").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        let net_rule = &body[0]["rule"]["net"]["domain"];
        // Wildcard should be compiled to a regex
        assert!(net_rule["regex"].is_string());
    }

    #[test]
    fn test_cwd_worktree() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        fs = [cwd(follow_worktrees = True, read = allow, write = allow)],
    )
    return policy(default = deny, rules = [exe("git").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        // Check worktree flag is set
        let fs_rule = &body[0]["rule"]["fs"]["path"]["subpath"];
        assert_eq!(fs_rule["worktree"], true);
    }

    #[test]
    fn test_tempdir_path() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        fs = [tempdir(allow_all = True)],
    )
    return policy(default = deny, rules = [exe("test").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        assert!(!body.is_empty());
        // Should reference TMPDIR env
        let path = &body[0]["rule"]["fs"]["path"]["subpath"]["path"];
        assert_eq!(path["env"], "TMPDIR");
    }

    #[test]
    fn test_path_static() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        fs = [path("/usr/local/bin", read = allow, execute = allow)],
    )
    return policy(default = deny, rules = [exe("test").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        assert!(!body.is_empty());
    }

    #[test]
    fn test_path_env() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(
        default = deny,
        fs = [path(env = "CARGO_HOME", read = allow, write = allow)],
    )
    return policy(default = deny, rules = [exe("cargo").allow().sandbox(box)])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let sandbox_pol = &doc["policies"][0];
        let body = sandbox_pol["body"].as_array().unwrap();
        let path = &body[0]["rule"]["fs"]["path"]["subpath"]["path"];
        assert_eq!(path["env"], "CARGO_HOME");
    }

    #[test]
    fn test_invalid_effect_errors() {
        let source = r#"
def main():
    return policy(default = "invalid", rules = [])
"#;
        // "invalid" is not an effect constant, it's a raw string
        let _result = evaluate(source, "test.star", &PathBuf::from("."));
        // Test with a path builder that validates effects
        let source2 = r#"
load("@clash//std.star", "exe")

def main():
    box = sandbox(default = deny, fs = [cwd(read = "invalid")])
    return policy(default = deny, rules = [exe("test").allow().sandbox(box)])
"#;
        let result2 = evaluate(source2, "test2.star", &PathBuf::from("."));
        assert!(result2.is_err());
    }

    #[test]
    fn test_stdlib_load() {
        let source = r#"
load("@clash//rust.star", "rust_sandbox")
load("@clash//std.star", "match_exes")

def main():
    return policy(
        default = deny,
        rules = [
            match_exes(["rustc", "cargo"]).allow().sandbox(rust_sandbox),
        ],
    )
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        assert_eq!(doc["schema_version"], 4);
        // Should have sandbox + main policies
        assert!(doc["policies"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn test_stdlib_all_modules_load() {
        for module in &["rust.star", "node.star", "python.star"] {
            let sandbox_name = module.strip_suffix(".star").unwrap().to_string() + "_sandbox";
            let source = format!(
                r#"
load("@clash//{module}", "{sandbox_name}")
load("@clash//std.star", "exe")

def main():
    return policy(
        default = deny,
        rules = [exe("test").allow().sandbox({sandbox_name})],
    )
"#
            );
            let result = evaluate(&source, "test.star", &PathBuf::from("."))
                .unwrap_or_else(|e| panic!("failed to load @clash//{module}: {e}"));
            let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
            assert_eq!(doc["schema_version"], 4, "failed for {module}");
        }
    }

    #[test]
    fn test_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = StarCache::at(dir.path().to_path_buf());

        let key = StarCache::cache_key("test source", &[]);
        assert!(cache.get(&key).is_none());

        cache.put(&key, r#"{"test": true}"#).unwrap();
        assert_eq!(cache.get(&key).unwrap(), r#"{"test": true}"#);
    }

    #[test]
    fn test_relative_load() {
        let dir = tempfile::tempdir().unwrap();
        let helper_path = dir.path().join("helpers.star");
        std::fs::write(
            &helper_path,
            r#"
my_sandbox = sandbox(default = deny, fs = [cwd(read = allow)])
"#,
        )
        .unwrap();

        let source = r#"
load("helpers.star", "my_sandbox")
load("@clash//std.star", "exe")

def main():
    return policy(default = deny, rules = [exe("test").allow().sandbox(my_sandbox)])
"#;
        let result = evaluate(source, "policy.star", dir.path()).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        assert_eq!(doc["schema_version"], 4);
        // loaded_files should include helpers.star
        assert!(!result.loaded_files.is_empty());
    }

    #[test]
    fn test_full_example_from_plan() {
        let source = r#"
load("@clash//rust.star", "rust_sandbox")
load("@clash//std.star", "exe", "tool", "match_exes")

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

    base = policy(default = deny, rules = [])
    base = base.extend(exe("git").allow().sandbox(gitbox))
    base = base.extend(match_exes(["rustc", "cargo"]).allow().sandbox(rust_sandbox))
    base = base.extend(tool().allow())
    return base
"#;
        let result = evaluate(source, "policy.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();

        assert_eq!(doc["schema_version"], 4);
        assert_eq!(doc["use"], "main");
        assert_eq!(doc["default_effect"], "deny");

        let policies = doc["policies"].as_array().unwrap();
        // Should have: gitbox sandbox, rust sandbox, main
        assert!(
            policies.len() >= 3,
            "expected >= 3 policies, got {}",
            policies.len()
        );

        // Main policy should have 3 rules: exe(git), match(rustc/cargo), tool().allow()
        let main_pol = policies.last().unwrap();
        assert_eq!(main_pol["name"], "main");
        let main_body = main_pol["body"].as_array().unwrap();
        assert_eq!(main_body.len(), 3);
    }

    #[test]
    fn test_exe_regex_pattern() {
        let source = r#"
load("@clash//std.star", "exe", "regex")

def main():
    return policy(default = deny, rules = [
        exe(regex("cargo.*")).allow(),
    ])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let rule = &doc["policies"][0]["body"][0]["rule"];
        assert_eq!(rule["exec"]["bin"]["regex"], "cargo.*");
    }

    #[test]
    fn test_exe_any_pattern() {
        let source = r#"
load("@clash//std.star", "exe")

def main():
    return policy(default = deny, rules = [
        exe().deny(),
    ])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let rule = &doc["policies"][0]["body"][0]["rule"];
        assert!(rule["exec"]["bin"]["any"].is_null());
    }

    #[test]
    fn test_tool_regex_pattern() {
        let source = r#"
load("@clash//std.star", "tool", "regex")

def main():
    return policy(default = deny, rules = [
        tool(regex("mcp__.*")).ask(),
    ])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let rule = &doc["policies"][0]["body"][0]["rule"];
        assert_eq!(rule["tool"]["name"]["regex"], "mcp__.*");
        assert_eq!(rule["effect"], "ask");
    }

    #[test]
    fn test_match_exes_with_regex() {
        let source = r#"
load("@clash//std.star", "match_exes", "regex")

def main():
    return policy(default = deny, rules = [
        match_exes(["git", regex("gh.*")]).allow(),
    ])
"#;
        let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
        let bin = &doc["policies"][0]["body"][0]["rule"]["exec"]["bin"];
        let or_pats = bin["or"].as_array().unwrap();
        assert_eq!(or_pats[0]["literal"], "git");
        assert_eq!(or_pats[1]["regex"], "gh.*");
    }
}
