//! WASM bindings for the Clash policy engine.
//!
//! Exposes the Starlark evaluator and match-tree policy engine to JavaScript
//! for use in the interactive tutorial on the Clash website.

use std::collections::HashMap;
use std::path::Path;

use wasm_bindgen::prelude::*;

mod engine;

/// Set up panic hook for better WASM error messages.
#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// Evaluate a Starlark policy source and return the compiled JSON policy document.
///
/// The source should define a `main()` function that returns a policy value.
/// Standard library modules (`@clash//std.star`, `@clash//rust.star`, etc.)
/// are available via `load()`.
#[wasm_bindgen]
pub fn evaluate_starlark(source: &str) -> Result<String, JsError> {
    let output = clash_starlark::evaluate(source, "policy.star", Path::new("."))
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(output.json)
}

/// Check a tool invocation against a compiled policy.
///
/// Arguments:
/// - `policy_json`: the v5 JSON policy document (from `evaluate_starlark`)
/// - `tool_name`: the tool being invoked (e.g. "Bash", "Glob", "Read")
/// - `tool_input_json`: the tool's input as JSON (e.g. `{"command": "git status"}`)
/// - `env_json`: environment variables as JSON (e.g. `{"PWD": "/project", "HOME": "/home/user"}`)
///
/// Returns a JSON string with the decision:
/// ```json
/// {
///   "effect": "allow",
///   "reason": "result: allow",
///   "sandbox": "sandbox_name",
///   "sandbox_policy": { ... },
///   "trace": ["Rule 'ToolName=Bash' matched — action allowed", ...]
/// }
/// ```
#[wasm_bindgen]
pub fn check_permission(
    policy_json: &str,
    tool_name: &str,
    tool_input_json: &str,
    env_json: &str,
) -> Result<String, JsError> {
    // Set thread-local environment for Value::resolve()
    let env: HashMap<String, String> = serde_json::from_str(env_json)
        .map_err(|e| JsError::new(&format!("invalid env JSON: {e}")))?;
    engine::set_env(env);

    // Parse compiled policy
    let policy: engine::CompiledPolicy = serde_json::from_str(policy_json)
        .map_err(|e| JsError::new(&format!("invalid policy JSON: {e}")))?;

    // Parse tool input
    let tool_input: serde_json::Value = serde_json::from_str(tool_input_json)
        .map_err(|e| JsError::new(&format!("invalid tool input JSON: {e}")))?;

    // Evaluate
    let decision = policy.evaluate(tool_name, &tool_input);

    // Serialize result
    let result = serde_json::json!({
        "effect": decision.effect.to_string(),
        "reason": decision.reason,
        "sandbox": decision.sandbox_name.map(|s| s.0),
        "sandbox_policy": decision.sandbox,
        "trace": decision.trace.render_human(),
    });

    Ok(result.to_string())
}

/// Format the rules in a compiled policy as human-readable lines.
#[wasm_bindgen]
pub fn format_rules(policy_json: &str) -> Result<String, JsError> {
    let policy: engine::CompiledPolicy = serde_json::from_str(policy_json)
        .map_err(|e| JsError::new(&format!("invalid policy JSON: {e}")))?;

    let rules = engine::format_rules(&policy);
    serde_json::to_string(&rules)
        .map_err(|e| JsError::new(&format!("serialization error: {e}")))
}
