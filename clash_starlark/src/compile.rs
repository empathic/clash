//! Compiler: Starlark return value → PolicyDocument JSON.
//!
//! Takes the return value of `main()` and produces a JSON string that
//! the existing `clash` compile pipeline can consume.

use serde_json::{Value as JsonValue, json};
use starlark::values::{Value, ValueLike};

use crate::builders::base::BasePolicyValue;

/// Compile a Starlark `main()` return value to a PolicyDocument JSON string.
pub fn compile_to_json(value: Value) -> anyhow::Result<String> {
    let base = value.downcast_ref::<BasePolicyValue>().ok_or_else(|| {
        anyhow::anyhow!(
            "main() must return a policy value (from import_json().extend() or policy()), got {}",
            value.get_type()
        )
    })?;

    let doc = compile_base_policy(base)?;
    serde_json::to_string_pretty(&doc).map_err(Into::into)
}

fn compile_base_policy(base: &BasePolicyValue) -> anyhow::Result<JsonValue> {
    let mut sandbox_defs: Vec<(String, JsonValue)> = Vec::new();
    let mut sandbox_counter = 0;
    let mut main_body: Vec<JsonValue> = Vec::new();

    // If there's a base document, merge its policies
    let mut base_policies: Vec<JsonValue> = Vec::new();
    if let Some(ref doc) = base.base_doc {
        if let Some(policies) = doc.get("policies").and_then(|p| p.as_array()) {
            base_policies = policies.clone();
        }
        if let Some(use_name) = doc.get("use").and_then(|u| u.as_str())
            && let Some(main_pol) = base_policies
                .iter()
                .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(use_name))
            && let Some(body) = main_pol.get("body").and_then(|b| b.as_array())
        {
            main_body.extend(body.iter().cloned());
        }
    }

    // Process rules
    for rule in &base.rules {
        let mut rule_json = rule.json.clone();

        if let Some(ref sb) = rule.sandbox {
            let name = format!("__sandbox_{}", sandbox_counter);
            sandbox_counter += 1;
            sandbox_defs.push((name.clone(), sb.clone()));
            // Inject sandbox reference into the rule
            if let Some(inner) = rule_json.get_mut("rule").and_then(|r| r.as_object_mut()) {
                inner.insert("sandbox".into(), json!({"named": name}));
            }
        }

        main_body.push(rule_json);
    }

    // Build the output document
    let mut policies: Vec<JsonValue> = Vec::new();

    // Emit sandbox policy defs (from base doc, excluding the main policy)
    if let Some(ref doc) = base.base_doc
        && let Some(use_name) = doc.get("use").and_then(|u| u.as_str())
    {
        for pol in &base_policies {
            if pol.get("name").and_then(|n| n.as_str()) != Some(use_name) {
                policies.push(pol.clone());
            }
        }
    }

    // Emit new sandbox defs (from Starlark-built sandboxes)
    for (name, sb_json) in &sandbox_defs {
        let body = sb_json
            .get("body")
            .and_then(|b| b.as_array())
            .cloned()
            .unwrap_or_default();
        policies.push(json!({
            "name": name,
            "body": body
        }));
    }

    // Emit main policy
    policies.push(json!({
        "name": "main",
        "body": main_body
    }));

    Ok(json!({
        "schema_version": 4,
        "use": "main",
        "default_effect": base.default_effect,
        "policies": policies
    }))
}
