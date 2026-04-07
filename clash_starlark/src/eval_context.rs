//! Evaluation context — accumulates registrations from top-level calls.
//!
//! Attached to `evaluator.extra` during module evaluation. Native functions
//! (`_register_settings`) write into this context; `evaluate()` reads it
//! after module eval completes.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::Value as JsonValue;
use starlark::values::ProvidesStaticType;

/// A record of a leaf value that was overwritten during `merge()`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShadowedRule {
    /// Dict key path to the conflicting leaf (e.g. `["Tool(Bash)", "git"]`).
    pub path: Vec<String>,
    /// String representation of the winning (rightmost) value.
    pub winner: String,
    /// String representation of the value that was overwritten.
    pub shadowed: String,
}

/// Settings registered via the `settings()` DSL call.
#[derive(Debug, Clone)]
pub struct SettingsValue {
    pub default_effect: String,
    pub default_sandbox: Option<String>,
    pub on_sandbox_violation: Option<String>,
    pub harness_defaults: Option<bool>,
}

/// A registered policy — name + match tree nodes + associated sandboxes.
#[derive(Debug, Clone)]
pub struct PolicyRegistration {
    pub name: String,
    /// Per-policy default effect override from a `default()` root key.
    pub default_effect: Option<String>,
    pub tree_nodes: Vec<JsonValue>,
    pub sandboxes: Vec<JsonValue>,
}

/// Evaluation context stashed in `evaluator.extra`.
///
/// Uses `RefCell` for interior mutability since `extra` is a shared reference.
#[derive(Debug, ProvidesStaticType)]
pub struct EvalContext {
    pub policy: RefCell<Option<PolicyRegistration>>,
    pub settings: RefCell<Option<SettingsValue>>,
    /// Sandboxes registered via top-level `sandbox(name, tree, ...)` calls.
    pub sandboxes: RefCell<BTreeMap<String, JsonValue>>,
    /// Leaf conflicts recorded by merge().
    pub shadows: RefCell<Vec<ShadowedRule>>,
}

impl EvalContext {
    pub fn new() -> Self {
        EvalContext {
            policy: RefCell::new(None),
            settings: RefCell::new(None),
            sandboxes: RefCell::new(BTreeMap::new()),
            shadows: RefCell::new(Vec::new()),
        }
    }

    /// Register a sandbox by name. Bails if a sandbox with the same name
    /// has already been registered.
    pub fn register_sandbox(&self, name: &str, sb_json: JsonValue) -> anyhow::Result<()> {
        let mut map = self.sandboxes.borrow_mut();
        if map.contains_key(name) {
            anyhow::bail!("sandbox `{name}` is already registered");
        }
        map.insert(name.to_string(), sb_json);
        Ok(())
    }

    /// Register settings.
    pub fn register_settings(&self, settings: SettingsValue) -> anyhow::Result<()> {
        let mut current = self.settings.borrow_mut();
        if current.is_some() {
            anyhow::bail!("settings() can only be called once per policy file");
        }
        *current = Some(settings);
        Ok(())
    }

    /// Register a policy.
    pub fn register_policy(&self, registration: PolicyRegistration) -> anyhow::Result<()> {
        let mut current = self.policy.borrow_mut();
        if current.is_some() {
            anyhow::bail!("policy() can only be called once per policy file");
        }
        *current = Some(registration);
        Ok(())
    }

    /// Assemble the v5 JSON policy document from all registrations.
    pub fn assemble_document(&self) -> anyhow::Result<JsonValue> {
        let policy = self
            .policy
            .borrow()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("policy file must call policy()"))?;

        let settings = self.settings.borrow();
        let default_effect = policy
            .default_effect
            .clone()
            .or_else(|| settings.as_ref().map(|s| s.default_effect.clone()))
            .unwrap_or_else(|| "deny".to_string());

        // Collect sandboxes from policy rules (allow(sandbox=box) references)
        let mut sandbox_map = serde_json::Map::new();
        for sb in &policy.sandboxes {
            if let Some(name) = sb.get("name").and_then(|n| n.as_str()) {
                sandbox_map
                    .entry(name.to_string())
                    .or_insert_with(|| sb.clone());
            }
        }

        let mut doc = serde_json::json!({
            "schema_version": 5,
            "default_effect": default_effect,
            "sandboxes": sandbox_map,
            "tree": policy.tree_nodes,
        });

        // Add default_sandbox if set
        if let Some(ref ds) = settings.as_ref().and_then(|s| s.default_sandbox.clone()) {
            doc.as_object_mut()
                .unwrap()
                .insert("default_sandbox".to_string(), serde_json::json!(ds));
        }

        // Add on_sandbox_violation if set
        if let Some(ref action) = settings
            .as_ref()
            .and_then(|s| s.on_sandbox_violation.clone())
        {
            doc.as_object_mut().unwrap().insert(
                "on_sandbox_violation".to_string(),
                serde_json::json!(action),
            );
        }

        // Add harness_defaults only when explicitly set to false (true is the default)
        if let Some(hd) = settings.as_ref().and_then(|s| s.harness_defaults) {
            if !hd {
                doc.as_object_mut()
                    .unwrap()
                    .insert("harness_defaults".to_string(), serde_json::json!(false));
            }
        }

        Ok(doc)
    }
}
