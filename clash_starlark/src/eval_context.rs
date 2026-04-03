//! Evaluation context — accumulates registrations from top-level calls.
//!
//! Attached to `evaluator.extra` during module evaluation. Native functions
//! (`_register_settings`) write into this context; `evaluate()` reads it
//! after module eval completes.

use std::cell::RefCell;

use serde_json::Value as JsonValue;
use starlark::values::ProvidesStaticType;

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
    /// Sandboxes collected by when() calls, drained by policy().
    pub pending_sandboxes: RefCell<Vec<JsonValue>>,
}

impl EvalContext {
    pub fn new() -> Self {
        EvalContext {
            policy: RefCell::new(None),
            settings: RefCell::new(None),
            pending_sandboxes: RefCell::new(Vec::new()),
        }
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
        let default_effect = settings
            .as_ref()
            .map(|s| s.default_effect.clone())
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
        if let Some(ref action) = settings.as_ref().and_then(|s| s.on_sandbox_violation.clone()) {
            doc.as_object_mut()
                .unwrap()
                .insert("on_sandbox_violation".to_string(), serde_json::json!(action));
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
