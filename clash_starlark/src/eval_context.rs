//! Evaluation context — accumulates registrations from top-level calls.
//!
//! Attached to `evaluator.extra` during module evaluation. Native functions
//! (`_register_policy`, `_register_sandbox`, `_register_settings`) write into
//! this context; `evaluate()` reads it after module eval completes.

use std::cell::RefCell;

use serde_json::Value as JsonValue;
use starlark::values::ProvidesStaticType;


/// Settings registered via the `settings()` DSL call.
#[derive(Debug, Clone)]
pub struct SettingsValue {
    pub default_effect: String,
    pub default_sandbox: Option<String>,
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
    pub sandboxes: RefCell<Vec<JsonValue>>,
    pub settings: RefCell<Option<SettingsValue>>,
}

impl EvalContext {
    pub fn new() -> Self {
        EvalContext {
            policy: RefCell::new(None),
            sandboxes: RefCell::new(Vec::new()),
            settings: RefCell::new(None),
        }
    }

    /// Register a sandbox definition.
    pub fn register_sandbox(&self, sandbox_json: JsonValue) -> anyhow::Result<()> {
        let name = sandbox_json
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>")
            .to_string();

        let mut sandboxes = self.sandboxes.borrow_mut();
        // Check for duplicate names
        for existing in sandboxes.iter() {
            if existing.get("name").and_then(|n| n.as_str()) == Some(&name) {
                anyhow::bail!("sandbox \"{name}\" is already registered");
            }
        }
        sandboxes.push(sandbox_json);
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
        let default_effect = settings
            .as_ref()
            .map(|s| s.default_effect.clone())
            .unwrap_or_else(|| "deny".to_string());

        // Merge sandboxes: policy-associated sandboxes override top-level registrations
        // (e.g. a merged sandbox referenced in a rule takes precedence over the original)
        let mut sandbox_map = serde_json::Map::new();

        // Policy-associated sandboxes first (from allow(sandbox=box) in rules)
        for sb in &policy.sandboxes {
            if let Some(name) = sb.get("name").and_then(|n| n.as_str()) {
                sandbox_map.entry(name.to_string()).or_insert_with(|| sb.clone());
            }
        }

        // Top-level sandbox() registrations (fill in any not already present)
        for sb in self.sandboxes.borrow().iter() {
            if let Some(name) = sb.get("name").and_then(|n| n.as_str()) {
                sandbox_map.entry(name.to_string()).or_insert_with(|| sb.clone());
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

        Ok(doc)
    }
}
