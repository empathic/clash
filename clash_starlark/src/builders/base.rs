//! Base policy value — the return type of `main()`.
//!
//! Wraps a v5 match tree JSON document.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::Value as JsonValue;
use starlark::starlark_simple_value;
use starlark::values::{NoSerialize, ProvidesStaticType, StarlarkValue, Trace, starlark_value};

/// A base policy value — the return type of `main()`.
///
/// Created by `_mt_policy()` which builds a v5 match tree document.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct BasePolicyValue {
    /// The v5 JSON document.
    #[allocative(skip)]
    pub base_doc: Option<JsonValue>,
    /// Default effect for unmatched requests.
    pub default_effect: String,
}

unsafe impl Trace<'_> for BasePolicyValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for BasePolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Policy(default={})", self.default_effect)
    }
}

starlark_simple_value!(BasePolicyValue);

#[starlark_value(type = "BasePolicyValue")]
impl<'v> StarlarkValue<'v> for BasePolicyValue {
    fn get_methods() -> Option<&'static starlark::environment::Methods> {
        static RES: starlark::environment::MethodsStatic =
            starlark::environment::MethodsStatic::new();
        RES.methods(base_policy_methods)
    }
}

#[starlark::starlark_module]
fn base_policy_methods(builder: &mut starlark::environment::MethodsBuilder) {
    /// Merge two policies together.
    ///
    /// In `a.merge(b)`, `b` is merged on top: `b`'s default effect is used,
    /// tree nodes are concatenated (`a`'s first, then `b`'s), and sandboxes
    /// are merged (first defined wins on name conflicts).
    fn merge(this: &BasePolicyValue, other: &BasePolicyValue) -> anyhow::Result<BasePolicyValue> {
        let default_effect = other.default_effect.clone();

        let base_doc = match (&this.base_doc, &other.base_doc) {
            (Some(left), Some(right)) => {
                let mut doc = left.clone();
                let obj = doc
                    .as_object_mut()
                    .ok_or_else(|| anyhow::anyhow!("policy document is not an object"))?;

                // Merge tree arrays
                if let Some(right_tree) = right.get("tree").and_then(|t| t.as_array()) {
                    let tree = obj
                        .entry("tree")
                        .or_insert_with(|| serde_json::json!([]))
                        .as_array_mut()
                        .ok_or_else(|| anyhow::anyhow!("policy tree is not an array"))?;
                    tree.extend(right_tree.iter().cloned());
                }

                // Merge sandbox maps
                if let Some(right_sb) = right.get("sandboxes").and_then(|s| s.as_object()) {
                    let sandboxes = obj
                        .entry("sandboxes")
                        .or_insert_with(|| serde_json::json!({}))
                        .as_object_mut()
                        .ok_or_else(|| anyhow::anyhow!("policy sandboxes is not an object"))?;
                    for (k, v) in right_sb {
                        sandboxes.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }

                // Update default effect
                obj.insert("default_effect".into(), serde_json::json!(default_effect));

                Some(doc)
            }
            (Some(doc), None) => Some(doc.clone()),
            (None, Some(doc)) => Some(doc.clone()),
            (None, None) => None,
        };

        Ok(BasePolicyValue {
            base_doc,
            default_effect,
        })
    }
}
