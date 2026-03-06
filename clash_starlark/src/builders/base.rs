//! Base policy builder — wraps imported JSON or constructed policies.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::Value as JsonValue;
use starlark::starlark_simple_value;
use starlark::values::list::ListRef;
use starlark::values::{
    NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, ValueLike, starlark_value,
};

use super::rule::RuleValue;
use super::unpack_effect_or_default;

/// A base policy value — the return type of `main()`.
///
/// Created by `import_json()` or `_policy()`, extended via `.extend()`.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct BasePolicyValue {
    /// The base JSON document (parsed from import_json), if any.
    #[allocative(skip)]
    pub base_doc: Option<JsonValue>,
    /// Default effect for unmatched requests.
    pub default_effect: String,
    /// Rule bindings.
    #[allocative(skip)]
    pub rules: Vec<RuleValue>,
}

unsafe impl Trace<'_> for BasePolicyValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for BasePolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BasePolicy(rules={})", self.rules.len())
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
    fn extend<'v>(
        this: &BasePolicyValue,
        #[starlark(require = pos)] binding: Value<'v>,
    ) -> anyhow::Result<BasePolicyValue> {
        let mut result = this.clone();

        if let Some(rule) = binding.downcast_ref::<RuleValue>() {
            result.rules.push(rule.clone());
        } else {
            anyhow::bail!(
                ".extend() expects a rule value, got {}",
                binding.get_type()
            );
        }

        Ok(result)
    }
}

impl BasePolicyValue {
    /// Create from an imported JSON document.
    pub fn from_json(doc: JsonValue) -> Self {
        let default_effect = doc
            .get("default_effect")
            .and_then(|v| v.as_str())
            .unwrap_or("deny")
            .to_string();
        BasePolicyValue {
            base_doc: Some(doc),
            default_effect,
            rules: vec![],
        }
    }

    /// Create from scratch (no base document).
    pub fn from_scratch<'v>(
        default: Option<&str>,
        rules: Option<Value<'v>>,
    ) -> anyhow::Result<Self> {
        let default_effect = unpack_effect_or_default(default, "deny");
        let mut rule_vec = Vec::new();

        if let Some(rules_val) = rules {
            let list = ListRef::from_value(rules_val)
                .ok_or_else(|| anyhow::anyhow!("rules= must be a list"))?;
            for item in list.iter() {
                if let Some(rule) = item.downcast_ref::<RuleValue>() {
                    rule_vec.push(rule.clone());
                } else {
                    anyhow::bail!(
                        "policy rules must be rule values, got {}",
                        item.get_type()
                    );
                }
            }
        }

        Ok(BasePolicyValue {
            base_doc: None,
            default_effect,
            rules: rule_vec,
        })
    }
}
