//! Base policy builder — wraps imported JSON or constructed policies.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::Value as JsonValue;
use starlark::starlark_simple_value;
use starlark::values::list::ListRef;
use starlark::values::{
    NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, ValueLike, starlark_value,
};

use super::exec::{ExecBindingValue, ToolBindingValue};
use super::unpack_effect_or_default;

/// Binding — either an exec or tool binding to extend a base policy with.
#[derive(Debug, Clone)]
pub enum Binding {
    Exec(ExecBindingValue),
    Tool(ToolBindingValue),
}

/// A base policy value — the return type of `main()`.
///
/// Created by `import_json()` or `policy()`, extended via `.extend()`.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct BasePolicyValue {
    /// The base JSON document (parsed from import_json), if any.
    #[allocative(skip)]
    pub base_doc: Option<JsonValue>,
    /// Default effect for unmatched requests.
    pub default_effect: String,
    /// Additional bindings added via .extend().
    #[allocative(skip)]
    pub bindings: Vec<Binding>,
}

unsafe impl Trace<'_> for BasePolicyValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for BasePolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "BasePolicy(bindings={})", self.bindings.len())
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

        if let Some(exec) = binding.downcast_ref::<ExecBindingValue>() {
            result.bindings.push(Binding::Exec(exec.clone()));
        } else if let Some(tool) = binding.downcast_ref::<ToolBindingValue>() {
            result.bindings.push(Binding::Tool(tool.clone()));
        } else {
            anyhow::bail!(
                ".extend() expects an exe(), match(), allow_tool(), or deny_tool() value, got {}",
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
            bindings: vec![],
        }
    }

    /// Create from scratch (no base document).
    pub fn from_scratch<'v>(
        default: Option<&str>,
        rules: Option<Value<'v>>,
    ) -> anyhow::Result<Self> {
        let default_effect = unpack_effect_or_default(default, "deny");
        let mut bindings = Vec::new();

        if let Some(rules_val) = rules {
            let list = ListRef::from_value(rules_val)
                .ok_or_else(|| anyhow::anyhow!("rules= must be a list"))?;
            for item in list.iter() {
                if let Some(exec) = item.downcast_ref::<ExecBindingValue>() {
                    bindings.push(Binding::Exec(exec.clone()));
                } else if let Some(tool) = item.downcast_ref::<ToolBindingValue>() {
                    bindings.push(Binding::Tool(tool.clone()));
                } else {
                    anyhow::bail!(
                        "policy rules list items must be exe(), match(), allow_tool(), or deny_tool(), got {}",
                        item.get_type()
                    );
                }
            }
        }

        Ok(BasePolicyValue {
            base_doc: None,
            default_effect,
            bindings,
        })
    }
}
