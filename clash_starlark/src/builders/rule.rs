//! Generic rule value — the single matcher type for all Starlark-built rules.
//!
//! Starlark builders (exe, tool, etc.) construct dict structures that get
//! wrapped into `RuleValue` via the `rule()` global. The Rust side only needs
//! this one type to handle any rule domain.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::Value as JsonValue;
use starlark::starlark_simple_value;
use starlark::values::dict::DictRef;
use starlark::values::list::ListRef;
use starlark::values::{
    NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, starlark_value,
};

use super::sandbox::SandboxValue;

/// A rule produced by a Starlark builder — wraps the JSON representation.
///
/// Created by calling `rule(dict)` from Starlark. The dict should be in the
/// exact JSON shape expected by the policy compiler, e.g.:
/// ```json
/// {"rule": {"effect": "allow", "exec": {"bin": {"literal": "git"}}}}
/// ```
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct RuleValue {
    #[allocative(skip)]
    pub json: JsonValue,
    #[allocative(skip)]
    pub sandbox: Option<SandboxValue>,
}

unsafe impl Trace<'_> for RuleValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for RuleValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rule({})", self.json)
    }
}

starlark_simple_value!(RuleValue);

#[starlark_value(type = "RuleValue")]
impl<'v> StarlarkValue<'v> for RuleValue {
    fn get_methods() -> Option<&'static starlark::environment::Methods> {
        static RES: starlark::environment::MethodsStatic =
            starlark::environment::MethodsStatic::new();
        RES.methods(rule_methods)
    }
}

#[starlark::starlark_module]
fn rule_methods(builder: &mut starlark::environment::MethodsBuilder) {
    fn sandbox(
        this: &RuleValue,
        #[starlark(require = pos)] sb: &SandboxValue,
    ) -> anyhow::Result<RuleValue> {
        Ok(RuleValue {
            json: this.json.clone(),
            sandbox: Some(sb.clone()),
        })
    }
}

/// Convert a Starlark value to serde_json::Value.
pub fn starlark_to_json(value: Value) -> anyhow::Result<JsonValue> {
    if value.is_none() {
        return Ok(JsonValue::Null);
    }
    if let Some(s) = value.unpack_str() {
        return Ok(JsonValue::String(s.to_string()));
    }
    if let Some(b) = value.unpack_bool() {
        return Ok(JsonValue::Bool(b));
    }
    if let Some(i) = value.unpack_i32() {
        return Ok(serde_json::json!(i));
    }
    if let Some(list) = ListRef::from_value(value) {
        let items: Result<Vec<_>, _> = list.iter().map(starlark_to_json).collect();
        return Ok(JsonValue::Array(items?));
    }
    if let Some(dict) = DictRef::from_value(value) {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key = k
                .unpack_str()
                .ok_or_else(|| anyhow::anyhow!("dict keys must be strings, got {}", k.get_type()))?;
            map.insert(key.to_string(), starlark_to_json(v)?);
        }
        return Ok(JsonValue::Object(map));
    }
    anyhow::bail!("cannot convert {} to JSON", value.get_type())
}
