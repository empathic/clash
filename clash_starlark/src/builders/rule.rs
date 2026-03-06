//! Generic rule value — the single matcher type for all Starlark-built rules.
//!
//! Starlark builders (exe, tool, etc.) construct dict structures that get
//! wrapped into `RuleValue` via the `rule()` global. The Rust side only needs
//! this one type to handle any rule domain.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::Value as JsonValue;
use starlark::starlark_simple_value;
use starlark::values::dict::Dict;
use starlark::values::dict::DictRef;
use starlark::values::list::ListRef;
use starlark::values::{
    Heap, NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, starlark_value,
};

/// A rule produced by a Starlark builder — wraps the JSON representation.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct RuleValue {
    #[allocative(skip)]
    pub json: JsonValue,
    #[allocative(skip)]
    pub sandbox: Option<JsonValue>,
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

    fn dir_attr(&self) -> Vec<String> {
        vec!["json".to_string()]
    }

    fn get_attr(&self, attribute: &str, heap: &'v Heap) -> Option<Value<'v>> {
        match attribute {
            "json" => json_to_starlark(&self.json, heap).ok(),
            _ => None,
        }
    }
}

#[starlark::starlark_module]
fn rule_methods(builder: &mut starlark::environment::MethodsBuilder) {
    fn sandbox<'v>(
        this: &RuleValue,
        #[starlark(require = pos)] sb: Value<'v>,
    ) -> anyhow::Result<RuleValue> {
        let json = starlark_to_json(sb)?;
        Ok(RuleValue {
            json: this.json.clone(),
            sandbox: Some(json),
        })
    }
}

/// Convert a serde_json::Value back to a Starlark Value.
fn json_to_starlark<'v>(json: &JsonValue, heap: &'v Heap) -> anyhow::Result<Value<'v>> {
    match json {
        JsonValue::Null => Ok(Value::new_none()),
        JsonValue::Bool(b) => Ok(Value::new_bool(*b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(heap.alloc(i as i32))
            } else if let Some(f) = n.as_f64() {
                Ok(heap.alloc(f))
            } else {
                anyhow::bail!("unsupported JSON number: {n}")
            }
        }
        JsonValue::String(s) => Ok(heap.alloc_str(s).to_value()),
        JsonValue::Array(arr) => {
            let items: Result<Vec<_>, _> = arr.iter().map(|v| json_to_starlark(v, heap)).collect();
            Ok(heap.alloc(items?))
        }
        JsonValue::Object(map) => {
            let dict = Dict::new(
                map.iter()
                    .map(|(k, v)| {
                        Ok((
                            heap.alloc_str(k).to_value().get_hashed().unwrap(),
                            json_to_starlark(v, heap)?,
                        ))
                    })
                    .collect::<anyhow::Result<_>>()?,
            );
            Ok(heap.alloc(dict))
        }
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
            let key = k.unpack_str().ok_or_else(|| {
                anyhow::anyhow!("dict keys must be strings, got {}", k.get_type())
            })?;
            map.insert(key.to_string(), starlark_to_json(v)?);
        }
        return Ok(JsonValue::Object(map));
    }
    anyhow::bail!("cannot convert {} to JSON", value.get_type())
}
