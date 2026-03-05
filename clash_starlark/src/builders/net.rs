//! Network permission builders.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::{Value as JsonValue, json};
use starlark::starlark_simple_value;
use starlark::values::dict::DictRef;
use starlark::values::{
    NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, starlark_value,
};

use super::effect_str_valid;

/// A network permission entry.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct NetValue {
    #[allocative(skip)]
    pub entries: Vec<NetEntry>,
}

// NetValue contains no starlark heap references
unsafe impl Trace<'_> for NetValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

#[derive(Debug, Clone)]
pub struct NetEntry {
    pub domain: String,
    pub effect: String,
}

impl Display for NetValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NetValue({} domains)", self.entries.len())
    }
}

starlark_simple_value!(NetValue);

#[starlark_value(type = "NetValue")]
impl<'v> StarlarkValue<'v> for NetValue {}

impl NetValue {
    /// Create from a dict of {domain: effect}.
    pub fn from_domains_dict<'v>(mapping: Value<'v>) -> anyhow::Result<Self> {
        let dict = DictRef::from_value(mapping)
            .ok_or_else(|| anyhow::anyhow!("domains() expects a dict argument"))?;

        let mut entries = Vec::new();
        for (k, v) in dict.iter() {
            let domain = k
                .unpack_str()
                .ok_or_else(|| anyhow::anyhow!("domain key must be a string, got {}", k))?;
            let effect = v.unpack_str().ok_or_else(|| {
                anyhow::anyhow!("domain effect must be a string (allow/deny/ask), got {}", v)
            })?;
            effect_str_valid(effect)?;
            entries.push(NetEntry {
                domain: domain.to_string(),
                effect: effect.to_string(),
            });
        }
        Ok(NetValue { entries })
    }

    /// Create a single domain entry.
    pub fn single_domain(name: &str, effect: &str) -> anyhow::Result<Self> {
        effect_str_valid(effect)?;
        Ok(NetValue {
            entries: vec![NetEntry {
                domain: name.to_string(),
                effect: effect.to_string(),
            }],
        })
    }

    /// Compile to net rule JSON objects.
    pub fn to_rules_json(&self) -> Vec<JsonValue> {
        self.entries
            .iter()
            .map(|entry| {
                json!({
                    "rule": {
                        "effect": entry.effect,
                        "net": {
                            "domain": if entry.domain == "*" {
                                json!({"any": null})
                            } else if entry.domain.starts_with("*.") {
                                json!({"regex": format!("(^|.*\\.){}", regex::escape(&entry.domain[2..]))})
                            } else {
                                json!({"literal": entry.domain})
                            }
                        }
                    }
                })
            })
            .collect()
    }
}
