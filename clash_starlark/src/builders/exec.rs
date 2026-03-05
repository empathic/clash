//! Exec and tool binding builders.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::{Value as JsonValue, json};
use starlark::starlark_simple_value;
use starlark::values::list::ListRef;
use starlark::values::{
    NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, starlark_value,
};

use super::sandbox::SandboxValue;

/// An exec binding — binds one or more executables to a sandbox.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct ExecBindingValue {
    pub bins: Vec<String>,
    #[allocative(skip)]
    pub sandbox: Option<SandboxValue>,
}

unsafe impl Trace<'_> for ExecBindingValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for ExecBindingValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExecBinding({:?})", self.bins)
    }
}

starlark_simple_value!(ExecBindingValue);

#[starlark_value(type = "ExecBindingValue")]
impl<'v> StarlarkValue<'v> for ExecBindingValue {}

impl ExecBindingValue {
    pub fn new_single(name: &str, sandbox: Option<&SandboxValue>) -> anyhow::Result<Self> {
        Ok(ExecBindingValue {
            bins: vec![name.to_string()],
            sandbox: sandbox.cloned(),
        })
    }

    pub fn new_multi<'v>(
        exe: Option<Value<'v>>,
        sandbox: Option<&SandboxValue>,
    ) -> anyhow::Result<Self> {
        let bins = match exe {
            Some(val) => {
                let list = ListRef::from_value(val)
                    .ok_or_else(|| anyhow::anyhow!("match(exe=...) must be a list of strings"))?;
                let mut names = Vec::new();
                for item in list.iter() {
                    let s = item
                        .unpack_str()
                        .ok_or_else(|| anyhow::anyhow!("exe list items must be strings"))?;
                    names.push(s.to_string());
                }
                names
            }
            None => anyhow::bail!("match() requires exe= argument"),
        };
        Ok(ExecBindingValue {
            bins,
            sandbox: sandbox.cloned(),
        })
    }

    /// Compile to a rule JSON object.
    pub fn to_rule_json(&self, sandbox_name: Option<&str>) -> JsonValue {
        let bin_pattern = if self.bins.len() == 1 {
            json!({"literal": self.bins[0]})
        } else {
            let literals: Vec<JsonValue> =
                self.bins.iter().map(|b| json!({"literal": b})).collect();
            json!({"or": literals})
        };

        let mut rule = json!({
            "effect": "allow",
            "exec": {
                "bin": bin_pattern
            }
        });

        if let Some(name) = sandbox_name {
            rule.as_object_mut()
                .unwrap()
                .insert("sandbox".into(), json!({"named": name}));
        }

        json!({"rule": rule})
    }
}

/// A tool binding — allow or deny a tool.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct ToolBindingValue {
    pub effect: String,
    pub name: Option<String>,
}

unsafe impl Trace<'_> for ToolBindingValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for ToolBindingValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ToolBinding({}, {:?})", self.effect, self.name)
    }
}

starlark_simple_value!(ToolBindingValue);

#[starlark_value(type = "ToolBindingValue")]
impl<'v> StarlarkValue<'v> for ToolBindingValue {}

impl ToolBindingValue {
    pub fn allow(name: Option<&str>) -> Self {
        ToolBindingValue {
            effect: "allow".into(),
            name: name.map(String::from),
        }
    }

    pub fn deny(name: Option<&str>) -> Self {
        ToolBindingValue {
            effect: "deny".into(),
            name: name.map(String::from),
        }
    }

    /// Compile to a rule JSON object.
    pub fn to_rule_json(&self) -> JsonValue {
        let name_pattern = match &self.name {
            Some(n) => json!({"literal": n}),
            None => json!({"any": null}),
        };
        json!({
            "rule": {
                "effect": self.effect,
                "tool": {
                    "name": name_pattern
                }
            }
        })
    }
}
