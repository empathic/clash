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
    pub args: Vec<String>,
    pub effect: String,
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
    pub fn new_single<'v>(
        name: &str,
        args: Option<Value<'v>>,
        effect: Option<&str>,
        sandbox: Option<&SandboxValue>,
    ) -> anyhow::Result<Self> {
        let parsed_args = match args {
            Some(val) => {
                let list = ListRef::from_value(val)
                    .ok_or_else(|| anyhow::anyhow!("exe(args=...) must be a list of strings"))?;
                let mut result = Vec::new();
                for item in list.iter() {
                    let s = item
                        .unpack_str()
                        .ok_or_else(|| anyhow::anyhow!("args list items must be strings"))?;
                    result.push(s.to_string());
                }
                result
            }
            None => Vec::new(),
        };
        let eff = effect.unwrap_or("allow");
        if eff != "allow" && eff != "deny" && eff != "ask" {
            anyhow::bail!("exe(effect=...) must be allow, deny, or ask");
        }
        Ok(ExecBindingValue {
            bins: vec![name.to_string()],
            args: parsed_args,
            effect: eff.to_string(),
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
            args: Vec::new(),
            effect: "allow".to_string(),
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

        let mut exec = json!({ "bin": bin_pattern });

        if !self.args.is_empty() {
            let mut args_json: Vec<JsonValue> =
                self.args.iter().map(|a| json!({"literal": a})).collect();
            args_json.push(json!({"any": null}));
            exec.as_object_mut()
                .unwrap()
                .insert("args".into(), json!(args_json));
        }

        let mut rule = json!({
            "effect": self.effect,
            "exec": exec
        });

        if let Some(name) = sandbox_name {
            rule.as_object_mut()
                .unwrap()
                .insert("sandbox".into(), json!({"named": name}));
        }

        json!({"rule": rule})
    }
}

/// A tool reference — returned by `tool()`, call `.allow()` or `.deny()` to produce a binding.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct ToolRefValue {
    pub name: Option<String>,
}

unsafe impl Trace<'_> for ToolRefValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for ToolRefValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.name {
            Some(n) => write!(f, "tool({:?})", n),
            None => write!(f, "tool(*)"),
        }
    }
}

starlark_simple_value!(ToolRefValue);

#[starlark_value(type = "ToolRefValue")]
impl<'v> StarlarkValue<'v> for ToolRefValue {
    fn get_methods() -> Option<&'static starlark::environment::Methods> {
        static RES: starlark::environment::MethodsStatic =
            starlark::environment::MethodsStatic::new();
        RES.methods(tool_ref_methods)
    }
}

#[starlark::starlark_module]
fn tool_ref_methods(builder: &mut starlark::environment::MethodsBuilder) {
    fn allow(this: &ToolRefValue) -> anyhow::Result<ToolBindingValue> {
        Ok(ToolBindingValue {
            effect: "allow".into(),
            name: this.name.clone(),
        })
    }

    fn deny(this: &ToolRefValue) -> anyhow::Result<ToolBindingValue> {
        Ok(ToolBindingValue {
            effect: "deny".into(),
            name: this.name.clone(),
        })
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
