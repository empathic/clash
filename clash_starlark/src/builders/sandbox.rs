//! Sandbox builder — a self-contained permission environment.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::{Value as JsonValue, json};
use starlark::starlark_simple_value;
use starlark::values::list::ListRef;
use starlark::values::{
    Heap, NoSerialize, ProvidesStaticType, StarlarkValue, Trace, Value, ValueLike, starlark_value,
};

use super::net::NetValue;
use super::path::PathValue;
use super::{effect_str_valid, unpack_effect_or_default};

/// A sandbox — a named permission environment for process execution.
///
/// Created by `sandbox(default=deny, fs=[...], net=...)`.
/// Compiles to a named `PolicyDef` containing fs/net rules.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct SandboxValue {
    pub default_effect: String,
    #[allocative(skip)]
    pub fs_entries: Vec<PathValue>,
    #[allocative(skip)]
    pub net_entries: Vec<NetValue>,
    pub net_simple: Option<String>,
}

unsafe impl Trace<'_> for SandboxValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for SandboxValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sandbox(default={})", self.default_effect)
    }
}

starlark_simple_value!(SandboxValue);

#[starlark_value(type = "SandboxValue")]
impl<'v> StarlarkValue<'v> for SandboxValue {}

impl SandboxValue {
    pub fn new<'v>(
        default: Option<&str>,
        fs: Option<Value<'v>>,
        net: Option<Value<'v>>,
        _heap: &'v Heap,
    ) -> anyhow::Result<Self> {
        let default_effect = unpack_effect_or_default(default, "deny");

        // Parse fs entries
        let mut fs_entries = Vec::new();
        if let Some(fs_val) = fs {
            let list = ListRef::from_value(fs_val)
                .ok_or_else(|| anyhow::anyhow!("fs= must be a list of path entries"))?;
            for item in list.iter() {
                let pv = item.downcast_ref::<PathValue>().ok_or_else(|| {
                    anyhow::anyhow!("fs entries must be PathValue, got {}", item.get_type())
                })?;
                fs_entries.push(pv.clone());
            }
        }

        // Parse net entries
        let mut net_entries = Vec::new();
        let mut net_simple = None;

        if let Some(net_val) = net {
            if let Some(s) = net_val.unpack_str() {
                effect_str_valid(s)?;
                net_simple = Some(s.to_string());
            } else if let Some(list) = ListRef::from_value(net_val) {
                for item in list.iter() {
                    let nv = item.downcast_ref::<NetValue>().ok_or_else(|| {
                        anyhow::anyhow!("net entries must be NetValue, got {}", item.get_type())
                    })?;
                    net_entries.push(nv.clone());
                }
            } else {
                anyhow::bail!("net= must be allow/deny or a list of network entries");
            }
        }

        Ok(SandboxValue {
            default_effect,
            fs_entries,
            net_entries,
            net_simple,
        })
    }

    /// Compile to the body of a PolicyDef (list of PolicyItem JSON).
    pub fn to_policy_body_json(&self) -> Vec<JsonValue> {
        let mut body = Vec::new();

        for fs_entry in &self.fs_entries {
            body.extend(fs_entry.to_rules_json());
        }

        if let Some(ref simple) = self.net_simple {
            body.push(json!({
                "rule": {
                    "effect": simple,
                    "net": { "domain": {"any": null} }
                }
            }));
        } else {
            for net_entry in &self.net_entries {
                body.extend(net_entry.to_rules_json());
            }
        }

        body
    }
}
