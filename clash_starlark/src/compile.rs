//! Compiler: BasePolicyValue → v5 match tree JSON.
//!
//! Retained for potential future use (e.g. programmatic policy construction).

#![allow(dead_code)]

use starlark::values::{Value, ValueLike};

use crate::builders::base::BasePolicyValue;

/// Compile a `BasePolicyValue` to a v5 JSON string.
pub fn compile_to_json(value: Value) -> anyhow::Result<String> {
    let base = value.downcast_ref::<BasePolicyValue>().ok_or_else(|| {
        anyhow::anyhow!(
            "expected a policy value (from policy()), got {}",
            value.get_type()
        )
    })?;

    // The base_doc contains the full v5 document
    if let Some(ref doc) = base.base_doc {
        return serde_json::to_string_pretty(doc).map_err(Into::into);
    }

    anyhow::bail!("policy value has no document (missing schema_version 5)")
}
