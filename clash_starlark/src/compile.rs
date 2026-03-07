//! Compiler: Starlark return value → v5 match tree JSON.
//!
//! Takes the return value of `main()` and produces a JSON string that
//! the `clash` compile pipeline can consume.

use starlark::values::{Value, ValueLike};

use crate::builders::base::BasePolicyValue;

/// Compile a Starlark `main()` return value to a v5 JSON string.
pub fn compile_to_json(value: Value) -> anyhow::Result<String> {
    let base = value.downcast_ref::<BasePolicyValue>().ok_or_else(|| {
        anyhow::anyhow!(
            "main() must return a policy value (from policy()), got {}",
            value.get_type()
        )
    })?;

    // The base_doc contains the full v5 document
    if let Some(ref doc) = base.base_doc {
        return serde_json::to_string_pretty(doc).map_err(Into::into);
    }

    anyhow::bail!("main() returned a policy without a document (missing schema_version 5)")
}
