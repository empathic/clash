//! `import_json()` implementation — loads an existing JSON policy file.

use starlark::eval::Evaluator;

use crate::builders::base::BasePolicyValue;

/// Load a JSON policy file and return a BasePolicyValue.
pub fn import_json_impl<'v>(
    filename: &str,
    _eval: &mut Evaluator<'v, '_, '_>,
) -> anyhow::Result<BasePolicyValue> {
    // Resolve relative to the loader's base directory.
    // For now, we read from the filesystem. The loader tracks this file
    // for cache invalidation.
    let source = std::fs::read_to_string(filename)
        .map_err(|e| anyhow::anyhow!("import_json({filename:?}): {e}"))?;

    let doc: serde_json::Value = serde_json::from_str(&source)
        .map_err(|e| anyhow::anyhow!("import_json({filename:?}): invalid JSON: {e}"))?;

    Ok(BasePolicyValue::from_json(doc))
}
