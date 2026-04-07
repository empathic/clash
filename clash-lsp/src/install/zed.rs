use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn install(dry_run: bool) -> Result<String> {
    let path = config_path()?;
    let existing: Value = if path.exists() {
        serde_json::from_str(&std::fs::read_to_string(&path)?)
            .context("parse zed settings.json")?
    } else {
        json!({})
    };
    let merged = merge(existing);
    let serialized = serde_json::to_string_pretty(&merged)?;
    if dry_run {
        return Ok(format!("would write to {}:\n\n{}", path.display(), serialized));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &serialized)?;
    Ok(format!("wrote {}", path.display()))
}

fn config_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("no config dir")?
        .join("zed")
        .join("settings.json"))
}

fn merge(mut existing: Value) -> Value {
    let obj = existing.as_object_mut().expect("zed settings root is an object");
    let lsp = obj.entry("lsp").or_insert_with(|| json!({}));
    lsp["clash-lsp"] = json!({
        "binary": { "path": "clash", "arguments": ["lsp"] }
    });
    let langs = obj.entry("languages").or_insert_with(|| json!({}));
    langs["Starlark"] = json!({
        "language_servers": ["clash-lsp"]
    });
    existing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_into_empty() {
        let merged = merge(json!({}));
        assert_eq!(merged["lsp"]["clash-lsp"]["binary"]["path"], "clash");
        assert_eq!(merged["languages"]["Starlark"]["language_servers"][0], "clash-lsp");
    }

    #[test]
    fn preserves_existing_keys() {
        let merged = merge(json!({"theme": "One Dark"}));
        assert_eq!(merged["theme"], "One Dark");
    }
}
