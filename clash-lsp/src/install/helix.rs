use anyhow::{Context, Result};
use std::path::PathBuf;
use toml::Value;

const LANGUAGE_NAME: &str = "starlark";
const SERVER_NAME: &str = "clash-lsp";

pub fn install(dry_run: bool) -> Result<String> {
    let path = config_path()?;
    let existing: Value = if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        toml::from_str(&text).context("parse existing helix languages.toml")?
    } else {
        toml::from_str("").unwrap()
    };

    let merged = merge(existing);
    let serialized = toml::to_string_pretty(&merged)?;

    if dry_run {
        return Ok(format!(
            "would write to {}:\n\n{}",
            path.display(),
            serialized
        ));
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
        .join("helix")
        .join("languages.toml"))
}

fn merge(mut existing: Value) -> Value {
    let table = existing.as_table_mut().expect("toml root is a table");

    // [language-server.clash-lsp]
    let servers = table
        .entry("language-server")
        .or_insert_with(|| Value::Table(Default::default()));
    let servers_tbl = servers.as_table_mut().unwrap();
    let mut clash_server = toml::value::Table::new();
    clash_server.insert("command".into(), Value::String("clash".into()));
    clash_server.insert(
        "args".into(),
        Value::Array(vec![Value::String("lsp".into())]),
    );
    servers_tbl.insert(SERVER_NAME.into(), Value::Table(clash_server));

    // [[language]] entry for starlark
    let langs = table
        .entry("language")
        .or_insert_with(|| Value::Array(vec![]));
    let langs_arr = langs.as_array_mut().unwrap();
    // Replace any existing starlark entry; otherwise append.
    langs_arr.retain(|v| v.get("name").and_then(|n| n.as_str()) != Some(LANGUAGE_NAME));
    let mut entry = toml::value::Table::new();
    entry.insert("name".into(), Value::String(LANGUAGE_NAME.into()));
    entry.insert(
        "file-types".into(),
        Value::Array(vec![Value::String("star".into())]),
    );
    entry.insert(
        "language-servers".into(),
        Value::Array(vec![Value::String(SERVER_NAME.into())]),
    );
    langs_arr.push(Value::Table(entry));

    existing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_into_empty_config() {
        let merged = merge(toml::from_str("").unwrap());
        let s = toml::to_string(&merged).unwrap();
        assert!(s.contains("clash-lsp"));
        assert!(s.contains("starlark"));
    }

    #[test]
    fn preserves_unrelated_languages() {
        let existing: Value = toml::from_str(
            r#"
            [[language]]
            name = "rust"
            file-types = ["rs"]
        "#,
        )
        .unwrap();
        let merged = merge(existing);
        let s = toml::to_string(&merged).unwrap();
        assert!(s.contains("rust"));
        assert!(s.contains("starlark"));
    }
}
