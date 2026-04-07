use anyhow::{Context, Result};
use std::path::PathBuf;

const SNIPPET: &str = r#"-- clash language server (managed by `clash lsp install`)
vim.lsp.start({
  name = "clash",
  cmd = { "clash", "lsp" },
  root_dir = vim.fs.root(0, { ".git", "policy.star", "policy.json" }),
})
"#;

pub fn install(dry_run: bool) -> Result<String> {
    let path = config_path()?;
    if dry_run {
        return Ok(format!("would write to {}:\n\n{}", path.display(), SNIPPET));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {parent:?}"))?;
    }
    std::fs::write(&path, SNIPPET).with_context(|| format!("write {path:?}"))?;
    Ok(format!("wrote {}", path.display()))
}

fn config_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("no config dir")?;
    Ok(base
        .join("nvim")
        .join("after")
        .join("ftplugin")
        .join("starlark.lua"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_does_not_touch_disk() {
        let out = install(true).unwrap();
        assert!(out.contains("would write"));
        assert!(out.contains("clash"));
    }
}
