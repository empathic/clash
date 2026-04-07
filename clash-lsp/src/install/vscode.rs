use anyhow::Result;

pub fn install(_dry_run: bool) -> Result<String> {
    Ok(concat!(
        "VS Code support is provided by the official extension.\n\n",
        "Install it from the marketplace (search for \"clash policy\")\n",
        "or run:\n\n",
        "    code --install-extension empathic.clash-policy\n\n",
        "Once installed, the extension will spawn `clash lsp` automatically.\n"
    )
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_marketplace_instructions() {
        let s = install(false).unwrap();
        assert!(s.contains("marketplace") || s.contains("install-extension"));
    }
}
