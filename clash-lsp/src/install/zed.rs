use anyhow::Result;

/// Returns install instructions for the Clash Zed extension.
///
/// Zed does not support arbitrary `lsp.<name>.binary` settings, so the only
/// supported path is installing the `clash-zed` extension.  This function
/// prints human-readable guidance; it does NOT touch settings.json.
pub fn install(_dry_run: bool) -> Result<String> {
    let msg = r#"To use clash-lsp in Zed, install the clash-zed dev extension:

  1. Open Zed and bring up the command palette (Cmd+Shift+P / Ctrl+Shift+P).
  2. Run: zed: install dev extension
  3. Select the clash-zed/ directory inside your clash checkout
     (e.g. ~/code/clash/clash-zed).

This registers the Starlark language and the clash-lsp language server so
that .star files are automatically connected to `clash lsp`.

Prerequisites: `clash` must be on your PATH.

Once the extension is published to the Zed marketplace you will be able to
install it directly from Extensions panel — search for "Clash Policy"."#;
    Ok(msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_mention_dev_extension() {
        let out = install(false).unwrap();
        assert!(
            out.contains("dev extension"),
            "output should mention dev extension"
        );
    }

    #[test]
    fn instructions_mention_clash_zed() {
        let out = install(false).unwrap();
        assert!(
            out.contains("clash-zed"),
            "output should mention the clash-zed extension directory"
        );
    }

    #[test]
    fn dry_run_same_as_normal() {
        // dry_run has no effect — instructions are the same either way
        assert_eq!(install(true).unwrap(), install(false).unwrap());
    }
}
