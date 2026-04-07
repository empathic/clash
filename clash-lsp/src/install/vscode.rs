use anyhow::Result;
use std::process::Command;

const EXTENSION_ID: &str = "empathic.clash-policy";

pub fn install(dry_run: bool) -> Result<String> {
    let code = which::which("code");
    if code.is_err() {
        return Ok(format!(
            "VS Code's `code` CLI is not on PATH. Install the extension manually:\n\n  \
             search for \"clash policy\" in the Extensions panel\n  \
             or visit https://marketplace.visualstudio.com/items?itemName={EXTENSION_ID}\n"
        ));
    }
    if dry_run {
        return Ok(format!(
            "would run: code --install-extension {EXTENSION_ID}"
        ));
    }
    let status = Command::new("code")
        .args(["--install-extension", EXTENSION_ID])
        .status()?;
    if !status.success() {
        return Ok(format!("code --install-extension exited with {status}"));
    }
    Ok(format!("installed {EXTENSION_ID} via code CLI"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_returns_install_intent() {
        // Whether `code` is on PATH or not, the result mentions the extension id.
        let s = install(true).unwrap();
        assert!(s.contains("clash-policy"));
    }
}
