use zed_extension_api::{self as zed, LanguageServerId, Result};

struct ClashExtension;

impl zed::Extension for ClashExtension {
    fn new() -> Self {
        ClashExtension
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let command = worktree.which("clash").ok_or_else(|| {
            "could not find `clash` on PATH — install clash from https://github.com/empathic/clash"
                .to_string()
        })?;
        Ok(zed::Command {
            command,
            args: vec!["lsp".to_string()],
            env: worktree.shell_env(),
        })
    }
}

zed::register_extension!(ClashExtension);
