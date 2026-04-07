use zed_extension_api::{self as zed, LanguageServerId, Result};

struct ClashExtension;

impl zed::Extension for ClashExtension {
    fn new() -> Self {
        ClashExtension
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &LanguageServerId,
        _worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        Ok(zed::Command {
            command: "clash".to_string(),
            args: vec!["lsp".to_string()],
            env: vec![],
        })
    }
}

zed::register_extension!(ClashExtension);
