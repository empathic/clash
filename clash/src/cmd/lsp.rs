use anyhow::Result;

use crate::cli::{Editor, LspCmd, LspSubcommand};

pub fn run(cmd: LspCmd) -> Result<()> {
    match cmd.subcommand {
        None => run_server(),
        Some(LspSubcommand::Install { editor, dry_run }) => {
            let report = clash_lsp::install::install(editor.into(), dry_run)?;
            println!("{report}");
            Ok(())
        }
    }
}

fn run_server() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(clash_lsp::run_stdio())
}

impl From<Editor> for clash_lsp::install::Editor {
    fn from(e: Editor) -> Self {
        match e {
            Editor::Vscode => clash_lsp::install::Editor::Vscode,
            Editor::Neovim => clash_lsp::install::Editor::Neovim,
            Editor::Helix => clash_lsp::install::Editor::Helix,
            Editor::Zed => clash_lsp::install::Editor::Zed,
        }
    }
}
