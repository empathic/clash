//! Editor integration helpers: write ready-to-use config snippets.

use anyhow::Result;

pub mod helix;
pub mod neovim;
pub mod vscode;
pub mod zed;

#[derive(Debug, Clone, Copy)]
pub enum Editor {
    Vscode,
    Neovim,
    Helix,
    Zed,
}

/// Run install for the chosen editor. Returns a human-readable report.
pub fn install(editor: Editor, dry_run: bool) -> Result<String> {
    match editor {
        Editor::Vscode => vscode::install(dry_run),
        Editor::Neovim => neovim::install(dry_run),
        Editor::Helix => helix::install(dry_run),
        Editor::Zed => zed::install(dry_run),
    }
}
