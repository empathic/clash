# Clash LSP — Plan 3: `clash lsp install` Subcommand

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Add `clash lsp install --editor <vscode|nvim|helix|zed>` so users get one-command setup for any supported editor instead of hand-editing config files.

**Architecture:** Introduce a small `install` module under `clash-lsp` (pure functions: editor → config patch). The `clash lsp` subcommand becomes a subcommand group with two children: `clash lsp` (run server, default) and `clash lsp install`. Each editor adapter knows its config file location and how to merge a clash language client entry without clobbering existing config.

**Tech Stack:** Rust, `serde_json`, `toml`, `dirs`.

**Spec:** `docs/superpowers/specs/2026-04-06-clash-lsp-design.md`

**Prerequisite:** Plan 1 merged.

---

## File Structure (additions)

```
clash-lsp/src/install/
  mod.rs                # Editor enum, install() entry point
  vscode.rs             # writes ~/.vscode/extensions or shows marketplace URL
  neovim.rs             # writes ~/.config/nvim/after/ftplugin/starlark.lua
  helix.rs              # patches ~/.config/helix/languages.toml
  zed.rs                # patches ~/.config/zed/settings.json
clash/src/cli.rs        # split `Lsp` into a subcommand group
clash/src/cmd/lsp.rs    # dispatch run vs install
```

---

## Task 1: Restructure the CLI surface

**Files:**
- Modify: `clash/src/cli.rs`
- Modify: `clash/src/cmd/lsp.rs`
- Modify: `clash/src/main.rs`

- [ ] **Step 1: Replace the flat `Lsp` variant with a subcommand group**

In `clash/src/cli.rs`, replace `Lsp,` with:

```rust
    /// Run the clash language server, or install editor configuration
    Lsp(LspCmd),
```

Add at the bottom of the file:

```rust
#[derive(clap::Args, Debug)]
pub struct LspCmd {
    #[command(subcommand)]
    pub subcommand: Option<LspSubcommand>,
}

#[derive(Subcommand, Debug)]
pub enum LspSubcommand {
    /// Install editor configuration to use clash lsp
    Install {
        /// Which editor to configure
        #[arg(long, value_enum)]
        editor: Editor,
        /// Print the config that would be written without applying it
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum Editor {
    Vscode,
    Neovim,
    Helix,
    Zed,
}
```

Default behavior (no subcommand) = run the server, preserving plan 1's behavior.

- [ ] **Step 2: Update the dispatcher**

`clash/src/cmd/lsp.rs`:

```rust
use anyhow::Result;
use crate::cli::{LspCmd, LspSubcommand, Editor};

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
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(clash_lsp::run_stdio())
}

impl From<Editor> for clash_lsp::install::Editor {
    fn from(e: Editor) -> Self {
        match e {
            Editor::Vscode => clash_lsp::install::Editor::Vscode,
            Editor::Neovim => clash_lsp::install::Editor::Neovim,
            Editor::Helix  => clash_lsp::install::Editor::Helix,
            Editor::Zed    => clash_lsp::install::Editor::Zed,
        }
    }
}
```

In `main.rs`, the match arm becomes:

```rust
        Commands::Lsp(cmd) => crate::cmd::lsp::run(cmd)?,
```

- [ ] **Step 3: Build (will fail until install module exists)**

Run: `cargo build -p clash`
Expected: FAIL — `clash_lsp::install` doesn't exist yet. That's the next task.

---

## Task 2: `install` module skeleton

**Files:**
- Create: `clash-lsp/src/install/mod.rs`
- Modify: `clash-lsp/src/lib.rs`

- [ ] **Step 1: Add the module**

`clash-lsp/src/install/mod.rs`:

```rust
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
        Editor::Helix  => helix::install(dry_run),
        Editor::Zed    => zed::install(dry_run),
    }
}
```

Add `pub mod install;` to `lib.rs`. Add `dirs.workspace = true` to `clash-lsp/Cargo.toml` deps.

- [ ] **Step 2: Stub each editor module so the build passes**

For each of `vscode.rs`, `neovim.rs`, `helix.rs`, `zed.rs`:

```rust
use anyhow::{Result, bail};

pub fn install(_dry_run: bool) -> Result<String> {
    bail!("not yet implemented")
}
```

- [ ] **Step 3: Build**

Run: `cargo build`
Expected: clean (CLI now compiles, install commands return errors).

- [ ] **Step 4: Commit**

```bash
git add clash/ clash-lsp/
git commit -m "feat(lsp): scaffold clash lsp install subcommand"
```

---

## Task 3: Neovim adapter (simplest, do first)

**Files:**
- Modify: `clash-lsp/src/install/neovim.rs`

- [ ] **Step 1: Implement**

```rust
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
    Ok(base.join("nvim").join("after").join("ftplugin").join("starlark.lua"))
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
```

- [ ] **Step 2: Run**

Run: `cargo test -p clash-lsp install::neovim`
Expected: PASS.

- [ ] **Step 3: Manual smoke test**

Run: `cargo run -p clash -- lsp install --editor neovim --dry-run`
Expected: prints the snippet and the target path.

- [ ] **Step 4: Commit**

```bash
git add clash-lsp/src/install/neovim.rs
git commit -m "feat(lsp): clash lsp install --editor neovim"
```

---

## Task 4: Helix adapter

**Files:**
- Modify: `clash-lsp/src/install/helix.rs`

- [ ] **Step 1: Implement**

Helix uses `~/.config/helix/languages.toml`. We need to *merge* not overwrite — Helix users will have other language configs.

```rust
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
        return Ok(format!("would write to {}:\n\n{}", path.display(), serialized));
    }
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(&path, &serialized)?;
    Ok(format!("wrote {}", path.display()))
}

fn config_path() -> Result<PathBuf> {
    Ok(dirs::config_dir().context("no config dir")?.join("helix").join("languages.toml"))
}

fn merge(mut existing: Value) -> Value {
    let table = existing.as_table_mut().expect("toml root is a table");

    // [language-server.clash-lsp]
    let servers = table.entry("language-server").or_insert_with(|| Value::Table(Default::default()));
    let servers_tbl = servers.as_table_mut().unwrap();
    let mut clash_server = toml::value::Table::new();
    clash_server.insert("command".into(), Value::String("clash".into()));
    clash_server.insert("args".into(), Value::Array(vec![Value::String("lsp".into())]));
    servers_tbl.insert(SERVER_NAME.into(), Value::Table(clash_server));

    // [[language]] entry for starlark
    let langs = table.entry("language").or_insert_with(|| Value::Array(vec![]));
    let langs_arr = langs.as_array_mut().unwrap();
    // Replace any existing starlark entry; otherwise append.
    langs_arr.retain(|v| v.get("name").and_then(|n| n.as_str()) != Some(LANGUAGE_NAME));
    let mut entry = toml::value::Table::new();
    entry.insert("name".into(), Value::String(LANGUAGE_NAME.into()));
    entry.insert("file-types".into(), Value::Array(vec![Value::String("star".into())]));
    entry.insert("language-servers".into(), Value::Array(vec![Value::String(SERVER_NAME.into())]));
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
        let existing: Value = toml::from_str(r#"
            [[language]]
            name = "rust"
            file-types = ["rs"]
        "#).unwrap();
        let merged = merge(existing);
        let s = toml::to_string(&merged).unwrap();
        assert!(s.contains("rust"));
        assert!(s.contains("starlark"));
    }
}
```

- [ ] **Step 2: Run**

Run: `cargo test -p clash-lsp install::helix`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/src/install/helix.rs
git commit -m "feat(lsp): clash lsp install --editor helix"
```

---

## Task 5: Zed adapter

**Files:**
- Modify: `clash-lsp/src/install/zed.rs`

- [ ] **Step 1: Implement**

Zed config lives at `~/.config/zed/settings.json`. We add a `lsp` entry for the `starlark` language.

```rust
use anyhow::{Context, Result};
use serde_json::{Value, json};
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
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(&path, &serialized)?;
    Ok(format!("wrote {}", path.display()))
}

fn config_path() -> Result<PathBuf> {
    Ok(dirs::config_dir().context("no config dir")?.join("zed").join("settings.json"))
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
```

- [ ] **Step 2: Run**

Run: `cargo test -p clash-lsp install::zed`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/src/install/zed.rs
git commit -m "feat(lsp): clash lsp install --editor zed"
```

---

## Task 6: VS Code adapter (without the extension yet)

**Files:**
- Modify: `clash-lsp/src/install/vscode.rs`

VS Code is unusual: the right path is the published extension (plan 4). Until that ships, `install --editor vscode` should print the marketplace URL and instructions, NOT touch user settings. Once plan 4 ships, this adapter is updated to verify the extension is installed and offer to install it via `code --install-extension`.

- [ ] **Step 1: Implement the placeholder**

```rust
use anyhow::Result;

pub fn install(_dry_run: bool) -> Result<String> {
    Ok(concat!(
        "VS Code support is provided by the official extension.\n\n",
        "Install it from the marketplace (search for \"clash policy\")\n",
        "or run:\n\n",
        "    code --install-extension empathic.clash-policy\n\n",
        "Once installed, the extension will spawn `clash lsp` automatically.\n"
    ).to_string())
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
```

- [ ] **Step 2: Run**

Run: `cargo test -p clash-lsp install::vscode`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/src/install/vscode.rs
git commit -m "feat(lsp): clash lsp install --editor vscode"
```

---

## Task 7: Docs

**Files:**
- Create: `docs/editor-setup.md`
- Modify: `AGENTS.md`

- [ ] **Step 1: Write the docs page**

`docs/editor-setup.md`: short page documenting `clash lsp install --editor <name>`, what it writes, and the manual instructions for any editor we don't directly support yet. One short section per editor.

- [ ] **Step 2: Update AGENTS.md command list**

Add `clash lsp install` next to `clash lsp` in the CLI commands enumeration.

- [ ] **Step 3: Run `just check`**

Run: `just check`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add docs/editor-setup.md AGENTS.md
git commit -m "docs: editor setup guide for clash lsp"
```

---

## Done

Three editors get one-command setup. VS Code is stubbed pending plan 4.
