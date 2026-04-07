# Editor Setup for clash lsp

`clash lsp install --editor <name>` configures your editor to use the clash
language server for Starlark policy files. Pass `--dry-run` to preview the
changes without writing anything to disk.

Supported editors: `neovim`, `helix`, `zed`, `vscode`.

---

## Neovim

```
clash lsp install --editor neovim
```

Writes `~/.config/nvim/after/ftplugin/starlark.lua` with a `vim.lsp.start`
block that launches `clash lsp` whenever a Starlark file is opened. The file
is overwritten on each run, so re-running after a `clash` upgrade is safe.

**Manual setup (alternative):** add the following to your Neovim config:

```lua
-- ~/.config/nvim/after/ftplugin/starlark.lua
vim.lsp.start({
  name = "clash",
  cmd = { "clash", "lsp" },
  root_dir = vim.fs.root(0, { ".git", "policy.star", "policy.json" }),
})
```

---

## Helix

```
clash lsp install --editor helix
```

Merges into `~/.config/helix/languages.toml`. Adds a `[language-server.clash-lsp]`
entry and a `[[language]]` block for `starlark` (file type `*.star`). Any
existing language configuration is preserved; only the `starlark` language
entry is replaced/appended.

**Manual setup (alternative):** add to `~/.config/helix/languages.toml`:

```toml
[language-server.clash-lsp]
command = "clash"
args = ["lsp"]

[[language]]
name = "starlark"
file-types = ["star"]
language-servers = ["clash-lsp"]
```

---

## Zed

```
clash lsp install --editor zed
```

Merges into `~/.config/zed/settings.json`. Adds `lsp.clash-lsp.binary` and
`languages.Starlark.language_servers`. All existing keys are preserved.

**Manual setup (alternative):** add to `~/.config/zed/settings.json`:

```json
{
  "lsp": {
    "clash-lsp": {
      "binary": { "path": "clash", "arguments": ["lsp"] }
    }
  },
  "languages": {
    "Starlark": {
      "language_servers": ["clash-lsp"]
    }
  }
}
```

---

## VS Code

```
clash lsp install --editor vscode
```

VS Code support is provided by the official **clash policy** extension.
The `install` command prints instructions; it does not write files.

Install via the marketplace (search for **clash policy**) or run:

```
code --install-extension empathic.clash-policy
```

Once installed, the extension automatically spawns `clash lsp` for `.star`
and `policy.json` files.
