# Clash Policy — Zed Extension

Starlark language support and `clash-lsp` integration for [Clash](https://github.com/empathic/clash) policy files (`.star`) in the [Zed editor](https://zed.dev).

## What it does

- Registers the Starlark language for `.star` files.
- Connects `clash lsp` as the language server, providing diagnostics,
  completions, hover docs, and go-to-definition.

## Prerequisites

`clash` must be on your PATH.  Install it by following the
[Clash installation guide](https://github.com/empathic/clash#installation).

## Installation (dev extension)

Until this extension is published to the Zed marketplace, install it as a
local dev extension:

1. Open Zed.
2. Open the command palette (`Cmd+Shift+P` on macOS, `Ctrl+Shift+P` on Linux).
3. Run **zed: install dev extension**.
4. Select this directory (`clash-zed/`) inside your clash checkout.

Zed compiles the extension automatically — no manual `cargo build` step is
required for local use.

## Quick install via `clash lsp install`

If you have clash installed you can run:

```sh
clash lsp install --editor zed
```

This prints the above instructions with the exact directory path on your machine.

## Publishing to the Zed marketplace

Publishing is a one-time manual step:

1. Fork [zed-industries/extensions](https://github.com/zed-industries/extensions).
2. Add `clash-zed` as a submodule under `extensions/clash-policy`.
3. Open a PR to `zed-industries/extensions` — the Zed team reviews and merges
   it, after which users can install directly from the Extensions panel.

## Building the wasm artifact manually

The wasm artifact is only needed if you want to inspect or redistribute it
outside of Zed's dev extension workflow.

```sh
cd clash-zed
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
# artifact: target/wasm32-wasip1/release/clash_zed.wasm
```

## Bugs and feedback

File issues at https://github.com/empathic/clash/issues.
