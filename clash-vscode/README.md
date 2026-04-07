# Clash Policy — VS Code Extension

Language support for [Clash](https://github.com/empathic/clash) policy files (`.star`).

## What it does

- Diagnostics for policy syntax and semantic errors in `.star` files
- Completion for builtins (`policy`, `sandbox`, `settings`)
- Hover documentation with signatures and descriptions
- Go-to-definition for top-level symbols

The extension spawns `clash lsp` as a language server over stdio and connects it to VS Code's language client infrastructure.

## Prerequisites

`clash` must be on your PATH. Install it by following the [Clash installation guide](https://github.com/empathic/clash#installation).

## Installation

**From the marketplace:**

```
code --install-extension empathic.clash-policy
```

Or search for "Clash Policy" in the Extensions panel (`Ctrl+Shift+X` / `Cmd+Shift+X`).

## Configuration

| Setting | Default | Description |
|---|---|---|
| `clashPolicy.binaryPath` | `"clash"` | Path to the `clash` binary. Override if `clash` is not on PATH or you want to pin a specific version. |

Example `settings.json`:

```json
{
  "clashPolicy.binaryPath": "/usr/local/bin/clash"
}
```

## Supported files

The extension activates on `.star` files that match one of:
- `policy.star`
- Any file inside a `clash/` directory: `**/clash/**/*.star`

This scoping avoids hijacking Bazel/Buck `.star` files in unrelated repos.

## Packaging

To produce a local `.vsix` for manual installation:

```bash
cd clash-vscode
bun install
bun run build
bunx vsce package
# produces clash-policy-<version>.vsix
code --install-extension clash-policy-<version>.vsix
```

Or use the workspace recipe:

```bash
just vscode-package
```

## Releasing

Publishing to the VS Code Marketplace is a manual step:

1. Obtain an Azure DevOps PAT with the **Marketplace (Manage)** scope from https://dev.azure.com/empathic/.
2. Run `bunx vsce publish` (or `bun run publish`) from the `clash-vscode/` directory.
3. Verify the new version appears at https://marketplace.visualstudio.com/items?itemName=empathic.clash-policy.

## Bugs and feedback

File issues at https://github.com/empathic/clash/issues.
