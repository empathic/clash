# Clash LSP — Design

## Goal

Provide a Language Server Protocol implementation for clash policy authoring,
targeting `.star` (Starlark) policy files. v1 ships diagnostics, completion,
hover, and go-to-definition with first-class integration for VS Code, Neovim,
Helix, and Zed.

## Distribution

- The language server runs as `clash lsp` (stdio). Anyone with `clash`
  installed has the LSP — no extra binary, no extra install step.
- `clash lsp install --editor <vscode|nvim|helix|zed>` writes the editor-side
  config so users don't hand-edit JSON/Lua/TOML. Mirrors the ergonomics of
  `clash init --agent ...`.
- A VS Code extension (`clash-vscode/` in the workspace, published to the
  marketplace) auto-detects `clash` on PATH, prompts to install if missing,
  and spawns `clash lsp`.

## Architecture

A new workspace crate `clash-lsp` contains the language server. The `clash`
binary gains a `lsp` subcommand that calls into it. Built on `tower-lsp`.

Dependencies:
- `clash_starlark` — parsing, scope, eval of `.star` policies.
- `clash::policy` — IR validation, capability schema.
- `clash::policy_gen` — shared definitions of the policy DSL surface (single
  source of truth for builtins, signatures, capability shapes).

## Components inside `clash-lsp`

- **`server`** — `tower-lsp` `LanguageServer` impl. Owns document state,
  dispatches LSP requests. Thin; delegates everything.
- **`documents`** — in-memory store of open `.star` files keyed by URI. Holds
  source text, last successful parse, and last diagnostics. Incremental sync.
- **`analysis`** — pure functions: `parse(text) -> ParsedPolicy`,
  `validate(parsed) -> Vec<Diagnostic>`, `symbols(parsed) -> SymbolIndex`. No
  I/O. Reuses `clash_starlark` and `clash::policy`. Clash-specific semantics
  live here: rule shape checks, capability matcher validation, unknown-builtin
  detection.
- **`features`** — one module per LSP feature: `diagnostics`, `completion`,
  `hover`, `goto_definition`. Each takes cached analysis output and produces
  an LSP response. Each is unit-testable without spinning up a server.
- **`schema`** — single source of truth describing clash's policy DSL: the
  builtins (`policy`, `sandbox`, `settings`, capability constructors), their
  signatures, docstrings, capability matcher shapes. Drives completion, hover,
  and validation. Generated from / shared with `clash/src/policy_gen/` so the
  LSP cannot drift from the real policy compiler.

The boundary that matters: `analysis` and `schema` are pure and
unit-testable. `server` and `documents` handle state and protocol. `features`
is the seam between them.

## Data flow

```
editor → didOpen/didChange → server → documents.update(uri, text)
                                        ↓
                                   analysis.parse + analysis.validate
                                        ↓
                                   cache ParsedPolicy + diagnostics
                                        ↓
                              server pushes diagnostics → editor

editor → completion/hover/definition → server → features.<x>(cached, position)
                                                   ↓
                                              LSP response → editor
```

Re-analysis runs on every change. Parsing a single `.star` file is fast, so
v1 has no background workers and no incremental reparse. Optimize only if
profiling shows it.

## Features (v1)

- **Diagnostics**: parse errors, unknown builtins, invalid rule shapes, bad
  capability matchers. Pushed on every change.
- **Completion**: builtins (`policy`, `sandbox`, `settings`), capability
  domains (`exec`, `fs`, `net`), matcher constructors (`literal`, `any`,
  `glob`), and field names within rule objects.
- **Hover**: docstrings and signatures for builtins, capability fields, and
  matcher types — sourced from `schema`.
- **Go-to-definition**: jump to rule and symbol definitions within the same
  file. Cross-file support is out of scope for v1.

## Error handling

- Parse errors → diagnostics with the Starlark span; never crash the server.
- IR validation errors → diagnostics with `severity = Error` and a stable
  code (e.g. `clash/E001`).
- Schema lookup misses → no completion/hover, debug log, never error.
- Server-internal panics → caught at the `tower-lsp` boundary; logged to
  stderr (editor surfaces it); document marked degraded, server stays up.

## Testing

- **Unit tests** in `analysis`, `schema`, and each `features` module — pure
  functions, golden-style: input `.star` snippet → expected
  diagnostics/completions/hover.
- **Integration tests** in `clash-lsp/tests/` driving the server over an
  in-process stdio pipe with scripted LSP messages.
- **End-to-end** via `clester`: one smoke script that runs `clash lsp`, sends
  a `didOpen` for a fixture `.star`, and asserts diagnostics.
- **VS Code extension** uses `@vscode/test-electron` for a minimal activation
  test that verifies `clash lsp` is spawned. Not in the Rust CI loop.

## Out of scope for v1

- `.json` policy files (compiled IR).
- Cross-file go-to-definition, workspace symbol search, rename refactoring.
- Formatting (`clash fmt` already exists; can be wired in later).
- Incremental reparse / background analysis.
- Semantic tokens / advanced highlighting.
