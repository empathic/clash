# Clash LSP — Plan 4: VS Code Extension

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Ship a VS Code extension `clash-policy` that activates on `.star` files, locates the `clash` binary on PATH, spawns `clash lsp`, and connects the language client. Published to the VS Code marketplace.

**Architecture:** Standard `vscode-languageclient` Node extension. Lives in a new top-level `clash-vscode/` directory (TypeScript, bun-based, mirroring `clash-opencode/`'s patterns). On activation: detect `clash` on PATH; if missing, show an error with a link to install instructions; otherwise spawn `clash lsp` over stdio and hand it to `LanguageClient`.

**Tech Stack:** TypeScript, `vscode-languageclient`, `bun`, `vsce` for packaging.

**Spec:** `docs/superpowers/specs/2026-04-06-clash-lsp-design.md`

**Prerequisite:** Plan 1 merged (`clash lsp` runs).

---

## File Structure

```
clash-vscode/
  package.json          # extension manifest, contributes, activationEvents
  tsconfig.json
  src/
    extension.ts        # activate(): find clash, start LanguageClient
    findClash.ts        # PATH lookup + version check
  syntaxes/
    starlark.tmLanguage.json   # basic highlighting (or `extends` an existing grammar)
  language-configuration.json
  README.md
  CHANGELOG.md
  .vscodeignore
```

---

## Task 1: Scaffold the extension package

**Files:**
- Create: `clash-vscode/package.json`
- Create: `clash-vscode/tsconfig.json`

- [ ] **Step 1: Look at `clash-opencode/` for the existing TS plugin pattern**

Run: `ls clash-opencode/ && cat clash-opencode/package.json`
Expected: see how this repo structures TS plugins (bun, scripts, deps).

- [ ] **Step 2: Write `package.json`**

```json
{
  "name": "clash-policy",
  "displayName": "Clash Policy",
  "description": "Language support for clash policy files (.star)",
  "version": "0.6.2",
  "publisher": "empathic",
  "repository": "https://github.com/empathic/clash",
  "engines": { "vscode": "^1.85.0" },
  "categories": ["Programming Languages", "Linters"],
  "activationEvents": [
    "onLanguage:clash-policy"
  ],
  "main": "./out/extension.js",
  "contributes": {
    "languages": [{
      "id": "clash-policy",
      "aliases": ["Clash Policy", "clash-policy"],
      "extensions": [".star"],
      "filenamePatterns": ["policy.star", "**/clash/**/*.star"],
      "configuration": "./language-configuration.json"
    }],
    "grammars": [{
      "language": "clash-policy",
      "scopeName": "source.python",
      "path": "./syntaxes/starlark.tmLanguage.json"
    }],
    "configuration": {
      "title": "Clash Policy",
      "properties": {
        "clashPolicy.binaryPath": {
          "type": "string",
          "default": "clash",
          "description": "Path to the clash binary. Defaults to looking up `clash` on PATH."
        }
      }
    }
  },
  "scripts": {
    "build": "tsc -p ./",
    "watch": "tsc -w -p ./",
    "package": "vsce package",
    "publish": "vsce publish"
  },
  "dependencies": {
    "vscode-languageclient": "^9.0.1"
  },
  "devDependencies": {
    "@types/node": "^20",
    "@types/vscode": "^1.85.0",
    "@vscode/vsce": "^3",
    "typescript": "^5"
  }
}
```

> **NOTE:** The `filenamePatterns` field scopes the language to `.star` files that *look like* clash policies, so we don't hijack every Bazel/Buck `.star` file in unrelated repos. Tune the patterns once we see them in real projects.

- [ ] **Step 3: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "module": "commonjs",
    "target": "ES2022",
    "lib": ["ES2022"],
    "outDir": "out",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "exclude": ["node_modules", ".vscode-test"]
}
```

- [ ] **Step 4: Install deps**

Run: `cd clash-vscode && bun install`
Expected: `node_modules` populated, lockfile written.

- [ ] **Step 5: Commit**

```bash
git add clash-vscode/package.json clash-vscode/tsconfig.json clash-vscode/bun.lock
git commit -m "feat(vscode): scaffold clash-policy extension"
```

---

## Task 2: `findClash` helper

**Files:**
- Create: `clash-vscode/src/findClash.ts`

- [ ] **Step 1: Implement**

```typescript
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as vscode from "vscode";

const exec = promisify(execFile);

export interface ClashLocation {
  command: string;
  version: string;
}

/**
 * Locate the clash binary, honoring `clashPolicy.binaryPath` if set.
 * Throws a user-facing error if clash is missing or unrunnable.
 */
export async function findClash(): Promise<ClashLocation> {
  const config = vscode.workspace.getConfiguration("clashPolicy");
  const command = config.get<string>("binaryPath") || "clash";

  try {
    const { stdout } = await exec(command, ["--version"]);
    return { command, version: stdout.trim() };
  } catch (err) {
    throw new Error(
      `Could not run \`${command} --version\`. Install clash from ` +
      `https://github.com/empathic/clash or set \`clashPolicy.binaryPath\` ` +
      `in settings. (${(err as Error).message})`
    );
  }
}
```

- [ ] **Step 2: Commit (will compile after Task 3)**

Hold the commit until extension.ts exists.

---

## Task 3: `extension.ts` — activation

**Files:**
- Create: `clash-vscode/src/extension.ts`

- [ ] **Step 1: Implement**

```typescript
import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";
import { findClash } from "./findClash";

let client: LanguageClient | undefined;

export async function activate(context: vscode.ExtensionContext) {
  let location;
  try {
    location = await findClash();
  } catch (err) {
    void vscode.window.showErrorMessage((err as Error).message);
    return;
  }

  const serverOptions: ServerOptions = {
    command: location.command,
    args: ["lsp"],
    transport: TransportKind.stdio,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "clash-policy" },
    ],
    synchronize: {
      fileEvents: vscode.workspace.createFileSystemWatcher("**/*.star"),
    },
  };

  client = new LanguageClient(
    "clashPolicy",
    "Clash Policy",
    serverOptions,
    clientOptions,
  );

  context.subscriptions.push({ dispose: () => client?.stop() });
  await client.start();
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
```

- [ ] **Step 2: Build**

Run: `cd clash-vscode && bun run build`
Expected: clean compile, `out/extension.js` produced.

- [ ] **Step 3: Commit**

```bash
git add clash-vscode/src/
git commit -m "feat(vscode): activate language client for clash lsp"
```

---

## Task 4: Language configuration & basic grammar

**Files:**
- Create: `clash-vscode/language-configuration.json`
- Create: `clash-vscode/syntaxes/starlark.tmLanguage.json`

- [ ] **Step 1: Write `language-configuration.json`**

```json
{
  "comments": { "lineComment": "#" },
  "brackets": [["{","}"], ["[","]"], ["(",")"]],
  "autoClosingPairs": [
    { "open": "{", "close": "}" },
    { "open": "[", "close": "]" },
    { "open": "(", "close": ")" },
    { "open": "\"", "close": "\"" },
    { "open": "'", "close": "'" }
  ],
  "surroundingPairs": [["{","}"], ["[","]"], ["(",")"], ["\"","\""], ["'","'"]]
}
```

- [ ] **Step 2: Grammar**

Starlark is close enough to Python for basic highlighting. The simplest move is to bundle a minimal grammar that maps `.star` to `source.python` (already declared in `package.json`'s `scopeName`). Write a near-empty `starlark.tmLanguage.json`:

```json
{
  "$schema": "https://raw.githubusercontent.com/martinring/tmlanguage/master/tmlanguage.json",
  "name": "Starlark",
  "scopeName": "source.python",
  "patterns": [],
  "fileTypes": ["star"]
}
```

> **NOTE:** A real Starlark TextMate grammar exists in the wild (e.g. Bazel's). If we want crisper highlighting later, vendor one. For v1, "good enough Python-ish" is fine because the LSP provides the substantive feedback.

- [ ] **Step 3: Build & sanity-check**

Run: `cd clash-vscode && bun run build && bunx vsce ls`
Expected: lists the files that would be packaged. Verify `out/`, `package.json`, grammar files, README are present and `node_modules/` is not.

- [ ] **Step 4: Add `.vscodeignore`**

```
.vscode/**
.vscode-test/**
src/**
.gitignore
tsconfig.json
**/*.map
**/*.ts
node_modules/**
!node_modules/vscode-languageclient/**
```

(The `!node_modules/vscode-languageclient/**` is important: the runtime needs the client at runtime since we're not bundling.)

- [ ] **Step 5: Commit**

```bash
git add clash-vscode/language-configuration.json clash-vscode/syntaxes/ clash-vscode/.vscodeignore
git commit -m "feat(vscode): language config and grammar for clash policies"
```

---

## Task 5: Activation smoke test

**Files:**
- Create: `clash-vscode/src/test/activation.test.ts` (and supporting test runner)

- [ ] **Step 1: Read what's already in the workspace**

Run: `find . -name "test-electron*" -o -name "vscode-test*" 2>/dev/null | head`

If `@vscode/test-electron` is not yet a workspace dep elsewhere, add it as a dev dep in `clash-vscode/package.json`:

```json
"@vscode/test-electron": "^2.4.0"
```

and `bun install`.

- [ ] **Step 2: Write a single activation test**

```typescript
import * as assert from "node:assert";
import * as vscode from "vscode";

suite("clash-policy extension", () => {
  test("activates on .star files", async () => {
    const ext = vscode.extensions.getExtension("empathic.clash-policy");
    assert.ok(ext, "extension should be registered");
    const doc = await vscode.workspace.openTextDocument({
      language: "clash-policy",
      content: "policy({})\n",
    });
    await vscode.window.showTextDocument(doc);
    await ext!.activate();
    assert.strictEqual(ext!.isActive, true);
  });
});
```

- [ ] **Step 3: Run**

Run: `cd clash-vscode && bun run test`
Expected: PASS. (If `clash` is not on PATH in CI, the activation will surface the missing-binary error message — that's fine; this test just verifies the extension loads, not the LSP handshake.)

- [ ] **Step 4: Commit**

```bash
git add clash-vscode/src/test/ clash-vscode/package.json clash-vscode/bun.lock
git commit -m "test(vscode): activation smoke test"
```

---

## Task 6: README + marketplace metadata

**Files:**
- Create: `clash-vscode/README.md`
- Create: `clash-vscode/CHANGELOG.md`

- [ ] **Step 1: Write the README**

Cover: what the extension does, how to install (`code --install-extension empathic.clash-policy`), prerequisite (`clash` on PATH), `clashPolicy.binaryPath` setting, where to file bugs.

- [ ] **Step 2: Write the CHANGELOG**

```markdown
# Changelog

## 0.6.2 — initial release

- Diagnostics for clash `.star` policies
- Completion for builtins (`policy`, `sandbox`, `settings`)
- Hover with signatures and docs
- Go-to-definition for top-level symbols
```

- [ ] **Step 3: Commit**

```bash
git add clash-vscode/README.md clash-vscode/CHANGELOG.md
git commit -m "docs(vscode): README and changelog"
```

---

## Task 7: Update `clash lsp install --editor vscode`

**Files:**
- Modify: `clash-lsp/src/install/vscode.rs`

- [ ] **Step 1: Detect `code` on PATH and offer to install**

Replace the stub from plan 3 task 6:

```rust
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
        return Ok(format!("would run: code --install-extension {EXTENSION_ID}"));
    }
    let status = Command::new("code")
        .args(["--install-extension", EXTENSION_ID])
        .status()?;
    if !status.success() {
        return Ok(format!("code --install-extension exited with {status}"));
    }
    Ok(format!("installed {EXTENSION_ID} via code CLI"))
}
```

Add `which.workspace = true` to `clash-lsp/Cargo.toml` if not already inherited.

- [ ] **Step 2: Update tests**

Replace the test in `clash-lsp/src/install/vscode.rs`:

```rust
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
```

- [ ] **Step 3: Run**

Run: `cargo test -p clash-lsp install::vscode && just check`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add clash-lsp/src/install/vscode.rs clash-lsp/Cargo.toml
git commit -m "feat(lsp): clash lsp install --editor vscode invokes code CLI"
```

---

## Task 8: CI + publish workflow (manual for v1)

**Files:**
- Modify: `justfile` (add a `vscode-package` target)

- [ ] **Step 1: Add a recipe**

Append to `justfile`:

```make
vscode-package:
    cd clash-vscode && bun install && bun run build && bunx vsce package
```

- [ ] **Step 2: Run it**

Run: `just vscode-package`
Expected: produces `clash-vscode/clash-policy-0.6.2.vsix`.

- [ ] **Step 3: Commit**

```bash
git add justfile
git commit -m "build(vscode): add just recipe to package the extension"
```

> **NOTE:** Marketplace publishing (`vsce publish`) needs an Azure DevOps PAT. That's a one-time human step — don't automate it in CI for v1. Document the publish process in `clash-vscode/README.md` under a "Releasing" section.

---

## Done

`clash lsp` is reachable from VS Code with one click. Plans 1–4 together deliver the full v1 spec.
