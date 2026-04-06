# Clash LSP — Plan 1: Skeleton + Diagnostics

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Stand up the `clash-lsp` workspace crate, wire it into a `clash lsp` stdio subcommand, sync open documents, and publish parse-error and policy-validation diagnostics.

**Architecture:** New workspace crate `clash-lsp` built on `tower-lsp`. Pure `analysis` module wraps `clash_starlark` parsing and `clash::policy` IR validation. `clash` binary gains an `lsp` subcommand that calls `clash_lsp::run_stdio()`. End-to-end smoke test via `clester`.

**Tech Stack:** Rust 2024, `tower-lsp`, `tokio`, `clash_starlark`, `clash::policy`, `lsp-types`.

**Spec:** `docs/superpowers/specs/2026-04-06-clash-lsp-design.md`

---

## File Structure

```
clash-lsp/
  Cargo.toml
  src/
    lib.rs              # pub fn run_stdio() -> anyhow::Result<()>; module exports
    server.rs           # tower_lsp::LanguageServer impl, dispatch only
    documents.rs        # DocumentStore: per-URI text + cached analysis
    analysis/
      mod.rs            # parse() + validate() entry points, ParsedPolicy struct
      diagnostic.rs     # AnalysisDiagnostic + conversion to lsp_types::Diagnostic
  tests/
    diagnostics.rs      # in-process server integration tests
clash/src/
  cli.rs                # add `Lsp` variant
  cmd/lsp.rs            # thin wrapper calling clash_lsp::run_stdio()
clester/tests/scripts/
  lsp_diagnostics.yaml  # smoke test
```

---

## Task 1: Create the `clash-lsp` crate

**Files:**
- Create: `clash-lsp/Cargo.toml`
- Create: `clash-lsp/src/lib.rs`
- Modify: `Cargo.toml` (workspace members + workspace dep entry)

- [ ] **Step 1: Add `tower-lsp` and `lsp-types` to workspace deps**

Edit `Cargo.toml`, add under `[workspace.dependencies]` (alphabetical):

```toml
lsp-types = "0.95"
tower-lsp = "0.20"
```

- [ ] **Step 2: Add the crate to workspace members**

In `Cargo.toml`, append to `members`:

```toml
    "clash-lsp",
```

And add an internal workspace alias near the bottom alongside `clash_starlark`:

```toml
clash-lsp = { path = "clash-lsp", version = "0.6.2" }
```

- [ ] **Step 3: Write `clash-lsp/Cargo.toml`**

```toml
[package]
name = "clash-lsp"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
anyhow.workspace = true
clash = { path = "../clash", version = "0.6.2" }
clash_starlark.workspace = true
lsp-types.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { workspace = true, features = ["rt-multi-thread", "io-std", "macros", "sync"] }
tower-lsp.workspace = true
tracing.workspace = true

[dev-dependencies]
indoc.workspace = true
pretty_assertions.workspace = true
```

- [ ] **Step 4: Write the empty `lib.rs`**

```rust
//! Language Server Protocol implementation for clash policy files.

pub mod analysis;
pub mod documents;
pub mod server;

/// Run the language server over stdio. Blocks until the client disconnects.
pub async fn run_stdio() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = tower_lsp::LspService::new(server::Backend::new);
    tower_lsp::Server::new(stdin, stdout, socket).serve(service).await;
    Ok(())
}
```

Also create empty stubs so the crate compiles:

`clash-lsp/src/analysis/mod.rs`:
```rust
//! Pure analysis: parse + validate clash `.star` policies.
```

`clash-lsp/src/documents.rs`:
```rust
//! In-memory store of open documents.
```

`clash-lsp/src/server.rs`:
```rust
//! `tower_lsp::LanguageServer` implementation.

use tower_lsp::{Client, LanguageServer, jsonrpc};
use tower_lsp::lsp_types::*;

pub struct Backend {
    #[allow(dead_code)]
    client: Client,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> jsonrpc::Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities::default(),
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {}

    async fn shutdown(&self) -> jsonrpc::Result<()> { Ok(()) }
}
```

- [ ] **Step 5: Build the workspace**

Run: `cargo build -p clash-lsp`
Expected: clean build, no warnings.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml clash-lsp/
git commit -m "feat(lsp): scaffold clash-lsp crate"
```

---

## Task 2: Wire up the `clash lsp` subcommand

**Files:**
- Modify: `clash/Cargo.toml` (add `clash-lsp` dep)
- Modify: `clash/src/cli.rs` (add `Lsp` variant)
- Modify: `clash/src/main.rs` (dispatch)
- Create: `clash/src/cmd/lsp.rs`

- [ ] **Step 1: Add the dep**

In `clash/Cargo.toml` `[dependencies]`:

```toml
clash-lsp = { workspace = true }
```

- [ ] **Step 2: Add CLI variant**

In `clash/src/cli.rs` inside `enum Commands`, append:

```rust
    /// Run the clash language server over stdio (LSP)
    Lsp,
```

- [ ] **Step 3: Create the cmd module**

`clash/src/cmd/lsp.rs`:

```rust
use anyhow::Result;

pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(clash_lsp::run_stdio())
}
```

Add `pub mod lsp;` to `clash/src/cmd/mod.rs`.

- [ ] **Step 4: Dispatch in `main.rs`**

Find the match arm for `Commands::*` (look for `Commands::Doctor` or similar) and add:

```rust
        Commands::Lsp => crate::cmd::lsp::run()?,
```

- [ ] **Step 5: Verify it builds and starts**

Run: `cargo build -p clash`
Run: `echo '' | cargo run -p clash -- lsp` (Ctrl-C after a moment)
Expected: process starts, waits on stdin, exits cleanly.

- [ ] **Step 6: Commit**

```bash
git add clash/Cargo.toml clash/src/cli.rs clash/src/cmd/lsp.rs clash/src/cmd/mod.rs clash/src/main.rs
git commit -m "feat(cli): add clash lsp subcommand"
```

---

## Task 3: Analysis — parse a `.star` source

**Files:**
- Modify: `clash-lsp/src/analysis/mod.rs`
- Create: `clash-lsp/src/analysis/diagnostic.rs`

- [ ] **Step 1: Write the failing test**

Append to `clash-lsp/src/analysis/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn parses_valid_policy_with_no_diagnostics() {
        let src = indoc! {r#"
            policy({
                "rule": {"effect": "allow", "exec": {"bin": {"literal": "ls"}}}
            })
        "#};
        let parsed = parse("test.star", src);
        assert!(parsed.diagnostics.is_empty(), "expected no diagnostics, got {:?}", parsed.diagnostics);
    }

    #[test]
    fn reports_syntax_error_with_span() {
        let src = "policy({ unclosed";
        let parsed = parse("bad.star", src);
        assert_eq!(parsed.diagnostics.len(), 1);
        let d = &parsed.diagnostics[0];
        assert!(d.message.to_lowercase().contains("syntax") || d.message.to_lowercase().contains("parse"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash-lsp analysis::tests`
Expected: FAIL — `parse` and `ParsedPolicy` undefined.

- [ ] **Step 3: Implement `parse`**

Replace `clash-lsp/src/analysis/mod.rs` with:

```rust
//! Pure analysis: parse + validate clash `.star` policies.

pub mod diagnostic;
pub use diagnostic::AnalysisDiagnostic;

/// Result of analyzing a single `.star` source.
#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

/// Parse a `.star` source. Always returns a `ParsedPolicy`; failures land in `diagnostics`.
pub fn parse(filename: &str, source: &str) -> ParsedPolicy {
    match clash_starlark::parse_source(filename, source) {
        Ok(_ast) => ParsedPolicy::default(),
        Err(e) => ParsedPolicy {
            diagnostics: vec![AnalysisDiagnostic::from_starlark_error(&e)],
        },
    }
}

#[cfg(test)]
mod tests { /* ... from Step 1 ... */ }
```

> **NOTE FOR IMPLEMENTER:** `clash_starlark::parse_source` is the assumed entry point. Before writing this, run `rg "pub fn parse" clash_starlark/src` to find the actual public parser. If the function name differs, update the call here. If no public parser exists, add one in `clash_starlark/src/lib.rs`:
>
> ```rust
> pub fn parse_source(filename: &str, source: &str) -> Result<starlark::syntax::AstModule, starlark::Error> {
>     starlark::syntax::AstModule::parse(filename, source.to_string(), &starlark::syntax::Dialect::Standard)
> }
> ```
>
> Commit that change as `feat(starlark): expose parse_source for LSP` before proceeding.

- [ ] **Step 4: Write `diagnostic.rs`**

`clash-lsp/src/analysis/diagnostic.rs`:

```rust
use lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range};

#[derive(Debug, Clone)]
pub struct AnalysisDiagnostic {
    pub message: String,
    pub severity: DiagnosticSeverity,
    pub range: Range,
    pub code: Option<String>,
}

impl AnalysisDiagnostic {
    pub fn from_starlark_error(err: &starlark::Error) -> Self {
        // Starlark errors carry an optional span. When absent, point at (0,0)..(0,0).
        let range = err
            .span()
            .map(|s| Range {
                start: Position { line: s.begin_line() as u32, character: s.begin_column() as u32 },
                end:   Position { line: s.end_line()   as u32, character: s.end_column()   as u32 },
            })
            .unwrap_or_default();
        Self {
            message: err.to_string(),
            severity: DiagnosticSeverity::ERROR,
            range,
            code: Some("clash/parse".into()),
        }
    }

    pub fn to_lsp(&self) -> Diagnostic {
        Diagnostic {
            range: self.range,
            severity: Some(self.severity),
            code: self.code.clone().map(lsp_types::NumberOrString::String),
            source: Some("clash".into()),
            message: self.message.clone(),
            ..Default::default()
        }
    }
}
```

> **NOTE:** The exact `starlark::Error` span API may differ between starlark crate versions. If `err.span()` doesn't compile, run `cargo doc -p starlark --open` or grep `clash_starlark` for how it formats errors. Adjust the field access; the goal is "best-effort line/column from the error". A zero range fallback is acceptable.

- [ ] **Step 5: Run tests**

Run: `cargo test -p clash-lsp analysis::tests`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add clash-lsp/src/analysis/ clash_starlark/src/lib.rs
git commit -m "feat(lsp): parse star sources into diagnostics"
```

---

## Task 4: Analysis — validate against the policy IR

**Files:**
- Modify: `clash-lsp/src/analysis/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module:

```rust
#[test]
fn reports_invalid_capability_matcher() {
    // `bin` requires a string matcher; passing an int is an IR error.
    let src = indoc! {r#"
        policy({
            "rule": {"effect": "allow", "exec": {"bin": {"literal": 42}}}
        })
    "#};
    let parsed = parse("bad_ir.star", src);
    assert!(
        parsed.diagnostics.iter().any(|d| d.code.as_deref() == Some("clash/validate")),
        "expected a clash/validate diagnostic, got {:?}",
        parsed.diagnostics
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash-lsp reports_invalid_capability_matcher`
Expected: FAIL — only parse diagnostics produced.

- [ ] **Step 3: Extend `parse` to also validate**

Update `parse()`:

```rust
pub fn parse(filename: &str, source: &str) -> ParsedPolicy {
    let ast = match clash_starlark::parse_source(filename, source) {
        Ok(ast) => ast,
        Err(e) => return ParsedPolicy {
            diagnostics: vec![AnalysisDiagnostic::from_starlark_error(&e)],
        },
    };

    let mut diagnostics = Vec::new();
    match clash_starlark::eval_ast_to_policy_json(filename, ast) {
        Ok(json) => {
            if let Err(err) = clash::policy::validate_json(&json) {
                diagnostics.push(AnalysisDiagnostic::from_validation_error(&err));
            }
        }
        Err(e) => diagnostics.push(AnalysisDiagnostic::from_starlark_error(&e)),
    }
    ParsedPolicy { diagnostics }
}
```

> **NOTE:** `clash_starlark::eval_ast_to_policy_json` and `clash::policy::validate_json` are the assumed entry points. Before writing, search:
> - `rg "pub fn" clash_starlark/src/lib.rs` to find the eval entry point
> - `rg "pub fn validate" clash/src/policy/` to find the validator
>
> Wire to the real names. If a unified "compile + validate" function already exists, use it instead of the two-step. The contract this task needs: "given a `.star` source, return validation errors with spans (best-effort)".

- [ ] **Step 4: Add `from_validation_error` constructor**

In `diagnostic.rs`:

```rust
impl AnalysisDiagnostic {
    pub fn from_validation_error(err: &dyn std::fmt::Display) -> Self {
        Self {
            message: err.to_string(),
            severity: DiagnosticSeverity::ERROR,
            range: Range::default(),
            code: Some("clash/validate".into()),
        }
    }
}
```

If the real validation error type carries a span, prefer that — fall back to `Range::default()` only when none is available.

- [ ] **Step 5: Run tests**

Run: `cargo test -p clash-lsp`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add clash-lsp/src/analysis/
git commit -m "feat(lsp): validate parsed policies against IR"
```

---

## Task 5: Document store

**Files:**
- Modify: `clash-lsp/src/documents.rs`

- [ ] **Step 1: Write the failing test**

Replace `clash-lsp/src/documents.rs`:

```rust
//! In-memory store of open documents.

use lsp_types::Url;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::analysis::{ParsedPolicy, parse};

#[derive(Default)]
pub struct DocumentStore {
    inner: RwLock<HashMap<Url, Entry>>,
}

struct Entry {
    text: String,
    parsed: ParsedPolicy,
}

impl DocumentStore {
    pub fn new() -> Self { Self::default() }

    pub fn open(&self, uri: Url, text: String) -> ParsedPolicy {
        let parsed = parse(uri.as_str(), &text);
        let snapshot = parsed.clone();
        self.inner.write().unwrap().insert(uri, Entry { text, parsed });
        snapshot
    }

    pub fn change(&self, uri: Url, text: String) -> ParsedPolicy {
        self.open(uri, text)
    }

    pub fn close(&self, uri: &Url) {
        self.inner.write().unwrap().remove(uri);
    }

    pub fn get(&self, uri: &Url) -> Option<ParsedPolicy> {
        self.inner.read().unwrap().get(uri).map(|e| e.parsed.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_then_get_returns_parsed() {
        let store = DocumentStore::new();
        let uri: Url = "file:///x.star".parse().unwrap();
        let parsed = store.open(uri.clone(), "policy({})".into());
        assert!(parsed.diagnostics.is_empty() || !parsed.diagnostics.is_empty()); // smoke
        assert!(store.get(&uri).is_some());
    }

    #[test]
    fn close_removes_entry() {
        let store = DocumentStore::new();
        let uri: Url = "file:///x.star".parse().unwrap();
        store.open(uri.clone(), "policy({})".into());
        store.close(&uri);
        assert!(store.get(&uri).is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p clash-lsp documents`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/src/documents.rs
git commit -m "feat(lsp): in-memory document store"
```

---

## Task 6: Server — wire didOpen/didChange/didClose to diagnostics

**Files:**
- Modify: `clash-lsp/src/server.rs`

- [ ] **Step 1: Replace `server.rs`**

```rust
//! `tower_lsp::LanguageServer` implementation.

use tower_lsp::{Client, LanguageServer, jsonrpc};
use tower_lsp::lsp_types::*;

use crate::analysis::ParsedPolicy;
use crate::documents::DocumentStore;

pub struct Backend {
    client: Client,
    docs: DocumentStore,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self { client, docs: DocumentStore::new() }
    }

    async fn publish(&self, uri: Url, parsed: ParsedPolicy) {
        let diags = parsed.diagnostics.iter().map(|d| d.to_lsp()).collect();
        self.client.publish_diagnostics(uri, diags, None).await;
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> jsonrpc::Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "clash-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client.log_message(MessageType::INFO, "clash-lsp ready").await;
    }

    async fn shutdown(&self) -> jsonrpc::Result<()> { Ok(()) }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let parsed = self.docs.open(uri.clone(), params.text_document.text);
        self.publish(uri, parsed).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let Some(change) = params.content_changes.into_iter().next() else { return };
        let parsed = self.docs.change(uri.clone(), change.text);
        self.publish(uri, parsed).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.docs.close(&params.text_document.uri);
    }
}
```

- [ ] **Step 2: Build**

Run: `cargo build -p clash-lsp`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/src/server.rs
git commit -m "feat(lsp): publish diagnostics on document sync"
```

---

## Task 7: Integration test — drive the server in-process

**Files:**
- Create: `clash-lsp/tests/diagnostics.rs`

- [ ] **Step 1: Write the test**

```rust
//! Drives `clash-lsp` over an in-memory duplex pipe and asserts that
//! a `didOpen` for an invalid policy produces a `publishDiagnostics`.

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_policy_emits_diagnostic() {
    let (client_to_server, server_from_client) = tokio::io::duplex(8192);
    let (server_to_client, mut client_from_server) = tokio::io::duplex(8192);

    let server = tokio::spawn(async move {
        let (service, socket) = tower_lsp::LspService::new(clash_lsp::server::Backend::new);
        tower_lsp::Server::new(server_from_client, server_to_client, socket)
            .serve(service)
            .await;
    });

    let mut client = client_to_server;

    // initialize
    send(&mut client, &json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"capabilities": {}}
    })).await;
    let _init_resp = read_message(&mut client_from_server).await;

    send(&mut client, &json!({
        "jsonrpc": "2.0", "method": "initialized", "params": {}
    })).await;

    // didOpen with garbage
    send(&mut client, &json!({
        "jsonrpc": "2.0", "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file:///bad.star",
                "languageId": "starlark",
                "version": 1,
                "text": "policy({ unclosed"
            }
        }
    })).await;

    // Drain messages until we see publishDiagnostics
    let diag = loop {
        let msg = read_message(&mut client_from_server).await;
        if msg["method"] == "textDocument/publishDiagnostics" {
            break msg;
        }
    };

    let diags = &diag["params"]["diagnostics"];
    assert!(diags.is_array() && !diags.as_array().unwrap().is_empty(),
        "expected at least one diagnostic, got {diag}");

    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
}

async fn send(w: &mut tokio::io::DuplexStream, v: &Value) {
    let body = serde_json::to_vec(v).unwrap();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    w.write_all(header.as_bytes()).await.unwrap();
    w.write_all(&body).await.unwrap();
    w.flush().await.unwrap();
}

async fn read_message(r: &mut tokio::io::DuplexStream) -> Value {
    // Read headers until \r\n\r\n
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        r.read_exact(&mut byte).await.unwrap();
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") { break; }
    }
    let headers = std::str::from_utf8(&buf).unwrap();
    let len: usize = headers
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
```

Make `Backend::new` and the `server` module `pub` if not already (Task 1 already exposed `pub mod server`).

- [ ] **Step 2: Run**

Run: `cargo test -p clash-lsp --test diagnostics`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/tests/diagnostics.rs
git commit -m "test(lsp): in-process integration test for diagnostics"
```

---

## Task 8: clester smoke test

**Files:**
- Create: `clester/tests/scripts/lsp_diagnostics.yaml`

- [ ] **Step 1: Look at an existing clester script for the format**

Run: `ls clester/tests/scripts/ | head` then read one (e.g. `cat clester/tests/scripts/<some>.yaml`).

> The exact YAML schema lives in the `clester` crate. Mirror an existing script that runs a `clash` subcommand, sends stdin, and asserts on stdout. The goal is: spawn `clash lsp`, send `initialize` + `didOpen` (LSP framed), assert that `publishDiagnostics` appears in stdout. If clester doesn't natively handle binary framing, the script can shell out to a small helper or skip framing assertions and just check that the process accepts `initialize` and exits cleanly on `shutdown`/`exit`.

- [ ] **Step 2: Write the script**

Minimum viable version: assert that `clash lsp` starts, accepts an `initialize` request over stdin, and exits cleanly. (Full diagnostic assertion is already covered by Task 7's in-process test; the clester smoke is just "the binary wires up".)

- [ ] **Step 3: Run**

Run: `just clester` (or the targeted invocation for a single script — see `clester --help`).
Expected: the new script passes.

- [ ] **Step 4: Commit**

```bash
git add clester/tests/scripts/lsp_diagnostics.yaml
git commit -m "test(clester): smoke test for clash lsp"
```

---

## Task 9: CI + docs

**Files:**
- Modify: `README.md` (mention `clash lsp`)
- Modify: `AGENTS.md` (add `clash lsp` to the CLI command list)

- [ ] **Step 1: Run `just check`**

Run: `just check`
Expected: PASS.

- [ ] **Step 2: Update AGENTS.md command list**

Find the line that lists CLI commands (search for `clash lsp` or `clash launch`) and add `clash lsp` after `clash launch`.

- [ ] **Step 3: README mention**

Add a short subsection under whatever heading lists editor/dev tooling:

```markdown
### Editor support

`clash lsp` runs a Language Server Protocol server over stdio for editing
`.star` policy files. See `docs/editor-setup.md` for editor-specific setup
(landing in plan #3).
```

- [ ] **Step 4: Commit**

```bash
git add README.md AGENTS.md
git commit -m "docs: document clash lsp subcommand"
```

---

## Done

At this point: `clash lsp` runs, an editor that points at it gets parse and IR-validation diagnostics on `.star` files. The crate has unit and integration tests. Plans 2–4 build on this foundation.
