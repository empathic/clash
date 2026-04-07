# Clash LSP — Plan 2: Completion, Hover, Go-to-Definition

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans.

**Goal:** Add the three remaining v1 features to `clash-lsp`: completion for builtins/capability fields/matchers, hover with docstrings, and intra-file go-to-definition.

**Architecture:** Introduce a `schema` module — the single source of truth for clash's policy DSL surface — and a `features/` directory with one file per LSP feature. Each feature consumes the cached `analysis` output and the schema, produces an LSP response, and is unit-tested in isolation.

**Tech Stack:** Same as plan 1.

**Spec:** `docs/superpowers/specs/2026-04-06-clash-lsp-design.md`

**Prerequisite:** Plan 1 merged.

---

## File Structure (additions)

```
clash-lsp/src/
  schema/
    mod.rs              # Schema struct + load_builtin() returning the canonical clash schema
    types.rs            # Builtin, Field, MatcherKind, Signature, Doc
  features/
    mod.rs
    completion.rs
    hover.rs
    goto_definition.rs
  analysis/
    symbols.rs          # SymbolIndex: name -> definition span
```

---

## Task 1: Schema module

**Files:**
- Create: `clash-lsp/src/schema/mod.rs`
- Create: `clash-lsp/src/schema/types.rs`

- [ ] **Step 1: Define the types**

`clash-lsp/src/schema/types.rs`:

```rust
#[derive(Debug, Clone)]
pub struct Schema {
    pub builtins: Vec<Builtin>,
}

#[derive(Debug, Clone)]
pub struct Builtin {
    pub name: &'static str,
    pub signature: &'static str,
    pub doc: &'static str,
}

impl Schema {
    pub fn lookup(&self, name: &str) -> Option<&Builtin> {
        self.builtins.iter().find(|b| b.name == name)
    }
}
```

- [ ] **Step 2: Define the canonical schema**

`clash-lsp/src/schema/mod.rs`:

```rust
pub mod types;
pub use types::{Builtin, Schema};

pub fn load_builtin() -> Schema {
    Schema {
        builtins: vec![
            Builtin {
                name: "policy",
                signature: "policy(rules: dict | list)",
                doc: "Register a clash policy. Accepts a dict with a `rule` key or a list of rules.",
            },
            Builtin {
                name: "sandbox",
                signature: "sandbox(name: str, rules: list)",
                doc: "Register a named sandbox with the given rules.",
            },
            Builtin {
                name: "settings",
                signature: "settings(claude: dict | None)",
                doc: "Register settings to merge into the agent configuration.",
            },
        ],
    }
}
```

> **NOTE:** This is a starter list. The real source of truth lives in `clash/src/policy_gen/`. Before merging plan 2, open `clash/src/policy_gen/` and either (a) re-export its definitions into `clash-lsp/src/schema/` so the LSP and the policy compiler can never drift, or (b) wrap them in a thin adapter that yields `Builtin`s. Pick whichever introduces fewer cyclic deps. Add a TODO above `load_builtin()` linking to the policy_gen module so the next reader knows where the canonical list lives.

- [ ] **Step 3: Test**

Append to `clash-lsp/src/schema/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_includes_core_builtins() {
        let s = load_builtin();
        assert!(s.lookup("policy").is_some());
        assert!(s.lookup("sandbox").is_some());
        assert!(s.lookup("settings").is_some());
    }
}
```

Run: `cargo test -p clash-lsp schema`
Expected: PASS.

- [ ] **Step 4: Wire into `lib.rs`**

Add `pub mod schema;` to `clash-lsp/src/lib.rs`.

- [ ] **Step 5: Commit**

```bash
git add clash-lsp/src/schema/ clash-lsp/src/lib.rs
git commit -m "feat(lsp): add clash policy schema module"
```

---

## Task 2: Completion feature

**Files:**
- Create: `clash-lsp/src/features/mod.rs`
- Create: `clash-lsp/src/features/completion.rs`

- [ ] **Step 1: Add module**

`clash-lsp/src/features/mod.rs`:

```rust
pub mod completion;
pub mod hover;
pub mod goto_definition;
```

Add `pub mod features;` to `lib.rs`.

- [ ] **Step 2: Write the failing test**

`clash-lsp/src/features/completion.rs`:

```rust
use lsp_types::{CompletionItem, CompletionItemKind, Position};

use crate::schema::Schema;

/// Produce completion items for a position in the source.
/// v1: returns every top-level builtin from the schema, ignoring position.
pub fn complete(schema: &Schema, _source: &str, _pos: Position) -> Vec<CompletionItem> {
    schema
        .builtins
        .iter()
        .map(|b| CompletionItem {
            label: b.name.to_string(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some(b.signature.to_string()),
            documentation: Some(lsp_types::Documentation::String(b.doc.to_string())),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::load_builtin;

    #[test]
    fn completes_builtins() {
        let items = complete(&load_builtin(), "", Position::default());
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"policy"));
        assert!(labels.contains(&"sandbox"));
        assert!(labels.contains(&"settings"));
    }
}
```

> **NOTE:** v1 is intentionally position-unaware — it always returns the full builtin list. Smarter completion (capability fields when inside an `exec` dict, matcher constructors when inside a `bin` value, etc.) is a follow-up. Don't add it speculatively. The seam (`_source`, `_pos` parameters) is reserved for that future work.

- [ ] **Step 3: Run**

Run: `cargo test -p clash-lsp features::completion`
Expected: PASS.

- [ ] **Step 4: Wire into the server**

In `clash-lsp/src/server.rs`, add to the `Backend` struct:

```rust
schema: crate::schema::Schema,
```

Initialize in `Backend::new`:

```rust
schema: crate::schema::load_builtin(),
```

Advertise the capability in `initialize`:

```rust
completion_provider: Some(CompletionOptions::default()),
```

Implement the handler:

```rust
async fn completion(
    &self,
    params: CompletionParams,
) -> jsonrpc::Result<Option<CompletionResponse>> {
    let uri = &params.text_document_position.text_document.uri;
    let _ = self.docs.get(uri); // reserved for position-aware completion
    let items = crate::features::completion::complete(
        &self.schema,
        "", // v1: source not needed
        params.text_document_position.position,
    );
    Ok(Some(CompletionResponse::Array(items)))
}
```

- [ ] **Step 5: Build**

Run: `cargo build -p clash-lsp && cargo test -p clash-lsp`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add clash-lsp/src/features/ clash-lsp/src/server.rs clash-lsp/src/lib.rs
git commit -m "feat(lsp): completion for clash builtins"
```

---

## Task 3: Hover feature

**Files:**
- Create: `clash-lsp/src/features/hover.rs`

- [ ] **Step 1: Write the function and test**

```rust
use lsp_types::{Hover, HoverContents, MarkupContent, MarkupKind, Position};

use crate::schema::Schema;

/// Look up the identifier at `pos` in `source` and return its hover doc.
pub fn hover(schema: &Schema, source: &str, pos: Position) -> Option<Hover> {
    let word = word_at(source, pos)?;
    let builtin = schema.lookup(&word)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: format!("```\n{}\n```\n\n{}", builtin.signature, builtin.doc),
        }),
        range: None,
    })
}

fn word_at(source: &str, pos: Position) -> Option<String> {
    let line = source.lines().nth(pos.line as usize)?;
    let col = pos.character as usize;
    if col > line.len() { return None; }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let start = line[..col].rfind(|c: char| !is_word(c)).map(|i| i + 1).unwrap_or(0);
    let end = line[col..].find(|c: char| !is_word(c)).map(|i| col + i).unwrap_or(line.len());
    if start == end { None } else { Some(line[start..end].to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::load_builtin;

    #[test]
    fn hovers_on_policy_builtin() {
        let src = "policy({})\n";
        let h = hover(&load_builtin(), src, Position { line: 0, character: 2 }).unwrap();
        if let HoverContents::Markup(m) = h.contents {
            assert!(m.value.contains("policy"));
        } else { panic!("expected markup"); }
    }

    #[test]
    fn no_hover_on_unknown_word() {
        let src = "frobnicate()\n";
        assert!(hover(&load_builtin(), src, Position { line: 0, character: 2 }).is_none());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p clash-lsp features::hover`
Expected: PASS.

- [ ] **Step 3: Wire into the server**

Add capability:

```rust
hover_provider: Some(HoverProviderCapability::Simple(true)),
```

Handler — this one needs the source text, so extend `DocumentStore` with a `get_text` method first:

In `documents.rs`:

```rust
pub fn get_text(&self, uri: &Url) -> Option<String> {
    self.inner.read().unwrap().get(uri).map(|e| e.text.clone())
}
```

In `server.rs`:

```rust
async fn hover(&self, params: HoverParams) -> jsonrpc::Result<Option<Hover>> {
    let uri = &params.text_document_position_params.text_document.uri;
    let Some(source) = self.docs.get_text(uri) else { return Ok(None) };
    Ok(crate::features::hover::hover(
        &self.schema,
        &source,
        params.text_document_position_params.position,
    ))
}
```

- [ ] **Step 4: Build & test**

Run: `cargo test -p clash-lsp && cargo build -p clash-lsp`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clash-lsp/src/features/hover.rs clash-lsp/src/documents.rs clash-lsp/src/server.rs
git commit -m "feat(lsp): hover for clash builtins"
```

---

## Task 4: Symbol index for go-to-definition

**Files:**
- Create: `clash-lsp/src/analysis/symbols.rs`
- Modify: `clash-lsp/src/analysis/mod.rs`

- [ ] **Step 1: Define `SymbolIndex`**

`clash-lsp/src/analysis/symbols.rs`:

```rust
use lsp_types::Range;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    defs: HashMap<String, Range>,
}

impl SymbolIndex {
    pub fn insert(&mut self, name: impl Into<String>, range: Range) {
        self.defs.insert(name.into(), range);
    }
    pub fn get(&self, name: &str) -> Option<Range> {
        self.defs.get(name).copied()
    }
}
```

- [ ] **Step 2: Build the index from the AST**

Extend `ParsedPolicy`:

```rust
#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    pub diagnostics: Vec<AnalysisDiagnostic>,
    pub symbols: SymbolIndex,
}
```

In `parse()`, walk the AST after a successful parse and record top-level `def`/`load`/assignment names with their spans. The starlark crate exposes an AST walker via `AstModule::statements()` (or similar — verify against the version in use).

> **NOTE:** Implementation depends on the exact starlark AST API. Pseudocode:
> ```rust
> for stmt in ast.top_level_statements() {
>     if let Some((name, span)) = stmt.as_assign_target() {
>         symbols.insert(name, span_to_range(span));
>     }
> }
> ```
> If this turns out to require substantial AST plumbing, scope v1 down to "no symbols, goto returns None" and file a follow-up. Don't burn the task on AST yak-shaving.

- [ ] **Step 3: Test**

```rust
#[test]
fn parses_top_level_assignment_into_symbols() {
    let src = "my_rule = {}\npolicy(my_rule)\n";
    let parsed = parse("x.star", src);
    assert!(parsed.symbols.get("my_rule").is_some());
}
```

Run: `cargo test -p clash-lsp parses_top_level_assignment_into_symbols`
Expected: PASS (or skipped via the scope-down note above).

- [ ] **Step 4: Commit**

```bash
git add clash-lsp/src/analysis/
git commit -m "feat(lsp): symbol index for top-level definitions"
```

---

## Task 5: Go-to-definition feature

**Files:**
- Create: `clash-lsp/src/features/goto_definition.rs`

- [ ] **Step 1: Implement**

```rust
use lsp_types::{GotoDefinitionResponse, Location, Position, Url};

use crate::analysis::ParsedPolicy;
use crate::features::hover::word_at_pub as word_at;

pub fn goto(
    parsed: &ParsedPolicy,
    source: &str,
    uri: &Url,
    pos: Position,
) -> Option<GotoDefinitionResponse> {
    let word = word_at(source, pos)?;
    let range = parsed.symbols.get(&word)?;
    Some(GotoDefinitionResponse::Scalar(Location { uri: uri.clone(), range }))
}
```

(Promote `word_at` from `hover.rs` to a sibling helper. Add `pub fn word_at_pub(...)` re-export, or move it into a small `features/util.rs`.)

- [ ] **Step 2: Test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parse;

    #[test]
    fn goto_finds_local_definition() {
        let src = "my_rule = {}\npolicy(my_rule)\n";
        let parsed = parse("x.star", src);
        let uri: Url = "file:///x.star".parse().unwrap();
        // position over `my_rule` in line 1
        let resp = goto(&parsed, src, &uri, Position { line: 1, character: 9 });
        assert!(resp.is_some());
    }
}
```

Run: `cargo test -p clash-lsp features::goto_definition`
Expected: PASS.

- [ ] **Step 3: Wire into server**

Capability:

```rust
definition_provider: Some(OneOf::Left(true)),
```

Handler:

```rust
async fn goto_definition(
    &self,
    params: GotoDefinitionParams,
) -> jsonrpc::Result<Option<GotoDefinitionResponse>> {
    let uri = params.text_document_position_params.text_document.uri.clone();
    let Some(source) = self.docs.get_text(&uri) else { return Ok(None) };
    let Some(parsed) = self.docs.get(&uri) else { return Ok(None) };
    Ok(crate::features::goto_definition::goto(
        &parsed,
        &source,
        &uri,
        params.text_document_position_params.position,
    ))
}
```

- [ ] **Step 4: Build & test**

Run: `just check`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clash-lsp/src/features/ clash-lsp/src/server.rs
git commit -m "feat(lsp): go-to-definition for top-level symbols"
```

---

## Task 6: Integration test for completion + hover

**Files:**
- Modify: `clash-lsp/tests/diagnostics.rs` → rename to `clash-lsp/tests/integration.rs`, or add a sibling test file.

- [ ] **Step 1: Add a test that opens a doc, requests completion, asserts builtins appear**

Use the same scaffold as plan 1 task 7. After the `initialized` notification, send:

```json
{"jsonrpc":"2.0","id":2,"method":"textDocument/completion",
 "params":{"textDocument":{"uri":"file:///x.star"},"position":{"line":0,"character":0}}}
```

Read responses until `id == 2`, assert `result.items` (or `result` as array) contains `policy`, `sandbox`, `settings`.

- [ ] **Step 2: Run**

Run: `cargo test -p clash-lsp --test integration`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash-lsp/tests/
git commit -m "test(lsp): integration test for completion handler"
```

---

## Done

`clash lsp` now provides diagnostics, completion, hover, and intra-file go-to-definition. Plans 3 and 4 add editor integration.
