# Sandbox CLI Starlark Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix `clash sandbox create/delete/list/add-rule/remove-rule` to work with Starlark policy files.

**Architecture:** Each sandbox CLI handler checks the policy file extension. `.star` files route through `StarDocument` + `mutate.rs` API. `.json` files error with a conversion hint. Missing files error with "run `clash init`".

**Tech Stack:** Rust, `clash_starlark::codegen::{document::StarDocument, mutate}`, `clash_starlark::codegen::ast::{Expr, DictEntry, Stmt}`

**Spec:** `docs/superpowers/specs/2026-04-02-sandbox-cli-starlark-design.md`

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `clash_starlark/src/codegen/mutate.rs` | Modify | Add `add_sandbox_rule()`, `remove_sandbox_rule()`, `find_sandbox_fs_mut()` |
| `clash/src/sandbox_cmd.rs` | Modify | Reroute CRUD handlers for `.star` files |
| `clester/tests/scripts/sandbox_cli.yaml` | Modify | Use Starlark policy format |

---

### Task 1: Add `find_sandbox_fs_mut` helper to mutate.rs

**Files:**
- Modify: `clash_starlark/src/codegen/mutate.rs:44-75`

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `clash_starlark/src/codegen/mutate.rs`:

```rust
#[test]
fn add_sandbox_rule_inserts() {
    let mut stmts = parse(
        r#"
sandbox(name = "dev", default = deny(), fs = {glob("$PWD/**"): allow("rwc")})

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
    )
    .unwrap();
    add_sandbox_rule(&mut stmts, "dev", "$HOME/.cache/**", "read").unwrap();
    let src = serialize(&stmts);
    assert!(
        src.contains(".cache") && src.contains("allow(\"read\")"),
        "got:\n{src}"
    );
}

#[test]
fn add_sandbox_rule_missing_sandbox_errors() {
    let mut stmts = policy_stmts();
    let err = add_sandbox_rule(&mut stmts, "nope", "$HOME/.cache/**", "read").unwrap_err();
    assert!(err.contains("not found"), "got: {err}");
}

#[test]
fn add_sandbox_rule_creates_fs_if_missing() {
    let mut stmts = parse(
        r#"
sandbox(name = "net", default = deny(), net = allow())

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
    )
    .unwrap();
    add_sandbox_rule(&mut stmts, "net", "$HOME/.cache/**", "read + write").unwrap();
    let src = serialize(&stmts);
    assert!(src.contains("fs ="), "should have added fs kwarg, got:\n{src}");
    assert!(src.contains(".cache"), "got:\n{src}");
}

#[test]
fn remove_sandbox_rule_removes() {
    let mut stmts = parse(
        r#"
sandbox(name = "dev", default = deny(), fs = {
    glob("$PWD/**"): allow("rwc"),
    glob("$HOME/.cache/**"): allow("read"),
})

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
    )
    .unwrap();
    let removed = remove_sandbox_rule(&mut stmts, "dev", "$HOME/.cache/**").unwrap();
    assert!(removed);
    let src = serialize(&stmts);
    assert!(!src.contains(".cache"), "got:\n{src}");
    assert!(src.contains("$PWD"), "should keep other rules, got:\n{src}");
}

#[test]
fn remove_sandbox_rule_returns_false_when_no_match() {
    let mut stmts = parse(
        r#"
sandbox(name = "dev", default = deny(), fs = {glob("$PWD/**"): allow("rwc")})

settings(default = deny())

policy("test", default = deny(), rules = [])
"#,
    )
    .unwrap();
    let removed = remove_sandbox_rule(&mut stmts, "dev", "$HOME/nope/**").unwrap();
    assert!(!removed);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash_starlark --lib codegen::mutate::tests::add_sandbox_rule 2>&1 | tail -5`
Expected: FAIL — functions not defined

- [ ] **Step 3: Add `find_sandbox_fs_mut` helper**

Add to `clash_starlark/src/codegen/mutate.rs` after `find_sandboxes` (after line 75):

```rust
/// Find the `fs = {...}` kwarg dict in a sandbox() call by name.
/// Returns a mutable reference to the dict entries, or None if not found.
fn find_sandbox_fs_mut(stmts: &mut [Stmt], name: &str) -> Option<&mut Vec<DictEntry>> {
    let sandboxes = find_sandboxes(stmts);
    let (idx, _) = sandboxes.iter().find(|(_, n)| n == name)?;
    let idx = *idx;

    let call = match &mut stmts[idx] {
        Stmt::Expr(expr) => expr,
        Stmt::Assign { value, .. } => value,
        _ => return None,
    };

    if let Expr::Call { kwargs, .. } = call {
        for (key, value) in kwargs.iter_mut() {
            if key == "fs" {
                if let Expr::Dict(entries) = value {
                    return Some(entries);
                }
            }
        }
    }
    None
}

/// Get a mutable reference to the kwargs of a sandbox() call by name.
fn find_sandbox_kwargs_mut(stmts: &mut [Stmt], name: &str) -> Option<&mut Vec<(String, Expr)>> {
    let sandboxes = find_sandboxes(stmts);
    let (idx, _) = sandboxes.iter().find(|(_, n)| n == name)?;
    let idx = *idx;

    let call = match &mut stmts[idx] {
        Stmt::Expr(expr) => expr,
        Stmt::Assign { value, .. } => value,
        _ => return None,
    };

    if let Expr::Call { kwargs, .. } = call {
        Some(kwargs)
    } else {
        None
    }
}
```

- [ ] **Step 4: Implement `add_sandbox_rule`**

Add to `clash_starlark/src/codegen/mutate.rs` after `remove_sandbox` (after line 274):

```rust
/// Add a filesystem rule to a sandbox's `fs = {...}` dict.
///
/// The path should be a glob pattern like `$HOME/.cache/**`.
/// Caps is a shorthand string like `"read"`, `"read + write"`, or `"rwc"`.
pub fn add_sandbox_rule(
    stmts: &mut Vec<Stmt>,
    sandbox_name: &str,
    path: &str,
    caps: &str,
) -> Result<(), String> {
    // Verify sandbox exists
    if !find_sandboxes(stmts).iter().any(|(_, n)| n == sandbox_name) {
        return Err(format!("sandbox '{sandbox_name}' not found"));
    }

    let key = Expr::call("glob", vec![Expr::string(path)]);
    let value = Expr::call("allow", vec![Expr::string(caps)]);
    let entry = DictEntry::new(key, value);

    // Try to add to existing fs dict
    if let Some(entries) = find_sandbox_fs_mut(stmts, sandbox_name) {
        entries.push(entry);
        return Ok(());
    }

    // No fs kwarg — create one
    let kwargs = find_sandbox_kwargs_mut(stmts, sandbox_name)
        .ok_or_else(|| format!("sandbox '{sandbox_name}' not found"))?;
    kwargs.push(("fs".to_string(), Expr::dict(vec![entry])));
    Ok(())
}

/// Remove a filesystem rule from a sandbox's `fs = {...}` dict by path.
///
/// Returns true if a rule was removed.
pub fn remove_sandbox_rule(
    stmts: &mut Vec<Stmt>,
    sandbox_name: &str,
    path: &str,
) -> Result<bool, String> {
    let entries = find_sandbox_fs_mut(stmts, sandbox_name)
        .ok_or_else(|| format!("sandbox '{sandbox_name}' not found or has no fs rules"))?;

    let before = entries.len();
    entries.retain(|e| {
        // Match glob("path") keys
        if let Expr::Call { func, args, .. } = &e.key {
            if let Expr::Ident(name) = func.as_ref() {
                if name == "glob" || name == "subpath" || name == "literal" {
                    if let Some(Expr::String(p)) = args.first() {
                        return p != path;
                    }
                }
            }
        }
        // Match bare string keys
        if let Expr::String(p) = &e.key {
            return p != path;
        }
        true // keep entries we can't parse
    });

    Ok(entries.len() < before)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clash_starlark --lib codegen::mutate::tests 2>&1 | tail -10`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add clash_starlark/src/codegen/mutate.rs
git commit -m "feat: add add_sandbox_rule and remove_sandbox_rule to Starlark mutate API"
```

---

### Task 2: Reroute sandbox CLI handlers for Starlark

**Files:**
- Modify: `clash/src/sandbox_cmd.rs:275-406`

- [ ] **Step 1: Add a file-type dispatch helper**

Add at the top of the sandbox CRUD handlers section (after line 273) in `clash/src/sandbox_cmd.rs`:

```rust
/// Check policy file type and return the path.
/// Errors if JSON (with conversion hint) or if no policy exists.
fn require_star_policy(scope: Option<String>) -> Result<std::path::PathBuf> {
    let path = crate::cmd::policy::resolve_manifest_path(scope)?;
    if path.extension().is_some_and(|e| e == "json") {
        anyhow::bail!(
            "sandbox commands require a .star policy file.\n\
             Convert your policy with: clash policy convert --file {} --replace",
            path.display()
        );
    }
    Ok(path)
}
```

- [ ] **Step 2: Rewrite `handle_create` for Starlark**

Replace the `handle_create` function (lines 275-291) with:

```rust
fn handle_create(
    name: &str,
    default: &str,
    network: &str,
    _doc: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let path = require_star_policy(scope)?;
    let mut doc = clash_starlark::codegen::StarDocument::open(&path)?;

    let default_effect = match default.trim().to_lowercase().as_str() {
        s if s.contains("deny") => clash_starlark::codegen::mutate::Effect::Deny,
        s if s.contains("allow") => clash_starlark::codegen::mutate::Effect::Allow,
        _ => clash_starlark::codegen::mutate::Effect::Ask,
    };
    let net_allow = network == "allow";

    clash_starlark::codegen::mutate::add_sandbox(&mut doc.stmts, name, default_effect, net_allow)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    doc.save()?;

    println!("{} Sandbox '{}' created", style::green_bold("✓"), name);
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}
```

- [ ] **Step 3: Rewrite `handle_delete` for Starlark**

Replace the `handle_delete` function (lines 293-301) with:

```rust
fn handle_delete(name: &str, scope: Option<String>) -> Result<()> {
    let path = require_star_policy(scope)?;
    let mut doc = clash_starlark::codegen::StarDocument::open(&path)?;

    clash_starlark::codegen::mutate::remove_sandbox(&mut doc.stmts, name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    doc.save()?;

    println!("{} Sandbox '{}' deleted", style::green_bold("✓"), name);
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}
```

- [ ] **Step 4: Rewrite `handle_add_rule` for Starlark**

Replace the `handle_add_rule` function (lines 351-389) with:

```rust
fn handle_add_rule(
    name: &str,
    allow: Option<String>,
    deny: Option<String>,
    path: &str,
    _path_match: &str,
    _doc: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let caps_str = match (allow, deny) {
        (Some(caps), None) => caps,
        (None, Some(_)) => {
            anyhow::bail!("deny rules in sandbox fs are not yet supported via CLI — use `clash policy edit`")
        }
        _ => anyhow::bail!("provide exactly one of --allow or --deny with capabilities"),
    };

    let policy_path = require_star_policy(scope)?;
    let mut doc = clash_starlark::codegen::StarDocument::open(&policy_path)?;

    clash_starlark::codegen::mutate::add_sandbox_rule(&mut doc.stmts, name, path, &caps_str)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    doc.save()?;

    println!(
        "{} Rule added to sandbox '{}'",
        style::green_bold("✓"),
        name
    );
    println!("  {}", style::dim(&policy_path.display().to_string()));
    Ok(())
}
```

- [ ] **Step 5: Rewrite `handle_remove_rule` for Starlark**

Replace the `handle_remove_rule` function (lines 391-406) with:

```rust
fn handle_remove_rule(name: &str, path: &str, scope: Option<String>) -> Result<()> {
    let policy_path = require_star_policy(scope)?;
    let mut doc = clash_starlark::codegen::StarDocument::open(&policy_path)?;

    let removed = clash_starlark::codegen::mutate::remove_sandbox_rule(&mut doc.stmts, name, path)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    if removed {
        doc.save()?;
        println!(
            "{} Rule removed from sandbox '{}'",
            style::green_bold("✓"),
            name
        );
        println!("  {}", style::dim(&policy_path.display().to_string()));
    } else {
        println!("No rule matching path '{}' in sandbox '{}'", path, name);
    }
    Ok(())
}
```

- [ ] **Step 6: Remove unused imports**

Remove any now-unused imports at the top of `sandbox_cmd.rs` that were only needed for the JSON manifest path (e.g., `sandbox_edit`, `RuleEffect`). Keep `Cap`, `PathMatch`, `NetworkPolicy` if still used by other functions.

Check with: `cargo check -p clash 2>&1 | grep "unused import"`

- [ ] **Step 7: Verify it compiles**

Run: `cargo check -p clash 2>&1 | tail -10`
Expected: Compiles with no errors

- [ ] **Step 8: Commit**

```bash
git add clash/src/sandbox_cmd.rs
git commit -m "feat: reroute sandbox CLI handlers to use StarDocument for .star policies"
```

---

### Task 3: Update clester test for sandbox CLI

**Files:**
- Modify: `clester/tests/scripts/sandbox_cli.yaml`

- [ ] **Step 1: Rewrite the test to use Starlark policy**

Replace the full content of `clester/tests/scripts/sandbox_cli.yaml`:

```yaml
meta:
  name: sandbox CLI — create, list, delete workflow
  description: Test sandbox create/list/delete commands via the clash CLI

clash:
  policy_star: |
    settings(default = deny())
    policy("test", default = deny(), rules = [])

steps:
  - name: create a sandbox named "ci"
    command: sandbox create ci --default "read + execute" --network deny --scope user
    expect:
      exit_code: 0
      stdout_contains: "ci"

  - name: sandbox list shows the new sandbox
    command: sandbox list
    expect:
      exit_code: 0
      stdout_contains: "ci"

  - name: add a filesystem rule to the ci sandbox
    command: sandbox add-rule ci --allow "read + write" --path "$HOME/.cache/**" --scope user
    expect:
      exit_code: 0
      stdout_contains: "Rule added"

  - name: remove the filesystem rule from ci sandbox
    command: sandbox remove-rule ci --path "$HOME/.cache/**" --scope user
    expect:
      exit_code: 0
      stdout_contains: "Rule removed"

  - name: delete the ci sandbox
    command: sandbox delete ci --scope user
    expect:
      exit_code: 0
      stdout_contains: "ci"
```

- [ ] **Step 2: Run clester**

Run: `just clester 2>&1 | grep -A2 "sandbox CLI"`
Expected: All steps PASS

- [ ] **Step 3: Commit**

```bash
git add clester/tests/scripts/sandbox_cli.yaml
git commit -m "test: update sandbox CLI clester test for Starlark policy format"
```

---

### Task 4: Run full CI and fix issues

**Files:**
- Any files that need fixing

- [ ] **Step 1: Run cargo check + test**

Run: `cargo check -p clash -p clash_starlark 2>&1 | tail -10`
Run: `cargo test -p clash_starlark --lib codegen::mutate 2>&1 | tail -10`
Run: `cargo test -p clash --lib sandbox_cmd 2>&1 | tail -10`
Expected: All pass

- [ ] **Step 2: Run clester**

Run: `just clester 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 3: Fix any failures and commit**

```bash
git add -A
git commit -m "fix: address CI issues from sandbox CLI starlark support"
```
