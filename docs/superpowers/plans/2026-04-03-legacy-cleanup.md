# Legacy Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove ~2,300 lines of dead, deprecated, and legacy code from clash and clash_starlark.

**Architecture:** Five independent removal tasks, each producing a clean commit. Tasks are ordered so that later tasks don't depend on earlier ones — each can be done in isolation, but the commit sequence reads as a coherent narrative.

**Tech Stack:** Rust (cargo), Starlark (.star files)

**Spec:** `docs/superpowers/specs/2026-04-03-legacy-cleanup-design.md`

---

### Task 1: Remove match_tree.star Legacy DSL Path

**Files:**
- Delete: `clash_starlark/stdlib/match_tree.star`
- Delete: `clash_starlark/src/builders/base.rs`
- Delete: `clash_starlark/src/compile.rs`
- Modify: `clash_starlark/src/builders/mod.rs` (remove `pub mod base;`)
- Modify: `clash_starlark/src/globals.rs` (remove `_mt_policy`, `_register_policy`, unused import)
- Modify: `clash_starlark/src/lib.rs` (remove 5 test_match_tree_* tests)

- [ ] **Step 1: Delete match_tree.star**

```bash
rm clash_starlark/stdlib/match_tree.star
```

- [ ] **Step 2: Delete builders/base.rs**

```bash
rm clash_starlark/src/builders/base.rs
```

- [ ] **Step 3: Delete compile.rs**

```bash
rm clash_starlark/src/compile.rs
```

- [ ] **Step 4: Remove `pub mod base;` from builders/mod.rs**

In `clash_starlark/src/builders/mod.rs`, remove the line:
```rust
pub mod base;
```

The file should only contain:
```rust
pub mod match_tree;
```

- [ ] **Step 5: Remove legacy functions and unused import from globals.rs**

In `clash_starlark/src/globals.rs`:

1. Remove the import on line 12:
```rust
use crate::builders::base::BasePolicyValue;
```

2. Remove the `_mt_policy()` function (lines 130-202), including the doc comment on line 130:
```rust
    /// Internal match tree policy constructor (legacy — used by match_tree.star).
    fn _mt_policy<'v>(
        ...
    }
```

3. Remove the `_register_policy()` function (lines 238-286), including the doc comment on line 238:
```rust
    /// Register a policy into the evaluation context (legacy — used by match_tree.star).
    fn _register_policy<'v>(
        ...
    }
```

- [ ] **Step 6: Remove match_tree tests from lib.rs**

In `clash_starlark/src/lib.rs`, remove lines 734-824 (the comment header and all 5 tests):
```rust
    // -----------------------------------------------------------------------
    // Match tree builder tests (using match_tree.star directly)
    // -----------------------------------------------------------------------

    #[test]
    fn test_match_tree_simple() { ... }

    #[test]
    fn test_match_tree_nested() { ... }

    #[test]
    fn test_match_tree_with_sandbox() { ... }

    #[test]
    fn test_match_tree_arg_and_named() { ... }

    #[test]
    fn test_match_tree_load_module() { ... }
```

- [ ] **Step 7: Build and test**

Run: `cargo build -p clash_starlark 2>&1`
Expected: compiles cleanly (no errors, no new warnings about unused imports)

Run: `cargo test -p clash_starlark 2>&1`
Expected: all remaining tests pass, test count is reduced by 5

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor(starlark): remove legacy match_tree.star DSL path

Remove the old match_tree.star Starlark DSL (exe/tool/has_arg/policy
wrappers), BasePolicyValue, the dead compile.rs module, and associated
globals (_mt_policy, _register_policy). No user ever wrote policies
using this path — the modern when()/policy() DSL in std.star is the
only supported interface.

The core MatchTreeNode type and _mt_* pattern builders remain as they
are shared infrastructure used by the modern when.rs path."
```

---

### Task 2: Remove Deprecated Playground REPL

**Files:**
- Delete: `clash/src/cmd/playground.rs`
- Modify: `clash/src/cmd/mod.rs` (remove `pub mod playground;`)
- Modify: `clash/src/main.rs` (remove `Commands::Playground` match arm)
- Modify: `clash/src/cli.rs` (remove `Playground` variant from `Commands` enum)

- [ ] **Step 1: Delete playground.rs**

```bash
rm clash/src/cmd/playground.rs
```

- [ ] **Step 2: Remove module declaration from cmd/mod.rs**

In `clash/src/cmd/mod.rs`, remove the line:
```rust
pub mod playground;
```

- [ ] **Step 3: Remove Playground variant from Commands enum in cli.rs**

In `clash/src/cli.rs`, remove lines 286-287:
```rust
    /// Interactive policy sandbox — write rules and test them against tool invocations
    Playground,
```

- [ ] **Step 4: Remove Playground match arm from main.rs**

In `clash/src/main.rs`, remove lines 53-57:
```rust
        Commands::Playground => {
            eprintln!("Note: `clash playground` is now `clash policy edit --test`");
            eprintln!("      The playground REPL has been unified into the policy editor.\n");
            cmd::playground::run()
        }
```

- [ ] **Step 5: Build and test**

Run: `cargo build -p clash 2>&1`
Expected: compiles cleanly

Run: `cargo test -p clash 2>&1`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(cli): remove deprecated playground REPL

The playground was deprecated in favor of 'clash policy edit --test'.
It already showed a deprecation notice on every invocation. The shared
test evaluation logic (policy/test_eval.rs) is retained — it's still
used by the TUI test panel."
```

---

### Task 3: Remove Legacy Cap String Format Support

**Files:**
- Modify: `clash/src/policy_loader.rs` (remove `migrate_legacy_caps`, `migrate_cap_value`, migration call, test)
- Modify: `clash/src/policy/sandbox_types.rs` (remove `Cap::parse`, `parse_sandbox_rule`, tests)

- [ ] **Step 1: Remove migration functions and call from policy_loader.rs**

In `clash/src/policy_loader.rs`:

1. Remove the doc comment and `migrate_legacy_caps()` function (lines 50-111):
```rust
/// Migrate legacy string-style capability values in a policy JSON to the
/// current array format.
///
/// Old format: `"caps": "read + write"`, `"default": "all - delete"`
/// New format: `"caps": ["read", "write"]`, `"default": ["read", "write", "create", "execute"]`
///
/// If any values are migrated, the fixed JSON is written back to disk so
/// the migration is transparent and one-time.
fn migrate_legacy_caps(path: &Path, raw: String) -> Result<String> {
    ...
}
```

2. Remove the doc comment and `migrate_cap_value()` function (lines 113-127):
```rust
/// If a JSON value is a string that looks like a legacy cap expression
/// ...
fn migrate_cap_value(value: &serde_json::Value) -> Option<serde_json::Value> {
    ...
}
```

3. In `load_json_policy()` (around line 131-137), remove the migration call. Change:
```rust
pub fn load_json_policy(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    // Migrate legacy string-style caps (e.g. "read + write") to array format
    // (e.g. ["read", "write"]) before parsing. Writes the fixed file back if changed.
    let raw = migrate_legacy_caps(path, raw)?;

    let manifest: PolicyManifest = serde_json::from_str(&raw)
```

To:
```rust
pub fn load_json_policy(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let manifest: PolicyManifest = serde_json::from_str(&raw)
```

4. Remove the `migrate_legacy_string_caps_to_array` test (starts at line 622, find the `#[test]` and the entire function body through its closing brace).

- [ ] **Step 2: Remove Cap::parse and parse_sandbox_rule from sandbox_types.rs**

In `clash/src/policy/sandbox_types.rs`:

1. Remove the `Cap::parse()` method (lines 32-75). Keep `parse_single()` which follows it — that's used by the Deserialize impl. The doc comment starting at line 32 (`/// Parse a capability expression.`) through line 75 (closing brace) should go.

2. Remove `parse_sandbox_rule()` function (lines 620-657), including its doc comment if any.

3. Remove these test functions:
   - `test_cap_parse` (lines 663-675)
   - `test_cap_parse_all_keyword` (lines 677-681)
   - `test_cap_parse_subtraction` (lines 683-718)
   - `test_parse_sandbox_rule` (lines 755-762)
   - `test_parse_sandbox_rule_deny` (lines 764-770)

4. Keep these tests (they don't use `Cap::parse`):
   - `test_cap_short`
   - `test_cap_display`
   - `test_cap_serde_roundtrip`
   - `test_cap_deserialize_string_rejected`
   - `test_effective_caps`

- [ ] **Step 3: Check for unused imports**

After the removals, check if any imports in `policy_loader.rs` or `sandbox_types.rs` became unused. The migration code used `Cap` from sandbox_types — verify it's still imported for other reasons. Remove any newly-unused imports.

- [ ] **Step 4: Build and test**

Run: `cargo build -p clash 2>&1`
Expected: compiles cleanly

Run: `cargo test -p clash 2>&1`
Expected: all tests pass, test count reduced

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(policy): remove legacy cap string format support

Remove migrate_legacy_caps() which converted old 'read + write' string
format to ['read', 'write'] array format on every policy load. Also
remove Cap::parse() (the expression parser) and parse_sandbox_rule()
which was defined but never called. The array format is the only
supported format now."
```

---

### Task 4: Remove Legacy Session Directory Scanning

**Files:**
- Modify: `clash/src/debug/log.rs` (remove `scan_legacy_session_dirs`, update `read_all_session_logs`)

- [ ] **Step 1: Remove legacy scan function**

In `clash/src/debug/log.rs`, remove the `scan_legacy_session_dirs()` function (lines 129-155):
```rust
/// Scan legacy temp-dir location (`/tmp/clash-<session_id>/audit.jsonl`).
fn scan_legacy_session_dirs(tmp: &Path, all_entries: &mut Vec<AuditLogEntry>) {
    ...
}
```

- [ ] **Step 2: Remove call site in read_all_session_logs**

In `read_all_session_logs()`, remove lines 89-91:
```rust
    // Also scan the legacy temp-dir location for backwards compatibility.
    let tmp = std::env::temp_dir();
    scan_legacy_session_dirs(&tmp, &mut all_entries);
```

Note: **keep `backfill_session_id()`** — it's also called from `scan_session_dirs()` (line 113) for the modern path.

- [ ] **Step 3: Build and test**

Run: `cargo build -p clash 2>&1`
Expected: compiles cleanly

Run: `cargo test -p clash 2>&1`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(debug): remove legacy session directory scanning

Remove scan_legacy_session_dirs() which scanned /tmp/clash-<id>/ for
audit logs from the old temp-dir layout. The modern path
(~/.clash/sessions/) has been the only location for a long time and
any old temp files have been cleaned up by the OS."
```

---

### Task 5: Dead Code Sweep and Structural Cleanup

**Files:**
- Modify: `clash/src/cmd/doctor.rs` (remove `check_settings_dir`, remove `check_deprecated_match` call and function)
- Modify: `clash_starlark/src/globals.rs` (verify clean after Task 1)
- Modify: `clash/src/policy_loader.rs` (verify clean after Task 3)

- [ ] **Step 1: Remove check_deprecated_match from doctor.rs**

In `clash/src/cmd/doctor.rs`:

1. Remove the call site at line 93:
```rust
        ("Deprecated match()", check_deprecated_match()),
```

2. Remove the entire function (lines 480-510):
```rust
/// Check: Do any policy files use the deprecated `match()` function (renamed to `when()`)?
fn check_deprecated_match() -> CheckResult {
    ...
}
```

- [ ] **Step 2: Remove check_settings_dir from doctor.rs**

In `clash/src/cmd/doctor.rs`, remove lines 711-724:
```rust
/// Check that the user-level settings dir (~/.clash/) exists.
///
/// Not used as a top-level check but available as a helper.
#[allow(dead_code)]
fn check_settings_dir() -> CheckResult {
    ...
}
```

- [ ] **Step 3: Check for newly-unused imports across all modified files**

Run: `cargo build -p clash -p clash_starlark 2>&1`

Look for warnings like `unused import`. Fix any that appear by removing the unused import lines.

- [ ] **Step 4: Full build and test**

Run: `cargo build --workspace 2>&1`
Expected: compiles cleanly with no new warnings

Run: `cargo test --workspace 2>&1`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(doctor): remove dead code and deprecated checks

Remove check_deprecated_match() which warned about the old match()→when()
rename (moot now that match_tree.star is gone). Remove check_settings_dir()
which was marked dead_code and never called. Clean up any unused imports
from prior removal tasks."
```

---

### Task 6: Final Verification

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace 2>&1`
Expected: clean build, no warnings

- [ ] **Step 2: Full workspace tests**

Run: `cargo test --workspace 2>&1`
Expected: all tests pass

- [ ] **Step 3: Run project checks**

Run: `just check 2>&1`
Expected: passes (unit tests + linting)

- [ ] **Step 4: Verify deleted files are gone**

```bash
test ! -f clash_starlark/stdlib/match_tree.star && echo "OK"
test ! -f clash_starlark/src/builders/base.rs && echo "OK"
test ! -f clash_starlark/src/compile.rs && echo "OK"
test ! -f clash/src/cmd/playground.rs && echo "OK"
```
Expected: four "OK" lines

- [ ] **Step 5: Quick grep for dangling references**

```bash
grep -r "match_tree\.star" clash_starlark/src/ clash/src/ || echo "No references"
grep -r "playground" clash/src/cmd/mod.rs clash/src/main.rs || echo "No references"
grep -r "migrate_legacy_caps\|migrate_cap_value" clash/src/ || echo "No references"
grep -r "scan_legacy_session_dirs" clash/src/ || echo "No references"
grep -r "check_deprecated_match\|check_settings_dir" clash/src/ || echo "No references"
```
Expected: all lines print "No references"
