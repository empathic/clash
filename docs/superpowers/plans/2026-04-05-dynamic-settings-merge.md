# Dynamic Settings Import via `merge()` + Dict-Only Policy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace one-time Claude settings import with dynamic `from_claude_settings()` in generated policies, add `merge()` for dict composition, and remove `when()`/`rules=` syntax.

**Architecture:** New `merge()` Starlark native function does deep dict merge (rightmost wins) with shadow tracking. `from_claude_settings()` returns a policy dict instead of `list[MatchTreeNode]`. `policy()` accepts only a single dict arg. Migration tooling converts old syntax.

**Tech Stack:** Rust + Starlark (starlark crate), tree-sitter for codegen/parsing, clap for CLI

---

### Task 1: Add `merge()` native function to Starlark globals

**Files:**
- Modify: `clash_starlark/src/globals.rs:45-147`
- Modify: `clash_starlark/src/eval_context.rs`
- Modify: `clash_starlark/stdlib/std.star:250-275`
- Test: `clash_starlark/src/lib.rs` (integration tests at bottom)

- [ ] **Step 1: Add `ShadowedRule` struct to eval_context.rs**

Add after the `PolicyRegistration` struct (line 27):

```rust
/// A rule from a lower-priority dict that was overridden during merge().
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShadowedRule {
    /// Human-readable key path, e.g. "Bash > git > push"
    pub path: Vec<String>,
    /// The winning (rightmost) effect, e.g. "deny"
    pub winner: String,
    /// The overridden effect, e.g. "allow"
    pub shadowed: String,
}
```

- [ ] **Step 2: Add `shadows` field to `EvalContext`**

Add to the `EvalContext` struct (line 33-38):

```rust
pub shadows: RefCell<Vec<ShadowedRule>>,
```

Initialize in `new()`:

```rust
shadows: RefCell::new(Vec::new()),
```

- [ ] **Step 3: Add `shadows` to `EvalOutput`**

In `clash_starlark/src/lib.rs`, add to `EvalOutput` (line 22-27):

```rust
pub struct EvalOutput {
    pub json: String,
    pub loaded_files: Vec<String>,
    pub shadows: Vec<eval_context::ShadowedRule>,
}
```

Update `evaluate()` (around line 63-70) to extract shadows from the context:

```rust
let shadows = ctx.shadows.borrow().clone();

Ok(EvalOutput { json, loaded_files, shadows })
```

- [ ] **Step 4: Register `_merge()` native function in globals.rs**

Add after `_from_claude_settings` (line 147). The function accepts variadic dict arguments, deep-merges them (rightmost wins), and records shadows in the EvalContext:

```rust
/// Deep-merge policy dicts. Rightmost wins at leaf conflicts.
/// Records shadowed rules in the EvalContext.
fn _merge<'v>(
    args: &starlark::eval::Arguments<'v, '_>,
    eval: &mut Evaluator<'v, '_, '_>,
) -> anyhow::Result<Value<'v>> {
    let positional = args.positional(eval.heap())?;
    if positional.len() < 2 {
        anyhow::bail!("merge() requires at least 2 dict arguments");
    }
    // Validate all args are dicts
    for (i, arg) in positional.iter().enumerate() {
        if starlark::values::dict::DictRef::from_value(*arg).is_none() {
            anyhow::bail!("merge() argument {} is not a dict (got {})", i + 1, arg.get_type());
        }
    }

    let heap = eval.heap();
    let ctx = eval.extra.and_then(|e| e.downcast_ref::<EvalContext>());

    // Start with the first dict, merge each subsequent one on top
    let mut result = positional[0];
    for arg in &positional[1..] {
        result = deep_merge_dicts(result, *arg, heap, ctx, &mut Vec::new())?;
    }
    Ok(result)
}
```

- [ ] **Step 5: Implement `deep_merge_dicts` helper**

Add as a module-level function in `globals.rs`:

```rust
/// Deep-merge two Starlark dicts. Values from `right` override `left` at leaf conflicts.
/// When both sides have a dict at the same key, recurse. Otherwise right wins.
fn deep_merge_dicts<'v>(
    left: Value<'v>,
    right: Value<'v>,
    heap: &'v Heap,
    ctx: Option<&EvalContext>,
    key_path: &mut Vec<String>,
) -> anyhow::Result<Value<'v>> {
    use starlark::values::dict::{DictRef, AllocDict};

    let left_dict = DictRef::from_value(left).unwrap();
    let right_dict = DictRef::from_value(right).unwrap();

    // Collect all key-value pairs, right overriding left
    let mut entries: Vec<(Value<'v>, Value<'v>)> = Vec::new();
    let mut right_keys: std::collections::HashSet<u32> = std::collections::HashSet::new();

    // First pass: iterate left, checking for overlaps with right
    for (lk, lv) in left_dict.iter() {
        if let Some(rv) = right_dict.get(lk)? {
            right_keys.insert(lk.get_hashed()?.hash());
            let left_is_dict = DictRef::from_value(lv).is_some();
            let right_is_dict = DictRef::from_value(rv).is_some();

            key_path.push(lk.to_string());
            if left_is_dict && right_is_dict {
                // Both dicts — recurse
                let merged = deep_merge_dicts(lv, rv, heap, ctx, key_path)?;
                entries.push((lk, merged));
            } else {
                // Leaf conflict — right wins, record shadow
                if let Some(ctx) = ctx {
                    ctx.shadows.borrow_mut().push(ShadowedRule {
                        path: key_path.clone(),
                        winner: rv.to_string(),
                        shadowed: lv.to_string(),
                    });
                }
                entries.push((lk, rv));
            }
            key_path.pop();
        } else {
            entries.push((lk, lv));
        }
    }

    // Second pass: add right-only keys
    for (rk, rv) in right_dict.iter() {
        let dominated = right_keys.contains(&rk.get_hashed()?.hash());
        if !dominated {
            entries.push((rk, rv));
        }
    }

    Ok(heap.alloc(AllocDict(entries)))
}
```

Note: The exact hash-based dedup above is a sketch. The real implementation needs to check key equality properly via Starlark's `equals()` method since `get_hashed()` collisions are possible. Use `right_dict.get(lk)?` returning `Some` as the authoritative overlap check, and track which right keys were consumed by iterating right and checking `left_dict.get(rk)?` to find right-only keys.

- [ ] **Step 6: Export `merge` in std.star**

In `clash_starlark/stdlib/std.star`, add after the `policy()` wrapper (around line 275):

```starlark
def merge(*dicts):
    """Deep-merge policy dicts. Rightmost wins at leaf conflicts.

    Usage:
        policy("default", merge(
            from_claude_settings(),  # lowest priority
            { ... user rules ... },  # highest priority
        ))
    """
    return _merge(*dicts)
```

- [ ] **Step 7: Write unit test for merge()**

Add to `clash_starlark/src/lib.rs` tests:

```rust
#[test]
fn merge_non_overlapping_dicts() {
    let source = r#"
policy("test", merge(
    {Tool("Bash"): {"git": allow()}},
    {Tool("Read"): allow()},
))
"#;
    let doc = eval_to_doc(source);
    let tree = doc["tree"].as_array().unwrap();
    assert_eq!(tree.len(), 2);
}

#[test]
fn merge_rightmost_wins() {
    let source = r#"
policy("test", merge(
    {Tool("Bash"): deny()},
    {Tool("Bash"): allow()},
))
"#;
    let doc = eval_to_doc(source);
    let tree = doc["tree"].as_array().unwrap();
    assert_eq!(tree.len(), 1);
    // The rightmost (allow) should win
    let decision = &tree[0]["condition"]["children"][0];
    assert!(decision["decision"].get("allow").is_some());
}

#[test]
fn merge_deep_nested() {
    let source = r#"
policy("test", merge(
    {Tool("Bash"): {"git": deny(), "cargo": allow()}},
    {Tool("Bash"): {"git": allow(), "npm": allow()}},
))
"#;
    let doc = eval_to_doc(source);
    let tree = doc["tree"].as_array().unwrap();
    // Should have one Tool("Bash") node with 3 children: git(allow), cargo(allow), npm(allow)
    assert_eq!(tree.len(), 1);
}

#[test]
fn merge_variadic_three_dicts() {
    let source = r#"
policy("test", merge(
    {Tool("Bash"): deny()},
    {Tool("Read"): deny()},
    {Tool("Bash"): allow()},
))
"#;
    let doc = eval_to_doc(source);
    let tree = doc["tree"].as_array().unwrap();
    assert_eq!(tree.len(), 2); // Bash + Read
}
```

- [ ] **Step 8: Run tests to verify merge() works**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark merge`
Expected: All new merge tests PASS

- [ ] **Step 9: Verify shadow tracking works**

Add test in `clash_starlark/src/lib.rs`:

```rust
#[test]
fn merge_records_shadows() {
    let source = r#"
policy("test", merge(
    {Tool("Bash"): deny()},
    {Tool("Bash"): allow()},
))
"#;
    let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
    assert_eq!(result.shadows.len(), 1);
    assert_eq!(result.shadows[0].path, vec!["Tool(\"Bash\")"]);
}
```

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark merge_records_shadows`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add clash_starlark/src/globals.rs clash_starlark/src/eval_context.rs clash_starlark/src/lib.rs clash_starlark/stdlib/std.star
git commit -m "feat(starlark): add merge() for deep dict composition with shadow tracking"
```

---

### Task 2: Convert `from_claude_settings()` to return a dict

**Files:**
- Modify: `clash_starlark/src/settings_compat.rs`
- Modify: `clash_starlark/src/globals.rs:139-147`
- Modify: `clash_starlark/stdlib/claude_compat.star`
- Test: `clash_starlark/src/settings_compat.rs` (tests at line 223+)

- [ ] **Step 1: Write failing test for dict return type**

Add to `clash_starlark/src/settings_compat.rs` tests:

```rust
#[test]
fn from_claude_settings_returns_dict() {
    let dir = tempfile::tempdir().unwrap();
    let settings_dir = dir.path().join(".claude");
    std::fs::create_dir_all(&settings_dir).unwrap();
    std::fs::write(
        settings_dir.join("settings.json"),
        r#"{"permissions":{"allow":["Bash(git:*)"]}}"#,
    ).unwrap();

    let resolver = test_resolver(dir.path());
    let dict = from_claude_settings_as_dict_inner(true, false, Some(resolver));
    // Should contain a Tool("Bash") key with git subtree
    assert!(!dict.is_empty());
    // Verify it's a nested structure, not a flat list
    assert!(dict.contains_key("Bash"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark from_claude_settings_returns_dict`
Expected: FAIL — function doesn't exist yet

- [ ] **Step 3: Implement `from_claude_settings_as_dict` in settings_compat.rs**

Add a new function that builds a nested `BTreeMap` representing the policy dict structure. This is a Rust-side intermediate representation that the native function will convert to a Starlark dict.

```rust
use std::collections::BTreeMap;

/// A tree of policy entries that can be converted to a Starlark dict.
#[derive(Debug, Clone)]
pub enum PolicyDictValue {
    /// A leaf effect: "allow", "deny", or "ask"
    Effect(String),
    /// A nested dict of sub-keys
    Dict(BTreeMap<String, PolicyDictValue>),
}

/// Build a policy dict from Claude Code settings.
/// Returns a nested map: tool_name → { arg/path → effect }
pub fn from_claude_settings_as_dict(user: bool, project: bool) -> BTreeMap<String, PolicyDictValue> {
    from_claude_settings_as_dict_inner(user, project, None)
}

pub(crate) fn from_claude_settings_as_dict_inner(
    user: bool,
    project: bool,
    resolver: Option<PathResolver>,
) -> BTreeMap<String, PolicyDictValue> {
    let manager = match resolver {
        Some(r) => claude_settings::ClaudeSettings::with_resolver(r),
        None => claude_settings::ClaudeSettings::new(),
    };

    let mut combined = claude_settings::PermissionSet::new();

    if user {
        if let Ok(Some(settings)) = manager.read(claude_settings::SettingsLevel::User) {
            combined = combined.merge(&settings.permissions);
        }
    }

    if project {
        if let Ok(Some(settings)) = manager.read(claude_settings::SettingsLevel::Project) {
            combined = combined.merge(&settings.permissions);
        }
        if let Ok(Some(settings)) = manager.read(claude_settings::SettingsLevel::ProjectLocal) {
            combined = combined.merge(&settings.permissions);
        }
    }

    permissions_to_dict(&combined)
}

fn permissions_to_dict(perms: &claude_settings::PermissionSet) -> BTreeMap<String, PolicyDictValue> {
    let mut root: BTreeMap<String, PolicyDictValue> = BTreeMap::new();

    for perm in perms.denied() {
        insert_permission(&mut root, perm, "deny");
    }
    for perm in perms.asking() {
        insert_permission(&mut root, perm, "ask");
    }
    for perm in perms.allowed() {
        insert_permission(&mut root, perm, "allow");
    }

    root
}

fn insert_permission(root: &mut BTreeMap<String, PolicyDictValue>, perm: &str, effect: &str) {
    // Skip MCP tools
    if perm.starts_with("mcp__") {
        return;
    }

    // Parse "ToolName" or "ToolName(arg)" format
    if let Some(paren_idx) = perm.find('(') {
        let tool = &perm[..paren_idx];
        let arg = &perm[paren_idx + 1..perm.len() - 1]; // strip parens

        if tool == "Bash" {
            // Bash(git:*) or Bash(cargo build:*)
            let parts: Vec<&str> = arg.trim_end_matches(":*").split_whitespace().collect();
            let binary = parts[0];
            let tool_entry = root
                .entry("Bash".to_string())
                .or_insert_with(|| PolicyDictValue::Dict(BTreeMap::new()));
            if let PolicyDictValue::Dict(bash_dict) = tool_entry {
                if parts.len() > 1 {
                    let bin_entry = bash_dict
                        .entry(binary.to_string())
                        .or_insert_with(|| PolicyDictValue::Dict(BTreeMap::new()));
                    if let PolicyDictValue::Dict(bin_dict) = bin_entry {
                        bin_dict.insert(parts[1].to_string(), PolicyDictValue::Effect(effect.to_string()));
                    }
                } else {
                    bash_dict.insert(binary.to_string(), PolicyDictValue::Effect(effect.to_string()));
                }
            }
        } else {
            // Tool(path) — file access like Read(.env) or Read(**/*.rs)
            let tool_entry = root
                .entry(tool.to_string())
                .or_insert_with(|| PolicyDictValue::Dict(BTreeMap::new()));
            if let PolicyDictValue::Dict(tool_dict) = tool_entry {
                tool_dict.insert(arg.to_string(), PolicyDictValue::Effect(effect.to_string()));
            }
        }
    } else {
        // Tool-only permission like "Read" or "Write"
        root.insert(perm.to_string(), PolicyDictValue::Effect(effect.to_string()));
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark from_claude_settings_returns_dict`
Expected: PASS

- [ ] **Step 5: Update `_from_claude_settings` native function to return a dict**

In `clash_starlark/src/globals.rs`, replace the existing `_from_claude_settings` (lines 139-147):

```rust
fn _from_claude_settings<'v>(
    #[starlark(require = named, default = true)] user: bool,
    #[starlark(require = named, default = true)] project: bool,
    heap: &'v Heap,
) -> anyhow::Result<Value<'v>> {
    let dict_tree = crate::settings_compat::from_claude_settings_as_dict(user, project);
    Ok(policy_dict_to_starlark(dict_tree, heap))
}
```

Implement the converter:

```rust
fn policy_dict_to_starlark<'v>(
    tree: std::collections::BTreeMap<String, crate::settings_compat::PolicyDictValue>,
    heap: &'v Heap,
) -> Value<'v> {
    use starlark::values::dict::AllocDict;

    let entries: Vec<(Value<'v>, Value<'v>)> = tree
        .into_iter()
        .map(|(key, value)| {
            let k = heap.alloc_str(&key).to_value();
            let v = match value {
                crate::settings_compat::PolicyDictValue::Effect(eff) => {
                    // Create effect struct via heap — for now use string
                    // that the policy dict processor recognizes
                    heap.alloc_str(&eff).to_value()
                }
                crate::settings_compat::PolicyDictValue::Dict(children) => {
                    policy_dict_to_starlark(children, heap)
                }
            };
            (k, v)
        })
        .collect();

    heap.alloc(AllocDict(entries))
}
```

Note: The keys need to be actual `Tool("Bash")` structs and the leaf values need to be `allow()`/`deny()`/`ask()` effect structs, not plain strings. The exact construction depends on how std.star constructs these. The native function should build the same struct types that the DSL uses. This may require calling back into the Starlark module to construct Tool() and allow()/deny()/ask(), OR building the equivalent structs natively. The simplest approach is to build them natively using `heap.alloc(starlark::values::structs::AllocStruct(...))` with the same field names the stdlib uses (`_match_key`, `_match_value` for Tool; `_effect`, `_sandbox`, `_is_effect` for effects).

- [ ] **Step 6: Write integration test for dict-based from_claude_settings in policy**

```rust
#[test]
fn from_claude_settings_dict_in_policy() {
    // This test uses the Starlark evaluator to verify the dict
    // returned by from_claude_settings() works inside merge() + policy()
    let source = r#"
load("@clash//claude_compat.star", "from_claude_settings")

policy("test", merge(
    from_claude_settings(user=False, project=False),
    {Tool("Bash"): {"git": allow()}},
))
"#;
    let result = evaluate(source, "test.star", &PathBuf::from(".")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&result.json).unwrap();
    let tree = doc["tree"].as_array().unwrap();
    assert!(!tree.is_empty());
}
```

- [ ] **Step 7: Run tests**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark from_claude_settings`
Expected: PASS

- [ ] **Step 8: Update claude_compat.star docs**

```starlark
# Claude Code compatibility — dynamic settings import.
#
# Usage:
#   load("@clash//claude_compat.star", "from_claude_settings")
#   policy("main", merge(
#       from_claude_settings(user=True, project=True),
#       { ... your rules ... },
#   ))

from_claude_settings = _from_claude_settings
```

- [ ] **Step 9: Commit**

```bash
git add clash_starlark/src/settings_compat.rs clash_starlark/src/globals.rs clash_starlark/stdlib/claude_compat.star clash_starlark/src/lib.rs
git commit -m "feat(starlark): from_claude_settings() returns policy dict for merge()"
```

---

### Task 3: Remove `when()` and `rules=` from policy evaluation

**Files:**
- Modify: `clash_starlark/src/globals.rs:219-294`
- Modify: `clash_starlark/src/when.rs`
- Modify: `clash_starlark/stdlib/std.star:250-275`
- Modify: `clash_starlark/src/eval_context.rs:36-37`
- Test: `clash_starlark/src/lib.rs`

- [ ] **Step 1: Write test confirming when() is undefined**

```rust
#[test]
fn when_is_removed() {
    let source = r#"
policy("test", rules=[when({"Read": allow()})])
"#;
    let result = evaluate(source, "test.star", &PathBuf::from("."));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("when") || err.contains("Variable `when` is not bound"),
        "error should mention when(): {err}"
    );
}

#[test]
fn rules_kwarg_is_removed() {
    let source = r#"
policy("test", rules=[])
"#;
    let result = evaluate(source, "test.star", &PathBuf::from("."));
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail (when/rules still exist)**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark when_is_removed rules_kwarg_is_removed`
Expected: FAIL — `when()` still exists

- [ ] **Step 3: Remove `when()` from std.star**

In `clash_starlark/stdlib/std.star`, remove the `when()` function definition (lines 250-257) and its section comment. Also remove `when` from any load statement references.

- [ ] **Step 4: Simplify `policy()` in std.star**

Replace the policy wrapper (lines 259-274):

```starlark
def policy(name, rules_or_dict=None, default="deny", default_sandbox=None):
    """Register a named policy.

    Usage:
        policy("default", {
            mode("plan"): allow(sandbox=plan_box),
            mode("edit"): allow(sandbox=edit_box),
        })

        # With merge for composing multiple sources:
        policy("default", merge(
            from_claude_settings(),
            { ... your rules ... },
        ))
    """
    _policy_impl(name, rules_or_dict, default=_unwrap_effect(default), default_sandbox=default_sandbox)
```

- [ ] **Step 5: Remove `_when_impl` from globals.rs**

Remove the `_when_impl` function (lines 219-237).

- [ ] **Step 6: Simplify `_policy_impl` in globals.rs**

Remove the `rules` parameter and the `process_rules_list` branch. The simplified function:

```rust
fn _policy_impl<'v>(
    #[starlark(require = pos)] name: &str,
    #[starlark(require = pos, default = starlark::values::none::NoneType)] rules_or_dict: Value<'v>,
    #[starlark(require = named, default = starlark::values::none::NoneType)] default: Value<'v>,
    #[starlark(require = named, default = starlark::values::none::NoneType)]
    default_sandbox: Value<'v>,
    eval: &mut Evaluator<'v, '_, '_>,
) -> anyhow::Result<NoneType> {
    let heap = eval.heap();
    let ctx = eval
        .extra
        .and_then(|e| e.downcast_ref::<EvalContext>())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "policy() can only be called in a policy file, not in loaded modules"
            )
        })?;

    let default_effect = if default.is_none() {
        "deny".to_string()
    } else if let Some(s) = default.unpack_str() {
        s.to_string()
    } else if default.get_type() == "struct" {
        default
            .get_attr("_effect", heap)
            .ok()
            .flatten()
            .and_then(|v| v.unpack_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "deny".to_string())
    } else {
        "deny".to_string()
    };

    let source = caller_source_location(eval);
    let (flat_nodes, sandboxes) =
        crate::when::policy_impl_dict_only(name, rules_or_dict, default_sandbox, heap, source)?;

    ctx.register_policy(PolicyRegistration {
        name: name.to_string(),
        tree_nodes: flat_nodes,
        sandboxes,
    })?;
    Ok(NoneType)
}
```

- [ ] **Step 7: Simplify `when.rs` — remove `when_impl`, `process_rules_list`, rename `policy_impl`**

Remove `pub fn when_impl` (lines 289-329). Remove `process_rules_list` (lines 421+). Rename and simplify `policy_impl` to `policy_impl_dict_only`:

```rust
pub fn policy_impl_dict_only<'v>(
    _name: &str,
    rules_or_dict: Value<'v>,
    default_sandbox: Value<'v>,
    heap: &'v Heap,
    source: Option<String>,
) -> anyhow::Result<(Vec<JsonValue>, Vec<JsonValue>)> {
    let mut flat_nodes: Vec<JsonValue> = Vec::new();
    let mut collector = SandboxCollector::new();

    if !rules_or_dict.is_none() {
        if let Some(dict) = DictRef::from_value(rules_or_dict) {
            process_policy_dict(&dict, heap, &source, &mut flat_nodes, &mut collector)?;
        } else {
            bail!("policy() requires a dict argument, got {}. The rules= syntax has been removed — use dict syntax instead. Run `clash policy migrate` to convert.", rules_or_dict.get_type());
        }
    }

    if !default_sandbox.is_none() {
        if default_sandbox.get_type() == "struct" {
            if let Ok(Some(name_val)) = default_sandbox.get_attr("_name", heap) {
                if let Some(sb_name) = name_val.unpack_str() {
                    if collector.seen.insert(sb_name.to_string()) {
                        let sb_json = sandbox_to_json(default_sandbox, heap)?;
                        collector.sandboxes.push(sb_json);
                    }
                }
            }
        }
    }

    Ok((flat_nodes, collector.sandboxes))
}
```

- [ ] **Step 8: Remove `pending_sandboxes` from EvalContext**

Since `when()` no longer collects sandboxes that get drained by `policy()`, remove the `pending_sandboxes` field from `EvalContext` and the drain logic in `_policy_impl`.

- [ ] **Step 9: Run all starlark tests**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark`
Expected: Tests using dict syntax PASS. Tests that relied on `when()` or `rules=` FAIL — update or remove them.

- [ ] **Step 10: Fix broken tests**

Update any existing tests in `clash_starlark/src/lib.rs` or `when.rs` that use `when()` or `rules=` to use dict syntax instead. For example, change:

```rust
policy("test", rules=[when({"Read": allow()})])
```

to:

```rust
policy("test", {"Read": allow()})
```

- [ ] **Step 11: Run full starlark test suite**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark`
Expected: All PASS

- [ ] **Step 12: Commit**

```bash
git add clash_starlark/src/globals.rs clash_starlark/src/when.rs clash_starlark/stdlib/std.star clash_starlark/src/eval_context.rs clash_starlark/src/lib.rs
git commit -m "feat(starlark)!: remove when() and rules= syntax, policy() accepts dict only"
```

---

### Task 4: Remove `MatchTreeNode` and match tree builder natives from globals

**Files:**
- Modify: `clash_starlark/src/globals.rs:59-127`
- Modify: `clash_starlark/src/settings_compat.rs`
- Modify: `clash_starlark/src/builders/match_tree.rs` (check what's still needed)

- [ ] **Step 1: Check what still references match tree builders**

Search for references to `_mt_node`, `_mt_condition`, `_mt_pattern`, `_mt_prefix`, `_mt_child_of`, `_mt_literal` in the codebase. The `when.rs` dict processing still uses `mt::` functions internally for the dict→JSON path. The native globals (`_mt_node` etc.) exposed to Starlark are what we want to remove — the internal Rust `mt::` module is still used by dict processing.

- [ ] **Step 2: Remove native match tree builder functions from globals.rs**

Remove lines 59-127 (the `_mt_node`, `_mt_condition`, `_mt_pattern`, `_mt_prefix`, `_mt_child_of`, `_mt_literal` functions from the `#[starlark_module]` block). These were only used by `when()` in Starlark — the internal Rust code uses the `mt::` module directly.

- [ ] **Step 3: Update settings_compat.rs to no longer return MatchTreeNode**

The old `from_claude_settings()` and `permission_set_to_nodes()` functions that return `Vec<MatchTreeNode>` — these can be removed now that Task 2 provides the dict-based alternative. Remove `from_claude_settings`, `from_claude_settings_inner`, `permission_set_to_nodes`, `classify_permission`, `make_tool_match`, `make_bash_prefix_match`, `make_tool_arg_match` and their tests. Keep only the new dict-based functions.

- [ ] **Step 4: Check if MatchTreeNode can be made non-public**

The `MatchTreeNode` type in `builders/match_tree.rs` is still used internally by `when.rs` (the dict processing path). It doesn't need to be exposed to Starlark anymore (no `StarlarkValue` impl needed). Check if it still needs `StarlarkValue` — if it's only used as intermediate JSON, the `StarlarkValue` derive can be removed.

Actually, `MatchTreeNode` still has a `StarlarkValue` impl because `process_policy_dict` returns nodes that get collected into `tree_nodes: Vec<JsonValue>` — it extracts the `.json` field. The Starlark allocation of `MatchTreeNode` is no longer needed since we removed `when()` which was the only thing that returned them to Starlark. The dict path in `policy_impl_dict_only` already works with `JsonValue` directly. So `MatchTreeNode` can have its `StarlarkValue` impl removed if it's no longer allocated on the Starlark heap.

- [ ] **Step 5: Run tests**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add clash_starlark/src/globals.rs clash_starlark/src/settings_compat.rs clash_starlark/src/builders/
git commit -m "refactor(starlark): remove match tree builder natives and old MatchTreeNode API"
```

---

### Task 5: Update generated policies to use `merge()` + `from_claude_settings()`

**Files:**
- Modify: `clash/src/default_policy.star`
- Modify: `clash/src/ecosystem.rs:213-305`
- Test: `clash/src/cmd/init.rs` (existing compile tests)

- [ ] **Step 1: Update default_policy.star**

```starlark
load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "workspace", "git_safe", "git_full")
load("@clash//claude_compat.star", "from_claude_settings")

policy("default", merge(
    from_claude_settings(),
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_safe)
                }
            }
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_full)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
))
```

- [ ] **Step 2: Run starter policy compile test**

Run: `cd /Users/eliot/code/clash && cargo test -p clash starter_policy_compiles`
Expected: PASS

- [ ] **Step 3: Update `generate_policy()` in ecosystem.rs**

Modify `generate_policy()` (line 213+) to:
1. Add `load("@clash//claude_compat.star", "from_claude_settings")` to loads
2. Wrap the `policy()` call's dict argument in `merge(from_claude_settings(), ...)`

In the codegen, this means:
- Add a new load statement: `Stmt::Load { module: "@clash//claude_compat.star".into(), names: vec!["from_claude_settings".into()] }`
- Wrap the final `Expr::call("policy", ...)` to pass `merge(from_claude_settings(), dict)` as the second arg:

```rust
// Instead of:
stmts.push(Stmt::Expr(Expr::call(
    "policy",
    vec![Expr::string("default"), Expr::dict(mode_entries)],
)));

// Do:
stmts.push(Stmt::Expr(Expr::call(
    "policy",
    vec![
        Expr::string("default"),
        Expr::call("merge", vec![
            Expr::call("from_claude_settings", vec![]),
            Expr::dict(mode_entries),
        ]),
    ],
)));
```

Also add the claude_compat load. Check `Stmt::Load` format in the codegen AST — look at `load_builtin()` and `load_sandboxes()` for the pattern.

- [ ] **Step 4: Run ecosystem policy compile test**

Run: `cd /Users/eliot/code/clash && cargo test -p clash detected_policy_compiles`
Expected: PASS

- [ ] **Step 5: Run full init tests**

Run: `cd /Users/eliot/code/clash && cargo test -p clash init`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add clash/src/default_policy.star clash/src/ecosystem.rs
git commit -m "feat: generated policies use merge(from_claude_settings(), {...})"
```

---

### Task 6: Update managed section / CLI mutation to use dict syntax

**Files:**
- Modify: `clash_starlark/src/codegen/managed.rs`
- Modify: `clash_starlark/src/codegen/mutate.rs:78-121`
- Modify: `clash/src/cmd/policy.rs:721-849`
- Test: `clash_starlark/src/codegen/managed.rs` (tests at line 287+)

- [ ] **Step 1: Write failing test for dict-based managed rules**

In `clash_starlark/src/codegen/managed.rs` tests, add:

```rust
fn base_stmts_dict() -> Vec<Stmt> {
    parse(
        r#"load("@clash//claude_compat.star", "from_claude_settings")

policy("test", merge(
    from_claude_settings(),
    {"Read": allow()},
))
"#,
    )
    .unwrap()
}

#[test]
fn upsert_exec_inserts_dict_rule() {
    let mut stmts = base_stmts_dict();
    let result =
        upsert_exec_rule(&mut stmts, "git", &["push"], mutate::Effect::Deny, None).unwrap();
    assert_eq!(result, ManagedUpsertResult::Inserted);
    let src = serialize(&stmts);
    // Managed rule should be a dict, not a when() call
    assert!(!src.contains("when("), "should not use when(): {src}");
    assert!(src.contains("_clash_rule_0"), "got:\n{src}");
    // Should be in the merge() args
    assert!(src.contains("merge("), "got:\n{src}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark upsert_exec_inserts_dict_rule`
Expected: FAIL — still generates `when()` calls

- [ ] **Step 3: Change managed rule expression builders to use dicts**

In `managed.rs`, replace `build_exec_when_expr` (lines 256-274):

```rust
fn build_exec_dict_expr(
    binary: &str,
    args: &[&str],
    effect: mutate::Effect,
    sandbox: Option<&str>,
) -> Expr {
    let effect_expr = build_effect_expr(effect, sandbox);

    // Build nested dict: binary -> arg1 -> arg2 -> ... -> effect
    let mut value = effect_expr;
    for arg in args.iter().rev() {
        value = Expr::dict(vec![DictEntry::new(Expr::string(*arg), value)]);
    }
    Expr::dict(vec![DictEntry::new(
        Expr::call("Tool", vec![Expr::string("Bash")]),
        Expr::dict(vec![DictEntry::new(Expr::string(binary), value)]),
    )])
}
```

Update `upsert_tool_rule` to generate a dict instead of `when()`:

```rust
let new_expr = Expr::dict(vec![DictEntry::new(
    Expr::call("Tool", vec![Expr::string(tool_name)]),
    effect_expr,
)]);
```

- [ ] **Step 4: Change `insert_managed_rule` to add to merge() args instead of rules list**

Replace the current `insert_managed_rule` which calls `mutate::policy_rules_mut()` and `mutate::ensure_loaded(stmts, "when")`. Instead:

```rust
fn insert_managed_rule(
    stmts: &mut Vec<Stmt>,
    var_name: &str,
    expr: Expr,
    match_key: &str,
) -> Result<(), String> {
    let insert_at = find_managed_section_end(stmts);

    stmts.insert(insert_at, Stmt::Comment(format!("clash-managed:{match_key}")));
    stmts.insert(insert_at + 1, Stmt::Assign {
        target: var_name.to_string(),
        value: expr,
    });

    // Add reference as the last arg to merge() in policy() call
    add_to_merge_args(stmts, var_name)
        .ok_or_else(|| "no policy() call with merge() found".to_string())?;

    Ok(())
}
```

Implement `add_to_merge_args` and `remove_from_merge_args` — these find the `merge()` call inside `policy()` and append/remove an ident from its argument list. Managed rules go last (rightmost = highest priority).

- [ ] **Step 5: Add `policy_merge_args_mut` to mutate.rs**

Replace or augment `policy_rules_mut` (lines 78-121) with a function that finds merge() args:

```rust
/// Find the merge() call inside policy() and return a mutable ref to its args.
pub fn policy_merge_args_mut(stmts: &mut [Stmt]) -> Option<&mut Vec<Expr>> {
    let policy_idx = find_policy_call(stmts)?;
    if let Stmt::Expr(Expr::Call { args, .. }) = &mut stmts[policy_idx] {
        // Second arg should be merge(...)
        if args.len() >= 2 {
            if let Expr::Call { name, args: merge_args, .. } = &mut args[1] {
                if name == "merge" {
                    return Some(merge_args);
                }
            }
        }
    }
    None
}
```

- [ ] **Step 6: Update `remove_managed_by_key` to use merge args**

```rust
fn remove_managed_by_key(stmts: &mut Vec<Stmt>, match_key: &str) -> bool {
    let found = find_managed_by_key(stmts, match_key);
    let Some((var_name, assign_idx)) = found else {
        return false;
    };
    let comment_idx = assign_idx - 1;

    // Remove the reference from merge() args
    if let Some(args) = mutate::policy_merge_args_mut(stmts) {
        args.retain(|expr| !is_ident_ref(expr, &var_name));
    }

    stmts.remove(assign_idx);
    stmts.remove(comment_idx);

    true
}
```

- [ ] **Step 7: Update old `base_stmts()` test fixture**

The old test fixture uses `rules=` which no longer works. Update it to use dict syntax + merge():

```rust
fn base_stmts() -> Vec<Stmt> {
    parse(
        r#"load("@clash//claude_compat.star", "from_claude_settings")

policy("test", merge(
    from_claude_settings(),
    {"Read": allow()},
))
"#,
    )
    .unwrap()
}
```

- [ ] **Step 8: Run managed section tests**

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark managed`
Expected: All PASS

- [ ] **Step 9: Run managed rules evaluation test**

The `managed_rules_evaluate_correctly` test should still verify that the generated code actually evaluates. Run:

Run: `cd /Users/eliot/code/clash && cargo test -p clash_starlark managed_rules_evaluate`
Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add clash_starlark/src/codegen/managed.rs clash_starlark/src/codegen/mutate.rs clash/src/cmd/policy.rs
git commit -m "feat(codegen): managed rules use dict syntax with merge() args"
```

---

### Task 7: Display shadowed rules in `clash status`

**Files:**
- Modify: `clash/src/cmd/status.rs`
- Modify: `clash/src/policy_loader.rs` (or wherever EvalOutput is consumed)

- [ ] **Step 1: Thread shadows through policy loading**

The key call site is `clash/src/policy_loader.rs:45-47` which calls `clash_starlark::evaluate()` and returns only `output.json`. Change this function to return `EvalOutput` (or a struct containing both `json` and `shadows`). Then in `clash/src/settings/loader.rs:307` (`load_policy_from_path`), store the shadows alongside the compiled policy. Add a `shadows: Vec<clash_starlark::eval_context::ShadowedRule>` field to `ClashSettings` or the policy state struct that `clash status` reads from.

- [ ] **Step 2: Add shadow display to status.rs**

After the policy tree rendering (around line 141), add:

```rust
// Display shadowed rules from merge()
if !shadows.is_empty() {
    println!();
    style::header("Overridden Claude Code settings");
    println!();
    for shadow in &shadows {
        let path = shadow.path.join(" > ");
        println!(
            "  {} {} (Claude Code: {})",
            style::dim(&path),
            style::bold(&shadow.winner),
            style::dim(&shadow.shadowed),
        );
    }
}
```

- [ ] **Step 3: Test manually**

Run: `clash status`
Expected: If user has Claude Code settings that overlap with their policy, the "Overridden Claude Code settings" section appears.

- [ ] **Step 4: Commit**

```bash
git add clash/src/cmd/status.rs clash/src/policy_loader.rs
git commit -m "feat(status): display shadowed rules from merge() in clash status"
```

---

### Task 8: Add `clash policy migrate` command

**Files:**
- Modify: `clash/src/cli.rs:56-190`
- Modify: `clash/src/cmd/policy.rs`
- Test: manual + clester

- [ ] **Step 1: Add `Migrate` variant to `PolicyCmd` enum**

In `clash/src/cli.rs`, add to the `PolicyCmd` enum:

```rust
/// Migrate policy from when()/rules= syntax to dict syntax
///
/// Converts deprecated when() calls and rules= lists to dict syntax.
/// Adds from_claude_settings() if not already present.
Migrate {
    /// Policy scope: "user" or "project" (default: auto-detect)
    #[arg(long)]
    scope: Option<String>,
    /// Skip confirmation dialog
    #[arg(long, short = 'y')]
    yes: bool,
},
```

- [ ] **Step 2: Add match arm in `run()` dispatcher**

In `clash/src/cmd/policy.rs`, add:

```rust
PolicyCmd::Migrate { scope, yes } => handle_migrate(scope, yes),
```

- [ ] **Step 3: Implement `handle_migrate()`**

```rust
fn handle_migrate(scope: Option<String>, yes: bool) -> Result<()> {
    let path = resolve_manifest_path(scope)?;

    if !path.extension().is_some_and(|ext| ext == "star") {
        ui::info("Migration is only needed for .star policy files.");
        ui::info("Run `clash policy convert` to convert .json to .star first.");
        return Ok(());
    }

    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    // Check if migration is needed
    let needs_when = source.contains("when(");
    let needs_rules = source.contains("rules=") || source.contains("rules =");
    let needs_claude_settings = !source.contains("from_claude_settings");

    if !needs_when && !needs_rules && !needs_claude_settings {
        ui::success("Policy already uses dict syntax. Nothing to migrate.");
        return Ok(());
    }

    // Parse into codegen AST
    use clash_starlark::codegen::document::StarDocument;
    let mut doc = StarDocument::open(&path)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let mut changes = Vec::new();

    if needs_when || needs_rules {
        migrate_when_and_rules(&mut doc.stmts)?;
        changes.push("converted when()/rules= to dict syntax");
    }

    if needs_claude_settings {
        add_from_claude_settings(&mut doc.stmts)?;
        changes.push("added from_claude_settings() via merge()");
    }

    // Validate the result
    let new_source = clash_starlark::codegen::serialize(&doc.stmts);
    let base_dir = path.parent().unwrap_or(std::path::Path::new("."));
    clash_starlark::evaluate(&new_source, &path.display().to_string(), base_dir)
        .context("migrated policy failed validation")?;

    // Show changes
    println!();
    ui::info("Migration changes:");
    for change in &changes {
        println!("  {}", style::dim(change));
    }

    // Show diff using existing tree diff if available
    // ... (use policy diff utility from workstream 1 if it exists)

    if !yes {
        println!();
        let confirm = crate::dialog::confirm("Apply migration?", false)?;
        if !confirm {
            ui::warn("Migration cancelled.");
            return Ok(());
        }
    }

    doc.save()
        .with_context(|| format!("failed to write {}", path.display()))?;

    ui::success(&format!("Policy migrated: {}", path.display()));
    Ok(())
}
```

- [ ] **Step 4: Implement `migrate_when_and_rules` helper**

This converts `when()` calls in rules lists to dict entries and restructures the policy call. The approach:

1. Find `policy()` call in the AST
2. If it has `rules=` kwarg or a list as second positional arg, extract the items
3. For each `when({...})` call, extract the dict arg
4. Combine all dicts into a single dict (or `merge()` call)
5. Replace the policy call with dict syntax

```rust
fn migrate_when_and_rules(stmts: &mut Vec<Stmt>) -> Result<()> {
    use clash_starlark::codegen::ast::{Expr, Stmt};
    use clash_starlark::codegen::mutate;

    // Find the policy() call
    let policy_idx = mutate::find_policy_call(stmts)
        .ok_or_else(|| anyhow::anyhow!("no policy() call found"))?;

    // Extract rules from when() calls and convert to dicts
    // This is AST-level transformation — extract dict args from when() calls
    // and combine them as merge() arguments or a single dict
    
    // Implementation depends on exact AST structure — walk the policy call's
    // arguments, find when() calls, extract their dict argument, collect them.
    // Then rebuild the policy call as policy("name", merge(dict1, dict2, ...))
    
    Ok(())
}
```

Note: The exact implementation depends on the codegen AST structure. The key transformation is:
- `policy("name", rules=[when({A}), when({B})])` → `policy("name", merge({A}, {B}))`
- `policy("name", rules=[when({A})])` → `policy("name", {A})`
- Managed `_clash_rule_N = when({...})` → `_clash_rule_N = {...}`

- [ ] **Step 5: Implement `add_from_claude_settings` helper**

```rust
fn add_from_claude_settings(stmts: &mut Vec<Stmt>) -> Result<()> {
    use clash_starlark::codegen::ast::{Expr, Stmt};
    use clash_starlark::codegen::mutate;

    // Add load statement
    mutate::add_load(stmts, "@clash//claude_compat.star", &["from_claude_settings"]);

    // Wrap existing policy dict in merge(from_claude_settings(), existing_dict)
    let policy_idx = mutate::find_policy_call(stmts)
        .ok_or_else(|| anyhow::anyhow!("no policy() call found"))?;

    if let Stmt::Expr(Expr::Call { args, .. }) = &mut stmts[policy_idx] {
        if args.len() >= 2 {
            let existing_dict = args[1].clone();
            // If already a merge(), prepend from_claude_settings() as first arg
            if matches!(&existing_dict, Expr::Call { name, .. } if name == "merge") {
                if let Expr::Call { args: merge_args, .. } = &mut args[1] {
                    merge_args.insert(0, Expr::call("from_claude_settings", vec![]));
                }
            } else {
                // Wrap in merge(from_claude_settings(), existing)
                args[1] = Expr::call("merge", vec![
                    Expr::call("from_claude_settings", vec![]),
                    existing_dict,
                ]);
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 6: Test migration on a sample policy**

Create a test in `policy.rs` or a clester script:

```yaml
name: policy_migrate_when_to_dict
steps:
  - write_file:
      path: ~/.clash/policy.star
      content: |
        policy("test", rules=[when({"Bash": {"git": allow()}})])
  - run: clash policy migrate -y
  - run: clash policy validate
    expect_success: true
  - read_file:
      path: ~/.clash/policy.star
    expect_contains: "merge("
    expect_not_contains: "when("
```

- [ ] **Step 7: Commit**

```bash
git add clash/src/cli.rs clash/src/cmd/policy.rs
git commit -m "feat(cli): add clash policy migrate to convert when()/rules= to dict syntax"
```

---

### Task 9: Add `clash doctor` check for deprecated syntax

**Files:**
- Modify: `clash/src/cmd/doctor.rs`

- [ ] **Step 1: Add `check_deprecated_syntax()` diagnostic**

```rust
fn check_deprecated_syntax() -> CheckResult {
    let policy_path = match ClashSettings::policy_file() {
        Ok(p) => p.with_extension("star"),
        Err(_) => return CheckResult::Pass,
    };

    if !policy_path.exists() {
        return CheckResult::Pass;
    }

    let source = match std::fs::read_to_string(&policy_path) {
        Ok(s) => s,
        Err(_) => return CheckResult::Pass,
    };

    let has_when = source.contains("when(");
    let has_rules = source.contains("rules=") || source.contains("rules =");

    if has_when || has_rules {
        return CheckResult::Warn(format!(
            "Policy uses deprecated {} syntax. Run `clash policy migrate` to update.",
            if has_when && has_rules {
                "when() and rules="
            } else if has_when {
                "when()"
            } else {
                "rules="
            }
        ));
    }

    // Also check for missing from_claude_settings()
    if !source.contains("from_claude_settings") {
        return CheckResult::Warn(
            "Policy does not use from_claude_settings(). Run `clash policy migrate` to add dynamic Claude settings import.".to_string()
        );
    }

    CheckResult::Pass
}
```

- [ ] **Step 2: Add to check list in `run_diagnose()`**

In `run_diagnose()` (line 88-97), add:

```rust
("Policy syntax", check_deprecated_syntax()),
```

- [ ] **Step 3: Add --fix support for deprecated syntax**

In the onboarding/fix flow of doctor, when `check_deprecated_syntax` returns `Warn`, the `--fix` flag should run the migration. Check how other `--fix` cases work in doctor.rs and follow the same pattern.

- [ ] **Step 4: Run doctor**

Run: `clash doctor`
Expected: If policy uses old syntax, shows warning. If clean, passes.

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/doctor.rs
git commit -m "feat(doctor): detect deprecated when()/rules= syntax and missing from_claude_settings()"
```

---

### Task 10: Fix remaining test suite and run full CI

**Files:**
- Various test files across `clash` and `clash_starlark` crates

- [ ] **Step 1: Run full check suite**

Run: `cd /Users/eliot/code/clash && just check`
Expected: Note all failures

- [ ] **Step 2: Fix any remaining test failures**

Update any tests in `clash/src/cmd/init.rs`, `clash/src/cmd/policy.rs`, or other crates that use `when()` or `rules=` syntax. Convert them to dict syntax.

Pay special attention to:
- `clash/src/cmd/init.rs` tests (lines 630-733) — these compile sandbox policies, should still work since they use dict syntax already
- `clash_starlark/src/codegen/managed.rs` tests — updated in Task 6
- Any clester end-to-end test scripts that create policies with `when()` or `rules=`

- [ ] **Step 3: Search for when() in clester test scripts**

Search `clester/tests/scripts/` for any YAML test scripts that use `when(` in policy content. Update them to dict syntax.

- [ ] **Step 4: Run full CI**

Run: `cd /Users/eliot/code/clash && just ci`
Expected: All PASS

- [ ] **Step 5: Commit any remaining fixes**

```bash
git add -A
git commit -m "fix: update remaining tests for dict-only policy syntax"
```

---

### Task 11: Update documentation

**Files:**
- Modify: any docs that reference `when()` or `rules=` syntax
- Modify: `AGENTS.md` if policy model section needs updating

- [ ] **Step 1: Search for documentation references to when()**

Search `docs/`, `README.md`, `AGENTS.md`, and any `.md` files for `when(`, `rules=`, or examples using the old syntax.

- [ ] **Step 2: Update AGENTS.md policy model section**

The Policy Model section (line 51) has an example using `when()`:
```
{ "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
```

This is JSON IR level which is unchanged. But check if there are Starlark examples that need updating.

- [ ] **Step 3: Update any site/ documentation**

Check `site/` for policy documentation that references `when()` or `rules=`. Update examples to dict syntax with `merge()`.

- [ ] **Step 4: Commit**

```bash
git add docs/ AGENTS.md site/
git commit -m "docs: update policy examples from when()/rules= to dict syntax with merge()"
```
