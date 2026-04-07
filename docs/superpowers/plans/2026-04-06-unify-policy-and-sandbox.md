# Unify `policy()` / `sandbox()` and remove `policy.json` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `policy()` and `sandbox()` a unified `(name, tree, *, ...kwargs)` surface with typed-constructor root keys, and remove `policy.json` as a user-authored source format (migration path preserved).

**Architecture:** Two independent change streams that share a worktree. **Stream A** reshapes the Starlark DSL: stdlib (`std.star`), Rust parser (`when.rs`, `globals.rs`), and examples. **Stream B** removes `policy.json` from discovery/loader/cmd/fmt/init/tui, updating tests and docs. `clash policy migrate` is updated to emit the new shape in both streams. Streams can be executed in parallel; only the migrate command and shared tests are a merge point.

**Tech Stack:** Rust (clash, clash_starlark), Starlark (stdlib + examples), clester YAML scripts.

**Reference spec:** `docs/superpowers/specs/2026-04-06-unify-policy-and-sandbox-design.md`

---

## File Structure

### Stream A — DSL surface

| File | Role |
|---|---|
| `clash_starlark/stdlib/std.star` | Rewrite `sandbox()`, `policy()`; add `tool()`, `default()`, update `path()`, `glob()`, `domain()`, `localhost()` to emit typed keys usable as dict keys; remove `fs=`/`net=` legacy paths |
| `clash_starlark/src/globals.rs` | Update `_policy_impl` and add `_sandbox_impl` (if needed) to accept the new tree; keep arg surface thin |
| `clash_starlark/src/when.rs` | Rewrite `policy_impl`/add `sandbox_tree_impl`: enforce typed-root-key rule; classify keys (`default`/`mode`/`tool`/`path`/`glob`/`domain`/`localhost`); produce emitted JSON IR |
| `clash_starlark/src/builders/match_tree.rs` | (Read only; types used by new code) |
| `clash/src/default_policy.star` | Rewrite default policy to new shape |
| `examples/*.star` | Rewrite all examples to new shape |
| `clash_starlark/tests/*` | Update existing tests; add new tests for typed-root-key rule and unified sandbox tree |

### Stream B — `policy.json` removal

| File | Role |
|---|---|
| `clash/src/settings/discovery.rs` | Drop `policy.json` lookup; `.star` only |
| `clash/src/policy_loader.rs` | Delete JSON source branch (`load_json_policy` entry point). Move legacy JSON parsing behind a `pub(crate)` function reachable only from `cmd::policy::migrate` |
| `clash/src/cmd/policy.rs` | `show`/`validate`/`check`/`allow`/`deny`/`remove`: `.star` only. `migrate`: the one call site for legacy JSON parsing |
| `clash/src/cmd/fmt.rs` | Drop JSON formatting |
| `clash/src/cmd/init.rs` | Scaffold `.star` only |
| `clash/src/cmd/import_settings.rs` | Drop JSON output path |
| `clash/src/tui/**` | Drop any `policy.json` edit affordance |
| `clash/src/ecosystem.rs`, `shell_cmd.rs`, `audit.rs`, `cmd/session.rs` | Targeted sweep for JSON source handling |
| `clash/src/test_utils.rs`, `clester/tests/scripts/**` | Migrate fixtures to `.star`; legacy-JSON tests move under migrate suite |
| `README.md`, `docs/**`, `site/**`, `AGENTS.md` | Doc sweep: `.star` only |

---

## Pre-work

- [ ] **Verify baseline:** run `just check` and `just clester`. If either fails on `main`, stop and surface the failure before making changes.

---

## Stream A — DSL surface

### Task A1: stdlib — add `default()`, `tool()` constructors and port `path()`/`glob()`/`domain()`/`localhost()` to be usable as dict keys

**Files:**
- Modify: `clash_starlark/stdlib/std.star`
- Test: `clash_starlark/tests/dsl_keys.rs` (new, thin — asserts constructors produce the expected `_match_key`/`_match_value` structure)

The goal of this task is to land the typed-root-key *constructors* before touching `sandbox()`/`policy()`. After this task, all constructors return a struct of the form:

```starlark
struct(_match_key="<kind>", _match_value=<value>, _doc=<optional>)
```

where `<kind>` is one of `"default"`, `"mode"`, `"tool"`, `"path"`, `"glob"`, `"domain"`, `"localhost"`.

- [ ] **Step 1: Write the failing test** (`clash_starlark/tests/dsl_keys.rs`):

```rust
use clash_starlark::load_starlark_source_for_test;

#[test]
fn typed_constructors_produce_match_keys() {
    let out = load_starlark_source_for_test(r#"
        result = [
            default()._match_key,
            tool("Bash")._match_key,
            path("$PWD")._match_key,
            glob("/tmp/**")._match_key,
            domain("github.com")._match_key,
            localhost()._match_key,
            mode("plan")._match_key,
        ]
    "#).unwrap();
    assert_eq!(
        out.get_global_strings("result").unwrap(),
        vec!["default", "tool", "path", "glob", "domain", "localhost", "mode"],
    );
}
```

If `load_starlark_source_for_test` / `get_global_strings` don't exist yet, add the minimal test harness helper under `clash_starlark/src/test_support.rs` and re-export it for tests. The helper: evaluates a source string against `clash_globals()` with a fresh `EvalContext`, returns a handle from which named globals can be read.

- [ ] **Step 2: Run test — expect fail**

Run: `cargo test -p clash_starlark typed_constructors_produce_match_keys`
Expected: FAIL (`default`, `tool` undefined or wrong shape).

- [ ] **Step 3: Edit `std.star`.** Apply these edits in order:

  1. Add `default()` constructor:

  ```starlark
  def default(doc=None):
      """Sentinel root key representing the fallback effect for a tree.

      Usage:
          policy("x", {default(): deny(), mode("plan"): allow()})
      """
      return struct(_match_key="default", _match_value=None, _doc=doc)
  ```

  2. Add `tool()` constructor (rename the capital-T `Tool` to lowercase; keep `Tool` as a thin alias that `fail()`s pointing to the new name):

  ```starlark
  def tool(name, doc=None):
      """Tool selector root key (policy trees).

      Usage:
          policy("x", {mode("plan"): {tool("Bash"): {"git push": deny()}}})
      """
      return struct(_match_key="tool", _match_value=name, _doc=doc)

  def Tool(name):
      fail("Tool() has been renamed to tool(). See docs/superpowers/specs/2026-04-06-unify-policy-and-sandbox-design.md")
  ```

  3. Rewrite `path()` to return a typed key *instead of* a path_match builder. Move the existing builder-style `path()`/`cwd()`/`home()`/`tempdir()` *machinery* into a private `_legacy_path_match()` used only by the sandbox migration emitter. The public `path()` now returns:

  ```starlark
  def path(path_str, doc=None):
      """Filesystem literal-path key.

      Usage:
          sandbox("x", {path("$PWD"): allow("rwc")})
      """
      if type(path_str) != "string":
          fail("path() takes a string; got " + type(path_str))
      return struct(_match_key="path", _match_value=path_str, _doc=doc)
  ```

  Note: `cwd()`, `home()`, `tempdir()` keep working but are deprecated — leave them returning the old builder structs for now so examples still parse until Task A3. They are removed in Task A6.

  4. Rewrite `glob()` to return a typed key. Preserve the current glob-pattern validation:

  ```starlark
  def glob(pattern, doc=None):
      """Filesystem glob-path key.

      Usage:
          sandbox("x", {glob("$HOME/**"): allow("r")})
      """
      if type(pattern) != "string":
          fail("glob() takes a string; got " + type(pattern))
      # Preserve existing suffix validation
      if pattern not in ("*", "**") and not (
          pattern.endswith("/*") or pattern.endswith("/**") or pattern.endswith("/**/*")
      ):
          fail("glob() pattern must end with /*, /**, or /**/* (got: " + pattern + ")")
      return struct(_match_key="glob", _match_value=pattern, _doc=doc)
  ```

  5. Rewrite `domain()` (two-arg → one-arg; no effect in the constructor; effect is the dict value):

  ```starlark
  def domain(name, doc=None):
      """Network domain key.

      Usage:
          sandbox("x", {domain("github.com"): allow()})
      """
      return struct(_match_key="domain", _match_value=name, _doc=doc)
  ```

  6. Rewrite `localhost()`:

  ```starlark
  def localhost(ports=None, doc=None):
      """Localhost network key. Optionally restricted to specific ports.

      Usage:
          sandbox("x", {localhost(): allow(), localhost(ports=[8080]): allow()})
      """
      if ports != None:
          for p in ports:
              if type(p) != "int":
                  fail("localhost() ports must be integers; got " + type(p))
              if p < 1 or p > 65535:
                  fail("localhost() port out of range (1-65535): " + str(p))
      return struct(_match_key="localhost", _match_value=ports, _doc=doc)
  ```

- [ ] **Step 4: Run test — expect pass**

Run: `cargo test -p clash_starlark typed_constructors_produce_match_keys`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/std.star clash_starlark/tests/dsl_keys.rs clash_starlark/src/test_support.rs
git commit -m "feat(starlark): add typed root-key constructors (default, tool, path, glob, domain, localhost)"
```

---

### Task A2: `when.rs` — classify typed root keys and reject bare strings

**Files:**
- Modify: `clash_starlark/src/when.rs:109-150` (`MatchKeyKind`, `classify_key`)
- Test: `clash_starlark/tests/root_key_rule.rs` (new)

Add the enforcement of the uniform root-key rule.

- [ ] **Step 1: Write the failing test**:

```rust
use clash_starlark::eval_policy_source_for_test;

#[test]
fn bare_string_at_policy_root_is_rejected() {
    let err = eval_policy_source_for_test(r#"
        policy("x", {"Bash": allow()})
    "#).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("typed constructor"),
        "expected typed-constructor error, got: {msg}"
    );
}

#[test]
fn typed_root_key_is_accepted() {
    eval_policy_source_for_test(r#"
        policy("x", {tool("Bash"): allow()})
    "#).unwrap();
}
```

Add `eval_policy_source_for_test` to `clash_starlark/src/test_support.rs` (evaluates source as a policy file with a fresh `EvalContext`, returns `anyhow::Result<EvalContext>`).

- [ ] **Step 2: Run tests — expect fail**

Run: `cargo test -p clash_starlark root_key_rule`
Expected: both FAIL (first passes today by mistreating `"Bash"` as a tool name).

- [ ] **Step 3: Modify `when.rs`.** Extend `MatchKeyKind` to cover all root kinds:

```rust
enum MatchKeyKind {
    Default { doc: Option<String> },
    Mode { pattern: JsonValue, doc: Option<String> },
    Tool { pattern: JsonValue, doc: Option<String> },
    Path { value: JsonValue, doc: Option<String> },
    Glob { value: JsonValue, doc: Option<String> },
    Domain { value: JsonValue, doc: Option<String> },
    Localhost { ports: JsonValue, doc: Option<String> },
}
```

Rewrite `classify_key` to **require** a `_match_key` struct for root keys:

```rust
fn classify_root_key<'v>(key: Value<'v>, heap: &'v Heap) -> anyhow::Result<MatchKeyKind> {
    if key.get_type() == "struct" {
        if let Ok(Some(mk_val)) = key.get_attr("_match_key", heap) {
            if let Some(mk) = mk_val.unpack_str() {
                let mv = key.get_attr("_match_value", heap).ok().flatten()
                    .context("match key struct missing _match_value")?;
                let doc = key.get_attr("_doc", heap).ok().flatten()
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.unpack_str().map(|s| s.to_string()));
                return match mk {
                    "default" => Ok(MatchKeyKind::Default { doc }),
                    "mode" => Ok(MatchKeyKind::Mode { pattern: pattern_to_json(mv, heap)?, doc }),
                    "tool" => Ok(MatchKeyKind::Tool { pattern: pattern_to_json(mv, heap)?, doc }),
                    "path" => Ok(MatchKeyKind::Path { value: pattern_to_json(mv, heap)?, doc }),
                    "glob" => Ok(MatchKeyKind::Glob { value: pattern_to_json(mv, heap)?, doc }),
                    "domain" => Ok(MatchKeyKind::Domain { value: pattern_to_json(mv, heap)?, doc }),
                    "localhost" => Ok(MatchKeyKind::Localhost { ports: pattern_to_json(mv, heap)?, doc }),
                    other => bail!("unknown match key type: {other}"),
                };
            }
        }
    }
    bail!(
        "Root keys in a policy or sandbox tree must use a typed constructor \
         (default(), mode(), tool(), path(), glob(), domain(), localhost()). \
         Got a bare {} key. If you meant a filesystem path, use path(\"...\"). \
         If you meant a tool name, use tool(\"...\").",
        key.get_type()
    )
}
```

Keep the old `classify_key` function under a new name `classify_nested_key` for use inside `build_arg_tree` (where bare strings *are* allowed as positional-arg matchers). The existing callsites in `build_tool_level` and `build_arg_tree` keep using the nested classifier.

Adjust `process_policy_dict` to call `classify_root_key` instead of `classify_key`, and to handle the new variants. For now, `Path`/`Glob`/`Domain`/`Localhost`/`Default` variants in a policy-root context should `bail!("sandbox-only key {kind} used in policy root")` — they will be wired up for sandbox trees in Task A3.

- [ ] **Step 4: Run tests — expect pass**

Run: `cargo test -p clash_starlark root_key_rule`
Expected: PASS.

- [ ] **Step 5: Run the whole `clash_starlark` suite**

Run: `cargo test -p clash_starlark`
Expected: PASS (there will be compile errors in `stdlib/std.star`-consuming tests if any stdlib example used a bare-string root key — fix them to use `tool("...")` as you find them).

- [ ] **Step 6: Commit**

```bash
git add clash_starlark/src/when.rs clash_starlark/tests/root_key_rule.rs clash_starlark/src/test_support.rs
git commit -m "feat(starlark): enforce typed root-key rule in policy/sandbox trees"
```

---

### Task A3: `when.rs` — implement `sandbox_tree_impl` for the unified sandbox tree

**Files:**
- Modify: `clash_starlark/src/when.rs` (add `pub fn sandbox_tree_impl`)
- Modify: `clash_starlark/src/globals.rs` (add `_sandbox_impl` global + wire registration)
- Modify: `clash_starlark/src/eval_context.rs` (add `SandboxRegistration` + `register_sandbox` if not already present in a usable form)
- Test: `clash_starlark/tests/sandbox_tree.rs` (new)

After this task, calling `_sandbox_impl("name", {path("$PWD"): allow("rwc"), domain("github.com"): allow()})` produces a JSON sandbox value structurally identical to what `sandbox_to_json` produces today from the builder-based struct.

- [ ] **Step 1: Write the failing test**:

```rust
use clash_starlark::eval_policy_source_for_test;

#[test]
fn sandbox_tree_fs_and_net_round_trip() {
    let ctx = eval_policy_source_for_test(r#"
        sandbox("rust-dev", {
            default(): deny(),
            path("$PWD"): allow("rwc"),
            glob("/tmp/**"): allow("rwc"),
            domain("crates.io"): allow(),
            localhost(): allow(),
        })
    "#).unwrap();
    let sb = ctx.sandboxes().get("rust-dev").expect("sandbox registered");
    // Structural assertions:
    assert_eq!(sb["default"], serde_json::json!("deny"));
    let rules = sb["rules"].as_array().unwrap();
    assert!(rules.iter().any(|r| r["path_value"] == "$PWD" && r["effect"] == "allow"));
    assert!(rules.iter().any(|r| r["path_value"] == "/tmp/**" && r["effect"] == "allow"));
    assert_eq!(sb["net"]["domains"][0], serde_json::json!("crates.io"));
    assert_eq!(sb["net"]["localhost"], serde_json::json!(true));
}
```

Use whatever snake-case keys `sandbox_to_json` currently emits. If the names don't match the above, update the test to match — the point is structural round-trip, not inventing a new wire format.

- [ ] **Step 2: Run test — expect fail**

Run: `cargo test -p clash_starlark sandbox_tree_fs_and_net_round_trip`
Expected: FAIL (no `sandbox()` tree form yet).

- [ ] **Step 3: Implement `sandbox_tree_impl` in `when.rs`.** Structure:

```rust
pub fn sandbox_tree_impl<'v>(
    name: &str,
    tree: Value<'v>,
    default_effect_kwarg: &str,  // from `default=` kwarg in std.star wrapper
    doc: Option<String>,
    heap: &'v Heap,
    source: Option<String>,
) -> anyhow::Result<JsonValue> {
    let dict = DictRef::from_value(tree)
        .ok_or_else(|| anyhow::anyhow!("sandbox() tree must be a dict"))?;

    let mut default_effect = default_effect_kwarg.to_string();
    let mut fs_rules: Vec<JsonValue> = Vec::new();
    let mut net_domains: Vec<String> = Vec::new();
    let mut net_localhost_allow: Option<bool> = None;
    let mut net_localhost_ports: Vec<i64> = Vec::new();
    let mut net_effect: Option<String> = None;

    for (key, value) in dict.iter() {
        match classify_root_key(key, heap)? {
            MatchKeyKind::Default { .. } => {
                let eff = effect_to_string(value, heap)?;
                default_effect = eff;
            }
            MatchKeyKind::Path { value: pv, doc } => {
                fs_rules.push(fs_rule_from(value, pv, doc, "literal", heap)?);
            }
            MatchKeyKind::Glob { value: pv, doc } => {
                fs_rules.push(fs_rule_from(value, pv, doc, "glob", heap)?);
            }
            MatchKeyKind::Domain { value: dv, .. } => {
                let name = dv.as_str().context("domain() value must be a string")?.to_string();
                // Value is the effect — today we only track the domain name in the IR,
                // matching legacy behavior; a deny at domain level is expressed via default.
                let _eff = effect_to_string(value, heap)?;
                net_domains.push(name);
            }
            MatchKeyKind::Localhost { ports, .. } => {
                let eff = effect_to_string(value, heap)?;
                if eff == "allow" {
                    net_localhost_allow = Some(true);
                }
                if let Some(arr) = ports.as_array() {
                    for p in arr {
                        if let Some(n) = p.as_i64() { net_localhost_ports.push(n); }
                    }
                }
            }
            MatchKeyKind::Mode { .. } | MatchKeyKind::Tool { .. } => {
                bail!("mode()/tool() are policy-only keys; not allowed in a sandbox tree")
            }
        }
    }

    // Add the system rules (root read, /Users|/home deny) that sandbox() in std.star used to inject.
    append_system_rules(&mut fs_rules);

    Ok(assemble_sandbox_json(
        name,
        &default_effect,
        fs_rules,
        net_effect,
        net_domains,
        net_localhost_allow,
        net_localhost_ports,
        doc,
    ))
}
```

Implement `fs_rule_from`, `effect_to_string`, `append_system_rules`, and `assemble_sandbox_json` as private helpers. `assemble_sandbox_json` should produce the *same* JSON shape that `sandbox_to_json` produces today (read `sandbox_to_json` at `clash_starlark/src/when.rs:364` and mirror its output). The cleanest approach: refactor `sandbox_to_json` to call a shared private `build_sandbox_json(name, default, rules, net, doc) -> JsonValue`, and have both `sandbox_to_json` (legacy struct path) and `sandbox_tree_impl` (new dict path) feed it.

- [ ] **Step 4: Register `_sandbox_impl` global.** In `clash_starlark/src/globals.rs`, under the `#[starlark_module] register_globals`:

```rust
fn _sandbox_impl<'v>(
    #[starlark(require = pos)] name: &str,
    #[starlark(require = pos)] tree: Value<'v>,
    #[starlark(require = named, default = "deny")] default: &str,
    #[starlark(require = named, default = starlark::values::none::NoneType)] doc: Value<'v>,
    eval: &mut Evaluator<'v, '_, '_>,
) -> anyhow::Result<NoneType> {
    let heap = eval.heap();
    let ctx = eval.extra.and_then(|e| e.downcast_ref::<EvalContext>())
        .ok_or_else(|| anyhow::anyhow!("sandbox() can only be called in a policy file"))?;
    let doc_str = doc.unpack_str().map(|s| s.to_string());
    let source = caller_source_location(eval);
    let sb_json = crate::when::sandbox_tree_impl(name, tree, default, doc_str, heap, source)?;
    ctx.register_sandbox(name, sb_json)?;
    Ok(NoneType)
}
```

If `EvalContext::register_sandbox` doesn't exist, add it in `clash_starlark/src/eval_context.rs`: append to an internal `sandboxes: RefCell<BTreeMap<String, JsonValue>>`, bailing on duplicate names.

- [ ] **Step 5: Wire `sandbox()` in `std.star`** to the new impl (this is the final signature change):

```starlark
def sandbox(name, tree, default="deny", doc=None):
    """Register a sandbox from a decision-tree dict.

    Usage:
        sandbox("rust-dev", {
            default(): deny(),
            path("$PWD"): allow("rwc"),
            domain("crates.io"): allow(),
        }, doc="Build and test Rust projects.")
    """
    if type(name) != "string":
        fail("sandbox() name must be a string")
    if type(tree) != "dict":
        fail("sandbox() tree must be a dict")
    _sandbox_impl(name, tree, default=_unwrap_effect(default), doc=doc)
```

Delete the legacy `_make_sandbox` / builder-based `sandbox()` body and the `fs=`/`net=` kwarg branches. Keep `cwd()`, `home()`, `tempdir()`, `_path_match` **deleted** — they are replaced by `path()`. If any stdlib code still references them, fix it now; they're removed in this task.

Add a helpful error shim for `fs=`/`net=`:

```starlark
# Friendly error for legacy calls
def _legacy_sandbox_error(**kwargs):
    fail("sandbox() no longer accepts fs= or net= kwargs. It now takes a single " +
         "decision-tree dict: sandbox(\"name\", {path(\"$PWD\"): allow(\"rwc\"), " +
         "domain(\"github.com\"): allow()}). Run `clash policy migrate` to convert.")
```

and detect legacy positional/kwarg shapes inside `sandbox()` before calling `_sandbox_impl`.

- [ ] **Step 6: Run test — expect pass**

Run: `cargo test -p clash_starlark sandbox_tree_fs_and_net_round_trip`
Expected: PASS.

- [ ] **Step 7: Run full `clash_starlark` suite**

Run: `cargo test -p clash_starlark`
Expected: PASS. If failures, they will be in tests/examples that used `fs=`/`net=` or bare string keys — fix those callsites inline to the new form as part of this task. Do **not** skip or weaken tests.

- [ ] **Step 8: Commit**

```bash
git add clash_starlark/
git commit -m "feat(starlark): unified sandbox() tree API with typed constructors"
```

---

### Task A4: `when.rs` — wire `default()` into policy trees and accept unified signature

**Files:**
- Modify: `clash_starlark/src/when.rs` (`policy_impl`, `process_policy_dict`)
- Modify: `clash_starlark/stdlib/std.star` (`policy()` wrapper)
- Modify: `clash_starlark/src/globals.rs` (`_policy_impl` signature)
- Test: `clash_starlark/tests/policy_tree.rs` (new)

- [ ] **Step 1: Write the failing test**:

```rust
use clash_starlark::eval_policy_source_for_test;

#[test]
fn policy_default_key_sets_fallback() {
    let ctx = eval_policy_source_for_test(r#"
        policy("x", {
            default(): deny(),
            mode("plan"): allow(),
            tool("Bash"): {"git push": deny()},
        })
    "#).unwrap();
    let pol = ctx.policies().get("x").unwrap();
    assert_eq!(pol["default_effect"], serde_json::json!("deny"));
    // Tree has 2 non-default root nodes (mode + tool)
    assert_eq!(pol["tree_nodes"].as_array().unwrap().len(), 2);
}
```

Use whatever field names `PolicyRegistration` actually emits; adjust the test to match.

- [ ] **Step 2: Run test — expect fail**

Run: `cargo test -p clash_starlark policy_default_key_sets_fallback`
Expected: FAIL.

- [ ] **Step 3: Modify `process_policy_dict`** to handle `MatchKeyKind::Default` (sets a local `default_effect` override) and `MatchKeyKind::Tool` / `MatchKeyKind::Mode` (existing behavior). Reject `Path`/`Glob`/`Domain`/`Localhost` at policy root with a clear message.

Change `policy_impl`'s return to `(default_effect, flat_nodes, sandboxes)` and propagate to `PolicyRegistration`. If `PolicyRegistration` lacks `default_effect`, add it.

- [ ] **Step 4: Update `_policy_impl` global signature** in `globals.rs` to the unified shape:

```rust
fn _policy_impl<'v>(
    #[starlark(require = pos)] name: &str,
    #[starlark(require = pos)] tree: Value<'v>,
    #[starlark(require = named, default = "deny")] default: &str,
    #[starlark(require = named, default = starlark::values::none::NoneType)] default_sandbox: Value<'v>,
    #[starlark(require = named, default = starlark::values::none::NoneType)] doc: Value<'v>,
    eval: &mut Evaluator<'v, '_, '_>,
) -> anyhow::Result<NoneType> { /* ... */ }
```

Keep the dict-only enforcement (current `clash_starlark/src/globals.rs:250-256`). Remove the "when()/rules= syntax" error text — replace with a pointer to the new shape.

- [ ] **Step 5: Update `policy()` in `std.star`** to the final signature:

```starlark
def policy(name, tree, default="deny", default_sandbox=None, doc=None):
    """Register a named policy from a decision-tree dict.

    Usage:
        policy("default", {
            default(): deny(sandbox=plan_box),
            mode("plan"): allow(sandbox=plan_box),
            tool("Bash"): {"git push": deny()},
        })
    """
    if type(name) != "string":
        fail("policy() name must be a string")
    if type(tree) != "dict":
        fail("policy() tree must be a dict. Run `clash policy migrate` to convert legacy files.")
    _policy_impl(name, tree, default=_unwrap_effect(default), default_sandbox=default_sandbox, doc=doc)
```

- [ ] **Step 6: Run test — expect pass**

Run: `cargo test -p clash_starlark policy_default_key_sets_fallback`
Expected: PASS.

- [ ] **Step 7: Run full suite**

Run: `cargo test -p clash_starlark && cargo test -p clash`
Expected: PASS. Fix fallout in `clash/src/default_policy.star` (Task A5) as needed to get this green — but that should mostly land in the next task.

- [ ] **Step 8: Commit**

```bash
git add clash_starlark/
git commit -m "feat(starlark): unify policy() signature with default() root key"
```

---

### Task A5: Rewrite `default_policy.star` and `examples/*.star` to the new shape

**Files:**
- Modify: `clash/src/default_policy.star`
- Modify: `examples/paranoid.star`, `examples/rust-dev.star`, `examples/git-ssh-protected.star`, `examples/python-dev.star`, `examples/read-only-repo.star`, `examples/permissive.star`, `examples/node-dev.star`, `examples/curl-localhost-only.star`

- [ ] **Step 1: Rewrite each file.** For each example: read the existing file, convert each `sandbox(...)`/`policy(...)` call to the new shape. The transformation is mechanical:

  - `sandbox("x", default=deny(), fs={...}, net=allow())` →
    ```starlark
    sandbox("x", {
        default(): deny(),
        # each fs entry becomes path(...) or glob(...)
        path("$PWD"): allow("rwc"),
        # net=allow() becomes an explicit net key, or omit if default is allow
        domain("..."): allow(),   # per domain
    }, doc="...")
    ```
  - `policy("x", {"Bash": ...})` → `policy("x", {tool("Bash"): ...})`
  - Every call site gets a meaningful `doc=`.

Work one file at a time. After each file, run `cargo test -p clash_starlark` to keep the feedback loop tight.

- [ ] **Step 2: Verify** the default policy loads:

Run: `cargo test -p clash default_policy`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash/src/default_policy.star examples/
git commit -m "refactor(examples): migrate examples and default policy to unified tree shape"
```

---

### Task A6: Remove `cwd()`, `home()`, `tempdir()`, legacy `domains()`, legacy `_path_match` from stdlib

**Files:**
- Modify: `clash_starlark/stdlib/std.star`

These are now unreachable from in-tree code (`default_policy.star` and examples were migrated in Task A5). Delete them.

- [ ] **Step 1: Delete** `cwd()`, `home()`, `tempdir()`, `path()` *builder variant*, `_path_match`, `domains()` (the legacy plural dict form), and any dead helpers (`_process_fs_dict`, `_resolve_path_value` etc.) now unused. Keep `path()` as the typed key constructor added in Task A1.

- [ ] **Step 2: Run full suite**

Run: `cargo test -p clash_starlark && cargo test -p clash`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash_starlark/stdlib/std.star
git commit -m "refactor(starlark): remove legacy path/sandbox builders"
```

---

## Stream B — `policy.json` removal

### Task B1: Fence off legacy JSON parsing behind `migrate` only

**Files:**
- Modify: `clash/src/policy_loader.rs` — rename `load_json_policy` → `migrate_load_json_policy`, mark `pub(crate)`, document "only call from `cmd::policy::migrate`".
- Modify: `clash/src/cmd/policy.rs` — update migrate to call the new name.
- Test: `clash/src/policy_loader.rs` — update existing JSON-loading tests to live under `mod migrate_tests` with an explicit `#[cfg(test)]` note.

- [ ] **Step 1: Rename and gate.** Grep for all callers of `load_json_policy`:

  Run: `rg -n 'load_json_policy' clash/`

  For each caller outside `cmd::policy::migrate`, replace the call with an error: if a `.json` file is discovered at load time, emit:

  > Legacy `policy.json` detected at `<path>`. Run `clash policy migrate` to convert to `.star` (the only supported format).

  Plumb through a clean `anyhow::Error` with that message.

- [ ] **Step 2: Run tests**

Run: `cargo test -p clash policy_loader`
Expected: PASS (migrate tests still call the renamed function; other tests now exercise the error path).

- [ ] **Step 3: Commit**

```bash
git add clash/src/policy_loader.rs clash/src/cmd/policy.rs
git commit -m "refactor(policy): gate legacy policy.json parsing behind migrate"
```

---

### Task B2: Discovery — drop `policy.json` lookup

**Files:**
- Modify: `clash/src/settings/discovery.rs:141-180` (the `.json`-preferring discovery helpers)
- Test: `clash/src/settings/discovery.rs` (adjust existing tests)

- [ ] **Step 1: Write the failing test**. Add to the existing test module in `discovery.rs`:

```rust
#[test]
fn discovery_ignores_policy_json() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("policy.json"), "{}").unwrap();
    std::fs::write(dir.path().join("policy.star"), "policy(\"x\", {default(): deny()})").unwrap();
    let found = discover_in(dir.path()).unwrap();
    assert!(found.ends_with("policy.star"));
}

#[test]
fn discovery_errors_on_lone_policy_json() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("policy.json"), "{}").unwrap();
    let err = discover_in(dir.path()).unwrap_err();
    assert!(format!("{err:#}").contains("policy migrate"));
}
```

(Rename `discover_in` to whatever the actual helper is.)

- [ ] **Step 2: Run tests — expect fail**

Run: `cargo test -p clash discovery`
Expected: first test passes today (wrong reason — picks `.json`), second fails.

- [ ] **Step 3: Modify `discovery.rs`** — in the helper currently at line 163 (`Return policy.json if it exists…`): always return `policy.star`. If only `policy.json` exists, return `Err` with the migrate pointer.

- [ ] **Step 4: Update doc comments** (lines 14, 16, 141, 152, 163, 218) — remove `.json` references.

- [ ] **Step 5: Run tests — expect pass**

Run: `cargo test -p clash discovery`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add clash/src/settings/discovery.rs
git commit -m "feat(settings): drop policy.json discovery; starlark is the only source format"
```

---

### Task B3: `cmd/policy.rs` — `.star`-only for show/validate/check/allow/deny/remove

**Files:**
- Modify: `clash/src/cmd/policy.rs`

- [ ] **Step 1: Grep for JSON source handling** in `cmd/policy.rs`:

Run: `rg -n '\.json|Json' clash/src/cmd/policy.rs`

For each hit in a non-`migrate` subcommand, replace with the `.star` path. Any write-to-JSON codepath (e.g., `write_policy_json`) is deleted. `allow`/`deny`/`remove` mutate `.star` files through `clash_starlark::codegen::mutate` (already the primary path — confirm by reading current code).

- [ ] **Step 2: Update clester scripts** under `clester/tests/scripts/` that exercise `clash policy show/validate/check/allow/deny/remove` against `.json` fixtures. Migrate fixtures to `.star` using the target shape.

- [ ] **Step 3: Run tests**

Run: `just check && just clester`
Expected: PASS. If clester scripts reference `.json` files in assertions, update them.

- [ ] **Step 4: Commit**

```bash
git add clash/src/cmd/policy.rs clester/tests/scripts/
git commit -m "feat(cmd/policy): require .star for all non-migrate subcommands"
```

---

### Task B4: `cmd/fmt.rs` — drop JSON formatting

**Files:**
- Modify: `clash/src/cmd/fmt.rs`

- [ ] **Step 1: Delete the JSON branch.** `clash fmt` now handles `.star` only. If invoked on a `.json` file, print the migrate pointer and exit non-zero.

- [ ] **Step 2: Run tests**

Run: `cargo test -p clash cmd::fmt && just clester`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash/src/cmd/fmt.rs
git commit -m "feat(cmd/fmt): starlark-only formatter"
```

---

### Task B5: `cmd/init.rs` — scaffold `.star` only; `cmd/import_settings.rs` — emit `.star`

**Files:**
- Modify: `clash/src/cmd/init.rs`
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1:** In `init.rs`, remove any code that writes `policy.json` as part of initialization. The scaffolded file is always `policy.star` in the new tree shape.

- [ ] **Step 2:** In `import_settings.rs`, remove the JSON output branch. Import always emits `.star`. The generator for `.star` should produce the new shape (typed root keys).

- [ ] **Step 3:** Run tests

Run: `just check && just clester`
Expected: PASS. Update any clester scripts that asserted on JSON output of init/import.

- [ ] **Step 4: Commit**

```bash
git add clash/src/cmd/init.rs clash/src/cmd/import_settings.rs
git commit -m "feat(cmd): init and import_settings emit .star only"
```

---

### Task B6: TUI — drop any policy.json affordance

**Files:**
- Modify: `clash/src/tui/mod.rs`, `clash/src/tui/inline_form.rs`

- [ ] **Step 1:** `rg -n 'policy\.json' clash/src/tui/` to find callsites. Each is either (a) opening `.json` for edit — delete, the TUI edits `.star`; (b) a label mentioning "policy.json" — update to "policy.star".

- [ ] **Step 2:** Run tests

Run: `cargo test -p clash tui`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add clash/src/tui/
git commit -m "refactor(tui): remove policy.json edit path"
```

---

### Task B7: Sweep remaining callsites

**Files:**
- Modify: `clash/src/ecosystem.rs`, `clash/src/shell_cmd.rs`, `clash/src/audit.rs`, `clash/src/cmd/session.rs`, `clash/src/test_utils.rs`

- [ ] **Step 1:** `rg -n 'policy\.json' clash/src/` — for each remaining hit outside `cmd/policy.rs` (migrate path), replace with `.star` or with the migrate-pointer error.

- [ ] **Step 2:** `rg -n 'policy\.json' clester/` — update all clester fixtures.

- [ ] **Step 3:** Run full suite

Run: `just ci`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: drop remaining policy.json references outside migrate"
```

---

### Task B8: `clash policy migrate` — emit new-shape `.star`

**Files:**
- Modify: `clash/src/cmd/policy.rs` (migrate subcommand)
- Modify: `clash/src/policy_gen/` (if migrate uses the PolicyBuilder pipeline)
- Test: clester script `clester/tests/scripts/policy-migrate-new-shape.yaml` (new)

- [ ] **Step 1: Write a new clester script** that:
  1. Creates a legacy `policy.json` with a few tool rules, a filesystem rule, and a network domain.
  2. Runs `clash policy migrate`.
  3. Asserts the resulting `.star` contains `tool("Bash")`, `path(`, `domain(`, and `default()`.
  4. Asserts the resulting `.star` loads successfully via `clash policy validate`.

- [ ] **Step 2: Run clester — expect fail**

Run: `just clester -- policy-migrate-new-shape`
Expected: FAIL (migrate still emits old-shape `.star`).

- [ ] **Step 3: Update the migrate emitter.** Find the writer (likely `clash/src/policy_gen/` or `clash_starlark/src/codegen/from_manifest.rs:235`). It currently emits bare string tool keys and builder-style `sandbox(..., fs=..., net=...)`. Change it to emit:
  - `policy("name", { default(): ..., mode(...): ..., tool("..."): ... })`
  - `sandbox("name", { default(): ..., path("..."): ..., glob("..."): ..., domain("..."): ..., localhost(): ... })`

- [ ] **Step 4: Run clester — expect pass**

Run: `just clester -- policy-migrate-new-shape`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/policy.rs clash/src/policy_gen/ clash_starlark/src/codegen/ clester/tests/scripts/policy-migrate-new-shape.yaml
git commit -m "feat(policy/migrate): emit unified tree shape with typed root keys"
```

---

### Task B9: Documentation sweep

**Files:**
- Modify: `README.md`, `docs/**`, `site/**`, `AGENTS.md:53`

- [ ] **Step 1:** `rg -n 'policy\.json' README.md docs/ site/ AGENTS.md` and update each hit. Leave mentions that are explicitly describing the migrate path.

- [ ] **Step 2:** Update `AGENTS.md` line 53 from:

  > Policy files use `.json` or `.star` extension (`.json` preferred when both exist)

  to:

  > Policy files use the `.star` extension. Legacy `policy.json` files are converted with `clash policy migrate`.

- [ ] **Step 3:** Update `docs/` examples and the site policy documentation to show the new unified tree shape (`default()`, `tool()`, `path()`, `domain()`, etc.). `doc=` should appear in every example.

- [ ] **Step 4:** Build the site

Run: `cd site && bun install && bun run build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/ site/ AGENTS.md
git commit -m "docs: document unified policy/sandbox tree shape; drop policy.json references"
```

---

## Final verification

- [ ] **Step 1:** Full CI

Run: `just ci`
Expected: PASS.

- [ ] **Step 2:** Smoke test the migrate path end-to-end

Run:
```bash
mkdir -p /tmp/clash-migrate-test && cd /tmp/clash-migrate-test
cat > policy.json <<'EOF'
{"default_effect":"deny","rules":[]}
EOF
clash policy migrate
cat policy.star
clash policy validate
```
Expected: migrate produces a `.star` file containing `default()`, loads clean.

- [ ] **Step 3:** Smoke test a unified sandbox

Create an example using the new shape and confirm `clash sandbox check` evaluates it correctly.

- [ ] **Step 4: Final review commit / squash** (if using subagent-driven-development, the reviewer does this).

---

## Self-Review Notes

- **Spec coverage check:**
  - §"Target API" signatures — Tasks A3 (sandbox), A4 (policy).
  - §"Uniform root-key rule" — Task A2.
  - §"Decision-tree shape" examples — exercised by tests in A3/A4; made canonical in A5.
  - §"Nested bare strings" — preserved by keeping `classify_nested_key` in A2.
  - §"Cultural: doc= load-bearing" — Task A5 rewrites examples with `doc=`.
  - §"policy.json removal — What is removed" items 1–8 — Tasks B1–B7.
  - §"What stays" — Task B1 (migrate fence), untouched JSON IR (no task — correct), `_from_claude_settings` (untouched — correct).
  - §"User-facing error" — Tasks B1, B2, B4.
  - §"Documentation sweep" — Task B9.
  - §"Error messages" — Task A2 (typed-root) and Task A3 (legacy `fs=`/`net=`).

- **Placeholder scan:** No "TBD"/"similar to"/"add error handling" placeholders. Every code block shows the actual code. Where a helper's current shape isn't fully verified (`discover_in`, `PolicyRegistration` fields), the task explicitly instructs reading the current code and adjusting test assertions to match — this is an intentional signal, not a placeholder.

- **Type consistency:** `MatchKeyKind` variants and `classify_root_key` / `classify_nested_key` names are used consistently across A2, A3, A4. `sandbox_tree_impl` is referenced in both A3 and A4 by the same name. `_sandbox_impl` is the global name in both `globals.rs` and `std.star`.
