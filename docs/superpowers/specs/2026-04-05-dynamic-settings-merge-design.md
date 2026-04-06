# Dynamic Claude Settings Import via `merge()` + Dict-Only Policy

**Date:** 2026-04-05
**Scope:** Remove `when()`/`rules=` syntax, add `merge()` for dict composition, make `from_claude_settings()` return a dict, include it in all generated policies

---

## Problem

Importing Claude Code settings into Clash is currently a one-time operation during `clash init`. If the user later changes their Claude Code permissions, Clash doesn't pick them up. The `from_claude_settings()` Starlark function (added in #427) solves the runtime read, but it returns a `list[MatchTreeNode]` designed for the `rules=` list syntax — a format that coexists awkwardly with the dict syntax that all generated policies actually use.

Meanwhile, the policy language carries two parallel syntaxes: dict-based (`policy("name", {...})`) and list-based (`policy("name", rules=[when(...), ...])`). No generated policy uses the list syntax. Removing it simplifies the language, the eval pipeline, the codegen, and the mutation logic.

---

## Design

### 1. `merge()` — Deep dict merge with shadow tracking

A new stdlib function that deep-merges policy dicts. Rightmost wins at leaf conflicts.

**Signature:**
```starlark
merge(base, override1, override2, ...) -> dict
```

**Semantics:**
- Variadic: accepts 2+ dicts
- Deep: when the same key exists in multiple dicts and both values are dicts, recurse. When both are leaves (decisions like `allow()`, `deny()`), the rightmost value wins.
- Shadow tracking: when a rightmost leaf overrides a leftmost leaf at the same key path, record the shadow in the `EvalContext` for display in `clash status`.

**Usage:**
```starlark
load("@clash//claude_compat.star", "from_claude_settings")

policy("default", merge(
    from_claude_settings(),  # lowest priority — Claude Code settings as base
    {                        # highest priority — user's rules override
        Tool("Bash"): {
            "git": {
                glob("**"): allow(sandbox=git_full)
            }
        }
    },
))
```

**Implementation in Rust (`globals.rs`):**
- Register as `_merge()` in the `#[starlark_module]` block, re-exported as `merge` via `std.star`
- Accept `args: &Arguments` for variadic positional dicts
- Walk keys recursively: if both values are dicts, recurse; otherwise rightmost wins
- On leaf conflict, push a `ShadowedRule { path: Vec<String>, winner: String, shadowed: String }` into the `EvalContext`
- Return the merged dict
- Key equality uses Starlark's built-in `==` — `Tool("Bash") == Tool("Bash")` works because these are value types with defined equality

### 2. `from_claude_settings()` returns a dict

Change the return type from `list[MatchTreeNode]` to a policy dict — the same nested `{Tool("Bash"): {"git": allow()}}` shape users write by hand.

**Parameters unchanged:** `user=True, project=True`

**Implementation (`settings_compat.rs`):**
- The existing `classify_permission()` logic stays, but instead of producing flat `MatchTreeNode` JSON blobs, build a nested Starlark dict
- Tool-only permissions: `{Tool("Read"): allow()}` 
- Bash prefix permissions: `{Tool("Bash"): {"git": {glob("**"): allow()}}}`
- File path permissions: `{Tool("Read"): {literal(".env"): deny()}}` or `{Tool("Read"): {glob("**/*.rs"): allow()}}`
- MCP tools: still skipped silently
- Merging across permission entries: permissions that share a key path merge into the same nested dict (e.g., two bash prefix rules both under `Tool("Bash")`)

### 3. Remove `when()` and `rules=` from `policy()`

**Removals:**
- `_when_impl()` in `globals.rs` — removed entirely
- `when` re-export in `std.star` — removed
- `rules` kwarg in `_policy_impl()` — removed
- `MatchTreeNode` Starlark type and the match tree builders (`_mt_node`, `_mt_condition`, `_mt_pattern`, `_mt_prefix`, `_mt_child_of`, `_mt_literal`) — these are internal plumbing for `when()` and `from_claude_settings()`, both of which are changing. Remove them.

**`policy()` simplified signature:**
```starlark
policy(name: str, dict)
```

Single positional dict argument (which can be a `merge()` result). The dict is flattened into match tree nodes internally, same as today's dict path.

**Error handling:** If a user's `.star` file uses `when()` or `rules=`, evaluation fails with a clear error message pointing to `clash policy migrate`.

### 4. Generated policies include `from_claude_settings()`

**Starter template (`default_policy.star`):**
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

**Ecosystem-generated policies (`ecosystem.rs`):** Same pattern — `merge(from_claude_settings(), {...detected rules...})`.

**Codegen changes:** `generate_policy()` wraps the dict in a `merge()` call with `from_claude_settings()` as the first (lowest priority) argument.

### 5. `clash status` shows shadowed rules

When `merge()` records shadows during eval, `clash status` displays them after the policy tree:

```
Shadowed rules (your policy overrides these Claude Code settings):
  Bash > git → allow (overridden by: deny in your policy)
```

**Implementation:**
- `EvalContext` gets a `shadows: Vec<ShadowedRule>` field
- `assemble_document()` includes shadows in the JSON output
- `clash status` reads and renders them

If there are no shadows, the section is omitted.

### 6. `clash policy allow/deny` mutation

Currently generates `when()` calls for managed rules in `.star` files. Change to generate dict entries.

**Managed section format:**
```starlark
# clash-managed rules
_clash_rule_0 = {Tool("Bash"): {"git": {"push": allow()}}}
```

**Policy call update:** Managed rules are inserted as the rightmost (highest priority) argument to `merge()`:
```starlark
policy("default", merge(
    from_claude_settings(),
    { ... user rules ... },
    _clash_rule_0,
))
```

When multiple managed rules exist, they can be individual `merge()` args or merged together — individual args is simpler for insertion and removal.

**Codegen changes (`codegen/mutate.rs`):**
- `node_json_to_expr()` → new `node_to_dict_expr()` that builds a dict literal instead of a `when()` call
- Managed variable values are dict literals
- `policy_rules_mut()` → `policy_merge_mut()` that inserts/removes idents in the `merge()` call

### 7. Migration tooling

#### `clash doctor` detection

Add a diagnostic that:
1. Reads the policy `.star` source
2. Searches for `when(` calls or `rules=` in `policy()` calls (simple text/AST scan)
3. Reports: `Policy uses deprecated when()/rules= syntax. Run "clash policy migrate" to update.`
4. With `--fix`: runs the migration automatically

#### `clash policy migrate` command

Dedicated command in `clash/src/cmd/migrate.rs` (or extend `policy.rs`):

1. **Parse** the `.star` file via tree-sitter AST (existing codegen infrastructure)
2. **Convert `when()` calls** to equivalent dict entries:
   - `when({"Bash": {"git": allow()}})` → `{Tool("Bash"): {"git": {glob("**"): allow()}}}`
   - The key mapping follows the same logic the dict parser uses in reverse
3. **Convert `rules=` list** to a `merge()` of dict entries
4. **Add `from_claude_settings()`** if not already present — as the first `merge()` arg
5. **Add `load("@clash//claude_compat.star", "from_claude_settings")`** if missing
6. **Validate** result via `clash_starlark::evaluate()`
7. **Show tree diff** (before vs after compiled policy)
8. **Prompt for confirmation** before writing

If the policy already uses dict-only syntax, the command reports "Nothing to migrate" (or just adds `from_claude_settings()` if missing).

---

## Key Files

| File | Changes |
|------|---------|
| **clash_starlark/src/globals.rs** | Add `_merge()`, remove `_when_impl()`, simplify `_policy_impl()` |
| **clash_starlark/src/eval_context.rs** | Add `ShadowedRule` struct and `shadows` vec |
| **clash_starlark/src/settings_compat.rs** | Return nested dict instead of `list[MatchTreeNode]` |
| **clash_starlark/stdlib/std.star** | Export `merge`, remove `when` |
| **clash_starlark/stdlib/claude_compat.star** | Update usage docs |
| **clash/src/default_policy.star** | Add `merge()` + `from_claude_settings()` |
| **clash/src/ecosystem.rs** | Wrap generated policy in `merge(..., from_claude_settings())` |
| **clash/src/cmd/policy.rs** | Mutation generates dict entries, not `when()` calls |
| **clash_starlark/src/codegen/mutate.rs** | Dict-based managed rule insertion into `merge()` args |
| **clash/src/cmd/doctor.rs** | Detect deprecated syntax, `--fix` migration |
| **clash/src/cmd/policy.rs** (or new `migrate.rs`) | `clash policy migrate` command |
| **clash/src/status.rs** (or `cmd/status.rs`) | Display shadowed rules section |
| **clash_starlark/src/lib.rs** | Pass shadow data through `EvalOutput` |

---

## Testing

### Unit tests
- `merge()` with non-overlapping dicts → union
- `merge()` with overlapping leaves → rightmost wins, shadows recorded
- `merge()` with nested overlapping dicts → deep merge, only leaf conflicts shadow
- `merge()` variadic with 3+ dicts → priority ordering correct
- `from_claude_settings()` returns well-formed dict for each permission type (tool, bash prefix, file path, glob)
- `policy()` rejects `rules=` kwarg with clear error
- `when()` is undefined — eval fails with helpful message

### Integration tests (clester)
- Generated starter policy compiles and includes Claude settings
- `clash policy allow "git push"` on `.star` file produces dict entry in `merge()`
- `clash policy migrate` converts a `when()`-based policy to dict syntax
- `clash status` shows shadowed rules when user overrides a Claude setting
- `clash doctor` detects old syntax and `--fix` migrates it

### Regression tests
- Empty Claude settings → `from_claude_settings()` returns empty dict, `merge()` is a no-op
- MCP tools still skipped
- Existing dict-only `.star` files continue to work unchanged

---

## Out of Scope

- **Session-level settings in `from_claude_settings()`** — the `session` parameter exists in the design spec but is `default=False` and not used in generated policies. No change needed.
- **Reverse sync** (Clash → Claude Code settings) — `from_claude_settings()` remains read-only.
- **`settings()` Starlark function** — unchanged by this work.
- **Sandbox definitions** — no changes to sandbox `.star` files.
