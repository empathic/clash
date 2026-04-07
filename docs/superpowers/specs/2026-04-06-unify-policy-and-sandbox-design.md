# Unify `policy()` and `sandbox()` + remove `policy.json`

**Date:** 2026-04-06
**Status:** Design approved, ready for implementation plan

## Motivation

`policy()` and `sandbox()` currently have divergent surfaces. `policy()` takes a
decision-tree dict; `sandbox()` takes separate `fs=` and `net=` kwargs. The
asymmetry is historical, not principled — both are really matcher→effect maps
over different capability domains. Unifying their surface makes the DSL
smaller, easier to teach, and easier to document.

Separately, clash still supports user-authored `policy.json` as a source format
alongside `.star`. Maintaining two source formats is tech debt with no
corresponding user benefit now that `.star` is the primary format.

## Goals

1. Make `policy()` and `sandbox()` take the same shape: `(name, tree, *, ...optional kwargs)`.
2. Express a sandbox as a single decision-tree dict, the same way a policy is.
3. Enforce one uniform rule for root-level keys in any tree: **typed constructors only**.
4. Remove `policy.json` as a user-authored source format. Keep the JSON IR and
   keep `clash policy migrate` as the one-way bridge for users with legacy files.

## Non-goals

- Unifying the policy and sandbox *evaluators* internally. Shared surface,
  separate guts — the domains are semantically distinct.
- Removing Claude Code `settings.json` support (`_from_claude_settings()`).
  That reads a different file for a different purpose and is unaffected.
- Removing the JSON IR. It remains the compiled representation that `.star`
  produces and the eval layer consumes.
- Scheduling removal of `clash policy migrate`. It stays indefinitely as a
  humane offramp for users who upgrade after a long gap.

## Target API

```python
policy(name, tree, *, default="deny", default_sandbox=None, doc=None)
sandbox(name, tree, *, default="deny", doc=None)
```

- `name` and `tree` are the only required positional arguments.
- `tree` is a decision-tree dict in both cases.
- `doc` is the optional description kwarg, consistent across both.
- `default` is an optional kwarg on both, preserving today's behavior.
- `default_sandbox` remains on `policy()` only.
- `sandbox()` no longer accepts `fs=` or `net=`. These kwargs are removed
  entirely, with no deprecation shim. Existing callers get a clear error at
  parse time pointing to the new shape.

## Decision-tree shape

Both `policy()` and `sandbox()` take a flat dict whose keys are *typed
constructors*. The constructor determines the capability domain and the
grammar of what may appear below it.

### Uniform root-key rule

**At the root of any decision tree, every key must be a typed constructor.**
Bare strings are only allowed *inside* a nested dict, where the enclosing
constructor has already established the domain.

Root constructors:

- `default()` — fallback effect for the tree.
- `mode("plan")` / `mode("edit")` / ... — policy mode selector. Below: tool keys.
- `tool("Bash")` / `tool("Edit")` / ... — policy tool selector. Below: argument matchers.
- `path("$PWD")` — sandbox filesystem literal path (env-var expansion applies). Below: nested subpath dict (strings OK here).
- `glob("$HOME/**")` — sandbox filesystem glob.
- `domain("github.com")` — sandbox network domain rule.
- `localhost(port=...)` — sandbox localhost rule.

The grammar becomes self-documenting: `mode(...)` dictates "tool selector
below," `tool(...)` dictates "arguments below," `path(...)` dictates "subpath
scope below."

### Example: sandbox

```python
sandbox("rust-dev",
    {
        default(): deny(),
        path("$PWD"): allow("rwc"),
        path("$HOME"): {
            ".ssh": allow("r"),
            ".cargo": allow("rwc"),
        },
        glob("/tmp/**"): allow("rwc"),
        domain("crates.io"): allow(),
        domain("github.com"): allow(),
        localhost(8080): allow(),
    },
    doc="Build and test Rust projects with access to cargo registries.",
)
```

### Example: policy

```python
policy("default",
    {
        default(): deny(),
        mode("plan"): allow(sandbox=plan_box),
        mode("edit"): allow(sandbox=edit_box),
        tool("Bash"): {
            "git push": deny(),
            "git *": allow(),
        },
        tool("Edit"): allow(),
    },
    default_sandbox=plan_box,
    doc="Default clash policy.",
)
```

### Why typed roots

Three overlapping reasons:

1. **No hidden sub-dialects in the string keyspace.** Bare strings at the root
   would force the reader (and the parser) to disambiguate between literal
   paths, globs, hostnames, and tool names based on content sniffing. Typed
   constructors eliminate the ambiguity.
2. **Visual honesty.** Every root line announces its domain. `domain("github.com")`
   and `path("github.com")` cannot be confused at a glance. `glob("$HOME/**")`
   and `path("$HOME/bin")` cannot be confused at a glance.
3. **Deliberation.** A `glob()` grants more than a `path()`. An author who
   types `glob(...)` performs the larger grant explicitly. The small friction
   is appropriate friction.

### Nested bare strings

Inside a nested dict value, bare strings are fine:

```python
path("$HOME"): {".ssh": allow("r"), ".cargo": allow("rwc")}
```

The enclosing `path()` has established that the domain is filesystem and the
scope is `$HOME`, so nested strings are unambiguous subpath literals.

### Cultural: `doc=` is load-bearing

Every stdlib example updates to include a meaningful `doc=` on both `policy()`
and `sandbox()`. The field is not enforced, but it is culturally elevated: a
sandbox without a `doc` is a sandbox whose author has not explained themselves,
and the examples should model the expected norm.

## `policy.json` removal

### What is removed

1. **Discovery** (`clash/src/settings/discovery.rs`) — stop looking for `policy.json`.
2. **Loader** (`clash/src/policy_loader.rs`) — drop the JSON source branch. `.star` → JSON IR remains.
3. **TUI edit** (`clash/src/tui/`) — remove any "edit policy.json" affordance.
4. **`clash fmt`** (`clash/src/cmd/fmt.rs`) — drop JSON formatting.
5. **`clash policy` subcommands** (`clash/src/cmd/policy.rs`) — `show`, `validate`, `check`, `allow`, `deny`, `remove` operate on `.star` exclusively. Any JSON-writing path is deleted.
6. **`clash init`** (`clash/src/cmd/init.rs`) — scaffolds `.star` only.
7. **`ecosystem.rs`, `shell_cmd.rs`, `audit.rs`, `cmd/session.rs`, `cmd/import_settings.rs`** — targeted sweep to drop JSON source handling.
8. **Tests** — fixtures authoring `policy.json` are migrated to `.star`, or moved under the migrate test suite if they test legacy behavior.

### What stays

- **`clash policy migrate`** — the only remaining reader of legacy user
  `policy.json`. Emits new-shape `.star` with uniform typed constructors.
  No scheduled removal.
- **JSON IR** — unchanged.
- **`_from_claude_settings()`** — unrelated; reads Claude Code `settings.json`.

### User-facing error

If a user has a `policy.json` in a location where clash used to look, clash
emits a helpful pointer rather than silently skipping:

> Legacy `policy.json` detected at `<path>`. Run `clash policy migrate` to
> convert to `.star` (the only supported format).

### Documentation sweep

- `README.md`
- `docs/`
- `site/` content
- `AGENTS.md` (line 53: "Policy files use `.json` or `.star` extension" → `.star` only)

All updated to reflect `.star` as the sole source format.

## Migration

- `clash policy migrate` is updated to emit the new decision-tree shape with
  uniform typed constructors — both when converting legacy `policy.json` and
  when converting older `.star` files that used `fs=`/`net=` kwargs or bare
  string root keys.
- Stdlib examples in `examples/*.star` and `clash/src/default_policy.star` are
  rewritten by hand to the new shape and committed as part of the
  implementation.
- Clester scripts that construct policies inline are updated.

## Error messages

Two parse-time errors matter most. Both should be instructive, not punitive:

1. **Bare string at root of a tree:**
   > Root keys in a policy or sandbox tree must use a typed constructor
   > (`path(...)`, `glob(...)`, `domain(...)`, `tool(...)`, `mode(...)`,
   > `default()`). Got a bare string key `"..."`. If you meant a filesystem
   > path, use `path("...")`.

2. **`sandbox(fs=..., net=...)`:**
   > The `fs=` and `net=` arguments to `sandbox()` have been removed.
   > Sandboxes now take a single decision-tree dict, the same shape as
   > `policy()`. See `docs/sandbox.md` for the new grammar, or run
   > `clash policy migrate` to convert existing files automatically.

## Out of scope

- Changing the underlying JSON IR or the eval layer.
- Any refactor of `clash_starlark/src/when.rs` beyond what is needed to parse
  the new root-key rule and the unified sandbox tree shape.
- Any change to how sandboxes are *executed* — this is purely a source-format
  and parse-time change.
