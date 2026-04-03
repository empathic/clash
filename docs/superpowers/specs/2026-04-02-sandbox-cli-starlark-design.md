# Sandbox CLI Starlark Support

> Fix `clash sandbox create/delete/list/add-rule/remove-rule` to work with
> Starlark policy files instead of only JSON manifests.

## Problem

The sandbox CLI commands (`clash sandbox create`, `delete`, `list`, `add-rule`,
`remove-rule`) use `read_manifest`/`write_manifest` which parse JSON. Since
Starlark is now the primary policy format, these commands fail when a `.star`
file exists.

## Solution

Route each handler based on file extension:

- **`.star` files**: Use `StarDocument::open()` → mutate API → `save()`
- **`.json` files**: Remove this and give user hint about how to convert their policy to .star
- **No policy file**: Error with "run `clash init` first"

## Changes

### New mutate functions (`clash_starlark/src/codegen/mutate.rs`)

**`add_sandbox_rule(stmts, sandbox_name, path, caps, effect, path_match)`**
- Find the `sandbox()` call with matching `name=` kwarg
- Locate the `fs=` kwarg (a dict expression)
- Add a new dict entry with the appropriate path matcher and effect
- If `fs=` doesn't exist, create it as an empty dict and add the entry

**`remove_sandbox_rule(stmts, sandbox_name, path) -> bool`**
- Find the `sandbox()` call with matching `name=` kwarg
- Locate the `fs=` kwarg dict
- Remove the dict entry whose key resolves to the given path
- Return whether anything was removed

### Updated handlers (`clash/src/sandbox_cmd.rs`)

Each handler gets a file-type dispatch:

- `handle_create` → `StarDocument::open()`, `mutate::add_sandbox()`, `doc.save()`
- `handle_delete` → `StarDocument::open()`, `mutate::remove_sandbox()`, `doc.save()`
- `handle_list_sandboxes` → `clash_starlark::evaluate()`, extract `sandboxes` from JSON
- `handle_add_rule` → `StarDocument::open()`, `mutate::add_sandbox_rule()`, `doc.save()`
- `handle_remove_rule` → `StarDocument::open()`, `mutate::remove_sandbox_rule()`, `doc.save()`

### Tests

- Unit tests in `mutate.rs` for `add_sandbox_rule` and `remove_sandbox_rule`
- Update `clester/tests/scripts/sandbox_cli.yaml` to use a Starlark policy

## Files

| File | Change |
|------|--------|
| `clash_starlark/src/codegen/mutate.rs` | Add `add_sandbox_rule()`, `remove_sandbox_rule()` |
| `clash/src/sandbox_cmd.rs` | Dispatch to StarDocument for `.star` files |
| `clester/tests/scripts/sandbox_cli.yaml` | Use `.star` policy format |
