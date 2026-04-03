# Import-Based Onboarding Design

> Redesign `clash init` to import permissions from the user's existing coding agent
> configuration (starting with Claude Code) and generate a matching Clash policy
> with sandbox enforcement.

## Motivation

The current `clash init` writes a hardcoded starter policy that doesn't reflect
the user's existing permissions. Users who have already configured Claude Code's
allow/deny/ask rules must manually recreate those rules in Clash's Starlark DSL.
This friction slows adoption and leads to a worse first experience.

## CLI Changes

### New default: `clash init` imports settings

`clash init` (with no flags) now imports by default:

1. Detect agent (prompt if not specified via `--agent`)
2. Read the agent's effective (merged) settings
3. If meaningful permissions exist → translate to Clash policy, write it, install
   hooks, print summary
4. If no meaningful permissions (empty lists or `bypass_permissions: true`) →
   prompt user to pick a posture (strict/balanced/permissive), generate policy
   from that, install hooks, print summary

No TUI editor is launched in any path.

### `clash init --no-import`

Skips policy generation entirely:

1. Install agent hooks/plugin
2. Print: "Run `clash policy edit` to configure your policy."
3. Exit

### `clash init --from-trace <PATH>`

Unchanged — continues to work as before.

## Sandbox Preset Renames

The stdlib sandbox presets in `sandboxes.star` are renamed for clarity:

| Old Name    | New Name       | Description                                              |
|-------------|----------------|----------------------------------------------------------|
| `plan`      | `readonly`     | Read-only project access, no writes, network allowed     |
| `edit`      | `project`      | R/W project + tmpdir + ~/.claude, no network             |
| `safe_yolo` | `workspace`    | Full home directory access, deny sensitive dirs           |
| `yolo`      | `unrestricted` | All capabilities, all network                            |

Definitions stay the same — only names and exported symbols change.

### Ripple effects

- `default_policy.star` — update sandbox references
- `from_trace.rs` — rename `_fs_box` → `project_files`, update sandbox loads
- `examples/*.star` — update references
- Tests referencing old sandbox names — update
- Docs/site pages — update references

## Permission Translation (Claude → Clash)

### Reading settings

```rust
let claude = claude_settings::ClaudeSettings::new();
let settings = claude.effective()?;
```

This merges all levels (system → project-local → project → user) into one
`Settings` struct.

### Translation rules

| Claude Permission           | Pattern Type      | Clash Rule                                                        |
|-----------------------------|-------------------|-------------------------------------------------------------------|
| `"Bash(git:*)"` allow      | Prefix on Bash    | `when({"Bash": {"git": {glob("**"): allow(sandbox=project)}}})` |
| `"Bash(cargo check:*)"` allow | Prefix on Bash | `when({"Bash": {"cargo": {"check": {glob("**"): allow(sandbox=project)}}}})` |
| `"Read"` allow              | Tool-only         | `when({"Read": allow(sandbox=project_files)})`                   |
| `"Read(.env)"` deny         | Exact on file tool| `when({"Read": {".env": deny()}})`                              |
| `"Read(**/*.rs)"` allow     | Glob              | **Skipped** with warning (no direct Clash equivalent)            |
| `"Write"` ask               | Tool-only         | `when({"Write": ask(sandbox=project_files)})`                    |
| MCP tools (`mcp__*`)        | Any               | **Skipped** with warning                                         |

### Grouping

- Bash prefix allows with the same effect are grouped into tuple keys:
  `("git", "cargo", "npm"): {glob("**"): allow(sandbox=project)}`
- File tools (Read/Glob/Grep) grouped together; write tools (Write/Edit) grouped
  together
- Deny rules emitted before allow rules (higher priority)

### Inline sandbox for file tools

File-access tools get a `project_files` sandbox scoped to the project directory
and `~/.claude`:

```starlark
project_files = sandbox(
    name = "cwd",
    fs = [
        cwd(follow_worktrees = True).recurse().allow(read = True, write = True),
        home().child(".claude").recurse().allow(read = True, write = True),
    ],
)
```

This is the same pattern currently used in `from_trace.rs` (as `_fs_box`). Both
should be unified in a follow-up.

### Default effect

- If Claude settings have explicit ask rules or no `bypass_permissions` →
  `settings(default = ask())`
- The posture prompt (for empty/bypass cases) overrides this

## Sandbox Mapping

When the user has meaningful permissions to import, the generated policy always
applies a sandbox. Clash adds sandbox enforcement regardless of whether Claude's
sandbox was enabled — this is a core value proposition.

The default sandbox for generated policies is `project` (read+write project,
tmpdir, ~/.claude).

## Posture Prompt

Shown when there's nothing meaningful to import (empty permissions or
`bypass_permissions: true`):

```
No existing permissions found in Claude Code settings.

? Pick a starting posture:
  ❯ Strict     — deny by default, read-only project access
    Balanced   — ask by default, read+write project access
    Permissive — allow by default, full workspace access (sandboxed)
```

| Posture    | `settings()`     | `default_sandbox` | Sandbox preset |
|------------|------------------|--------------------|----------------|
| Strict     | `default = deny()` | `readonly`       | Read-only project, network allowed |
| Balanced   | `default = ask()`  | `project`        | R/W project + tmpdir + ~/.claude |
| Permissive | `default = allow()` | `workspace`     | Full home, deny sensitive dirs |

The generated policy for a posture pick is minimal — loads, settings, and a
`policy()` call with builtins and no custom rules.

## Generated Policy Examples

### Full import (typical Claude settings)

```starlark
# Imported from Claude Code settings
load("@clash//builtin.star", "base")
load("@clash//std.star", "when", "policy", "settings", "sandbox", "cwd", "home", "allow", "ask", "deny")
load("@clash//sandboxes.star", "project")

# Sandbox for file-access tools (scoped to project + ~/.claude)
project_files = sandbox(
    name = "cwd",
    fs = [
        cwd(follow_worktrees = True).recurse().allow(read = True, write = True),
        home().child(".claude").recurse().allow(read = True, write = True),
    ],
)

settings(default = ask(), default_sandbox = project)

policy("imported",
    default = ask(),
    rules = [
        # Denied patterns
        when({"Read": {".env": deny()}}),

        # Allowed binaries
        when({"Bash": {
            ("git", "cargo", "npm"): {glob("**"): allow(sandbox = project)},
        }}),

        # Read-only tools
        when({("Read", "Glob", "Grep"): allow(sandbox = project_files)}),

        # Write tools
        when({("Write", "Edit"): allow(sandbox = project_files)}),
    ],
)
```

### Posture only (empty settings, user picks "Balanced")

```starlark
load("@clash//builtin.star", "base")
load("@clash//std.star", "policy", "settings", "allow", "ask", "deny")
load("@clash//sandboxes.star", "project")

settings(default = ask(), default_sandbox = project)

policy("default",
    default = ask(),
    rules = [],
)
```

## File Changes

| File | Change |
|------|--------|
| `clash/src/cmd/import_settings.rs` | **New** — read Claude settings, analyze, generate Starlark |
| `clash/src/cli.rs` | Add `--no-import` flag to `Init` |
| `clash/src/main.rs` | Route: default → import, `--no-import` → install-only + hint |
| `clash/src/cmd/mod.rs` | Add `pub mod import_settings` |
| `clash/src/cmd/init.rs` | Make `install_agent_plugin` `pub(crate)` |
| `clash_starlark/stdlib/sandboxes.star` | Rename presets |
| `clash/src/default_policy.star` | Update sandbox references |
| `clash/src/cmd/from_trace.rs` | Rename `_fs_box` → `project_files`, update sandbox loads |
| `examples/*.star` | Update sandbox references |
| Tests referencing old names | Update |
| Docs/site pages | Update sandbox references |
| `clester/tests/scripts/import_no_import.yaml` | **New** — test `--no-import` path |
| `clester/tests/scripts/sandbox_presets.yaml` | **New** — test new sandbox preset names |

## Testing

### Unit tests in `import_settings.rs`

1. `test_analyze_empty_settings` — empty settings → triggers posture prompt path
2. `test_analyze_bypass_permissions` — `bypass_permissions: true` → posture prompt
3. `test_analyze_basic_permissions` — known allows/denies/asks → correct categorization
4. `test_analyze_multi_word_prefix` — `"Bash(cargo check:*)"` → binary + subcommand
5. `test_analyze_skips_mcp` — MCP permissions skipped without error
6. `test_analyze_skips_globs` — glob permissions skipped without error
7. `test_generate_compiles` — generated Starlark passes `compile_to_tree()`
8. `test_generate_posture_compiles` — each posture generates valid Starlark
9. `test_generate_groups_bash_prefixes` — multiple bash allows → tuple key
10. `test_generate_denies_first` — deny rules before allow rules

### Sandbox rename tests

- `starter_policy_compiles` in `init.rs` passes with new names
- `from_trace.rs` tests updated for `project_files` rename

### Clester tests

- `import_no_import.yaml` — `clash init --no-import` installs hooks, exits clean
- `sandbox_presets.yaml` — policy using `readonly`/`project`/`workspace`/`unrestricted` compiles and evaluates

## Out of Scope (Follow-ups)

- Import from other agents (Gemini, Codex, etc.)
- Shared `project_files` sandbox builder extracted to common helper (unify
  `from_trace` + `import_settings`)
- Glob-pattern permission translation (`Read(**/*.rs)`)
- MCP tool permission translation
