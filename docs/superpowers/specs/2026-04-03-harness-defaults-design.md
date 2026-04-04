# Harness Default Permissions

## Problem

When Clash enforces policy on an agent like Claude Code, the agent needs access to its own infrastructure directories to function — writing memories, loading skills, reading project config, managing transcripts. Without explicit policy rules for these paths, every access triggers an "ask" prompt, making the agent nearly unusable out of the box.

Users should not need to write policy rules for their agent's basic operational needs. But power users who want full control over their agent's filesystem access should be able to disable these defaults and write their own rules.

## Design

### Harness Path Definitions

Each `AgentKind` defines a set of harness paths — filesystem locations the agent needs to operate. These are hardcoded constants in Clash, not user-editable.

**Claude (`AgentKind::Claude`):**

| Path | Access | Purpose |
|------|--------|---------|
| `~/.claude/` | read, write, create, delete | Memories, settings, plugin cache, skills |
| `<project>/.claude/` | read | Project config (CLAUDE.md discovery, settings) |
| `<transcript_dir>/` | read, write, create, delete | Session transcripts, task output |

Other agents follow the same pattern (e.g., Gemini gets `~/.gemini/`). Only Claude's paths are defined initially; others are added as needed.

All harness rules are unsandboxed allows — no kernel enforcement. These are the agent's own config directories.

### Path Resolution

Paths are resolved at evaluation time from already-available context:

- **`~/.claude/`** — `$HOME` environment variable
- **`<project>/.claude/`** — project root (already discovered during settings loading)
- **`<transcript_dir>/`** — from `HookContext::transcript_path`

If a path cannot be resolved (e.g., no transcript dir available), that rule is omitted silently — no error.

### Priority & Evaluation

The policy loading hierarchy becomes:

```
Session policy    (highest priority, first match)
Project policy
User policy
Harness defaults  (lowest priority, last match)
```

During `CompiledPolicy` compilation, if harness defaults are enabled, the harness rules for the active agent are appended after all user-defined rules. Since evaluation is first-match-wins DFS, any user rule on the same path takes precedence over the harness default.

When a harness default rule matches, the `PolicyDecision` trace tags it as `source: "harness"` so status output can identify and filter it.

### Disable Mechanisms

Two ways to disable harness defaults:

**Environment variable:**
- `CLASH_NO_HARNESS_DEFAULTS=1`
- Checked early in settings loading, before policy compilation
- Useful for CI, scripting, quick toggling

**Starlark setting:**
- `settings(harness_defaults=False)`
- Parsed during policy evaluation alongside other settings (e.g., `default_effect`)
- Can live in user or project policy file

Resolution order (first found wins):
1. `CLASH_NO_HARNESS_DEFAULTS=1` env var → disabled
2. `settings(harness_defaults=False)` in any loaded policy file → disabled
3. Otherwise → enabled

Both mechanisms set the same boolean that the policy compiler checks before appending harness rules.

### Status & Visibility

**`clash status` (default):**
- Harness rules are hidden from the rule list
- Shows a footer note: `"N harness rules active (use --verbose to show)"`
- If harness defaults are disabled, no mention at all

**`clash status --verbose`:**
- Harness rules are shown alongside user rules, tagged with `[harness]` to distinguish them

**`clash policy list` / `clash policy show`:**
- Same behavior — hide by default, show with `--verbose`, always indicate count when hidden

### Agent-Specific Scoping

Only the active agent's harness defaults apply during evaluation. The `AgentKind` is already available in the `QueryContext`. Claude running does not get harness defaults for Gemini's paths, and vice versa.

## Out of Scope

- Network harness defaults (e.g., skill update fetching) — filesystem only for now
- Sandbox restrictions on harness paths — unsandboxed for now
- CLI flag on `clash init` — env var and Starlark setting are sufficient
- Harness defaults for agents other than Claude — added as needed
