# clash

The core CLI binary and library. See the [project README](../README.md) for usage and documentation.

## Status Line internals

The `clash statusline` command powers the Claude Code status bar integration. It uses a **stats sidecar** pattern to keep rendering fast regardless of session length.

### Architecture

```
PreToolUse hook
  → policy evaluation
  → log_decision() writes audit.jsonl
  → update_session_stats() writes stats.json  (atomic: write tmp + rename)

Claude Code (after each assistant message)
  → clash statusline render
  → reads stats.json from /tmp/clash-<session_id>/
  → prints ANSI-colored line to stdout (<10ms)
```

### Stats sidecar (`stats.json`)

Instead of parsing the growing `audit.jsonl` on every render, the PreToolUse hook maintains a small JSON file with pre-aggregated counters:

```json
{
  "allowed": 12,
  "denied": 3,
  "asked": 1,
  "last_tool": "Bash",
  "last_input_summary": "git status",
  "last_effect": "allow",
  "last_at": "1706123456.789",
  "default_effect": "deny",
  "last_deny_hint": null
}
```

The file is written atomically (write to `.stats.json.tmp`, then `fs::rename`) to prevent partial reads by the concurrent render process.

### Double-count prevention

Stats are updated in the **PreToolUse handler only** (`cmd/hooks.rs`), not inside `log_decision()`. This is intentional: "ask" decisions trigger both PreToolUse and PermissionRequest hooks, and both re-evaluate the policy via `check_permission()` → `log_decision()`. Counting in `log_decision` would double-count asks.

### Deny hints

When a tool is denied, `deny_hint()` generates the narrowest possible allow rule based on the tool type and input:

- `Bash` → `(exec "<binary>" *)` using the first word of the command
- `Read`/`Write` → `(fs read/write (subpath "<parent>"))` from the file path
- `WebFetch` → `(net "<domain>")` extracted from the URL
- Fallback → bare verb shortcuts (`clash allow bash`, etc.)

### Color forcing

The render function calls `console::set_colors_enabled(true)` because Claude Code pipes the status line command's stdout (not a TTY), but the TUI does support ANSI escape codes.
