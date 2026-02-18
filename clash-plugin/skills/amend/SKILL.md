---
name: amend
description: Edit the clash policy — add and remove rules using the transactional shell editor
---
Help the user modify their clash policy. Use `clash policy shell` for all policy editing — it provides a transactional editor that accumulates changes in memory and applies them atomically.

## Preferred approach: `clash policy shell`

Use `clash policy shell -c '<statement>'` for one-liner changes, or pipe mode for multiple changes.

### Rule format

Rules are either:

- **Full s-expression**: `(allow (exec "git" *))` — the effect is part of the rule
- **Shortcut**: `allow:bash`, `deny:web`, `ask:edit` — effect:verb format

### Commands

| Command | Syntax | Description |
|---------|--------|-------------|
| `add` | `add [<policy>] <rule>` | Add a rule |
| `remove` | `remove [<policy>] <rule>` | Remove a rule by its text |
| `create` | `create <policy>` | Create a new policy block |
| `default` | `default <effect> [<policy>]` | Change the default effect |

## Steps

1. **Dry-run first** to preview the change:
   ```bash
   clash policy shell --scope project --dry-run -c 'add (allow (exec "git" *))'
   ```
   Show the output to the user and explain what the resulting policy will do.

2. **Get confirmation**, then apply:
   ```bash
   clash policy shell --scope project -c 'add (allow (exec "git" *))'
   ```

3. **For multiple changes**, use pipe mode:
   ```bash
   clash policy shell --scope project --dry-run <<EOF
   add (allow (exec "cargo" *))
   add (deny (exec "git" "push" :has "--force"))
   remove (deny (exec "npm" *))
   EOF
   ```
   Then apply without `--dry-run` after confirmation.

4. **Report success** and summarize what changed.

## Scope selection

- `--scope project` — saved in `<project>/.clash/policy.sexpr`, persists across sessions
- `--scope user` — saved in `~/.clash/policy.sexpr`, applies everywhere
- `--scope session` — temporary, lasts only for the current Claude Code session

## Safety guidelines

- Always dry-run first and show the result before applying
- Prefer scoped rules over broad wildcards
- Warn the user when removing deny rules — they may be there for good reason

## Legacy: `clash amend`

`clash amend` still works but `clash policy shell` is preferred. If you encounter `clash amend` in existing workflows, it continues to function identically.
