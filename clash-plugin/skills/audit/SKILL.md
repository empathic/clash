---
name: audit
description: View recent clash permission decisions from the audit log
---
Use `clash debug log` to view recent permission decisions:

```bash
clash debug log
```

The command supports filtering options:

```bash
clash debug log --since 5m            # entries from the last 5 minutes
clash debug log --effect deny          # only denied actions
clash debug log --tool Bash            # only Bash tool invocations
clash debug log --limit 10             # show at most 10 entries
clash debug log --session "abc"        # entries from sessions matching "abc"
clash debug log --json                 # machine-readable output
```

Parse the output and present a readable summary. For each entry:

1. **Timestamp** — when the decision was made
2. **Decision** — show `ALLOW`, `DENY`, or `ASK`
3. **Tool** — the tool name
4. **Input** — what was invoked (truncated to keep output readable)
5. **Reason** — the matched rule or reason for the decision

If the user asks to filter by tool name, decision type, or time range, use the appropriate flags on `clash debug log`.
