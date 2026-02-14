---
name: status
description: Show clash permission enforcement status and configuration
---

Show the current clash configuration status.

Run:

```bash
$CLASH_BIN status
```

Report the results to the user in plain English, including:
1. What Claude can currently do (allowed capabilities)
2. What is blocked
3. The default permission behavior

For more detail, suggest:
- `/clash:describe` for a full policy breakdown
- `/clash:edit` to make changes
- `clash policy use <profile>` to switch the active profile
- `clash policy setup` in the terminal for interactive reconfiguration
