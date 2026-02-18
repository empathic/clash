---
name: status
description: Show clash permission enforcement status and configuration
---

Show the current clash configuration status.

Run:

```bash
clash-cli status
```

Report the results to the user in plain English, including:
1. What Claude can currently do (allowed capabilities)
2. What is blocked
3. The default permission behavior

For more detail, suggest:
- `/clash:describe` for a full policy breakdown
- `/clash:edit` to make changes
- `clash-cli edit` in the terminal for interactive reconfiguration
