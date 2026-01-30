---
name: status
description: Show clash permission enforcement status and configuration
---

Check and display the current clash installation and configuration status.

Run the clash status command using Bash:

```bash
$PLUGIN_DIR/bin/clash status --verbose
```

Report the results to the user, including:
1. Whether clash is enabled at each settings level (user, project-local, project)
2. The current permission rules configured
3. Any warnings about misconfiguration
