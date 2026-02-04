---
name: dogfood
description: Initialize clash with a safe default policy
---
Explain to the user that you are going to initialize clash and that you will be asking for permission because clash doesn't have any rules set yet.
Run the clash init command (without --force, so it won't overwrite an existing config):

```bash
${CLAUDE_PLUGIN_ROOT}/bin/clash init
```
If this fails, ask the user if they want to re-run with "--force" to fully reinitilize

After running the command, explain to the user:

1. A default `policy.yaml` has been written to `~/.clash/policy.yaml`
2. The default policy provides these protections:
   - **SSH keys** (`~/.ssh`) are blocked from being read, written, or edited
   - **Git commits and pushes** are denied — Claude cannot create or push commits
   - **Destructive git operations** (`reset --hard`, `clean`, `branch -D`) are denied
   - **`sudo`** is denied
   - **Bash commands** are sandboxed away from `~/.ssh`, `~/.gnupg`, and `~/.aws`
3. The policy uses `ask` as the default, so anything not covered by a rule will prompt for approval
4. They should review and customize `~/.clash/policy.yaml` for their needs — for example:
   - Add `deny bash git checkout main:` / `deny bash git switch main:` to prevent switching to main
   - Adjust the sensitive directory list in the `allow` rules
   - Add project-specific deny rules for commands they want blocked
5. Run `clash launch` to start Claude Code with clash enforcing the policy
6. For local development run `just dev` to rebuild the clash plugin and start a new Claude Code session with that plugin enabled.
