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
2. The default policy uses **profiles** to organize filesystem access:
   - **cwd** — allows all tools to read, write, execute, create, and delete files within the current working directory
   - **claude-internal** — allows all tools to access `~/.claude` (needed for Claude Code's own state)
   - **tmp** — allows all tools to access `/tmp`
   - **main** — the active profile, includes all three above plus the git/sudo rules below
   - **`__clash_internal__`** (built-in) — always active, allows reading `~/.clash/` and grants `clash init` sandbox access to write its config. Can be overridden by defining a profile with the same name in the policy.
   - **`__claude_internal__`** (built-in) — always active, allows Claude Code meta-tools (AskUserQuestion, ExitPlanMode, task management, etc.) so they are never blocked by policy. Can be overridden by defining a profile with the same name in the policy.
3. The default policy provides these protections:
   - **Git commits** require approval (`ask`) — Claude must get permission before committing
   - **Git push** is denied — Claude cannot push commits
   - **Git merge** is denied — Claude cannot merge branches
   - **Destructive git operations** (`reset --hard`, `clean`, `branch -D`) are denied
   - **`sudo`** is denied
4. The policy uses `ask` as the default, so anything not covered by a rule will prompt for approval
5. They should review and customize `~/.clash/policy.yaml` for their needs — for example:
   - Add `deny bash git checkout main:` / `deny bash git switch main:` to prevent switching to main
   - Add project-specific deny rules for commands they want blocked
   - Adjust the filesystem access profiles for their workflow
