---
name: allow
description: Add an allow rule to the clash policy
---
Help the user add an **allow** rule to their clash policy.

## Steps

1. **Determine the rule** from the conversation context. Prefer broad patterns over narrow ones:
   - Good: `allow bash git *` (covers all git commands)
   - Avoid: `allow bash git status` (too narrow, user will hit another prompt soon)
   - If unsure, ask the user what they want to allow.
   - **Bare verb shortcuts**: if the user wants a common capability, use a bare verb:
     - `clash policy allow edit` — allow editing files in the project
     - `clash policy allow bash` — allow running commands in the project
     - `clash policy allow web` — allow web search and fetch
     - `clash policy allow read` — allow reading files in the project
   - **Full rule** for specific patterns:
     - `clash policy allow "bash git *"` — allow all git commands
   - If the request involves a **directory path** or filesystem access (e.g., "allow access to ~/Library/Caches"):
     - Use `"* *"` as the rule with a `--fs` constraint
     - Example: `clash policy allow "* *" --fs "full:subpath(~/Library/Caches)"`
     - Capabilities: `read`, `write`, `create`, `delete`, `execute`, or `full` (all of the above)
     - Filters: `subpath(path)`, `literal(path)`, `regex(pattern)` — combinable with `|` (or) and `&` (and)

2. **Confirm with the user** before making any changes:
   - Show the exact command that will be run
   - Explain what the rule means in plain English

3. **Dry-run first** to preview the change:
   ```bash
   clash policy allow "RULE" --dry-run
   # Or with filesystem constraints:
   clash policy allow "* *" --fs "full:subpath(~/dir)" --dry-run
   ```
   Show the output to the user.

4. **Get confirmation**, then apply:
   ```bash
   clash policy allow "RULE"
   ```

5. **Report success** and explain that the rule is now active.

## Safety guidelines

- Always dry-run first and show the result before applying
- Never suggest rules that override intentional deny rules without explicit user consent
- Never suggest `allow "* *"` or `allow "bash *"` without explaining the security implications and getting explicit user consent
- If the user asks to allow something that is currently denied, warn them that deny rules always take precedence (even over constrained allows) and they may need to remove the deny rule first
- If the user wants an allow rule to override a broader ask, suggest adding inline constraints (url, args, etc.) to the allow rule — constrained allows beat unconstrained asks
- Prefer scoped rules (e.g., `allow "bash git *"`) over broad wildcards
