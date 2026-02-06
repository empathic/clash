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

2. **Confirm with the user** before making any changes:
   - Show the exact rule that will be added
   - Show which profile it will be added to (the active profile by default)
   - Explain what the rule means in plain English

3. **Dry-run first** to preview the change:
   ```bash
   $CLASH_BIN policy add-rule "RULE" --dry-run
   ```
   Show the output to the user.

4. **Get confirmation**, then apply:
   ```bash
   $CLASH_BIN policy add-rule "RULE"
   ```

5. **Report success** and explain that the rule is now active.

## Safety guidelines

- Always dry-run first and show the result before applying
- Never suggest rules that override intentional deny rules without explicit user consent
- Never suggest `allow * *` or `allow bash *` without explaining the security implications and getting explicit user consent
- If the user asks to allow something that is currently denied, warn them that deny rules take precedence and they may need to remove the deny rule first
- Prefer scoped rules (e.g., `allow bash git *`) over broad wildcards
