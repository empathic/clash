---
name: deny
description: Add a deny rule to the clash policy
---
Help the user add a **deny** rule to their clash policy.

## Steps

1. **Determine the rule** from the conversation context. Consider what the user wants to block:
   - Example: `deny bash git push*` (block git push)
   - Example: `deny bash sudo *` (block sudo commands)
   - If unsure, ask the user what they want to deny.

2. **Confirm with the user** before making any changes:
   - Show the exact rule that will be added
   - Show which profile it will be added to (the active profile by default)
   - Explain what the rule means in plain English
   - Remind the user that **deny takes precedence over allow** — this rule will block the action even if an allow rule also matches

3. **Dry-run first** to preview the change:
   ```bash
   ${CLASH_PLUGIN_ROOT}/bin/clash policy add-rule "RULE" --dry-run
   ```
   Show the output to the user.

4. **Get confirmation**, then apply:
   ```bash
   ${CLASH_PLUGIN_ROOT}/bin/clash policy add-rule "RULE"
   ```

5. **Report success** and explain that the deny rule is now active.

## Safety guidelines

- Always dry-run first and show the result before applying
- Explain that deny rules take precedence: `deny > ask > allow`
- Warn if the deny rule is very broad (e.g., `deny bash *` or `deny * *`) as it may block legitimate operations
- Suggest using `ask` instead of `deny` if the user might want to approve the action on a case-by-case basis
