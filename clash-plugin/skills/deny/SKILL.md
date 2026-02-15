---
name: deny
description: Add a deny rule to the clash policy
---
Help the user add a **deny** rule to their clash policy.

## Steps

1. **Determine the rule** from the conversation context. Consider what the user wants to block:
   - Example: `clash policy deny "bash git push*"` (block git push)
   - Example: `clash policy deny "bash sudo *"` (block sudo commands)
   - Example: `clash policy deny "* *" --fs "write+delete:subpath(~/important)"` (block writes to a directory)
   - If unsure, ask the user what they want to deny.

2. **Confirm with the user** before making any changes:
   - Show the exact command that will be run
   - Explain what the rule means in plain English
   - Remind the user that **deny always wins** — this rule will block the action even if a constrained allow or ask rule also matches

3. **Dry-run first** to preview the change:
   ```bash
   clash policy deny "RULE" --dry-run
   ```
   Show the output to the user.

4. **Get confirmation**, then apply:
   ```bash
   clash policy deny "RULE"
   ```

5. **Report success** and explain that the deny rule is now active.

## Safety guidelines

- Always dry-run first and show the result before applying
- Explain that deny rules always take precedence, regardless of constraint specificity
- Warn if the deny rule is very broad (e.g., `deny "bash *"` or `deny "* *"`) as it may block legitimate operations
- Suggest using `ask` instead of `deny` if the user might want to approve the action on a case-by-case basis
