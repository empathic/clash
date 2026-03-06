---
name: deny
description: Add a deny rule to the clash policy
---
Help the user add a **deny** rule to their clash policy by editing the `.star` policy file directly.

## Steps

1. **Determine the rule** from the conversation context. Consider what the user wants to block:
   - Exec: `exe("git", args = ["push"]).deny()` — block git push
   - Exec broad: `exe("sudo").deny()` — block sudo commands
   - Net: `domains({"evil.com": deny})` — block network access to a domain
   - If unsure, ask the user what they want to deny.

2. **Find the policy file** to edit:
   - Project-level: `<project>/.clash/policy.star` (or `policy.json`)
   - User-level: `~/.clash/policy.star` (or `policy.json`)
   - Prefer the project-level file if it exists; fall back to user-level.
   - Prefer `.star` files over `.json` files.

3. **Read the current policy file** to understand the existing structure.

4. **Confirm with the user** before making any changes:
   - Show the exact Starlark rule that will be added
   - Explain what the rule means in plain English
   - Remind the user that **deny always wins** — this rule will block the action even if an allow rule also matches

5. **Edit the policy file** to add the deny rule into the `rules = [...]` list in the `main()` function. Make sure any new builders are added to the `load()` statement at the top.

6. **Validate the change**:
   ```bash
   clash policy validate
   ```
   Show the output to the user.

7. **Report success** and explain that the deny rule is now active.

## Safety guidelines

- Always show the user the exact change before applying it
- Explain that deny rules always take precedence, regardless of specificity
- Warn if the deny rule is very broad (e.g., denying all exec or all fs) as it may block legitimate operations
- Suggest using `ask` instead of `deny` if the user might want to approve the action on a case-by-case basis
