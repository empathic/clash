---
name: deny
description: Add a deny rule to the clash policy
---
Help the user add a **deny** rule to their clash policy.

## Steps

1. **Determine the rule** from the conversation context. Consider what the user wants to block:
   - Exec: `clash-cli policy deny '(exec "git" "push" *)'` (block git push)
   - Exec broad: `clash-cli policy deny '(exec "sudo" *)'` (block sudo commands)
   - Fs: `clash-cli policy deny '(fs write (subpath (env HOME)))'` (block writes under home)
   - Fs scoped: `clash-cli policy deny '(fs (or write delete) (subpath "/important"))'` (block writes and deletes under a directory)
   - Net: `clash-cli policy deny '(net "evil.com")'` (block network access to a domain)
   - Bare verbs also work for broad rules: `clash-cli policy deny bash`, `clash-cli policy deny edit`
   - If unsure, ask the user what they want to deny.

2. **Confirm with the user** before making any changes:
   - Show the exact command that will be run
   - Explain what the rule means in plain English
   - Remind the user that **deny always wins** — this rule will block the action even if an allow rule also matches

3. **Dry-run first** to preview the change:
   ```bash
   clash-cli policy deny '(exec "git" "push" *)' --dry-run
   ```
   Show the output to the user.

4. **Get confirmation**, then apply:
   ```bash
   clash-cli policy deny '(exec "git" "push" *)'
   ```

5. **Report success** and explain that the deny rule is now active.

## Safety guidelines

- Always dry-run first and show the result before applying
- Explain that deny rules always take precedence, regardless of specificity
- Warn if the deny rule is very broad (e.g., `deny '(exec)'` or `deny '(fs)'`) as it may block legitimate operations
- Suggest using `ask` instead of `deny` if the user might want to approve the action on a case-by-case basis
