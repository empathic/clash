---
name: amend
description: Edit the clash policy — add and remove rules by editing the policy file
---
Help the user modify their clash policy by editing the `.star` policy file directly.

## Policy file location

- Project-level: `<project>/.clash/policy.star` (or `policy.json`)
- User-level: `~/.clash/policy.star` (or `policy.json`)
- Prefer the project-level file if it exists; fall back to user-level.
- Prefer `.star` files over `.json` files.

## Starlark policy format

Policies are `.star` files defining a `main()` function that returns a `policy()` value. Rules go in the `rules = [...]` list:

```python
load("@clash//std.star", "exe", "policy", "cwd", "home", "domains")

def main():
    return policy(default = deny, rules = [
        exe("git").allow(),
        exe("git", args = ["push"]).deny(),
        cwd(follow_worktrees = True, read = allow, write = allow),
        home().child(".ssh", read = allow),
        domains({"github.com": allow}),
    ])
```

## Steps

1. **Read the current policy file** to understand the existing structure.

2. **Dry-run by describing the change** to the user — show the exact Starlark rule that will be added or the rule that will be removed, and explain what the resulting policy will do.

3. **Get confirmation**, then edit the policy file directly.

4. **For adding a rule**, insert it into the `rules = [...]` list. Common patterns:

   - Allow all git commands:
     ```python
     exe("git").allow()
     ```
   - Deny git push:
     ```python
     exe("git", args = ["push"]).deny()
     ```
   - Allow reads under cwd:
     ```python
     cwd(follow_worktrees = True, read = allow)
     ```
   - Allow network access to a domain:
     ```python
     domains({"github.com": allow})
     ```

   Make sure any new builders are added to the `load()` statement at the top.

5. **For removing a rule**, delete the corresponding entry from the `rules = [...]` list.

6. **Validate the change** after editing:
   ```bash
   clash policy validate
   ```

7. **Report success** and summarize what changed.

## Safety guidelines

- Always show the user the exact change before applying it
- Prefer scoped rules over broad wildcards
- Warn the user when removing deny rules — they may be there for good reason
