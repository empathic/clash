---
name: edit
description: Guided editing of the clash policy file
---
First, get an overview of the current policy:

```bash
clash status
```

Then list the active rules:

```bash
clash policy list
```

If the user has already stated what they want to change, proceed. Otherwise, ask what change they would like to make. Common requests include:
- Adding allow/deny/ask rules for specific commands
- Removing existing rules
- Changing the default permission behavior
- Viewing rules in a different profile

## Policy file location

The policy file to edit:

- Project-level: `<project>/.clash/policy.star` (or `policy.json`) — persists across sessions, project-specific
- User-level: `~/.clash/policy.star` (or `policy.json`) — applies everywhere
- Prefer the project-level file if it exists; fall back to user-level.
- Prefer `.star` files over `.json` files.

## Adding a rule

Read the policy file, then insert the appropriate rule into the `rules = [...]` list in the `main()` function. Common rule patterns:

- Allow all git commands:
  ```python
  exe("git").allow()
  ```
- Deny git push:
  ```python
  exe("git", args = ["push"]).deny()
  ```
- Allow filesystem reads under cwd:
  ```python
  cwd(read = allow)
  ```
- Allow filesystem read/write/create under cwd:
  ```python
  cwd(follow_worktrees = True, read = allow, write = allow)
  ```
- Allow network access to a domain:
  ```python
  domains({"github.com": allow})
  ```
- Access to a subdirectory of home:
  ```python
  home().child(".ssh", read = allow)
  ```

Make sure any new builders are added to the `load()` statement at the top of the file.

Show the user the exact change before applying it. After confirmation, edit the file.

## Removing a rule

Read the policy file, identify the rule entry to remove from the `rules = [...]` list, show it to the user, then delete that entry after confirmation.

## Validating changes

After applying a change, validate the policy:

```bash
clash policy validate
```

Then verify behavior with explain:

```bash
clash explain bash "git push"
```

Suggest follow-up skills:
- `/clash:describe` to review the full updated policy
- `/clash:test` to test several scenarios against the policy
- `/clash:allow` or `/clash:deny` for quick single-rule additions
