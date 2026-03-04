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

The JSON policy file to edit:

- Project-level: `<project>/.clash/policy.json` — persists across sessions, project-specific
- User-level: `~/.clash/policy.json` — applies everywhere
- Prefer the project-level file if it exists; fall back to user-level.

## Adding a rule

Read the policy file, then insert the appropriate rule into the policy's `body` array. Common rule patterns:

- Allow all git commands:
  ```json
  { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
  ```
- Deny git push:
  ```json
  { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
  ```
- Allow filesystem reads under cwd:
  ```json
  { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" }, "worktree": true } } } } }
  ```
- Allow filesystem read/write/create under cwd:
  ```json
  { "rule": { "effect": "allow", "fs": { "op": { "or": ["read", "write", "create"] }, "path": { "subpath": { "path": { "env": "PWD" }, "worktree": true } } } } }
  ```
- Allow network access to a domain:
  ```json
  { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
  ```

Show the user the exact JSON change before applying it. After confirmation, edit the file.

## Removing a rule

Read the policy file, identify the rule entry to remove, show it to the user, then delete that entry from the `body` array after confirmation.

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
