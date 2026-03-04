---
name: amend
description: Edit the clash policy — add and remove rules by editing the JSON policy file
---
Help the user modify their clash policy by editing the JSON policy file directly.

## Policy file location

- Project-level: `<project>/.clash/policy.json`
- User-level: `~/.clash/policy.json`
- Prefer the project-level file if it exists; fall back to user-level.

## JSON policy format

Rules are objects in a policy's `body` array:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" }, "worktree": true } } } } },
        { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
      ]
    }
  ]
}
```

## Steps

1. **Read the current policy file** to understand the existing structure.

2. **Dry-run by describing the change** to the user — show the exact JSON rule that will be added or the rule that will be removed, and explain what the resulting policy will do.

3. **Get confirmation**, then edit the JSON policy file directly.

4. **For adding a rule**, insert it into the appropriate policy's `body` array. Common patterns:

   - Allow all git commands:
     ```json
     { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
     ```
   - Deny git push:
     ```json
     { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
     ```
   - Allow reads under cwd:
     ```json
     { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" }, "worktree": true } } } } }
     ```
   - Allow network access to a domain:
     ```json
     { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
     ```
   - Include another policy block:
     ```json
     { "include": "other-policy-name" }
     ```

5. **For removing a rule**, delete the corresponding entry from the `body` array.

6. **Validate the change** after editing:
   ```bash
   clash policy validate
   ```

7. **Report success** and summarize what changed.

## Safety guidelines

- Always show the user the exact JSON change before applying it
- Prefer scoped rules over broad wildcards
- Warn the user when removing deny rules — they may be there for good reason
