---
name: allow
description: Add an allow rule to the clash policy
---
Help the user add an **allow** rule to their clash policy by editing the JSON policy file directly.

## Steps

1. **Determine the rule** from the conversation context. Prefer broad patterns over narrow ones:
   - Good: allow all git commands (covers all git subcommands)
   - Avoid: allow only `git status` (too narrow, user will hit another prompt soon)
   - If unsure, ask the user what they want to allow.

2. **Find the policy file** to edit:
   - Project-level: `<project>/.clash/policy.json`
   - User-level: `~/.clash/policy.json`
   - Prefer the project-level file if it exists; fall back to user-level.

3. **Read the current policy file** to understand the existing structure.

4. **Confirm with the user** before making any changes:
   - Show the exact rule that will be added (as a JSON snippet)
   - Explain what the rule means in plain English

5. **Edit the JSON policy file** to add the rule into the appropriate policy body. Common rule patterns:

   - Exec (all git commands):
     ```json
     { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
     ```
   - Exec with subcommand (git push):
     ```json
     { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
     ```
   - Filesystem read under cwd:
     ```json
     { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" }, "worktree": true } } } } }
     ```
   - Filesystem read/write/create under cwd:
     ```json
     { "rule": { "effect": "allow", "fs": { "op": { "or": ["read", "write", "create"] }, "path": { "subpath": { "path": { "env": "PWD" }, "worktree": true } } } } }
     ```
   - Filesystem access under a specific path:
     ```json
     { "rule": { "effect": "allow", "fs": { "path": { "subpath": { "path": { "literal": "/tmp" } } } } } }
     ```
   - Network access to a domain:
     ```json
     { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
     ```
   - Allow all tool use:
     ```json
     { "rule": { "effect": "allow", "tool": {} } }
     ```

6. **Validate the change** with:
   ```bash
   clash policy validate
   ```
   Show the output to the user.

7. **Report success** and explain that the rule is now active.

## Safety guidelines

- Always show the user the exact JSON change before applying it
- Never suggest rules that override intentional deny rules without explicit user consent
- Never add a broad match-all allow rule without explaining the security implications and getting explicit user consent
- If the user asks to allow something that is currently denied by an explicit deny rule, warn them that deny rules take precedence and they may need to remove the deny rule first
- Prefer scoped rules (e.g., targeting a specific binary) over broad wildcards
