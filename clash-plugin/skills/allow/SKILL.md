---
name: allow
description: Add an allow rule to the clash policy
---
Help the user add an **allow** rule to their clash policy by editing the `.star` policy file directly.

## Steps

1. **Determine the rule** from the conversation context. Prefer broad patterns over narrow ones:
   - Good: allow all git commands (covers all git subcommands)
   - Avoid: allow only `git status` (too narrow, user will hit another prompt soon)
   - If unsure, ask the user what they want to allow.

2. **Find the policy file** to edit:
   - Project-level: `<project>/.clash/policy.star` (or `policy.json`)
   - User-level: `~/.clash/policy.star` (or `policy.json`)
   - Prefer the project-level file if it exists; fall back to user-level.
   - Prefer `.star` files over `.json` files.

3. **Read the current policy file** to understand the existing structure.

4. **Confirm with the user** before making any changes:
   - Show the exact rule that will be added (as a Starlark snippet)
   - Explain what the rule means in plain English

5. **Edit the policy file** to add the rule into the `rules = [...]` list in the `main()` function. Common rule patterns:

   - Exec (all git commands):
     ```python
     exe("git").allow()
     ```
   - Exec with subcommand (git push):
     ```python
     exe("git", args = ["push"]).allow()
     ```
   - Multiple binaries:
     ```python
     exe(["cargo", "rustc"]).allow()
     ```
   - Filesystem access under cwd (via sandbox on a tool rule):
     ```python
     fs_sandbox = sandbox(fs=[cwd(follow_worktrees = True, read = allow, write = allow)])
     tool(["Read", "Glob", "Grep"]).sandbox(fs_sandbox).allow()
     tool(["Write", "Edit"]).sandbox(fs_sandbox).allow()
     ```
   - Filesystem access under a specific path (via sandbox):
     ```python
     ssh_sandbox = sandbox(fs=[home().child(".ssh", read = allow)])
     exe("ssh").sandbox(ssh_sandbox).allow()
     ```
   - Network access to a domain:
     ```python
     domains({"github.com": allow})
     ```
   - Allow all tool use:
     ```python
     tool().allow()
     ```

   **Important:** Filesystem path entries (`cwd`, `home`, `tempdir`, `path`) cannot appear directly in the `rules = [...]` list. They must be wrapped in a `sandbox()` and attached to a `tool()` or `exe()` rule.

   Make sure any new builders used are added to the `load()` statement at the top of the file, e.g.:
   ```python
   load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "home", "domains")
   ```

6. **Validate the change** with:
   ```bash
   clash policy validate
   ```
   Show the output to the user.

7. **Report success** and explain that the rule is now active.

## Safety guidelines

- Always show the user the exact change before applying it
- Never suggest rules that override intentional deny rules without explicit user consent
- Never add a broad match-all allow rule without explaining the security implications and getting explicit user consent
- If the user asks to allow something that is currently denied by an explicit deny rule, warn them that deny rules take precedence and they may need to remove the deny rule first
- Prefer scoped rules (e.g., targeting a specific binary) over broad wildcards
