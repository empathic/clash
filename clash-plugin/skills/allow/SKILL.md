---
name: allow
description: Add an allow rule to the clash policy
---
Help the user add an **allow** rule to their clash policy.

## Steps

1. **Determine the rule** from the conversation context. Prefer broad patterns over narrow ones:
   - Good: `allow '(exec "git" *)'` (covers all git commands)
   - Avoid: `allow '(exec "git" "status")'` (too narrow, user will hit another prompt soon)
   - If unsure, ask the user what they want to allow.
   - **Bare verb shortcuts**: if the user wants a common capability, use a bare verb:
     - `clash policy allow edit` — allow editing files in the project
     - `clash policy allow bash` — allow running commands in the project
     - `clash policy allow web` — allow web search and fetch
     - `clash policy allow read` — allow reading files in the project
   - **S-expression rules** for specific patterns:
     - Exec: `clash policy allow '(exec "git" *)'` — allow all git commands
     - Exec with subcommand: `clash policy allow '(exec "git" "push" *)'` — allow git push
     - Fs: `clash policy allow '(fs read (subpath (env PWD)))'` — allow reads under cwd
     - Fs with path: `clash policy allow '(fs (subpath "/tmp"))'` — allow all fs ops under /tmp
     - Fs with env: `clash policy allow '(fs write (subpath (env HOME)))'` — allow writes under home
     - Net: `clash policy allow '(net "github.com")'` — allow network access to github.com
   - If the request involves a **directory path** or filesystem access (e.g., "allow access to ~/Library/Caches"):
     - Use an `(fs ...)` s-expression with a `(subpath ...)` path filter
     - Example: `clash policy allow '(fs (subpath "/Users/me/Library/Caches"))'`
     - Use `(env HOME)` or `(env PWD)` for dynamic paths: `clash policy allow '(fs (subpath (join (env HOME) "/Library/Caches")))'`
     - Optionally scope to an operation: `read`, `write`, `create`, `delete`, or combine with `(or read write)`
   - When unsure about the exact syntax, run `clash policy allow --help` to check available options.

2. **Confirm with the user** before making any changes:
   - Show the exact command that will be run
   - Explain what the rule means in plain English

3. **Dry-run first** to preview the change:
   ```bash
   clash policy allow '(exec "git" *)' --dry-run
   # Or for filesystem access:
   clash policy allow '(fs write (subpath (env HOME)))' --dry-run
   ```
   Show the output to the user.

4. **Get confirmation**, then apply:
   ```bash
   clash policy allow '(exec "git" *)'
   ```

5. **Report success** and explain that the rule is now active.

## Session-scoped rules

When a user approves a permission prompt and wants that approval to last for the rest of the session (but NOT permanently), use `--scope session`:

1. **Determine if session scope is appropriate**:
   - The user just approved a one-off action and wants to avoid re-prompting for similar actions
   - The user explicitly asks for "just this session" or "for now"
   - You received advisory context from PostToolUse suggesting a session rule

2. **Use `--scope session`** to add a temporary rule:
   ```bash
   clash policy allow '(exec "git" *)' --scope session --dry-run
   clash policy allow '(exec "git" *)' --scope session
   ```

3. **Craft precise rules** — avoid overly broad permissions:
   - Good: `(exec "git" *)` — allows all git commands for the session
   - Good: `(exec "cargo" "test" *)` — allows cargo test for the session
   - Avoid: `(exec *)` — too broad, allows any command
   - When PostToolUse suggests a rule, use it as a starting point but consider whether a narrower scope makes sense

Session rules live only for the current Claude Code session and are automatically cleaned up when the session ends.

## Safety guidelines

- Always dry-run first and show the result before applying
- Never suggest rules that override intentional deny rules without explicit user consent
- Never suggest `allow '(exec)'` or `allow '(fs)'` (match-anything rules) without explaining the security implications and getting explicit user consent
- If the user asks to allow something that is currently denied, warn them that deny rules always take precedence (even over allows) and they may need to remove the deny rule first
- Prefer scoped rules (e.g., `allow '(exec "git" *)'`) over broad wildcards
