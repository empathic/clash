# ADR-003: Filesystem Sandbox for Bash Only

## Status

Accepted

## Context

When a policy has filesystem constraints (`fs: subpath(.)`), we need to enforce them. For read/write/edit tools, the tool itself accesses a single known file path — we can check the path against the constraint before allowing the tool call.

For bash commands, the situation is different. A bash command like `git status` may access many files across the filesystem. We cannot reliably predict which files a command will access by parsing the command string. Even if we could, the command might spawn subprocesses that access additional files.

Options:

1. **Parse the command string** and predict file access. Unreliable — shell expansion, aliases, subprocesses make this intractable.
2. **Deny bash commands with fs constraints**. Too restrictive — makes `fs` constraints useless for bash.
3. **Kernel-level sandbox**: apply OS-level restrictions (macOS Seatbelt / Linux Landlock) that the process cannot escape, then let the command run freely within those restrictions.

## Decision

For bash commands, `fs` constraints generate kernel-level sandbox rules instead of acting as permission guards. The sandbox is applied before exec'ing the command and inherited by all child processes.

For non-bash verbs (read, write, edit), `fs` constraints act as permission guards — the file path is checked against the filter expression before the tool is allowed.

The dual behavior is implemented by:
- `CompiledConstraintDef::eval()` skipping the `fs` check for `Verb::Execute`
- `generate_sandbox_from_profiles()` / `generate_unified_sandbox()` collecting `fs` constraints from matched allow rules and converting them to `SandboxPolicy`

## Consequences

**Positive:**
- Bash commands are genuinely sandboxed at the kernel level — no escape via subprocesses, shell tricks, or dynamic file access
- Same `fs` constraint syntax works for both bash and non-bash tools — users don't need to learn two systems
- Sandbox restrictions are inherited by child processes and cannot be removed

**Negative:**
- Requires platform-specific code (macOS Seatbelt profiles, Linux Landlock rules)
- Sandbox is one-way — once applied, the process cannot gain additional permissions
- Filter expression semantics differ slightly: `And(a, b)` / `Or(a, b)` both collect rules from both sides in sandbox generation (the boolean logic is approximated by the union of sandbox rules)
- Regex-based filters have limited support on some platforms
