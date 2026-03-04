# Policy Writing Guide

A practical guide to writing clash policies. For formal grammar details, see [policy-grammar.md](./policy-grammar.md). For evaluation semantics, see [policy-semantics.md](./policy-semantics.md).

---

## Quick Start

Clash policies use JSON format with three capability domains: **exec** (shell commands), **fs** (file operations), and **net** (network access).

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
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
      ]
    }
  ]
}
```

This policy allows git commands (except push), file reads under the current directory, and network access to github.com. Everything else is denied.

---

## Policy File Location

| Path | Scope |
|------|-------|
| `~/.clash/policy.json` | User-level (applies to all projects) |

Clash reads the policy on every hook invocation, so changes take effect immediately.

---

## Capability Domains

Clash controls three capability domains, not individual tools. A single rule can cover multiple tools:

### Exec — Shell Commands

```json
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
{ "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" }, "args": [{ "literal": "test" }, { "any": null }] } } }
```

The `bin` field matches the binary name; `args` matches positional arguments. More arguments = more specific.

> **Scope:** Exec rules evaluate the top-level command that Claude Code invokes via the Bash tool. They do not apply to child processes spawned by that command. For example, a deny rule on `git push` prevents Claude from directly running `git push`, but if an allowed command like `make deploy` internally calls `git push`, the deny rule does not fire — the policy engine only sees the top-level `make` command. Sandbox restrictions for filesystem and network access *are* enforced on all child processes at the kernel level (see [Sandbox Policies](#sandbox-policies)).

### Fs — File Operations

```json
{ "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
{ "rule": { "effect": "allow", "fs": { "op": { "or": ["read", "write"] }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
{ "rule": { "effect": "deny", "fs": { "op": { "single": "write" }, "path": { "literal": ".env" } } } }
{ "rule": { "effect": "deny", "fs": { "op": "*", "path": { "subpath": { "path": { "static": "/etc" } } } } } }
```

The fs domain maps to these tools:
- `Read` → `fs read`
- `Write` → `fs write`
- `Edit` → `fs write`
- `Glob`/`Grep` → `fs read`

### Net — Network Access

```json
{ "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
{ "rule": { "effect": "allow", "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }] } } } }
{ "rule": { "effect": "deny", "net": { "domain": { "regex": ".*\\.evil\\.com" } } } }
```

The net domain maps to:
- `WebFetch` → `net` with the URL's domain
- `WebSearch` → `net` with wildcard domain

---

## Precedence

Rules are sorted by **specificity** at compile time (most specific first). Within a capability domain, the first matching rule wins.

### Specificity Ranking

More specific patterns take precedence:

```
Literal > Regex > Wildcard
More args > Fewer args
Single op > Or > Any
Literal path > Regex path > Subpath > No path
```

### Example

```json
{ "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
```

`git push origin main` matches the deny rule first (more specific). `git status` skips the deny (doesn't match "push") and matches the allow.

### Conflict Detection

If two rules have the same specificity but different effects and could match the same request, the compiler rejects the policy with a conflict error. This prevents ambiguous orderings.

### Cross-Domain Resolution

When a request matches rules in multiple capability domains (rare), deny-overrides applies: deny > ask > allow.

If no rules match, the `default_effect` applies.

---

## Policy Composition

Break policies into reusable pieces with `{ "include": "name" }`:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "cwd-access",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "write" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
      ]
    },
    {
      "name": "safe-git",
      "body": [
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "reset" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
      ]
    },
    {
      "name": "main",
      "body": [
        { "include": "cwd-access" },
        { "include": "safe-git" },
        { "rule": { "effect": "allow", "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }] } } } }
      ]
    }
  ]
}
```

Include inlines the referenced policy's rules. Circular includes are rejected at compile time.

---

## Sandbox Policies

Exec rules can attach a **sandbox policy** using the `"sandbox"` key. The sandbox policy defines what filesystem and network access a spawned process gets.

### Named sandbox

For sandbox policies reused across multiple exec rules, define a named policy and reference it by name:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "cargo-env",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "write" }, "path": { "subpath": { "path": { "static": "./target" } } } } } },
        { "rule": { "effect": "allow", "net": { "domain": "*" } } }
      ]
    },
    {
      "name": "git-env",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
      ]
    },
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" } }, "sandbox": { "named": "cargo-env" } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } }, "sandbox": { "named": "git-env" } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
      ]
    }
  ]
}
```

When `cargo build` matches the exec rule, the `"cargo-env"` policy defines the sandbox: the process can read the project, write to `./target`, and has unrestricted network access. When `git status` matches, it gets only read access to the project via `"git-env"`.

Named sandbox references must point to a policy defined in the `"policies"` array of the same file. A compile error is raised if the referenced policy doesn't exist.

### Default behavior

When no `"sandbox"` is specified on an exec allow, the spawned process gets no filesystem/network access beyond bare minimum (deny-all sandbox by default).

### What sandboxes enforce

Sandbox policies constrain **filesystem and network access** at the kernel level — these restrictions are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce **exec-level argument matching** on child processes. If a sandboxed command spawns a subprocess, the subprocess inherits the filesystem and network restrictions but is not checked against exec rules. Tracking issue: [#136](https://github.com/empathic/clash/issues/136).

### Automatic sandbox inclusions

Sandboxes automatically grant access to:

- **Temp directories**: `/tmp`, `/var/tmp` (Linux) or `/private/tmp`, `/private/var/folders` (macOS), plus `$TMPDIR`

### Sandbox network restrictions

Sandbox network access has four modes:

- `{ "rule": { "effect": "allow", "net": { "domain": "*" } } }` — sandbox **allows** all network access (no restrictions)
- `{ "rule": { "effect": "allow", "net": { "domain": { "literal": "localhost" } } } }` — sandbox allows **localhost-only** connections, enforced at the kernel level without a proxy
- `{ "rule": { "effect": "allow", "net": { "domain": { "literal": "domain.com" } } } }` — sandbox allows network access **only to listed domains** via a local HTTP proxy
- No net rule — sandbox **denies** all network access

**Localhost-only mode**: When all allowed domains are loopback addresses (`"localhost"`, `"127.0.0.1"`, `"::1"`), Clash uses a lightweight localhost-only mode that is enforced directly by the OS sandbox without spawning an HTTP proxy. This is useful for processes that need to connect to local development servers but should not access the internet. On macOS, Seatbelt blocks non-localhost connections at the kernel level. On Linux, enforcement is advisory (seccomp cannot filter connect destinations).

**Domain filtering**: Domain-specific net rules like `{ "domain": { "literal": "crates.io" } }` are enforced using a local HTTP proxy. The OS sandbox restricts the process to localhost-only connections, and clash starts a proxy that checks each request against the domain allowlist. Programs that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables (curl, cargo, npm, pip, etc.) are filtered; programs that bypass the proxy can still reach any host on Linux (advisory enforcement). On macOS, Seatbelt blocks non-localhost connections at the kernel level.

Subdomain matching is supported: `{ "domain": { "literal": "github.com" } }` also permits `api.github.com`.

---

## Patterns

### Wildcards

`{ "any": null }` or `"*"` matches anything in that position:

```json
{ "exec": { "bin": { "literal": "git" } } }
{ "fs": { "op": { "single": "read" } } }
{ "net": { "domain": "*" } }
```

### Literals

`{ "literal": "value" }` matches exactly:

```json
{ "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }] } }
{ "net": { "domain": { "literal": "github.com" } } }
```

### Regex

`{ "regex": "pattern" }` for flexible matching:

```json
{ "exec": { "bin": { "regex": "^cargo-.*" } } }
{ "net": { "domain": { "regex": ".*\\.example\\.com" } } }
{ "fs": { "op": { "single": "read" }, "path": { "regex": ".*\\.log" } } }
```

### Glob

`{ "glob": "pattern" }` for glob-style matching:

```json
{ "fs": { "op": { "single": "read" }, "path": { "glob": "**/*.log" } } }
```

---

## Path Filters

### Subpath

Match a directory and everything beneath it:

```json
{ "subpath": { "path": { "env": "PWD" } } }
{ "subpath": { "path": { "static": "/home/user" } } }
```

### Worktree-Aware Subpath

When working in a git worktree, git operations write to the backing repository's `.git/` directory — which is outside the worktree's directory tree. The `"worktree": true` flag on `subpath` tells the compiler to detect this and automatically extend access:

```json
{ "subpath": { "path": { "env": "PWD" }, "worktree": true } }
```

The default policy uses `"worktree": true` on `env PWD` rules so git commands work out of the box in worktrees. If you override the default policy, add `"worktree": true` to your CWD subpath rules if you need git operations to work in worktrees.

### Environment Variables

`{ "env": "NAME" }` is resolved at compile time:

```json
{ "subpath": { "path": { "env": "PWD" } } }
{ "subpath": { "path": { "env": "HOME" } } }
```

### Path Join

```json
{ "subpath": { "path": { "join": [{ "env": "HOME" }, { "static": "/projects" }] } } }
```

---

## Common Recipes

### 1. Conservative (Untrusted Projects)

Deny everything by default, explicitly allow only safe operations:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
      ]
    }
  ]
}
```

### 2. Developer-Friendly

Allow reads and common dev tools, deny destructive operations:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "cwd-access",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "or": ["read", "write"] }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
      ]
    },
    {
      "name": "main",
      "body": [
        { "include": "cwd-access" },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" } } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "npm" } } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "status" }] } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "diff" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "log" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "add" }, { "any": null }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "reset" }, { "any": null }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "sudo" } } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "rm" }, "args": [{ "literal": "-rf" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }, { "literal": "npmjs.com" }] } } } }
      ]
    }
  ]
}
```

### 3. Full Trust with Guardrails

Allow almost everything, but block the truly dangerous:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "allow",
  "policies": [
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "literal": "--force" }, { "any": null }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "reset" }, { "literal": "--hard" }, { "any": null }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "sudo" } } } },
        { "rule": { "effect": "deny", "fs": { "op": { "single": "write" }, "path": { "literal": ".env" } } } },
        { "rule": { "effect": "deny", "fs": { "op": { "single": "write" }, "path": { "subpath": { "path": { "env": "HOME" } } } } } }
      ]
    }
  ]
}
```

### 4. Read-Only Audit

Allow reading only, deny all modifications:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" } } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "cat" } } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "ls" } } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "grep" } } } }
      ]
    }
  ]
}
```

### 5. Sandboxed Build Tools

Allow build tools with constrained sandbox environments:

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "cargo-env",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "write" }, "path": { "subpath": { "path": { "static": "./target" } } } } } },
        { "rule": { "effect": "allow", "net": { "domain": "*" } } }
      ]
    },
    {
      "name": "npm-env",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "write" }, "path": { "subpath": { "path": { "static": "./node_modules" } } } } } },
        { "rule": { "effect": "allow", "net": { "domain": { "literal": "registry.npmjs.org" } } } }
      ]
    },
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" } }, "sandbox": { "named": "cargo-env" } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "npm" } }, "sandbox": { "named": "npm-env" } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
      ]
    }
  ]
}
```

---

## Debugging Policies

### Explain a Decision

Use `clash explain` to see which rule matches a given action:

```bash
clash explain bash "git push origin main"
```

This shows which rules matched, which were skipped, and the final decision.

### View Active Policy

```bash
clash policy show
```

---

## Reference

- [Policy Grammar](./policy-grammar.md) — formal EBNF grammar
- [Policy Semantics](./policy-semantics.md) — compilation pipeline and evaluation algorithm
- [CLI Reference](./cli-reference.md) — full command documentation
