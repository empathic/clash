---
layout: base.njk
title: Policy Language
description: How to write clash policies — effects, domains, patterns, composition, and sandboxes.
permalink: /policy/
---

<h1 class="page-title">Policy Language</h1>
<p class="page-desc">Everything you need to write clash policies. See also the <a href="/policy/grammar/">formal grammar</a>.</p>

## Effects

Every rule starts with an effect:

- <span class="badge badge--allow">allow</span> — auto-approve the action
- <span class="badge badge--deny">deny</span> — block the action
- <span class="badge badge--ask">ask</span> — prompt the user for confirmation

```json
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
{ "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "ask",   "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "commit" }, { "any": null }] } } }
```

**Deny always wins.** When multiple rules match, deny beats ask beats allow. More specific rules take precedence over less specific rules.

---

## Capability domains

Clash controls three capability domains. Rules target capabilities, not tool names — a single rule can cover multiple agent tools.

### Exec — shell commands

```json
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
{ "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" }, "args": [{ "literal": "test" }, { "any": null }] } } }
```

The `bin` field matches the binary name. The `args` array matches positional arguments. More arguments = more specific.

**Scope:** Exec rules evaluate the top-level command the agent invokes. They do not apply to child processes spawned by that command. Sandbox restrictions on filesystem and network access *are* enforced on all child processes at the kernel level.

### Fs — file operations

```json
{ "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
{ "rule": { "effect": "allow", "fs": { "op": { "or": ["read", "write"] }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
{ "rule": { "effect": "deny",  "fs": { "op": { "single": "write" }, "path": { "static": ".env" } } } }
```

The fs domain maps to agent tools: `Read` / `Glob` / `Grep` → `fs read`, `Write` / `Edit` → `fs write`.

### Net — network access

```json
{ "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
{ "rule": { "effect": "allow", "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }] } } } }
{ "rule": { "effect": "deny",  "net": { "domain": { "regex": ".*\\.evil\\.com" } } } }
```

The net domain maps to: `WebFetch` → `net` with the URL's domain, `WebSearch` → `net` with wildcard domain.

---

## Patterns

### Wildcards

`{ "any": null }` matches anything in that position. `"*"` is the shorthand form for domains:

```json
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
{ "rule": { "effect": "allow", "fs": { "op": { "single": "read" } } } }
{ "rule": { "effect": "allow", "net": { "domain": "*" } } }
```

### Literals

`{ "literal": "value" }` matches exactly:

```json
{ "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }] } }
{ "net": { "domain": { "literal": "github.com" } } }
```

### Glob

`{ "glob": "pattern" }` matches using shell glob syntax:

```json
{ "exec": { "bin": { "glob": "cargo-*" } } }
{ "fs": { "op": { "single": "read" }, "path": { "glob": "**/*.log" } } }
```

### Regex

`{ "regex": "pattern" }` for flexible matching:

```json
{ "exec": { "bin": { "regex": "^cargo-.*" } } }
{ "net": { "domain": { "regex": ".*\\.example\\.com" } } }
```

### Combinators

`{ "or": [...] }` matches any of the listed values:

```json
{ "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }] } } }
{ "fs": { "op": { "or": ["read", "write"] } } }
```

---

## Path filters

### Subpath

Match a directory and everything beneath it using `{ "subpath": { "path": ... } }`:

```json
{ "subpath": { "path": { "env": "PWD" } } }
{ "subpath": { "path": { "static": "/home/user" } } }
```

### Environment variables

`{ "env": "NAME" }` is resolved at evaluation time:

```json
{ "subpath": { "path": { "env": "PWD" } } }
{ "subpath": { "path": { "env": "HOME" } } }
```

### Worktree-aware subpath

When working in a git worktree, git operations write to the backing repository's `.git/` directory — which is outside the worktree. The `"worktree": true` flag detects this and automatically extends access:

```json
{ "subpath": { "path": { "env": "PWD" }, "worktree": true } }
```

### Path concatenation

`{ "join": [...] }` concatenates path expressions:

```json
{ "subpath": { "path": { "join": [{ "env": "HOME" }, { "static": "/.clash" }] } } }
```

---

## Precedence

Rules are sorted by **specificity** at compile time. The first matching rule wins.

```
Literal > Glob > Regex > Wildcard
More args > Fewer args
Single op > Or > Any
Literal path > Regex path > Subpath > No path
```

Example:

```json
{ "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
```

`git push origin main` matches the deny first. `git status` skips the deny and matches the allow.

If two rules have the same specificity but different effects, the compiler rejects the policy with a conflict error.

---

## Policy composition

Break policies into reusable pieces with `{ "include": "policy-name" }`:

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
        { "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "reset" }, { "any": null }] } } },
        { "rule": { "effect": "ask",   "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "commit" }, { "any": null }] } } },
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

## Sandbox policies

Allowed exec rules can carry a sandbox that constrains what the spawned process can access at the kernel level (Landlock on Linux, Seatbelt on macOS).

### Named sandbox

For reuse across multiple exec rules, define a sandbox policy and reference it by name:

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
      "name": "main",
      "body": [
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" } }, "sandbox": { "named": "cargo-env" } } }
      ]
    }
  ]
}
```

### What sandboxes enforce

Sandbox restrictions on **filesystem and network access** are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce exec-level argument matching on child processes.

### Sandbox network modes

- `{ "rule": { "effect": "allow", "net": { "domain": "*" } } }` in a sandbox policy — allows all network access
- `{ "rule": { "effect": "allow", "net": { "domain": { "literal": "localhost" } } } }` — localhost-only, enforced at the kernel level
- `{ "rule": { "effect": "allow", "net": { "domain": { "literal": "domain.com" } } } }` — domain-filtered via local HTTP proxy
- No net rule — denies all network access

---

## Common recipes

### Conservative (untrusted projects)

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "ask",   "exec": {} } }
      ]
    }
  ]
}
```

### Developer-friendly

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "ask",
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
        { "rule": { "effect": "ask",   "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "commit" }, { "any": null }] } } },
        { "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "reset" }, { "any": null }] } } },
        { "rule": { "effect": "deny",  "exec": { "bin": { "literal": "sudo" } } } },
        { "rule": { "effect": "deny",  "exec": { "bin": { "literal": "rm" }, "args": [{ "literal": "-rf" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }, { "literal": "npmjs.com" }] } } } }
      ]
    }
  ]
}
```

### Full trust with guardrails

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
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "rm" }, "args": [{ "literal": "-rf" }, { "regex": "/.*" }] } } },
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "sudo" } } } },
        { "rule": { "effect": "deny", "fs": { "op": { "single": "write" }, "path": { "static": ".env" } } } },
        { "rule": { "effect": "ask",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
      ]
    }
  ]
}
```

### Sandboxed build tools

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
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "npm" } },   "sandbox": { "named": "npm-env" } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
      ]
    }
  ]
}
```
