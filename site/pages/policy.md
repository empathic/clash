---
layout: base.njk
title: Policy Language
description: How to write clash policies — effects, domains, patterns, composition, and sandboxes.
permalink: /policy/
---

<h1 class="page-title">Policy Language</h1>
<p class="page-desc">Everything you need to write clash policies. Policies are written in Starlark (<code>.star</code> files) and compiled to JSON IR.</p>

## Effects

Every rule ends with an effect:

- <span class="badge badge--allow">allow</span> — auto-approve the action
- <span class="badge badge--deny">deny</span> — block the action
- <span class="badge badge--ask">ask</span> — prompt the user for confirmation

```python
exe("git").allow()
exe("git", args = ["push"]).deny()
exe("git", args = ["commit"]).ask()
```

<details>
<summary>JSON IR</summary>

```json
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
{ "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "ask",   "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "commit" }, { "any": null }] } } }
```
</details>

**Deny always wins.** When multiple rules match, deny beats ask beats allow. More specific rules take precedence over less specific rules.

---

## Capability domains

Clash controls three capability domains. Rules target capabilities, not tool names — a single rule can cover multiple agent tools.

### Exec — shell commands

```python
exe("git").allow()
exe("git", args = ["push"]).deny()
exe("cargo", args = ["test"]).allow()
exe(["cargo", "rustc"]).allow()  # multiple binaries
```

<details>
<summary>JSON IR</summary>

```json
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } }
{ "rule": { "effect": "deny",  "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } }
{ "rule": { "effect": "allow", "exec": { "bin": { "literal": "cargo" }, "args": [{ "literal": "test" }, { "any": null }] } } }
```
</details>

The `exe()` builder matches binary names. The `args` parameter matches positional arguments. More arguments = more specific.

**Scope:** Exec rules evaluate the top-level command the agent invokes. They do not apply to child processes spawned by that command. Sandbox restrictions on filesystem and network access *are* enforced on all child processes at the kernel level.

### Fs — file operations

```python
cwd(read = allow)                          # read under working directory
cwd(read = allow, write = allow)           # read + write under cwd
cwd(follow_worktrees = True, read = allow) # git worktree-aware
home().child(".ssh", read = allow)          # read under ~/.ssh
```

<details>
<summary>JSON IR</summary>

```json
{ "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
{ "rule": { "effect": "allow", "fs": { "op": { "or": ["read", "write"] }, "path": { "subpath": { "path": { "env": "PWD" } } } } } }
{ "rule": { "effect": "deny",  "fs": { "op": { "single": "write" }, "path": { "static": ".env" } } } }
```
</details>

The fs domain maps to agent tools: `Read` / `Glob` / `Grep` → `fs read`, `Write` / `Edit` → `fs write`.

### Net — network access

```python
domains({"github.com": allow})
domains({"github.com": allow, "crates.io": allow})
```

<details>
<summary>JSON IR</summary>

```json
{ "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
{ "rule": { "effect": "allow", "net": { "domain": { "or": [{ "literal": "github.com" }, { "literal": "crates.io" }] } } } }
{ "rule": { "effect": "deny",  "net": { "domain": { "regex": ".*\\.evil\\.com" } } } }
```
</details>

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

In Starlark, break policies into reusable pieces using `load()` to import from other `.star` files:

```python
# ~/.clash/safe_git.star
load("@clash//std.star", "exe")

safe_git_rules = [
    exe("git", args = ["push"]).deny(),
    exe("git", args = ["reset"]).deny(),
    exe("git", args = ["commit"]).ask(),
    exe("git").allow(),
]
```

```python
# ~/.clash/policy.star
load("@clash//std.star", "exe", "policy", "cwd", "domains")
load("safe_git.star", "safe_git_rules")

def main():
    return policy(default = deny, rules = [
        cwd(follow_worktrees = True, read = allow, write = allow),
        *safe_git_rules,
        domains({"github.com": allow, "crates.io": allow}),
    ])
```

<details>
<summary>JSON IR (include-based composition)</summary>

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
</details>

Starlark `load()` imports values from other `.star` files. In JSON IR, `{ "include": "name" }` inlines a referenced policy's rules. Circular references are rejected at compile time.

---

## Sandbox policies

Allowed exec rules can carry a sandbox that constrains what the spawned process can access at the kernel level (Landlock on Linux, Seatbelt on macOS).

### Defining a sandbox

In Starlark, use the `sandbox()` builder and attach it to exec rules with `.sandbox()`:

```python
load("@clash//std.star", "exe", "policy", "sandbox", "cwd")

def main():
    cargo_env = sandbox(
        default = deny,
        fs = [cwd(read = allow, write = allow)],
        net = allow,
    )
    return policy(default = deny, rules = [
        exe("cargo").sandbox(cargo_env).allow(),
    ])
```

Note that `.sandbox(sb)` goes **before** `.allow()` / `.deny()` / `.ask()`.

<details>
<summary>JSON IR</summary>

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
</details>

### What sandboxes enforce

Sandbox restrictions on **filesystem and network access** are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce exec-level argument matching on child processes.

### Sandbox network modes

- `net = allow` in a sandbox — allows all network access
- `net = [domains({"localhost": allow})]` — localhost-only, enforced at the kernel level
- `net = [domains({"domain.com": allow})]` — domain-filtered via local HTTP proxy
- `net = deny` or omitted — denies all network access

---

## Common recipes

### Conservative (untrusted projects)

```python
load("@clash//std.star", "policy", "cwd")

def main():
    return policy(default = deny, rules = [
        cwd(read = allow),
    ])
```

### Developer-friendly

```python
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = ask, rules = [
        cwd(follow_worktrees = True, read = allow, write = allow),
        exe(["cargo", "npm"]).allow(),
        exe("git", args = ["status"]).allow(),
        exe("git", args = ["diff"]).allow(),
        exe("git", args = ["log"]).allow(),
        exe("git", args = ["add"]).allow(),
        exe("git", args = ["commit"]).ask(),
        exe("git", args = ["push"]).deny(),
        exe("git", args = ["reset"]).deny(),
        exe("sudo").deny(),
        exe("rm", args = ["-rf"]).deny(),
        domains({"github.com": allow, "crates.io": allow, "npmjs.com": allow}),
    ])
```

### Full trust with guardrails

```python
load("@clash//std.star", "exe", "policy")

def main():
    return policy(default = allow, rules = [
        exe("git", args = ["push", "--force"]).deny(),
        exe("git", args = ["reset", "--hard"]).deny(),
        exe("rm", args = ["-rf"]).deny(),
        exe("sudo").deny(),
        exe("git", args = ["push"]).ask(),
    ])
```

### Sandboxed build tools

```python
load("@clash//std.star", "exe", "policy", "sandbox", "cwd", "domains")

def main():
    cargo_env = sandbox(
        default = deny,
        fs = [cwd(read = allow, write = allow)],
        net = allow,
    )
    npm_env = sandbox(
        default = deny,
        fs = [cwd(read = allow, write = allow)],
        net = [domains({"registry.npmjs.org": allow})],
    )
    return policy(default = deny, rules = [
        exe("cargo").sandbox(cargo_env).allow(),
        exe("npm").sandbox(npm_env).allow(),
        cwd(read = allow),
    ])
```
