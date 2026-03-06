# Policy Writing Guide

A practical guide to writing clash policies. Clash policies are written in Starlark, a Python-like configuration language. For the built-in API, see the `@clash//std.star` standard library. For evaluation semantics, see [policy-semantics.md](./policy-semantics.md).

---

## Quick Start

Clash policies use Starlark (`.star` files) with three capability domains: **exec** (shell commands), **fs** (file operations), and **net** (network access).

```python
# ~/.clash/policy.star
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = deny, rules = [
        exe("git", args = ["push"]).deny(),
        exe("git").allow(),
        cwd(read = allow, write = allow),
        domains({"github.com": allow}),
    ])
```

This policy allows git commands (except push), file reads and writes under the current directory, and network access to github.com. Everything else is denied.

<details>
<summary>Compiled JSON IR (advanced)</summary>

The Starlark policy above compiles to the following JSON intermediate representation. Users typically do not write this directly.

```json
{
  "schema_version": 4,
  "use": "main",
  "default_effect": "deny",
  "policies": [
    {
      "name": "main",
      "body": [
        { "rule": { "effect": "deny", "exec": { "bin": { "literal": "git" }, "args": [{ "literal": "push" }, { "any": null }] } } },
        { "rule": { "effect": "allow", "exec": { "bin": { "literal": "git" } } } },
        { "rule": { "effect": "allow", "fs": { "op": { "single": "read" }, "path": { "subpath": { "path": { "env": "PWD" } } } } } },
        { "rule": { "effect": "allow", "net": { "domain": { "literal": "github.com" } } } }
      ]
    }
  ]
}
```

</details>

---

## Policy File Location

| Path | Scope |
|------|-------|
| `~/.clash/policy.star` | User-level (applies to all projects) |
| `~/.clash/policy.json` | User-level (JSON IR, also supported) |

Starlark (`.star`) is the preferred format. If both `.star` and `.json` exist, the `.star` file takes precedence. Clash reads the policy on every hook invocation, so changes take effect immediately.

---

## Capability Domains

Clash controls three capability domains, not individual tools. A single rule can cover multiple tools:

### Exec -- Shell Commands

```python
exe("git").allow()
exe("git", args = ["push"]).deny()
exe("cargo", args = ["test"]).allow()
```

The first argument matches the binary name; `args` matches positional arguments. More arguments = more specific.

> **Scope:** Exec rules evaluate the top-level command that Claude Code invokes via the Bash tool. They do not apply to child processes spawned by that command. For example, a deny rule on `git push` prevents Claude from directly running `git push`, but if an allowed command like `make deploy` internally calls `git push`, the deny rule does not fire -- the policy engine only sees the top-level `make` command. Sandbox restrictions for filesystem and network access *are* enforced on all child processes at the kernel level (see [Sandbox Policies](#sandbox-policies)).

### Fs -- File Operations

```python
cwd(read = allow)
cwd(read = allow, write = allow)
home().child(".ssh", read = allow)
path("/etc").deny()
```

The fs domain maps to these tools:
- `Read` -> `fs read`
- `Write` -> `fs write`
- `Edit` -> `fs write`
- `Glob`/`Grep` -> `fs read`

### Net -- Network Access

```python
domains({"github.com": allow})
domains({"github.com": allow, "crates.io": allow})
```

The net domain maps to:
- `WebFetch` -> `net` with the URL's domain
- `WebSearch` -> `net` with wildcard domain

### Tool -- Agent Tools

```python
tool("WebSearch").deny()
tool(["Read", "Glob", "Grep"]).allow()
```

The tool domain matches agent tools by name. Use this for tools that don't map to exec/fs/net capabilities (e.g., `Skill`, `Agent`, `AskUserQuestion`) or when you want to control a tool directly rather than through its capability.

---

## Precedence

Rules use **first-match semantics**: within a capability domain, the first matching rule wins. Order matters — put more specific rules before broader ones.

### Example

```python
exe("git", args = ["push"]).deny()
exe("git").allow()
```

`git push origin main` matches the deny rule first (it's listed first and matches). `git status` skips the deny (doesn't match "push") and matches the allow.

If the rules were reversed, `git push` would match `exe("git").allow()` first and be allowed — the deny would never fire.

### Cross-Domain Resolution

When a request matches rules in multiple capability domains (rare), deny-overrides applies: deny > ask > allow.

If no rules match, the `default` effect applies.

---

## Policy Composition

Starlark policies compose naturally using functions and variables:

```python
load("@clash//std.star", "exe", "policy", "cwd")

def cwd_access():
    return [
        cwd(read = allow, write = allow),
    ]

def safe_git():
    return [
        exe("git", args = ["push"]).deny(),
        exe("git", args = ["reset"]).deny(),
        exe("git").allow(),
    ]

def main():
    return policy(default = deny, rules = [
        *cwd_access(),
        *safe_git(),
        domains({"github.com": allow, "crates.io": allow}),
    ])
```

You can also use `load()` to import from other `.star` files.

---

## Sandbox Policies

Exec rules can attach a **sandbox policy** that defines what filesystem and network access a spawned process gets.

### Defining sandboxes

```python
load("@clash//std.star", "exe", "sandbox", "cwd", "home", "policy", "domains")

def main():
    cargo_env = sandbox(
        default = deny,
        fs = [
            cwd(read = allow),
            path("./target", write = allow),
        ],
        net = allow,
    )

    git_env = sandbox(
        default = deny,
        fs = [
            cwd(read = allow),
        ],
    )

    return policy(default = deny, rules = [
        exe("git", args = ["push"]).deny(),
        exe("cargo").sandbox(cargo_env).allow(),
        exe("git").sandbox(git_env).allow(),
        cwd(read = allow),
        domains({"github.com": allow}),
    ])
```

When `cargo build` matches the exec rule, the `cargo_env` sandbox defines the restrictions: the process can read the project, write to `./target`, and has unrestricted network access. When `git status` matches, it gets only read access to the project via `git_env`.

Note: `.sandbox(sb)` goes **before** `.allow()` / `.deny()` / `.ask()`.

### Pre-built sandboxes

Load pre-built sandbox configurations for common toolchains:

```python
load("@clash//rust.star", "rust_sandbox")

def main():
    return policy(default = deny, rules = [
        exe(["cargo", "rustc"]).sandbox(rust_sandbox).allow(),
    ])
```

### Default behavior

When no sandbox is specified on an exec allow, the spawned process gets no filesystem/network access beyond bare minimum (deny-all sandbox by default).

### What sandboxes enforce

Sandbox policies constrain **filesystem and network access** at the kernel level -- these restrictions are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce **exec-level argument matching** on child processes. If a sandboxed command spawns a subprocess, the subprocess inherits the filesystem and network restrictions but is not checked against exec rules. Tracking issue: [#136](https://github.com/empathic/clash/issues/136).

### Automatic sandbox inclusions

Sandboxes automatically grant access to:

- **Temp directories**: `/tmp`, `/var/tmp` (Linux) or `/private/tmp`, `/private/var/folders` (macOS), plus `$TMPDIR`

### Sandbox network restrictions

Sandbox network access has four modes:

- `net = allow` -- sandbox **allows** all network access (no restrictions)
- Localhost-only -- sandbox allows **localhost-only** connections, enforced at the kernel level without a proxy
- Domain list -- sandbox allows network access **only to listed domains** via a local HTTP proxy
- No net rule -- sandbox **denies** all network access

**Localhost-only mode**: When all allowed domains are loopback addresses (`"localhost"`, `"127.0.0.1"`, `"::1"`), Clash uses a lightweight localhost-only mode that is enforced directly by the OS sandbox without spawning an HTTP proxy. This is useful for processes that need to connect to local development servers but should not access the internet. On macOS, Seatbelt blocks non-localhost connections at the kernel level. On Linux, enforcement is advisory (seccomp cannot filter connect destinations).

**Domain filtering**: Domain-specific net rules are enforced using a local HTTP proxy. The OS sandbox restricts the process to localhost-only connections, and clash starts a proxy that checks each request against the domain allowlist. Programs that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables (curl, cargo, npm, pip, etc.) are filtered; programs that bypass the proxy can still reach any host on Linux (advisory enforcement). On macOS, Seatbelt blocks non-localhost connections at the kernel level.

Subdomain matching is supported: `"github.com"` also permits `api.github.com`.

---

## Starlark API Reference

### Patterns

```python
# Literal match (exact binary name or domain)
exe("git")
domains({"github.com": allow})

# Regex match
exe(regex("^cargo-.*"))

# Multiple binaries
exe(["cargo", "rustc"])

# Chain with .also()
exe("git").also(exe("gh"))
```

### Path Helpers

```python
# Current working directory (with worktree support)
cwd(read = allow, write = allow)
cwd(follow_worktrees = True, read = allow, write = allow)

# Home directory and subdirectories
home().child(".ssh", read = allow)

# Temp directories
tempdir(allow_all = True)

# Arbitrary paths
path("/usr/local", read = allow)
path(env = "CARGO_HOME", read = allow)
```

### Tools

```python
# Deny specific tool
tool("WebSearch").deny()

# Allow multiple tools
tool(["Read", "Glob", "Grep"]).allow()

# Allow a single tool with sandbox
tool("Read").sandbox(my_sandbox).allow()
```

---

## JSON IR Patterns (Advanced Reference)

> Users typically do not write JSON IR directly. This section is a reference for the compiled output format.

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

## JSON IR Path Filters (Advanced Reference)

### Subpath

Match a directory and everything beneath it:

```json
{ "subpath": { "path": { "env": "PWD" } } }
{ "subpath": { "path": { "static": "/home/user" } } }
```

### Worktree-Aware Subpath

When working in a git worktree, git operations write to the backing repository's `.git/` directory -- which is outside the worktree's directory tree. The `"worktree": true` flag on `subpath` tells the compiler to detect this and automatically extend access:

```json
{ "subpath": { "path": { "env": "PWD" }, "worktree": true } }
```

In Starlark, use `cwd(follow_worktrees = True, ...)` to get this behavior.

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

```python
load("@clash//std.star", "policy", "cwd")

def main():
    return policy(default = deny, rules = [
        cwd(read = allow),
    ])
```

### 2. Developer-Friendly

Allow reads and common dev tools, deny destructive operations:

```python
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = deny, rules = [
        cwd(read = allow, write = allow),
        exe("cargo").allow(),
        exe("npm").allow(),
        exe("git", args = ["status"]).allow(),
        exe("git", args = ["diff"]).allow(),
        exe("git", args = ["log"]).allow(),
        exe("git", args = ["add"]).allow(),
        exe("git", args = ["push"]).deny(),
        exe("git", args = ["reset"]).deny(),
        exe("sudo").deny(),
        exe("rm", args = ["-rf"]).deny(),
        domains({"github.com": allow, "crates.io": allow, "npmjs.com": allow}),
    ])
```

### 3. Full Trust with Guardrails

Allow almost everything, but block the truly dangerous:

```python
load("@clash//std.star", "exe", "policy", "cwd", "home", "path")

def main():
    return policy(default = allow, rules = [
        exe("git", args = ["push", "--force"]).deny(),
        exe("git", args = ["reset", "--hard"]).deny(),
        exe("sudo").deny(),
        path(".env", write = deny),
        home(write = deny),
    ])
```

### 4. Read-Only Audit

Allow reading only, deny all modifications:

```python
load("@clash//std.star", "exe", "policy", "cwd")

def main():
    return policy(default = deny, rules = [
        cwd(read = allow),
        exe("cat").allow(),
        exe("ls").allow(),
        exe("grep").allow(),
    ])
```

### 5. Sandboxed Build Tools

Allow build tools with constrained sandbox environments:

```python
load("@clash//std.star", "exe", "sandbox", "cwd", "path", "policy", "domains")

def main():
    cargo_env = sandbox(
        default = deny,
        fs = [
            cwd(read = allow),
            path("./target", write = allow),
        ],
        net = allow,
    )

    npm_env = sandbox(
        default = deny,
        fs = [
            cwd(read = allow),
            path("./node_modules", write = allow),
        ],
        net = domains({"registry.npmjs.org": allow}),
    )

    return policy(default = deny, rules = [
        exe("cargo").sandbox(cargo_env).allow(),
        exe("npm").sandbox(npm_env).allow(),
        cwd(read = allow),
    ])
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

- `@clash//std.star` -- built-in standard library (loaded via `load()` in policy files)
- [Policy Semantics](./policy-semantics.md) -- compilation pipeline and evaluation algorithm
- [CLI Reference](./cli-reference.md) -- full command documentation
