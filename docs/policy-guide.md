# Policy Writing Guide

A practical guide to writing clash policies. For formal grammar details, see [policy-grammar.md](./policy-grammar.md). For evaluation semantics, see [policy-semantics.md](./policy-semantics.md).

---

## Quick Start

Clash policies use an s-expression format with three capability domains: **exec** (shell commands), **fs** (file operations), and **net** (network access).

```
(default deny "main")

(policy "main"
  (allow (exec "git" *))
  (deny  (exec "git" "push" *))
  (allow (fs read (subpath (env PWD))))
  (allow (net "github.com")))
```

This policy allows git commands (except push), file reads under the current directory, and network access to github.com. Everything else is denied.

---

## Policy File Location

| Path | Scope |
|------|-------|
| `~/.clash/policy` | User-level (applies to all projects) |

Clash reads the policy on every hook invocation, so changes take effect immediately.

---

## Capability Domains

Clash controls three capability domains, not individual tools. A single rule can cover multiple tools:

### Exec — Shell Commands

```
(allow (exec "git" *))              ; allow all git commands
(deny  (exec "git" "push" *))       ; deny git push specifically
(ask   (exec "git" "commit" *))     ; prompt before any rm
(allow (exec "cargo" "test" *))     ; allow cargo test
```

The first pattern matches the binary name, subsequent patterns match positional arguments. More arguments = more specific.

> **Scope:** Exec rules evaluate the top-level command that Claude Code invokes via the Bash tool. They do not apply to child processes spawned by that command. For example, `(deny (exec "git" "push" *))` prevents Claude from directly running `git push`, but if an allowed command like `make deploy` internally calls `git push`, the deny rule does not fire — the policy engine only sees the top-level `make` command. Sandbox restrictions for filesystem and network access *are* enforced on all child processes at the kernel level (see [Sandbox Policies](#sandbox-policies)).

### Fs — File Operations

```
(allow (fs read (subpath (env PWD))))                ; read files under CWD
(allow (fs (or read write) (subpath (env PWD))))     ; read + write under CWD
(deny  (fs write ".env"))                            ; block writing .env
(deny  (fs * (subpath "/etc")))                      ; block all fs ops on /etc
```

The fs domain maps to these tools:
- `Read` → `fs read`
- `Write` → `fs write`
- `Edit` → `fs write`
- `Glob`/`Grep` → `fs read`

### Net — Network Access

```
(allow (net "github.com"))                    ; allow github.com
(allow (net (or "github.com" "crates.io")))   ; allow multiple domains
(deny  (net /.*\.evil\.com/))                 ; deny evil.com subdomains
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

```
(deny  (exec "git" "push" *))    ; specificity: high (literal bin + literal arg + wildcard)
(allow (exec "git" *))           ; specificity: lower (literal bin + wildcard)
```

`git push origin main` matches the deny rule first (more specific). `git status` skips the deny (doesn't match "push") and matches the allow.

### Conflict Detection

If two rules have the same specificity but different effects and could match the same request, the compiler rejects the policy with a conflict error. This prevents ambiguous orderings.

### Cross-Domain Resolution

When a request matches rules in multiple capability domains (rare), deny-overrides applies: deny > ask > allow.

If no rules match, the `default` effect applies.

---

## Policy Composition

Break policies into reusable pieces with `(include ...)`:

```
(default deny "main")

(policy "cwd-access"
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath (env PWD)))))

(policy "safe-git"
  (deny  (exec "git" "push" *))
  (deny  (exec "git" "reset" *))
  (ask   (exec "git" "commit" *))
  (allow (exec "git" *)))

(policy "main"
  (include "cwd-access")
  (include "safe-git")
  (allow (net (or "github.com" "crates.io"))))
```

Include inlines the referenced policy's rules. Circular includes are rejected at compile time.

---

## Sandbox Policies

Exec rules can attach a **sandbox policy** using the `:sandbox` keyword. The sandbox policy defines what filesystem and network access a spawned process gets.

### Inline sandbox

For simple cases, define sandbox rules directly on the exec rule:

```
(allow (exec "clash" "bug" *) :sandbox (allow (net *)))
```

Multiple inline rules are supported:

```
(allow (exec "cargo" "build" *) :sandbox
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath "./target")))
  (allow (net)))
```

### Named sandbox

For sandbox policies reused across multiple exec rules, define a named policy and reference it by name:

```
(default deny "main")

(policy "cargo-env"
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath "./target")))
  (allow (net)))

(policy "git-env"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "cargo" *) :sandbox "cargo-env")
  (allow (exec "git" *)   :sandbox "git-env")
  (allow (fs read (subpath (env PWD))))
  (allow (net "github.com")))
```

When `cargo build` matches the exec rule, the `"cargo-env"` policy defines the sandbox: the process can read the project, write to `./target`, and has unrestricted network access. When `git status` matches, it gets only read access to the project via `"git-env"`.

Named sandbox references must point to a policy defined with `(policy "name" ...)` in the same file. A compile error is raised if the referenced policy doesn't exist.

### Default behavior

When no `:sandbox` is specified on an exec allow, the spawned process gets no filesystem/network access beyond bare minimum (deny-all sandbox by default).

### What sandboxes enforce

Sandbox policies constrain **filesystem and network access** at the kernel level — these restrictions are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce **exec-level argument matching** on child processes. If a sandboxed command spawns a subprocess, the subprocess inherits the filesystem and network restrictions but is not checked against exec rules. Tracking issue: [#136](https://github.com/empathic/clash/issues/136).

### Sandbox network restrictions

Sandbox network access has three modes:

- `(allow (net))` or `(allow (net *))` — sandbox **allows** all network access (no restrictions)
- `(allow (net "domain.com"))` — sandbox allows network access **only to listed domains** via a local HTTP proxy
- No net rule — sandbox **denies** all network access

Domain-specific net rules like `(allow (net "crates.io"))` are enforced using a local HTTP proxy. The OS sandbox restricts the process to localhost-only connections, and clash starts a proxy that checks each request against the domain allowlist. Programs that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables (curl, cargo, npm, pip, etc.) are filtered; programs that bypass the proxy can still reach any host on Linux (advisory enforcement). On macOS, Seatbelt blocks non-localhost connections at the kernel level.

Subdomain matching is supported: `(allow (net "github.com"))` also permits `api.github.com`.

---

## Patterns

### Wildcards

`*` matches anything in that position:

```
(exec "git" *)        ; git with any arguments
(fs read *)           ; read any file (path filter omitted = any)
(net *)               ; any domain
```

### Literals

Quoted strings match exactly:

```
(exec "git" "push")   ; only "git push" with no further args
(net "github.com")     ; only github.com, not subdomain.github.com
```

### Regex

Slash-delimited regex for flexible matching:

```
(exec /^cargo-.*/)              ; cargo-build, cargo-test, cargo-clippy
(net /.*\.example\.com/)        ; any subdomain of example.com
(fs read /.*\.log/)             ; any .log file
```

### Combinators

```
(or "github.com" "crates.io")   ; match either
(not "secret")                   ; match anything except "secret"
```

---

## Path Filters

### Subpath

Match a directory and everything beneath it:

```
(subpath (env PWD))     ; current working directory tree
(subpath "/home/user")   ; fixed path
```

### Environment Variables

`(env NAME)` is resolved at compile time:

```
(subpath (env PWD))    ; → /home/user/project (or wherever you are)
(subpath (env HOME))   ; → /home/user
```

### Path Combinators

```
(or (subpath "/tmp") (subpath (env PWD)))   ; either location
(not (subpath ".git"))                       ; exclude .git
```

---

## Naming Convention

All user-provided names must be **quoted strings**:

```
(default deny "main")             ; policy name is a string
(policy "cwd-access" ...)         ; policy name is a string
(include "cwd-access")            ; include target is a string
(allow (exec "cargo" *) :sandbox "cargo-env")  ; named sandbox ref is a string
```

Bare atoms (`allow`, `deny`, `exec`, `fs`, `net`, `or`, `not`, `subpath`, `env`, `include`, `default`, `policy`) are reserved for language keywords.

---

## Common Recipes

### 1. Conservative (Untrusted Projects)

Deny everything by default, explicitly allow only safe operations:

```
(default deny "main")

(policy "main"
  (allow (fs read (subpath (env PWD))))
  (ask   (exec *)))
```

### 2. Developer-Friendly

Allow reads and common dev tools, ask for writes, deny destructive operations:

```
(default ask "main")

(policy "cwd-access"
  (allow (fs (or read write) (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")

  (allow (exec "cargo" *))
  (allow (exec "npm" *))
  (allow (exec "git" "status"))
  (allow (exec "git" "diff" *))
  (allow (exec "git" "log" *))
  (allow (exec "git" "add" *))
  (ask   (exec "git" "commit" *))
  (deny  (exec "git" "push" *))
  (deny  (exec "git" "reset" *))
  (deny  (exec "sudo" *))
  (deny  (exec "rm" "-rf" *))

  (allow (net (or "github.com" "crates.io" "npmjs.com"))))
```

### 3. Full Trust with Guardrails

Allow almost everything, but block the truly dangerous:

```
(default allow "main")

(policy "main"
  (deny (exec "git" "push" "--force" *))
  (deny (exec "git" "reset" "--hard" *))
  (deny (exec "rm" "-rf" /*))
  (deny (exec "sudo" *))
  (deny (fs write ".env"))
  (deny (fs write (subpath (env HOME))))
  (ask  (exec "git" "push" *)))
```

### 4. Read-Only Audit

Allow reading only, deny all modifications:

```
(default deny "main")

(policy "main"
  (allow (fs read *))
  (allow (exec "cat" *))
  (allow (exec "ls" *))
  (allow (exec "grep" *)))
```

### 5. Sandboxed Build Tools

Allow build tools with constrained sandbox environments:

```
(default deny "main")

(policy "cargo-env"
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath "./target")))
  (allow (net)))

(policy "npm-env"
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath "./node_modules")))
  (allow (net "registry.npmjs.org")))

(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env")
  (allow (exec "npm" *)   :sandbox "npm-env")
  (allow (fs read (subpath (env PWD)))))
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
