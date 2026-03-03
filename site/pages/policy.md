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

```lisp
(allow (exec "git" *))           ; auto-approve all git commands
(deny  (exec "git" "push" *))   ; block git push
(ask   (exec "git" "commit" *)) ; prompt before commit
```

**Deny always wins.** When multiple rules match, deny beats ask beats allow. More specific rules take precedence over less specific rules.

---

## Capability domains

Clash controls three capability domains. Rules target capabilities, not tool names — a single rule can cover multiple agent tools.

### Exec — shell commands

```lisp
(allow (exec "git" *))              ; allow all git commands
(deny  (exec "git" "push" *))       ; deny git push specifically
(allow (exec "cargo" "test" *))     ; allow cargo test
```

The first pattern matches the binary name, subsequent patterns match positional arguments. More arguments = more specific.

**Scope:** Exec rules evaluate the top-level command the agent invokes. They do not apply to child processes spawned by that command. Sandbox restrictions on filesystem and network access *are* enforced on all child processes at the kernel level.

### Fs — file operations

```lisp
(allow (fs read (subpath (env PWD))))                ; read files under CWD
(allow (fs (or read write) (subpath (env PWD))))     ; read + write under CWD
(deny  (fs write ".env"))                            ; block writing .env
```

The fs domain maps to agent tools: `Read` / `Glob` / `Grep` → `fs read`, `Write` / `Edit` → `fs write`.

### Net — network access

```lisp
(allow (net "github.com"))                    ; allow github.com
(allow (net (or "github.com" "crates.io")))   ; allow multiple domains
(deny  (net /.*\.evil\.com/))                 ; deny evil.com subdomains
```

The net domain maps to: `WebFetch` → `net` with the URL's domain, `WebSearch` → `net` with wildcard domain.

---

## Patterns

### Wildcards

`*` matches anything in that position:

```lisp
(exec "git" *)        ; git with any arguments
(fs read *)           ; read any file
(net *)               ; any domain
```

### Literals

Quoted strings match exactly:

```lisp
(exec "git" "push")   ; only "git push" with no further args
(net "github.com")     ; only github.com
```

### Regex

Slash-delimited regex for flexible matching:

```lisp
(exec /^cargo-.*/)              ; cargo-build, cargo-test, etc.
(net /.*\.example\.com/)        ; any subdomain of example.com
(fs read /.*\.log/)             ; any .log file
```

### Combinators

```lisp
(or "github.com" "crates.io")   ; match either
(not "secret")                   ; match anything except "secret"
```

---

## Path filters

### Subpath

Match a directory and everything beneath it:

```lisp
(subpath (env PWD))     ; current working directory tree
(subpath "/home/user")   ; fixed path
```

### Environment variables

`(env NAME)` is resolved at compile time:

```lisp
(subpath (env PWD))    ; expands to your current directory
(subpath (env HOME))   ; expands to your home directory
```

### Worktree-aware subpath

When working in a git worktree, git operations write to the backing repository's `.git/` directory — which is outside the worktree. The `:worktree` flag detects this and automatically extends access:

```lisp
(subpath :worktree (env PWD))   ; CWD + git worktree dirs (if applicable)
```

### Path concatenation

`(join expr1 expr2 ...)` concatenates path expressions:

```lisp
(subpath (join (env HOME) "/.clash"))   ; e.g. /home/user/.clash
```

### Path combinators

```lisp
(or (subpath "/tmp") (subpath (env PWD)))   ; either location
(not (subpath ".git"))                       ; exclude .git
```

---

## Precedence

Rules are sorted by **specificity** at compile time. The first matching rule wins.

```
Literal > Regex > Wildcard
More args > Fewer args
Single op > Or > Any
Literal path > Regex path > Subpath > No path
```

Example:

```lisp
(deny  (exec "git" "push" *))    ; high specificity
(allow (exec "git" *))           ; lower specificity
```

`git push origin main` matches the deny first. `git status` skips the deny and matches the allow.

If two rules have the same specificity but different effects, the compiler rejects the policy with a conflict error.

---

## Policy composition

Break policies into reusable pieces with `(include ...)`:

```lisp
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

## Sandbox policies

Allowed exec rules can carry a sandbox that constrains what the spawned process can access at the kernel level (Landlock on Linux, Seatbelt on macOS).

### Inline sandbox

```lisp
(allow (exec "cargo" "build" *) :sandbox
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath "./target")))
  (allow (net)))
```

### Named sandbox

For reuse across multiple exec rules:

```lisp
(policy "cargo-env"
  (allow (fs read (subpath (env PWD))))
  (allow (fs write (subpath "./target")))
  (allow (net)))

(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env"))
```

### What sandboxes enforce

Sandbox restrictions on **filesystem and network access** are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce exec-level argument matching on child processes.

### Sandbox network modes

- `(allow (net))` or `(allow (net *))` — allows all network access
- `(allow (net "localhost"))` — localhost-only, enforced at the kernel level
- `(allow (net "domain.com"))` — domain-filtered via local HTTP proxy
- No net rule — denies all network access

---

## Common recipes

### Conservative (untrusted projects)

```lisp
(default deny "main")

(policy "main"
  (allow (fs read (subpath (env PWD))))
  (ask   (exec *)))
```

### Developer-friendly

```lisp
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

### Full trust with guardrails

```lisp
(default allow "main")

(policy "main"
  (deny (exec "git" "push" "--force" *))
  (deny (exec "git" "reset" "--hard" *))
  (deny (exec "rm" "-rf" /*))
  (deny (exec "sudo" *))
  (deny (fs write ".env"))
  (ask  (exec "git" "push" *)))
```

### Sandboxed build tools

```lisp
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
