# Policy Writing Guide

A practical guide to writing clash policies. For formal grammar details, see [policy-grammar.md](./policy-grammar.md). For evaluation semantics, see [policy-semantics.md](./policy-semantics.md).

---

## Quick Start

Clash policies live in `~/.clash/policy.sexp`. Run `clash init` to generate a safe starting policy, or create one manually:

```scheme
; Default: deny everything not explicitly allowed, use profile "main"
(default deny main)

(profile main
  (allow read *)
  (deny bash "git push*"))
```

This policy allows all file reads, denies git push, and denies everything else.

---

## Policy File Location

| Path | Scope |
|------|-------|
| `~/.clash/policy.sexp` | User-level (applies to all projects) |

Clash reads the policy on every hook invocation, so changes take effect immediately without restarting Claude Code.

---

## Rule Syntax

Each rule follows the pattern: **(effect verb noun)**

```scheme
(allow read *)              ; allow reading any file
(deny bash "rm -rf *")      ; deny rm -rf commands
(ask bash "git commit*")    ; prompt before git commit
```

### Effect

| Effect | Meaning |
|--------|---------|
| `allow` | Permit without asking |
| `deny` | Block the action |
| `ask` | Prompt the user for confirmation |

### Verb

The verb maps to the tool type Claude Code is using:

| Verb | Tool | Examples |
|------|------|----------|
| `bash` | Shell commands | `git status`, `npm test`, `rm -rf /` |
| `read` | File reads | `src/main.rs`, `.env` |
| `write` | File writes | `output.txt`, `config.json` |
| `edit` | File edits | `src/lib.rs`, `package.json` |
| `*` | Any tool | Matches everything |

Custom tool names also work: `task`, `glob`, `grep`, `websearch`, etc.

### Noun

The noun is a glob pattern matched against the command string or file path. Quote nouns that contain spaces:

| Pattern | Matches |
|---------|---------|
| `*` | Anything |
| `"git *"` | Any git command |
| `"git push*"` | `git push`, `git push origin main` |
| `*.env` | `.env`, `staging.env` |
| `"src/**/*.rs"` | Any Rust file under `src/` |

Glob wildcards: `*` matches any characters (including `/`), `?` matches a single character.

---

## Precedence

Clash uses **specificity-aware precedence** to resolve conflicts when multiple rules match:

1. **Deny always wins** — a deny rule overrides everything, regardless of constraints
2. **Constrained beats unconstrained** — among non-deny rules, a rule with active inline constraints (url, args, pipe, redirect) takes precedence over one without
3. **Within the same tier** — `ask > allow`

```scheme
(allow read *)         ; allow reading anything
(deny read *.env)      ; except .env files (deny wins)
```

Here, reading `config.env` is denied even though the first rule allows all reads.

### Constraint specificity in action

```scheme
(allow webfetch *
  (url "github.com"))     ; constrained: only github.com
(ask webfetch *)          ; unconstrained: all URLs
```

A webfetch to `github.com` is **allowed** — the constrained allow rule is more specific and wins. A webfetch to `example.com` triggers **ask** — the constrained allow doesn't match, so the unconstrained ask applies.

If no rules match, the default effect from `(default ...)` applies.

---

## Profiles

Profiles group rules into reusable, composable sets. The active profile is set in the `(default ...)` form.

```scheme
(default ask main)

; Rules scoped to the current working directory
(profile cwd
  (allow (fs read write) (subpath .)))

; Deny dangerous git operations
(profile safe-git
  (ask bash "git commit*")
  (deny bash "git push*")
  (deny bash "git reset --hard*"))

; Compose profiles with include
(profile main
  (include cwd safe-git)
  (deny bash "sudo *"))
```

### How Include Works

`(include ...)` merges rules from parent profiles. Parent rules are evaluated alongside the current profile's rules. Multiple includes are supported:

```scheme
(profile main
  (include cwd safe-git sensitive)
  ; additional rules specific to main
  )
```

Circular includes are detected at parse time and will produce an error.

---

## Filesystem Access (Sandbox-First)

The s-expr format supports **sandbox-first rules** that declare filesystem access and automatically derive tool permissions:

```scheme
(profile main
  ; Filesystem access declarations (auto-derives tool permissions)
  (allow (fs read) (subpath .))          ; → allows read tool for files in cwd
  (allow (fs read write) (subpath .))    ; → allows read, edit, write tools in cwd

  ; Explicit tool rules (overrides / refinements)
  (allow bash *)
  (deny bash "git push*"))
```

### How derivation works

| FS declaration | Derived tool permission |
|---------------|----------------------|
| `(allow (fs read) ...)` | `allow read *` with fs constraint |
| `(allow (fs write) ...)` | `allow edit *` with fs constraint |
| `(allow (fs write) ...)` | `allow write *` with fs constraint |

Explicit tool rules like `(deny bash "git push*")` are overrides applied after derivation.

### Filter Expressions

| Expression | Meaning |
|-----------|---------|
| `(subpath path)` | Path must be under `path` |
| `(literal path)` | Path must match exactly |
| `(regex pattern)` | Path must match regex |

Combine with boolean operators:

```scheme
; Read from either location
(allow (fs read) (or (subpath "~/.ssh") (subpath "~/.aws")))

; CWD except .git
(allow (fs read write) (and (subpath .) (not (subpath "./.git"))))
```

### Capabilities

| Capability | Meaning |
|-----------|---------|
| `read` | Read file contents |
| `write` | Modify existing files |
| `create` | Create new files |
| `delete` | Remove files |
| `execute` | Run as programs |
| `full` | All capabilities |

---

## Shell Constraints

For bash rules, you can restrict command structure:

```scheme
(allow bash "git *"
  (args "--no-force" (not "--hard"))   ; require --no-force, forbid --hard
  (pipe deny)                          ; disallow piping (|)
  (redirect deny))                     ; disallow redirects (>, <)
```

- **`(not "arg")`** in args: forbid that argument (deny if present)
- **bare strings** in args: require that argument (deny if absent)
- **`(pipe deny)`**: deny commands containing `|`
- **`(redirect deny)`**: deny commands containing `>` or `<`

---

## Sandbox Integration

When a bash rule has filesystem constraints and the effect is `allow`, clash automatically generates a kernel-level sandbox (Landlock on Linux, Seatbelt on macOS) that enforces the filesystem restrictions.

### Profile-Level Sandbox

Declare a `(sandbox ...)` block on a profile to apply OS-level sandboxing to all allowed bash commands:

```scheme
(profile main
  (sandbox
    (fs read execute (subpath .))
    (fs write create (subpath "./target"))
    (network deny))

  (allow bash "cargo *")
  (allow bash "git status")
  (deny bash "git push*"))
```

This allows `cargo` to read anywhere in the project but only write to `target/`. Network access is blocked at the kernel level.

### Network Control

```scheme
(sandbox
  (network deny))     ; block all network access
(sandbox
  (network allow))    ; allow network access (default)
```

### What Happens on Violation

When a sandboxed command tries to access a path outside its allowed scope, the OS returns a permission denied error. Clash translates this into an actionable message explaining which policy rule caused the restriction.

### Include Merging

When a profile includes parents, sandbox configs are merged:
- `fs` entries: union (parent entries first, then child)
- `network`: deny wins (if any profile in the chain sets `network deny`, it applies)

### Limitations

- Sandbox only applies to `bash` commands (not `read`/`write`/`edit` which are handled by Claude Code directly)
- Linux requires kernel 5.13+ for Landlock support
- macOS uses Seatbelt profiles (available on all supported versions)
- Network restrictions are all-or-nothing (no per-host filtering)

---

## Common Recipes

### 1. Conservative (Untrusted Projects)

Deny everything by default, explicitly allow only safe operations:

```scheme
(default deny main)

(profile main
  (allow (fs read) (subpath .))
  (ask bash *)
  (ask write *)
  (ask edit *))
```

### 2. Developer-Friendly

Allow reads and common dev tools, ask for writes, deny destructive operations:

```scheme
(default ask main)

(profile cwd-read
  (allow (fs read) (subpath .)))

(profile main
  (include cwd-read)

  ; Allow common dev commands (sandboxed)
  (sandbox
    (fs full (subpath .))
    (network deny))
  (allow bash "cargo *")
  (allow bash "npm *")
  (allow bash "git status")
  (allow bash "git diff*")
  (allow bash "git log*")
  (allow bash "git add *")

  ; Ask before committing
  (ask bash "git commit*")

  ; Deny dangerous operations
  (deny bash "git push*")
  (deny bash "git reset --hard*")
  (deny bash "sudo *")
  (deny bash "rm -rf *"))
```

### 3. Full Trust with Guardrails

Allow almost everything, but block the truly dangerous:

```scheme
(default allow main)

(profile main
  (deny bash "git push --force*")
  (deny bash "git reset --hard*")
  (deny bash "rm -rf /*")
  (deny bash "sudo *")
  (deny write *.env)
  (deny write "~/.ssh/*")
  (deny write "~/.aws/*")
  (ask bash "git push*"))
```

### 4. Read-Only Audit

Allow reading only, deny all modifications:

```scheme
(default deny main)

(profile main
  (allow read *)
  (allow bash "cat *")
  (allow bash "ls *")
  (allow bash "find *")
  (allow bash "grep *")
  (deny write *)
  (deny edit *)
  (deny bash "rm *"))
```

---

## Built-in Profiles

Clash automatically injects two built-in profiles:

- **`__clash_internal__`** — allows reading `~/.clash/` and grants `clash init` / `clash policy` sandbox access
- **`__claude_internal__`** — allows Claude Code meta-tools (AskUserQuestion, ExitPlanMode, task management)

You can override these by defining a profile with the same name in your policy.

---

## Debugging Policies

### Explain a Decision

Use `clash explain` to see which rule matches a given action:

```bash
clash explain bash "git push origin main"
```

This shows:
- Which rules matched and their effects
- Which rules were skipped and why
- The final decision after precedence resolution

### View Active Policy

```bash
clash policy show              # summary of active profile and default
clash policy list-rules        # all rules in the active profile
clash policy list-rules --json # machine-readable output
```

### Modify Policy Interactively

Use the `/clash:edit` skill in Claude Code to modify your policy with guided prompts, or edit `~/.clash/policy.sexp` directly.

```bash
clash policy add-rule "deny bash rm -rf *"
clash policy remove-rule "allow bash *"
clash policy add-rule "allow bash cargo *" --profile main
```

### Common Issues

**All actions are being asked**: Your default is `ask` and no `allow` rules match. Add specific allow rules or use the `cwd` profile pattern to allow operations within your project.

**A rule is not matching**: Use `clash explain` to check. Common causes:
- Glob pattern does not match the full command string
- An fs constraint is restricting the path
- A deny rule elsewhere is overriding your allow

**Policy parse error on startup**: Check your syntax (balanced parentheses, matching quotes). Clash reports the position and what it expected.

---

## Reference

- [Policy Grammar](./policy-grammar.md) — formal EBNF grammar for the policy format
- [Policy Semantics](./policy-semantics.md) — detailed evaluation algorithm and sandbox generation
- [CLI Reference](./cli-reference.md) — full command documentation
