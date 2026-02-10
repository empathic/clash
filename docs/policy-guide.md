# Policy Writing Guide

A practical guide to writing clash policies. For formal grammar details, see [policy-grammar.md](./policy-grammar.md). For evaluation semantics, see [policy-semantics.md](./policy-semantics.md).

---

## Quick Start

Clash policies live in `~/.clash/policy.yaml`. Run `clash init` to generate a safe starting policy, or create one manually:

```yaml
default:
  permission: ask
  profile: main

profiles:
  main:
    rules:
      allow read *:
      deny bash git push*:
```

This policy allows all file reads, denies git push, and prompts for everything else.

---

## Policy File Location

| Path | Scope |
|------|-------|
| `~/.clash/policy.yaml` | User-level (applies to all projects) |

The policy file is YAML. Clash reads it on every hook invocation, so changes take effect immediately without restarting Claude Code.

---

## Rule Syntax

Each rule follows the pattern: **effect verb noun**

```yaml
rules:
  allow read *:              # allow reading any file
  deny bash rm -rf *:        # deny rm -rf commands
  ask bash git commit*:      # prompt before git commit
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

The noun is a glob pattern matched against the command string or file path:

| Pattern | Matches |
|---------|---------|
| `*` | Anything |
| `git *` | Any git command |
| `git push*` | `git push`, `git push origin main` |
| `*.env` | `.env`, `staging.env` |
| `src/**/*.rs` | Any Rust file under `src/` |
| `/etc/*` | Files directly in `/etc/` |

Glob wildcards: `*` matches any characters (including `/`), `?` matches a single character.

---

## Precedence

**deny > ask > allow**

If multiple rules match the same action, the strictest effect wins. Rule order in the file does not matter.

```yaml
rules:
  allow read *:          # allow reading anything
  deny read *.env:       # except .env files (deny wins)
```

Here, reading `config.env` is denied even though the first rule allows all reads.

If no rules match, the `default.permission` effect applies (typically `ask`).

---

## Profiles

Profiles group rules into reusable, composable sets. The active profile is set in `default.profile`.

```yaml
default:
  permission: ask
  profile: main

profiles:
  # Rules scoped to the current working directory
  cwd:
    rules:
      allow * *:
        fs:
          all: subpath(.)

  # Deny dangerous git operations
  safe-git:
    rules:
      ask bash git commit*:
      deny bash git push*:
      deny bash git reset --hard*:

  # Compose profiles with include
  main:
    include: [cwd, safe-git]
    rules:
      deny bash sudo *:
```

### How Include Works

`include` merges rules from parent profiles. Parent rules are evaluated alongside the current profile's rules. Multiple includes are supported:

```yaml
main:
  include: [cwd, safe-git, sensitive]
  rules:
    # additional rules specific to main
```

Circular includes are detected at parse time and will produce an error.

---

## Filesystem Constraints

Rules can restrict which files or directories an action applies to using `fs:` constraints. These scope rules by capability:

```yaml
rules:
  allow * *:
    fs:
      all: subpath(.)               # all operations within current directory

  allow read *:
    fs:
      read: subpath(~/.config)      # read-only access to ~/.config
```

### Filter Expressions

| Expression | Meaning |
|-----------|---------|
| `subpath(path)` | Path must be under `path` |
| `literal(path)` | Path must match exactly |
| `regex(pattern)` | Path must match regex |

Combine with operators:

| Operator | Meaning |
|----------|---------|
| `expr & expr` | Both must match (AND) |
| `expr \| expr` | Either can match (OR) |
| `!expr` | Must NOT match (negation) |
| `(expr)` | Grouping |

```yaml
rules:
  allow read *:
    fs:
      read: subpath(~/.ssh) | subpath(~/.aws)     # read from either

  allow * *:
    fs:
      all: subpath(.) & !subpath(./.git)           # cwd except .git
```

### Capabilities

| Capability | Meaning |
|-----------|---------|
| `read` | Read file contents |
| `write` | Modify existing files |
| `create` | Create new files |
| `delete` | Remove files |
| `execute` | Run as programs |
| `all` | All capabilities |

Combine with `+` and `-`:

```yaml
fs:
  read + execute: subpath(.)       # read and execute in cwd
  all - delete: subpath(/tmp)      # everything except delete in /tmp
```

---

## Shell Constraints

For bash rules, you can restrict command structure:

```yaml
rules:
  allow bash git *:
    args:
      - "!--force"                   # forbid --force flag
      - "!--hard"                    # forbid --hard flag
    pipe: false                      # disallow piping (|)
    redirect: false                  # disallow redirects (>, <)
```

- **args with `!` prefix**: forbid that argument (deny if present)
- **args without `!` prefix**: require that argument (deny if absent)
- **pipe: false**: deny commands containing `|`
- **redirect: false**: deny commands containing `>` or `<`

---

## Sandbox Integration

When a bash rule has `fs:` constraints and the effect is `allow`, clash automatically generates a kernel-level sandbox (Landlock on Linux, Seatbelt on macOS) that enforces the filesystem restrictions.

```yaml
rules:
  allow bash cargo *:
    fs:
      read + execute: subpath(.)
      write + create: subpath(./target)
    network: allow
```

This allows `cargo` to read anywhere in the project but only write to `target/`. The sandbox is enforced at the OS level - even if the process tries to escape, the kernel blocks it.

### Network Control

```yaml
network: deny      # block all network access
network: allow     # allow network access (default)
```

### What Happens on Violation

When a sandboxed command tries to access a path outside its allowed scope, the OS returns a permission denied error. Clash translates this into an actionable message explaining which policy rule caused the restriction.

### Limitations

- Sandbox only applies to `bash` commands (not `read`/`write`/`edit` which are handled by Claude Code directly)
- Linux requires kernel 5.13+ for Landlock support
- macOS uses Seatbelt profiles (available on all supported versions)
- Network restrictions are all-or-nothing (no per-host filtering)

---

## Common Recipes

### 1. Conservative (Untrusted Projects)

Deny everything by default, explicitly allow only safe operations:

```yaml
default:
  permission: deny
  profile: main

profiles:
  main:
    rules:
      allow read *:
        fs:
          read: subpath(.)
      ask bash *:
      ask write *:
      ask edit *:
```

### 2. Developer-Friendly

Allow reads and common dev tools, ask for writes, deny destructive operations:

```yaml
default:
  permission: ask
  profile: main

profiles:
  cwd:
    rules:
      allow * *:
        fs:
          all: subpath(.)

  main:
    include: [cwd]
    rules:
      # Allow common dev commands
      allow bash cargo *:
      allow bash npm *:
      allow bash git status:
      allow bash git diff*:
      allow bash git log*:
      allow bash git add *:

      # Ask before committing
      ask bash git commit*:

      # Deny dangerous operations
      deny bash git push*:
      deny bash git reset --hard*:
      deny bash sudo *:
      deny bash rm -rf *:
```

### 3. Full Trust with Guardrails

Allow almost everything, but block the truly dangerous:

```yaml
default:
  permission: allow
  profile: main

profiles:
  main:
    rules:
      deny bash git push --force*:
      deny bash git reset --hard*:
      deny bash rm -rf /*:
      deny bash sudo *:
      deny write *.env:
      deny write ~/.ssh/*:
      deny write ~/.aws/*:
      ask bash git push*:
```

### 4. Read-Only Audit

Allow reading only, deny all modifications:

```yaml
default:
  permission: deny
  profile: main

profiles:
  main:
    rules:
      allow read *:
      allow bash cat *:
      allow bash ls *:
      allow bash find *:
      allow bash grep *:
      deny write *:
      deny edit *:
      deny bash rm *:
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

Use the `/clash:edit` skill in Claude Code to modify your policy with guided prompts, or edit `~/.clash/policy.yaml` directly.

```bash
clash policy add-rule "deny bash rm -rf *"
clash policy remove-rule "allow bash *"
clash policy add-rule "allow bash cargo *" --profile main
```

### Common Issues

**All actions are being asked**: Your default is `ask` and no `allow` rules match. Add specific allow rules or use the `cwd` profile pattern to allow operations within your project.

**A rule is not matching**: Use `clash explain` to check. Common causes:
- Glob pattern does not match the full command string
- An `fs:` constraint is restricting the path
- A deny rule elsewhere is overriding your allow

**Policy parse error on startup**: Check your YAML syntax. Clash reports the line number and what it expected. Empty policy files default to `ask` for everything.

---

## Reference

- [Policy Grammar](./policy-grammar.md) — formal EBNF grammar for the policy format
- [Policy Semantics](./policy-semantics.md) — detailed evaluation algorithm and sandbox generation
- [CLI Reference](./cli-reference.md) — full command documentation
