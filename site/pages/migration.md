---
layout: base.njk
title: Migration Guide
description: How to migrate from legacy policy formats (s-expressions, YAML, simple permissions) to Starlark.
permalink: /migration/
---

<h1 class="page-title">Migration Guide</h1>
<p class="page-desc">Upgrading from legacy policy formats to Starlark (<code>.star</code>).</p>

## What changed

Clash v2 replaced three legacy formats with a single Starlark policy language. The key shift: rules now target **capabilities** (exec, fs, net) instead of **tool names** (Bash, Read, Write).

| | Legacy | Starlark (v2) |
|---|---|---|
| **Rules target** | Tool names (`Bash`, `Read`) | Capabilities (`exec`, `fs`, `net`) |
| **Composition** | Profiles with inheritance | Functions + `load()` |
| **Sandboxes** | Not available | Kernel-enforced |

---

## From s-expressions

S-expression policies used `(effect (domain args...))` syntax.

### Exec rules

| S-expression | Starlark |
|---|---|
| `(allow (exec "git" *))` | `exe("git").allow()` |
| `(deny (exec "git" "push" *))` | `exe("git", args = ["push"]).deny()` |
| `(allow (exec "cargo" "test" *))` | `exe("cargo", args = ["test"]).allow()` |

### Filesystem rules

| S-expression | Starlark |
|---|---|
| `(allow (fs read (subpath ".")))` | `cwd(read = allow)` |
| `(allow (fs (or read write) (subpath ".")))` | `cwd(read = allow, write = allow)` |
| `(allow (fs read (subpath "$HOME/.ssh")))` | `home().child(".ssh", read = allow)` |

### Network rules

| S-expression | Starlark |
|---|---|
| `(allow (net (domain "github.com")))` | `domains({"github.com": allow})` |
| `(deny (net (domain "evil.com")))` | `domains({"evil.com": deny})` |

### Before and after

<div class="migration-compare">

**Before** — s-expression policy:

```
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny (exec "git" "push" *))
  (allow (exec "cargo" *))
  (allow (fs read (subpath ".")))
  (allow (net (domain "github.com"))))
```

**After** — Starlark policy (`~/.clash/policy.star`):

```python
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = deny, rules = [
        exe("git", args = ["push"]).deny(),
        exe("git").allow(),
        exe("cargo").allow(),
        cwd(read = allow),
        domains({"github.com": allow}),
    ])
```

</div>

Note the order change: Starlark uses **first-match** semantics. Specific denies go before broad allows.

---

## From Claude Code simple permissions

Claude Code's built-in format used tool-name patterns in a JSON allow/deny list.

| Simple format | Starlark |
|---|---|
| `"Bash(git:*)"` in allow | `exe("git").allow()` |
| `"Bash(rm:*)"` in deny | `exe("rm").deny()` |
| `"Read(*)"` in allow | `cwd(read = allow)` |
| `"Read(.env)"` in deny | Use `default = deny` and only allow `cwd()` |

<div class="migration-compare">

**Before:**

```json
{
  "permissions": {
    "allow": ["Bash(git:*)", "Read(**/*.rs)"],
    "deny": ["Read(.env)", "Bash(rm:*)"]
  }
}
```

**After:**

```python
load("@clash//std.star", "exe", "policy", "cwd")

def main():
    return policy(default = deny, rules = [
        exe("rm").deny(),
        exe("git").allow(),
        cwd(read = allow),
    ])
```

</div>

---

## From YAML profiles

YAML policies used named profiles with inheritance and constraints.

### Profiles become functions

<div class="migration-compare">

**Before:**

```yaml
default:
  permission: ask
  profile: dev
profiles:
  readonly:
    rules:
      allow read *:
      deny write *:
  dev:
    include: readonly
    rules:
      allow bash git *:
        args: ["!--force"]
      deny bash rm *:
```

**After:**

```python
load("@clash//std.star", "exe", "policy", "cwd")

readonly_rules = [
    cwd(read = allow),
]

def main():
    return policy(default = deny, rules = [
        *readonly_rules,
        exe("git", args = ["push", "--force"]).deny(),
        exe("git").allow(),
        exe("rm").deny(),
    ])
```

</div>

### URL constraints become domain rules

```yaml
# Before
allow webfetch *:
  url: ["github.com"]
```

```python
# After
domains({"github.com": allow})
```

---

## Key differences

1. **Rule order matters.** First match wins — put specific denies before broad allows.
2. **Capabilities, not tools.** `exe()` replaces `Bash(...)`. `cwd()` replaces `Read(...)`/`Write(...)`.
3. **No profiles.** Use Starlark variables and `load()` imports for reuse.
4. **Sandboxes are new.** Attach kernel-enforced restrictions to exec rules — see the [policy language reference](/policy/#sandbox-policies).
5. **Validate after migrating.** Run `clash policy validate` to catch errors.

---

## File locations

| Layer | Old path | New path |
|---|---|---|
| User | `~/.clash/policy.yaml` | `~/.clash/policy.star` |
| Project | `<repo>/.clash/policy.yaml` | `<repo>/.clash/policy.star` |

Old `.yaml` files are ignored. Delete them after migrating.

---

## Quick start

```bash
# Generate a new policy interactively
clash init

# Or validate an existing .star file
clash policy validate
```

See the [policy language reference](/policy/) for the full Starlark API.
