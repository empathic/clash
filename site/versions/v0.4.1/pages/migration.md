---
layout: base.njk
title: Migration Guide
description: How to migrate from s-expression policies (v0.3.x) to Starlark (v0.4.0).
permalink: /migration/
---

<h1 class="page-title">Migration Guide</h1>
<p class="page-desc">Upgrading from s-expression policies (v0.3.x) to Starlark (v0.4.0).</p>

## What changed

In v0.3.x, policies declared rules inside fixed capability domains using s-expressions:

```
(allow (exec "git" *))        ← effect + domain
```

In v0.4.0, the policy engine is a **match tree** — patterns match against properties of each tool invocation (tool name, arguments, file paths, URLs) and produce a decision. Decisions can optionally attach a **sandbox** that constrains what the spawned process can access at the kernel level.

The Starlark builders (`exe()`, `cwd()`, `domains()`) compile down to match tree nodes. They're ergonomic sugar over a general-purpose pattern matching engine.

| | v0.3.x (s-expressions) | v0.4.0 (Starlark) |
|---|---|---|
| **Model** | Flat rules in fixed domains | Match tree: pattern match → decision |
| **Evaluation** | Specificity-based | First-match (order matters) |
| **Composition** | Named policies | Functions, variables, `load()` |
| **Sandbox** | Not available | Kernel-enforced (Landlock/Seatbelt) |

---

## From s-expressions

### Exec rules

| S-expression | Starlark |
|---|---|
| `(allow (exec "git" *))` | `exe("git").allow()` |
| `(deny (exec "git" "push" *))` | `exe("git", args = ["push"]).deny()` |
| `(allow (exec "cargo" "test" *))` | `exe("cargo", args = ["test"]).allow()` |

### Filesystem rules

| S-expression | Starlark |
|---|---|
| `(allow (fs read (subpath ".")))` | `cwd().allow(read = True)` |
| `(allow (fs (or read write) (subpath ".")))` | `cwd().allow(read = True, write = True)` |
| `(allow (fs read (subpath "$HOME/.ssh")))` | `home().child(".ssh").allow(read = True)` |

### Network rules

| S-expression | Starlark |
|---|---|
| `(allow (net (domain "github.com")))` | `domains({"github.com": allow})` |
| `(deny (net (domain "evil.com")))` | `domains({"evil.com": deny})` |

### Before and after

<div class="migration-compare">

**Before** — v0.3.x s-expression policy:

```
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny (exec "git" "push" *))
  (allow (exec "cargo" *))
  (allow (fs read (subpath ".")))
  (allow (net (domain "github.com"))))
```

**After** — v0.4.0 Starlark policy (`~/.clash/policy.star`):

```python
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = deny, rules = [
        exe("git", args = ["push"]).deny(),
        exe("git").allow(),
        exe("cargo").allow(),
        cwd().allow(read = True),
        domains({"github.com": allow}),
    ])
```

</div>

**Rule order matters.** In v0.3.x, specificity determined which rule won. In v0.4.0, the **first matching rule wins** — put specific denies before broad allows.

---

## From Claude Code simple permissions

Claude Code's built-in format (pre-Clash, or v0.1.x) used tool-name patterns.

| Simple format | Starlark |
|---|---|
| `"Bash(git:*)"` in allow | `exe("git").allow()` |
| `"Bash(rm:*)"` in deny | `exe("rm").deny()` |
| `"Read(*)"` in allow | `cwd().allow(read = True)` |
| `"Read(.env)"` in deny | Use `default = deny` and scope `cwd()` to your project |

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
        cwd().allow(read = True),
    ])
```

</div>

---

## From YAML profiles

YAML policies (early v0.3.x) used named profiles with inheritance.

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
    cwd().allow(read = True),
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

Profile inheritance becomes list splicing. For cross-file reuse, use `load()`:

```python
load("readonly.star", "readonly_rules")
```

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

1. **First-match, not specificity.** In v0.3.x, more-specific rules won regardless of order. In v0.4.0, the first matching rule wins — order matters.
2. **Match tree under the hood.** The builders compile to a trie that pattern-matches on tool invocation properties. Capability domains are sugar, not primitives.
3. **Sandboxes are new.** Attach kernel-enforced filesystem and network constraints to exec rules — see the [policy reference](/policy/#sandbox-policies).
4. **No profiles or named policies.** Use Starlark variables, functions, and `load()` imports.
5. **Validate after migrating.** Run `clash policy validate` to catch errors.

---

## File locations

The file path is the same (`~/.clash/policy.star`), but the syntax inside has changed from s-expressions to Starlark. Clash v0.4.0 will not parse s-expression syntax — you must rewrite the contents.

| Layer | Path |
|---|---|
| User | `~/.clash/policy.star` |
| Project | `<repo>/.clash/policy.star` |

If you had a `.yaml` policy from an earlier format, that is also no longer read. Remove old `.yaml` files after migrating.

---

## Quick start

```bash
# Generate a new policy interactively
clash init

# Or validate an existing .star file
clash policy validate
```

See the [policy language reference](/policy/) for the full Starlark API.
