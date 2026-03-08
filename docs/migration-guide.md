# Migration Guide: Legacy Formats to Starlark

As of v2 (February 2026), Clash uses **Starlark** (`.star` files) as its sole policy format. The three legacy formats — Claude Code simple permissions, YAML profiles, and s-expressions — have been removed.

This guide walks through migrating each legacy format to Starlark.

## What changed

The biggest shift isn't syntax — it's the mental model:

| | Legacy formats | Starlark (v2) |
|---|---|---|
| **Unit of control** | Tool names (`Bash`, `Read`, `Write`) | Capabilities (`exec`, `fs`, `net`) |
| **Rule target** | "Allow Bash(git:*)" | "Allow executing git" |
| **Implication** | Rules break when tools change | Rules survive tool renames |
| **Composition** | Profiles with inheritance | Starlark functions + `load()` |
| **Sandbox** | Not available | Kernel-enforced (Landlock/Seatbelt) |

A single `exe("git").allow()` rule covers any agent tool that runs shell commands — you no longer need to know which tool the agent uses.

## Quick start

If you just want to get running:

```bash
# Back up your old policy
cp ~/.clash/policy.star ~/.clash/policy.star.bak 2>/dev/null
cp ~/.clash/policy.yaml ~/.clash/policy.yaml.bak 2>/dev/null

# Generate a new Starlark policy interactively
clash init
```

Or create `~/.clash/policy.star` manually — see the examples below.

## Migrating from s-expressions

S-expression policies used `(effect (domain args...))` syntax inside named policy blocks.

### Default effect

```
# s-expr
(default deny "main")
(policy "main" ...)
```

```python
# Starlark
load("@clash//std.star", "policy")

def main():
    return policy(default = deny, rules = [...])
```

### Exec rules

| S-expression | Starlark |
|---|---|
| `(allow (exec "git" *))` | `exe("git").allow()` |
| `(deny (exec "git" "push" *))` | `exe("git", args = ["push"]).deny()` |
| `(allow (exec "cargo" "test" *))` | `exe("cargo", args = ["test"]).allow()` |

### Filesystem rules

| S-expression | Starlark |
|---|---|
| `(allow (fs read (subpath "/project")))` | `cwd(read = allow)` |
| `(allow (fs (or read write) (subpath ".")))` | `cwd(read = allow, write = allow)` |
| `(allow (fs read (subpath "$HOME/.ssh")))` | `home().child(".ssh", read = allow)` |

### Network rules

| S-expression | Starlark |
|---|---|
| `(allow (net (domain "github.com")))` | `domains({"github.com": allow})` |
| `(deny (net (domain "evil.com")))` | `domains({"evil.com": deny})` |

### Full example

```
# s-expr
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny (exec "git" "push" *))
  (allow (exec "cargo" *))
  (allow (fs read (subpath ".")))
  (allow (net (domain "github.com"))))
```

```python
# Starlark
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

Note the rule order change: in Starlark, **first match wins** within a domain. Put specific denies before broad allows.

## Migrating from Claude Code simple permissions

Claude Code's built-in format used tool-name patterns in JSON settings.

| Simple format | Starlark |
|---|---|
| `"Bash(git:*)"` in allow | `exe("git").allow()` |
| `"Bash(rm:*)"` in deny | `exe("rm").deny()` |
| `"Read(*)"` in allow | `cwd(read = allow)` |
| `"Read(.env)"` in deny | `path(".env", read = deny)` — or omit and rely on `default = deny` |

### Full example

```json
{
  "permissions": {
    "allow": ["Bash(git:*)", "Read(**/*.rs)"],
    "deny": ["Read(.env)", "Bash(rm:*)"]
  }
}
```

```python
# Starlark
load("@clash//std.star", "exe", "policy", "cwd")

def main():
    return policy(default = deny, rules = [
        exe("rm").deny(),
        exe("git").allow(),
        cwd(read = allow),
    ])
```

The `.env` deny is handled naturally by `default = deny` — only the working directory is readable.

## Migrating from YAML profiles

YAML policies used named profiles with inheritance and constraints.

### Profiles become functions

```yaml
# YAML
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

```python
# Starlark
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

### Arg constraints

YAML used `args: ["!--force"]` to forbid specific flags. In Starlark, express this as a deny rule for the specific argument placed before the allow:

```python
exe("git", args = ["push", "--force"]).deny()
exe("git", args = ["reset", "--hard"]).deny()
exe("git").allow()
```

### URL constraints

```yaml
# YAML
allow webfetch *:
  url: ["github.com"]
deny webfetch *:
  url: ["evil.com"]
```

```python
# Starlark
domains({"github.com": allow, "evil.com": deny})
```

## Key differences to remember

1. **Rule order matters.** Starlark uses first-match semantics — put specific denies before broad allows.
2. **Capabilities, not tools.** Use `exe()` instead of naming `Bash`. Use `cwd()` instead of naming `Read`/`Write`.
3. **No profiles.** Use Starlark variables and `load()` for composition instead of profile inheritance.
4. **Sandboxes are new.** You can now attach kernel-enforced sandboxes to exec rules — see the [Policy Writing Guide](policy-guide.md#sandbox-policies).
5. **Validate after migrating.** Run `clash policy validate` to catch syntax errors before they block your session.

## File locations

| Layer | Old path | New path |
|---|---|---|
| User | `~/.clash/policy.yaml` | `~/.clash/policy.star` |
| Project | `<repo>/.clash/policy.yaml` | `<repo>/.clash/policy.star` |

Old `.yaml` files are ignored. Remove them after migrating to avoid confusion.

## Getting help

- `clash init` — generate a starter policy interactively
- `clash policy validate` — check your policy for errors
- `clash policy show` — view the compiled policy
- [Policy Writing Guide](policy-guide.md) — full reference with recipes and examples
