# Migration Guide: S-Expressions to Starlark

Clash v0.4.0 replaces the s-expression policy format (used in v0.3.x) with **Starlark** (`.star` files). Earlier formats — Claude Code simple permissions (v0.1.x) and YAML profiles — are also removed.

This guide shows how to rewrite your existing policy in Starlark.

## What changed

In v0.3.x, policies declared rules inside fixed capability domains using s-expressions:

```
(allow (exec "git" *))        ← "allow" is the effect, "exec" is the domain
(deny (fs write (subpath "/")))
```

In v0.4.0, the policy engine is a **match tree** — a trie of patterns that match against properties of each tool invocation (tool name, arguments, input fields). When a path through the tree reaches a leaf, it produces a decision (allow, deny, or ask) and optionally attaches a **sandbox** that constrains what the spawned process can access at the kernel level.

The Starlark DSL uses `policy()` with a dict and `merge()` for dict composition. Under the hood, every rule is a chain of "observe this value, match it against this pattern, then continue or decide."

| | v0.3.x (s-expressions) | v0.4.0 (Starlark) |
|---|---|---|
| **Model** | Flat rules in fixed capability domains | Match tree: pattern match on invocation → decision |
| **Evaluation** | Domain-grouped, specificity-based | First-match DFS walk through the tree |
| **Composition** | Named policies with `(default ... "name")` | Starlark dicts, `merge()`, `load()` imports |
| **Sandbox** | Not available | Kernel-enforced filesystem + network constraints (Landlock/Seatbelt) |
| **File format** | `.star` (s-expression syntax) | `.star` (Starlark/Python-like syntax) |

## Quick start

```bash
# Back up your old policy
cp ~/.clash/policy.star ~/.clash/policy.star.bak 2>/dev/null

# Generate a new Starlark policy interactively
clash init
```

Or create `~/.clash/policy.star` manually — see the examples below.

## Migrating from s-expressions

### Default effect and policy structure

```
# v0.3.x
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny (exec "git" "push" *)))
```

```python
# v0.4.0
settings(default = deny())

policy("default", {
    "Bash": {
        "git": {
            "push": deny(),
            glob("**"): allow(),
        },
    },
})
```

Named policy blocks (`(policy "main" ...)`) are replaced by a `policy()` call with a dict. The `(default deny "name")` header becomes `settings(default = deny())`.

### Exec rules

| S-expression | Starlark |
|---|---|
| `(allow (exec "git" *))` | `{"Bash": {"git": allow()}}` |
| `(deny (exec "git" "push" *))` | `{"Bash": {"git": {"push": deny()}}}` |
| `(allow (exec "cargo" "test" *))` | `{"Bash": {"cargo": {"test": allow()}}}` |

Policy dicts compile to match tree nodes that observe the tool name (must be `Bash`) and then pattern-match against positional arguments extracted from the command string.

### Filesystem rules

| S-expression | Starlark |
|---|---|
| `(allow (fs read (subpath "/project")))` | `{"Read": allow()}`, `{"Glob": allow()}`, `{"Grep": allow()}` |
| `(allow (fs (or read write) (subpath ".")))` | `{("Read", "Write", "Edit", "Glob", "Grep"): allow()}` |
| `(allow (fs read (subpath "$HOME/.ssh")))` | `{"Bash": {"ssh": allow(sandbox=sandbox(name="ssh", fs={"$HOME/.ssh": allow("r")}))}}` |

Policy dicts match agent tools by name. For path-scoped access, attach a `sandbox(fs=...)` to the `allow()` in the match rule. Working-directory access is expressed as `sandbox(name="cwd", fs={"$PWD": allow("r")})`.

### Network rules

| S-expression | Starlark |
|---|---|
| `(allow (net (domain "github.com")))` | `domains({"github.com": allow()})` |
| `(deny (net (domain "evil.com")))` | `domains({"evil.com": deny()})` |

### Full example

```
# v0.3.x
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny (exec "git" "push" *))
  (allow (exec "cargo" *))
  (allow (fs read (subpath ".")))
  (allow (net (domain "github.com"))))
```

```python
# v0.4.0
settings(default = deny())

policy("default", merge(
    {
        "Bash": {
            "git": {
                "push": deny(),
                glob("**"): allow(),
            },
            "cargo": allow(),
        },
        ("Read", "Glob", "Grep"): allow(),
    },
    domains({"github.com": allow()}),
))
```

**Rule order matters.** In v0.3.x, specificity determined which rule won. In v0.4.0, rules use **first-match semantics** — the first matching rule wins. Put specific denies before broad allows.

## Migrating from Claude Code simple permissions

Claude Code's built-in format (used before Clash, or in v0.1.x with Clash) used tool-name patterns in JSON settings.

| Simple format | Starlark |
|---|---|
| `"Bash(git:*)"` in allow | `{"Bash": {"git": allow()}}` |
| `"Bash(rm:*)"` in deny | `{"Bash": {"rm": deny()}}` |
| `"Read(*)"` in allow | `{("Read", "Glob", "Grep"): allow()}` |
| `"Read(.env)"` in deny | Use `settings(default = deny())` — only explicitly allowed tools can read files |

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
# v0.4.0
settings(default = deny())

policy("default", {
    "Bash": {
        "rm": deny(),
        "git": allow(),
    },
    ("Read", "Glob", "Grep"): allow(),
})
```

The `.env` deny is handled naturally by `settings(default = deny())` — only explicitly allowed tools can read files.

## Migrating from YAML profiles

YAML policies (used in early v0.3.x) had named profiles with inheritance and constraints.

### Profiles become variables and functions

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
# v0.4.0
readonly_rules = {
    ("Read", "Glob", "Grep"): allow(),
}

settings(default = deny())

policy("default", merge(
    readonly_rules,
    {
        "Bash": {
            "git": {
                "push": {"--force": deny()},
                glob("**"): allow(),
            },
            "rm": deny(),
        },
    },
))
```

Profile inheritance (`include: readonly`) becomes `merge()`. For cross-file reuse, use `load()`:

```python
load("readonly.star", "readonly_rules")
```

### Arg constraints

YAML used `args: ["!--force"]` to forbid specific flags. In Starlark, express this as a deny rule for the specific argument placed before the allow:

```python
policy("default", {
    "Bash": {
        "git": {
            "push": {"--force": deny()},
            "reset": {"--hard": deny()},
            glob("**"): allow(),
        },
    },
})
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
domains({"github.com": allow(), "evil.com": deny()})
```

## Key differences to remember

1. **First-match, not specificity.** In v0.3.x, more-specific rules won regardless of order. In v0.4.0, the first matching rule wins — order your rules deliberately.
2. **Match tree, not capability domains.** Policy dicts compile down to a general-purpose match tree. Under the hood, rules pattern-match on observable properties of tool invocations (tool name, arguments, file paths, URLs).
3. **Sandboxes are new.** You can attach kernel-enforced filesystem and network constraints to any exec rule via `allow(sandbox=...)` — see the [Policy Writing Guide](policy-guide.md#sandbox-policies).
4. **No profiles or named policies.** Use Starlark variables, `merge()`, and `load()` imports for composition.
5. **Validate after migrating.** Run `clash policy validate` to catch errors before they block your session.

## File locations

| Layer | Old path | New path |
|---|---|---|
| User | `~/.clash/policy.star` | `~/.clash/policy.star` (same path, new syntax) |
| Project | `<repo>/.clash/policy.star` | `<repo>/.clash/policy.star` |

The file extension is the same (`.star`), but the syntax inside has changed from s-expressions to Starlark. Clash v0.4.0 will not parse s-expression syntax — you must rewrite the contents.

If you had a `.yaml` policy from an earlier format, that is also no longer read. Remove old `.yaml` files after migrating to avoid confusion.

## Getting help

- `clash init` — generate a starter policy interactively
- `clash policy validate` — check your policy for errors
- `clash policy show` — view the compiled policy
- `clash policy migrate` — automatically migrate deprecated `when()`-based policies
- [Policy Writing Guide](policy-guide.md) — full reference with recipes and examples
