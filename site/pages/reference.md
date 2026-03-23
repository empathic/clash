---
layout: base.njk
title: Reference
description: Complete reference for Clash policy language, sandboxes, and compiled schema
permalink: /reference/
---

<h1 class="page-title">Reference</h1>
<p class="page-desc">Everything you need to write clash policies. Use Starlark (<code>.star</code>) for expressive, hand-crafted policies. Use <code>policy.json</code> for CLI-driven and tool-managed rules.</p>

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

**First match wins.** Rules are evaluated in order — the first matching rule determines the effect. Put specific rules (like denies) before broad ones (like allows).

---

## Domains

Clash matches rules across three domains. A single rule can cover multiple tools.

### Exec — shell commands

```python
exe("git").allow()
exe("git", args = ["push"]).deny()
exe("cargo", args = ["test"]).allow()
exe(["cargo", "rustc"]).allow()  # multiple binaries
```

The `exe()` builder matches binary names. The `args` parameter matches positional arguments. More arguments = more specific.

**Scope:** Exec rules evaluate the top-level command the agent invokes. They do not apply to child processes spawned by that command. Sandbox restrictions on filesystem and network access *are* enforced on all child processes at the kernel level.

#### Command trees with `cmd()`

For commands with many subcommands, `cmd()` provides a cleaner tree syntax:

```python
cmd("git", {
    "push": deny(),
    ("pull", "fetch"): allow(),
    "remote": {
        "add": ask(),
    },
})
```

### Fs — file operations

```python
cwd().allow(read = True)                          # read under working directory
cwd().allow(read = True, write = True)             # read + write under cwd
cwd(follow_worktrees = True).allow(read = True)    # git worktree-aware
home().child(".ssh").allow(read = True)             # read under ~/.ssh
```

The fs domain maps to agent tools: `Read` / `Glob` / `Grep` → `fs read`, `Write` / `Edit` → `fs write`.

### Net — network access

```python
domains({"github.com": allow()})
domains({"github.com": allow(), "crates.io": allow()})
```

The net domain maps to: `WebFetch` → `net` with the URL's domain, `WebSearch` → `net` with wildcard domain.

### Tool — agent tools

```python
tool("WebSearch").deny()
tool(["Read", "Glob", "Grep"]).allow()
```

The tool domain matches agent tools by name. Use this for tools that don't map to exec/fs/net capabilities (e.g., `Skill`, `Agent`) or when you want to control a tool directly.

---

## Patterns

In the compiled match tree, patterns are used inside condition nodes to match against observable values.

### Wildcard

`"wildcard"` matches anything:

```json
{ "condition": { "observe": "tool_name", "pattern": "wildcard", "children": [{ "decision": { "allow": null } }] } }
```

### Literal

`{ "literal": <value> }` matches a resolved value exactly:

```json
{ "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } }, "children": [...] } }
{ "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } }, "children": [...] } }
```

### Regex

`{ "regex": "pattern" }` for flexible matching:

```json
{ "condition": { "observe": { "positional_arg": 0 }, "pattern": { "regex": "^cargo-.*" }, "children": [...] } }
```

### Combinators

`{ "any_of": [...] }` matches any sub-pattern. `{ "not": <pattern> }` negates:

```json
{ "condition": { "observe": "tool_name", "pattern": { "any_of": [
    { "literal": { "literal": "Read" } },
    { "literal": { "literal": "Glob" } },
    { "literal": { "literal": "Grep" } }
] }, "children": [{ "decision": { "allow": null } }] } }
```

---

## Values

Values appear inside `Literal` patterns and are resolved at eval time:

| Form | JSON | Description |
|---|---|---|
| Literal string | `{ "literal": "git" }` | A constant string value |
| Environment var | `{ "env": "HOME" }` | Resolved from environment at eval time |
| Path join | `{ "path": [{ "env": "HOME" }, { "literal": ".ssh" }] }` | Segments joined with `/` |

---

## Precedence

Rules use **first-match semantics**: the first matching rule wins. Order matters — put specific rules before broad ones.

Example:

```python
exe("git", args = ["push"]).deny()
exe("git").allow()
```

`git push origin main` matches the deny first (listed first, matches). `git status` skips the deny (doesn't match "push") and matches the allow.

If the rules were reversed, `git push` would match the allow first and the deny would never fire.

When a request matches rules in multiple domains, deny-overrides applies across domains: deny > ask > allow.

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
load("@clash//std.star", "allow", "deny", "exe", "policy", "cwd", "domains")
load("safe_git.star", "safe_git_rules")

def main():
    return policy(default = deny(), rules = [
        cwd(follow_worktrees = True).allow(read = True, write = True),
        *safe_git_rules,
        domains({"github.com": allow(), "crates.io": allow()}),
    ])
```

Starlark `load()` imports values from other `.star` files. All composition (function calls, list splicing, imports) resolves at compile time.

### Two formats: `.star` for humans, `.json` for tools

Clash supports two policy formats that serve different purposes:

**Starlark (`.star`)** is for humans. Write expressive policies with functions, variables, imports, and composition. When you want to craft a nuanced policy — conditionals, shared rule sets across projects, sandbox builders — this is the format to use.

**JSON (`policy.json`)** is for tools. CLI commands like `clash policy allow`, `clash policy deny`, and `clash policy remove` read and write `policy.json` directly. It's a machine-readable format designed to be mutated programmatically — by the CLI, by scripts, or by agents themselves.

```json
{
  "default_effect": "deny",
  "includes": [
    { "path": "@clash//builtin.star" },
    { "path": "team-rules.star" }
  ],
  "tree": []
}
```

The `includes` field lets `policy.json` pull in `.star` files, so you can combine CLI-managed rules with hand-written Starlark. Included files are compiled and merged at load time, with inline `tree` rules taking precedence. When both `.json` and `.star` exist at the same level, `.json` wins.

### Updating policies

The `update()` method combines two policies. In `a.update(b)`, `b`'s default effect is used, tree nodes from both are concatenated (`a`'s first, then `b`'s), and sandboxes are merged (first defined wins on name conflicts).

```python
load("@clash//builtin.star", "base")
load("@clash//std.star", "allow", "deny", "exe", "policy", "cwd", "domains")

def main():
    my_policy = policy(default = deny(), rules = [
        cwd().allow(read = True, write = True),
        exe("git").allow(),
        domains({"github.com": allow()}),
    ])
    return base.update(my_policy)
```

### Built-in policy (`@clash//builtin.star`)

The `base` export from `@clash//builtin.star` bundles rules for:

- **Clash CLI** — allows `clash status`, `clash policy list/show/explain`, and `clash bug` with appropriate sandboxes
- **Claude Code tools** — allows interactive tools (`Agent`, `Skill`, `AskUserQuestion`, `ToolSearch`, etc.) with a sandbox scoped to `~/.claude`

Merge with `base` to get sensible defaults. If you don't, you'll need your own rules for these tools.

---

## Sandbox policies

Allowed exec rules can carry a sandbox that constrains what the spawned process can access at the kernel level (Landlock on Linux, Seatbelt on macOS).

### Defining a sandbox

In Starlark, use the `sandbox()` builder and attach it to exec rules with `.sandbox()`:

```python
load("@clash//std.star", "allow", "deny", "exe", "policy", "sandbox", "cwd")

def main():
    cargo_env = sandbox(
        default = deny(),
        fs = [cwd().allow(read = True, write = True)],
        net = allow(),
    )
    return policy(default = deny(), rules = [
        exe("cargo").sandbox(cargo_env).allow(),
    ])
```

Note that `.sandbox(sb)` goes **before** `.allow()` / `.deny()` / `.ask()`.

### What sandboxes enforce

Sandbox restrictions on **filesystem and network access** are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce exec-level argument matching on child processes.

### Sandbox network modes

- `net = allow()` in a sandbox — allows all network access
- `net = [domains({"localhost": allow()})]` — localhost-only, enforced at the kernel level
- `net = [domains({"domain.com": allow()})]` — domain-filtered via local HTTP proxy
- `net = deny()` or omitted — denies all network access

---

## Common recipes

### Conservative (untrusted projects)

```python
load("@clash//std.star", "deny", "policy", "cwd")

def main():
    return policy(default = deny(), rules = [
        cwd().allow(read = True),
    ])
```

### Developer-friendly

```python
load("@clash//std.star", "allow", "ask", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = ask(), rules = [
        cwd(follow_worktrees = True).allow(read = True, write = True),
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
        domains({"github.com": allow(), "crates.io": allow(), "npmjs.com": allow()}),
    ])
```

### Full trust with guardrails

```python
load("@clash//std.star", "allow", "exe", "policy")

def main():
    return policy(default = allow(), rules = [
        exe("git", args = ["push", "--force"]).deny(),
        exe("git", args = ["reset", "--hard"]).deny(),
        exe("rm", args = ["-rf"]).deny(),
        exe("sudo").deny(),
        exe("git", args = ["push"]).ask(),
    ])
```

### Sandboxed build tools

```python
load("@clash//std.star", "allow", "deny", "exe", "policy", "sandbox", "cwd", "domains")

def main():
    cargo_env = sandbox(
        default = deny(),
        fs = [cwd().allow(read = True, write = True)],
        net = allow(),
    )
    npm_env = sandbox(
        default = deny(),
        fs = [cwd().allow(read = True, write = True)],
        net = [domains({"registry.npmjs.org": allow()})],
    )
    return policy(default = deny(), rules = [
        exe("cargo").sandbox(cargo_env).allow(),
        exe("npm").sandbox(npm_env).allow(),
        cwd().allow(read = True),
    ])
```

---

## Policy schema (JSON IR)

JSON IR schema for compiled clash policies. Policies are authored as Starlark (.star) files or managed via `policy.json`, and compiled to this format.

### Document structure

```json
{
  "schema_version": 5,
  "default_effect": "<effect>",
  "sandboxes": { "<name>": <sandbox-policy> },
  "tree": [ <node>, ... ]
}
```

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Internal version identifier |
| `default_effect` | string | Effect when no rule matches: `"allow"`, `"deny"`, or `"ask"` |
| `sandboxes` | object | Named sandbox definitions (may be empty) |
| `tree` | array | Root-level nodes of the match tree |

### Nodes

The tree is a uniform trie of two node types:

#### Condition

Observe a value from the query context, test against a pattern, recurse into children on match:

```json
{ "condition": { "observe": <observable>, "pattern": <pattern>, "children": [ <node>, ... ] } }
```

| Field | Type | Description |
|---|---|---|
| `observe` | observable | What to extract from the query context |
| `pattern` | pattern | What to test the observed value against |
| `children` | array of nodes | Evaluated (in order) if the pattern matches |

#### Decision

A leaf node that produces an effect:

```json
{ "decision": { "allow": null } }
{ "decision": "deny" }
{ "decision": { "ask": null } }
{ "decision": { "allow": "<sandbox-name>" } }
```

| Form | Description |
|---|---|
| `{ "allow": null }` | Allow without sandbox |
| `{ "allow": "<name>" }` | Allow with named sandbox |
| `"deny"` | Deny |
| `{ "ask": null }` | Ask the user |
| `{ "ask": "<name>" }` | Ask the user, with sandbox if approved |

### Observables

What to extract from the query context for pattern matching.

```json
"tool_name"
"hook_type"
"agent_name"
{ "positional_arg": 0 }
"has_arg"
{ "named_arg": "file_path" }
{ "nested_field": ["input", "url"] }
```

| Observable | JSON | Description |
|---|---|---|
| Tool name | `"tool_name"` | The agent tool being invoked (e.g. "Bash", "Read") |
| Hook type | `"hook_type"` | The hook event type |
| Agent name | `"agent_name"` | The agent identifier |
| Positional arg | `{ "positional_arg": N }` | Nth positional argument (0-indexed) |
| Has arg | `"has_arg"` | True if any positional arg matches the pattern |
| Named arg | `{ "named_arg": "key" }` | Value of a named argument |
| Nested field | `{ "nested_field": ["a", "b"] }` | Path into structured tool_input JSON |

### Evaluation

Evaluation is a single DFS pass over the tree:

1. For each node in children (in order):
   - **Decision**: return the decision immediately
   - **Condition**: extract the observable value from the query context, test against the pattern. If it matches, recurse into children. If a child produces a decision, return it. Otherwise, backtrack and try the next sibling.
2. If no node produces a decision, return the `default_effect`.

First-match semantics: the first matching path through the tree wins. Specificity is encoded by sibling order — put more specific conditions before broader ones.
