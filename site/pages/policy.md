---
layout: base.njk
title: Policy Language
description: How to write clash policies — effects, domains, patterns, composition, and sandboxes.
permalink: /policy/
---

<h1 class="page-title">Policy Language</h1>
<p class="page-desc">Everything you need to write clash policies. Policies are written in Starlark (<code>.star</code> files) and compiled to JSON IR.</p>

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

<details>
<summary>JSON IR (v5 match tree)</summary>

```json
{ "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } }, "children": [
    { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } }, "children": [
        { "decision": { "allow": null } }
    ] } }
] } }
{ "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "push" } }, "children": [{ "decision": "deny" }] } }
{ "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "commit" } }, "children": [{ "decision": { "ask": null } }] } }
```
</details>

**First match wins.** Within a capability domain, rules are evaluated in order — the first matching rule determines the effect. Put specific rules (like denies) before broad ones (like allows).

---

## Capability domains

Clash controls three capability domains. Rules target capabilities, not tool names — a single rule can cover multiple agent tools.

### Exec — shell commands

```python
exe("git").allow()
exe("git", args = ["push"]).deny()
exe("cargo", args = ["test"]).allow()
exe(["cargo", "rustc"]).allow()  # multiple binaries
```

<details>
<summary>JSON IR (v5 match tree)</summary>

```json
{ "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } }, "children": [
    { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } }, "children": [
        { "decision": { "allow": null } }
    ] } }
] } }
{ "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } }, "children": [
    { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "push" } }, "children": [{ "decision": "deny" }] } }
] } }
{ "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "cargo" } }, "children": [
    { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "test" } }, "children": [{ "decision": { "allow": null } }] } }
] } }
```
</details>

The `exe()` builder matches binary names. The `args` parameter matches positional arguments. More arguments = more specific.

**Scope:** Exec rules evaluate the top-level command the agent invokes. They do not apply to child processes spawned by that command. Sandbox restrictions on filesystem and network access *are* enforced on all child processes at the kernel level.

### Fs — file operations

```python
cwd().allow(read = True)                          # read under working directory
cwd().allow(read = True, write = True)             # read + write under cwd
cwd(follow_worktrees = True).allow(read = True)    # git worktree-aware
home().child(".ssh").allow(read = True)             # read under ~/.ssh
```

<details>
<summary>JSON IR (v5 match tree)</summary>

Filesystem rules are compiled by Starlark into condition nodes that observe tool names and named arguments. The `cwd()` builder generates conditions matching Read/Write/Edit/Glob/Grep tools with path checks via `named_arg` or `nested_field` observables.
</details>

The fs domain maps to agent tools: `Read` / `Glob` / `Grep` → `fs read`, `Write` / `Edit` → `fs write`.

### Net — network access

```python
domains({"github.com": allow})
domains({"github.com": allow, "crates.io": allow})
```

<details>
<summary>JSON IR (v5 match tree)</summary>

Network rules are compiled by Starlark into condition nodes that observe the tool name (WebFetch/WebSearch) and extract the domain via `nested_field` or `named_arg` observables.
</details>

The net domain maps to: `WebFetch` → `net` with the URL's domain, `WebSearch` → `net` with wildcard domain.

### Tool — agent tools

```python
tool("WebSearch").deny()
tool(["Read", "Glob", "Grep"]).allow()
```

The tool domain matches agent tools by name. Use this for tools that don't map to exec/fs/net capabilities (e.g., `Skill`, `Agent`) or when you want to control a tool directly.

---

## Patterns (v5 match tree)

In the v5 match tree IR, patterns are used inside condition nodes to match against observable values.

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

When a request matches rules in multiple capability domains, deny-overrides applies across domains: deny > ask > allow.

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
load("@clash//std.star", "exe", "policy", "cwd", "domains")
load("safe_git.star", "safe_git_rules")

def main():
    return policy(default = deny, rules = [
        cwd(follow_worktrees = True).allow(read = True, write = True),
        *safe_git_rules,
        domains({"github.com": allow, "crates.io": allow}),
    ])
```

<details>
<summary>Compiled JSON IR (v5 match tree)</summary>

In v5, composition happens at the Starlark level — the compiled output is a flat match tree with no includes. The tree from the Starlark above would contain condition nodes for git commands (deny push/reset, ask commit, allow others) followed by the remaining rules, all flattened into a single tree array.
</details>

Starlark `load()` imports values from other `.star` files. All composition (function calls, list splicing, imports) resolves at compile time — the v5 JSON IR has no include mechanism.

### Merging policies

The `merge()` method combines two policies. In `a.merge(b)`, `b` is merged on top: `b`'s default effect is used, tree nodes from both are concatenated (`a`'s rules first, then `b`'s), and sandboxes are merged (first defined wins on name conflicts).

```python
load("@clash//builtin.star", "base")
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    my_policy = policy(default = deny, rules = [
        cwd().allow(read = True, write = True),
        exe("git").allow(),
        domains({"github.com": allow}),
    ])
    return my_policy.merge(base)
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
load("@clash//std.star", "exe", "policy", "sandbox", "cwd")

def main():
    cargo_env = sandbox(
        default = deny,
        fs = [cwd().allow(read = True, write = True)],
        net = allow,
    )
    return policy(default = deny, rules = [
        exe("cargo").sandbox(cargo_env).allow(),
    ])
```

Note that `.sandbox(sb)` goes **before** `.allow()` / `.deny()` / `.ask()`.

<details>
<summary>JSON IR (v5 match tree)</summary>

```json
{
  "schema_version": 5,
  "default_effect": "deny",
  "sandboxes": {
    "cargo-env": { "fs": [...], "net": "allow" }
  },
  "tree": [
    { "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } },
        "children": [
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "cargo" } },
              "children": [{ "decision": { "allow": "cargo-env" } }] } }
        ] } }
  ]
}
```

Sandboxes are declared in the top-level `sandboxes` map and referenced by name in decision nodes.
</details>

### What sandboxes enforce

Sandbox restrictions on **filesystem and network access** are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce exec-level argument matching on child processes.

### Sandbox network modes

- `net = allow` in a sandbox — allows all network access
- `net = [domains({"localhost": allow})]` — localhost-only, enforced at the kernel level
- `net = [domains({"domain.com": allow})]` — domain-filtered via local HTTP proxy
- `net = deny` or omitted — denies all network access

---

## Common recipes

### Conservative (untrusted projects)

```python
load("@clash//std.star", "policy", "cwd")

def main():
    return policy(default = deny, rules = [
        cwd().allow(read = True),
    ])
```

### Developer-friendly

```python
load("@clash//std.star", "exe", "policy", "cwd", "domains")

def main():
    return policy(default = ask, rules = [
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
        domains({"github.com": allow, "crates.io": allow, "npmjs.com": allow}),
    ])
```

### Full trust with guardrails

```python
load("@clash//std.star", "exe", "policy")

def main():
    return policy(default = allow, rules = [
        exe("git", args = ["push", "--force"]).deny(),
        exe("git", args = ["reset", "--hard"]).deny(),
        exe("rm", args = ["-rf"]).deny(),
        exe("sudo").deny(),
        exe("git", args = ["push"]).ask(),
    ])
```

### Sandboxed build tools

```python
load("@clash//std.star", "exe", "policy", "sandbox", "cwd", "domains")

def main():
    cargo_env = sandbox(
        default = deny,
        fs = [cwd().allow(read = True, write = True)],
        net = allow,
    )
    npm_env = sandbox(
        default = deny,
        fs = [cwd().allow(read = True, write = True)],
        net = [domains({"registry.npmjs.org": allow})],
    )
    return policy(default = deny, rules = [
        exe("cargo").sandbox(cargo_env).allow(),
        exe("npm").sandbox(npm_env).allow(),
        cwd().allow(read = True),
    ])
```
