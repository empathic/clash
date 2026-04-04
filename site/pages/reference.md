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
when({"Bash": {"git": allow()}})
when({"Bash": {"git": {"push": deny()}}})
when({"Bash": {"git": {"commit": ask()}}})
```

**First match wins.** Rules are evaluated in order — the first matching rule determines the effect. Put specific rules (like denies) before broad ones (like allows).

---

## Domains

Clash matches rules across three domains. A single rule can cover multiple tools.

### Exec — shell commands

```python
when({"Bash": {"git": allow()}})
when({"Bash": {"git": {"push": deny()}}})
when({"Bash": {"cargo": {"test": allow()}}})
when({"Bash": {("cargo", "rustc"): allow()}})  # multiple binaries
```

The `when()` function builds rules by nesting tool names, binary names, and subcommands in a dict. Deeper nesting = more specific matching.

**Scope:** Exec rules evaluate the top-level command the agent invokes. They do not apply to child processes spawned by that command. Sandbox restrictions on filesystem and network access *are* enforced on all child processes at the kernel level.

#### Command trees

For commands with many subcommands, `when()` supports nested dicts and tuple keys:

```python
when({"Bash": {"git": {
    "push": deny(),
    ("pull", "fetch"): allow(),
    "remote": {
        "add": ask(),
    },
}}})
```

#### Typed match keys: `Mode()` and `Tool()`

Use `Mode()` to apply different rules based on the agent's current permission mode (e.g. plan mode vs code mode). Use `Tool()` as an explicit alternative to raw strings for tool names:

```python
load("@clash//std.star", "when", "allow", "deny", "Mode", "Tool")

when({
    Mode("plan"): {
        Tool("Read"): allow(),
        Tool("ExitPlanMode"): allow(),
    },
    Tool("Bash"): {"git": allow()},
    "WebSearch": deny(),
})
```

### Fs — file operations

File access for agent tools is controlled via sandboxes. Use `when()` to attach a sandbox to tool rules:

```python
load("@clash//std.star", "allow", "deny", "when", "sandbox", "subpath")

project_sandbox = sandbox(
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),  # project dir, worktree-aware
        "$HOME/.ssh": allow("r"),                                  # read-only ~/.ssh
    },
)

when({("Read", "Glob", "Grep"): allow(sandbox = project_sandbox)})
when({("Write", "Edit"): allow(sandbox = project_sandbox)})
```

The `fs` dict in a sandbox maps path strings (or `subpath()` for worktree support) to capabilities. The fs domain maps to agent tools: `Read` / `Glob` / `Grep` → `fs read`, `Write` / `Edit` → `fs write`.

### Net — network access

```python
domains({"github.com": allow()})
domains({"github.com": allow(), "crates.io": allow()})
```

The net domain maps to: `WebFetch` → `net` with the URL's domain, `WebSearch` → `net` with wildcard domain.

### Tool — agent tools

```python
when({"WebSearch": deny()})
when({("Read", "Glob", "Grep"): allow()})
when({("Skill", "Agent"): allow()})
```

Use `when()` to control agent tools by name. This works for any tool, including those that don't map to exec/fs/net capabilities (e.g., `Skill`, `Agent`).

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
when({"Bash": {"git": {"push": deny()}}})
when({"Bash": {"git": allow()}})
```

`git push origin main` matches the deny first (listed first, matches). `git status` skips the deny (doesn't match "push") and matches the allow.

If the rules were reversed, `git push` would match the allow first and the deny would never fire.

When a request matches rules in multiple domains, deny-overrides applies across domains: deny > ask > allow.

---

## Policy composition

In Starlark, break policies into reusable pieces using `load()` to import from other `.star` files:

```python
# ~/.clash/safe_git.star
load("@clash//std.star", "allow", "ask", "deny", "when")

safe_git_rules = [
    when({"Bash": {"git": {"push": deny()}}}),
    when({"Bash": {"git": {"reset": deny()}}}),
    when({"Bash": {"git": {"commit": ask()}}}),
    when({"Bash": {"git": allow()}}),
]
```

```python
# ~/.clash/policy.star
load("@clash//std.star", "allow", "deny", "domains", "when", "policy", "sandbox", "subpath")
load("safe_git.star", "safe_git_rules")

def main():
    project_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
    )

    return policy(default = deny(), rules = [
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = project_sandbox)}),
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
load("@clash//std.star", "allow", "deny", "domains", "when", "policy", "sandbox", "subpath")

def main():
    project_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
    )

    my_policy = policy(default = deny(), rules = [
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = project_sandbox)}),
        when({"Bash": {"git": allow()}}),
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

In Starlark, use the `sandbox()` builder and pass it to `allow()` / `deny()` / `ask()` via the `sandbox` keyword:

```python
load("@clash//std.star", "allow", "deny", "when", "policy", "sandbox", "subpath")

def main():
    cargo_env = sandbox(
        default = deny(),
        fs = {"$PWD": allow("rwc")},
        net = allow(),
    )
    return policy(default = deny(), rules = [
        when({"Bash": {"cargo": allow(sandbox = cargo_env)}}),
    ])
```

### What sandboxes enforce

Sandbox restrictions on **filesystem and network access** are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce exec-level argument matching on child processes.

### Sandbox network modes

- `net = allow()` in a sandbox — allows all network access
- `net = [domains({"localhost": allow()})]` — localhost-only, enforced at the kernel level
- `net = [domains({"domain.com": allow()})]` — domain-filtered via local HTTP proxy
- `net = deny()` or omitted — denies all network access

---

## Policy settings

The `settings()` function configures global policy behavior. It is optional; defaults apply when omitted.

```python
settings(default=deny(), on_sandbox_violation="stop")
```

### `default`

The default effect when no rule matches. Accepts `allow()`, `deny()`, or `ask()`. Defaults to `"deny"`.

### `default_sandbox`

A sandbox to apply by default to all shell command rules that do not specify their own sandbox.

### `on_sandbox_violation`

Controls model behavior when a sandbox blocks an operation. Added as a parameter to `settings()`:

```python
settings(default=deny(), on_sandbox_violation="stop")
```

Values:
- `"stop"` (default) — Tell the model to stop and suggest a policy fix. Don't retry.
- `"workaround"` — Tell the model to try an alternative approach. If no workaround is possible, suggest the policy fix.
- `"smart"` — Let the model assess context to decide whether to suggest a fix or find an alternative.

### `harness_defaults`

Controls whether clash automatically injects rules that allow the agent to access its own infrastructure directories. Defaults to `True`.

When enabled, clash injects rules at the lowest priority (after all user-defined rules) to allow access to:

| Path | Permissions | Purpose |
|------|-------------|---------|
| `~/.claude/` | read, write, create, delete | Memories, settings, plugin cache, skills |
| `<project>/.claude/` | read only | Project config |
| `<transcript_dir>/` | read, write, create, delete | Session transcripts |

Your rules always take precedence over harness defaults.

```python
settings(harness_defaults=False)  # disable harness defaults
```

Or via environment variable: `CLASH_NO_HARNESS_DEFAULTS=1`.

`clash status` hides harness rules by default and shows a count. Use `clash status --verbose` to see them tagged with `[harness]`.

---

## Common recipes

### Conservative (untrusted projects)

```python
load("@clash//std.star", "allow", "deny", "when", "policy", "sandbox", "subpath")

def main():
    readonly_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("r")},
    )

    return policy(default = deny(), rules = [
        when({("Read", "Glob", "Grep"): allow(sandbox = readonly_sandbox)}),
    ])
```

### Developer-friendly

```python
load("@clash//std.star", "allow", "ask", "deny", "domains", "when", "policy", "sandbox", "subpath")

def main():
    project_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
    )

    return policy(default = ask(), rules = [
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = project_sandbox)}),
        when({"Bash": {
            ("cargo", "npm"): allow(),
            "git": {
                ("status", "diff", "log", "add"): allow(),
                "commit": ask(),
                ("push", "reset"): deny(),
            },
            "sudo": deny(),
            "rm": {"-rf": deny()},
        }}),
        domains({"github.com": allow(), "crates.io": allow(), "npmjs.com": allow()}),
    ])
```

### Full trust with guardrails

```python
load("@clash//std.star", "allow", "ask", "deny", "when", "policy")

def main():
    return policy(default = allow(), rules = [
        when({"Bash": {
            "git": {
                "push": {"--force": deny()},
                "reset": {"--hard": deny()},
            },
            "rm": {"-rf": deny()},
            "sudo": deny(),
        }}),
        when({"Bash": {"git": {"push": ask()}}}),
    ])
```

### Sandboxed build tools

```python
load("@clash//std.star", "allow", "deny", "domains", "when", "policy", "sandbox", "subpath")

def main():
    cargo_env = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
        net = allow(),
    )
    npm_env = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
        net = [domains({"registry.npmjs.org": allow()})],
    )
    readonly_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("r")},
    )
    return policy(default = deny(), rules = [
        when({("Read", "Glob", "Grep"): allow(sandbox = readonly_sandbox)}),
        when({"Bash": {
            "cargo": allow(sandbox = cargo_env),
            "npm": allow(sandbox = npm_env),
        }}),
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
"mode"
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
| Mode | `"mode"` | The agent's current permission mode (e.g. "plan", "code") |
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
