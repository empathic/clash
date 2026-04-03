# Policy Writing Guide

A practical guide to writing clash policies. Clash policies are written in Starlark, a Python-like configuration language. For the built-in API, see the `@clash//std.star` standard library. For evaluation semantics, see [policy-semantics.md](./policy-semantics.md).

---

## Quick Start

Clash policies use Starlark (`.star` files) with three capability domains: **shell commands** (via `when()`), **fs** (file operations), and **net** (network access).

```python
# ~/.clash/policy.star
load("@clash//std.star", "allow", "deny", "when", "policy", "domains")

def main():
    return policy(default = deny(), rules = [
        when({"Bash": {"git": {"push": deny()}}}),
        when({"Bash": {"git": allow()}}),
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
        domains({"github.com": allow()}),
    ])
```

This policy allows git commands (except push), file reads and writes, and network access to github.com. Everything else is denied.

<details>
<summary>Compiled JSON IR (advanced)</summary>

The Starlark policy above compiles to the following JSON intermediate representation. Users typically do not write this directly.

```json
{
  "schema_version": 5,
  "default_effect": "deny",
  "sandboxes": {},
  "tree": [
    { "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } },
        "children": [
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } },
              "children": [
                { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "push" } },
                    "children": [{ "decision": "deny" }] } },
                { "decision": { "allow": null } }
              ] } }
        ] } },
    { "condition": { "observe": "tool_name", "pattern": "wildcard",
        "children": [{ "decision": { "allow": null } }] } }
  ]
}
```

</details>

---

## Policy File Location

| Path | Scope |
|------|-------|
| `~/.clash/policy.json` | User-level (machine-readable, preferred) |
| `~/.clash/policy.star` | User-level (Starlark, for power users) |
| `<project>/.clash/policy.json` | Project-level (machine-readable, preferred) |
| `<project>/.clash/policy.star` | Project-level (Starlark, for power users) |

JSON (`.json`) is the preferred format. If both `.json` and `.star` exist at the same level, the `.json` file takes precedence. Clash reads the policy on every hook invocation, so changes take effect immediately.

CLI commands like `clash policy allow`, `clash policy deny`, and `clash policy remove` operate on `policy.json` files. If only a `policy.star` exists, these commands will auto-create a `policy.json` that includes the existing `.star` file.

### policy.json Format

The `policy.json` file extends the v5 compiled policy format with an `includes` field for referencing Starlark files:

```json
{
  "schema_version": 5,
  "default_effect": "deny",
  "default_sandbox": "cwd",
  "sandboxes": {},
  "includes": [
    { "path": "@clash//builtin.star" },
    { "path": "team-rules.star" }
  ],
  "tree": []
}
```

- **`includes`** — References to `.star` files that are compiled and merged at load time. Use `@clash//` for stdlib modules or relative paths for local files.
- **`tree`** — Inline rules managed by CLI commands. These take precedence over included rules.
- **`sandboxes`** — Named sandbox definitions, also CLI-managed.

Included `.star` files are evaluated and their rules are appended after the inline `tree` rules, so inline rules always have higher priority.

---

## Capability Domains

Clash controls three capability domains, not individual tools. A single rule can cover multiple tools:

### Shell Commands

```python
when({"Bash": {"git": allow()}})
when({"Bash": {"git": {"push": deny()}}})
when({"Bash": {"cargo": {"test": allow()}}})
```

The `when()` function maps tool names to nested rules. Keys are matched against positional arguments -- deeper nesting = more specific matches.

> **Scope:** Shell command rules evaluate the top-level command that Claude Code invokes via the Bash tool. They do not apply to child processes spawned by that command. For example, a deny rule on `git push` prevents Claude from directly running `git push`, but if an allowed command like `make deploy` internally calls `git push`, the deny rule does not fire -- the policy engine only sees the top-level `make` command. Sandbox restrictions for filesystem and network access *are* enforced on all child processes at the kernel level (see [Sandbox Policies](#sandbox-policies)).

### Fs -- File Operations

File access for Claude Code tools is controlled via `when()` rules. Use `when()` to allow or deny the file-operation tools directly:

```python
when({("Read", "Glob", "Grep"): allow()})                        # read-only
when({("Read", "Write", "Edit", "Glob", "Grep"): allow()})       # read + write
```

To scope filesystem access to specific paths, attach a sandbox to an exec or tool match rule via the `sandbox=` parameter on `allow()`:

```python
when({("Read", "Write", "Edit"): allow(sandbox = sandbox(fs={"$PWD": allow("rwc")}))})
```

The fs domain maps to these tools:
- `Read` -> `fs read`
- `Write` -> `fs write`
- `Edit` -> `fs write`
- `Glob`/`Grep` -> `fs read`

### Net -- Network Access

```python
domains({"github.com": allow()})
domains({"github.com": allow(), "crates.io": allow()})
```

The net domain maps to:
- `WebFetch` -> `net` with the URL's domain
- `WebSearch` -> `net` with wildcard domain

### Tool -- Agent Tools

```python
when({"WebSearch": deny()})
when({("Read", "Glob", "Grep"): allow()})
```

The tool domain matches agent tools by name via `when()`. Use this for tools that don't map to exec/fs/net capabilities (e.g., `Skill`, `Agent`, `AskUserQuestion`) or when you want to control a tool directly rather than through its capability.

---

## Precedence

Rules use **first-match semantics**: within a capability domain, the first matching rule wins. Order matters — put more specific rules before broader ones.

### Example

```python
when({"Bash": {"git": {"push": deny()}}})
when({"Bash": {"git": allow()}})
```

`git push origin main` matches the deny rule first (it's listed first and matches). `git status` skips the deny (doesn't match "push") and matches the allow.

If the rules were reversed, `git push` would match the `allow()` first and be allowed — the deny would never fire.

### Cross-Domain Resolution

When a request matches rules in multiple capability domains (rare), deny-overrides applies: deny > ask > allow.

If no rules match, the `default` effect applies.

---

## Policy Composition

Starlark policies compose naturally using functions and variables:

```python
load("@clash//std.star", "allow", "deny", "when", "policy", "domains")

def file_access():
    return [
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
    ]

def safe_git():
    return [
        when({"Bash": {"git": {"push": deny()}}}),
        when({"Bash": {"git": {"reset": deny()}}}),
        when({"Bash": {"git": allow()}}),
    ]

def main():
    return policy(default = deny(), rules = [
        *file_access(),
        *safe_git(),
        domains({"github.com": allow(), "crates.io": allow()}),
    ])
```

You can also use `load()` to import from other `.star` files.

### Updating Policies

The `update()` method combines two policies. In `a.update(b)`, `b`'s default effect is used, tree nodes from both are concatenated (`a`'s first, then `b`'s), and sandboxes are merged (first defined wins on name conflicts).

```python
load("@clash//builtin.star", "base")
load("@clash//std.star", "allow", "deny", "when", "policy", "domains")

def main():
    my_policy = policy(default = deny(), rules = [
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
        when({"Bash": {"git": allow()}}),
        domains({"github.com": allow()}),
    ])
    return base.update(my_policy)
```

The `base` policy from `@clash//builtin.star` includes built-in rules for clash CLI commands and Claude Code interactive tools (Agent, Skill, etc.). Updating `base` with your policy ensures these tools work correctly alongside your custom rules.

### Built-in Policy (`@clash//builtin.star`)

The `@clash//builtin.star` module exports a `base` policy that bundles rules for:

- **Clash CLI** — allows `clash status`, `clash policy list`, `clash policy show`, `clash explain`, and `clash bug` with appropriate sandboxes
- **Claude Code tools** — allows interactive tools (`Agent`, `AskUserQuestion`, `EnterPlanMode`, `Skill`, `ToolSearch`, etc.) with a sandbox scoped to `~/.claude`

Load and update it with your policy to get sensible defaults for these tools:

```python
load("@clash//builtin.star", "base")
```

If you don't use `base`, you'll need to write your own rules for clash CLI commands and Claude Code interactive tools.

---

## Sandbox Policies

Shell command rules can attach a **sandbox policy** that defines what filesystem and network access a spawned process gets.

### Defining sandboxes

```python
load("@clash//std.star", "allow", "deny", "when", "sandbox", "policy", "domains")

def main():
    cargo_env = sandbox(
        default = deny(),
        fs = {
            "$PWD": allow("r"),
            "$PWD/target": allow("rwcd"),
        },
        net = allow(),
    )

    git_env = sandbox(
        default = deny(),
        fs = {
            "$PWD": allow("r"),
        },
    )

    return policy(default = deny(), rules = [
        when({"Bash": {"git": {"push": deny()}}}),
        when({"Bash": {"cargo": allow(sandbox = cargo_env)}}),
        when({"Bash": {"git": allow(sandbox = git_env)}}),
        when({("Read", "Glob", "Grep"): allow()}),
        domains({"github.com": allow()}),
    ])
```

When `cargo build` matches the shell command rule, the `cargo_env` sandbox defines the restrictions: the process can read the project, write to `./target`, and has unrestricted network access. When `git status` matches, it gets only read access to the project via `git_env`.

Note: Pass the sandbox via the `sandbox=` parameter on `allow()`, e.g. `allow(sandbox = my_sandbox)`.

### Sandbox presets

Intent-based sandbox presets express what you trust a command to do:

| Preset | Filesystem | Network | Use case |
|---|---|---|---|
| `restricted` | Read-only project | Deny | Untrusted scripts |
| `read_only` | Read project + home, write temp | Deny | Linters, analyzers |
| `dev` | Read+write project, read home | Deny | Build tools, git |
| `dev_network` | Read+write project, read home | Allow | Package managers, gh |
| `unrestricted` | Full project + home access | Allow | Fully trusted tools |

```python
load("@clash//sandboxes.star", "dev", "dev_network")

def main():
    return policy(default = deny(), rules = [
        when({"Bash": {"gh": allow(sandbox = dev_network)}}),
        when({"Bash": {"git": allow(sandbox = dev)}}),
        when({"Bash": allow(sandbox = dev)}),
    ])
```

### Language-specific sandboxes

Load pre-built sandbox configurations for common toolchains:

```python
load("@clash//rust.star", "rust_sandbox")

def main():
    return policy(default = deny(), rules = [
        when({"Bash": {("cargo", "rustc"): allow(sandbox = rust_sandbox)}}),
    ])
```

### Default behavior

When no sandbox is specified on a shell command allow, the spawned process gets no filesystem/network access beyond bare minimum (deny-all sandbox by default).

### What sandboxes enforce

Sandbox policies constrain **filesystem and network access** at the kernel level -- these restrictions are inherited by all child processes and cannot be bypassed. However, sandboxes do not enforce **argument matching** on child processes. If a sandboxed command spawns a subprocess, the subprocess inherits the filesystem and network restrictions but is not checked against shell command rules. Tracking issue: [#136](https://github.com/empathic/clash/issues/136).

### Automatic sandbox inclusions

Sandboxes automatically grant access to:

- **Temp directories**: `/tmp`, `/var/tmp` (Linux) or `/private/tmp`, `/private/var/folders` (macOS), plus `$TMPDIR`

### Sandbox network restrictions

Sandbox network access has four modes:

- `net = allow()` -- sandbox **allows** all network access (no restrictions)
- Localhost-only -- sandbox allows **localhost-only** connections, enforced at the kernel level without a proxy
- Domain list -- sandbox allows network access **only to listed domains** via a local HTTP proxy
- No net rule -- sandbox **denies** all network access

**Localhost-only mode**: When all allowed domains are loopback addresses (`"localhost"`, `"127.0.0.1"`, `"::1"`), Clash uses a lightweight localhost-only mode that is enforced directly by the OS sandbox without spawning an HTTP proxy. This is useful for processes that need to connect to local development servers but should not access the internet. On macOS, Seatbelt blocks non-localhost connections at the kernel level. On Linux, enforcement is advisory (seccomp cannot filter connect destinations).

**Domain filtering**: Domain-specific net rules are enforced using a local HTTP proxy. The OS sandbox restricts the process to localhost-only connections, and clash starts a proxy that checks each request against the domain allowlist. Programs that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables (curl, cargo, npm, pip, etc.) are filtered; programs that bypass the proxy can still reach any host on Linux (advisory enforcement). On macOS, Seatbelt blocks non-localhost connections at the kernel level.

Subdomain matching is supported: `"github.com"` also permits `api.github.com`.

---

## Starlark API Reference

### Patterns

```python
# Literal match (exact binary name or domain)
when({"Bash": {"git": allow()}})
domains({"github.com": allow()})

# Regex match
when({"Bash": {regex("^cargo-.*"): allow()}})

# Multiple binaries
when({"Bash": {("cargo", "rustc"): allow()}})

# Nested argument matching (tree builder)
when({"Bash": {"git": {"push": deny(), "pull": allow()}}})
```

### Platform Constants

```python
load("@clash//std.star", "allow", "when", "OS", "ARCH")

# OS is "macos" or "linux"; ARCH is "aarch64" or "x86_64"
if OS == "linux":
    extra_rules = [when({("Read", "Glob", "Grep"): allow()})]
else:
    extra_rules = []
```

Use `OS` and `ARCH` to write policies that compile differently per platform.

### Sandbox `fs=` Path Keys

In `sandbox(fs=...)` parameters, use the dict API with bare strings or `subpath()` / `literal()` / `regex()` as keys:

```python
sandbox(default = deny(), fs = {
    # Bare string: matches path and all descendants (subpath)
    "$PWD": allow("rwc"),

    # subpath() with follow_worktrees for git worktree support
    subpath("$PWD", follow_worktrees = True): allow("rwc"),

    # Nested dict: path concatenation — equivalent to "$HOME/.cargo" and "$HOME/.ssh"
    "$HOME": {
        ".cargo": allow("rwc"),
        ".ssh": allow("r"),
    },

    # Temp directory
    "$TMPDIR": allow(),

    # Arbitrary absolute path
    "/usr/local": allow("r"),

    # literal() for exact path match (no descendants)
    literal("/etc/hosts"): allow("r"),

    # regex() for pattern match
    regex("^/opt/.*"): allow("r"),
})
```

Key rules for the dict API:
- **Bare string + decision value** — subpath (path and all descendants)
- **Bare string + nested dict** — literal join point (the string is concatenated as a prefix into child keys)
- **`subpath(path, follow_worktrees=True)`** — subpath with git worktree support
- **`literal(path)`** — exact path match only
- **`regex(pattern)`** — regex match

### Capability Shorthand

The `allow()` function accepts a shorthand string of capability letters for use in sandbox `fs=` dicts:

| Letter | Capability |
|--------|-----------|
| `r` | read |
| `w` | write |
| `c` | create |
| `d` | delete |
| `x` | execute |

```python
allow("r")       # read only
allow("rw")      # read + write
allow("rwc")     # read + write + create
allow("rwcd")    # read + write + create + delete
allow("rwcdx")   # all capabilities
allow()          # all capabilities (no args)
```

The kwargs form still works and is equivalent:

```python
allow(read = True, write = True, create = True)  # same as allow("rwc")
```

### Tools

```python
# Deny specific tool
when({"WebSearch": deny()})

# Allow multiple tools
when({("Read", "Glob", "Grep"): allow()})

# Allow a single tool with sandbox
when({"Read": allow(sandbox = my_sandbox)})
```

### Docstrings

Annotate rules and sandboxes with `doc=` to explain *why* they exist. Docstrings persist through the compiled IR and appear in `clash status` output.

```python
# On tool rules
tool("WebSearch", doc = "No external searches needed").deny()

# On sandboxes
sandbox(
    name = "dev",
    doc = "Development sandbox for project work",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$HOME/.ssh": allow("r"),
    },
)
```

### Policy settings

The `settings()` function configures global policy behavior. It is optional; defaults apply when omitted.

```python
settings(default=deny(), on_sandbox_violation="stop")
```

#### `default`

The default effect when no rule matches. Accepts `allow()`, `deny()`, or `ask()`. Defaults to `"deny"`.

#### `default_sandbox`

A sandbox to apply by default to all shell command rules that do not specify their own sandbox.

#### `on_sandbox_violation`

Controls model behavior when a sandbox blocks an operation.

Values:
- `"stop"` (default) — Tell the model to stop and suggest a policy fix. Don't retry.
- `"workaround"` — Tell the model to try an alternative approach. If no workaround is possible, suggest the policy fix.
- `"smart"` — Let the model assess context to decide whether to suggest a fix or find an alternative.

```python
settings(default=deny(), on_sandbox_violation="workaround")
```

---

## JSON IR Reference (Advanced)

> Users typically do not write JSON IR directly. This section is a reference for the compiled output format (schema v5).

### Document Structure

```json
{
  "schema_version": 5,
  "default_effect": "deny",
  "sandboxes": {},
  "tree": [ <node>, ... ]
}
```

The tree is an array of `Node` values. Each node is either a `condition` (observe + pattern + children) or a `decision` (allow/deny/ask).

### Nodes

**Condition** — observe a value from the query context and test it against a pattern:

```json
{ "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } }, "children": [...] } }
{ "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } }, "children": [...] } }
```

**Decision** — a leaf that produces an effect:

```json
{ "decision": { "allow": null } }
{ "decision": "deny" }
{ "decision": { "ask": null } }
{ "decision": { "allow": "my-sandbox" } }
```

### Observables

| Observable | JSON | Description |
|---|---|---|
| Tool name | `"tool_name"` | The agent tool name (e.g. "Bash", "Read") |
| Hook type | `"hook_type"` | The hook event type |
| Agent name | `"agent_name"` | The agent identifier |
| Positional arg | `{ "positional_arg": N }` | Nth positional argument (0-indexed) |
| Has arg | `"has_arg"` | Scan all args, true if any matches |
| Named arg | `{ "named_arg": "key" }` | A named argument by key |
| Nested field | `{ "nested_field": ["a", "b"] }` | Path into structured tool_input JSON |

### Patterns

| Pattern | JSON | Description |
|---|---|---|
| Wildcard | `"wildcard"` | Matches anything |
| Literal | `{ "literal": { "literal": "value" } }` | Exact string match |
| Env literal | `{ "literal": { "env": "PWD" } }` | Match against env var value |
| Regex | `{ "regex": "^cargo-.*" }` | Regular expression match |
| AnyOf | `{ "any_of": [<pattern>, ...] }` | Match any sub-pattern |
| Not | `{ "not": <pattern> }` | Negated match |

### Values

Values appear inside `Literal` patterns and resolve at eval time:

```json
{ "literal": "git" }
{ "env": "HOME" }
{ "path": [{ "env": "HOME" }, { "literal": ".ssh" }] }
```

---

## Common Recipes

### 1. Conservative (Untrusted Projects)

Deny everything by default, explicitly allow only safe operations:

```python
load("@clash//std.star", "allow", "deny", "when", "policy")

def main():
    return policy(default = deny(), rules = [
        when({("Read", "Glob", "Grep"): allow()}),
    ])
```

### 2. Developer-Friendly

Allow reads and common dev tools, deny destructive operations:

```python
load("@clash//std.star", "allow", "deny", "when", "policy", "domains")

def main():
    return policy(default = deny(), rules = [
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
        when({"Bash": {"cargo": allow()}}),
        when({"Bash": {"npm": allow()}}),
        when({"Bash": {"git": {
            "status": allow(),
            "diff": allow(),
            "log": allow(),
            "add": allow(),
            "push": deny(),
            "reset": deny(),
        }}}),
        when({"Bash": {"sudo": deny()}}),
        when({"Bash": {"rm": {"-rf": deny()}}}),
        domains({"github.com": allow(), "crates.io": allow(), "npmjs.com": allow()}),
    ])
```

### 3. Full Trust with Guardrails

Allow almost everything, but block the truly dangerous:

```python
load("@clash//std.star", "allow", "deny", "when", "policy")

def main():
    return policy(default = allow(), rules = [
        when({"Bash": {"git": {"push": {"--force": deny()}}}}),
        when({"Bash": {"git": {"reset": {"--hard": deny()}}}}),
        when({"Bash": {"sudo": deny()}}),
    ])
```

### 4. Read-Only Audit

Allow reading only, deny all modifications:

```python
load("@clash//std.star", "allow", "deny", "when", "policy")

def main():
    return policy(default = deny(), rules = [
        when({("Read", "Glob", "Grep"): allow()}),
        when({"Bash": {("cat", "ls", "grep"): allow()}}),
    ])
```

### 5. Sandboxed Build Tools

Allow build tools with constrained sandbox environments:

```python
load("@clash//std.star", "allow", "deny", "when", "sandbox", "policy", "domains")

def main():
    cargo_env = sandbox(
        default = deny(),
        fs = {
            "$PWD": allow("r"),
            "$PWD/target": allow("rwcd"),
        },
        net = allow(),
    )

    npm_env = sandbox(
        default = deny(),
        fs = {
            "$PWD": allow("r"),
            "$PWD/node_modules": allow("rwcd"),
        },
        net = domains({"registry.npmjs.org": allow()}),
    )

    return policy(default = deny(), rules = [
        when({"Bash": {"cargo": allow(sandbox = cargo_env)}}),
        when({"Bash": {"npm": allow(sandbox = npm_env)}}),
        when({("Read", "Glob", "Grep"): allow()}),
    ])
```

---

## Debugging Policies

### Explain a Decision

Use `clash explain` to see which rule matches a given action:

```bash
clash explain bash "git push origin main"
```

This shows which rules matched, which were skipped, and the final decision.

### View Active Policy

```bash
clash policy show
```

---

## Reference

- `@clash//std.star` -- built-in standard library (loaded via `load()` in policy files)
- `@clash//builtin.star` -- built-in policy for clash CLI and Claude Code tools (exports `base`)
- `@clash//sandboxes.star` -- intent-based sandbox presets: `restricted`, `read_only`, `dev`, `dev_network`, `unrestricted`
- `@clash//rust.star`, `@clash//python.star`, `@clash//node.star` -- pre-built sandbox configurations for common toolchains
- [Policy Semantics](./policy-semantics.md) -- compilation pipeline and evaluation algorithm
- [CLI Reference](./cli-reference.md) -- full command documentation
