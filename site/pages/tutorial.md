---
layout: base.njk
title: Tutorial
description: Build a Clash policy from scratch, step by step
permalink: /tutorial/
---

<h1 class="page-title">Tutorial</h1>
<p class="page-desc">Build a real policy from an empty file. Each step adds one concept.</p>

## Prerequisites

Clash installed and initialized. If not, run through the [Quick Start](/quick-start/) first.

You should have a policy file at `~/.clash/policy.star`. Open it:

```bash
clash policy edit --raw
```

Replace whatever's there with the code below as we go. Every time you save, Clash picks up the changes immediately — no restart needed.

---

## Step 1: Start with deny-all

The safest starting point. Block everything, then open up what you need.

```python
load("@clash//std.star", "deny", "policy")

def main():
    return policy(default = deny())
```

Every policy file has a `main()` function that returns a `policy()`. The `default` is the effect applied when no rule matches — here, deny everything.

Save this file and try running your agent. Every tool call will be blocked. That's the point — we'll open it up from here.

---

## Step 2: Allow safe read operations

Your agent needs to read files to be useful. Let's allow that.

```python
load("@clash//std.star", "allow", "deny", "match", "policy")

def main():
    return policy(default = deny(), rules = [
        match({("Read", "Glob", "Grep"): allow()}),
    ])
```

One new concept: `match()` matches Claude Code tools by name. `Read`, `Glob`, and `Grep` are the read-only file tools — allowing all three lets the agent browse and read files without being able to write or edit them.

Test it:

```bash
clash explain glob "src/**/*.rs"
```

You should see an <span class="badge badge--allow">allow</span> decision.

---

## Step 3: Allow writes to your project

Read-only is safe but not very productive. Let's allow writes too.

```python
load("@clash//std.star", "allow", "deny", "match", "policy", "sandbox", "subpath")

def main():
    project_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
    )

    return policy(default = deny(), rules = [
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = project_sandbox)}),
    ])
```

The sandbox restricts file tool access to your project directory. Files outside your project are still denied.

---

## Step 4: Allow commands with `match()`

Your agent needs to run build tools and git. The `match()` builder lets you define rules as a tree of tool names and subcommands:

```python
load("@clash//std.star", "allow", "deny", "match", "policy", "sandbox", "subpath")

def main():
    project_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
    )

    return policy(default = deny(), rules = [
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = project_sandbox)}),

        match({"Bash": {"git": {
            ("add", "commit", "diff", "log", "status", "branch"): allow(),
            "push": deny(),
            "reset": {"--hard": deny()},
        }}}),

        match({"Bash": {"cargo": {
            ("build", "test", "check", "clippy", "fmt"): allow(),
            "publish": deny(),
        }}}),
    ])
```

`match()` takes a dict where roots are tool names and values are trees of subcommands. Each key maps to an effect:

- Tuples like `("add", "commit", "diff")` match any of those subcommands
- Nested dicts like `"reset": {"--hard": deny()}` match deeper argument patterns
- Unmatched subcommands fall through to the policy default (deny, in our case)

Verify your rules:

```bash
clash explain bash "git status"    # → allow
clash explain bash "git push"      # → deny
clash explain bash "git stash"     # → deny (no rule, falls to default)
```

---

## Step 5: Add a default for everything else

Denying everything unmatched is safe but noisy when you're actively working. Switch the default to `ask` so your agent can request approval for things you haven't written rules for yet:

```python
load("@clash//std.star", "allow", "ask", "deny", "match", "policy", "sandbox", "subpath")

def main():
    project_sandbox = sandbox(
        default = deny(),
        fs = {subpath("$PWD", follow_worktrees = True): allow("rwc")},
    )

    return policy(default = ask(), rules = [
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = project_sandbox)}),

        match({"Bash": {"git": {
            ("add", "commit", "diff", "log", "status", "branch"): allow(),
            "push": deny(),
            "reset": {"--hard": deny()},
        }}}),

        match({"Bash": {"cargo": {
            ("build", "test", "check", "clippy", "fmt"): allow(),
            "publish": deny(),
        }}}),
    ])
```

Now unmatched commands prompt you instead of silently failing. As you work, you'll notice which commands you're approving repeatedly — add rules for those.

---

## Step 6: Add sandboxes

Rules control whether a command runs. Sandboxes control what it can access *while* it runs — filesystem paths and network access, enforced at the OS level.

```python
load("@clash//std.star", "allow", "ask", "deny", "match", "policy", "sandbox", "subpath")

def main():
    dev_sandbox = sandbox(
        name = "dev",
        default = deny(),
        fs = {
            subpath("$PWD", follow_worktrees = True): allow("rwc"),
            "$HOME/.cargo": allow("rwc"),
            "$HOME/.rustup": allow("r"),
            "$TMPDIR": allow(),
        },
        net = allow(),
    )

    return policy(default = ask(), rules = [
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = dev_sandbox)}),

        match({"Bash": {"git": {
            ("add", "commit", "diff", "log", "status", "branch"): allow(),
            "push": deny(),
            "reset": {"--hard": deny()},
        }}}),

        match({"Bash": {"cargo": {
            ("build", "test", "check", "clippy", "fmt"): allow(sandbox = dev_sandbox),
            "publish": deny(),
        }}}),
    ])
```

The `sandbox()` builder defines a restricted environment:

- `fs` is a dict mapping paths to capabilities. Keys are path strings (or `subpath()` for worktree support); values are the allowed capabilities.
- `net` controls network access — `allow()`, `deny()`, or a list of `domains()`
- `default = deny()` blocks access to anything not listed

Attach a sandbox to an effect with `allow(sandbox = dev_sandbox)`. When cargo runs, it can access your project, cargo's cache, rustup, and temp — nothing else. This is enforced at the kernel level. Child processes inherit the same restrictions.

---

## Step 7: Restrict network access

Instead of allowing all network access in your sandbox, restrict it to specific domains:

```python
load("@clash//std.star", "allow", "ask", "deny", "domains", "match", "policy", "sandbox", "subpath")

def main():
    dev_sandbox = sandbox(
        name = "dev",
        default = deny(),
        fs = {
            subpath("$PWD", follow_worktrees = True): allow("rwc"),
            "$HOME/.cargo": allow("rwc"),
            "$HOME/.rustup": allow("r"),
            "$TMPDIR": allow(),
        },
        net = [
            domains({
                "github.com": allow(),
                "crates.io": allow(),
                "*.crates.io": allow(),
            }),
        ],
    )

    return policy(default = ask(), rules = [
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = dev_sandbox)}),

        match({"Bash": {"git": {
            ("add", "commit", "diff", "log", "status", "branch"): allow(),
            "push": deny(),
            "reset": {"--hard": deny()},
        }}}),

        match({"Bash": {"cargo": {
            ("build", "test", "check", "clippy", "fmt"): allow(sandbox = dev_sandbox),
            "publish": deny(),
        }}}),
    ])
```

Now cargo can reach GitHub and crates.io but nothing else. The `*` prefix matches subdomains.

---

## Step 8: Use the builtins

Clash ships with built-in rules for its own CLI and common Claude Code tools. Instead of writing rules for `clash status` or the `Agent` tool yourself, merge with the builtins:

```python
load("@clash//builtin.star", "builtins")
load("@clash//std.star", "allow", "ask", "deny", "domains", "match", "policy", "sandbox", "subpath")

def main():
    dev_sandbox = sandbox(
        name = "dev",
        default = deny(),
        fs = {
            subpath("$PWD", follow_worktrees = True): allow("rwc"),
            "$HOME/.cargo": allow("rwc"),
            "$HOME/.rustup": allow("r"),
            "$TMPDIR": allow(),
        },
        net = [
            domains({
                "github.com": allow(),
                "crates.io": allow(),
                "*.crates.io": allow(),
            }),
        ],
    )

    return policy(default = ask(), rules = builtins + [
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow(sandbox = dev_sandbox)}),

        match({"Bash": {"git": {
            ("add", "commit", "diff", "log", "status", "branch"): allow(),
            "push": deny(),
            "reset": {"--hard": deny()},
        }}}),

        match({"Bash": {"cargo": {
            ("build", "test", "check", "clippy", "fmt"): allow(sandbox = dev_sandbox),
            "publish": deny(),
        }}}),
    ])
```

`builtins` is a list of rules. Prepending it with `builtins + [...]` puts the built-in rules first, then yours.

---

## Verify your policy

Check the full policy status:

```bash
clash status
```

Test specific commands against your rules:

```bash
clash explain bash "cargo test"        # → allow (sandbox: dev)
clash explain bash "git push --force"  # → deny
clash explain read "~/.ssh/id_rsa"     # → ask (no rule, falls to default)
```

Format your policy file:

```bash
clash fmt
```

---

## What to do next

**Start a session and pay attention to prompts.** Every time Clash asks you to approve something, that's a rule you might want to add. The goal is to eliminate prompts for commands you trust while keeping blocks on commands you don't.

- Use `clash policy allow "command"` to add rules from the CLI without editing the file
- See the [Reference](/reference/) for the full list of policy builders
- Browse the [example policies](https://github.com/empathic/clash/tree/main/examples) for Python, Node, and Rust development setups
