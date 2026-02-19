# clash

**C**ommand **L**ine **A**gent **S**afety **H**arness

Stop babysitting Claude, go touch grass.

---
> [!IMPORTANT]
> Clash is under heavy development. It's being used by engineers at Empathic and is quite productive, but the API is not stable and is subject to change. Please report bugs!


## The Problem

Claude Code's default permission model is all-or-nothing: either you allow a tool entirely or get prompted every time. You end up clicking "yes" hundreds of times a session, or giving blanket approval and hoping for the best.

Clash gives you granular control. Write policy rules that decide what to **allow**, **deny**, or **ask** about — then let the agent work freely on safe operations while blocking dangerous ones. On Linux, rules can generate kernel-enforced filesystem sandboxes so even allowed commands can only touch the files you specify.

---

## Quick Start

There are two ways to run clash depending on what you're doing:

### Install (use clash in your day-to-day work)

```bash
cargo install --path clash
clash init
claude
```

`clash init` writes a default policy, installs the Claude Code plugin from GitHub, and walks you through initial configuration. After init, every `claude` session automatically loads clash.

If you have the repo checked out, you can also use `just install` which registers the plugin from the local source tree instead of GitHub.

### Develop (hack on clash itself)

```bash
just dev
```

This builds the binary, symlinks it into the source plugin directory, and launches a one-off Claude Code session with the plugin loaded directly from source. Changes to skills, hooks, or Rust code take effect on the next `just dev` — no install step needed.

---

## Interactive Configuration

Once clash is running inside Claude Code, you have access to slash commands (skills) for managing your policy without leaving your session:

| Skill | What it does |
|-------|-------------|
| `/clash:onboard` | Interactively build your policy from scratch |
| `/clash:edit` | Guided editing of your policy file |
| `/clash:status` | Show current policy, rules, and enforcement status |
| `/clash:describe` | Plain-English description of your active policy |
| `/clash:explain` | See which rule matches a specific tool invocation |
| `/clash:allow` | Quickly add an allow rule |
| `/clash:deny` | Quickly add a deny rule |
| `/clash:test` | Test your policy against hypothetical tool uses |
| `/clash:audit` | View recent permission decisions from the audit log |

If you're new, start with `/clash:onboard` — it walks you through creating a policy tailored to your workflow.

---

## Policy Rules

Policies use s-expression syntax: `(effect (capability ...))`. Clash reads them on every tool invocation, so edits take effect immediately — no restart needed.

### Policy Layers

Clash supports three policy levels, each automatically included and evaluated in order of precedence:

| Level | Location | Purpose |
|-------|----------|---------|
| **User** | `~/.clash/policy.sexpr` | Your personal defaults across all projects |
| **Project** | `<project>/.clash/policy.sexpr` | Shared rules for a specific repository |
| **Session** | Created via `--scope session` | Temporary overrides for the current session |

**Layer precedence:** Session > Project > User. Higher layers can shadow rules from lower layers — for example, a project-level deny overrides a user-level allow for the same capability. Use `clash status` to see all active layers and which rules are shadowed.

### Example

```lisp
; ~/.clash/policy.sexpr (user level)
(default ask "main")

(policy "main"
  (include "cwd-access")
  (allow (exec "cargo" *))          ; let it run cargo commands
  (allow (exec "git" *))            ; let it run git commands
  (deny (exec "git" "push" *))      ; never allow push
  (deny (exec "git" "reset" "--hard" *))
  (allow (net "github.com")))        ; allow github.com access

(policy "cwd-access"
  (allow (fs read (subpath (env PWD))))
  (allow (fs (or write create) (subpath (env PWD)))))
```

**Effects:** `allow` (auto-approve), `deny` (block), `ask` (prompt you)

**Capabilities:** `exec` (commands), `fs` (filesystem), `net` (network)

**Precedence:** `deny` always wins. More specific rules beat less specific. Within the same specificity, `ask` beats `allow`. Higher layers shadow lower layers at the same specificity. See [Policy Semantics](docs/policy-semantics.md) for the full algorithm.

### Policy Blocks

Rules are organized into named **policy blocks** that can include other blocks, letting you compose reusable layers:

```lisp
(policy "readonly"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "readonly")              ; import rules from other blocks
  (allow (exec "git" *)))
```

### Kernel Sandbox

Allowed exec rules can carry sandbox constraints that clash compiles into OS-enforced sandboxes (Landlock on Linux, Seatbelt on macOS):

```lisp
(allow (exec "cargo" *)
  (sandbox "cargo-sandbox"))

(sandbox "cargo-sandbox"
  (fs read (subpath (env PWD)))
  (fs write (subpath "./target"))
  (net allow))
```

Even if a command is allowed by policy, the sandbox ensures it can only access the paths you specify.

For the full rule syntax, see the [Policy Writing Guide](docs/policy-guide.md).

---

## Useful Commands

```bash
clash init                                   # set up clash with a safe default policy
clash allow bash                             # allow command execution
clash allow edit                             # allow file editing in project
clash allow web                              # allow web access
clash deny '(exec "rm" *)'                   # deny rm commands
clash ask bash                               # require approval for bash commands
clash status                                 # see all layers, rules, and shadowing
clash explain bash "git push"                # see which rule matches a command
clash policy list                            # list all rules with level tags
clash policy remove '(deny (exec "rm" *))'   # remove a rule
clash edit                                   # interactive policy editor
```

For the full command reference, see the [CLI Reference](docs/cli-reference.md).

---

## Requirements

- **macOS** (Apple Silicon or Intel) or **Linux** (x86_64 or aarch64)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed
- Rust toolchain (for building from source)
- Windows is **not** supported

---

## Troubleshooting

### "command not found: clash"

Make sure `~/.cargo/bin` is on your `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### Double-prompting (clash asks, then Claude Code asks)

This means Claude Code's built-in permissions are still active. Re-run init — it sets `bypassPermissions: true` in your Claude Code user settings by default so clash is the sole permission handler:

```bash
clash init
```

### Policy not working as expected

Use `clash explain` to see exactly which rule matches:

```bash
clash explain bash "git push origin main"
```

Or use the `/clash:explain` skill inside Claude Code for an interactive walkthrough.

---

## Documentation

- [Policy Writing Guide](docs/policy-guide.md) — rules, profiles, constraints, and recipes
- [CLI Reference](docs/cli-reference.md) — all commands, flags, and options
- [Policy Grammar](docs/policy-grammar.md) — formal EBNF grammar
- [Policy Semantics](docs/policy-semantics.md) — evaluation algorithm and sandbox generation

---

## Development

### How it works

Clash is a Claude Code **plugin**. The plugin registers hooks that intercept every tool call and evaluate it against your policy before Claude Code executes it.

```
Claude Code → hook (PreToolUse) → clash binary → policy evaluation → allow / deny / ask
```

The plugin lives in `clash-plugin/` and consists of hook definitions, skill definitions (slash commands), and the `clash` binary. In dev mode, `just dev` symlinks the freshly-built binary into `clash-plugin/bin/` and points Claude Code at the source directory. In install mode, `just install` stages a self-contained copy and registers it via the marketplace.

### Recipes

```bash
just dev         # build + launch Claude Code with plugin from source
just install     # build + install system-wide via marketplace
just uninstall   # remove installed plugin and binary
just check       # fmt + test + clippy
just clester     # end-to-end tests (YAML-based hook simulation)
just ci          # full CI (check + clester)
```

### Project Structure

```
clash/
├── clash/              # CLI binary + library (Rust)
├── clash-plugin/       # Claude Code plugin (hooks, skills, bin/)
├── clash_notify/       # Notification support (desktop, Zulip)
├── claude_settings/    # Claude Code settings library
├── clester/            # End-to-end test harness
└── docs/               # Documentation
```

---

## License

Apache License 2.0
