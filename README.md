# clash

**C**ommand **L**ine **A**gent **S**afety **H**arness

Stop babysitting your coding agent, go touch grass.

---
> [!IMPORTANT]
> Clash is under heavy development. It's being used by engineers at Empathic and is quite productive, but the API is not stable and is subject to change. Please report bugs!

## Agent Support

Clash is designed to be **agent-agnostic** — a universal safety harness for any coding agent that executes tools on your behalf. The policy language and capability model are agent-independent; only the integration layer is specific to each agent.

| Agent | Status | Tracking |
|-------|--------|----------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | **Supported** | — |
| [Codex CLI](https://github.com/openai/codex) | Planned | [#195](https://github.com/empathic/clash/issues/195) |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | Planned | [#196](https://github.com/empathic/clash/issues/196) |
| [OpenCode](https://github.com/opencode-ai/opencode) | Planned | [#197](https://github.com/empathic/clash/issues/197) |

Currently, the Claude Code integration is the most mature. If you'd like to help bring Clash to another agent, contributions are welcome!

---

## The Problem

Coding agents operate with broad tool access — executing commands, editing files, and making network requests on your behalf. Their permission models tend to be all-or-nothing: either you allow a tool entirely or get prompted every time. You end up clicking "yes" hundreds of times a session, or giving blanket approval and hoping for the best.

Clash gives you granular control. Write policy rules that decide what to **allow**, **deny**, or **ask** about — then let the agent work freely on safe operations while blocking dangerous ones. On Linux, rules can generate kernel-enforced filesystem sandboxes so even allowed commands can only touch the files you specify.

---

## Quick Start

There are two ways to run clash depending on what you're doing:

### Install (use clash in your day-to-day work)

```bash
curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash
clash init
claude
```

This downloads the latest release binary to `~/.local/bin/` (Apple Silicon Mac, Linux x86_64, Linux aarch64). On Intel Mac or other platforms, install via Cargo:

```bash
cargo install clash
```

`clash init` writes a default `.star` policy (or `.json`), installs the Claude Code plugin from GitHub, installs the status line, and walks you through initial configuration. After init, every `claude` session automatically loads clash.

If you have the repo checked out, you can also use `just install` which registers the plugin from the local source tree instead of GitHub.

### Develop (hack on clash itself)

```bash
just dev
```

This builds the binary and launches a one-off Claude Code session with the plugin loaded directly from source. Changes to hooks or Rust code take effect on the next `just dev` — no install step needed.

---

## Policy Rules

Policies are written in **Starlark** (`.star`), a Python-like configuration language that compiles to JSON IR. Clash reads policies on every tool invocation, so edits take effect immediately — no restart needed.

You can also write policies directly in JSON if you prefer — see the [Policy Writing Guide](docs/policy-guide.md) for the JSON schema.

### Policy Layers

Clash supports three policy levels, each automatically included and evaluated in order of precedence:

| Level | Location | Purpose |
|-------|----------|---------|
| **User** | `~/.clash/policy.json` (or `.star`) | Your personal defaults across all projects |
| **Project** | `<project>/.clash/policy.json` (or `.star`) | Shared rules for a specific repository |
| **Session** | Created via `--scope session` | Temporary overrides for the current session |

> **Note:** Both `.json` and `.star` are supported. When both exist at the same level, `.json` takes precedence. CLI commands (`clash policy allow/deny/remove`) operate on `policy.json`.

**Layer precedence:** Session > Project > User. Higher layers can shadow rules from lower layers — for example, a project-level deny overrides a user-level allow for the same capability. Use `clash status` to see all active layers and which rules are shadowed.

### Example

```python
# ~/.clash/policy.star
load("@clash//std.star", "exe", "policy", "sandbox", "cwd", "deny", "ask")

def main():
    cwd_access = sandbox(
        default = deny(),
        fs = [cwd(follow_worktrees = True).allow(read = True, write = True)],
    )
    return policy(
        default = ask(),
        rules = [
            exe("cargo").sandbox(cwd_access).allow(),
            exe("git").sandbox(cwd_access).allow(),
        ],
    )
```

<details>
<summary>Equivalent JSON IR</summary>

```json
{
  "schema_version": 5,
  "default_effect": "ask",
  "sandboxes": {},
  "tree": [
    { "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } },
        "children": [
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "cargo" } },
              "children": [{ "decision": { "allow": null } }] } },
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } },
              "children": [{ "decision": { "allow": null } }] } }
        ] } }
  ]
}
```

</details>

**Effects:** `allow` (auto-approve), `deny` (block), `ask` (prompt you)

**Capabilities:** `exec` (commands), `fs` (filesystem), `net` (network)

**Precedence:** `deny` always wins. More specific rules beat less specific. Within the same specificity, `ask` beats `allow`. Higher layers shadow lower layers at the same specificity. See [Policy Semantics](docs/policy-semantics.md) for the full algorithm.

### Reusable Sandboxes

Starlark replaces JSON's named policy blocks and `include` with standard `load()` imports and function composition:

```python
load("@clash//rust.star", "rust_sandbox")
load("@clash//std.star", "exe", "policy", "sandbox", "cwd", "deny")

def main():
    return policy(
        default = deny(),
        rules = [
            exe(["rustc", "cargo"]).sandbox(rust_sandbox).allow(),
            exe("git").sandbox(sandbox(default = deny(), fs = [cwd().allow(read = True)])).allow(),
        ],
    )
```

The `@clash//` prefix loads from the built-in standard library, which includes sandboxes for common toolchains (`rust.star`, `node.star`, `python.star`).

### Kernel Sandbox

Exec rules can carry sandbox constraints that clash compiles into OS-enforced sandboxes (Landlock on Linux, Seatbelt on macOS):

```python
load("@clash//std.star", "exe", "policy", "sandbox", "cwd", "path", "tempdir", "allow", "deny")

def main():
    cargo_box = sandbox(
        default = deny(),
        fs = [
            cwd().allow(read = True),
            path("./target").allow(write = True),
            tempdir().allow(),
        ],
        net = allow(),
    )
    return policy(default = deny(), rules = [exe("cargo").sandbox(cargo_box).allow()])
```

Even if a command is allowed by policy, the sandbox ensures it can only access the paths you specify.

> **Note:** Exec rules apply to the top-level command Claude runs. If an allowed command spawns a subprocess that runs a denied command, the exec rule does not fire. Kernel sandbox restrictions on filesystem and network access *do* apply to all child processes. See [#136](https://github.com/empathic/clash/issues/136) for tracking deeper exec enforcement.

For the full rule syntax, see the [Policy Writing Guide](docs/policy-guide.md).

### Examples

See the [`examples/`](examples/) directory for ready-to-use policies:

- **[rust-dev.star](examples/rust-dev.star)** — Rust development with cargo sandboxing
- **[node-dev.star](examples/node-dev.star)** — Node.js development with npm/bun
- **[python-dev.star](examples/python-dev.star)** — Python development with pip/uv
- **[paranoid.star](examples/paranoid.star)** — Maximum security, read-only access
- **[permissive.star](examples/permissive.star)** — Minimal friction, common tools allowed

---

## Useful Commands

```bash
clash init                       # set up clash with a safe default policy
clash status                     # see all layers, rules, and enforcement status
clash doctor                     # diagnose common setup issues
clash update                     # update clash to the latest release
clash explain bash "git push"    # see which rule matches a command
clash policy list                # list all rules with level tags
clash policy validate            # validate policy syntax
clash policy edit                # open the interactive policy editor
clash policy allow "gh pr create"  # allow a command
clash policy deny --bin rm         # deny a binary
clash policy remove --tool Read    # remove a rule
clash sandbox create dev           # create a named sandbox
clash sandbox add-rule dev ./src   # add a sandbox filesystem rule
clash playground                 # interactive policy sandbox for testing rules
clash shell                      # sandboxed shell with per-command enforcement
clash debug log                  # view audit log entries
clash trace export               # export session trace as JSON
clash session list               # list recent sessions
```

For the full command reference, see the [CLI Reference](docs/cli-reference.md).

---

## Status Line

Clash can display a live scoreboard in Claude Code's status bar, giving you ambient visibility into policy enforcement without interrupting your workflow.

```
⚡clash ✓12 ✗3 ?1 · ✗ Bash(touch ...)
```

The status line shows:

- **Counts**: `✓` allowed, `✗` denied, `?` asked — color-coded green/red/yellow
- **Last action**: the most recent policy decision with tool name and input summary

### Setup

```bash
clash statusline install     # add status line to Claude Code settings
clash statusline uninstall   # remove it
```

After installing, the status line appears automatically in your next Claude Code session.

---

## Requirements

- **macOS** (Apple Silicon or Intel) or **Linux** (x86_64 or aarch64)
- A [supported coding agent](#agent-support) installed
- Rust toolchain (for building from source)
- Windows is **not** supported

---

## Troubleshooting

Run `clash doctor` to automatically diagnose common setup issues:

```bash
clash doctor
```

It checks policy files, plugin registration, PATH, file permissions, and sandbox support, reporting actionable fix instructions for each problem.

### "command not found: clash"

Make sure the install directory is on your `PATH`:

```bash
# If installed via the install script
export PATH="$HOME/.local/bin:$PATH"

# If installed via cargo
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

### All actions blocked — policy error

If every tool use is being denied with a "policy failed to compile" message, your policy file has a syntax error. Clash blocks all actions when it can't compile the policy rather than silently degrading.

To diagnose:

```bash
clash policy validate
```

This will show which policy file has the error and suggest how to fix it. If you want to start fresh:

```bash
clash init
```

---

## Disabling & Uninstalling

You're always in control of whether clash is active.

### Disable for one session

```bash
CLASH_DISABLE=1 claude
```

Clash stays installed but becomes a complete pass-through — no policy enforcement, no sandbox, no prompts. `clash status` and the status line will reflect the disabled state. Set `CLASH_DISABLE=0` or unset the variable to re-enable.

### Uninstall completely

```bash
clash uninstall
```

This removes bypass permissions, the Claude Code plugin, the status line, policy files (`~/.clash/`), and the binary itself — regardless of how clash was installed. Use `clash uninstall -y` to skip confirmation prompts.

After uninstalling, Claude Code reverts to its built-in permission model.

---

## Documentation

- [Policy Writing Guide](docs/policy-guide.md) — rules, profiles, constraints, and recipes
- [CLI Reference](docs/cli-reference.md) — all commands, flags, and options
- [Policy Semantics](docs/policy-semantics.md) — evaluation algorithm and sandbox generation

---

## Development

### How it works

Clash integrates with coding agents via their plugin or extension system. For each supported agent, an integration layer intercepts tool calls and evaluates them against your policy before the agent executes them.

```
Agent → integration hook → clash binary → policy evaluation → allow / deny / ask
```

**Claude Code** (current integration): The plugin lives in `clash-plugin/` and registers hooks that intercept every tool call. Hook definitions in `hooks/hooks.json` handle PreToolUse, PostToolUse, PermissionRequest, Notification, and SessionStart events — all delegating to the `clash` binary. In dev mode, `just dev` builds the binary and launches Claude Code with the plugin loaded from source. In install mode, `just install` registers the plugin via the Claude Code marketplace.

### Recipes

```bash
just dev         # build + launch Claude Code with plugin from source
just install     # build + install system-wide via marketplace
just uninstall   # remove installed plugin and binary
just check       # fmt + test + clippy
just clester     # end-to-end tests (YAML-based hook simulation)
just ci          # full CI (check + clester)
just release 0.4.0  # bump versions, commit, tag (push to trigger release)
```

### Project Structure

```
clash/
├── clash/                    # CLI binary + library (Rust)
├── clash_starlark/           # Starlark policy evaluator (.star → JSON IR)
├── clash-plugin/             # Claude Code plugin (hooks)
├── clash-brush-core/         # Sandboxed shell core engine
├── clash-brush-parser/       # Shell command parser
├── clash-brush-builtins/     # Shell built-in commands
├── clash-brush-interactive/  # Interactive shell (REPL)
├── clash_notify/             # Notification support (desktop, Zulip)
├── claude_settings/          # Claude Code settings library
├── clester/                  # End-to-end test harness
└── docs/                     # Documentation
```

---

## License

Apache License 2.0
