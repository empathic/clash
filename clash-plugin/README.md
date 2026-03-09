# Clash Plugin for Claude Code

The Claude Code plugin that integrates clash into your agent sessions. It registers hooks to intercept tool calls and provides slash-command skills for managing your policy interactively.

> Clash is designed to be agent-agnostic. This is the Claude Code integration — see the [main README](../README.md#agent-support) for the full list of supported and planned agent integrations.

For general usage and policy documentation, see the [project README](../README.md).

## Building

Requires Rust toolchain.

```bash
# Build the plugin (outputs to ./target/clash-dev/clash-plugin/)
just build-plugin

# Build and launch Claude Code with the plugin
just dev
```

### Manual build

```bash
cargo build --release -p clash
claude --plugin-dir /path/to/clash-plugin
```

The build copies this plugin directory and the compiled `clash` binary into a staging directory that Claude Code can load.

## How It Works

The plugin registers four hook types via `hooks/hooks.json`:

| Hook | Purpose |
|------|---------|
| **PreToolUse** | Evaluates policy rules before tool execution; returns Allow, Deny, or Ask |
| **PostToolUse** | Runs after tool execution (audit logging) |
| **PermissionRequest** | Responds to permission prompts on behalf of the user |
| **Notification** | Handles notification events (permission prompts, idle detection, etc.) |

## Policy Basics

Policies are written in Starlark (`.star` files), a Python-like configuration language. The `.star` file defines a `main()` function that returns a policy. Policy files are read from `~/.clash/policy.star` (user-level) or `<project>/.clash/policy.star` (project-level). JSON (`.json`) is also supported as raw IR.

### Policy File Structure

```python
# ~/.clash/policy.star
load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "home", "domains")

def main():
    fs_access = sandbox(fs=[
        cwd(follow_worktrees = True).allow(read = True, write = True),
        home().child(".ssh").allow(read = True),
    ])

    return policy(default = deny, rules = [
        tool(["Read", "Glob", "Grep"]).sandbox(fs_access).allow(),
        tool(["Write", "Edit"]).sandbox(fs_access).allow(),
        exe("git").allow(),
        exe("git", args = ["push"]).deny(),
        tool().allow(),
        domains({"github.com": allow}),
    ])
```

Note: Filesystem path entries (`cwd`, `home`, `tempdir`, `path`) cannot appear directly in the `rules = [...]` list. They must be wrapped in a `sandbox()` and attached to a `tool()` or `exe()` rule.

### Rule Syntax Quick Reference

| Pattern | Starlark |
|---------|----------|
| Allow a binary | `exe("git").allow()` |
| Deny a subcommand | `exe("git", args = ["push"]).deny()` |
| Ask for confirmation | `exe("git", args = ["commit"]).ask()` |
| Multiple binaries | `exe(["cargo", "rustc"]).allow()` |
| Filesystem (via sandbox) | `tool(["Read"]).sandbox(sandbox(fs=[cwd().allow(read = True)])).allow()` |
| Home subdir (via sandbox) | `exe("ssh").sandbox(sandbox(fs=[home().child(".ssh").allow(read = True)])).allow()` |
| Network domains | `domains({"github.com": allow})` |
| Tool access | `tool().allow()` |
| Sandbox on exec | `exe("cargo").sandbox(sb).allow()` |

### Sandbox Definition

```python
sb = sandbox(
    default = deny,
    fs = [cwd(follow_worktrees = True).allow(read = True, write = True)],
    net = allow,
)
exe("cargo").sandbox(sb).allow()
```

Note: `.sandbox(sb)` goes **before** `.allow()` / `.deny()` / `.ask()`.

### Policy File Paths

- User-level: `~/.clash/policy.star`
- Project-level: `<project>/.clash/policy.star`
- Session-scoped rules can be added via `/clash:allow` or `/clash:deny` skills during a session

### Fixing Sandbox Errors

If a command fails because of sandbox restrictions, update the policy's sandbox definition to grant the needed access:

```python
# If cargo needs network access, add net = allow to its sandbox
cargo_env = sandbox(
    default = deny,
    fs = [cwd(follow_worktrees = True).allow(read = True, write = True)],
    net = allow,
)
exe("cargo").sandbox(cargo_env).allow()
```

See the [Policy Writing Guide](../docs/policy-guide.md) for full syntax.

## Skills

Skills are slash commands available inside Claude Code when the plugin is loaded:

| Skill | Description |
|-------|-------------|
| `/clash:onboard` | Interactively build a policy from scratch |
| `/clash:edit` | Guided editing of your policy file |
| `/clash:status` | Show policy, rules, and enforcement status |
| `/clash:describe` | Plain-English description of your active policy |
| `/clash:explain` | See which rule matches a tool invocation |
| `/clash:allow` | Add an allow rule |
| `/clash:deny` | Add a deny rule |
| `/clash:test` | Test policy against hypothetical tool uses |
| `/clash:audit` | View recent permission decisions |
| `/clash:bug-report` | File a bug report |

## Project Structure

```
clash-plugin/
├── .claude-plugin/
│   └── plugin.json       # Plugin manifest
├── hooks/
│   └── hooks.json        # Hook configuration
├── skills/
│   ├── onboard/          # Interactive policy builder
│   ├── edit/             # Guided policy editing
│   ├── status/           # Status display
│   ├── explain/          # Rule matching explanation
│   ├── allow/            # Quick allow rule
│   ├── deny/             # Quick deny rule
│   ├── test/             # Policy testing
│   ├── audit/            # Audit log viewer
│   ├── describe/         # Policy description
│   └── bug-report/       # Bug reporting
└── bin/                  # Compiled clash binary (populated by build)
```

## Development

```bash
just dev       # build plugin and launch Claude Code with it
just check     # fmt, test, clippy
```

Logs are written to `/tmp/clash.log`.
