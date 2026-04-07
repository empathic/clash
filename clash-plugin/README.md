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

The plugin registers five hook types via `hooks/hooks.json`:

| Hook | Purpose |
|------|---------|
| **PreToolUse** | Evaluates policy rules before tool execution; returns Allow, Deny, or Ask |
| **PostToolUse** | Runs after tool execution (audit logging) |
| **PermissionRequest** | Responds to permission prompts on behalf of the user |
| **Notification** | Handles notification events (permission prompts, idle detection, etc.) |
| **SessionStart** | Initializes session state and injects system prompt context |

## Policy Basics

Policies are written in Starlark (`.star` files). Policy files are read from `~/.clash/policy.star` (user-level) and `<project>/.clash/policy.star` (project-level). Legacy `policy.json` files can be migrated with `clash policy convert`.

### Policy File Structure

```python
# ~/.clash/policy.star
load("@clash//std.star", "allow", "ask", "deny", "policy", "sandbox", "subpath", "domains", "merge")

fs_access = sandbox(
    name = "fs_access",
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$HOME/.ssh": allow("r"),
    },
)

settings(default = deny())

policy("default", merge(
    {
        ("Read", "Glob", "Grep", "Write", "Edit"): allow(sandbox = fs_access),
        "Bash": {
            "git": {
                "push": deny(),
                glob("**"): allow(),
            },
        },
    },
    domains({"github.com": allow()}),
))
```

### Rule Syntax Quick Reference

| Pattern | Starlark |
|---------|----------|
| Allow a binary | `{"Bash": {"git": allow()}}` |
| Deny a subcommand | `{"Bash": {"git": {"push": deny()}}}` |
| Ask for confirmation | `{"Bash": {"git": {"commit": ask()}}}` |
| Multiple binaries | `{"Bash": {("cargo", "rustc"): allow()}}` |
| Filesystem (via sandbox) | `{"Read": allow(sandbox=sandbox(name="s", fs={"$PWD": allow("r")}))}` |
| Home subdir (via sandbox) | `{"Bash": {"ssh": allow(sandbox=sandbox(name="s", fs={"$HOME/.ssh": allow("r")}))}}` |
| Network domains | `domains({"github.com": allow()})` |
| Tool access | `{"Read": allow()}` |
| Sandbox on exec | `{"Bash": {"cargo": allow(sandbox=sb)}}` |

### Sandbox Definition

```python
sb = sandbox(
    name = "sb",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
    },
    net = allow(),
)

policy("default", {
    "Bash": {"cargo": allow(sandbox = sb)},
})
```

### Policy File Paths

- User-level: `~/.clash/policy.star`
- Project-level: `<project>/.clash/policy.star`
- Session-scoped rules can be added via `/clash:allow` or `/clash:deny` skills during a session
- CLI commands (`clash policy allow/deny/remove`) operate on `policy.star` files
- Legacy `policy.json` files are migrated with `clash policy convert`

### Fixing Sandbox Errors

If a command fails because of sandbox restrictions, update the policy's sandbox definition to grant the needed access:

```python
# If cargo needs network access, add net = allow() to its sandbox
cargo_env = sandbox(
    name = "cargo_env",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
    },
    net = allow(),
)

policy("default", {
    "Bash": {"cargo": allow(sandbox = cargo_env)},
})
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
