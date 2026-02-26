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

Policy rules are read from `~/.clash/policy.sexpr`. See the [Policy Writing Guide](../docs/policy-guide.md) for syntax.

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
