# Clash Plugin for Claude Code

Clash (Claude Shell) is a permission enforcement plugin for Claude Code. It intercepts tool usage and enforces permission policies (Allow/Deny/Ask) based on your configuration.

## Installation

### Build and run

Requires Rust toolchain.

```bash
# Build the plugin (outputs to /tmp/clash-dev/clash-plugin/)
just build-plugin

# Build and launch Claude Code with the plugin
just dev
```

### Manual build

```bash
# Build the binary
cargo build --release -p clash

# Use the plugin with Claude Code
claude --plugin-dir /path/to/clash-plugin
```

When using `just build-plugin`, the build copies the plugin directory and compiled binary into a staging directory that Claude Code can load.

## Configuration

Clash reads permission rules from your Claude Code settings. Configure permissions in your settings files (highest to lowest priority):

- **System**: `/etc/claude-code/managed-settings.json` (read-only)
- **Project local**: `.claude/settings.local.json` (not version controlled)
- **Project**: `.claude/settings.json` (version controlled)
- **User**: `~/.claude/settings.json`

Example permission configuration:
```json
{
  "permissions": {
    "allow": [
      "Bash(git:*)",
      "Bash(cargo:*)",
      "Read"
    ],
    "deny": [
      "Bash(rm -rf:*)",
      "Read(.env)"
    ]
  }
}
```

### Permission patterns

- `Tool` - Match any usage of a tool
- `Tool(prefix:*)` - Match tool usage where the argument starts with a prefix
- `Tool(exact)` - Match an exact argument

## Hooks

The plugin registers four hook types via `hooks/hooks.json`:

| Hook | Purpose |
|------|---------|
| **PreToolUse** | Checks permissions before tool execution; returns Allow, Deny, or Ask |
| **PostToolUse** | Runs after tool execution (informational) |
| **PermissionRequest** | Responds to permission prompts on behalf of the user |
| **Notification** | Handles notification events (permission prompts, idle prompts, auth, etc.) |

## Skills

### `/clash:status`

Shows the current clash installation status and configured permissions across all settings levels.

## Project structure

```
clash-plugin/
├── .claude-plugin/
│   └── plugin.json       # Plugin manifest
├── hooks/
│   └── hooks.json        # Hook configuration
├── skills/
│   └── status/
│       └── SKILL.md      # /clash:status skill
└── scripts/              # Build scripts
```

The compiled `clash` binary is placed in `bin/` by the build process (`just build-plugin`).

## Development

```bash
# Build plugin and launch Claude Code with it
just dev

# Run checks (fmt, test, clippy)
just check
```

Logs are written to `/tmp/clash.log`.
