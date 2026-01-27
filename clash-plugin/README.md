# Clash Plugin for Claude Code

Clash (Claude Shell) is a permission enforcement plugin for Claude Code. It intercepts tool usage and enforces permission policies (Allow/Deny/Ask) based on your configuration.

## Installation

### Using the plugin

1. Build the binaries for your platform:
   ```bash
   ./scripts/build.sh
   ```

2. Use the plugin with Claude Code:
   ```bash
   claude --plugin-dir /path/to/clash-plugin
   ```

### Pre-built binaries

The plugin supports pre-built binaries for:
- `darwin-arm64` (macOS Apple Silicon)
- `darwin-x86_64` (macOS Intel)
- `linux-x86_64` (Linux x86_64)

The wrapper script at `bin/clash` automatically selects the correct binary for your platform.

## Configuration

Clash reads permission rules from your Claude Code settings. Configure permissions in your settings files:

- User level: `~/.claude/settings.json`
- Project local: `.claude/settings.local.json`
- Project: `.claude/settings.json`

Example permission configuration:
```json
{
  "permissions": {
    "allow": [
      "Bash(git status:*)",
      "Bash(cargo build:*)",
      "Read"
    ],
    "deny": [
      "Bash(rm -rf:*)"
    ]
  }
}
```

## Skills

### `/clash:status`

Shows the current clash installation status and configured permissions across all settings levels.

## How it works

The plugin installs a `PreToolUse` hook that runs before every tool invocation in Claude Code. The hook:

1. Receives tool invocation details (tool name, arguments, etc.)
2. Checks the tool against your configured permission rules
3. Returns one of:
   - `allow` - Tool execution proceeds
   - `deny` - Tool execution is blocked
   - `ask` - User is prompted for confirmation

## Development

### Local development setup

For local development, use symlinks to your cargo build output:

```bash
# Set up the symlink (builds if needed)
./scripts/setup-dev.sh

# Rebuild after changes
cargo build --release -p clash
```

The wrapper script at `bin/clash` automatically uses `bin/clash-dev` if it exists.

### Building release binaries

Requires Rust toolchain.

```bash
# Build for current platform
cargo build --release -p clash

# Cross-compile (requires cross or cargo-zigbuild)
./scripts/build.sh
```

### Project structure

```
clash-plugin/
├── .claude-plugin/
│   └── plugin.json       # Plugin manifest
├── hooks/
│   └── hooks.json        # Hook configuration
├── skills/
│   └── status/
│       └── SKILL.md      # /clash:status skill
├── bin/
│   ├── clash             # Platform selector script
│   └── clash-*           # Pre-built binaries
└── scripts/
    └── build.sh          # Build script
```

## Migration from standalone CLI

If you were using `clash install`/`clash uninstall`, these commands are now deprecated. Simply use the plugin instead:

```bash
# Old way (deprecated)
clash install

# New way
claude --plugin-dir /path/to/clash-plugin
```

The `clash enter` command (subshell mode) is still available in the standalone CLI for temporary hook installation.
