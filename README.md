# clash

A permission enforcement tool for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Clash intercepts tool usage and enforces permission policies (Allow/Deny/Ask) based on your configuration.

## Features

- **Permission enforcement** - Control which tools Claude Code can use automatically
- **Hierarchical settings** - Configure permissions at system, project, or user level
- **Plugin mode** - Run as a Claude Code plugin for seamless integration
- **CLI mode** - Standalone commands for managing settings and permissions

## Installation

### As a Claude Code plugin (recommended)

```bash
# Build the project
cargo build --release

# Use with Claude Code
claude --plugin-dir /path/to/clash-plugin
```

### As a standalone CLI

```bash
cargo install --path clash
```

## Usage

### Plugin mode

When running as a plugin, clash automatically intercepts tool usage and checks permissions:

```bash
claude --plugin-dir /path/to/clash-plugin
```

### CLI commands

```bash
# Check installation status
clash status

# Enter a subshell with clash hooks temporarily installed
clash enter

# Legacy: Install/uninstall hooks (deprecated, use plugin mode)
clash install
clash uninstall
```

## Configuration

Configure permissions in your Claude Code settings files:

- **User level**: `~/.claude/settings.json`
- **Project local**: `.claude/settings.local.json` (not version controlled)
- **Project**: `.claude/settings.json` (version controlled)
- **System**: `/etc/claude-code/managed-settings.json` (read-only)

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
- `Tool(prefix:*)` - Match tool usage where the argument starts with prefix
- `Tool(exact)` - Match exact argument

## Project structure

```
clash/
├── clash/              # Main CLI binary
├── clash-plugin/       # Claude Code plugin
└── claude_settings/    # Settings library (also usable standalone)
```

## Library usage

The `claude_settings` crate can be used independently to read and write Claude Code settings:

```rust
use claude_settings::{ClaudeSettings, Settings, SettingsLevel, PermissionSet};

let manager = ClaudeSettings::new();

// Read effective settings (merged from all levels)
let settings = manager.effective()?;

// Check permissions
if settings.permissions.is_allowed("Bash", Some("git status")) {
    println!("git commands are allowed");
}

// Write settings
let new_settings = Settings::new()
    .with_permissions(PermissionSet::new().allow("Bash(git:*)"));
manager.write(SettingsLevel::Project, &new_settings)?;
```

## License

Apache License 2.0
