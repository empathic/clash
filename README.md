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
├── claude_settings/    # Settings library (also usable standalone)
└── clester/            # End-to-end testing tool
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

## Testing with clester

`clester` (claude tester) is a headless, deterministic end-to-end testing tool for clash. It simulates Claude Code's hook invocations by feeding scripted inputs to the clash binary and asserting on outputs.

### Running tests

```bash
# Run all end-to-end tests
just clester

# Run with verbose output (shows clash stdout/stderr)
just clester -v

# Run a single test script
just clester-run clester/tests/scripts/basic_permissions.yaml

# Validate test scripts without executing
just clester-validate

# Full CI: unit tests + clippy + end-to-end tests
just ci
```

### Writing test scripts

Test scripts are YAML files that define:

1. **Settings** - Permission configurations at user/project levels
2. **Steps** - Hook invocations with expected outcomes

Example test script:

```yaml
meta:
  name: basic permission enforcement
  description: Test that allow/deny rules work

settings:
  user:
    permissions:
      allow:
        - "Bash(git:*)"
      deny:
        - "Read(.env)"

steps:
  - name: git status should be allowed
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow
      reason_contains: explicitly allowed

  - name: read .env should be denied
    hook: pre-tool-use
    tool_name: Read
    tool_input:
      file_path: ".env"
    expect:
      decision: deny
```

### Test script reference

**Settings levels**: `settings.user`, `settings.project`, `settings.project_local`

**Hook types**: `pre-tool-use`, `post-tool-use`, `permission-request`, `notification`

**Tool types**: `Bash`, `Read`, `Write`, `Edit`

**Assertions**:
- `decision` - Expected permission decision: `"allow"`, `"deny"`, or `"ask"`
- `exit_code` - Expected process exit code (default: 0)
- `no_decision` - Expect no hook-specific output (for informational hooks)
- `reason_contains` - Expected substring in the decision reason

## License

Apache License 2.0
