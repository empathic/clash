# clash

A permission enforcement tool for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Clash intercepts tool usage and enforces permission policies (Allow/Deny/Ask) based on your configuration, with optional kernel-enforced sandboxing for runtime restrictions.

## Features

- **Permission enforcement** - Control which tools Claude Code can use automatically
- **Hierarchical settings** - Configure permissions at system, project, or user level
- **Policy engine** - Expressive (entity, verb, noun) rules with deny > ask > allow precedence
- **Kernel-enforced sandbox** - Runtime filesystem and network restrictions via Landlock + seccomp (Linux) or Seatbelt (macOS)
- **Plugin mode** - Run as a Claude Code plugin for seamless integration
- **CLI mode** - Launch Claude Code with managed hooks, migrate legacy permissions, and test sandbox policies
- **Legacy migration** - Convert existing Claude Code permission rules to the new policy format

## Installation

### As a Claude Code plugin (recommended)

```bash
# Build the plugin (copies binary + plugin manifest to /tmp/clash-dev/)
just build-plugin

# Use with Claude Code
claude --plugin-dir /tmp/clash-dev/clash-plugin/
```

### As a standalone CLI

```bash
cargo install --path clash
```

### Development mode

```bash
# Build plugin and launch Claude Code with it
just dev
```

## Usage

### Launch mode (recommended)

The `launch` command starts Claude Code with clash managing all hooks and sandbox enforcement:

```bash
# Launch with default settings
clash launch

# Launch with a custom policy file
clash launch --policy ./policy.yaml

# Pass additional arguments to Claude Code
clash launch -- --debug
```

### Plugin mode

When running as a plugin, clash automatically intercepts tool usage via hooks:

```bash
claude --plugin-dir /path/to/clash-plugin
```

### CLI commands

```bash
# Launch Claude Code with clash managing hooks and sandbox
clash launch [--policy <path>] [-- <claude-args>...]

# Hook commands (called by Claude Code, not typically invoked directly)
clash hook pre-tool-use       # Evaluate permissions before tool execution
clash hook post-tool-use      # Post-execution informational hook
clash hook permission-request # Auto-approve/deny permission requests
clash hook notification       # Handle notifications

# Sandbox commands
clash sandbox exec --policy '<json>' --cwd /path -- <command>  # Run command in sandbox
clash sandbox test --policy '<json>' --cwd /path -- <command>  # Test sandbox interactively
clash sandbox check                                             # Check platform support

# Migrate legacy permissions to policy format
clash migrate              # Write policy.yaml to ~/.clash/policy.yaml
clash migrate --dry-run    # Preview generated policy on stdout
clash migrate --default deny  # Set default effect (ask, deny, allow)
```

## Configuration

### Legacy permissions (Claude Code settings)

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

**Permission patterns:**

- `Tool` - Match any usage of a tool
- `Tool(prefix:*)` - Match tool usage where the argument starts with prefix
- `Tool(exact)` - Match exact argument

### Policy engine

The policy engine provides expressive (entity, verb, noun) rules for fine-grained control. Use `clash migrate` to convert legacy permissions to this format.

**Evaluation:** All matching statements are collected, then precedence applies: **deny > ask > allow**. If no statement matches, the configurable default effect is used.

Example policy (YAML):

```yaml
default: ask

rules:
  - allow execute git *
  - allow execute cargo *
  - deny read .env
  - deny execute rm -rf *
```

**Entities:** `*`, `user`, `agent`, `agent:claude`, `service:github-mcp`, etc.

**Verbs:** `read`, `write`, `edit`, `execute`, `delegate`

**Nouns:** File paths, command strings, globs (with `*` and `**`)

**Negation:** `!` inverts entity and noun matching:
- `deny(!user, read, ~/config/*)` - only users can read config
- `deny(agent:*, write, !~/code/proj/**)` - agents can't write outside project

### Sandbox policy

The sandbox enforces kernel-level restrictions on processes spawned by Claude Code. Restrictions are inherited by child processes and cannot be removed at runtime.

**Platform backends:**
- **Linux**: Landlock LSM (filesystem) + seccomp-BPF (syscall filtering)
- **macOS**: Seatbelt sandbox profiles (SBPL)

Example sandbox policy:

```yaml
sandbox:
  default: read + execute
  network: deny
  rules:
    - allow read + write + create + delete in $CWD
    - deny write + delete + create in $CWD/.git
    - deny read in $CWD/.env
```

**Capabilities:** `read`, `write`, `create`, `delete`, `execute` (combined with `+`)

**Path variables:** `$CWD`, `$HOME`, `$TMPDIR`

**Network:** `deny` (default, blocks network access) or `allow`

## Project structure

```
clash/
├── clash/              # Main CLI binary (hooks, sandbox, launch, migrate)
├── clash-plugin/       # Claude Code plugin (hooks.json + skills)
├── claude_settings/    # Settings library (permissions, policy engine, sandbox types)
├── clester/            # End-to-end testing tool
└── plans/              # Design documents and research
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
