# clash

A permission enforcement tool for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Clash intercepts tool usage and enforces permission policies (Allow/Deny/Ask) based on your configuration, with optional kernel-enforced sandboxing for runtime restrictions.

## Features

- **Permission enforcement** - Control which tools Claude Code can use automatically
- **Hierarchical settings** - Configure permissions at system, project, or user level
- **Policy engine** - Profile-based rules with inline constraints and deny > ask > allow precedence
- **Unified sandbox** - `fs` constraints on bash rules automatically generate kernel-enforced sandbox via Landlock + seccomp (Linux) or Seatbelt (macOS)
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

The policy engine uses a profile-based syntax with inline constraints for fine-grained control over permissions and sandboxing. Use `clash migrate` to convert legacy permissions to this format.

**Evaluation:** All matching rules in the active profile are collected, then precedence applies: **deny > ask > allow**. If no rule matches, the configurable default effect is used.

#### Policy file structure

```yaml
default:
  permission: ask        # Default effect: ask, deny, or allow
  profile: main          # Active profile name

profiles:
  base:
    rules:
      deny bash rm *:

  main:
    include: [base]      # Inherit rules from other profiles
    rules:
      allow bash git *:
        args: ["!--force"]       # Forbid --force flag
      allow bash cargo *:
      allow read *:
      deny bash curl *:
```

#### Rule syntax

Rules use the format `effect verb noun:` with optional inline constraints:

```yaml
allow bash git *:          # Allow all git commands
deny bash rm *:            # Deny all rm commands
allow read *:              # Allow reading any file
ask * *:                   # Ask for everything else
```

- **Effect**: `allow`, `deny`, or `ask`
- **Verb**: `bash`, `read`, `write`, `edit`, any tool name (e.g., `task`, `glob`, `websearch`), or `*` (wildcard)
- **Noun**: A resource pattern — file path, command string, or glob (with `*` and `**`)

#### Inline constraints

Rules can have inline constraints that further restrict when they match and how commands are sandboxed:

```yaml
allow bash cargo *:
  args: ["!--force", "--dry-run"]  # Forbid --force, require --dry-run
  fs:
    read + execute: subpath(.)     # Sandbox: allow r+x in CWD
  network: deny                    # Sandbox: block network access
  pipe: false                      # Disallow pipe operators
  redirect: false                  # Disallow I/O redirects
```

**`args`** — Argument constraints using a unified list:
- `"!--force"` — Forbid this argument (rule won't match if present; falls to default)
- `"--dry-run"` — Require this argument (rule won't match if absent)

**`fs`** — Cap-scoped filesystem constraints. For `bash` rules, these generate kernel-enforced sandbox rules. For other verbs (`read`, `write`, `edit`), they act as permission guards.

```yaml
fs:
  read + execute: subpath(.)          # Allow read+execute under CWD
  read + write: subpath(~/.ssh)       # Allow read+write under ~/.ssh
```

Capabilities: `read`, `write`, `create`, `delete`, `execute` (combined with `+`)

**`network`** — `deny` or `allow` (controls network access in the sandbox)

**`pipe`** / **`redirect`** — `true` or `false` (control shell pipe and I/O redirect operators)

#### Filter expressions

Filter expressions specify filesystem path constraints:

- `subpath(.)` — Path must be under this directory
- `literal(.env)` — Exactly this path
- `regex(\\.env\\.*)` — Regex pattern match
- `!expr` — NOT (invert the expression)
- `a & b` — AND (both must match)
- `a | b` — OR (either can match)

#### Profile inheritance

Profiles can inherit rules from other profiles via `include`. Multiple includes are supported, and circular dependencies are detected:

```yaml
profiles:
  safe-ssh:
    rules:
      deny * *:
        fs:
          read + write: subpath(~/.ssh)

  safe-read:
    rules:
      allow read *:

  research:
    include: [safe-ssh, safe-read]
    rules:
      allow bash *:
        args: ["!-delete"]
```

Parent rules are included first (lower precedence), then the profile's own rules. The standard **deny > ask > allow** precedence still applies across all collected rules.

### Sandbox

For `bash` rules with `fs` constraints, the policy engine automatically generates a kernel-enforced sandbox. The sandbox restrictions are inherited by child processes and cannot be removed at runtime.

**Platform backends:**
- **Linux**: Landlock LSM (filesystem) + seccomp-BPF (syscall filtering)
- **macOS**: Seatbelt sandbox profiles (SBPL)

When a bash command matches an `allow` rule with `fs` or `network` constraints, the command is automatically wrapped in a sandbox:

```bash
# Original command
cargo build

# Rewritten by clash as
clash sandbox exec --policy '<json>' --cwd /path -- bash -c "cargo build"
```

**Path variables in filter expressions:** `$CWD`, `$HOME`, `$TMPDIR`

## Project structure

```
clash/
├── clash/              # CLI binary + library (hooks, permissions, sandbox, handlers)
│   ├── src/lib.rs      #   Library entry point (use clash as a dependency)
│   ├── src/main.rs     #   Thin CLI wrapper
│   ├── src/handlers.rs #   Pre-built hook handlers
│   ├── src/hooks.rs    #   Hook I/O types (input/output for Claude Code protocol)
│   ├── src/permissions.rs # Policy-based permission evaluation
│   ├── src/settings.rs #   Settings loading + default policy template
│   ├── src/sandbox/    #   Platform-specific sandbox backends
│   ├── src/audit.rs    #   Audit logging
│   └── src/notifications.rs # Desktop + Zulip notifications
├── clash-plugin/       # Claude Code plugin (hooks.json + skills)
├── claude_settings/    # Settings library (permissions, policy engine, sandbox types)
├── clester/            # End-to-end testing tool
└── plans/              # Design documents and research
```

## Library usage

### Using clash as a library

The `clash` crate can be used as a library for permission enforcement, hook handling, and sandbox management:

```rust
use clash::hooks::ToolUseHookInput;
use clash::permissions::check_permission;
use clash::settings::ClashSettings;

// Load settings and evaluate a tool invocation
let settings = ClashSettings::load_or_create()?;
let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
let output = check_permission(&input, &settings)?;
output.write_stdout()?;
```

Use the pre-built handlers for full hook integration:

```rust
use clash::handlers;
use clash::hooks::{ToolUseHookInput, SessionStartHookInput};
use clash::settings::ClashSettings;

let settings = ClashSettings::load_or_create()?;

// Handle permission requests (integrates policy + Zulip + desktop notifications)
let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
let output = handlers::handle_permission_request(&input, &settings)?;

// Handle session start (validates policy, settings, sandbox support)
let session_input = SessionStartHookInput::from_reader(std::io::stdin().lock())?;
let output = handlers::handle_session_start(&session_input)?;
```

### Using claude_settings

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
