# CLI Reference

Complete reference for the `clash` command-line interface.

---

## Global Options

All commands accept:

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Enable verbose/debug output |
| `-h`, `--help` | Print help |

---

## clash init

Initialize a new clash policy with a safe default configuration.

```
clash init [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--no-bypass` | Skip setting `bypassPermissions` in Claude Code settings |

**What it does:**

1. Creates `~/.clash/policy.yaml` with a safe default policy (or reconfigures an existing one)
2. Sets `bypassPermissions: true` in Claude Code settings so clash is the sole permission handler
3. Offers an interactive wizard to configure capabilities

If a policy already exists and stdin is a TTY, prompts you to choose between reconfiguring from scratch or updating the existing configuration.

**Examples:**

```bash
# First-time setup
clash init

# Re-run to reconfigure (interactive prompt)
clash init

# Initialize without touching Claude Code settings
clash init --no-bypass
```

---

## clash launch

Launch Claude Code with clash managing hooks and sandbox enforcement.

```
clash launch [OPTIONS] [ARGS]...
```

**Options:**

| Flag | Description |
|------|-------------|
| `--policy <POLICY>` | Path to policy file (default: `~/.clash/policy.yaml`) |

**Arguments:**

| Arg | Description |
|-----|-------------|
| `[ARGS]...` | Arguments passed through to Claude Code |

**Examples:**

```bash
# Launch with default policy
clash launch

# Launch with a custom policy
clash launch --policy ./project-policy.yaml

# Pass arguments to Claude Code
clash launch -- --model sonnet
```

---

## clash explain

Explain which policy rule would match a given tool invocation. Useful for debugging why an action is allowed, denied, or prompts for confirmation.

```
clash explain [OPTIONS] [TOOL] [INPUT]
```

**Arguments:**

| Arg | Description |
|-----|-------------|
| `[TOOL]` | Tool type: `bash`, `read`, `write`, `edit` (or full name like `Bash`, `Read`) |
| `[INPUT]` | The command, file path, or noun to check |

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON instead of human-readable text |

Accepts either CLI arguments or JSON from stdin.

**Examples:**

```bash
# Check a bash command
clash explain bash "git push origin main"

# Check a file read
clash explain read ".env"

# JSON output for scripting
clash explain --json bash "rm -rf /"

# Pipe JSON input
echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | clash explain
```

---

## clash migrate

Migrate legacy Claude Code permissions into clash policy. Reads Claude Code's existing permission settings and converts them to clash rules.

```
clash migrate [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview the migration: show which rules would be added without writing |
| `--default <DEFAULT>` | Default effect when creating a new policy (ignored when merging). Default: `ask` |

**Behavior:**

- If no `policy.yaml` exists, creates one with migrated rules
- If one already exists, merges new rules into the active profile

**Examples:**

```bash
# Preview what would be migrated
clash migrate --dry-run

# Migrate with deny as default
clash migrate --default deny

# Standard migration
clash migrate
```

---

## clash policy

View and edit policy rules.

### clash policy show

Show active profile, default permission, and available profiles.

```
clash policy show [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

**Examples:**

```bash
clash policy show
clash policy show --json
```

### clash policy list-rules

List all rules in the active profile, with included profiles resolved.

```
clash policy list-rules [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--profile <PROFILE>` | Show rules for a specific profile instead of the active one |
| `--json` | Output as JSON |

**Examples:**

```bash
# List rules in active profile
clash policy list-rules

# List rules in a specific profile
clash policy list-rules --profile safe-git

# Machine-readable output
clash policy list-rules --json
```

### clash policy add-rule

Add a rule to the policy file.

```
clash policy add-rule [OPTIONS] <RULE>
```

**Arguments:**

| Arg | Description |
|-----|-------------|
| `<RULE>` | Rule in `"effect verb noun"` format |

**Options:**

| Flag | Description |
|------|-------------|
| `--profile <PROFILE>` | Target profile (default: active profile from `default.profile`) |
| `--dry-run` | Print modified policy to stdout without writing |

**Examples:**

```bash
# Deny rm -rf
clash policy add-rule "deny bash rm -rf *"

# Allow cargo in a specific profile
clash policy add-rule "allow bash cargo *" --profile main

# Preview the change
clash policy add-rule "allow read *" --dry-run
```

### clash policy remove-rule

Remove a rule from the policy file.

```
clash policy remove-rule [OPTIONS] <RULE>
```

**Arguments:**

| Arg | Description |
|-----|-------------|
| `<RULE>` | Rule in `"effect verb noun"` format to remove |

**Options:**

| Flag | Description |
|------|-------------|
| `--profile <PROFILE>` | Target profile |
| `--dry-run` | Preview the change without writing |

**Examples:**

```bash
clash policy remove-rule "allow bash *"
clash policy remove-rule "deny bash git push*" --profile safe-git
```

### clash policy schema

Show the full schema of `policy.yaml` settings — sections, fields, types, and defaults.

```
clash policy schema [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (useful for tooling and agent integration) |

**Examples:**

```bash
# Human-readable schema
clash policy schema

# JSON for programmatic use
clash policy schema --json
```

---

## clash sandbox

Apply and test kernel-level sandbox restrictions. Clash uses Seatbelt on macOS and Landlock on Linux to enforce filesystem and network restrictions at the OS level.

### clash sandbox check

Check if sandboxing is supported on the current platform.

```
clash sandbox check
```

**Examples:**

```bash
clash sandbox check
```

### clash sandbox exec

Apply sandbox restrictions and execute a command.

```
clash sandbox exec [OPTIONS] --policy <POLICY> --cwd <CWD> [COMMAND]...
```

**Options:**

| Flag | Description |
|------|-------------|
| `--policy <POLICY>` | Sandbox policy as JSON string |
| `--cwd <CWD>` | Working directory for path resolution |

**Arguments:**

| Arg | Description |
|-----|-------------|
| `[COMMAND]...` | Command and arguments to execute under sandbox |

**Examples:**

```bash
# Run ls under a read-only sandbox
clash sandbox exec \
  --policy '{"read":["/Users/me/project"],"write":[]}' \
  --cwd /Users/me/project \
  ls -la

# Run cargo with write access to target/
clash sandbox exec \
  --policy '{"read":["."],"write":["./target"]}' \
  --cwd /Users/me/project \
  cargo build
```

### clash sandbox test

Test sandbox enforcement interactively. Same interface as `exec` but designed for verifying that restrictions work as expected.

```
clash sandbox test [OPTIONS] --policy <POLICY> --cwd <CWD> [COMMAND]...
```

**Options and arguments are the same as `sandbox exec`.**

---

## clash hook

Internal commands called by Claude Code's hook system. These are not typically invoked directly — they are registered in `hooks.json` and called automatically by Claude Code.

### clash hook pre-tool-use

Called before a tool is executed. Evaluates the policy and returns an allow/deny/ask decision. Reads hook input from stdin as JSON.

```
clash hook pre-tool-use
```

### clash hook post-tool-use

Called after a tool is executed. Used for audit logging and notifications. Reads hook input from stdin as JSON.

```
clash hook post-tool-use
```

### clash hook permission-request

Called when Claude Code prompts for permission. Responds to permission prompts on behalf of the user based on policy rules. Reads hook input from stdin as JSON.

```
clash hook permission-request
```

### clash hook session-start

Called when a Claude Code session begins. Initializes session state, exports environment variables (`CLASH_BIN`, `CLASH_SESSION_DIR`), and injects system prompt context. Reads hook input from stdin as JSON.

```
clash hook session-start
```

---

## clash bug

File a bug report to the clash issue tracker.

```
clash bug [OPTIONS] <TITLE>
```

**Arguments:**

| Arg | Description |
|-----|-------------|
| `<TITLE>` | Short summary of the bug |

**Options:**

| Flag | Description |
|------|-------------|
| `-d`, `--description <DESCRIPTION>` | Detailed description of the bug |
| `--include-config` | Include the clash policy config in the report |
| `--include-logs` | Include recent debug logs in the report |

**Examples:**

```bash
# Simple bug report
clash bug "Sandbox blocks cargo build in target directory"

# Detailed report with diagnostics
clash bug "Policy not matching git commands" \
  -d "The rule 'allow bash git *' does not match 'git status'" \
  --include-config \
  --include-logs
```

---

## Environment Variables

Clash exports these environment variables during a session:

| Variable | Description |
|----------|-------------|
| `CLASH_BIN` | Absolute path to the clash binary |
| `CLASH_SESSION_DIR` | Path to the per-session temp directory (`/tmp/clash-<session_id>/`) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (parse failure, I/O error, etc.) |
| `2` | CLI usage error (invalid arguments) |

---

## See Also

- [Policy Writing Guide](./policy-guide.md) — how to write policy rules
- [Policy Grammar](./policy-grammar.md) — formal EBNF grammar
- [Policy Semantics](./policy-semantics.md) — evaluation algorithm
