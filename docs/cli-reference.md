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

1. Creates `~/.clash/policy.sexpr` with a safe default policy (or reconfigures an existing one)
2. Sets `bypassPermissions: true` in Claude Code settings so clash is the sole permission handler
3. Offers an interactive wizard to configure capabilities

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

## clash status

Show policy status: profiles, rules, security posture, and potential issues.

```
clash status [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON instead of human-readable text |

Outputs a comprehensive breakdown covering:

- **Default behavior** — active policy name and default effect
- **Profiles** — all defined profiles, rule counts, and inheritance via `include:`
- **Rules** — every rule with its s-expression and a plain-English description
- **Effective security posture** — what is allowed, denied, and requires approval
- **Potential issues** — detectable misconfigurations (overly broad wildcards, missing deny rules, etc.)

**Example:**

```bash
clash status
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
| `--policy <POLICY>` | Path to policy file (default: `~/.clash/policy.sexpr`) |

**Arguments:**

| Arg | Description |
|-----|-------------|
| `[ARGS]...` | Arguments passed through to Claude Code |

**Examples:**

```bash
# Launch with default policy
clash launch

# Launch with a custom policy
clash launch --policy ./project.policy

# Pass arguments to Claude Code
clash launch -- --model sonnet
```

---

## clash explain

Explain which policy rule would match a given tool invocation. Useful for debugging why an action is allowed, denied, or prompts for confirmation.

```
clash explain [OPTIONS] <TOOL> [ARGS]...
```

**Arguments:**

| Arg | Description |
|-----|-------------|
| `<TOOL>` | Tool type: `bash`, `read`, `write`, `edit` (or full name like `Bash`, `Read`) |
| `[ARGS]...` | The command, file path, or noun to check (remaining args joined) |

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON instead of human-readable text |

Accepts either CLI arguments or JSON from stdin. Trailing arguments are joined with spaces, so quoting is not required.

**Examples:**

```bash
# Check a bash command (no quoting needed)
clash explain bash git push origin main

# Check a file read
clash explain read .env

# JSON output for scripting
clash explain --json bash rm -rf /

# Quoting still works
clash explain bash "git push origin main"

# Pipe JSON input (via policy explain)
echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | clash policy explain
```

---

## clash policy

View the compiled policy.

### clash policy show

Show the compiled decision tree: default effect, policy name, and all rules grouped by capability domain.

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

---

## clash sandbox

Apply and test kernel-level sandbox restrictions. Clash uses Seatbelt on macOS and Landlock on Linux to enforce filesystem and network restrictions at the OS level.

### clash sandbox check

Check if sandboxing is supported on the current platform.

```
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

Called when a Claude Code session begins. Initializes session state, symlinks the clash binary into `~/.local/bin/`, and injects system prompt context. Reads hook input from stdin as JSON.

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
  -d "The rule (allow (exec git *)) does not match git status" \
  --include-config \
  --include-logs
```

---

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
