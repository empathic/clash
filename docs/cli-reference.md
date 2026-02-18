# CLI Reference

Complete reference for the `clash-cli` command-line interface.

---

## Global Options

All commands accept:

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Enable verbose/debug output |
| `-h`, `--help` | Print help |

---

## clash-cli init

Initialize a new clash policy with a safe default configuration.

```
clash-cli init [OPTIONS]
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
clash-cli init

# Re-run to reconfigure (interactive prompt)
clash-cli init

# Initialize without touching Claude Code settings
clash-cli init --no-bypass
```

---

## clash-cli edit

Interactive policy editor. Walks through building a policy rule by rule using a decision-tree interface.

```
clash-cli edit
```

Opens an interactive wizard that lets you add and remove rules from your policy. Each step presents only valid options. Press Escape to go back at any point.

**Examples:**

```bash
# Open the interactive policy editor
clash-cli edit
```

---

## clash-cli status

Show policy status: layers, rules with shadowing, and potential issues.

```
clash-cli status [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON instead of human-readable text |

Outputs a comprehensive breakdown covering:

- **Policy layers** — which levels are active (user, project, session) with file paths, and the automatic precedence chain (session > project > user)
- **Effective policy** — all rules in evaluation order grouped by domain (exec, filesystem, network, tool), with level tags showing where each rule originates and shadow indicators when a higher-precedence layer overrides a lower one
- **Potential issues** — detectable misconfigurations (overly broad wildcards, missing deny rules, shadowed rules, etc.)

**Example:**

```bash
clash-cli status
```

---

## clash-cli launch

Launch Claude Code with clash managing hooks and sandbox enforcement.

```
clash-cli launch [OPTIONS] [ARGS]...
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
clash-cli launch

# Launch with a custom policy
clash-cli launch --policy ./project.policy

# Pass arguments to Claude Code
clash-cli launch -- --model sonnet
```

---

## clash-cli explain

Explain which policy rule would match a given tool invocation. Useful for debugging why an action is allowed, denied, or prompts for confirmation.

```
clash-cli explain [OPTIONS] <TOOL> [ARGS]...
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
clash-cli explain bash git push origin main

# Check a file read
clash-cli explain read .env

# JSON output for scripting
clash-cli explain --json bash rm -rf /

# Quoting still works
clash-cli explain bash "git push origin main"

# Pipe JSON input (via policy explain)
echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | clash-cli policy explain
```

---

## clash-cli policy

View the compiled policy.

### clash-cli policy show

Show the compiled decision tree: default effect, policy name, and all rules grouped by capability domain.

```
clash-cli policy show [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

**Examples:**

```bash
clash-cli policy show
clash-cli policy show --json
```

---

## clash-cli sandbox

Apply and test kernel-level sandbox restrictions. Clash uses Seatbelt on macOS and Landlock on Linux to enforce filesystem and network restrictions at the OS level.

### clash-cli sandbox check

Check if sandboxing is supported on the current platform.

```
clash-cli sandbox check
```

### clash-cli sandbox exec

Apply sandbox restrictions and execute a command.

```
clash-cli sandbox exec [OPTIONS] --policy <POLICY> --cwd <CWD> [COMMAND]...
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
clash-cli sandbox exec \
  --policy '{"read":["/Users/me/project"],"write":[]}' \
  --cwd /Users/me/project \
  ls -la

# Run cargo with write access to target/
clash-cli sandbox exec \
  --policy '{"read":["."],"write":["./target"]}' \
  --cwd /Users/me/project \
  cargo build
```

### clash-cli sandbox test

Test sandbox enforcement interactively. Same interface as `exec` but designed for verifying that restrictions work as expected.

```
clash-cli sandbox test [OPTIONS] --policy <POLICY> --cwd <CWD> [COMMAND]...
```

**Options and arguments are the same as `sandbox exec`.**

---

## clash-cli hook

Internal commands called by Claude Code's hook system. These are not typically invoked directly — they are registered in `hooks.json` and called automatically by Claude Code.

### clash-cli hook pre-tool-use

Called before a tool is executed. Evaluates the policy and returns an allow/deny/ask decision. Reads hook input from stdin as JSON.

```
clash-cli hook pre-tool-use
```

### clash-cli hook post-tool-use

Called after a tool is executed. Used for audit logging and notifications. Reads hook input from stdin as JSON.

```
clash-cli hook post-tool-use
```

### clash-cli hook permission-request

Called when Claude Code prompts for permission. Responds to permission prompts on behalf of the user based on policy rules. Reads hook input from stdin as JSON.

```
clash-cli hook permission-request
```

### clash-cli hook session-start

Called when a Claude Code session begins. Initializes session state, symlinks the clash-cli binary into `~/.local/bin/`, and injects system prompt context. Reads hook input from stdin as JSON.

```
clash-cli hook session-start
```

---

## clash-cli bug

File a bug report to the clash issue tracker.

```
clash-cli bug [OPTIONS] <TITLE>
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
clash-cli bug "Sandbox blocks cargo build in target directory"

# Detailed report with diagnostics
clash-cli bug "Policy not matching git commands" \
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
