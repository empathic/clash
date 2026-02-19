# CLI Reference

Complete reference for the `clash` command-line interface.

---

## Global Options

All commands accept:

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Enable verbose/debug output |
| `-V`, `--version` | Print version |
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

## clash edit

Interactive policy editor. Walks through building a policy rule by rule using a decision-tree interface.

```
clash edit
```

Opens an interactive wizard that lets you add and remove rules from your policy. Each step presents only valid options. Press Escape to go back at any point.

**Examples:**

```bash
# Open the interactive policy editor
clash edit
```

---

## clash status

Show policy status: layers, rules with shadowing, and potential issues.

```
clash status [OPTIONS]
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
clash status
```

---

## clash policy shell

Transactional policy editor. Accumulates changes in memory and applies them atomically. Works as a pipe-friendly protocol (for Claude via stdin), an interactive REPL (for humans), or a one-liner (via `-c`).

```
clash policy shell [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Print resulting policy without writing to disk |
| `--scope <LEVEL>` | Policy level to modify: `user`, `project`, or `session` |
| `-c`, `--command <STMT>` | Execute a single statement and exit |

**Command language:**

| Command | Syntax | Description |
|---------|--------|-------------|
| `add` | `add [<policy>] <rule>` | Add a rule to current (or named) policy block |
| `remove` | `remove [<policy>] <rule>` | Remove a rule by its Display form |
| `create` | `create <policy>` | Create a new empty policy block |
| `default` | `default <effect> [<policy>]` | Change the default declaration |
| `use` | `use <policy>` | Switch current policy context |
| `show` | `show` | Display current policy with pending changes |
| `rules` | `rules [<policy>]` | List rules in a policy block |
| `test` | `test <tool> <args...>` | Test if a tool invocation would be allowed/denied |
| `diff` | `diff` | Show pending changes as a unified diff |
| `apply` | `apply` | Write changes to disk and exit |
| `abort` | `abort` | Discard changes and exit |
| `help` | `help [<command>]` | Show available commands |

Rules can be full s-expressions `(allow (exec "git" *))` or shortcuts `allow:bash`.

**Input mode detection:**

- `-c` flag: parse and execute single statement, apply, exit
- stdin is not a TTY (pipe mode): read all lines, apply atomically at end
- stdin is a TTY: interactive REPL with line editing, tab completion, and history

**Examples:**

```bash
# One-liner: add a rule
clash policy shell --scope project -c 'add (allow (exec "git" *))'

# One-liner with shortcut
clash policy shell --scope project -c 'add allow:bash'

# Pipe mode: multiple changes atomically
clash policy shell --scope project <<EOF
add (allow (exec "cargo" *))
add (deny (exec "git" "push" :has "--force"))
remove (deny (exec "npm" *))
EOF

# Dry-run to preview
clash policy shell --scope project --dry-run -c 'add (allow (exec "cargo" *))'

# Interactive REPL
clash policy shell --scope project
```

---

## clash amend

> **Deprecated:** prefer `clash policy shell` for a transactional editing experience.

Amend the policy: add and remove multiple rules in one atomic operation. Unlike `clash allow` / `clash deny` which handle one rule at a time, `clash amend` supports mixed effects and combined add/remove operations.

```
clash amend [OPTIONS] [RULES]...
```

**Arguments:**

| Arg | Description |
|-----|-------------|
| `[RULES]...` | Rules to add, each as `(effect (matcher ...))` or `effect:verb` |

**Options:**

| Flag | Description |
|------|-------------|
| `--remove <RULE>` | Remove a rule (repeatable). Rule text in Display form |
| `--dry-run` | Print modified policy without writing to disk |
| `--scope <LEVEL>` | Policy level to modify: `user`, `project`, or `session` |

Each rule includes its effect, so you can mix allow/deny/ask in one command:

**Examples:**

```bash
# Add multiple rules with mixed effects
clash amend '(allow (exec "git" *))' '(deny (exec "git" "push" :has "--force"))' --scope project

# Bare verb shortcuts (effect:verb format)
clash amend allow:bash deny:web --scope session

# Add and remove atomically
clash amend '(allow (exec "npm" *))' --remove '(deny (exec "npm" *))' --scope project

# Preview changes without applying
clash amend --dry-run '(allow (exec "git" *))' '(deny (exec "git" "push" :has "--force"))'

# Session-scoped rules (temporary, current session only)
clash amend allow:bash allow:edit --scope session
```

Removals are applied before additions, so you can atomically replace rules. The entire operation is validated before writing — if any rule fails to parse or the resulting policy is invalid, no changes are made.

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

## clash update

Update clash to the latest release from GitHub, or check if an update is available.

```
clash update [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--check` | Only check for updates, don't install |
| `-y`, `--yes` | Skip confirmation prompt |
| `--version <VERSION>` | Update to a specific version (e.g., `0.4.0`) |

The command compares the running version against the latest GitHub release, downloads the matching binary for your platform, verifies the SHA-256 checksum, and atomically replaces the current binary.

If clash was installed via `cargo install`, the command prints the appropriate cargo command instead of replacing the binary directly.

**Examples:**

```bash
# Update to latest release
clash update

# Check for updates without installing
clash update --check

# Update non-interactively (e.g., in a script)
clash update --yes

# Install a specific version
clash update --version 0.2.0
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
