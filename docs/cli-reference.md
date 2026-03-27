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
clash init [SCOPE] [OPTIONS]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `SCOPE` | Scope to initialize: `user` (global) or `project` (this repo). When omitted, an interactive prompt lets you choose. |

**Options:**

| Flag | Description |
|------|-------------|
| `--quick` | Skip the interactive editor and create a sensible default policy |
| `--agent <AGENT>` | Which coding agent to set up: `claude` (default), `gemini`, `codex`, `amazonq`, `opencode`, `copilot` |
| `--from-trace <PATH>` | Generate policy from an observed session trace file |

**What it does:**

- **`clash init user`** — Creates `~/.clash/policy.star` with a safe default policy, installs the Claude Code plugin, and installs the clash status line.
- **`clash init project`** — Creates `.clash/policy.star` in the current repository root with a minimal deny-all policy.
- **`clash init --agent gemini`** — Creates the policy and prints agent-specific setup instructions for installing the Clash extension.

Only one scope is initialized per invocation. When no scope is given, clash explains both options and asks you to choose.

**Examples:**

```bash
# Interactive — prompts you to choose user or project scope
clash init

# Set up your global (user-level) policy
clash init user

# Create a repo-specific policy
clash init project

# Set up for a non-Claude agent
clash init --agent gemini
clash init --agent codex
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
| `--verbose` | Show all rules including builtin rules from `@clash//builtin.star` |

Outputs a comprehensive breakdown covering:

- **Policy layers** — which levels are active (user, project, session) with file paths, and the automatic precedence chain (session > project > user)
- **Effective policy** — all rules in evaluation order grouped by domain (exec, filesystem, network, tool), with level tags showing where each rule originates and shadow indicators when a higher-precedence layer overrides a lower one. Builtin rules (from `@clash//builtin.star`, included via `base.update(...)`) are collapsed into a summary count by default; pass `--verbose` to expand them.
- **Potential issues** — detectable misconfigurations (overly broad wildcards, missing deny rules, shadowed rules, etc.)

**Example:**

```bash
clash status            # user/project/session rules; builtin rules collapsed
clash status --verbose  # all rules including builtin rules expanded
```

---

## clash doctor

Diagnose common setup issues and report fix instructions. Runs a series of checks and reports pass/warn/fail status for each.

```
clash doctor [OPTIONS]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--onboard` | Run interactive onboarding: diagnose issues and offer to fix them automatically |
| `--agent <AGENT>` | Which coding agent to diagnose: `claude` (default), `gemini`, `codex`, `amazonq`, `opencode`, `copilot` |

**Checks performed:**

| Check | Description |
|-------|-------------|
| Policy files | Verifies user and project policy files exist |
| Policy parsing | Attempts to parse and compile each policy file, reporting syntax errors |
| Plugin installed | Checks if clash is registered as a Claude Code plugin with hooks configured |
| Binary on PATH | Verifies the `clash` binary is findable on `$PATH` |
| File permissions | Checks policy files are not world/group readable (Unix) |
| Sandbox support | Checks if the platform supports sandboxing (Seatbelt on macOS, Landlock on Linux) |

Each check outputs a status (**PASS**, **WARN**, or **FAIL**) with a message. Failures include concrete fix commands or instructions.

With `--onboard`, failing checks prompt the user to fix the issue interactively (install the plugin, configure bypassPermissions, create a policy, install the status line). This collapses the multi-step `clash init` flow into a single guided command.

**Examples:**

```bash
# Standard diagnostics
clash doctor

# Interactive onboarding — diagnose and fix
clash doctor --onboard

# Diagnose a specific agent
clash doctor --agent gemini
```

---

## clash policy

View, validate, and manage policy rules.

### clash policy check

Check policy for multi-agent portability issues. Scans policy rules for agent-specific tool names and suggests canonical alternatives.

```
clash policy check [--json]
```

Tool names like `Bash`, `Read`, `Write` are Claude Code-specific. Canonical names like `shell`, `read`, `write` match across all supported agents. This command warns about agent-specific names and suggests portable replacements.

```bash
clash policy check
clash policy check --json
```

---

### clash policy allow

Add an allow rule for a tool or binary. Supports positional command syntax or explicit flags.

```
clash policy allow [OPTIONS] [COMMAND]...
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `[COMMAND]...` | Command to allow (e.g. `"gh pr create"` → bin=gh, args=[pr, create]) |

**Options:**

| Flag | Description |
|------|-------------|
| `--tool <TOOL>` | Tool name (e.g. "Bash", "Read", "Write") |
| `--bin <BIN>` | Binary name (implies --tool Bash) |
| `--sandbox <SANDBOX>` | Named sandbox to apply (must be defined in the policy) |
| `--scope <SCOPE>` | Policy scope: "user" or "project" (default: auto-detect) |

When no flags are provided, the positional command is parsed as a Bash tool rule: the first word becomes the binary name and remaining words become positional arguments.

**Examples:**

```bash
# Allow a command (positional syntax)
clash policy allow "gh pr create"

# Allow a specific binary
clash policy allow --bin grep

# Allow a binary with a sandbox
clash policy allow --bin cargo --sandbox cwd

# Allow a tool by name
clash policy allow --tool Read

# Allow in user scope
clash policy allow --scope user --bin git
```

### clash policy deny

Add a deny rule for a tool or binary. Same syntax as `allow`.

```
clash policy deny [OPTIONS] [COMMAND]...
```

**Arguments and options are the same as `clash policy allow`** (except `--sandbox` is not available for deny rules).

**Examples:**

```bash
# Deny a command
clash policy deny "rm -rf"

# Deny a tool
clash policy deny --tool WebSearch

# Deny a binary
clash policy deny --bin curl
```

### clash policy remove

Remove a rule matching a tool or binary.

```
clash policy remove [OPTIONS] [COMMAND]...
```

**Arguments and options are the same as `clash policy allow`** (except `--sandbox` is not available).

**Examples:**

```bash
# Remove a previously added command rule
clash policy remove "gh pr create"

# Remove a tool rule
clash policy remove --tool Read

# Remove a binary rule
clash policy remove --bin grep
```

### clash policy edit

Open the policy file in `$EDITOR`.

```
clash policy edit [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--scope <SCOPE>` | Policy scope to edit: "user" or "project" (default: auto-detect) |

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

### clash policy list

List all active rules with level tags showing which policy layer each rule comes from.

```
clash policy list [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

**Examples:**

```bash
clash policy list
clash policy list --json
```

### clash policy validate

Validate policy files and report errors. Checks that each policy file parses and compiles successfully, reporting the policy name, default effect, and rule count on success, or detailed error messages with hints on failure.

```
clash policy validate [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--file <PATH>` | Path to a specific policy file to validate (default: all active levels) |
| `--json` | Output as JSON |

When no `--file` is given, validates all active policy levels (user, project) and reports results for each. Exits with code 0 if all files are valid, code 1 if any have errors.

**Examples:**

```bash
# Validate all active policy levels
clash policy validate

# Validate a specific file
clash policy validate --file ~/.clash/policy.star

# JSON output for scripting
clash policy validate --json
```

### clash policy schema

Print the JSON schema for the policy file format.

```
clash policy schema
```

**Examples:**

```bash
clash policy schema
```

### clash policy explain

Explain which policy rule would match a given tool invocation, reading hook input from stdin as JSON.

```
clash policy explain
```

**Examples:**

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | clash policy explain
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
| `<TOOL>` | Tool type: `bash`, `read`, `write`, `edit`, `tool` (or full name like `Bash`, `Read`) |
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

# Check a tool capability
clash explain tool "ExitPlanMode"

# Pipe JSON input (via policy explain)
echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | clash policy explain
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
| `--policy <POLICY>` | Path to policy file (default: `~/.clash/policy.star`) |

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

## clash sandbox

Apply and test kernel-level sandbox restrictions. Clash uses Seatbelt on macOS and Landlock on Linux to enforce filesystem and network restrictions at the OS level.

### clash sandbox create

Create a new named sandbox definition in the policy.

```
clash sandbox create [OPTIONS] <NAME>
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<NAME>` | Name for the new sandbox |

**Options:**

| Flag | Description |
|------|-------------|
| `--default <DEFAULT>` | Default capability: "deny" or "allow" (default: deny) |
| `--network <NETWORK>` | Network policy: "allow", "deny", or "localhost" (default: deny) |
| `--doc <DOC>` | Documentation string for the sandbox |
| `--scope <SCOPE>` | Policy scope: "user" or "project" |

**Examples:**

```bash
# Create a basic sandbox
clash sandbox create dev

# Create a sandbox with network access
clash sandbox create build --network allow --doc "Build tools sandbox"

# Create a sandbox with localhost-only networking
clash sandbox create test --network localhost
```

### clash sandbox delete

Delete a named sandbox from the policy.

```
clash sandbox delete [OPTIONS] <NAME>
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<NAME>` | Name of the sandbox to delete |

**Options:**

| Flag | Description |
|------|-------------|
| `--scope <SCOPE>` | Policy scope: "user" or "project" |

### clash sandbox list

List all named sandboxes in the policy.

```
clash sandbox list [OPTIONS]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--scope <SCOPE>` | Policy scope: "user" or "project" |

### clash sandbox add-rule

Add a filesystem rule to a named sandbox.

```
clash sandbox add-rule [OPTIONS] <SANDBOX> <PATH>
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<SANDBOX>` | Name of the sandbox to modify |
| `<PATH>` | Filesystem path for the rule |

**Options:**

| Flag | Description |
|------|-------------|
| `--effect <EFFECT>` | Rule effect: "allow" or "deny" (default: allow) |
| `--caps <CAPS>` | Capabilities: "read", "write", or "read,write" (default: read) |
| `--match <MATCH>` | Path match mode: "prefix" or "literal" (default: prefix) |
| `--doc <DOC>` | Documentation string for the rule |
| `--scope <SCOPE>` | Policy scope: "user" or "project" |

**Examples:**

```bash
# Allow read access to a directory
clash sandbox add-rule dev ./src

# Allow read+write access
clash sandbox add-rule dev ./target --caps read,write

# Add a deny rule
clash sandbox add-rule dev /etc --effect deny
```

### clash sandbox remove-rule

Remove a filesystem rule from a named sandbox by path.

```
clash sandbox remove-rule [OPTIONS] <SANDBOX> <PATH>
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `<SANDBOX>` | Name of the sandbox |
| `<PATH>` | Path of the rule to remove |

**Options:**

| Flag | Description |
|------|-------------|
| `--scope <SCOPE>` | Policy scope: "user" or "project" |

### clash sandbox check

Check if sandboxing is supported on the current platform.

```
clash sandbox check
```

### clash sandbox exec

Apply sandbox restrictions and execute a command.

```
clash sandbox exec [OPTIONS] --sandbox <SANDBOX> --cwd <CWD> [COMMAND]...
```

**Options:**

| Flag | Description |
|------|-------------|
| `--sandbox <SANDBOX>` | Sandbox config: inline JSON or a named sandbox from the policy |
| `--cwd <CWD>` | Working directory for path resolution |

**Arguments:**

| Arg | Description |
|-----|-------------|
| `[COMMAND]...` | Command and arguments to execute under sandbox |

**Examples:**

```bash
# Run ls under a read-only sandbox
clash sandbox exec \
  --sandbox '{"read":["/Users/me/project"],"write":[]}' \
  --cwd /Users/me/project \
  ls -la

# Run cargo with write access to target/
clash sandbox exec \
  --sandbox '{"read":["."],"write":["./target"]}' \
  --cwd /Users/me/project \
  cargo build
```

### clash sandbox test

Test sandbox enforcement interactively. Same interface as `exec` but designed for verifying that restrictions work as expected.

```
clash sandbox test [OPTIONS] --sandbox <SANDBOX> --cwd <CWD> [COMMAND]...
```

**Options and arguments are the same as `sandbox exec`.**

---

## clash hook

Internal commands called by coding agent hook systems. These are not typically invoked directly — they are registered in hook configuration files and called automatically by the agent.

All hook subcommands accept `--agent <AGENT>` to select the protocol format (defaults to `claude`).

```
clash hook [--agent <AGENT>] <SUBCOMMAND>
```

### clash hook pre-tool-use

Called before a tool is executed. Evaluates the policy and returns an allow/deny/ask decision. Reads hook input from stdin as JSON.

```
clash hook [--agent gemini] pre-tool-use
```

### clash hook post-tool-use

Called after a tool is executed. Used for audit logging and notifications. Reads hook input from stdin as JSON.

```
clash hook [--agent gemini] post-tool-use
```

### clash hook permission-request

Called when the agent prompts for permission. Responds to permission prompts on behalf of the user based on policy rules. Reads hook input from stdin as JSON.

```
clash hook permission-request
```

### clash hook session-start

Called when a coding agent session begins. Initializes session state and injects system prompt context. Reads hook input from stdin as JSON.

```
clash hook [--agent gemini] session-start
```

### clash hook stop

Called when a conversation turn ends without a tool call. Syncs traces.

```
clash hook [--agent gemini] stop
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

File a bug report to both Linear (private, with full diagnostics) and GitHub (public, title and description only).

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
| `--include-config` | Include the clash policy config in the Linear report |
| `--include-logs` | Include recent debug logs in the Linear report |
| `--include-trace` | Include the session trace in the Linear report |

Private data (config, logs, trace) is only sent to the Linear issue. The GitHub issue contains only the title and description.

**Examples:**

```bash
# Simple bug report
clash bug "Sandbox blocks cargo build in target directory"

# Detailed report with diagnostics
clash bug "Policy not matching git commands" \
  -d "The rule on git does not match git status" \
  --include-config \
  --include-logs \
  --include-trace
```

---

## Disabling Clash

Set the `CLASH_DISABLE` environment variable to temporarily bypass all clash enforcement for a session.

| Value | Effect |
|-------|--------|
| Unset or empty | Clash **enabled** (normal operation) |
| `0` or `false` | Clash **enabled** |
| Any other value (`1`, `true`, `yes`, ...) | Clash **disabled** (all hooks pass-through) |

When disabled, clash hooks still run but immediately return pass-through responses — no policy evaluation, no sandbox enforcement. `clash status` and `clash doctor` will report the disabled state.

**Examples:**

```bash
# Disable for a single session
CLASH_DISABLE=1 claude

# Re-enable
unset CLASH_DISABLE
```

---

## Uninstalling

```bash
clash uninstall
```

This removes the Claude Code plugin, the status line, policy files (`~/.clash/`), and the binary — regardless of how it was installed. Use `clash uninstall -y` to skip confirmation prompts.

After uninstalling, Claude Code reverts to its built-in permission model.

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
- [Policy Semantics](./policy-semantics.md) — evaluation algorithm
