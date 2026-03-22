---
layout: base.njk
title: CLI Reference
description: Complete reference for the clash command-line interface.
permalink: /cli/
---

<h1 class="page-title">CLI Reference</h1>
<p class="page-desc">Every command, flag, and workflow for the <code>clash</code> binary.</p>

## Global options

All commands accept:

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Enable verbose/debug output |
| `-V`, `--version` | Print version |
| `-h`, `--help` | Print help |

---

## clash init

Initialize a new clash policy with a safe default configuration.

```bash
clash init [SCOPE] [OPTIONS]
```

| Argument | Description |
|---|---|
| `SCOPE` | `user` (global) or `project` (this repo). Omit for interactive prompt. |

| Flag | Description |
|---|---|
| `--no-bypass` | Skip setting `bypassPermissions` in Claude Code settings |

**What it does:**

- **`clash init user`** — Creates `~/.clash/policy.star` with a safe default policy, installs the Claude Code plugin, configures Claude Code so clash is the sole permission handler, and installs the status line.
- **`clash init project`** — Creates `.clash/policy.star` in the current repo root with a minimal deny-all policy.

```bash
clash init              # interactive — prompts you to choose
clash init user         # set up your global policy
clash init project      # create a repo-specific policy
```

---

## clash status

Show policy status: layers, rules with shadowing, and potential issues.

```bash
clash status [OPTIONS]
```

| Flag | Description |
|---|---|
| `--json` | Output as JSON |
| `--verbose` | Show all rules including builtins |

---

## clash doctor

Diagnose common setup issues and report fix instructions.

```bash
clash doctor
```

**Checks:** Policy files exist, policy parses successfully, plugin installed, binary on PATH, file permissions, sandbox support.

---

## clash explain

See which rule matches a given tool invocation.

```bash
clash explain <TOOL> [ARGS]...
```

| Argument | Description |
|---|---|
| `<TOOL>` | Tool type: `bash`, `read`, `write`, `edit`, `tool` |
| `[ARGS]...` | Command, file path, or noun to check |

```bash
clash explain bash git push origin main
clash explain read .env
clash explain --json bash rm -rf /
```

---

## clash policy

### clash policy allow / deny / remove

Add or remove rules from your `policy.json`. Supports positional command syntax or explicit flags.

```bash
# Positional syntax — parsed as bin + args
clash policy allow "gh pr create"
clash policy deny "rm -rf"
clash policy remove "gh pr create"

# Explicit flags
clash policy allow --tool Read
clash policy deny --bin curl
clash policy allow --bin cargo --sandbox cwd
```

| Flag | Description |
|---|---|
| `--tool <TOOL>` | Tool name (e.g. "Bash", "Read") |
| `--bin <BIN>` | Binary name (implies --tool Bash) |
| `--sandbox <SANDBOX>` | Named sandbox to apply (allow only) |
| `--scope <SCOPE>` | "user" or "project" (default: auto-detect) |

### clash policy show

Show the compiled decision tree.

```bash
clash policy show [--json]
```

### clash policy validate

Validate policy files and report errors.

```bash
clash policy validate [--file <PATH>] [--json]
```

### clash policy list

List all rules with level tags.

```bash
clash policy list
```

---

## clash sandbox

### clash sandbox create / delete / list

Manage named sandbox definitions in your `policy.json`.

```bash
clash sandbox create dev --network allow --doc "Dev sandbox"
clash sandbox delete dev
clash sandbox list [--json]
```

### clash sandbox add-rule / remove-rule

Add or remove filesystem rules within a named sandbox.

```bash
clash sandbox add-rule dev ./src --caps read
clash sandbox add-rule dev ./target --caps read,write
clash sandbox remove-rule dev ./target
```

### clash sandbox check

Check if sandboxing is supported on the current platform.

```bash
clash sandbox check
```

### clash sandbox exec

Apply sandbox restrictions and execute a command.

```bash
clash sandbox exec --sandbox <SANDBOX> --cwd <CWD> [COMMAND]...
```

```bash
clash sandbox exec \
  --sandbox '{"read":["/Users/me/project"],"write":[]}' \
  --cwd /Users/me/project \
  ls -la
```

---

## clash update

Update clash to the latest release from GitHub.

```bash
clash update [OPTIONS]
```

| Flag | Description |
|---|---|
| `--check` | Only check for updates |
| `-y`, `--yes` | Skip confirmation |
| `--version <VERSION>` | Install a specific version |

---

## clash bug

File a bug report to the issue tracker.

```bash
clash bug <TITLE> [-d <DESCRIPTION>] [--include-config] [--include-logs]
```

---

## Interactive skills

Once clash is running inside Claude Code, you have access to slash commands for managing your policy without leaving your session:

| Skill | What it does |
|---|---|
| `/clash:onboard` | Interactively build your policy from scratch |
| `/clash:edit` | Guided editing of your policy file |
| `/clash:status` | Show current policy and enforcement status |
| `/clash:describe` | Plain-English description of your active policy |
| `/clash:explain` | See which rule matches a specific tool invocation |
| `/clash:allow` | Quickly add an allow rule |
| `/clash:deny` | Quickly add a deny rule |
| `/clash:test` | Test your policy against hypothetical tool uses |
| `/clash:audit` | View recent permission decisions |

---

## Disabling clash

Set `CLASH_DISABLE` to temporarily bypass all enforcement:

```bash
CLASH_DISABLE=1 claude    # disable for one session
unset CLASH_DISABLE       # re-enable
```

---

## Environment variables

| Variable | Effect |
|---|---|
| `CLASH_DISABLE` | Set to `1` to disable all enforcement |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | General error (parse failure, I/O error) |
| `2` | CLI usage error (invalid arguments) |

---

## Uninstalling

```bash
claude plugin uninstall clash          # remove the plugin
cargo uninstall clash                  # remove the binary (cargo)
rm -f ~/.local/bin/clash               # remove the binary (install script)
# Optional cleanup:
rm -rf ~/.clash                        # user-level policy and logs
rm -rf .clash                          # project-level policy
```
