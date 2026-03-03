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

- **`clash init user`** — Creates `~/.clash/policy.sexpr` with a safe default policy, installs the Claude Code plugin, configures Claude Code so clash is the sole permission handler, installs the status line, and drops into the policy shell.
- **`clash init project`** — Creates `.clash/policy.sexpr` in the current repo root with a minimal deny-all policy.

```bash
clash init              # interactive — prompts you to choose
clash init user         # set up your global policy
clash init project      # create a repo-specific policy
```

---

## clash edit

Interactive policy editor. Opens the policy shell for transactional editing with tab completion, inline help, and rule testing.

```bash
clash edit
```

Equivalent to `clash policy shell`. Type `help` for available commands, `apply` to save.

---

## clash tui

Full-screen terminal UI for viewing and editing policy rules across all active levels.

```bash
clash tui
```

**Layout:** Header bar (loaded levels, modified indicator, position counter), tree view (rules grouped by domain), description pane (contextual details), key hints bar.

### Navigation

| Key | Action |
|---|---|
| `j` / `Down` | Move cursor down |
| `k` / `Up` | Move cursor up |
| `h` / `Left` | Collapse node or go to parent |
| `l` / `Right` / `Enter` | Expand node or enter children |
| `Space` | Toggle expand/collapse |
| `g` / `G` | Jump to top / bottom |

### Editing

| Key | Action |
|---|---|
| `e` | Edit node value inline |
| `E` | Edit full rule as s-expression |
| `Tab` | Cycle effect |
| `a` | Add a new rule (guided form) |
| `d` | Delete rule at cursor |
| `w` | Save all changes (shows diff) |
| `u` / `Ctrl+r` | Undo / redo |

### Search

| Key | Action |
|---|---|
| `/` | Start fuzzy search |
| `n` / `N` | Next / previous match |
| `Esc` | Clear search or quit |

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

## clash allow / deny / ask

Shortcut commands to quickly add a rule:

```bash
clash allow bash                             # allow command execution
clash allow edit                             # allow file editing in project
clash allow web                              # allow web access
clash deny '(exec "rm" *)'                   # deny rm commands
clash ask bash                               # require approval for bash
```

---

## clash policy

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

### clash policy upgrade

Upgrade policy syntax to the latest version.

```bash
clash policy upgrade [--dry-run] [--scope <LEVEL>]
```

### clash policy list

List all rules with level tags.

```bash
clash policy list
```

### clash policy remove

Remove a specific rule.

```bash
clash policy remove '(deny (exec "rm" *))'
```

---

## clash policy shell

Transactional policy editor. Accumulates changes in memory and applies them atomically.

```bash
clash policy shell [OPTIONS]
```

| Flag | Description |
|---|---|
| `--dry-run` | Print resulting policy without writing |
| `--scope <LEVEL>` | Policy level: `user`, `project`, or `session` |
| `-c <STMT>` | Execute a single statement and exit |

**Commands:** `add`, `remove`, `create`, `default`, `use`, `show`, `rules`, `test`, `diff`, `apply`, `abort`, `help`

```bash
# One-liner
clash policy shell --scope project -c 'add (allow (exec "git" *))'

# Pipe mode
clash policy shell --scope project <<EOF
add (allow (exec "cargo" *))
add (deny (exec "git" "push" :has "--force"))
EOF

# Interactive REPL
clash policy shell --scope project
```

---

## clash sandbox

### clash sandbox check

Check if sandboxing is supported on the current platform.

```bash
clash sandbox check
```

### clash sandbox exec

Apply sandbox restrictions and execute a command.

```bash
clash sandbox exec --policy <JSON> --cwd <CWD> [COMMAND]...
```

```bash
clash sandbox exec \
  --policy '{"read":["/Users/me/project"],"write":[]}' \
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
