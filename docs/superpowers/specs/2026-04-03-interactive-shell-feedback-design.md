# Interactive Shell Policy Feedback

## Problem

When users run commands in the clash interactive shell (or via agent hooks), they get generic feedback about policy decisions. Denied commands suggest `clash policy allow --tool Bash` rather than the specific command that was blocked. Allowed commands show nothing at all. Users have no easy way to adjust policy based on what just happened.

The sandbox violation hints feature already solves this well for sandbox-level blocks — generating specific `clash sandbox add-rule` commands. Policy-level feedback should be equally actionable.

## Design

### Hash-based `clash policy allow|deny <hash>`

The audit log already assigns a 7-character hex hash to every policy evaluation. This hash becomes the universal handle for adjusting policy.

**Usage:**

```
clash policy allow a1b2c3f          # allow this exact command
clash policy allow a1b2c3f --broad  # allow with glob (e.g., git push *)
clash policy deny a1b2c3f           # deny this exact command
clash policy deny a1b2c3f --broad   # deny with glob
```

**How it works:**

1. Look up the audit entry by hash prefix (same prefix matching as `clash debug replay`)
2. Extract tool name and input (binary name, arguments)
3. Generate the appropriate policy rule
4. Show a confirmation dialog before writing:

```
$ clash policy allow a1b2c3f

  Add rule to user policy:
    allow exec git push origin main

  Proceed? [y/N]
```

With `--broad`:

```
$ clash policy allow a1b2c3f --broad

  Add rule to user policy:
    allow exec git push *

  Proceed? [y/N]
```

**Flags:**

- `--broad`: Drop trailing arguments and add glob pattern. Only meaningful when the command has more than one argument segment beyond the binary.
- `--scope <user|project>`: Override scope. Defaults to `user`.
- `--yes` / `-y`: Skip confirmation dialog (for scripting).

**Error cases:**

- Hash not found: `no audit entry matching "a1b2c3f". Run clash debug log to see recent entries.`
- Ambiguous prefix: list matching entries with timestamps (like git's ambiguous ref behavior).

**Broad rule generation:**

For a command `git push origin main`:
- Exact: `allow exec git push origin main`
- Broad: `allow exec git push *` (keeps binary + first subcommand, globs the rest)

For a single-word command like `curl`:
- `--broad` is a no-op (same as exact)

### Interactive shell prompt

After each command, the prompt displays the evaluation hash and a single-character decision indicator with color:

```
clash[a1b2c3f:✓] $    # green ✓ = allow
clash[b3e9f01:✗] $    # red ✗ = deny
clash[c4d8e02:?] $    # yellow ? = ask
```

The prompt width is fixed — the single character ensures no horizontal shifting between decisions.

First prompt before any command has been run:

```
clash $ _
```

### Startup banner

On shell start, print a one-line help message:

```
Run `clash policy allow|deny <id>` to change policy for any command.
```

### Denied command feedback

When a command is denied, print actionable hints to stderr between the denial message and the next prompt:

```
clash $ git push origin main
clash: blocked shell on git push origin main
  clash policy allow a1b2c3f          # allow this exact command
  clash policy allow a1b2c3f --broad  # allow all git push
clash[a1b2c3f:✗] $ _
```

The `--broad` suggestion is only shown when there are trailing args to drop.

### Policy reload

After every command execution in the interactive shell, reload the policy unconditionally. This ensures that if a user runs `clash policy allow <hash>` in another terminal (or via the shell itself), the very next command picks up the change.

Implementation: call the existing policy load/compile path at the top of each command evaluation cycle, replacing the current load-once-at-startup behavior.

### Hook path

The same hint generation logic is shared with the agent hook path. When a command is denied via hooks, the `additional_context` includes:

```
clash: blocked shell on git push origin main
  clash policy allow a1b2c3f
  clash policy allow a1b2c3f --broad
```

This is a follow-on benefit — no changes to the hook protocol itself.

## Components

1. **Hash resolution** (`clash/src/cmd/policy.rs`): Add hash-as-positional-arg support to `allow`/`deny` subcommands. Look up audit entry, derive rule, confirm, write.
2. **Broad rule generation** (`clash/src/cmd/policy.rs`): Logic to drop trailing args and append glob pattern.
3. **Confirmation dialog** (`clash/src/cmd/policy.rs`): Human-readable rule preview with y/N prompt. Skippable with `--yes`.
4. **Prompt integration** (`clash-brush-interactive/src/interactive_shell.rs`): Track last evaluation hash + effect, render in prompt.
5. **Denied feedback** (`clash/src/permissions.rs` or shared hint module): Generate actionable `clash policy allow` hints using the audit hash.
6. **Policy reload** (`clash/src/shell_cmd.rs` or hook setup): Reload policy before each command evaluation.
7. **Startup banner** (`clash-brush-interactive/src/interactive_shell.rs`): One-line help on shell init.

## Scope

- Primary: interactive shell (`clash shell`)
- Secondary: hook path (benefits from shared hint generation)
- Out of scope: changes to the hook protocol, new hook fields
