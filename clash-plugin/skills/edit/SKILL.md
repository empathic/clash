---
name: edit
description: Guided editing of the clash policy file
---
First, get an overview of the current policy:

```bash
clash status
```

Then list the active rules:

```bash
clash policy list
```

If the user has already stated what they want to change, proceed. Otherwise, ask what change they would like to make. Common requests include:
- Adding allow/deny/ask rules for specific commands
- Removing existing rules
- Changing the default permission behavior
- Viewing rules in a different profile

## Adding a rule

Translate the user's intent into a rule. The effect (allow/deny) is part of the subcommand:

- **Allow**: `clash policy allow "verb noun"` where verb is `bash`, `read`, `write`, `edit`, or `*`, and noun is a glob pattern
- **Deny**: `clash policy deny "verb noun"`
- **Bare verb shortcuts**: `clash policy allow edit` (expands to allow editing with cwd-scoped filesystem access)

Preview the change with `--dry-run`:

```bash
clash policy allow "bash git *" --dry-run
```

Show the preview to the user. After confirmation, apply:

```bash
clash policy allow "bash git *"
```

To target a specific profile, add `--profile NAME`.

## Removing a rule

Preview the removal:

```bash
clash policy remove "allow bash *" --dry-run
```

After confirmation:

```bash
clash policy remove "allow bash *"
```

## Removing or changing constraints on a rule

There is no single command to remove a constraint (e.g., `url`, `args`, `fs`) from a rule.
Use a remove-then-re-add workflow:

1. Remove the existing rule (this deletes the rule and all its constraints):

```bash
clash policy remove "allow bash *"
```

2. Re-add the rule — either without constraints, or with only the constraints you want to keep:

```bash
# No constraints:
clash policy allow "bash *"

# With specific constraints:
clash policy allow "bash *" --fs "full:subpath(~/dir)" --url "example.com" --args "--safe-flag"
```

Available inline constraint flags:
- `--fs` — filesystem constraints as `"caps:filter_expr"` (e.g., `"full:subpath(~/dir)"`, `"read+write:subpath(.)"`)
- `--url` — domain patterns (e.g., `"github.com"`, `"!evil.com"` to forbid)
- `--args` — argument constraints (e.g., `"--dry-run"`, `"!--delete"` to forbid)
- `--pipe` — allow piped input (boolean flag)
- `--redirect` — allow output redirection (boolean flag)

## Validating changes

After applying a change, validate it by running explain with a simulated request:

```bash
clash policy explain bash "git push"
```

Suggest follow-up skills:
- `/clash:describe` to review the full updated policy
- `/clash:test` to test several scenarios against the policy
- `/clash:allow` or `/clash:deny` for quick single-rule additions
