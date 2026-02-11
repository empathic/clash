---
name: edit
description: Guided editing of the clash policy file
---
First, get an overview of the current policy:

```bash
$CLASH_BIN policy show
```

Then list the active rules:

```bash
$CLASH_BIN policy list-rules
```

If the user has already stated what they want to change, proceed. Otherwise, ask what change they would like to make. Common requests include:
- Adding allow/deny/ask rules for specific commands
- Removing existing rules
- Changing the default permission behavior
- Viewing rules in a different profile

## Adding a rule

Translate the user's intent into a rule string: `effect verb noun` where:
- **effect**: `allow`, `deny`, or `ask`
- **verb**: `bash`, `read`, `write`, `edit`, or `*` (all tools)
- **noun**: a glob pattern (e.g., `git push*`, `*.env`, `*`)

Preview the change with `--dry-run`:

```bash
$CLASH_BIN policy add-rule "RULE" --dry-run
```

Show the preview to the user. After confirmation, apply:

```bash
$CLASH_BIN policy add-rule "RULE"
```

To target a specific profile, add `--profile NAME`.

## Removing a rule

Preview the removal:

```bash
$CLASH_BIN policy remove-rule "RULE" --dry-run
```

After confirmation:

```bash
$CLASH_BIN policy remove-rule "RULE"
```

## Removing or changing constraints on a rule

There is no single command to remove a constraint (e.g., `url`, `args`, `fs`) from a rule.
Use a remove-then-re-add workflow:

1. Remove the existing rule (this deletes the rule and all its constraints):

```bash
$CLASH_BIN policy remove-rule "RULE"
```

2. Re-add the rule — either without constraints, or with only the constraints you want to keep:

```bash
# No constraints:
$CLASH_BIN policy add-rule "RULE"

# With specific constraints:
$CLASH_BIN policy add-rule "RULE" --fs "full:subpath(~/dir)" --url "example.com" --args "--safe-flag"
```

Available inline constraint flags for `add-rule`:
- `--fs` — filesystem constraints as `"caps:filter_expr"` (e.g., `"full:subpath(~/dir)"`, `"read+write:subpath(.)"`)
- `--url` — domain patterns (e.g., `"github.com"`, `"!evil.com"` to forbid)
- `--args` — argument constraints (e.g., `"--dry-run"`, `"!--delete"` to forbid)
- `--pipe` — allow piped input (boolean flag)
- `--redirect` — allow output redirection (boolean flag)

## Validating changes

After applying a change, validate it by running explain with a simulated request:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"<matching-command>"}}' | $CLASH_BIN explain
```

Suggest follow-up skills:
- `/clash:describe` to review the full updated policy
- `/clash:test` to test several scenarios against the policy
- `/clash:allow` or `/clash:deny` for quick single-rule additions
