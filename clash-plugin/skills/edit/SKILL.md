---
name: edit
description: Guided editing of the clash policy file
---
First, get an overview of the current policy:

```bash
$PLUGIN_DIR/bin/clash policy show
```

Then list the active rules:

```bash
$PLUGIN_DIR/bin/clash policy list-rules
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
$PLUGIN_DIR/bin/clash policy add-rule "RULE" --dry-run
```

Show the preview to the user. After confirmation, apply:

```bash
$PLUGIN_DIR/bin/clash policy add-rule "RULE"
```

To target a specific profile, add `--profile NAME`.

## Removing a rule

Preview the removal:

```bash
$PLUGIN_DIR/bin/clash policy remove-rule "RULE" --dry-run
```

After confirmation:

```bash
$PLUGIN_DIR/bin/clash policy remove-rule "RULE"
```

## Validating changes

After applying a change, validate it by running explain with a simulated request:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"<matching-command>"}}' | $PLUGIN_DIR/bin/clash explain
```

Suggest follow-up skills:
- `/clash:describe` to review the full updated policy
- `/clash:test` to test several scenarios against the policy
- `/clash:allow` or `/clash:deny` for quick single-rule additions
