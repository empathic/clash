---
name: edit
description: Guided editing of the clash policy file
---
First, get an overview of the current policy:

```bash
clash-cli status
```

Then list the active rules:

```bash
clash-cli policy list
```

If the user has already stated what they want to change, proceed. Otherwise, ask what change they would like to make. Common requests include:
- Adding allow/deny/ask rules for specific commands
- Removing existing rules
- Changing the default permission behavior
- Viewing rules in a different profile

## Adding a rule

Translate the user's intent into a rule. The effect (allow/deny) is part of the subcommand:

- **Bare verb shortcuts**: `clash-cli policy allow edit` (expands to allow editing with cwd-scoped filesystem access)
- **Exec rules**: `clash-cli policy allow '(exec "git" *)'` — allow all git commands
- **Fs rules**: `clash-cli policy allow '(fs read (subpath (env PWD)))'` — allow reads under cwd
- **Net rules**: `clash-cli policy allow '(net "github.com")'` — allow network access to github.com
- **Deny**: `clash-cli policy deny '(exec "git" "push" *)'` — block git push

Preview the change with `--dry-run`:

```bash
clash-cli policy allow '(exec "git" *)' --dry-run
```

Show the preview to the user. After confirmation, apply:

```bash
clash-cli policy allow '(exec "git" *)'
```

To target a specific profile, add `--profile NAME`.

## Removing a rule

Preview the removal:

```bash
clash-cli policy remove '(allow (exec "git" *))' --dry-run
```

After confirmation:

```bash
clash-cli policy remove '(allow (exec "git" *))'
```

## Validating changes

After applying a change, validate it by running explain with a simulated request:

```bash
clash-cli policy explain bash "git push"
```

Suggest follow-up skills:
- `/clash:describe` to review the full updated policy
- `/clash:test` to test several scenarios against the policy
- `/clash:allow` or `/clash:deny` for quick single-rule additions
