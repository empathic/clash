---
name: dogfood
description: Initialize clash with a safe default policy
---

## Tone

Be brief. Summarize command output in plain English — don't paste raw terminal output.

## Binary resolution

If `$CLASH_BIN` is empty or a command fails with "command not found":

```bash
CLASH_BIN="${CLASH_BIN:-$(command -v clash 2>/dev/null || echo "$HOME/.local/bin/clash")}"
```

## Initialize

Tell the user you're going to set up clash with safe defaults, and that you'll need permission for the first few actions since there are no rules yet.

Run the init command (without --force, so it won't overwrite an existing config):

```bash
$CLASH_BIN init
```

If this fails because a config already exists, ask the user if they want to re-run with `--force` to fully reinitialize.

## Explain what was created

After initialization, summarize briefly:

- **Default**: `ask` — anything without a matching rule prompts for approval
- **Git**: commits need approval, push/merge/destructive ops are blocked
- **Sudo**: blocked
- **File access**: current directory, `~/.claude`, and `/tmp` are allowed. Sensitive paths (`~/.ssh`, `~/.aws`) prompt for approval.

Suggest they review `~/.clash/policy.yaml` and use `/clash:edit` to customize.
