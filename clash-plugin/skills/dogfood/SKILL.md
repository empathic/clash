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

Run the init command:

```bash
$CLASH_BIN init
```

If clash is already configured, `init` will interactively ask whether to reconfigure from scratch or update the existing configuration.

## Explain what was created

After initialization, run `$CLASH_BIN status` and summarize briefly what Claude can and cannot do.

Suggest they run `clash policy setup` in their terminal for interactive configuration, or use `/clash:edit` to customize individual rules.
