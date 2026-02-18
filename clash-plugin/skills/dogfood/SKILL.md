---
name: dogfood
description: Initialize clash with a safe default policy
---

## Tone

Be brief. Summarize command output in plain English — don't paste raw terminal output.

## Initialize

Tell the user you're going to set up clash with safe defaults, and that you'll need permission for the first few actions since there are no rules yet.

Run the init command:

```bash
clash-cli init
```

If clash is already configured, `init` will interactively ask whether to reconfigure from scratch or update the existing configuration.

## Explain what was created

After initialization, run `clash-cli status` and summarize briefly what Claude can and cannot do.

Suggest they run `clash-cli edit` in their terminal for interactive configuration, or use `/clash:edit` to customize individual rules.
