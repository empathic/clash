---
name: onboard
description: Interactively create your clash policy
---

## Tone and presentation

- Be brief and conversational. No walls of text.
- Summarize command output in plain English — never paste raw terminal output, JSON, or log lines to the user.
- Don't take unsolicited system actions (chmod, chown, etc.).

## Steps

1. **Check current state.** Run `clash policy list 2>&1` to see if rules exist.

2. **If no rules exist** (fresh install or empty policy):
   - Tell the user: "You don't have any policy rules yet. The easiest way to set up clash is the interactive policy editor."
   - Instruct them to run `clash edit` in their terminal (NOT inside this chat — the editor uses interactive terminal prompts with tab completion).
   - If they can't run it right now, mention they can also use `/clash:edit` to add rules one at a time.

3. **If rules already exist:**
   - Run `clash status 2>&1` and summarize what Claude can and cannot do in 2-3 plain-English sentences.
   - Ask: "Want to change anything?"
   - If yes → point them to `clash edit` for a full reconfigure, or `/clash:allow` and `/clash:deny` for quick single-rule changes.
   - If no → "You're all set."

4. **Done.** One sentence: "Use `/clash:edit` anytime to tweak rules, or `clash edit` to reconfigure from scratch."

## Important

Do NOT ask configuration questions yourself. The CLI policy editor (`clash edit`) handles interactive configuration in the terminal with tab completion, inline help, and rule testing. This skill is a thin wrapper that checks state and directs the user to the right tool.
