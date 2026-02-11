---
name: onboard
description: Interactively create your clash policy
---

## Tone and presentation

- Be brief and conversational. No walls of text.
- Ask one question at a time using `AskUserQuestion`. Always include a recommended option.
- Summarize command output in plain English — never paste raw terminal output, JSON, or log lines to the user.
- Use short sentences and bullet lists. Don't format anything as tables.
- Don't take unsolicited system actions (chmod, chown, etc.). If you notice a warning, mention it and move on.
- When a command fails, explain briefly and move on. Don't retry the same command.

## Binary resolution

If `$CLASH_BIN` is empty or a command fails with "command not found":

```bash
CLASH_BIN="${CLASH_BIN:-$(command -v clash 2>/dev/null || echo "$HOME/.local/bin/clash")}"
```

Run this once at the start, before any other command. If the resolved path doesn't exist either, tell the user clash doesn't appear to be installed and stop.

## Step 1: Detect state and migrate

Run these sequentially (not in parallel). Don't show raw output to the user.

```bash
$CLASH_BIN migrate 2>&1
$CLASH_BIN policy show 2>&1
$CLASH_BIN policy list-rules 2>&1
```

Based on the output, take one of two paths:

### Path A: Fresh install (no policy, or `policy show` fails)

Run `$CLASH_BIN init` to create the default policy. Then give a one-paragraph explanation:

> "Clash controls what Claude can do using a policy file. Rules like `deny bash git push*` block specific commands, and `allow bash just *` lets others through automatically. Anything without a rule prompts you for approval. I've set up sensible defaults — let me walk you through the key decisions."

If migrate imported rules, add: "I also imported X rules from your existing Claude Code permissions."

Proceed to Step 2.

### Path B: Existing configuration (has rules)

Summarize what they have in 2-3 short sentences focused on **outcomes**, not syntax. Example:

> "You have 18 rules. Git push and destructive operations are blocked. Commits need your approval. Everything else prompts you."

If migrate imported rules, mention it.

Ask: "Want to customize anything, or does this look good?" If they're happy, skip to Step 4.

## Step 2: Discover settings

```bash
$CLASH_BIN policy schema --json 2>&1
```

Parse the JSON to understand what's configurable. Use it to drive the questions below. If the schema includes sections not covered here, use your judgment about whether to ask.

## Step 3: Customize (one question at a time)

Ask about the **most impactful decisions only**, in this order. Use `AskUserQuestion` for each. Stop when the user says things look good — don't exhaustively cover every field.

1. **Default permission** — "When no rule matches, should clash prompt you for approval (recommended), or deny the action outright?"

2. **Git workflow** — "How should Claude handle git? Recommend: commits need your approval, push and merge are always blocked."

3. **Build tools** — "Any commands Claude should run freely? For example: `cargo test`, `npm test`, `just`, `go build`"

4. **Stop here** unless the user asks for more. Don't bring up notifications, audit, sensitive files, or .env unless the user raises them.

Apply each change silently:

```bash
$CLASH_BIN policy add-rule "RULE"
```

Confirm in plain English after each: "Done — git push is now blocked."

## Step 4: Confirm

Run `$CLASH_BIN policy list-rules` and summarize the final state in 2-3 sentences:

> "Your policy has 12 rules. Git push and destructive operations are blocked, commits need approval, and `just` commands run freely. Everything else prompts you."

## Step 5: Done

One sentence:

> "You're all set. Use `/clash:edit` anytime to change rules."
