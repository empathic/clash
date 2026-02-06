---
name: onboard
description: Interactively create your clash policy
---

## Goal
Help the user understand what clash is and how its policies work. Then build a clash policy tailored to their needs through an interactive, discovery-driven flow.

## How clash works (explain this to the user)

Clash is a permission enforcement layer for Claude Code. Instead of Claude's built-in yes/no permission prompts, clash gives you a **policy file** (`~/.clash/policy.yaml`) with rules that automatically allow, deny, or ask for approval on every tool invocation.

Each rule has three parts: **`effect verb noun`**
- **effect**: `allow`, `deny`, or `ask`
- **verb**: which tool — `bash`, `read`, `write`, `edit`, or `*` (any)
- **noun**: a glob pattern — e.g. `git push*`, `*.env`, `*`

Precedence: **deny > ask > allow**. If multiple rules match, the strictest wins.

## Step 1: Migrate existing permissions

Import any existing Claude Code permissions as a starting point:

```bash
$CLASH_BIN migrate
```

Then show the current state:

```bash
$CLASH_BIN policy show
$CLASH_BIN policy list-rules
```

## Step 2: Discover available settings

**Do not hardcode questions.** Instead, discover what clash supports:

```bash
$CLASH_BIN policy schema --json
```

Parse the JSON output. It describes every configurable section (default, notifications, audit, profiles), every field (with types, defaults, descriptions), and the full rule syntax (effects, verbs, constraints, filesystem filters, capabilities).

Use this schema to drive the onboarding questions below. If a section or field appears in the schema that isn't covered here, ask about it anyway — the schema is the source of truth.

## Step 3: Walk through each section

For each section in the schema output, ask the user about their preferences:

### default
- What should happen when no rule matches? (ask is recommended for most users)

### notifications
Present **all** notification backends from the schema:
- **desktop**: macOS/Linux notification center alerts (configurable timeout)
- **zulip**: remote permission resolution via a Zulip bot — posts ask prompts to a stream and polls for approve/deny replies (requires bot credentials: server_url, bot_email, bot_api_key, stream)
- Both can be enabled simultaneously

### audit
- Enable audit logging? Records every permission decision to a JSON Lines file.
- Custom log path? (default: ~/.clash/audit.jsonl)

### profiles and rules
Walk through common permission decisions:

**Git workflow:**
- `git commit` — allow / ask / deny?
- `git push` — allow / ask / deny?
- `git merge` — allow / ask / deny?
- Destructive git ops (`reset --hard`, `clean`, `branch -D`) — deny recommended

**Sensitive files:**
- `~/.ssh` — SSH keys
- `~/.aws` — AWS credentials
- `~/.gnupg` — GPG keys
- `~/.kube` — Kubernetes config
- `.env` files — environment secrets

**Dangerous commands:**
- `sudo` — deny recommended
- Anything else to block?

## Step 4: Apply changes

For rule changes, use the add-rule workflow:

```bash
$CLASH_BIN policy add-rule "RULE" --dry-run
```

Show the dry-run output, get confirmation, then apply:

```bash
$CLASH_BIN policy add-rule "RULE"
```

For non-rule settings (notifications, audit), edit the policy.yaml directly using the Edit tool, preserving existing comments and structure.

## Step 5: Validate

After all changes, verify the policy:

```bash
$CLASH_BIN policy show
$CLASH_BIN policy list-rules
```

Test a few scenarios with explain:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | $CLASH_BIN explain
```

## Follow-up skills

Suggest these for further customization:
- `/clash:describe` to review the full policy in plain English
- `/clash:test` to test scenarios against the policy
- `/clash:allow` or `/clash:deny` for quick single-rule additions
- `/clash:edit` for guided policy editing
