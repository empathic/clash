---
name: test
description: Test your clash policy against hypothetical tool uses
---
Ask the user what tool use they want to test, or use what they already described. Examples:
- "Would `rm -rf /` be allowed?"
- "Can I read `/etc/passwd`?"
- "Test `git push` to origin main"
- "What if I write to `~/.ssh/config`?"

Run each test through clash explain using the simple CLI syntax:

```bash
$CLASH_BIN explain bash "rm -rf /" --json
$CLASH_BIN explain read "/etc/passwd" --json
$CLASH_BIN explain bash "git push origin main" --json
$CLASH_BIN explain write "~/.ssh/config" --json
```

Parse the JSON output and present results clearly with visual indicators:
- **ALLOWED** -- the action is permitted by the policy
- **DENIED** -- the action is blocked by the policy
- **REQUIRES APPROVAL** -- the action will prompt for user approval

If the user wants to test multiple actions, batch them and present results as a summary table.

After showing results, offer next steps:
- `/clash:explain` for more detail on a specific result (without `--json`)
- `/clash:allow` or `/clash:deny` to quickly add a rule
- `/clash:edit` for more complex policy changes
- `/clash:describe` to see the full policy in plain English
