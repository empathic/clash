---
name: explain
description: Explain which policy rule matches a tool invocation
---
Ask the user what tool invocation they want to understand. Examples:
- "Would `git push` be allowed?"
- "What happens if I try to read ~/.ssh/id_rsa?"
- "Why was my last command denied?"

Run the explain command with the tool type and the command/path:

```bash
clash-cli policy explain bash "git push"
clash-cli policy explain read "/etc/passwd"
clash-cli policy explain write "/tmp/output.txt"
clash-cli policy explain edit "src/main.rs"
```

For machine-readable output (useful when chaining with other tools):

```bash
clash-cli policy explain bash "git push" --json
```

Parse and present the results clearly:
1. **Decision** — Whether the invocation would be ALLOWED, DENIED, or REQUIRES APPROVAL
2. **Matched rules** — Which rules matched and why
3. **Skipped rules** — Which rules were considered but didn't match
4. **Sandbox policy** — Any sandbox restrictions that apply (for bash commands)

Suggest next steps based on the result:
- If denied and the user wants to allow it: suggest `/clash:allow` or `/clash:edit`
- If allowed and the user wants to restrict it: suggest `/clash:deny` or `/clash:edit`
- To test multiple scenarios: suggest `/clash:test`
