---
name: describe
description: Describe the active clash policy in human-readable terms
---
Run the status command to get a detailed breakdown of the active policy:

```bash
clash status
```

Review the output and add any additional analysis or recommendations beyond what the command provides. In particular, elaborate on:

1. **Effective security posture** — Summarize in plain English what the policy allows and blocks. For example: "This policy allows all file operations within the working directory, blocks git push and destructive git operations, and requires approval for everything else."
2. **Potential issues** — Note any gaps, overly permissive rules, or misconfigurations beyond what the command detected. For example: missing deny rules for sensitive paths, overly broad wildcards, or redundant rules.
