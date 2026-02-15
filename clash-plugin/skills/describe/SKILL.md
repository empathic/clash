---
name: describe
description: Describe the active clash policy in human-readable terms
---
Start with a quick summary:

```bash
clash status
```

Then read the active policy file for full details:

```bash
cat ~/.clash/policy.yaml
```

Parse and explain the policy in human-readable terms. Cover each of the following:

1. **Default behavior** — What is the default permission behavior (`allow`, `deny`, or `ask`)? What profile is active?
2. **Profiles** — Which profiles are defined and what does each one include? Show the inheritance chain if profiles use `include:`.
3. **Rules** — For each rule in the active profile (and inherited profiles), explain:
   - What effect it has (`allow`, `deny`, or `ask`)
   - What verb and noun pattern it matches
   - What inline constraints are in place (filesystem restrictions, network, pipe, redirect, argument constraints)
4. **Filesystem constraints** — Summarize which paths have which capabilities (`read`, `write`, `create`, `delete`, `execute`, or `full`), and what sandbox restrictions apply to bash commands.
5. **Effective security posture** — Summarize in plain English what the policy allows and blocks. For example: "This policy allows all file operations within the working directory, blocks git push and destructive git operations, and requires approval for everything else."
6. **Potential issues** — Note any gaps, overly permissive rules, or misconfigurations. For example: missing deny rules for sensitive paths, overly broad wildcards, or redundant rules.
