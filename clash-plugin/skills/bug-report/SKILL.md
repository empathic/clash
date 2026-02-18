---
name: bug-report
description: File a bug report to the clash issue tracker
---

## Goal

Help the user file a bug report for clash. Gather a clear description of the problem, then submit it to the issue tracker using `clash-cli bug`.

## Steps

1. **Understand the problem.** Ask the user to describe what went wrong. Ask clarifying questions if needed to get a clear, actionable summary. Compose a short title (under 80 characters) and a detailed description.

2. **Ask about diagnostic data.** Ask the user whether they'd like to include:
   - Their clash policy config (`--include-config`)
   - Recent debug logs (`--include-logs`)

   Recommend including both unless the user has a reason not to (e.g., sensitive data in the config). If the user is concerned about sensitive data, suggest they review the config first with `clash-cli policy show`.

3. **Preview the command.** Show the user the exact command that will be run before executing it:

   ```bash
   clash-cli bug "title here" --description "description here" --include-config --include-logs
   ```

   Get confirmation before proceeding.

4. **Submit the report.** Run the command. On success, share the issue URL with the user. On failure, show the error and suggest possible fixes (e.g., network issues, missing API key).

5. **Follow up.** Let the user know they can track the issue at the URL provided.
