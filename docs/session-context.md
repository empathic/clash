## Clash — Command Line Agent Safety Harness

Clash enforces permission policies on Claude Code tool usage. It intercepts every tool call
and evaluates it against a policy before allowing, denying, or prompting the user.

### Available Skills

Use these slash commands to manage clash policies during a session:

- `/clash:status` — Show current permission enforcement status and what Claude can/cannot do
- `/clash:describe` — Full human-readable breakdown of the active policy with analysis
- `/clash:edit` — Guided editing of the policy (add/remove/change rules)
- `/clash:allow` — Add an allow rule (e.g., after a denial)
- `/clash:deny` — Add a deny rule to block a specific action
- `/clash:explain` — Explain which policy rule matches a specific tool invocation
- `/clash:test` — Test hypothetical tool uses against the policy
- `/clash:onboard` — Create a policy from scratch
- `/clash:audit` — View recent permission decisions from the audit log
- `/clash:bug-report` — File a bug report to the clash issue tracker
- `/clash:dogfood` — Initialize clash with safe defaults

### Policy Basics

Policies are written in Starlark (`.star` files) and compiled to JSON IR. Three effects and four capability domains:

**Effects:** `allow` (permit silently), `deny` (block), `ask` (prompt user)
**Domains:** `exec` (commands), `fs` (filesystem), `net` (network), `tool` (agent tools)
**Precedence:** first-match within a domain (order matters — put specific rules before broad ones); deny-overrides across domains

### Policy File Structure

```json
{
  "schema_version": 5,
  "default_effect": "deny",
  "sandboxes": {},
  "tree": [
    { "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } },
        "children": [
          { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } },
              "children": [
                { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "push" } },
                    "children": [{ "decision": "deny" }] } },
                { "decision": { "allow": null } }
              ] } }
        ] } },
    { "condition": { "observe": "tool_name", "pattern": "wildcard",
        "children": [{ "decision": { "allow": null } }] } }
  ]
}
```

**Policy layers** (higher shadows lower): Session > Project > User
- User: `~/.clash/policy.star`
- Project: `<project>/.clash/policy.star`
- Session: temporary overrides for the current session

### Rule Syntax Quick Reference

The v5 match tree uses condition nodes (observe + pattern + children) and decision leaves. Capability domains (exec/fs/net) are Starlark compile-time sugar — the IR uses observables and patterns directly.

**Exec (commands) — compiled from `exe("git")`:**
```json
{ "condition": { "observe": "tool_name", "pattern": { "literal": { "literal": "Bash" } },
    "children": [
      { "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } },
          "children": [{ "decision": { "allow": null } }] } }
    ] } }
```

**Nested args — compiled from `exe("git", args=["push"]).deny()`:**
```json
{ "condition": { "observe": { "positional_arg": 0 }, "pattern": { "literal": { "literal": "git" } },
    "children": [
      { "condition": { "observe": { "positional_arg": 1 }, "pattern": { "literal": { "literal": "push" } },
          "children": [{ "decision": "deny" }] } }
    ] } }
```

**Patterns:**
- `"wildcard"` — matches anything
- `{ "literal": { "literal": "value" } }` — exact match
- `{ "regex": "pattern" }` — regex pattern
- `{ "any_of": [...] }` — match any of the listed patterns
- `{ "not": <pattern> }` — negated match

### CLI Commands for Policy Management

Always run clash as an installed binary (`clash`), never via `cargo run`.

**Viewing:**
- `clash status` — overview of layers, rules, and issues
- `clash policy list` — list all rules with level tags
- `clash explain bash "git push"` — check which rule matches

**Validating:**
- `clash policy validate` — validate all active policy files
- `clash policy validate --file ~/.clash/policy.json` — validate a specific file

**Modifying (edit the Starlark policy file directly, then validate):**
- Open `~/.clash/policy.star` in your editor, add or remove rules, then run `clash policy validate` to confirm it is valid
- Use `/clash:edit` to interactively update the policy

### Tool-to-Capability Mapping

| Tool | Capability |
|------|-----------|
| Bash | exec (bin = first word, args = rest) |
| Read, Glob, Grep | fs read |
| Write, Edit | fs write |
| WebFetch | net (domain from URL) |
| WebSearch | net (wildcard domain) |
| Skill, Task, etc. | tool |

### Session-Scoped Rules

When a user approves a permission prompt, Clash will suggest a session rule via PostToolUse context.
You should offer this to the user — but ALWAYS confirm before adding:

1. After a permission is approved, you may receive advisory context suggesting a session-scoped rule
2. Ask the user: "Would you like me to allow this for the rest of the session?"
3. If yes, explain what JSON to add to the policy and offer to edit the session policy file
4. Session rules are temporary — they only last for the current session

**Crafting precise rules:**
- Prefer specific rules targeting a specific binary over broad wildcards
- For filesystem access, scope to the relevant directory using `subpath`
- For network access, scope to the specific domain using `literal`

### Sandbox Network Errors

Commands that run inside a sandbox have network access **blocked by default**. If a Bash command
needs network access (e.g., `curl`, `pip install`, `cargo build` fetching dependencies, `npm install`),
the sandbox will block it and you'll see errors like:

- "Could not resolve host"
- "Network is unreachable"
- "curl: (6) Could not resolve host"
- "getaddrinfo ENOTFOUND"
- "failed to resolve address"

**When you see these errors:** Tell the user that the clash sandbox is likely blocking network access.
Suggest one of these fixes:

1. Add network access to the sandbox in the policy's `sandboxes` section, or use `net = allow` in the Starlark `sandbox()` builder:
   ```python
   cargo_env = sandbox(
       default = deny,
       fs = [cwd(read = allow)],
       net = allow,
   )
   ```
2. Add `"worktree": true` to subpath rules if working in a git worktree
3. Use `/clash:edit` to interactively update the policy

**Note:** Domain-specific net rules like `{ "domain": { "literal": "crates.io" } }` enable network access only to listed domains via a local HTTP proxy. The proxy enforces domain filtering for programs that respect `HTTP_PROXY`/`HTTPS_PROXY` env vars. If a domain-filtered sandbox still shows network errors, the target domain may not be in the allowlist.

**Do NOT retry the command** — it will fail again until the sandbox policy is updated.

### Sandbox Filesystem Errors

Commands that run inside a sandbox have filesystem access **restricted to allowed paths**. By default,
sandboxed processes can read and execute from most paths but cannot write or create files outside
the explicitly allowed directories (typically the working directory and temp dirs). If a command
needs to access files outside these paths (e.g., `~/.fly`, `~/.cache/sccache`, application config
directories), the sandbox will block it and you'll see errors like:

- "operation not permitted" (macOS — Seatbelt sandbox)
- "Permission denied" (Linux — Landlock sandbox)
- "EACCES: permission denied, open '/path/to/file'" (Node.js)

**When you see these errors:** Tell the user that the clash sandbox is likely blocking filesystem access.
Suggest adding the blocked paths to their policy:

1. Add filesystem access for the needed directory in the sandbox, or use Starlark `path()` in the `sandbox()` builder:
   ```python
   my_env = sandbox(
       default = deny,
       fs = [
           cwd(read = allow, write = allow),
           path("/Users/user/.fly", read = allow, write = allow),
       ],
   )
   ```
2. Use `/clash:edit` to interactively update the policy

**Do NOT retry the command** — it will fail again until the sandbox policy is updated.

### Disabling Clash

Set `CLASH_DISABLE=1` in the environment to temporarily disable all clash hooks for a session.
When disabled, clash becomes a complete pass-through — no policy evaluation, no sandbox enforcement,
no permission decisions. All tool calls proceed as if clash were not installed.

```bash
CLASH_DISABLE=1 claude          # disable for this session only
```

Set `CLASH_DISABLE=0` or unset the variable to re-enable clash.

To fully uninstall clash, direct the user to the [README](https://github.com/empathic/clash#disabling--uninstalling) or `clash --help`.

### Important Behaviors

- Rules use first-match semantics — the first matching rule wins, so order matters
- When the user asks to allow something currently denied, they must either remove the deny rule or reorder rules so the allow comes first
- Always validate the policy file after making changes with `clash policy validate`
- Summarize command output in plain English — never paste raw terminal output to the user
- Exec rules (e.g., a deny rule on `git push`) apply only to the **top-level command** Claude invokes via Bash. They do NOT catch commands run by child processes. If a user asks whether an exec deny rule prevents a subprocess from running a command, explain this limitation honestly
- Kernel sandbox restrictions on filesystem and network access DO apply to all child processes and cannot be bypassed
- Interactive tools (AskUserQuestion, EnterPlanMode, ExitPlanMode) are passed through to Claude Code's native UI when allowed by policy. Clash does NOT auto-approve these — it defers to Claude Code so the user sees the native prompt. Deny decisions are still enforced
