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
- `/clash:onboard` — Create a policy from scratch (directs to `clash edit` wizard)
- `/clash:audit` — View recent permission decisions from the audit log
- `/clash:bug-report` — File a bug report to the clash issue tracker
- `/clash:dogfood` — Initialize clash with safe defaults

### Policy Basics

Policies use s-expression syntax with three effects and four capability domains:

**Effects:** `allow` (permit silently), `deny` (block), `ask` (prompt user)
**Domains:** `exec` (commands), `fs` (filesystem), `net` (network), `tool` (agent tools)
**Precedence:** deny always wins over allow; more specific rules beat less specific ones

### Policy File Structure

```
(version 1)                      ; policy language version (optional, default: 1)
(default deny "main")           ; default effect + entry policy name

(policy "helpers"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "helpers")            ; inline another policy's rules
  (allow (exec "git" *))         ; allow all git commands
  (deny  (exec "git" "push" *)) ; but block git push
  (allow (net "github.com")))    ; allow github.com network access
```

**Policy layers** (higher shadows lower): Session > Project > User
- User: `~/.clash/policy.sexpr`
- Project: `<project>/.clash/policy.sexpr`
- Session: created via `clash edit --session`

### Rule Syntax Quick Reference

**Exec (commands):**
```
(allow (exec "git" *))                    ; all git commands
(deny  (exec "git" "push" *))            ; git push with any args
(allow (exec "cargo" "test" *))           ; cargo test
(deny  (exec "git" :has "--force"))       ; git commands containing --force
```

**Fs (filesystem):**
```
(allow (fs read (subpath (env PWD))))     ; read files under working directory
(allow (fs (or read write) (subpath (env PWD))))  ; read+write under cwd
(deny  (fs write ".env"))                 ; block writing .env
```

**Net (network):**
```
(allow (net "github.com"))                ; allow github.com
(allow (net (or "github.com" "crates.io")))  ; allow multiple domains
```

**Patterns:** `*` (wildcard), `"literal"` (exact), `/regex/` (regex), `(or ...)` (any of), `(not ...)` (negate)

### CLI Commands for Policy Management

Always run clash as an installed binary (`clash`), never via `cargo run`.

**Viewing:**
- `clash status` — overview of layers, rules, and issues
- `clash policy list` — list all rules with level tags
- `clash policy explain bash "git push"` — check which rule matches

**Modifying (always dry-run first):**
- `clash policy allow '(exec "git" *)'` — add an allow rule
- `clash policy deny '(exec "rm" "-rf" *)'` — add a deny rule
- `clash policy remove '(allow (exec "git" *))'` — remove a rule
- Add `--dry-run` to any modification command to preview without applying

**Bare verb shortcuts:**
- `clash policy allow edit` — allow editing files in the project
- `clash policy allow bash` — allow running commands in the project
- `clash policy allow web` — allow web search and fetch
- `clash policy allow read` — allow reading files in the project

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

1. After a permission is approved, you may receive advisory context suggesting a `clash policy allow --scope session` command
2. Ask the user: "Would you like me to allow this for the rest of the session?"
3. If yes, dry-run first, then apply:
   ```
   clash policy allow '(exec "git" *)' --scope session --dry-run
   clash policy allow '(exec "git" *)' --scope session
   ```
4. Session rules are temporary — they only last for the current session

**Crafting precise rules:**
- Use the suggested rule from the advisory context as a starting point
- Prefer specific rules: `(exec "git" *)` over `(exec *)`
- For filesystem access, scope to the relevant directory
- For network access, scope to the specific domain

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

1. Add `(net allow)` to the sandbox block in their policy:
   ```
   (sandbox "my-sandbox"
     (fs read (subpath (env PWD)))
     (net allow))
   ```
2. Run `clash allow web` for broader network access
3. Use `/clash:edit` to interactively update the policy

**Note:** Domain-specific net rules like `(allow (net "crates.io"))` enable network access only to listed domains via a local HTTP proxy. The proxy enforces domain filtering for programs that respect `HTTP_PROXY`/`HTTPS_PROXY` env vars. If a domain-filtered sandbox still shows network errors, the target domain may not be in the allowlist.

**Do NOT retry the command** — it will fail again until the sandbox policy is updated.

### Disabling Clash

Set `CLASH_DISABLE=1` in the environment to temporarily disable all clash hooks for a session.
When disabled, clash becomes a complete pass-through — no policy evaluation, no sandbox enforcement,
no permission decisions. All tool calls proceed as if clash were not installed.

```bash
CLASH_DISABLE=1 claude          # disable for this session only
```

Set `CLASH_DISABLE=0` or unset the variable to re-enable clash.

### Important Behaviors

- Deny rules ALWAYS take precedence over allow rules, regardless of specificity
- When the user asks to allow something currently denied, they must remove the deny rule first
- Always use `--dry-run` before applying policy changes
- Summarize command output in plain English — never paste raw terminal output to the user
- Exec rules (e.g., `(deny (exec "git" "push" *))`) apply only to the **top-level command** Claude invokes via Bash. They do NOT catch commands run by child processes. If a user asks whether an exec deny rule prevents a subprocess from running a command, explain this limitation honestly
- Kernel sandbox restrictions on filesystem and network access DO apply to all child processes and cannot be bypassed
- Interactive tools (AskUserQuestion, EnterPlanMode, ExitPlanMode) are passed through to Claude Code's native UI when allowed by policy. Clash does NOT auto-approve these — it defers to Claude Code so the user sees the native prompt. Deny decisions are still enforced
