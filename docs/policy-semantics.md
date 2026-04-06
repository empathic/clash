# Policy Evaluation Semantics

How clash compiles and evaluates policies.

---

## Capability Model

Clash operates on three capability domains, not individual tools. Tool invocations are mapped to capability queries at evaluation time:

| Tool | Capability | Fields |
|------|-----------|--------|
| `Bash` | `exec` | bin = first non-env-assignment word of command, args = rest |
| `Read` | `fs(read)` | path = `file_path` |
| `Write` | `fs(write)` | path = `file_path` |
| `Edit` | `fs(write)` | path = `file_path` |
| `WebFetch` | `net` | domain extracted from `url` |
| `WebSearch` | `net` | domain = `*` (any) |
| `Glob`/`Grep` | `fs(read)` | path = `path` or `pattern` |
| `Skill`, `Agent`, etc. | `tool` | name = tool name |
| Unknown tools | — | no capability match → default effect |

> **Enforcement scope:** This capability mapping applies to top-level tool calls intercepted by Claude Code hooks. When a Bash command spawns child processes, those child processes are *not* re-evaluated against exec rules — only the top-level command is matched. Filesystem and network restrictions from sandbox policies are enforced at the kernel level and apply to all descendant processes. See [#136](https://github.com/empathic/clash/issues/136) for tracking exec-level enforcement of child processes.

---

## Compilation Pipeline

```
Starlark source (.star) or JSON
    │
    ▼
JSON IR (schema v5)              ← clash_starlark (if .star)
    │
    ▼
CompiledPolicy (match tree)      ← compile.rs, match_tree.rs
    │
    ├── default_effect: Effect
    ├── sandboxes: HashMap<String, SandboxPolicy>
    └── tree: Vec<Node>           (uniform trie structure)
        ├── Condition { observe, pattern, children }
        └── Decision { Allow | Deny | Ask }
```

The match tree is a uniform trie IR where:
- One node type (`Condition`) with an observable + pattern + children
- Capability domains (exec/fs/net) are Starlark compile-time sugar, not IR concepts
- Sandboxes are decoupled and referenced by name
- Evaluation is a single DFS pass with no node visited twice

### Compilation Steps

0. **Evaluate Starlark** (if `.star`) — run `main()` to produce JSON IR via `clash_starlark`
1. **Parse** — JSON IR → `CompiledPolicy` (match tree)
2. **Validate sandbox references** — verify each `SandboxRef` in decision nodes points to an entry in `CompiledPolicy.sandboxes`
3. **Sort by specificity** — children sorted by pattern specificity: `Literal(3) > Regex(2) > AnyOf/Not(1) > Wildcard(0)`, with ties broken by observable specificity
4. **Detect unreachable branches** — warn if a wildcard sibling precedes more specific siblings

Built-in rules for clash CLI commands and Claude Code interactive tools are provided by `@clash//builtin.star` and combined with the user's policy via the `update()` method in Starlark. This keeps the compilation pipeline simple — no implicit policy injection.

---

## Rule Ordering

Within a capability domain, rules use **first-match semantics**: the first rule whose matcher matches the request determines the effect. Rules are evaluated in the order they appear in the policy.

This means **order matters**. Put more specific rules before broader ones:

```python
# Correct: deny matches git push first, allow catches everything else
policy("default", {"Bash": {"git": {
    "push": deny(),
    glob("**"): allow(),
}}})

# Wrong: allow matches git push first, deny never fires
policy("default", {"Bash": {"git": {
    glob("**"): allow(),
    "push": deny(),  # never reached
}}})
```

Children at the same level are automatically sorted by specificity (literals before regexes before wildcards), but top-level rule order from the policy source is preserved. Put more specific rules before broader ones to ensure the desired evaluation order.

---

## Evaluation Algorithm

```
evaluate(tool_name, tool_input):
    1. Build QueryContext from tool invocation
       (tool_name, positional args, tool_input JSON)

    2. DFS walk the match tree:
       for each node in children:
         - Decision: return the decision (allow/deny/ask + optional sandbox ref)
         - Condition: extract observable value from context,
                      test against pattern:
                      - if matches: recurse into children
                      - if no child produces a decision: backtrack
                      - if no match: skip to next sibling

    3. If DFS produces no match → return default_effect

    4. Resolve sandbox: if decision has SandboxRef,
       look up in CompiledPolicy.sandboxes

    5. Build PolicyDecision with effect, sandbox, and trace
```

> **Note:** This evaluation runs once per Claude Code tool call via the PreToolUse hook. It does not run for child processes spawned by allowed Bash commands. Child processes inherit kernel-level sandbox restrictions (fs/net) but are not checked against exec rules.

### First-Match Semantics

Within a capability domain, the first matching rule wins. Rules are evaluated in the order they appear in the policy — the author controls precedence through ordering.

### Path Resolution

Relative paths in tool inputs are resolved against the current working directory before matching against path filters. This means `{ "subpath": { "path": { "env": "PWD" } } }` correctly matches both absolute paths under CWD and relative paths.

---

## Decision Trace

Every evaluation produces a `DecisionTrace` recording:

- **matched_rules**: rules where the matcher passed, with their effect and sandbox reference (if any)
- **skipped_rules**: rules that were considered but didn't match, with reason
- **final_resolution**: human-readable summary of how the final effect was determined

This enables the `clash explain` command and structured audit logging.

---

## Sandbox Attachment

Runtime constraints (filesystem and network sandbox policies) are attached to decisions via named sandbox references.

### How It Works

Sandbox definitions are declared at the top level of the policy and referenced by name in `Decision` nodes. When a decision includes a `SandboxRef`, the evaluator looks up the corresponding `SandboxPolicy` from `CompiledPolicy.sandboxes` and attaches it to the `PolicyDecision`.

```python
policy("default", {
    "Bash": {"cargo": allow(sandbox = cwd_sb)},
})
```

This keeps sandbox definitions decoupled from the decision tree — the same sandbox can be referenced by multiple rules.

### Enforcement

The sandbox policy is enforced at the kernel level:
- **Linux**: Landlock LSM restricts file and network access
- **macOS**: Seatbelt sandbox profiles restrict file and network access

Network enforcement has three tiers:

- **Allow** — unrestricted network access
- **AllowDomains** — a local HTTP proxy enforces domain filtering. The OS sandbox restricts the process to localhost-only connections; the proxy checks each request against the allowlist. On macOS, Seatbelt enforces the localhost restriction at the kernel level. On Linux, seccomp cannot filter `connect()` by destination (pointer argument), so proxy enforcement is advisory for programs that bypass `HTTP_PROXY`/`HTTPS_PROXY`.
- **Deny** — all network access denied at the kernel level

All sandbox policies automatically include read/write/create/delete/execute access to system temp directories, so sandboxed tools (compilers, package managers, etc.) can create temporary files without explicit policy rules. On macOS this covers `/private/tmp` and `/private/var/folders`; on Linux `/tmp` and `/var/tmp`; plus `$TMPDIR` if set to a non-standard location.

### Worktree-Aware Path Expansion

The `{ "subpath": { "path": { "env": "PWD" }, "worktree": true } }` path filter supports git worktrees at compile time. When the resolved path is inside a git worktree, the compiler detects this by reading the `.git` file's `gitdir:` pointer and the `commondir` file, then expands the single `subpath` into an `or` filter covering:

1. The original resolved path
2. The worktree-specific git directory (e.g., `/path/to/repo/.git/worktrees/my-branch`)
3. The shared common directory (e.g., `/path/to/repo/.git`)

This ensures that git commands (commit, push, etc.) work correctly inside worktrees, since git stores its data (objects, refs, config) in the main repository's `.git/` directory outside the worktree's own directory tree.

When the path is not inside a worktree, `"worktree": true` has no effect — the filter compiles to a plain `subpath`. The default policy uses `"worktree": true` on `env PWD` subpath rules for CWD access rules.

Sandbox enforcement covers filesystem and network access only. Exec-level argument matching (e.g., distinguishing `git push` from `git status`) is not enforced on child processes within the sandbox — only the top-level command is checked against exec rules. See [#136](https://github.com/empathic/clash/issues/136) for the tracking issue.

---

## Deny-Overrides Precedence

The deny-overrides principle applies **across capability domains**: if a request matches rules in multiple domains (exec, fs, net, tool), deny > ask > allow.

Within a single domain, **first-match wins** — the policy author controls precedence through rule ordering. To express "deny everything except X", put the allow rule before the deny rule:

```python
# Allow reads, deny everything else
policy("default", {("Read", "Glob", "Grep"): allow()})
# The default=deny (from settings) handles everything not matched above
```

See [ADR-002](./adr/002-deny-overrides.md) for the full rationale.
