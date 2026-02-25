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
| Unknown tools | — | no capability match → default effect |

> **Enforcement scope:** This capability mapping applies to top-level tool calls intercepted by Claude Code hooks. When a Bash command spawns child processes, those child processes are *not* re-evaluated against exec rules — only the top-level command is matched. Filesystem and network restrictions from sandbox policies are enforced at the kernel level and apply to all descendant processes. See [#136](https://github.com/empathic/clash/issues/136) for tracking exec-level enforcement of child processes.

---

## Compilation Pipeline

```
S-expression source text
    │
    ▼
Vec<TopLevel> (AST)             ← parse.rs
    │
    ├── Default { effect, policy }
    └── Policy { name, body: [Rule | Include] }
    │
    ▼
DecisionTree (IR)               ← compile.rs
    │
    ├── default: Effect
    ├── policy_name: String
    ├── exec_rules: Vec<CompiledRule>   (sorted by specificity)
    ├── fs_rules: Vec<CompiledRule>     (sorted by specificity)
    ├── net_rules: Vec<CompiledRule>    (sorted by specificity)
    └── sandbox_policies: HashMap<String, Vec<CompiledRule>>
```

### Compilation Steps

1. **Parse** — s-expression text → AST (`Vec<TopLevel>`)
2. **Find default** — extract the `(default effect "name")` declaration
3. **Build policy map** — index all `(policy "name" ...)` blocks by name
4. **Flatten** — recursively resolve `(include ...)` into a flat rule list
5. **Validate sandbox references** — verify each named `:sandbox "name"` points to an existing policy; compile inline `:sandbox (rule ...)` rules immediately
6. **Group** — split rules by capability domain (exec/fs/net)
7. **Compile matchers** — convert AST patterns to IR with pre-compiled regexes, resolve `(env NAME)` references
8. **Sort by specificity** — most specific rules first within each domain
9. **Detect conflicts** — reject rules with equal specificity but different effects that could match the same request
10. **Compile sandbox policies** — for each named sandbox reference, compile the referenced policy's rules into standalone rule sets (inline sandbox rules are compiled in step 5)

---

## Specificity Model

Rules are ranked by containment: if every request matching rule A also matches rule B, then A is more specific than B. Specificity is computed per-domain:

### Exec Rules

| Component | Score |
|-----------|-------|
| Primary: bin pattern | Literal(3) > Regex(1) > Any(0) |
| Secondary: argument specificity | Sum of arg pattern scores + arg count |

More args = more specific. Literal args score higher than wildcards.

### Fs Rules

| Component | Score |
|-----------|-------|
| Primary: path filter | Literal(3) > Regex(2) > Subpath(1) > None(0) |
| Secondary: op pattern | Single(2) > Or(1) > Any(0) |

### Net Rules

| Component | Score |
|-----------|-------|
| Primary: domain pattern | Literal(3) > Regex(1) > Any(0) |
| Secondary | Always 0 |

### Conflict Detection

Two rules **conflict** when:
1. They have equal specificity
2. They have different effects
3. Their matchers may overlap (conservative check: different literals in the same position prove non-overlap)

Conflicts are compile-time errors. This guarantees that specificity ordering is unambiguous.

---

## Evaluation Algorithm

```
evaluate(tool_name, tool_input, cwd):
    1. Map tool invocation to capability queries
       (e.g., Bash "git push" → Exec { bin: "git", args: ["push"] }, Bash "FOO=1 cargo build" → Exec { bin: "cargo", args: ["build"] })

    2. For each query, select the rule list:
       - Exec query → exec_rules
       - Fs query → fs_rules
       - Net query → net_rules

    3. Walk the rule list (sorted most-specific-first):
       - Test if the compiled matcher matches the query
       - First match wins → record effect
       - If the matching rule has :sandbox, note sandbox name in trace
       - Non-matching rules are recorded as skipped

    4. If no queries produced matches → return default effect

    5. If multiple domains matched (rare):
       - deny > ask > allow (deny-overrides)

    6. Build PolicyDecision with effect, reason, and trace
```

> **Note:** This evaluation runs once per Claude Code tool call via the PreToolUse hook. It does not run for child processes spawned by allowed Bash commands. Child processes inherit kernel-level sandbox restrictions (fs/net) but are not checked against exec rules.

### First-Match Semantics

Within a capability domain, the first matching rule wins. This is safe because:
- Rules are sorted by specificity (most specific first)
- Conflicts are rejected at compile time
- Therefore, the first match is always the most specific applicable rule

### Path Resolution

Relative paths in tool inputs are resolved against the current working directory before matching against path filters. This means `(subpath (env PWD))` correctly matches both absolute paths under CWD and relative paths.

---

## Decision Trace

Every evaluation produces a `DecisionTrace` recording:

- **matched_rules**: rules where the matcher passed, with their effect and sandbox reference (if any)
- **skipped_rules**: rules that were considered but didn't match, with reason
- **final_resolution**: human-readable summary of how the final effect was determined

This enables the `clash explain` command and structured audit logging.

---

## Sandbox Generation

When an exec allow rule matches with a `:sandbox` annotation, the sandbox rules define the filesystem and network permissions for the spawned process. Sandbox rules can be specified two ways:

- **Named**: `:sandbox "name"` references a `(policy "name" ...)` block whose rules are pre-compiled into `sandbox_policies`.
- **Inline**: `:sandbox (allow (net *)) (allow (fs ...))` compiles the inline rules directly into `sandbox_policies` under a synthetic key.

Both forms produce the same compiled representation — downstream evaluation is identical.

The sandbox policy is enforced at the kernel level:
- **Linux**: Landlock LSM restricts file and network access
- **macOS**: Seatbelt sandbox profiles restrict file and network access

Network enforcement in sandboxes has three tiers:

- **Wildcard** `(allow (net))` — unrestricted network access
- **Domain-specific** `(allow (net "crates.io"))` — a local HTTP proxy enforces domain filtering. The OS sandbox restricts the process to localhost-only connections; the proxy checks each request against the allowlist. On macOS, Seatbelt enforces the localhost restriction at the kernel level. On Linux, seccomp cannot filter `connect()` by destination (pointer argument), so proxy enforcement is advisory for programs that bypass `HTTP_PROXY`/`HTTPS_PROXY`.
- **No net rule** — all network access denied at the kernel level

When no `:sandbox` is specified on an exec allow, the spawned process gets a deny-all sandbox by default.

All sandbox policies automatically include read/write/create/delete/execute access to system temp directories, so sandboxed tools (compilers, package managers, etc.) can create temporary files without explicit policy rules. On macOS this covers `/private/tmp` and `/private/var/folders`; on Linux `/tmp` and `/var/tmp`; plus `$TMPDIR` if set to a non-standard location.

When the working directory is inside a **git worktree**, sandbox policies and filesystem rules automatically include the backing repository's git directories. Git worktrees store their data (objects, refs, config) in the main repository's `.git/` directory, which is outside the worktree's own directory tree. Clash detects this by reading the `.git` file's `gitdir:` pointer and the `commondir` file, then grants access to both the worktree-specific git directory and the shared common directory. This ensures that git commands (commit, push, etc.) work correctly inside worktrees without requiring explicit policy rules. These rules are injected under the policy name `__worktree__` — to disable this behavior, define an empty `(policy "__worktree__")` in your policy file, following the same override mechanism as `__internal_clash__` and `__internal_claude__`.

Sandbox enforcement covers filesystem and network access only. Exec-level argument matching (e.g., distinguishing `git push` from `git status`) is not enforced on child processes within the sandbox — only the top-level command is checked against exec rules. See [#136](https://github.com/empathic/clash/issues/136) for the tracking issue.

*(Note: Kernel-level sandbox enforcement is a future PR. Currently the sandbox reference is validated and compiled but not yet enforced.)*

---

## Deny-Overrides Precedence

The deny-overrides principle applies at two levels:

1. **Within a domain**: first-match wins (specificity ordering ensures the most specific rule is checked first)
2. **Across domains**: if a request matches rules in multiple domains, deny > ask > allow

A deny rule can never be overridden by an allow rule. To express "deny everything except X", use negation patterns:

```
(deny  (fs write (not (subpath (env PWD)))))   ; deny writes outside CWD
(allow (fs write (subpath (env PWD))))          ; allow writes inside CWD
```

See [ADR-002](./adr/002-deny-overrides.md) for the full rationale.
