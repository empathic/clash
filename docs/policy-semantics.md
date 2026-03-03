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
    ├── Version { number }
    ├── Use { policy_name }
    └── Policy { name, body: [When | Match | Effect | Include] }
    │
    ▼
PolicyTree (IR)                 ← compile.rs, tree.rs
    │                             (v1 also compiles to flat DecisionTree)
    ├── default: Effect
    ├── policy_name: String
    ├── root: Node               (tree-shaped decision structure)
    │   ├── Sequence { children }
    │   ├── DenyOverrides { children }
    │   ├── When { predicate, body }
    │   ├── Match { observable, arms, constraint_policy? }
    │   └── Leaf { effect }
    └── node_meta: Vec<NodeMeta>
```

### Compilation Steps

1. **Parse** — s-expression text → AST (`Vec<TopLevel>`)
2. **Extract version** — read the `(version N)` declaration from the AST (default: 1 if absent)
3. **Validate version** — verify the declared version is a known version (≤ `CURRENT_VERSION`); reject unknown future versions. Future: check for deprecated features based on the declared version.
4. **Find default** — extract the `(default effect "name")` declaration
5. **Build policy map** — index all `(policy "name" ...)` blocks by name
6. **Flatten** — recursively resolve `(include ...)` into a flat rule list
7. **Validate sandbox references** — verify each named `:sandbox "name"` points to an existing policy; compile inline `:sandbox (rule ...)` rules immediately
8. **Group** — split rules by capability domain (exec/fs/net)
9. **Compile matchers** — convert AST patterns to IR with pre-compiled regexes, resolve `(env NAME)` references
10. **Sort by specificity** — most specific rules first within each domain
11. **Detect conflicts** — reject rules with equal specificity but different effects that could match the same request
12. **Compile sandbox policies** — for each named sandbox reference, compile the referenced policy's rules into standalone rule sets (inline sandbox rules are compiled in step 7)

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
    1. Map tool invocation to EvalContext
       (command, tool, http.domain, fs.action, fs.path, etc.)

    2. Walk the policy tree (root node):
       - Sequence: evaluate children in order, return first match
       - DenyOverrides: evaluate ALL children, deny > ask > allow
       - When: test predicate against context, recurse into body if true
       - Match: if observable is relevant, dispatch on arms (first-match);
               if irrelevant and constraint_policy present,
               merge constraints into SandboxOut, return implicit Allow
       - Leaf: return effect

    3. If tree walk produces no match → return default effect

    4. Build PolicyDecision with effect, sandbox_out, and trace
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

## Constraint Derivation (v3)

In v3, runtime constraints (filesystem and network sandbox policies) are derived from surviving `(match ...)` blocks in the decision tree, rather than from explicit `(sandbox ...)` annotations.

### How It Works

Match blocks on constraint-derivable observables (`ctx.http.domain`, `ctx.http.method`, `ctx.http.port`, `ctx.http.path`, `ctx.fs.action`, `ctx.fs.path`, `ctx.fs.exists`) are pre-compiled into a `SandboxPolicy` at compile time. The `constraint_policy` is attached to the `Node::Match` in the decision tree.

At runtime, the decision tree is evaluated. When a match block's observable is **relevant** (e.g. the request involves HTTP), it dispatches normally (first-match on arms). When the observable is **irrelevant** (e.g. an `ctx.http.domain` match on a non-HTTP request), the match block contributes its pre-compiled constraints to the `SandboxOut` and returns an implicit `Allow`.

### DenyOverrides for When Bodies

When a `(when ...)` block has multiple body items (e.g. an effect + constraint match blocks), the body uses `DenyOverrides` semantics: all children are evaluated (not just the first match), allowing both the decision effect and constraints to be collected.

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

The `(subpath :worktree <path>)` path filter supports git worktrees at compile time. When the resolved path is inside a git worktree, the compiler detects this by reading the `.git` file's `gitdir:` pointer and the `commondir` file, then expands the single `subpath` into an `or` filter covering:

1. The original resolved path
2. The worktree-specific git directory (e.g., `/path/to/repo/.git/worktrees/my-branch`)
3. The shared common directory (e.g., `/path/to/repo/.git`)

This ensures that git commands (commit, push, etc.) work correctly inside worktrees, since git stores its data (objects, refs, config) in the main repository's `.git/` directory outside the worktree's own directory tree.

When the path is not inside a worktree, `:worktree` has no effect — the filter compiles to a plain `subpath`. The default policy uses `(subpath :worktree (env PWD))` for CWD access rules.

Sandbox enforcement covers filesystem and network access only. Exec-level argument matching (e.g., distinguishing `git push` from `git status`) is not enforced on child processes within the sandbox — only the top-level command is checked against exec rules. See [#136](https://github.com/empathic/clash/issues/136) for the tracking issue.

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
