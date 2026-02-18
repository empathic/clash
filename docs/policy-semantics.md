# Policy Evaluation Semantics

How clash compiles and evaluates policies.

---

## Capability Model

Clash operates on three capability domains, not individual tools. Tool invocations are mapped to capability queries at evaluation time:

| Tool | Capability | Fields |
|------|-----------|--------|
| `Bash` | `exec` | bin = first word of command, args = rest |
| `Read` | `fs(read)` | path = `file_path` |
| `Write` | `fs(write)` | path = `file_path` |
| `Edit` | `fs(write)` | path = `file_path` |
| `WebFetch` | `net` | domain extracted from `url` |
| `WebSearch` | `net` | domain = `*` (any) |
| `Glob`/`Grep` | `fs(read)` | path = `path` or `pattern` |
| Unknown tools | — | no capability match → default effect |

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
5. **Validate sandbox references** — verify each `:sandbox "name"` points to an existing policy
6. **Group** — split rules by capability domain (exec/fs/net)
7. **Compile matchers** — convert AST patterns to IR with pre-compiled regexes, resolve `(env NAME)` references
8. **Sort by specificity** — most specific rules first within each domain
9. **Detect conflicts** — reject rules with equal specificity but different effects that could match the same request
10. **Compile sandbox policies** — for each sandbox reference, compile the referenced policy's rules into standalone rule sets

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
       (e.g., Bash "git push" → Exec { bin: "git", args: ["push"] })

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

This enables the `clash-cli explain` command and structured audit logging.

---

## Sandbox Generation

When an exec allow rule matches with `:sandbox "name"`, the referenced policy's rules are pre-compiled in `sandbox_policies`. These rules define the filesystem and network permissions for the spawned process.

The sandbox policy is enforced at the kernel level:
- **Linux**: Landlock LSM restricts file and network access
- **macOS**: Seatbelt sandbox profiles restrict file and network access

When no `:sandbox` is specified on an exec allow, the spawned process gets a deny-all sandbox by default.

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
