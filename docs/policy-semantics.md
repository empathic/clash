# Policy Evaluation Semantics

How clash evaluates requests against compiled policies.

---

## Request Model

Every request is a triple:

| Slot | Description | Examples |
|------|-------------|----------|
| **Entity** | Who is making the request | `agent:claude`, `user`, `service:mcp` |
| **Verb** | What action is being performed | `read`, `write`, `edit`, `execute`, `delegate` |
| **Noun** | What resource is being acted upon | `/home/user/file.rs`, `git commit -m 'fix'` |

Additional context is available during evaluation:

- **cwd**: current working directory (for resolving relative paths)
- **tool_input**: raw JSON from the tool call (for extracting command strings)
- **verb_str**: raw tool name string (for arbitrary verb matching in new-format rules)

---

## Compilation Pipeline

```
YAML/TOML text
    │
    ▼
PolicyDocument (AST)          ← parse.rs
    │
    ├── Legacy statements     ← Statement with entity/verb/noun
    ├── Named constraints     ← ConstraintDef
    ├── Named profiles        ← ProfileExpr
    └── Profile definitions   ← ProfileDef with inline rules
    │
    ▼
CompiledPolicy (IR)           ← compile.rs
    │
    ├── active_profile_rules  ← Vec<CompiledProfileRule> (unified)
    ├── constraints           ← HashMap<String, CompiledConstraintDef>
    └── profiles              ← HashMap<String, ProfileExpr>
```

### Format Unification

Both legacy `Statement`s and new-format `ProfileRule`s are converted into `CompiledProfileRule` at compile time. This enables a single evaluation path:

| Legacy field | Converted to |
|-------------|-------------|
| `VerbPattern::Any` | `verb: "*"` |
| `VerbPattern::Exact(v)` | `verb: v.rule_name()` |
| `entity: Pattern` | `entity_matcher: Some(CompiledPattern)` |
| `noun: Pattern` | `noun_matcher: CompiledPattern` |
| `profile: Option<ProfileExpr>` | `profile_guard: Option<ProfileExpr>` |
| `reason: Option<String>` | `reason: Option<String>` |
| `delegate: Option<DelegateConfig>` | `delegate: Option<DelegateConfig>` |

New-format rules have `entity_matcher: None` (always match all entities) and `profile_guard: None` (use inline constraints instead).

---

## Evaluation Algorithm

For each rule in `active_profile_rules` (order-independent due to precedence):

```
1. ENTITY MATCH
   If rule.entity_matcher is Some, check against ctx.entity.
   Skip rule if no match.

2. VERB MATCH
   If rule.verb == "*", match any verb.
   Otherwise, exact string match against ctx.verb_str.
   Skip rule if no match.

3. NOUN MATCH
   Evaluate rule.noun_matcher against ctx.noun.
   Pattern types: Any, Exact, Glob (pre-compiled regex), Typed (entity-only).
   Negated patterns invert the match.
   Skip rule if no match.

4. INLINE CONSTRAINT CHECK
   If rule.constraints is Some, check:
   - pipe: if false, command must not contain unquoted '|'
   - redirect: if false, command must not contain unquoted '>' or '<'
   - forbid_args: none of the forbidden args may appear in command tokens
   - require_args: at least one required arg must appear in command tokens
   Skip rule if any constraint fails.

5. CAP-SCOPED FS GUARD (non-bash verbs only)
   If rule.constraints has fs entries:
   - Map verb to capability (read→READ, write→WRITE|CREATE, edit→WRITE)
   - For each fs entry whose caps intersect the verb cap:
     the noun must match the filter expression
   Skip rule if guard fails.

6. PROFILE GUARD (legacy-converted rules only)
   If rule.profile_guard is Some, evaluate the profile expression:
   - Ref(name): resolve as profile (recurse) or constraint (eval)
   - And(a, b): both must be satisfied
   - Or(a, b): at least one must be satisfied
   - Not(inner): inner must NOT be satisfied
   Skip rule if guard fails.

7. RECORD MATCH
   Record the rule's effect (deny/ask/allow/delegate).
```

### Constraint Evaluation (Legacy Named Constraints)

`CompiledConstraintDef.eval()` checks all specified fields (AND):

- **fs** (non-bash only): resolved path must match filter expression
- **pipe**: command must not have unquoted `|`
- **redirect**: command must not have unquoted `>` or `<`
- **forbid_args**: command must not contain any forbidden argument
- **require_args**: command must contain at least one required argument

For bash commands, `fs` is **not** checked as a permission guard — instead, it generates sandbox rules for kernel-level enforcement.

---

## Precedence Resolution

After all rules are evaluated, the final effect is determined by strict precedence:

```
deny > ask > allow > delegate > default
```

This means:
- If **any** matching rule says `deny`, the result is `deny` regardless of other rules
- If no deny but **any** matching rule says `ask`, the result is `ask`
- If no deny/ask but **any** matching rule says `allow`, the result is `allow`
- If no deny/ask/allow but **any** matching rule says `delegate`, the result is `delegate`
- If **no rules match**, the configured `default` effect applies (typically `ask`)

Rule order in the document does **not** affect precedence. A deny rule at the bottom overrides an allow rule at the top.

---

## Negation

The `!` operator inverts pattern matching:

```yaml
# Only users can read config (deny non-users)
deny !user read ~/config/*

# Agents can't write outside project
deny agent:* write !~/code/proj/**
```

For entity patterns: `!user` matches anything that is NOT `user`.
For noun patterns: `!~/code/proj/**` matches any path NOT under `~/code/proj/`.

---

## Sandbox Generation

When an `allow` rule matches a bash command and has filesystem constraints, a kernel-level sandbox policy is generated.

### Sources

Two sources of sandbox rules are merged:

1. **Inline constraints** (new format): cap-scoped `(filter, cap)` pairs from `CompiledInlineConstraints.fs`
2. **Profile guards** (legacy format): profile expressions walked to collect `fs`, `caps`, `network` from referenced constraints

### Filter-to-Sandbox Mapping

| FilterExpr | SandboxRule |
|-----------|-------------|
| `Subpath(".")` | Allow caps on resolved cwd path, PathMatch::Subpath |
| `Literal(".env")` | Allow caps on resolved path, PathMatch::Literal |
| `Regex(pattern)` | Allow caps matching pattern, PathMatch::Regex |
| `Not(inner)` | Flip effect: Allow ↔ Deny |
| `And(a, b)` | Collect rules from both sides |
| `Or(a, b)` | Collect rules from both sides |

### Sandbox Defaults

- **Default capabilities**: `READ | EXECUTE` (processes can read and execute by default)
- **Network**: `Allow` unless any constraint specifies `Deny` (deny wins)
- **Caps composition**: intersection (most restrictive wins across multiple constraints)

### Cap-Scoped Filesystem Constraints

New-format rules scope filesystem constraints by capability:

```yaml
fs:
  read + write: subpath(~/.ssh)    # READ and WRITE restricted to ~/.ssh
  read: "!regex(\\./)"             # READ denied for dotfile-relative paths
```

Each entry maps a capability set to a filter expression. For bash commands, these become sandbox rules. For non-bash verbs, they act as permission guards (the verb is mapped to a capability and checked against matching entries).

The shorthand `full` can be used in place of `read + write + create + delete + execute`:

```yaml
fs:
  full: subpath(.)    # All capabilities under CWD
```

---

## Profile Inheritance

New-format profiles support single or multiple inheritance via `include:`:

```yaml
profiles:
  base:
    rules:
      deny bash rm *:

  dev:
    include: base
    rules:
      allow bash git *:
```

Flattening resolves the include chain depth-first: parent rules come first (lower precedence in document order, but precedence is effect-based not order-based). Circular includes are detected at parse time.

---

## Entity Hierarchy

Entity matching respects a type hierarchy:

| Pattern | Matches |
|---------|---------|
| `*` | Everything |
| `agent` | `agent`, `agent:claude`, `agent:codex`, ... |
| `agent:claude` | Only `agent:claude` |
| `user` | Only `user` |
| `service:mcp` | Only `service:mcp` |

A bare type name (e.g., `agent`) matches the type itself and any instance of that type.

---

## Decision Trace

Every evaluation produces a `DecisionTrace` recording:

- **matched_rules**: rules where entity/verb/noun/constraints all passed, with their effect
- **skipped_rules**: rules considered but rejected, with the reason (entity mismatch, constraint failure, etc.)
- **final_resolution**: human-readable summary of precedence resolution

This enables the `clash explain` command and structured audit logging.
