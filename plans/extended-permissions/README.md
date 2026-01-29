# Extended Permissions System: Policy Language Design

## Core Concept

Permissions are expressed as **statements** over `(entity, verb, noun)` triples:

```
effect(entity, verb, noun)
```

- **Entity**: who is requesting — `agent:claude`, `user`, `service:github-mcp`, `*`
- **Verb**: what action — `read`, `write`, `edit`, `execute`
- **Noun**: what resource — file paths, command strings, globs

A **request** is a concrete triple: `(agent:claude, read, ~/config/test.json)`.
A **statement** is a rule that matches requests and produces an effect.

---

## Statement Semantics

### Effects

Three effects: `permit`, `forbid`, `ask`.

```
permit(agent:claude, execute, git *)     # allow claude to run git commands
forbid(*, write, ~/.ssh/*)               # nobody can write to .ssh
ask(agent:*, execute, rm *)              # always confirm rm commands
```

### Evaluation

1. Collect all statements that match the request
2. Apply effect precedence: **forbid > ask > permit**
3. If no statement matches: apply the **default effect** (configurable)

```toml
[policy]
default = "ask"       # interactive mode
# default = "deny"    # headless/CI mode
```

### Negation

`!` inverts the match on **entity** and **noun** slots only. Verbs are always positive.

```
forbid(!user, read, ~/config/*)         # only users can read config
forbid(agent:*, write, !~/code/proj/**) # agents can't write outside project
permit(*, read, !~/.ssh/*)              # anyone can read anything except .ssh
```

`!pattern` matches when the pattern does NOT match. So `!user` matches any entity that is not `user`. `!~/code/proj/**` matches any path not under `~/code/proj/`.

### Entity Model

Entities are extensible, typed names:

```
*                    # wildcard — matches any entity
user                 # the human operator
agent                # any AI agent (shorthand for agent:*)
agent:claude         # specific agent
agent:codex          # another agent
service:github-mcp   # an MCP server or external service
service:*            # any service
```

Entity hierarchy:
- `*` matches everything
- `agent` matches `agent:claude`, `agent:codex`, etc.
- `service` matches `service:github-mcp`, etc.
- `user` is a leaf (no subtypes for now)

### Verb Model

Fixed set of verbs mapping to tool types:

| Verb | Tool | Noun is... |
|------|------|------------|
| `read` | Read | file path |
| `write` | Write | file path |
| `edit` | Edit | file path |
| `execute` | Bash | command string |
| `delegate` | (future) | service endpoint |

Verbs are not negatable. `*` is supported as a verb wildcard:

```
forbid(agent:untrusted, *, ~/sensitive/**)   # deny all actions on sensitive
```

### Pattern Matching

Nouns support three matching modes:

| Syntax | Meaning | Example |
|--------|---------|---------|
| `*` | Match anything | `permit(*, read, *)` |
| `exact string` | Exact match | `forbid(*, read, .env)` |
| `glob pattern` | Glob with `*` and `**` | `permit(*, read, ~/code/**/*.rs)` |
| `prefix *` | Prefix match (for commands) | `permit(agent, execute, git *)` |

Entity patterns support:

| Syntax | Meaning |
|--------|---------|
| `*` | Any entity |
| `user` | The human user |
| `agent` | Any agent (= `agent:*`) |
| `agent:claude` | Specific named agent |
| `service:*` | Any service |
| `!pattern` | Invert — match everything the pattern doesn't |

---

## Textual Representation (TOML)

### Simple case — backward compatible

```toml
# ~/.clash/policy.toml

[policy]
default = "ask"

[permissions]
allow = ["Bash(git:*)", "Read(**/*.rs)"]
deny = ["Read(.env)", "Bash(rm -rf:*)"]
ask = ["Write"]
```

The `[permissions]` block is syntactic sugar. It desugars to statements with `entity = "agent"`:
- `allow` → `permit(agent, execute, git *)`
- `deny` → `forbid(agent, read, .env)`
- `ask` → `ask(agent, write, *)`

### Full statement syntax

```toml
[policy]
default = "ask"

[[statements]]
effect = "permit"
entity = "*"
verb = "read"
noun = "~/**/*.rs"

[[statements]]
effect = "forbid"
entity = "!user"
verb = "read"
noun = "~/config/*"
reason = "Only users can read config files"

[[statements]]
effect = "forbid"
entity = "agent:*"
verb = "write"
noun = "!~/code/myproject/**"
reason = "Agents restricted to project directory"

[[statements]]
effect = "ask"
entity = "agent:*"
verb = "execute"
noun = "rm *"
reason = "Destructive commands require confirmation"

[[statements]]
effect = "permit"
entity = "agent:claude"
verb = "execute"
noun = "git *"

[[statements]]
effect = "permit"
entity = "agent:claude"
verb = "execute"
noun = "cargo *"
```

### Delegation (future extension)

```toml
[[statements]]
effect = "delegate"
entity = "agent:*"
verb = "execute"
noun = "*"
delegate.type = "http"
delegate.endpoint = "http://localhost:9090/evaluate"
delegate.timeout_ms = 5000
delegate.fallback = "ask"
```

---

## Rust Type Design

### Core types — `claude_settings/src/policy.rs`

```rust
/// A complete policy document.
pub struct PolicyDocument {
    pub policy: PolicyConfig,
    pub permissions: Option<LegacyPermissions>,  // backward compat
    pub statements: Vec<Statement>,
}

pub struct PolicyConfig {
    pub default: Effect,  // ask, deny, or permit
}

pub enum Effect {
    Permit,
    Forbid,
    Ask,
    Delegate,
}

/// A single policy statement: effect(entity, verb, noun).
pub struct Statement {
    pub effect: Effect,
    pub entity: Pattern,      // who — supports !
    pub verb: VerbPattern,    // what action — no !
    pub noun: Pattern,        // what resource — supports !
    pub reason: Option<String>,
    pub delegate: Option<DelegateConfig>,
}

/// A pattern that may be negated.
pub enum Pattern {
    /// Matches when the inner pattern matches.
    Match(MatchExpr),
    /// Matches when the inner pattern does NOT match.
    Not(MatchExpr),
}

/// The actual matching expression.
pub enum MatchExpr {
    /// Wildcard — matches anything.
    Any,
    /// Exact string match.
    Exact(String),
    /// Glob pattern (*, **, ?).
    Glob(String),
    /// Typed entity (e.g., "agent:claude").
    Typed { entity_type: String, name: Option<String> },
}

/// Verb pattern — not negatable, supports wildcard.
pub enum VerbPattern {
    /// Matches any verb.
    Any,
    /// Matches a specific verb.
    Exact(Verb),
}

pub enum Verb {
    Read,
    Write,
    Edit,
    Execute,
    Delegate,
}
```

### Compiled policy — `claude_settings/src/policy/compile.rs`

```rust
/// Pre-compiled policy for fast evaluation.
pub struct CompiledPolicy {
    pub default: Effect,
    pub statements: Vec<CompiledStatement>,
}

pub struct CompiledStatement {
    pub effect: Effect,
    pub entity_matcher: CompiledPattern,
    pub verb_matcher: CompiledVerbPattern,
    pub noun_matcher: CompiledPattern,
    pub reason: Option<String>,
    pub delegate: Option<DelegateConfig>,
}

pub enum CompiledPattern {
    Match(CompiledMatchExpr),
    Not(CompiledMatchExpr),
}

pub enum CompiledMatchExpr {
    Any,
    Exact(String),
    Glob { pattern: String, regex: regex::Regex },
    Typed { entity_type: String, name: Option<String> },
}
```

### Evaluation context — `clash/src/policy_eval.rs`

```rust
/// A concrete request to evaluate.
pub struct Request<'a> {
    pub entity: &'a str,       // "agent:claude", "user", etc.
    pub verb: Verb,            // Read, Write, Edit, Execute
    pub noun: &'a str,         // file path or command string
    // Extended context (for conditions, future use)
    pub cwd: &'a str,
    pub session_id: &'a str,
    pub tool_input: &'a serde_json::Value,
}

impl CompiledPolicy {
    pub fn evaluate(&self, request: &Request) -> Effect {
        let mut matched_effects: Vec<&Effect> = Vec::new();

        for stmt in &self.statements {
            if stmt.matches(request) {
                matched_effects.push(&stmt.effect);
            }
        }

        if matched_effects.is_empty() {
            return self.default.clone();
        }

        // Precedence: forbid > ask > permit
        if matched_effects.iter().any(|e| **e == Effect::Forbid) {
            return Effect::Forbid;
        }
        if matched_effects.iter().any(|e| **e == Effect::Ask) {
            return Effect::Ask;
        }
        if matched_effects.iter().any(|e| **e == Effect::Delegate) {
            return Effect::Delegate;
        }
        Effect::Permit
    }
}
```

### Delegation — `clash/src/delegate.rs`

```rust
pub struct DelegateConfig {
    pub delegate_type: DelegateType,
    pub endpoint: String,
    pub timeout_ms: u64,
    pub fallback: Effect,
    pub cache_ttl_secs: u64,
    pub headers: HashMap<String, String>,
}

pub enum DelegateType {
    Http,
    Command,
}

/// JSON sent to delegate endpoint.
pub struct DelegateRequest {
    pub entity: String,
    pub verb: String,
    pub noun: String,
    pub cwd: String,
    pub session_id: String,
    pub tool_input: serde_json::Value,
}

/// JSON received from delegate endpoint.
pub struct DelegateResponse {
    pub effect: Effect,    // "permit", "forbid", "ask"
    pub reason: Option<String>,
}
```

---

## Enforcement Pipeline

```
Hook stdin (JSON)
    │
    ▼
Parse ToolUseHookInput
    │
    ▼
Build Request {
    entity: determine from context (currently always "agent:claude")
    verb:   tool_name → Verb mapping
    noun:   extract from tool_input (command / file_path)
    cwd, session_id, tool_input: from hook input
}
    │
    ▼
Check engine_mode setting ─┬─ "policy"  → evaluate CompiledPolicy
                           ├─ "legacy"  → use existing PermissionSet
                           └─ "auto"    → try policy, fall back to legacy
    │
    ▼
CompiledPolicy::evaluate(request)
    │
    ├─ Collect all matching statements
    ├─ Apply precedence: forbid > ask > permit
    ├─ If no match: return default effect
    ├─ If delegate: dispatch to endpoint, cache, fallback on error
    │
    ▼
Map Effect → HookOutput
    permit → HookOutput::allow(reason)
    forbid → HookOutput::deny(reason)
    ask    → HookOutput::ask(reason)
    │
    ▼
Write HookOutput to stdout
```

### Engine mode

Users choose which engine to use in `~/.clash/settings.json`:

```json
{
    "engine_mode": "policy"
}
```

- `"policy"` — only the new statement-based engine
- `"legacy"` — only the existing Claude Code PermissionSet
- `"auto"` — policy engine first, legacy fallback

---

## Migration

`clash migrate` reads existing Claude Code settings and produces policy.toml:

| Current JSON | Generated Statement |
|---|---|
| `allow: ["Bash(git:*)"]` | `permit(agent, execute, git *)` |
| `allow: ["Read"]` | `permit(agent, read, *)` |
| `allow: ["Read(**/*.rs)"]` | `permit(agent, read, **/*.rs)` |
| `deny: ["Read(.env)"]` | `forbid(agent, read, .env)` |
| `deny: ["Bash(rm -rf:*)"]` | `forbid(agent, execute, rm -rf *)` |
| `ask: ["Write"]` | `ask(agent, write, *)` |

---

## Files to Create/Modify

### New files

| File | Purpose |
|------|---------|
| `claude_settings/src/policy.rs` | `PolicyDocument`, `Statement`, `Effect`, `Pattern`, `MatchExpr`, `Verb`, `VerbPattern` |
| `claude_settings/src/policy/compile.rs` | `CompiledPolicy`, `CompiledStatement`, `CompiledPattern`, compilation logic |
| `claude_settings/src/policy/parse.rs` | TOML deserialization, legacy `[permissions]` desugaring |
| `clash/src/policy_eval.rs` | `Request`, evaluation logic, integration with hook pipeline |
| `clash/src/delegate.rs` | HTTP + subprocess delegation, caching, `DelegateRequest`/`DelegateResponse` |

### Modified files

| File | Changes |
|------|---------|
| `clash/src/settings.rs` | Add `engine_mode`, policy loading, `CompiledPolicy` field |
| `clash/src/permissions.rs` | Route through policy engine based on engine_mode |
| `clash/src/main.rs` | Add `migrate` and `policy check` subcommands |
| `claude_settings/src/lib.rs` | Re-export policy module |

---

## Implementation Phases

### Phase 1: Core types + TOML parsing ✅ DONE
- Statement, Effect, Pattern, MatchExpr, Verb types with serde
- Parse `policy.toml` with `[policy]` config and `[[statements]]`
- Parse legacy `[permissions]` block, desugar to statements
- Unit tests for parsing and desugaring
- Files: `claude_settings/src/policy/mod.rs`, `claude_settings/src/policy/parse.rs`

### Phase 2: Compilation + evaluation ✅ DONE
- CompiledPolicy with pre-compiled regex/glob patterns
- evaluate() with forbid > ask > permit precedence
- `!` negation on entity and noun
- Configurable default effect
- 40 unit tests passing
- Files: `claude_settings/src/policy/compile.rs`
- Note: policy glob uses `.*` for `*` (not `[^/]*`) since patterns apply to both paths and commands

### Phase 3: Integration — NEXT
- Engine mode setting in ClashSettings
- Wire policy evaluation into check_permission()
- `clash migrate` subcommand
- Integration tests end-to-end

### Phase 4: Delegation
- HTTP POST delegation (reqwest/ureq)
- Subprocess delegation (stdin/stdout JSON)
- Response caching, timeout, fallback
- Integration tests with mock endpoints

### Phase 5: Advanced (future)
- Conditions block (cwd, env, rate limits)
- Policy imports
- `clash policy check` validation
- `clash policy test` dry-run simulation
- File watching for hot-reload

---

## Verification

- `just check` passes
- Unit tests: TOML parsing (valid, invalid, legacy compat)
- Unit tests: pattern matching (exact, glob, prefix, negation with !)
- Unit tests: evaluation (forbid > ask > permit, default effect, no-match)
- Unit tests: entity hierarchy (agent:claude matches agent, * matches all)
- Unit tests: migration (JSON → TOML statements)
- Integration test: full hook invocation with policy.toml
- Manual test: `echo '{"tool_name":"Bash",...}' | clash hook pre-tool-use`

---

## Design Rationale

### Why (entity, verb, noun) triples?

The core insight is that permissions are fundamentally about "X wants to do Y to Z." This maps to the same subject-action-resource model used by:

- **Cedar (AWS)**: principal/action/resource with `permit`/`forbid` statements
- **XACML**: subject/action/resource/environment
- **Casbin**: subject/object/action with configurable matchers
- **OPA/Rego**: freeform input with conventional allow/deny rules

Cedar is the closest fit: native Rust implementation (`cedar-policy` crate), sub-millisecond evaluation, formally verified, and uses the same permit/forbid duality we chose.

### Why forbid > ask > permit precedence?

This is the "deny-overrides" combining algorithm from XACML, also used by Cedar's "forbid overrides permit" semantics. It's the safest default: a single forbid rule cannot be accidentally overridden by a permit.

### Why configurable default effect?

Different environments have different safety requirements:
- **Interactive** (human at keyboard): default to `ask` — the human can approve
- **Headless/CI** (no human): default to `deny` — fail closed
- **Trusted sandbox**: could default to `permit` with specific forbids

### Why `!` negation on entity and noun only?

Verbs are a small, fixed set. Negating them (`!read` means "write, edit, execute, delegate") is confusing and better expressed as separate statements. Entity and noun negation is much more natural: "not this user" and "not under this path" are common real-world policies.

### Why TOML?

- figment (already a dependency) supports TOML
- Human-readable and editable
- Supports arrays-of-tables (`[[statements]]`) naturally
- No footgun problems like YAML (Norway problem, etc.)
- pest (already a dependency) available for future custom DSL layer
