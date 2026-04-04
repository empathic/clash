# Modular Policy Generation & Sandbox Mutation

## Problem

Clash has three independent policy generators (`from_posture`, `from_analysis`, `from_trace`) that have diverged significantly. They duplicate tool name lists, sandbox definitions, load statement logic, and ecosystem integration — leading to bugs where one path references variables another doesn't define. The Starlark API also has inconsistent shapes between `sandbox()` and `policy()`, and users cannot modify built-in sandboxes without copying the entire definition.

## Goals

1. Eliminate fragility in policy generation through shared Rust-side definitions
2. Make generators composable — one pipeline with multiple inputs, where one input can be another generator's output
3. Give users a mutation API for sandboxes (`extend`, `remove`)
4. Unify the Starlark API shape
5. Push logic into statically typed Rust — Starlark becomes a thin DSL layer

## Design

### Unified Starlark API

**`sandbox(name, rules_dict)`** — two positional args. The dict keys describe what's matched (paths, domains), values describe capabilities:

```python
my_box = sandbox("my_box", {
    glob("$PWD/**"): allow("rwc"),
    glob("$HOME/.claude/**"): allow("rwc"),
    domain("github.com"): allow(),
})
```

**`settings()`** — the single top-level registration call. Policy is a dict, not a separate function:

```python
settings(
    default=ask(),
    default_sandbox=my_box,
    harness_defaults=True,
    on_sandbox_violation="smart",
    policy={
        ("Read", "Write", "Edit"): allow(sandbox=my_box),
        "Bash": {
            "git": allow(sandbox=git_full),
            "cargo": { glob("**"): allow(sandbox=rust_full) },
        },
    },
)
```

There is no `policy()` wrapper function. The `policy` kwarg takes a raw dict with the same rule grammar that exists today.

**Sandbox mutation** — methods on sandbox objects, always producing a new named sandbox:

```python
load("@clash//sandboxes.star", "git_full")

my_git = git_full.extend("my_git", {
    glob("$HOME/.gitconfig"): allow("r"),
})

my_git_restricted = git_full.remove("my_git_restricted", [
    domain("github.com"),
])
```

`extend(name, dict)` adds or overrides rules — keys are patterns, values are capabilities. `remove(name, list)` removes rules matching the given patterns — a list of keys, no values needed. Both return a new `SandboxTemplate` with the given name. The original is unchanged.

### SandboxTemplate (Rust)

The source of truth for sandbox definitions lives in Rust:

```rust
struct SandboxTemplate {
    name: String,
    default_caps: Cap,           // from existing Cap bitflags
    rules: Vec<SandboxRule>,     // typed path/domain + caps pairs
    network: NetworkPolicy,      // existing enum
}
```

Where `SandboxRule` uses typed path patterns instead of strings:

```rust
enum PathPattern {
    Cwd { follow_worktrees: bool },
    Home(Option<String>),        // Home(Some(".claude")) = $HOME/.claude
    Env(String),                 // arbitrary env var
    Literal(String),             // absolute path
}

struct SandboxRule {
    pattern: PathPattern,
    path_match: PathMatch,       // Subpath, ChildOf, Literal
    caps: Cap,
}
```

**Built-in templates** are Rust constants/functions:

- `SandboxTemplate::project()` — `$PWD` rwc + `$HOME/.claude` rwc
- `SandboxTemplate::readonly()` — `$PWD` read-only
- `SandboxTemplate::workspace()` — `$HOME` full minus sensitive dirs
- `SandboxTemplate::git_safe()`, `::git_full()`, etc.
- Ecosystem templates: `SandboxTemplate::rust_full()`, `::node_full()`, etc.

These replace the current Starlark-defined presets in `sandboxes.star`. The `.star` files become thin wrappers that instantiate the Rust templates, or are eliminated entirely.

**Mutation methods** on `SandboxTemplate`:

```rust
impl SandboxTemplate {
    fn extend(self, name: &str, rules: Vec<SandboxRule>) -> Self
    fn remove(self, name: &str, patterns: Vec<PathPattern>) -> Self
    fn with_default(self, caps: Cap) -> Self
    fn with_network(self, network: NetworkPolicy) -> Self
}
```

These are exposed to Starlark via the sandbox object type. Starlark parses arguments and delegates to Rust.

**Serialization:** `SandboxTemplate` emits Starlark AST (`to_starlark() -> Vec<Stmt>`) for policy file generation. All policies flow through `Starlark text → evaluate → JSON IR` — one compilation path.

### Shared Definitions Module

A new `clash/src/policy_gen/` module owns canonical definitions:

**Tool constants:**

```rust
const FS_READ_TOOLS: &[&str] = &["Read", "Glob", "Grep"];
const FS_WRITE_TOOLS: &[&str] = &["Write", "Edit", "NotebookEdit"];
const FS_ALL_TOOLS: &[&str] = &["Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit"];
```

**Standard loads** — functions that return the correct load statements for a given set of sandbox presets and ecosystems.

**Sandbox templates** — the Rust-defined templates described above.

All generators consume these definitions. No hardcoded strings in generator code.

### Generator Pipeline

```
Input source → PolicySpec → PolicyBuilder → Starlark text → evaluate → JSON IR
```

**`PolicySpec`** is a Rust struct describing what the policy should contain:

```rust
struct PolicySpec {
    default_effect: Effect,
    default_sandbox: Option<SandboxTemplate>,
    additional_sandboxes: Vec<SandboxTemplate>,
    rules: Vec<RuleSpec>,
    ecosystems: Vec<EcosystemDef>,
    extra_loads: Vec<LoadSpec>,
    settings: PolicySettings,  // harness_defaults, on_sandbox_violation, etc.
}
```

**`RuleSpec`** is a typed enum:

```rust
enum RuleSpec {
    FsToolAllow { sandbox: String },
    BashAllow { binaries: Vec<String>, sandbox: String },
    BashDeny { binaries: Vec<String> },
    ToolAllow { tools: Vec<String> },
    ToolDeny { tools: Vec<String> },
    EcosystemRouting { ecosystem: EcosystemDef },
    Custom(Expr),  // escape hatch
}
```

**Input sources** produce `PolicySpec`:

- `PolicySpec::from_posture(posture, detection)` — replaces `generate_starlark_from_posture`
- `PolicySpec::from_analysis(analysis, detection)` — replaces `generate_starlark_from_analysis`
- `PolicySpec::from_trace(trace_analysis)` — replaces `from_trace::generate_starlark`

**Composition:** `PolicySpec` is data, so specs can merge:

```rust
impl PolicySpec {
    fn merge(self, other: PolicySpec) -> PolicySpec
}
```

An existing generator's output can feed into another as input. For example, a trace-based spec merged with ecosystem detection.

**`PolicyBuilder`** takes a `PolicySpec` and serializes to Starlark text. One implementation handles load statements, sandbox definitions, rule ordering, and the `settings()` call. The existing three generators are deleted and replaced by input-source functions that return `PolicySpec`.

### Migration Path

The new `settings()` API is a breaking change. Migration strategy:

1. Ship the new API alongside the old one initially — the evaluator accepts both forms
2. `clash init` generates the new form
3. `clash policy validate` warns on old form with migration hints
4. After a release cycle, remove the old form

Existing policies using `policy("name", ...)` and `settings(default=...)` separately continue to work during the transition. The evaluator detects which form is used and handles both.

## Decomposition

This is too large for a single implementation plan. Recommended sub-projects in order:

1. **Shared definitions module** — extract tool constants, sandbox templates into `policy_gen/`. Migrate existing generators to consume them. No API changes.
2. **Generator pipeline** — introduce `PolicySpec`, `RuleSpec`, `PolicyBuilder`. Rewrite generators as input sources. No Starlark API changes.
3. **Starlark API unification** — new `settings()` shape, `policy` as dict, `sandbox(name, dict)` shape. Migration support for old form.
4. **Sandbox mutation** — `extend`/`remove` methods on `SandboxTemplate`, exposed to Starlark.

Each sub-project delivers standalone value and can ship independently.

## Out of Scope

- Network rule mutation (can be added later via the same `extend`/`remove` pattern)
- Visual policy editor or TUI for policy authoring
- Policy linting beyond `clash policy validate`
- Multi-agent policy composition (separate policies per agent)
