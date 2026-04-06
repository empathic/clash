# PolicySpec/PolicyBuilder Unification Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 4 independent policy generators with a single `PolicySpec` → `PolicyBuilder` pipeline so adding cross-cutting concerns (like `from_claude_settings()`) requires changing exactly one place.

**Architecture:** Define a `PolicySpec` struct that captures what a policy should contain (effect, sandboxes, rules, ecosystems, settings). Each input source (`from_posture`, `from_analysis`, `from_trace`, `from_ecosystems`) produces a `PolicySpec`. A single `PolicyBuilder` converts any `PolicySpec` to Starlark text, handling loads, settings, merge/from_claude_settings, canonicalization, and serialization.

**Tech Stack:** Rust, clash_starlark codegen builder API

---

## File Structure

| File | Responsibility |
|------|---------------|
| `clash/src/policy_gen/spec.rs` | **New** — `PolicySpec` struct and builder methods |
| `clash/src/policy_gen/builder.rs` | **New** — `PolicyBuilder` that converts `PolicySpec` → Starlark text |
| `clash/src/policy_gen/mod.rs` | Modify — re-export spec + builder |
| `clash/src/cmd/import_settings.rs` | Modify — replace inline generation with `PolicySpec::from_analysis/from_posture` |
| `clash/src/cmd/from_trace.rs` | Modify — replace inline generation with `PolicySpec::from_trace` |
| `clash/src/ecosystem.rs` | Modify — replace inline generation with `PolicySpec::from_ecosystems` |
| `clash/src/policy_gen/tests.rs` | Modify — update integration tests |

---

### Task 1: Define PolicySpec and PolicyBuilder with from_posture

**Files:**
- Create: `clash/src/policy_gen/spec.rs`
- Create: `clash/src/policy_gen/builder.rs`
- Modify: `clash/src/policy_gen/mod.rs`
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Write failing test for PolicySpec::from_posture**

In `clash/src/policy_gen/spec.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_posture_balanced_produces_valid_policy() {
        let spec = PolicySpec::from_posture(
            "ask",       // default effect
            "project",   // default sandbox preset
            &[],         // no ecosystems
        );
        let starlark = spec.to_starlark();
        let result = clash_starlark::evaluate(&starlark, "test.star", &std::path::PathBuf::from("."));
        assert!(result.is_ok(), "generated policy should evaluate: {:?}\n\n{starlark}", result.err());
    }

    #[test]
    fn from_posture_includes_from_claude_settings() {
        let spec = PolicySpec::from_posture("ask", "project", &[]);
        let starlark = spec.to_starlark();
        assert!(starlark.contains("from_claude_settings"), "should include from_claude_settings:\n{starlark}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash policy_gen::spec`
Expected: FAIL — module doesn't exist

- [ ] **Step 3: Define PolicySpec struct**

Create `clash/src/policy_gen/spec.rs`:

```rust
//! Typed policy specification — the single intermediate representation
//! for all policy generators.
//!
//! Input sources produce a `PolicySpec`. The `to_starlark()` method
//! converts it to Starlark text via a single builder pipeline.

use clash_starlark::codegen::ast::Expr;
use crate::ecosystem::EcosystemDef;

/// What a generated policy should contain.
///
/// All generators produce this struct. `to_starlark()` handles loads,
/// settings, sandbox definitions, rule ordering, `from_claude_settings()`,
/// and canonicalization in one place.
pub struct PolicySpec {
    /// Policy name (e.g., "default", "imported").
    pub name: String,
    /// Default effect: "allow", "deny", or "ask".
    pub default_effect: String,
    /// Default sandbox preset name (e.g., "project", "readonly").
    /// If set, added to `settings(default_sandbox=...)`.
    pub default_sandbox: Option<String>,
    /// Whether to define the `project_files` sandbox.
    pub define_project_files_sandbox: bool,
    /// Sandbox presets to load from sandboxes.star (e.g., ["readonly", "project", "workspace"]).
    pub sandbox_presets: Vec<String>,
    /// Ecosystems to include (adds loads + routing rules).
    pub ecosystems: Vec<&'static EcosystemDef>,
    /// Whether to use mode-based routing (plan/edit/unrestricted).
    /// When true, ecosystem rules are wrapped in mode keys.
    pub mode_routing: bool,
    /// Custom rules (tool matches, bash entries, etc.) in priority order.
    /// These go after ecosystem rules, before asks.
    pub rules: Vec<PolicyRule>,
    /// Whether to include `from_claude_settings()` as the base.
    /// Default: true.
    pub include_claude_settings: bool,
    /// Whether to run canonicalization pass on output.
    pub canonicalize: bool,
    /// Optional comment at the top of the file.
    pub header_comment: Option<String>,
}

/// A typed rule entry. Converted to Expr by the builder.
pub enum PolicyRule {
    /// A pre-built codegen expression (escape hatch).
    Expr(Expr),
    /// A commented expression.
    Commented(String, Expr),
}

impl Default for PolicySpec {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            default_effect: "ask".to_string(),
            default_sandbox: None,
            define_project_files_sandbox: false,
            sandbox_presets: vec![],
            ecosystems: vec![],
            mode_routing: false,
            rules: vec![],
            include_claude_settings: true,
            canonicalize: false,
            header_comment: None,
        }
    }
}
```

- [ ] **Step 4: Implement `to_starlark()` on PolicySpec**

This is the single builder pipeline. Add to `spec.rs`:

```rust
impl PolicySpec {
    /// Convert to Starlark source text.
    ///
    /// Handles: loads, sandbox definitions, settings, rule ordering,
    /// from_claude_settings, merge, canonicalization, and serialization.
    pub fn to_starlark(&self) -> String {
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;
        use super::sandboxes;
        use super::ecosystems as eco_gen;
        use super::loads;

        let mut stmts: Vec<Stmt> = vec![];

        // --- Header comment ---
        if let Some(ref comment) = self.header_comment {
            stmts.push(Stmt::comment(comment));
        }

        // --- Loads ---
        stmts.push(load_builtin());

        // Collect sandbox presets
        let preset_refs: Vec<&str> = self.sandbox_presets.iter().map(|s| s.as_str()).collect();
        let eco_refs: Vec<&EcosystemDef> = self.ecosystems.iter().copied().collect();
        let mut load_stmts = loads::standard_loads(&preset_refs, &eco_refs);
        // standard_loads includes builtin, so skip the first if it's a duplicate
        if !load_stmts.is_empty() {
            // standard_loads already includes load_builtin, so use it instead
            stmts.clear();
            if let Some(ref comment) = self.header_comment {
                stmts.push(Stmt::comment(comment));
            }
            stmts.extend(load_stmts);
        }

        // Claude compat load
        if self.include_claude_settings {
            stmts.push(Stmt::load(
                "@clash//claude_compat.star",
                &["from_claude_settings"],
            ));
        }

        stmts.push(Stmt::Blank);

        // --- Sandbox definitions ---
        if self.define_project_files_sandbox {
            stmts.extend(sandboxes::project_files_sandbox());
            stmts.push(Stmt::Blank);
        }

        // --- Settings ---
        let default_expr = Expr::call(&self.default_effect, vec![]);
        let sandbox_expr = self.default_sandbox.as_ref().map(|s| Expr::ident(s));
        stmts.push(Stmt::Expr(settings(default_expr.clone(), sandbox_expr)));
        stmts.push(Stmt::Blank);

        // --- Rules ---
        let mut rules: Vec<Expr> = vec![];

        // from_claude_settings as lowest-priority base
        if self.include_claude_settings {
            rules.push(Expr::call("from_claude_settings", vec![]));
        }

        if self.mode_routing {
            // Mode-based routing: build mode dict, pass as single rule
            let mode_dict = self.build_mode_dict();
            rules.push(mode_dict);
        } else {
            // Flat rules: ecosystem rules + custom rules
            let eco_sandbox = self.default_sandbox.as_deref()
                .or_else(|| {
                    if self.define_project_files_sandbox {
                        Some(sandboxes::PROJECT_FILES_SANDBOX)
                    } else {
                        None
                    }
                })
                .unwrap_or("project");
            rules.extend(eco_gen::ecosystem_rules(&self.ecosystems, eco_sandbox));

            for rule in &self.rules {
                match rule {
                    PolicyRule::Expr(e) => rules.push(e.clone()),
                    PolicyRule::Commented(comment, e) => {
                        rules.push(Expr::commented(comment, e.clone()));
                    }
                }
            }
        }

        // --- Policy call ---
        stmts.push(Stmt::Expr(policy(
            &self.name,
            default_expr,
            rules,
            None,
        )));

        // --- Canonicalize ---
        if self.canonicalize {
            let _ = clash_starlark::codegen::canonicalize::canonicalize(&mut stmts);
        }

        clash_starlark::codegen::serialize(&stmts)
    }
}
```

- [ ] **Step 5: Implement `build_mode_dict` helper for ecosystem generator**

```rust
impl PolicySpec {
    /// Build a mode-routing dict for ecosystem-aware policies.
    fn build_mode_dict(&self) -> Expr {
        use clash_starlark::codegen::ast::DictEntry;
        use clash_starlark::codegen::builder::*;

        let mut mode_entries: Vec<DictEntry> = vec![];

        // Plan mode: readonly + safe sandboxes
        let plan_bash = self.build_bash_routing(true);
        let mut plan_inner = vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            allow_with_sandbox(Expr::ident("readonly")),
        )];
        if !plan_bash.is_empty() {
            plan_inner.push(DictEntry::new(
                Expr::call("Tool", vec![Expr::string("Bash")]),
                Expr::dict(plan_bash),
            ));
        }
        mode_entries.push(DictEntry::new(
            Expr::call("mode", vec![Expr::string("plan")]),
            Expr::dict(plan_inner),
        ));

        // Edit/default mode: project + full sandboxes
        let edit_bash = self.build_bash_routing(false);
        let mut edit_inner = vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            allow_with_sandbox(Expr::ident("project")),
        )];
        if !edit_bash.is_empty() {
            edit_inner.push(DictEntry::new(
                Expr::call("Tool", vec![Expr::string("Bash")]),
                Expr::dict(edit_bash),
            ));
        }
        mode_entries.push(DictEntry::new(
            Expr::tuple(vec![
                Expr::call("mode", vec![Expr::string("edit")]),
                Expr::call("mode", vec![Expr::string("default")]),
            ]),
            Expr::dict(edit_inner),
        ));

        // Unrestricted mode
        mode_entries.push(DictEntry::new(
            Expr::call("mode", vec![Expr::string("unrestricted")]),
            Expr::dict(vec![DictEntry::new(
                Expr::call("glob", vec![Expr::string("**")]),
                allow_with_sandbox(Expr::ident("workspace")),
            )]),
        ));

        Expr::dict(mode_entries)
    }

    /// Build Bash ecosystem routing entries.
    fn build_bash_routing(&self, use_safe: bool) -> Vec<DictEntry> {
        use clash_starlark::codegen::ast::DictEntry;
        use clash_starlark::codegen::builder::*;

        let mut entries = vec![];
        for eco in &self.ecosystems {
            let sandbox_name = if use_safe {
                eco.safe_sandbox.unwrap_or(eco.full_sandbox)
            } else {
                eco.full_sandbox
            };
            let key = if eco.binaries.len() == 1 {
                Expr::string(eco.binaries[0])
            } else {
                Expr::tuple(eco.binaries.iter().map(|b| Expr::string(*b)).collect())
            };
            let glob_entry = DictEntry::new(
                Expr::call("glob", vec![Expr::string("**")]),
                allow_with_sandbox(Expr::ident(sandbox_name)),
            );
            entries.push(DictEntry::new(key, Expr::dict(vec![glob_entry])));
        }
        entries
    }
}
```

- [ ] **Step 6: Add `from_posture` constructor**

```rust
impl PolicySpec {
    /// Create a spec from a posture choice (Strict/Balanced/Permissive).
    pub fn from_posture(
        default_effect: &str,
        sandbox_preset: &str,
        ecosystems: &[&'static EcosystemDef],
    ) -> Self {
        Self {
            name: "default".to_string(),
            default_effect: default_effect.to_string(),
            default_sandbox: Some(sandbox_preset.to_string()),
            define_project_files_sandbox: false,
            sandbox_presets: vec![sandbox_preset.to_string()],
            ecosystems: ecosystems.to_vec(),
            mode_routing: false,
            rules: vec![],
            include_claude_settings: true,
            canonicalize: false,
            header_comment: None,
        }
    }
}
```

- [ ] **Step 7: Register module in mod.rs**

Add to `clash/src/policy_gen/mod.rs`:

```rust
pub mod spec;
```

- [ ] **Step 8: Run tests**

Run: `cargo test -p clash policy_gen::spec`
Expected: Both tests PASS

- [ ] **Step 9: Migrate `generate_starlark_from_posture` to use PolicySpec**

In `clash/src/cmd/import_settings.rs`, replace `generate_starlark_from_posture()` body:

```rust
fn generate_starlark_from_posture(posture: Posture, detection: &EcosystemDetection) -> String {
    use crate::policy_gen::spec::PolicySpec;

    PolicySpec::from_posture(
        posture.default_effect(),
        posture.sandbox_preset(),
        &detection.ecosystems,
    ).to_starlark()
}
```

- [ ] **Step 10: Run import_settings tests**

Run: `cargo test -p clash import_settings`
Expected: All PASS

- [ ] **Step 11: Commit**

```bash
git add clash/src/policy_gen/spec.rs clash/src/policy_gen/mod.rs clash/src/cmd/import_settings.rs
git commit -m "feat(policy_gen): add PolicySpec with from_posture, migrate posture generator"
```

---

### Task 2: Migrate from_analysis to PolicySpec

**Files:**
- Modify: `clash/src/policy_gen/spec.rs`
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Write failing test for from_analysis**

In `clash/src/policy_gen/spec.rs` tests:

```rust
#[test]
fn from_analysis_empty_produces_valid_policy() {
    let spec = PolicySpec::from_analysis(
        &mut ImportAnalysis::default(),
        &[],  // no ecosystems
    );
    let starlark = spec.to_starlark();
    let result = clash_starlark::evaluate(&starlark, "test.star", &std::path::PathBuf::from("."));
    assert!(result.is_ok(), "should evaluate: {:?}\n\n{starlark}", result.err());
}
```

Note: `ImportAnalysis` may need to be moved to a shared location or the test can live in `import_settings.rs`. Use whichever is simplest.

- [ ] **Step 2: Add `from_analysis` constructor to PolicySpec**

This is the most complex generator. It needs to convert `ImportAnalysis` fields into `PolicyRule` entries:

```rust
impl PolicySpec {
    /// Create a spec from analyzed Claude Code settings.
    pub fn from_analysis(
        analysis: &mut super::super::cmd::import_settings::ImportAnalysis,
        ecosystems: &[&'static EcosystemDef],
    ) -> Self {
        // ... dedup, build rules from analysis fields,
        // filter eco binaries from bash_allows, etc.
        // Move the rule-building logic from generate_starlark_from_analysis
        // into here, producing PolicyRule entries.
    }
}
```

The key insight: most of the logic in `generate_starlark_from_analysis` is about converting `ImportAnalysis` fields into `Expr` rule entries. That logic moves into `from_analysis()`, producing `PolicyRule::Expr` / `PolicyRule::Commented` entries. The load generation, settings, from_claude_settings wrapping, and serialization are handled by `to_starlark()`.

- [ ] **Step 3: Migrate `generate_starlark_from_analysis`**

Replace the body with:

```rust
fn generate_starlark_from_analysis(
    analysis: &mut ImportAnalysis,
    detection: &EcosystemDetection,
) -> String {
    use crate::policy_gen::spec::PolicySpec;

    PolicySpec::from_analysis(analysis, &detection.ecosystems).to_starlark()
}
```

- [ ] **Step 4: Run import_settings tests**

Run: `cargo test -p clash import_settings`
Expected: All PASS (including the 4+ compilation tests)

- [ ] **Step 5: Commit**

```bash
git add clash/src/policy_gen/spec.rs clash/src/cmd/import_settings.rs
git commit -m "feat(policy_gen): migrate from_analysis to PolicySpec"
```

---

### Task 3: Migrate from_trace to PolicySpec

**Files:**
- Modify: `clash/src/policy_gen/spec.rs`
- Modify: `clash/src/cmd/from_trace.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn from_trace_empty_produces_valid_policy() {
    let analysis = TraceAnalysis {
        total_invocations: 0,
        tools: std::collections::BTreeSet::new(),
        binaries: std::collections::BTreeSet::new(),
    };
    let spec = PolicySpec::from_trace(&analysis);
    let starlark = spec.to_starlark();
    let result = clash_starlark::evaluate(&starlark, "test.star", &std::path::PathBuf::from("."));
    assert!(result.is_ok(), "should evaluate: {:?}\n\n{starlark}", result.err());
}
```

- [ ] **Step 2: Add `from_trace` constructor**

Moves the tool categorization and rule building from `from_trace::generate_starlark()` into `PolicySpec::from_trace()`:

```rust
impl PolicySpec {
    pub fn from_trace(analysis: &TraceAnalysis) -> Self {
        // Categorize tools into FS read, FS write, net, other
        // Build destructive git deny rules if git observed
        // Build binary-specific sandbox rules
        // Return spec with define_project_files_sandbox=true, rules=[...]
    }
}
```

- [ ] **Step 3: Migrate `from_trace::generate_starlark`**

```rust
fn generate_starlark(analysis: &TraceAnalysis) -> String {
    use crate::policy_gen::spec::PolicySpec;
    PolicySpec::from_trace(analysis).to_starlark()
}
```

- [ ] **Step 4: Run from_trace tests**

Run: `cargo test -p clash from_trace`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/policy_gen/spec.rs clash/src/cmd/from_trace.rs
git commit -m "feat(policy_gen): migrate from_trace to PolicySpec"
```

---

### Task 4: Migrate ecosystem generator to PolicySpec

**Files:**
- Modify: `clash/src/policy_gen/spec.rs`
- Modify: `clash/src/ecosystem.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn from_ecosystems_produces_valid_policy() {
    let ecosystems: Vec<&EcosystemDef> = crate::ecosystem::ECOSYSTEMS
        .iter()
        .filter(|e| e.name == "rust" || e.name == "git")
        .collect();
    let spec = PolicySpec::from_ecosystems(&ecosystems);
    let starlark = spec.to_starlark();
    let result = clash_starlark::evaluate(&starlark, "test.star", &std::path::PathBuf::from("."));
    assert!(result.is_ok(), "should evaluate: {:?}\n\n{starlark}", result.err());
}
```

- [ ] **Step 2: Add `from_ecosystems` constructor**

This is the mode-routing path:

```rust
impl PolicySpec {
    pub fn from_ecosystems(ecosystems: &[&'static EcosystemDef]) -> Self {
        let mut sandbox_presets = vec![
            "readonly".to_string(),
            "project".to_string(),
            "workspace".to_string(),
        ];
        // Add ecosystem sandbox presets
        for eco in ecosystems {
            if eco.star_file == "sandboxes.star" {
                if let Some(safe) = eco.safe_sandbox {
                    if !sandbox_presets.iter().any(|s| s == safe) {
                        sandbox_presets.push(safe.to_string());
                    }
                }
                if !sandbox_presets.iter().any(|s| s == eco.full_sandbox) {
                    sandbox_presets.push(eco.full_sandbox.to_string());
                }
            }
        }

        Self {
            name: "default".to_string(),
            default_effect: "deny".to_string(),
            default_sandbox: None,
            define_project_files_sandbox: false,
            sandbox_presets,
            ecosystems: ecosystems.to_vec(),
            mode_routing: true,
            rules: vec![],
            include_claude_settings: true,
            canonicalize: false,
            header_comment: None,
        }
    }
}
```

Note: the ecosystem generator doesn't emit `settings()`. The `to_starlark()` builder currently always emits settings. Add a `define_settings: bool` field to `PolicySpec` (default true) and set it to `false` for from_ecosystems, OR always emit settings since it's harmless. Prefer always emitting — it's simpler and the evaluator handles it fine.

- [ ] **Step 3: Migrate `ecosystem::generate_policy`**

```rust
pub fn generate_policy(ecosystems: &[&EcosystemDef]) -> String {
    use crate::policy_gen::spec::PolicySpec;
    PolicySpec::from_ecosystems(ecosystems).to_starlark()
}
```

- [ ] **Step 4: Run ecosystem and init tests**

Run: `cargo test -p clash detected_policy_compiles starter_policy_compiles`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/policy_gen/spec.rs clash/src/ecosystem.rs
git commit -m "feat(policy_gen): migrate ecosystem generator to PolicySpec"
```

---

### Task 5: Clean up — remove dead code and update tests

**Files:**
- Modify: `clash/src/cmd/import_settings.rs` — remove old helper functions that are now in PolicySpec
- Modify: `clash/src/cmd/from_trace.rs` — remove old helper functions
- Modify: `clash/src/ecosystem.rs` — remove old helper functions (`build_bash_routing`, `load_*` calls, `allow_with_sandbox`)
- Modify: `clash/src/policy_gen/tests.rs` — update integration tests

- [ ] **Step 1: Remove dead helper functions from import_settings.rs**

Functions like `build_bash_entry()`, `tool_entry()`, and the direct load/settings/policy construction code that's now handled by `to_starlark()`. Keep only `ImportAnalysis`, its classification logic, and the `from_analysis` / `from_posture` wrappers.

- [ ] **Step 2: Remove dead helper functions from from_trace.rs**

The tool categorization and rule building that moved into `PolicySpec::from_trace()`.

- [ ] **Step 3: Remove dead helper functions from ecosystem.rs**

The `build_bash_routing()`, mode dict construction, and load generation that moved into `PolicySpec`.

- [ ] **Step 4: Update policy_gen/tests.rs**

Update integration tests to use `PolicySpec` directly:

```rust
#[test]
fn project_files_sandbox_evaluates_to_valid_policy() {
    let spec = PolicySpec {
        define_project_files_sandbox: true,
        default_sandbox: Some("project_files".to_string()),
        ..PolicySpec::default()
    };
    let starlark = spec.to_starlark();
    let result = clash_starlark::evaluate(&starlark, "test.star", &std::path::PathBuf::from("."));
    assert!(result.is_ok(), "should evaluate: {:?}\n\n{starlark}", result.err());
}
```

- [ ] **Step 5: Run full test suite**

Run: `cargo test -p clash --lib`
Expected: 644+ pass, only the 21 pre-existing env failures

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(policy_gen): remove dead generator code, update tests"
```
