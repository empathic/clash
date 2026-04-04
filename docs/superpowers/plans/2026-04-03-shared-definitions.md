# Shared Policy Definitions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract duplicated tool name lists, sandbox definitions, load statement helpers, and ecosystem rule generation into a shared `policy_gen` module, then migrate all three generators to consume it.

**Architecture:** Create `clash/src/policy_gen/` with `tools.rs` (tool name constants), `sandboxes.rs` (project_files sandbox builder), `loads.rs` (standard load statement generation), and `mod.rs` tying them together. Migrate `import_settings.rs` and `from_trace.rs` to use the shared module. No Starlark API changes — this is pure internal consolidation.

**Tech Stack:** Rust, clash_starlark codegen builder API

---

### Task 1: Create `policy_gen` module with tool name constants

**Files:**
- Create: `clash/src/policy_gen/mod.rs`
- Create: `clash/src/policy_gen/tools.rs`
- Modify: `clash/src/lib.rs`

- [ ] **Step 1: Write tests for tool constants**

Create `clash/src/policy_gen/tools.rs`:

```rust
//! Canonical tool name constants for policy generation.
//!
//! All policy generators must use these constants instead of hardcoding
//! tool name strings. Adding a new file-access or network tool means
//! updating exactly one place.

/// File-access tools that perform read operations.
pub const FS_READ_TOOLS: &[&str] = &["Read", "Glob", "Grep"];

/// File-access tools that perform write operations.
pub const FS_WRITE_TOOLS: &[&str] = &["Write", "Edit", "NotebookEdit"];

/// All file-access tools (union of read and write).
pub const FS_ALL_TOOLS: &[&str] = &["Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit"];

/// Network-access tools.
pub const NET_TOOLS: &[&str] = &["WebFetch", "WebSearch"];

/// Returns true if the tool name is a file-access tool.
pub fn is_fs_tool(name: &str) -> bool {
    FS_ALL_TOOLS.contains(&name)
}

/// Returns true if the tool name is a network tool.
pub fn is_net_tool(name: &str) -> bool {
    NET_TOOLS.contains(&name)
}

/// Returns true if the tool name is a "special" tool handled by specific
/// policy rules (fs tools, net tools, Bash). Other tools get generic rules.
pub fn is_categorized_tool(name: &str) -> bool {
    is_fs_tool(name) || is_net_tool(name) || name == "Bash"
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fs_all_is_union_of_read_and_write() {
        for tool in FS_READ_TOOLS {
            assert!(FS_ALL_TOOLS.contains(tool), "{tool} missing from FS_ALL_TOOLS");
        }
        for tool in FS_WRITE_TOOLS {
            assert!(FS_ALL_TOOLS.contains(tool), "{tool} missing from FS_ALL_TOOLS");
        }
        assert_eq!(
            FS_ALL_TOOLS.len(),
            FS_READ_TOOLS.len() + FS_WRITE_TOOLS.len(),
            "FS_ALL_TOOLS should be exactly read + write"
        );
    }

    #[test]
    fn no_overlap_between_read_and_write() {
        for tool in FS_READ_TOOLS {
            assert!(!FS_WRITE_TOOLS.contains(tool), "{tool} in both read and write");
        }
    }

    #[test]
    fn is_fs_tool_works() {
        assert!(is_fs_tool("Read"));
        assert!(is_fs_tool("Edit"));
        assert!(!is_fs_tool("Bash"));
        assert!(!is_fs_tool("WebFetch"));
    }

    #[test]
    fn is_categorized_tool_works() {
        assert!(is_categorized_tool("Read"));
        assert!(is_categorized_tool("WebSearch"));
        assert!(is_categorized_tool("Bash"));
        assert!(!is_categorized_tool("Agent"));
        assert!(!is_categorized_tool("TodoWrite"));
    }
}
```

- [ ] **Step 2: Create module files**

Create `clash/src/policy_gen/mod.rs`:

```rust
//! Shared definitions for policy generation.
//!
//! All policy generators (import_settings, from_trace, etc.) consume
//! these definitions instead of hardcoding tool names, sandbox shapes,
//! and load statements.

pub mod tools;
```

- [ ] **Step 3: Register the module in lib.rs**

In `clash/src/lib.rs`, add `pub mod policy_gen;` in alphabetical order (between `policy_loader` and `sandbox`).

- [ ] **Step 4: Run tests**

Run: `cargo test -p clash policy_gen`
Expected: PASS (all tests in tools.rs)

- [ ] **Step 5: Commit**

```bash
git add clash/src/policy_gen/mod.rs clash/src/policy_gen/tools.rs clash/src/lib.rs
git commit -m "feat(policy_gen): add shared tool name constants"
```

---

### Task 2: Create shared `project_files` sandbox builder

**Files:**
- Create: `clash/src/policy_gen/sandboxes.rs`
- Modify: `clash/src/policy_gen/mod.rs`

- [ ] **Step 1: Write tests**

Create `clash/src/policy_gen/sandboxes.rs`:

```rust
//! Shared sandbox builders for policy generation.
//!
//! Provides canonical sandbox definitions as Starlark AST, ensuring all
//! generators produce identical sandbox shapes.

use clash_starlark::codegen::ast::{DictEntry, Expr, Stmt};
use clash_starlark::codegen::builder::*;

/// Build the `project_files` sandbox definition: `$PWD` (r/w/c, follow worktrees)
/// and `$HOME/.claude` (r/w/c). Returns a `(comment, assign)` pair of statements.
///
/// The sandbox name is `"project_files"` and the variable is assigned to that name.
pub fn project_files_sandbox() -> Vec<Stmt> {
    let fs_dict = Expr::dict(vec![
        DictEntry::new(
            Expr::call_kwargs(
                "subpath",
                vec![Expr::string("$PWD")],
                vec![("follow_worktrees", Expr::ident("True"))],
            ),
            Expr::call("allow", vec![Expr::string("rwc")]),
        ),
        DictEntry::new(
            Expr::call("glob", vec![Expr::string("$HOME/.claude/**")]),
            Expr::call("allow", vec![Expr::string("rwc")]),
        ),
    ]);
    let sb = sandbox("project_files", vec![("default", ask()), ("fs", fs_dict)]);
    vec![
        Stmt::comment("Sandbox for file-access tools (scoped to project + ~/.claude)"),
        Stmt::assign("project_files", sb),
    ]
}

/// Name of the project_files sandbox, for use in `allow(sandbox=...)` references.
pub const PROJECT_FILES_SANDBOX: &str = "project_files";

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn project_files_sandbox_produces_statements() {
        let stmts = project_files_sandbox();
        assert_eq!(stmts.len(), 2, "expected comment + assign");
        assert!(matches!(&stmts[0], Stmt::Comment(_)));
        assert!(matches!(&stmts[1], Stmt::Assign { .. }));
    }

    #[test]
    fn project_files_sandbox_compiles() {
        let stmts = project_files_sandbox();
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("project_files"), "should define project_files");
        assert!(code.contains("$PWD"), "should reference $PWD");
        assert!(code.contains("$HOME/.claude"), "should reference $HOME/.claude");
    }
}
```

- [ ] **Step 2: Register in mod.rs**

In `clash/src/policy_gen/mod.rs`, add:

```rust
pub mod sandboxes;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p clash policy_gen`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add clash/src/policy_gen/sandboxes.rs clash/src/policy_gen/mod.rs
git commit -m "feat(policy_gen): add shared project_files sandbox builder"
```

---

### Task 3: Create shared load statement helpers

**Files:**
- Create: `clash/src/policy_gen/loads.rs`
- Modify: `clash/src/policy_gen/mod.rs`

- [ ] **Step 1: Write the module**

Create `clash/src/policy_gen/loads.rs`:

```rust
//! Standard load statement generation for policy files.
//!
//! Generates the correct set of `load()` statements based on which
//! sandbox presets and ecosystems a policy needs.

use clash_starlark::codegen::ast::Stmt;
use clash_starlark::codegen::builder::*;

use crate::ecosystem::EcosystemDef;

/// Generate all load statements needed for a policy with the given
/// sandbox presets and ecosystems.
///
/// Always includes `load("@clash//builtin.star", "builtins")`.
/// Adds sandbox preset loads and ecosystem-specific loads as needed.
pub fn standard_loads(
    sandbox_presets: &[&str],
    ecosystems: &[&EcosystemDef],
) -> Vec<Stmt> {
    let mut stmts = vec![load_builtin()];

    // Collect sandbox names from presets + ecosystem sandboxes that live in sandboxes.star
    let mut sandbox_names: Vec<&str> = sandbox_presets.to_vec();
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            if let Some(safe) = eco.safe_sandbox {
                if !sandbox_names.contains(&safe) {
                    sandbox_names.push(safe);
                }
            }
            if !sandbox_names.contains(&eco.full_sandbox) {
                sandbox_names.push(eco.full_sandbox);
            }
        }
    }
    if !sandbox_names.is_empty() {
        stmts.push(load_sandboxes(&sandbox_names));
    }

    // Ecosystem-specific loads (non-sandboxes.star files)
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            continue;
        }
        let mut names: Vec<&str> = Vec::new();
        if let Some(safe) = eco.safe_sandbox {
            names.push(safe);
        }
        names.push(eco.full_sandbox);
        stmts.push(load_ecosystem(eco.star_file, &names));
    }

    stmts
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn standard_loads_with_no_extras() {
        let stmts = standard_loads(&[], &[]);
        assert_eq!(stmts.len(), 1, "should have just builtin load");
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("builtin.star"));
    }

    #[test]
    fn standard_loads_with_preset() {
        let stmts = standard_loads(&["project"], &[]);
        assert_eq!(stmts.len(), 2);
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("sandboxes.star"));
        assert!(code.contains("project"));
    }

    #[test]
    fn standard_loads_with_ecosystem() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();
        let stmts = standard_loads(&[], &[rust]);
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("rust.star"));
        assert!(code.contains("rust_full"));
    }

    #[test]
    fn standard_loads_deduplicates_sandbox_presets() {
        let git = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "git")
            .unwrap();
        // git lives in sandboxes.star — should merge with preset load
        let stmts = standard_loads(&["project"], &[git]);
        let code = clash_starlark::codegen::serialize(&stmts);
        // Should be one sandboxes.star load with both project and git sandboxes
        let sandboxes_count = code.matches("sandboxes.star").count();
        assert_eq!(sandboxes_count, 1, "should have single sandboxes.star load");
    }
}
```

- [ ] **Step 2: Register in mod.rs**

In `clash/src/policy_gen/mod.rs`, add:

```rust
pub mod loads;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p clash policy_gen`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add clash/src/policy_gen/loads.rs clash/src/policy_gen/mod.rs
git commit -m "feat(policy_gen): add shared load statement generation"
```

---

### Task 4: Extract `build_ecosystem_rules` into `policy_gen`

**Files:**
- Create: `clash/src/policy_gen/ecosystems.rs`
- Modify: `clash/src/policy_gen/mod.rs`
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Create `ecosystems.rs` with the extracted function**

Create `clash/src/policy_gen/ecosystems.rs`:

```rust
//! Ecosystem-aware rule generation for policy files.
//!
//! Generates `when()` rules that route file-access tools and ecosystem
//! binaries to appropriate sandboxes.

use clash_starlark::codegen::ast::{DictEntry, Expr};
use clash_starlark::codegen::builder::*;

use crate::ecosystem::EcosystemDef;
use super::tools::FS_ALL_TOOLS;

/// Build `when()` routing rules for detected ecosystems.
///
/// Generates two kinds of rules:
/// 1. File-access tools → `fs_sandbox` sandbox
/// 2. Bash binary routing → ecosystem-specific sandboxes
pub fn ecosystem_rules(
    ecosystems: &[&EcosystemDef],
    fs_sandbox: &str,
) -> Vec<Expr> {
    if ecosystems.is_empty() {
        return vec![];
    }

    let mut rules = Vec::new();

    // File-access tools — allow within the given sandbox
    rules.push(Expr::commented(
        "file-access tools — sandboxed to project",
        tool_match(FS_ALL_TOOLS, allow_with_sandbox(Expr::ident(fs_sandbox))),
    ));

    // Bash binary routing
    let mut bash_entries: Vec<(MatchKey, MatchValue)> = Vec::new();
    for eco in ecosystems {
        let key: MatchKey = if eco.binaries.len() == 1 {
            eco.binaries[0].into()
        } else {
            eco.binaries.into()
        };
        let sandbox_expr = allow_with_sandbox(Expr::ident(eco.full_sandbox));
        let glob_entry = Expr::dict(vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            sandbox_expr,
        )]);
        bash_entries.push((key, MatchValue::Effect(glob_entry)));
    }

    rules.push(Expr::commented(
        "ecosystem sandboxes (detected)",
        match_rule(vec![("Bash".into(), MatchValue::Nested(bash_entries))]),
    ));

    rules
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_ecosystems_returns_empty() {
        let rules = ecosystem_rules(&[], "project");
        assert!(rules.is_empty());
    }

    #[test]
    fn ecosystem_rules_reference_fs_sandbox() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();
        let rules = ecosystem_rules(&[rust], "my_sandbox");
        let code = rules
            .iter()
            .map(|e| clash_starlark::codegen::ast::format_expr(e, 0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("my_sandbox"),
            "should reference the passed sandbox name"
        );
    }

    #[test]
    fn ecosystem_rules_route_binaries() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();
        let rules = ecosystem_rules(&[rust], "project");
        let code = rules
            .iter()
            .map(|e| clash_starlark::codegen::ast::format_expr(e, 0))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(code.contains("cargo"));
        assert!(code.contains("rust_full"));
    }
}
```

- [ ] **Step 2: Register in mod.rs**

In `clash/src/policy_gen/mod.rs`, add:

```rust
pub mod ecosystems;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p clash policy_gen::ecosystems`
Expected: PASS

Note: The `format_expr` function may not exist as a public API. If it doesn't, use `clash_starlark::codegen::serialize` on a full `Stmt` wrapping the `Expr`. Adapt the test accordingly — the goal is to verify the generated Starlark contains the expected sandbox and binary names.

- [ ] **Step 4: Migrate `import_settings.rs` to use the shared function**

In `clash/src/cmd/import_settings.rs`:

1. Replace the local `build_ecosystem_rules` function (lines ~536-581) with a thin wrapper or direct call to `crate::policy_gen::ecosystems::ecosystem_rules`.
2. Update the two call sites:
   - Line ~219: `let eco_rules = crate::policy_gen::ecosystems::ecosystem_rules(&detection.ecosystems, preset);`
   - Line ~366: `rules.extend(crate::policy_gen::ecosystems::ecosystem_rules(&detection.ecosystems, "project_files"));`
3. Delete the old `build_ecosystem_rules` function.

- [ ] **Step 5: Run full check**

Run: `just check`
Expected: PASS (all existing tests still pass)

- [ ] **Step 6: Commit**

```bash
git add clash/src/policy_gen/ecosystems.rs clash/src/policy_gen/mod.rs clash/src/cmd/import_settings.rs
git commit -m "refactor(policy_gen): extract ecosystem rules into shared module"
```

---

### Task 5: Migrate `import_settings.rs` to use shared definitions

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Replace hardcoded tool name lists**

In `generate_starlark_from_analysis()`, replace the hardcoded tool list at lines ~382-386:

```rust
// Before:
let fs_tool_names: Vec<&str> = ["Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit"]
    .iter()
    .filter(|t| analysis.tool_allows.contains(&t.to_string()))
    .copied()
    .collect();

// After:
use crate::policy_gen::tools::FS_ALL_TOOLS;
let fs_tool_names: Vec<&str> = FS_ALL_TOOLS
    .iter()
    .filter(|t| analysis.tool_allows.contains(&t.to_string()))
    .copied()
    .collect();
```

Replace the excluded tools list at lines ~394-402:

```rust
// Before:
let excluded: &[&str] = &[
    "Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit", "Bash",
];

// After:
use crate::policy_gen::tools::is_categorized_tool;
let other_allows: Vec<&str> = analysis
    .tool_allows
    .iter()
    .filter(|t| !is_categorized_tool(t))
    .map(|s| s.as_str())
    .collect();
```

- [ ] **Step 2: Replace inline sandbox definition**

In `generate_starlark_from_analysis()`, replace lines ~294-314 with:

```rust
use crate::policy_gen::sandboxes;
stmts.extend(sandboxes::project_files_sandbox());
stmts.push(Stmt::Blank);
```

And replace the sandbox reference at line ~318:

```rust
// Before:
Some(Expr::ident("project_files")),

// After:
Some(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
```

Also replace sandbox references at lines ~375 and ~387-390:

```rust
// Before:
allow_with_sandbox(Expr::ident("project_files")),

// After:
allow_with_sandbox(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
```

- [ ] **Step 3: Run full check**

Run: `just check`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "refactor(import): use shared tool constants and sandbox builder"
```

---

### Task 6: Migrate `from_trace.rs` to use shared definitions

**Files:**
- Modify: `clash/src/cmd/from_trace.rs`

- [ ] **Step 1: Replace hardcoded tool name lists**

In `generate_starlark()`, replace the tool categorization at lines ~393-421:

```rust
// Before:
let read_tools: Vec<&str> = ["Read", "Glob", "Grep"]
    .iter()
    .filter(|t| analysis.tools.contains(**t))
    .copied()
    .collect();
let write_tools: Vec<&str> = ["Write", "Edit", "NotebookEdit"]
    .iter()
    .filter(|t| analysis.tools.contains(**t))
    .copied()
    .collect();
let net_tools: Vec<&str> = ["WebFetch", "WebSearch"]
    .iter()
    .filter(|t| analysis.tools.contains(**t))
    .copied()
    .collect();
let other_tools: Vec<&String> = analysis
    .tools
    .iter()
    .filter(|t| {
        ![
            "Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit",
            "WebFetch", "WebSearch", "Bash",
        ]
        .contains(&t.as_str())
    })
    .collect();

// After:
use crate::policy_gen::tools::{FS_READ_TOOLS, FS_WRITE_TOOLS, NET_TOOLS, is_categorized_tool};
let read_tools: Vec<&str> = FS_READ_TOOLS
    .iter()
    .filter(|t| analysis.tools.contains(**t))
    .copied()
    .collect();
let write_tools: Vec<&str> = FS_WRITE_TOOLS
    .iter()
    .filter(|t| analysis.tools.contains(**t))
    .copied()
    .collect();
let net_tools: Vec<&str> = NET_TOOLS
    .iter()
    .filter(|t| analysis.tools.contains(**t))
    .copied()
    .collect();
let other_tools: Vec<&String> = analysis
    .tools
    .iter()
    .filter(|t| !is_categorized_tool(t))
    .collect();
```

- [ ] **Step 2: Replace inline sandbox definition**

Replace lines ~372-390:

```rust
// Before:
let rw = clash_starlark::kwargs!(read = true, write = true);
let fs_box = sandbox(
    "cwd",
    vec![( "fs", Expr::list(vec![ ... ]) )],
);
stmts.push(Stmt::comment("Sandbox for file-access tools ..."));
stmts.push(Stmt::assign("project_files", fs_box));
stmts.push(Stmt::Blank);

// After:
use crate::policy_gen::sandboxes;
stmts.extend(sandboxes::project_files_sandbox());
stmts.push(Stmt::Blank);
```

- [ ] **Step 3: Replace sandbox name references**

Find all `"project_files"` string literals in `from_trace.rs` used as sandbox references and replace with `sandboxes::PROJECT_FILES_SANDBOX`:

```rust
// Before:
allow_with_sandbox(Expr::ident("project_files")),

// After:
allow_with_sandbox(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
```

- [ ] **Step 4: Run full check**

Run: `just check`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/from_trace.rs
git commit -m "refactor(trace): use shared tool constants and sandbox builder"
```

---

### Task 7: Add test that generators compile and stay in sync

**Files:**
- Create: `clash/src/policy_gen/tests.rs`
- Modify: `clash/src/policy_gen/mod.rs`

- [ ] **Step 1: Write integration tests**

Create `clash/src/policy_gen/tests.rs`:

```rust
//! Integration tests verifying that shared definitions stay consistent
//! and that generated policies compile successfully.

#[cfg(test)]
mod test {
    use crate::policy_gen::sandboxes;
    use crate::policy_gen::tools::*;

    #[test]
    fn project_files_sandbox_evaluates_to_valid_policy() {
        // Build a minimal policy using the shared sandbox builder
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;

        let mut stmts = vec![
            load_builtin(),
            load_std(&["settings", "policy", "sandbox", "allow", "ask", "deny", "glob", "subpath", "when"]),
            Stmt::Blank,
        ];
        stmts.extend(sandboxes::project_files_sandbox());
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(settings(
            ask(),
            Some(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
        )));
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(policy(
            "test",
            ask(),
            vec![tool_match(
                FS_ALL_TOOLS,
                allow_with_sandbox(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
            )],
            None,
        )));

        let code = clash_starlark::codegen::serialize(&stmts);
        let result = clash_starlark::evaluate(&code, "test.star", &std::path::PathBuf::from("."));
        assert!(
            result.is_ok(),
            "generated policy should evaluate successfully: {:?}",
            result.err()
        );
    }

    #[test]
    fn ecosystem_rules_with_shared_sandbox_compile() {
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;
        use crate::policy_gen::ecosystems;
        use crate::policy_gen::loads;

        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();

        let mut stmts = loads::standard_loads(&[], &[rust]);
        stmts.push(load_std(&[
            "settings", "policy", "sandbox", "allow", "ask", "deny",
            "glob", "subpath", "when",
        ]));
        stmts.push(Stmt::Blank);
        stmts.extend(sandboxes::project_files_sandbox());
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(settings(ask(), None)));
        stmts.push(Stmt::Blank);

        let eco_rules = ecosystems::ecosystem_rules(
            &[rust],
            sandboxes::PROJECT_FILES_SANDBOX,
        );
        stmts.push(Stmt::Expr(policy("test", ask(), eco_rules, None)));

        let code = clash_starlark::codegen::serialize(&stmts);
        let result = clash_starlark::evaluate(&code, "test.star", &std::path::PathBuf::from("."));
        assert!(
            result.is_ok(),
            "policy with ecosystem rules should evaluate: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );
    }
}
```

- [ ] **Step 2: Register in mod.rs**

In `clash/src/policy_gen/mod.rs`, add:

```rust
#[cfg(test)]
mod tests;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p clash policy_gen`
Expected: PASS

- [ ] **Step 4: Run full check**

Run: `just check`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/policy_gen/tests.rs clash/src/policy_gen/mod.rs
git commit -m "test(policy_gen): add integration tests for shared definitions"
```

---

### Task 8: Update documentation

**Files:**
- Modify: `AGENTS.md`

- [ ] **Step 1: Add policy_gen to the Layout section**

In `AGENTS.md`, add an entry to the Layout section:

```
* *policy_gen* Shared definitions for policy generation (tool constants, sandbox builders, ecosystem rules)
```

- [ ] **Step 2: Commit**

```bash
git add AGENTS.md
git commit -m "docs: add policy_gen module to layout documentation"
```
