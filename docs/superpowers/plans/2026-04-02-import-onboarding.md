# Import-Based Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign `clash init` to import permissions from Claude Code settings and generate a matching Clash policy with renamed sandbox presets.

**Architecture:** Read Claude's effective settings via the `claude_settings` crate, classify each permission into categories (bash prefix, tool-only, file exact/glob), generate a Starlark policy using the `codegen::builder` API. Sandbox presets are renamed in the stdlib (`plan`→`readonly`, `edit`→`project`, `safe_yolo`→`workspace`, `yolo`→`unrestricted`). A posture selection prompt handles empty/bypass settings.

**Tech Stack:** Rust, Starlark (policy DSL), `claude_settings` crate, `clash_starlark::codegen` builder API, `dialoguer` (interactive prompts), clester (e2e tests)

**Spec:** `docs/superpowers/specs/2026-04-02-import-onboarding-design.md`

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `clash_starlark/stdlib/sandboxes.star` | Modify | Rename sandbox presets |
| `clash/src/default_policy.star` | Modify | Update sandbox references to new names |
| `clash/src/cmd/from_trace.rs` | Modify | Rename `_fs_box` → `project_files`, load `project` instead of `dev` |
| `examples/permissive.star` | Modify | No sandbox refs, but review |
| `examples/paranoid.star` | Modify | No sandbox refs, but review |
| `examples/node-dev.star` | Modify | No stdlib sandbox refs, no change needed |
| `examples/python-dev.star` | Modify | No stdlib sandbox refs, no change needed |
| `examples/rust-dev.star` | Modify | No stdlib sandbox refs, no change needed |
| `clash/src/cmd/import_settings.rs` | Create | Core import logic: analyze + generate |
| `clash/src/cmd/mod.rs` | Modify | Register new module |
| `clash/src/cmd/init.rs` | Modify | Make `install_agent_plugin` `pub(crate)`, extract no-import path |
| `clash/src/cli.rs` | Modify | Add `--no-import` flag, restructure `Init` variant |
| `clash/src/main.rs` | Modify | Route `Init` to import by default |
| `clester/tests/scripts/star_sandbox_presets.yaml` | Create | Test new sandbox preset names |
| `clester/tests/scripts/init_no_import.yaml` | Create | Test `--no-import` path |

---

### Task 1: Rename sandbox presets in stdlib

**Files:**
- Modify: `clash_starlark/stdlib/sandboxes.star` (full file, 50 lines)

- [ ] **Step 1: Update `sandboxes.star` with new names**

Replace the full content of `clash_starlark/stdlib/sandboxes.star` with:

```starlark
# Clash sandbox presets — intent-based trust levels for Bash commands.
#
# These presets express what you trust a command to do, not what
# the command literally says.  Pick a preset based on intent:
#
#   readonly     — read-only project access, network allowed
#   project      — build tools, git: read+write project, no network
#   workspace    — full home directory access, deny sensitive dirs
#   unrestricted — fully trusted: all filesystem + network access
#

UNSAFE_IN_HOME = (".ssh", ".gpg", ".config", ".aws", ".gh", ".git")


readonly = sandbox(
    name = "readonly",
    default = ask(),
    fs = {
        glob("$PWD/**"): allow("rx"),
        glob("$HOME/.claude/**"): allow("r"),
    },
    net = allow(),
)

project = sandbox(
    name = "project",
    default=ask(),
    fs = {
        glob("$PWD/**"): allow(FULL),
        glob("$HOME/.claude/**"): allow("rwcd"),
        glob("$TMPDIR/**"): allow(FULL),
    }
)

workspace = sandbox(
    name = "workspace",
    default=deny(),
    fs = {
        glob("$HOME/**"): allow(),
        } | {
        glob("$HOME/{}/**".format(d)): deny() for d in UNSAFE_IN_HOME
    },
)

unrestricted = sandbox(
    name = "unrestricted",
    default=allow(),
)
```

- [ ] **Step 2: Run check to verify stdlib loads**

Run: `cargo test -p clash_starlark 2>&1 | tail -20`
Expected: All tests pass (the stdlib is loaded at compile time in tests)

- [ ] **Step 3: Commit**

```bash
git add clash_starlark/stdlib/sandboxes.star
git commit -m "refactor: rename sandbox presets (plan→readonly, edit→project, safe_yolo→workspace, yolo→unrestricted)"
```

---

### Task 2: Update default_policy.star for new sandbox names

**Files:**
- Modify: `clash/src/default_policy.star` (full file, 20 lines)

- [ ] **Step 1: Update default_policy.star**

Replace the full content of `clash/src/default_policy.star` with:

```starlark
load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "project", "workspace")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
        },
        (mode("edit"), mode("default")): {
            tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
```

- [ ] **Step 2: Run the compile test**

Run: `cargo test -p clash --lib cmd::init::tests::starter_policy_compiles 2>&1 | tail -10`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add clash/src/default_policy.star
git commit -m "refactor: update default_policy.star for renamed sandbox presets"
```

---

### Task 3: Update from_trace.rs — rename `_fs_box` → `project_files` and load `project`

**Files:**
- Modify: `clash/src/cmd/from_trace.rs:309-470`

- [ ] **Step 1: Update the sandbox load and variable name in `generate_starlark`**

In `clash/src/cmd/from_trace.rs`, make these changes:

Change line 318 from:
```rust
        load_sandboxes(&["dev"]),
```
to:
```rust
        load_sandboxes(&["project"]),
```

Change line 337 from:
```rust
    stmts.push(Stmt::comment(
        "Tighter sandbox for Claude fs tools (scoped to cwd + ~/.claude)",
    ));
```
to:
```rust
    stmts.push(Stmt::comment(
        "Sandbox for file-access tools (scoped to project + ~/.claude)",
    ));
```

Change line 339 from:
```rust
    stmts.push(Stmt::assign("_fs_box", fs_box));
```
to:
```rust
    stmts.push(Stmt::assign("project_files", fs_box));
```

Change all references to `Expr::ident("_fs_box")` to `Expr::ident("project_files")` (lines 380, 389).

Change all references to `Expr::ident("dev")` to `Expr::ident("project")` (lines 438, 451).

Change the settings call at line 461 from:
```rust
        Expr::ident("ask"),
        Some(Expr::ident("dev")),
```
to:
```rust
        Expr::ident("ask"),
        Some(Expr::ident("project")),
```

- [ ] **Step 2: Update the test assertions**

In the same file, update test functions:

In `test_generate_starlark_basic` (~line 628), change:
```rust
        assert!(policy.contains("(\"Read\", \"Grep\"): allow(sandbox = _fs_box)"));
        assert!(policy.contains("\"Write\": allow(sandbox = _fs_box)"));
```
to:
```rust
        assert!(policy.contains("(\"Read\", \"Grep\"): allow(sandbox = project_files)"));
        assert!(policy.contains("\"Write\": allow(sandbox = project_files)"));
```

Change:
```rust
        assert!(policy.contains("allow(sandbox = dev)"));
```
to:
```rust
        assert!(policy.contains("allow(sandbox = project)"));
```

In `test_generate_starlark_no_binaries` (~line 656), change:
```rust
        assert!(policy.contains("\"Read\": allow(sandbox = _fs_box)"));
        assert!(policy.contains("\"Edit\": allow(sandbox = _fs_box)"));
```
to:
```rust
        assert!(policy.contains("\"Read\": allow(sandbox = project_files)"));
        assert!(policy.contains("\"Edit\": allow(sandbox = project_files)"));
```

In `test_generate_starlark_bash_without_binary_detail` (~line 674), change:
```rust
        assert!(policy.contains("when({\"Bash\": allow(sandbox = dev)})"));
```
to:
```rust
        assert!(policy.contains("when({\"Bash\": allow(sandbox = project)})"));
```

- [ ] **Step 3: Run from_trace tests**

Run: `cargo test -p clash --lib cmd::from_trace 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add clash/src/cmd/from_trace.rs
git commit -m "refactor: rename _fs_box to project_files and use project sandbox preset in from_trace"
```

---

### Task 4: Update docs and site references to old sandbox names

**Files:**
- Modify: docs and site files that reference `plan`, `edit`, `safe_yolo`, `yolo` as sandbox names

- [ ] **Step 1: Find all references**

Run:
```bash
grep -rn 'safe_yolo\|"plan"\|"edit"\|"yolo"' docs/ site/ README.md --include='*.md' | grep -i sandbox
```

Update each reference to use the new names. The exact files depend on grep output — fix each one.

- [ ] **Step 2: Update example files if needed**

The example files (`examples/permissive.star`, `examples/paranoid.star`) do not reference the stdlib sandbox presets — they define their own inline sandboxes or use none. No changes needed for `examples/node-dev.star`, `examples/python-dev.star`, `examples/rust-dev.star` either (they define local sandbox names like `"node"`, `"python"`, `"rust"`).

Verify:
```bash
grep -n 'plan\|edit\|safe_yolo\|yolo' examples/*.star
```

- [ ] **Step 3: Run full check**

Run: `just check 2>&1 | tail -30`
Expected: All tests and lints pass

- [ ] **Step 4: Commit**

```bash
git add -A docs/ site/ README.md examples/
git commit -m "docs: update sandbox preset names in documentation"
```

---

### Task 5: Add `--no-import` flag to CLI and update routing

**Files:**
- Modify: `clash/src/cli.rs:199-212`
- Modify: `clash/src/main.rs:17-23`
- Modify: `clash/src/cmd/init.rs:102` (visibility)
- Modify: `clash/src/cmd/mod.rs:9`

- [ ] **Step 1: Add `--no-import` flag to `cli.rs`**

In `clash/src/cli.rs`, change the `Init` variant (lines 199-212) to:

```rust
    /// Initialize a new clash policy with a safe default configuration
    ///
    /// By default, imports permissions from your coding agent's existing
    /// configuration and generates a matching Clash policy. Use --no-import
    /// to skip policy generation and just install hooks.
    Init {
        /// Generate policy from an observed session trace file.
        /// Pass a path to trace.jsonl or audit.jsonl, or "latest" to auto-detect.
        #[arg(long = "from-trace", value_name = "PATH", conflicts_with = "no_import")]
        from_trace: Option<std::path::PathBuf>,
        /// Skip policy import — just install hooks and print setup instructions
        #[arg(long = "no-import", conflicts_with = "from_trace")]
        no_import: bool,
        /// Which coding agent to set up (prompts if omitted)
        #[arg(long)]
        agent: Option<crate::agents::AgentKind>,
    },
```

- [ ] **Step 2: Register import_settings module in `cmd/mod.rs`**

In `clash/src/cmd/mod.rs`, add after line 7 (`pub mod from_trace;`):

```rust
pub mod import_settings;
```

- [ ] **Step 3: Make `install_agent_plugin` pub(crate) in `init.rs`**

In `clash/src/cmd/init.rs` line 102, change:

```rust
fn install_agent_plugin(agent: AgentKind) -> Result<bool> {
```

to:

```rust
pub(crate) fn install_agent_plugin(agent: AgentKind) -> Result<bool> {
```

- [ ] **Step 4: Update routing in `main.rs`**

In `clash/src/main.rs`, change the `Commands::Init` match arm (lines 17-23) to:

```rust
            Commands::Init { from_trace, no_import, agent } => {
                if let Some(trace_path) = from_trace {
                    cmd::from_trace::run(&trace_path).map(|_| ())
                } else if no_import {
                    cmd::init::run_no_import(agent)
                } else {
                    cmd::import_settings::run(agent)
                }
            }
```

- [ ] **Step 5: Add `run_no_import` function to `init.rs`**

In `clash/src/cmd/init.rs`, add after the `run_install` function (after line 52):

```rust
/// Minimal init: install hooks/plugin only, no policy generation.
pub fn run_no_import(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    install_agent_plugin(agent)?;

    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            tracing::warn!(error = %e, "Could not install status line");
        }
    }

    println!();
    ui::success("Clash hooks installed.");
    println!();
    println!(
        "  Run {} to configure your policy.",
        style::bold("clash policy edit")
    );
    println!(
        "  Run {} to verify the setup.",
        style::bold(&format!("clash doctor --agent {agent}"))
    );

    Ok(())
}
```

- [ ] **Step 6: Create stub `import_settings.rs`**

Create `clash/src/cmd/import_settings.rs` with a minimal stub so the project compiles:

```rust
//! Import permissions from a coding agent's settings and generate a Clash policy.

use anyhow::Result;

use crate::agents::AgentKind;

/// Import settings from the agent and generate a Clash policy.
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let _agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    // TODO: implement in subsequent tasks
    anyhow::bail!("import not yet implemented — use `clash init --no-import` for now")
}
```

- [ ] **Step 7: Verify it compiles**

Run: `cargo build -p clash 2>&1 | tail -10`
Expected: Compiles successfully

- [ ] **Step 8: Commit**

```bash
git add clash/src/cli.rs clash/src/main.rs clash/src/cmd/init.rs clash/src/cmd/mod.rs clash/src/cmd/import_settings.rs
git commit -m "feat: add --no-import flag to clash init, stub import_settings module"
```

---

### Task 6: Implement posture selection prompt

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Define the `Posture` enum with `SelectItem`**

In `clash/src/cmd/import_settings.rs`, replace the stub with:

```rust
//! Import permissions from a coding agent's settings and generate a Clash policy.

use anyhow::Result;

use crate::agents::AgentKind;

/// A starting posture for policy generation when no permissions exist to import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Posture {
    Strict,
    Balanced,
    Permissive,
}

impl crate::dialog::SelectItem for Posture {
    fn label(&self) -> &str {
        match self {
            Posture::Strict => "Strict",
            Posture::Balanced => "Balanced",
            Posture::Permissive => "Permissive",
        }
    }

    fn description(&self) -> &str {
        match self {
            Posture::Strict => "deny by default, read-only project access",
            Posture::Balanced => "ask by default, read+write project access",
            Posture::Permissive => "allow by default, full workspace access (sandboxed)",
        }
    }

    fn variants() -> &'static [Self] {
        &[Posture::Strict, Posture::Balanced, Posture::Permissive]
    }
}

impl Posture {
    /// The Starlark default effect for this posture.
    fn default_effect(&self) -> &str {
        match self {
            Posture::Strict => "deny",
            Posture::Balanced => "ask",
            Posture::Permissive => "allow",
        }
    }

    /// The sandbox preset name for this posture.
    fn sandbox_preset(&self) -> &str {
        match self {
            Posture::Strict => "readonly",
            Posture::Balanced => "project",
            Posture::Permissive => "workspace",
        }
    }
}

/// Import settings from the agent and generate a Clash policy.
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let _agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    // TODO: implement in subsequent tasks
    anyhow::bail!("import not yet implemented — use `clash init --no-import` for now")
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo build -p clash 2>&1 | tail -10`
Expected: Compiles successfully

- [ ] **Step 3: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "feat: add Posture enum for policy generation prompt"
```

---

### Task 7: Implement settings analysis

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Write the failing tests for `analyze_settings`**

Add at the bottom of `clash/src/cmd/import_settings.rs`:

```rust
/// Categorized analysis of a Claude Code settings file.
#[derive(Debug, Default)]
struct ImportAnalysis {
    /// Tool-only allows (e.g., "Edit" with no pattern).
    tool_allows: Vec<String>,
    /// Tool-only denies.
    tool_denies: Vec<String>,
    /// Tool-only asks.
    tool_asks: Vec<String>,
    /// Bash prefix allows — each entry is a list of command segments.
    /// e.g., "Bash(git:*)" → vec!["git"], "Bash(cargo check:*)" → vec!["cargo", "check"]
    bash_allows: Vec<Vec<String>>,
    /// Bash prefix denies.
    bash_denies: Vec<Vec<String>>,
    /// Bash prefix asks.
    bash_asks: Vec<Vec<String>>,
    /// Exact file path denies (tool, path).
    file_denies: Vec<(String, String)>,
    /// Whether bypass_permissions is set.
    bypass_permissions: bool,
    /// Whether the permissions set is empty (nothing to import).
    is_empty: bool,
    /// Permissions that were skipped (globs, MCP tools) — for user warnings.
    skipped: Vec<String>,
}

impl ImportAnalysis {
    /// Returns true if there are no meaningful permissions to import.
    fn needs_posture_prompt(&self) -> bool {
        self.is_empty || self.bypass_permissions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty_settings() {
        let settings = claude_settings::Settings::default();
        let analysis = analyze_settings(&settings);
        assert!(analysis.is_empty);
        assert!(analysis.needs_posture_prompt());
    }

    #[test]
    fn test_analyze_bypass_permissions() {
        let settings = claude_settings::Settings::default().with_bypass_permissions(true);
        let analysis = analyze_settings(&settings);
        assert!(analysis.bypass_permissions);
        assert!(analysis.needs_posture_prompt());
    }

    #[test]
    fn test_analyze_basic_permissions() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Read")
            .deny("Read(.env)")
            .ask("Write");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert!(!analysis.needs_posture_prompt());
        assert_eq!(analysis.bash_allows, vec![vec!["git".to_string()]]);
        assert!(analysis.tool_allows.contains(&"Read".to_string()));
        assert_eq!(analysis.file_denies, vec![("Read".into(), ".env".into())]);
        assert!(analysis.tool_asks.contains(&"Write".to_string()));
    }

    #[test]
    fn test_analyze_multi_word_prefix() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new().allow("Bash(cargo check:*)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert_eq!(
            analysis.bash_allows,
            vec![vec!["cargo".to_string(), "check".to_string()]]
        );
    }

    #[test]
    fn test_analyze_skips_mcp() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("mcp__server__tool")
            .allow("Read");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert_eq!(analysis.tool_allows, vec!["Read".to_string()]);
        assert_eq!(analysis.skipped.len(), 1);
        assert!(analysis.skipped[0].contains("mcp__"));
    }

    #[test]
    fn test_analyze_skips_globs() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Read(**/*.rs)")
            .allow("Edit");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert_eq!(analysis.tool_allows, vec!["Edit".to_string()]);
        assert_eq!(analysis.skipped.len(), 1);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib cmd::import_settings 2>&1 | tail -20`
Expected: FAIL — `analyze_settings` is not defined

- [ ] **Step 3: Implement `analyze_settings`**

Add this function to `clash/src/cmd/import_settings.rs` (before the tests module):

```rust
use claude_settings::permission::{Permission, PermissionPattern};

/// Analyze Claude Code settings and classify permissions into categories.
fn analyze_settings(settings: &claude_settings::Settings) -> ImportAnalysis {
    let perms = &settings.permissions;
    let mut analysis = ImportAnalysis {
        bypass_permissions: settings.bypass_permissions.unwrap_or(false),
        is_empty: perms.is_empty(),
        ..Default::default()
    };

    if analysis.is_empty || analysis.bypass_permissions {
        return analysis;
    }

    for perm in perms.allowed() {
        classify_permission(perm, "allow", &mut analysis);
    }
    for perm in perms.denied() {
        classify_permission(perm, "deny", &mut analysis);
    }
    for perm in perms.asking() {
        classify_permission(perm, "ask", &mut analysis);
    }

    analysis
}

/// Classify a single permission into the appropriate analysis bucket.
fn classify_permission(perm: &Permission, effect: &str, analysis: &mut ImportAnalysis) {
    let tool = perm.tool();

    // Skip MCP tools
    if tool.starts_with("mcp__") {
        analysis.skipped.push(perm.to_string());
        return;
    }

    match perm.pattern() {
        None => {
            // Tool-only permission (e.g., "Read", "Edit")
            match effect {
                "allow" => analysis.tool_allows.push(tool.to_string()),
                "deny" => analysis.tool_denies.push(tool.to_string()),
                "ask" => analysis.tool_asks.push(tool.to_string()),
                _ => {}
            }
        }
        Some(PermissionPattern::Prefix(prefix)) if tool == "Bash" => {
            // Bash prefix (e.g., "Bash(git:*)" or "Bash(cargo check:*)")
            let segments: Vec<String> = prefix.split_whitespace().map(String::from).collect();
            match effect {
                "allow" => analysis.bash_allows.push(segments),
                "deny" => analysis.bash_denies.push(segments),
                "ask" => analysis.bash_asks.push(segments),
                _ => {}
            }
        }
        Some(PermissionPattern::Exact(path)) => {
            // Exact file match (e.g., "Read(.env)")
            match effect {
                "deny" => analysis.file_denies.push((tool.to_string(), path.clone())),
                // Exact allows/asks on file tools are unusual, treat as tool-level
                "allow" => analysis.tool_allows.push(tool.to_string()),
                "ask" => analysis.tool_asks.push(tool.to_string()),
                _ => {}
            }
        }
        Some(PermissionPattern::Glob(_)) => {
            // Glob patterns — skip with warning (no direct Clash equivalent)
            analysis.skipped.push(perm.to_string());
        }
        Some(PermissionPattern::Prefix(_)) => {
            // Non-Bash prefix (unusual) — treat as tool-level
            match effect {
                "allow" => analysis.tool_allows.push(tool.to_string()),
                "deny" => analysis.tool_denies.push(tool.to_string()),
                "ask" => analysis.tool_asks.push(tool.to_string()),
                _ => {}
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clash --lib cmd::import_settings 2>&1 | tail -20`
Expected: All 6 tests pass

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "feat: implement settings analysis for permission import"
```

---

### Task 8: Implement Starlark policy generation

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Write the failing compile-check test**

Add to the `tests` module in `clash/src/cmd/import_settings.rs`:

```rust
    #[test]
    fn test_generate_compiles() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Bash(cargo:*)")
            .allow("Bash(npm:*)")
            .allow("Read")
            .allow("Glob")
            .allow("Grep")
            .allow("Write")
            .allow("Edit")
            .deny("Read(.env)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(&analysis);

        // Must produce valid Starlark that compiles to a policy tree
        crate::policy::compile::compile_to_tree(&compile_star(&starlark))
            .expect("generated policy must compile");
    }

    #[test]
    fn test_generate_posture_compiles() {
        for posture in Posture::variants() {
            let starlark = generate_starlark_from_posture(*posture);
            crate::policy::compile::compile_to_tree(&compile_star(&starlark))
                .unwrap_or_else(|e| panic!("posture {:?} failed to compile: {e}", posture));
        }
    }

    #[test]
    fn test_generate_groups_bash_prefixes() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Bash(cargo:*)")
            .allow("Bash(npm:*)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(&analysis);

        // Should group into a tuple key
        assert!(
            starlark.contains("(\"cargo\", \"git\", \"npm\")"),
            "expected grouped tuple key, got:\n{starlark}"
        );
    }

    #[test]
    fn test_generate_denies_first() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Read")
            .deny("Read(.env)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(&analysis);

        let deny_pos = starlark.find("deny()").expect("should contain deny");
        let allow_pos = starlark.find("allow(").expect("should contain allow");
        assert!(
            deny_pos < allow_pos,
            "deny rules should come before allow rules"
        );
    }

    /// Helper: compile a .star string to JSON via the starlark evaluator.
    fn compile_star(source: &str) -> String {
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("starlark evaluation failed");
        output.json
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib cmd::import_settings 2>&1 | tail -20`
Expected: FAIL — `generate_starlark_from_analysis` and `generate_starlark_from_posture` not defined

- [ ] **Step 3: Implement `generate_starlark_from_posture`**

Add to `clash/src/cmd/import_settings.rs`:

```rust
use clash_starlark::codegen::ast::{Expr, Stmt};
use clash_starlark::codegen::builder::*;

/// Generate a minimal Starlark policy from a posture selection.
fn generate_starlark_from_posture(posture: Posture) -> String {
    let effect_name = posture.default_effect();
    let sandbox_name = posture.sandbox_preset();

    let stmts = vec![
        load_builtin(),
        load_std(&["policy", "settings", "allow", "ask", "deny"]),
        load_sandboxes(&[sandbox_name]),
        Stmt::Blank,
        Stmt::Expr(settings(
            Expr::ident(effect_name),
            Some(Expr::ident(sandbox_name)),
        )),
        Stmt::Blank,
        Stmt::Expr(policy(
            "default",
            Expr::ident(effect_name),
            vec![],
            None,
        )),
    ];

    clash_starlark::codegen::serialize(&stmts)
}
```

- [ ] **Step 4: Implement `generate_starlark_from_analysis`**

Add to `clash/src/cmd/import_settings.rs`:

```rust
/// Generate a Starlark policy from analyzed Claude Code settings.
fn generate_starlark_from_analysis(analysis: &ImportAnalysis) -> String {
    let mut stmts = vec![
        Stmt::comment("Imported from Claude Code settings"),
        load_builtin(),
        load_std(&[
            "when", "policy", "settings", "sandbox", "cwd", "home", "allow", "ask", "deny",
        ]),
        load_sandboxes(&["project"]),
        Stmt::Blank,
    ];

    // Inline sandbox for file-access tools
    let rw = clash_starlark::kwargs!(read = true, write = true);
    let fs_box = sandbox(
        "cwd",
        vec![(
            "fs",
            Expr::list(vec![
                cwd(clash_starlark::kwargs!(follow_worktrees = true))
                    .recurse()
                    .allow_kwargs(rw.clone()),
                home().child(".claude").recurse().allow_kwargs(rw),
            ]),
        )],
    );
    stmts.push(Stmt::comment(
        "Sandbox for file-access tools (scoped to project + ~/.claude)",
    ));
    stmts.push(Stmt::assign("project_files", fs_box));
    stmts.push(Stmt::Blank);

    // Settings
    stmts.push(Stmt::Expr(settings(
        Expr::ident("ask"),
        Some(Expr::ident("project")),
    )));
    stmts.push(Stmt::Blank);

    // Build rules
    let mut rules: Vec<Expr> = Vec::new();

    // 1. File denies (highest priority)
    for (tool, path) in &analysis.file_denies {
        let expr = clash_starlark::match_tree! {
            tool.as_str() => {
                path.as_str() => deny(),
            },
        };
        rules.push(expr);
    }

    // 2. Bash denies
    if !analysis.bash_denies.is_empty() {
        let bash_deny_rules = build_bash_rules(&analysis.bash_denies, deny());
        rules.push(Expr::commented("Denied commands", bash_deny_rules));
    }

    // 3. Bash allows (grouped)
    if !analysis.bash_allows.is_empty() {
        let bash_allow_rules =
            build_bash_rules(&analysis.bash_allows, allow_with_sandbox(Expr::ident("project")));
        rules.push(Expr::commented("Allowed commands", bash_allow_rules));
    }

    // 4. Bash asks
    if !analysis.bash_asks.is_empty() {
        let bash_ask_rules =
            build_bash_rules(&analysis.bash_asks, ask_with_sandbox(Expr::ident("project")));
        rules.push(bash_ask_rules);
    }

    // 5. Tool denies
    if !analysis.tool_denies.is_empty() {
        let names: Vec<&str> = analysis.tool_denies.iter().map(|s| s.as_str()).collect();
        rules.push(tool_match(&names, deny()));
    }

    // 6. Tool allows — categorize into read/write/other
    let read_tools: Vec<&str> = analysis
        .tool_allows
        .iter()
        .filter(|t| ["Read", "Glob", "Grep"].contains(&t.as_str()))
        .map(|s| s.as_str())
        .collect();
    let write_tools: Vec<&str> = analysis
        .tool_allows
        .iter()
        .filter(|t| ["Write", "Edit", "NotebookEdit"].contains(&t.as_str()))
        .map(|s| s.as_str())
        .collect();
    let other_tools: Vec<&str> = analysis
        .tool_allows
        .iter()
        .filter(|t| {
            !["Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit"].contains(&t.as_str())
        })
        .map(|s| s.as_str())
        .collect();

    if !read_tools.is_empty() {
        rules.push(Expr::commented(
            "Read-only tools",
            tool_match(&read_tools, allow_with_sandbox(Expr::ident("project_files"))),
        ));
    }
    if !write_tools.is_empty() {
        rules.push(Expr::commented(
            "Write tools",
            tool_match(&write_tools, allow_with_sandbox(Expr::ident("project_files"))),
        ));
    }
    if !other_tools.is_empty() {
        rules.push(tool_match(&other_tools, allow()));
    }

    // 7. Tool asks
    if !analysis.tool_asks.is_empty() {
        let names: Vec<&str> = analysis.tool_asks.iter().map(|s| s.as_str()).collect();
        rules.push(tool_match(&names, ask()));
    }

    stmts.push(Stmt::Expr(policy("imported", Expr::ident("ask"), rules, None)));

    clash_starlark::codegen::serialize(&stmts)
}

/// Build a `when({"Bash": {("git", "cargo"): {glob("**"): effect}}})` rule
/// from a list of command segment lists.
///
/// Multi-segment commands (e.g., ["cargo", "check"]) are flattened to their
/// first segment — Clash's match tree with `glob("**")` will match any
/// subcommands under that binary anyway.
fn build_bash_rules(commands: &[Vec<String>], effect: Expr) -> Expr {
    use clash_starlark::codegen::builder::{MatchKey, MatchValue};

    // Collect unique binary names (first segment of each command)
    let mut bins: Vec<String> = commands
        .iter()
        .filter_map(|segs| segs.first().cloned())
        .collect();
    bins.sort();
    bins.dedup();

    let key: MatchKey = if bins.len() == 1 {
        MatchKey::Single(bins[0].clone())
    } else {
        MatchKey::Tuple(bins)
    };

    // Wrap effect in glob("**") => effect
    let glob_entry = clash_starlark::codegen::ast::DictEntry::new(
        Expr::call("glob", vec![Expr::string("**")]),
        effect,
    );
    let glob_dict = Expr::dict(vec![glob_entry]);

    match_rule(vec![(
        "Bash".into(),
        MatchValue::Nested(vec![(key, MatchValue::Effect(glob_dict))]),
    )])
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clash --lib cmd::import_settings 2>&1 | tail -30`
Expected: All tests pass. The `compile_star` test helper uses `clash_starlark::evaluate()` directly to compile `.star` source to JSON, then `crate::policy::compile::compile_to_tree()` to verify the JSON produces a valid policy tree.

- [ ] **Step 7: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "feat: implement Starlark policy generation from imported settings"
```

---

### Task 9: Wire up the full import flow

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Implement the full `run` function**

Replace the stub `run` function in `clash/src/cmd/import_settings.rs` with:

```rust
use crate::settings::ClashSettings;
use crate::style;
use crate::ui;

/// Import settings from the agent and generate a Clash policy.
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    // Step 1: Read effective Claude settings
    let claude = claude_settings::ClaudeSettings::new();
    let settings = claude.effective().unwrap_or_default();
    let analysis = analyze_settings(&settings);

    // Step 2: Generate policy
    let policy_content = if analysis.needs_posture_prompt() {
        // No meaningful permissions — prompt for a posture
        if analysis.bypass_permissions {
            ui::info("Claude Code is running with bypass_permissions enabled.");
        } else {
            ui::info("No existing permissions found in Claude Code settings.");
        }
        println!();
        let posture = crate::dialog::select::<Posture>("Pick a starting posture")?;
        generate_starlark_from_posture(*posture)
    } else {
        // Import permissions
        print_import_summary(&analysis);
        generate_starlark_from_analysis(&analysis)
    };

    // Step 3: Write policy file
    let policy_path = write_policy(&policy_content)?;
    ui::success(&format!("Policy written to {}", policy_path.display()));

    // Step 4: Install agent plugin
    super::init::install_agent_plugin(agent)?;

    // Step 5: Install statusline for Claude
    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            tracing::warn!(error = %e, "Could not install status line");
        }
    }

    // Step 6: Print summary
    println!();
    println!(
        "  Run {} to tweak your policy.",
        style::bold("clash policy edit")
    );
    println!(
        "  Run {} to verify the setup.",
        style::bold(&format!("clash doctor --agent {agent}"))
    );

    Ok(())
}

/// Print a summary of what was found in the settings.
fn print_import_summary(analysis: &ImportAnalysis) {
    println!();
    ui::info("Importing permissions from Claude Code settings:");

    if !analysis.bash_allows.is_empty() {
        let bins: Vec<&str> = analysis
            .bash_allows
            .iter()
            .map(|segs| segs[0].as_str())
            .collect();
        ui::success(&format!("  Bash commands: {}", bins.join(", ")));
    }

    let all_tools: Vec<&str> = analysis
        .tool_allows
        .iter()
        .chain(analysis.tool_asks.iter())
        .map(|s| s.as_str())
        .collect();
    if !all_tools.is_empty() {
        ui::success(&format!("  Tools: {}", all_tools.join(", ")));
    }

    if !analysis.file_denies.is_empty() {
        let denied: Vec<String> = analysis
            .file_denies
            .iter()
            .map(|(tool, path)| format!("{tool}({path})"))
            .collect();
        ui::success(&format!("  Denied: {}", denied.join(", ")));
    }

    if !analysis.skipped.is_empty() {
        ui::warn(&format!(
            "  Skipped {} unsupported patterns: {}",
            analysis.skipped.len(),
            analysis.skipped.join(", ")
        ));
    }

    println!();
}

/// Write a policy string to the user's policy file.
fn write_policy(content: &str) -> Result<std::path::PathBuf> {
    let policy_path = ClashSettings::policy_file()
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".clash")
                .join("policy.star")
        })
        .with_extension("star");

    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    std::fs::write(&policy_path, content)
        .with_context(|| format!("writing policy to {}", policy_path.display()))?;

    Ok(policy_path)
}
```

- [ ] **Step 2: Add necessary imports at the top of the file**

Make sure the top of `import_settings.rs` has:

```rust
//! Import permissions from a coding agent's settings and generate a Clash policy.

use anyhow::{Context, Result};

use crate::agents::AgentKind;
use crate::settings::ClashSettings;
use crate::style;
use crate::ui;

use claude_settings::permission::{Permission, PermissionPattern};
use clash_starlark::codegen::ast::{Expr, Stmt};
use clash_starlark::codegen::builder::*;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo build -p clash 2>&1 | tail -10`
Expected: Compiles. Fix any import issues.

- [ ] **Step 4: Run all import_settings tests**

Run: `cargo test -p clash --lib cmd::import_settings 2>&1 | tail -30`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "feat: wire up full import settings flow with summary and file writing"
```

---

### Task 10: Add clester tests

**Files:**
- Create: `clester/tests/scripts/star_sandbox_presets.yaml`
- Create: `clester/tests/scripts/init_no_import.yaml`

- [ ] **Step 1: Create sandbox presets clester test**

Create `clester/tests/scripts/star_sandbox_presets.yaml`:

```yaml
meta:
  name: starlark policy — renamed sandbox presets
  description: Test that readonly, project, workspace, unrestricted sandbox presets work

clash:
  policy_star: |
    load("@clash//std.star", "match", "policy", "settings", "allow", "deny", "ask")
    load("@clash//sandboxes.star", "readonly", "project", "workspace", "unrestricted")
    settings(default=ask(), default_sandbox=project)
    policy("test", rules=[
        match({"Bash": {"git": {glob("**"): allow(sandbox=project)}}}),
        match({("Read", "Glob", "Grep"): allow()}),
    ])

steps:
  - name: git status allowed with project sandbox
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow

  - name: read tool allowed
    hook: pre-tool-use
    tool_name: Read
    tool_input:
      file_path: /tmp/test.txt
    expect:
      decision: allow

  - name: curl asks by default
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: "curl https://example.com"
    expect:
      decision: ask
```

- [ ] **Step 2: Create init --no-import clester test**

Create `clester/tests/scripts/init_no_import.yaml`:

```yaml
meta:
  name: clash init --no-import
  description: Test that --no-import installs hooks without generating a policy

steps:
  - name: init with --no-import succeeds
    command: init --no-import --agent claude
    expect:
      exit_code: 0
      stdout_contains: "clash policy edit"
```

- [ ] **Step 3: Run clester tests**

Run: `just clester 2>&1 | tail -30`
Expected: New tests pass. If the `command:` step type isn't supported for `init`, adjust the test format based on what clester supports (check existing tests for the pattern).

- [ ] **Step 4: Commit**

```bash
git add clester/tests/scripts/star_sandbox_presets.yaml clester/tests/scripts/init_no_import.yaml
git commit -m "test: add clester tests for sandbox presets and --no-import"
```

---

### Task 11: Run full CI and fix any issues

**Files:**
- Any files that need fixing

- [ ] **Step 1: Run full check**

Run: `just check 2>&1 | tail -50`
Expected: All tests pass, no lint warnings

- [ ] **Step 2: Run clester**

Run: `just clester 2>&1 | tail -50`
Expected: All e2e tests pass

- [ ] **Step 3: Fix any failures**

Address any compilation errors, test failures, or lint warnings discovered.

- [ ] **Step 4: Final commit if needed**

```bash
git add -A
git commit -m "fix: address CI issues from import onboarding feature"
```

---

### Task 12: Update documentation

**Files:**
- Modify: `README.md` (if it references `clash init` flow or sandbox names)
- Modify: `docs/policy-guide.md` (if it exists and references sandbox names)
- Modify: relevant site pages

- [ ] **Step 1: Update README**

Search for references to old sandbox names or the old init flow and update them.

Run: `grep -n 'safe_yolo\|"plan"\|"edit"\|"yolo"\|clash init' README.md`

Update any matches to reflect:
- `clash init` now imports by default
- `clash init --no-import` for hooks-only setup
- New sandbox names: `readonly`, `project`, `workspace`, `unrestricted`

- [ ] **Step 2: Update policy guide**

Run: `grep -rn 'safe_yolo\|"plan"\|"edit"\|"yolo"' docs/ --include='*.md' | grep -iv 'superpowers'`

Update any sandbox name references.

- [ ] **Step 3: Update site pages**

Run: `grep -rn 'safe_yolo\|sandbox.*plan\|sandbox.*edit\|sandbox.*yolo' site/pages/ --include='*.md'`

Update any matches. Note: versioned pages under `site/versions/` should NOT be updated (they document historical behavior).

- [ ] **Step 4: Commit**

```bash
git add README.md docs/ site/pages/
git commit -m "docs: update documentation for import onboarding and renamed sandbox presets"
```
