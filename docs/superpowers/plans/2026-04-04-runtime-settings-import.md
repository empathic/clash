# Runtime Settings Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `from_claude_settings()` native Starlark function that dynamically imports Claude Code permission settings as Clash rules at policy evaluation time.

**Architecture:** Register a native Rust function in `clash_starlark`'s globals that wraps the `claude_settings` crate to parse permission entries and convert them to match tree nodes. Extract shared classification logic from the existing one-time import into a reusable module. Add glob pattern support.

**Tech Stack:** Rust, Starlark (native function via `#[starlark_module]`), `claude_settings` crate

---

## File Structure

| File | Responsibility |
|------|---------------|
| `clash/src/policy/settings_compat.rs` | **New** — shared permission classification and conversion: parse permission strings, convert to codegen Expr nodes |
| `clash/src/policy/mod.rs` | Add `pub mod settings_compat;` |
| `clash_starlark/src/globals.rs` | Register `_from_claude_settings()` native function |
| `clash_starlark/stdlib/claude_compat.star` | **New** — stdlib module that wraps the native function |
| `clash_starlark/src/stdlib.rs` | Register `claude_compat.star` in the embedded stdlib |
| `clash_starlark/Cargo.toml` | Add `claude_settings` dependency |
| `clash/src/cmd/import_settings.rs` | Refactor to use shared `settings_compat` module |

---

### Task 1: Extract shared permission classification logic

**Files:**
- Create: `clash/src/policy/settings_compat.rs`
- Modify: `clash/src/policy/mod.rs`
- Test: inline `#[cfg(test)]` module

- [ ] **Step 1: Write tests for permission classification**

Create `clash/src/policy/settings_compat.rs` with tests covering all permission patterns. The module needs to classify permission strings and convert them to match tree node JSON.

```rust
use serde_json::Value as JsonValue;

/// Classification of a Claude Code permission entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ClassifiedPermission {
    /// Tool-only permission (e.g., "Read", "Edit")
    Tool { tool: String, effect: String },
    /// Bash prefix command (e.g., "Bash(git:*)" → bin="git")
    BashPrefix { segments: Vec<String>, effect: String },
    /// File path exact match (e.g., "Read(.env)")
    FileExact { tool: String, path: String, effect: String },
    /// File path glob match (e.g., "Read(src/**/*.ts)")
    FileGlob { tool: String, pattern: String, effect: String },
    /// MCP tool — skip
    Mcp { name: String },
}

/// Classify a single permission string with its effect into a structured type.
pub fn classify(tool: &str, pattern: Option<&str>, effect: &str) -> ClassifiedPermission {
    todo!()
}

/// Convert a list of classified permissions into match tree node JSON values.
/// These can be used directly in a policy's rules list.
pub fn to_match_tree_nodes(permissions: &[ClassifiedPermission]) -> Vec<JsonValue> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tool_only() {
        let result = classify("Read", None, "allow");
        assert_eq!(result, ClassifiedPermission::Tool {
            tool: "Read".into(),
            effect: "allow".into(),
        });
    }

    #[test]
    fn classify_bash_prefix() {
        let result = classify("Bash", Some("git"), "allow");
        assert_eq!(result, ClassifiedPermission::BashPrefix {
            segments: vec!["git".into()],
            effect: "allow".into(),
        });
    }

    #[test]
    fn classify_bash_multi_segment() {
        let result = classify("Bash", Some("cargo check"), "allow");
        assert_eq!(result, ClassifiedPermission::BashPrefix {
            segments: vec!["cargo".into(), "check".into()],
            effect: "allow".into(),
        });
    }

    #[test]
    fn classify_file_exact() {
        let result = classify("Read", Some(".env"), "deny");
        assert_eq!(result, ClassifiedPermission::FileExact {
            tool: "Read".into(),
            path: ".env".into(),
            effect: "deny".into(),
        });
    }

    #[test]
    fn classify_file_glob() {
        let result = classify("Read", Some("src/**/*.ts"), "allow");
        assert_eq!(result, ClassifiedPermission::FileGlob {
            tool: "Read".into(),
            pattern: "src/**/*.ts".into(),
            effect: "allow".into(),
        });
    }

    #[test]
    fn classify_mcp_tool() {
        let result = classify("mcp__server__tool", None, "allow");
        assert_eq!(result, ClassifiedPermission::Mcp {
            name: "mcp__server__tool".into(),
        });
    }

    #[test]
    fn to_nodes_produces_valid_json() {
        let perms = vec![
            ClassifiedPermission::Tool { tool: "Read".into(), effect: "allow".into() },
            ClassifiedPermission::BashPrefix { segments: vec!["git".into()], effect: "allow".into() },
        ];
        let nodes = to_match_tree_nodes(&perms);
        assert_eq!(nodes.len(), 2);
        // Each node should be a valid match tree condition
        for node in &nodes {
            assert!(node.is_object());
        }
    }

    #[test]
    fn glob_pattern_converted_to_node() {
        let perms = vec![
            ClassifiedPermission::FileGlob {
                tool: "Read".into(),
                pattern: "src/**/*.ts".into(),
                effect: "allow".into(),
            },
        ];
        let nodes = to_match_tree_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json_str = serde_json::to_string(&nodes[0]).unwrap();
        assert!(json_str.contains("src/**/*.ts"));
    }

    #[test]
    fn mcp_tools_are_filtered_out() {
        let perms = vec![
            ClassifiedPermission::Mcp { name: "mcp__server__tool".into() },
            ClassifiedPermission::Tool { tool: "Read".into(), effect: "allow".into() },
        ];
        let nodes = to_match_tree_nodes(&perms);
        assert_eq!(nodes.len(), 1); // MCP was filtered
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib policy::settings_compat`
Expected: FAIL with `not yet implemented`

- [ ] **Step 3: Implement classify()**

```rust
pub fn classify(tool: &str, pattern: Option<&str>, effect: &str) -> ClassifiedPermission {
    // MCP tools
    if tool.starts_with("mcp__") {
        return ClassifiedPermission::Mcp { name: tool.into() };
    }

    match pattern {
        None => ClassifiedPermission::Tool {
            tool: tool.into(),
            effect: effect.into(),
        },
        Some(p) if tool == "Bash" => {
            let segments: Vec<String> = p.split_whitespace().map(String::from).collect();
            ClassifiedPermission::BashPrefix {
                segments,
                effect: effect.into(),
            }
        }
        Some(p) if is_glob_pattern(p) => ClassifiedPermission::FileGlob {
            tool: tool.into(),
            pattern: p.into(),
            effect: effect.into(),
        },
        Some(p) => ClassifiedPermission::FileExact {
            tool: tool.into(),
            path: p.into(),
            effect: effect.into(),
        },
    }
}

fn is_glob_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}
```

- [ ] **Step 4: Implement to_match_tree_nodes()**

This function converts classified permissions into the JSON IR format that Clash's match tree compiler expects. Look at how `build_rule_node()` in `cmd/policy.rs` and `Node` serialization work to produce the correct JSON structure.

```rust
pub fn to_match_tree_nodes(permissions: &[ClassifiedPermission]) -> Vec<JsonValue> {
    permissions
        .iter()
        .filter_map(|p| match p {
            ClassifiedPermission::Mcp { .. } => None,
            ClassifiedPermission::Tool { tool, effect } => {
                Some(tool_node(tool, effect))
            }
            ClassifiedPermission::BashPrefix { segments, effect } => {
                Some(bash_prefix_node(segments, effect))
            }
            ClassifiedPermission::FileExact { tool, path, effect } => {
                Some(file_exact_node(tool, path, effect))
            }
            ClassifiedPermission::FileGlob { tool, pattern, effect } => {
                Some(file_glob_node(tool, pattern, effect))
            }
        })
        .collect()
}

fn effect_json(effect: &str) -> JsonValue {
    serde_json::json!({
        "decision": { "effect": effect }
    })
}

fn tool_node(tool: &str, effect: &str) -> JsonValue {
    serde_json::json!({
        "condition": {
            "observe": "tool_name",
            "pattern": { "literal": tool },
            "children": [effect_json(effect)]
        }
    })
}

fn bash_prefix_node(segments: &[String], effect: &str) -> JsonValue {
    // Build nested conditions: Bash → segment[0] → segment[1] → ... → effect
    let mut current = effect_json(effect);
    for segment in segments.iter().rev() {
        current = serde_json::json!({
            "condition": {
                "observe": "positional_arg",
                "pattern": { "prefix": segment },
                "children": [current]
            }
        });
    }
    serde_json::json!({
        "condition": {
            "observe": "tool_name",
            "pattern": { "literal": "Bash" },
            "children": [current]
        }
    })
}

fn file_exact_node(tool: &str, path: &str, effect: &str) -> JsonValue {
    serde_json::json!({
        "condition": {
            "observe": "tool_name",
            "pattern": { "literal": tool },
            "children": [{
                "condition": {
                    "observe": "file_path",
                    "pattern": { "literal": path },
                    "children": [effect_json(effect)]
                }
            }]
        }
    })
}

fn file_glob_node(tool: &str, pattern: &str, effect: &str) -> JsonValue {
    serde_json::json!({
        "condition": {
            "observe": "tool_name",
            "pattern": { "literal": tool },
            "children": [{
                "condition": {
                    "observe": "file_path",
                    "pattern": { "glob": pattern },
                    "children": [effect_json(effect)]
                }
            }]
        }
    })
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clash --lib policy::settings_compat`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add clash/src/policy/settings_compat.rs clash/src/policy/mod.rs
git commit -m "feat: shared permission classification for settings import"
```

---

### Task 2: Add claude_settings dependency to clash_starlark

**Files:**
- Modify: `clash_starlark/Cargo.toml`

- [ ] **Step 1: Add the dependency**

In `clash_starlark/Cargo.toml`, add under `[dependencies]`:

```toml
claude_settings = { path = "../claude_settings" }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p clash_starlark`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add clash_starlark/Cargo.toml
git commit -m "build: add claude_settings dependency to clash_starlark"
```

---

### Task 3: Create the claude_compat.star stdlib module

**Files:**
- Create: `clash_starlark/stdlib/claude_compat.star`
- Modify: `clash_starlark/src/stdlib.rs` (or wherever stdlib modules are registered)

- [ ] **Step 1: Find how stdlib modules are registered**

Look at how existing stdlib modules (like `sandboxes.star`, `std.star`) are registered in the `stdlib` module. The `include_dir` crate is used to embed files. Check `clash_starlark/src/stdlib.rs` or `clash_starlark/src/lib.rs` for the `stdlib::get()` function.

- [ ] **Step 2: Create the stdlib module file**

Create `clash_starlark/stdlib/claude_compat.star`:

```starlark
# claude_compat.star — Import rules from Claude Code settings at runtime.
#
# Usage:
#   load("@clash//claude_compat.star", "from_claude_settings")
#   policy("main", rules = [...] + from_claude_settings())
#
# Parameters:
#   user (bool, default True)    — include ~/.claude/settings.json rules
#   project (bool, default True) — include project-level settings rules
#   session (bool, default False) — include session-level settings rules
#
# Returns a list of match tree rules composable with + in the policy() rules list.
# MCP tool permissions are skipped. Glob patterns are converted to Clash glob() matchers.

from_claude_settings = _from_claude_settings
```

The native function `_from_claude_settings` will be pre-injected by the globals, and this module just re-exports it with a clean name.

- [ ] **Step 3: Verify the stdlib module is picked up**

Run: `cargo check -p clash_starlark`
Expected: PASS (the file is embedded via `include_dir!`, which picks up all files in the stdlib directory automatically)

- [ ] **Step 4: Commit**

```bash
git add clash_starlark/stdlib/claude_compat.star
git commit -m "feat: add claude_compat.star stdlib module"
```

---

### Task 4: Register the native from_claude_settings function

**Files:**
- Modify: `clash_starlark/src/globals.rs`
- Test: inline test or in `clash_starlark/tests/`

- [ ] **Step 1: Write a test for from_claude_settings**

Write a test that evaluates a policy using `from_claude_settings()`. Since it reads actual Claude Code settings, the test should work even when settings are empty (returning an empty list).

```rust
#[test]
fn from_claude_settings_returns_list() {
    let source = r#"
load("@clash//claude_compat.star", "from_claude_settings")

policy("test",
    default = ask(),
    rules = from_claude_settings(user=True, project=False, session=False),
)
"#;
    // This should not error even if no Claude Code settings exist
    let result = crate::evaluate(source, "test.star", std::path::Path::new("."));
    assert!(result.is_ok(), "from_claude_settings should succeed even with no settings: {result:?}");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p clash_starlark from_claude_settings`
Expected: FAIL — the native function doesn't exist yet, so `_from_claude_settings` is undefined

- [ ] **Step 3: Implement the native function**

In `clash_starlark/src/globals.rs`, add inside the `#[starlark_module]` block:

```rust
    /// Import Claude Code permission settings as match tree rules.
    /// Returns a list of MatchTreeNode values that can be concatenated into policy rules.
    fn _from_claude_settings<'v>(
        #[starlark(require = named, default = true)] user: bool,
        #[starlark(require = named, default = true)] project: bool,
        #[starlark(require = named, default = false)] session: bool,
        heap: &'v Heap,
    ) -> anyhow::Result<Vec<MatchTreeNode>> {
        use claude_settings::ClaudeSettings;

        let settings = ClaudeSettings::new();
        let mut all_permissions = Vec::new();

        // Collect permissions from requested layers
        if user {
            if let Ok(user_settings) = settings.user() {
                collect_permissions(&user_settings, &mut all_permissions);
            }
        }
        if project {
            if let Ok(project_settings) = settings.project() {
                collect_permissions(&project_settings, &mut all_permissions);
            }
        }
        if session {
            if let Ok(session_settings) = settings.session() {
                collect_permissions(&session_settings, &mut all_permissions);
            }
        }

        // Convert to match tree nodes
        let nodes: Vec<MatchTreeNode> = all_permissions
            .into_iter()
            .filter_map(|json_value| {
                Some(MatchTreeNode { json: json_value })
            })
            .collect();

        Ok(nodes)
    }
```

Add a helper function outside the starlark_module block:

```rust
/// Collect permissions from a Claude Code settings layer into JSON match tree nodes.
fn collect_permissions(settings: &claude_settings::EffectiveSettings, out: &mut Vec<serde_json::Value>) {
    for (effect_name, permissions) in [
        ("allow", &settings.permissions.allow),
        ("deny", &settings.permissions.deny),
        ("ask", &settings.permissions.ask),
    ] {
        for perm in permissions {
            let tool = perm.tool();
            let pattern = perm.pattern_str();
            // Use the shared classification logic
            let classified = clash::policy::settings_compat::classify(tool, pattern, effect_name);
            let nodes = clash::policy::settings_compat::to_match_tree_nodes(&[classified]);
            out.extend(nodes);
        }
    }
}
```

**Note:** Since `clash_starlark` cannot depend on the `clash` binary crate, the `settings_compat` module needs to live in `claude_settings` or in `clash_starlark` itself. The classify/convert logic should be placed in `clash_starlark/src/settings_compat.rs` instead of `clash/src/policy/settings_compat.rs`. Update the file structure accordingly.

- [ ] **Step 4: Move settings_compat to clash_starlark**

Since `clash_starlark` is the crate that needs this logic at eval time, create the module there:
- Create `clash_starlark/src/settings_compat.rs` with the classify/convert logic from Task 1
- Update `clash_starlark/src/lib.rs` to add `pub mod settings_compat;`
- Update globals.rs to use `crate::settings_compat::{classify, to_match_tree_nodes}`
- The `clash` binary crate can then also use `clash_starlark::settings_compat` for the one-time import refactor

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p clash_starlark from_claude_settings`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add clash_starlark/src/globals.rs clash_starlark/src/settings_compat.rs clash_starlark/src/lib.rs
git commit -m "feat: native from_claude_settings() starlark function (#427)"
```

---

### Task 5: Refactor existing one-time import to use shared logic

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Update import_settings to use shared classify()**

Replace the local `classify_permission()` function in `import_settings.rs` with calls to `clash_starlark::settings_compat::classify()`. This ensures both code paths use the same classification logic.

The bulk of `import_settings.rs` handles the interactive flow (posture selection, ecosystem detection, file writing), which stays. Only the permission classification and node building should delegate to the shared module.

- [ ] **Step 2: Remove glob pattern skipping**

In `import_settings.rs`, find where `PermissionPattern::Glob(_)` pushes to `analysis.skipped` and instead route it through the shared classify logic which now handles globs.

- [ ] **Step 3: Run existing import_settings tests**

Run: `cargo test -p clash import_settings`
Expected: PASS — behavior should be the same except globs are now supported

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "refactor: import_settings uses shared classification, adds glob support"
```

---

### Task 6: End-to-end verification

- [ ] **Step 1: Build the full workspace**

Run: `cargo build --workspace`
Expected: PASS

- [ ] **Step 2: Run all tests**

Run: `cargo test --workspace`
Expected: All tests PASS

- [ ] **Step 3: Write an integration test**

Add a test that creates a `.star` file using `from_claude_settings()` and evaluates it:

```rust
#[test]
fn from_claude_settings_integrates_with_policy() {
    let source = r#"
load("@clash//claude_compat.star", "from_claude_settings")

policy("test",
    default = deny(),
    rules = [
        when({"Bash": {"git": allow()}}),
    ] + from_claude_settings(user=True, project=False),
)
"#;
    let output = clash_starlark::evaluate(source, "test.star", std::path::Path::new(".")).unwrap();
    // Should produce valid JSON with at least the explicit git rule
    let doc: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    assert!(doc["policies"].is_array() || doc["policies"].is_object());
}
```

- [ ] **Step 4: Run the integration test**

Run: `cargo test -p clash_starlark from_claude_settings_integrates`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/tests/
git commit -m "test: integration test for from_claude_settings"
```
