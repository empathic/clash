# Harness Default Permissions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a lowest-priority policy layer that automatically allows agents to access their own infrastructure directories (e.g., Claude gets r/w to `~/.claude/`), with env var and Starlark `settings()` opt-out.

**Architecture:** Harness rules are `Vec<Node>` generated per-`AgentKind`, appended to the compiled policy tree after all user-defined levels merge. A `harness_defaults` boolean (from env var or Starlark setting) controls whether they're injected. Status output filters them unless `--verbose`.

**Tech Stack:** Rust, Starlark (clash_starlark crate), serde_json

---

### Task 1: Add `harness_defaults` to Starlark `settings()` and `SettingsValue`

**Files:**
- Modify: `clash_starlark/src/eval_context.rs:14-18` (SettingsValue struct)
- Modify: `clash_starlark/src/globals.rs:132-178` (_register_settings function)

- [ ] **Step 1: Write test for `harness_defaults` in SettingsValue**

Add to existing tests in `clash_starlark/`. We need a test that evaluates a Starlark policy with `settings(default=allow(), harness_defaults=False)` and confirms the resulting JSON document contains `"harness_defaults": false`.

```rust
#[test]
fn settings_harness_defaults_false() {
    let source = r#"
load("@clash//std.star", "allow", "policy", "settings")
settings(default=allow(), harness_defaults=False)
policy("test", rules=[])
"#;
    let json = crate::evaluate(source).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(doc["harness_defaults"], serde_json::json!(false));
}

#[test]
fn settings_harness_defaults_default_is_true() {
    let source = r#"
load("@clash//std.star", "allow", "policy", "settings")
settings(default=allow())
policy("test", rules=[])
"#;
    let json = crate::evaluate(source).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    // When not specified, harness_defaults should not appear (defaults to true at runtime)
    assert!(doc.get("harness_defaults").is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash-starlark settings_harness_defaults`
Expected: FAIL — `harness_defaults` param doesn't exist on `settings()` yet.

- [ ] **Step 3: Add `harness_defaults` field to `SettingsValue`**

In `clash_starlark/src/eval_context.rs`, add the field:

```rust
#[derive(Debug, Clone)]
pub struct SettingsValue {
    pub default_effect: String,
    pub default_sandbox: Option<String>,
    pub on_sandbox_violation: Option<String>,
    pub harness_defaults: Option<bool>,
}
```

- [ ] **Step 4: Add `harness_defaults` parameter to `_register_settings`**

In `clash_starlark/src/globals.rs`, add the named parameter:

```rust
fn _register_settings<'v>(
    #[starlark(require = named)] default: &str,
    #[starlark(require = named, default = starlark::values::none::NoneType)]
    default_sandbox: Value<'v>,
    #[starlark(require = named, default = starlark::values::none::NoneType)]
    on_sandbox_violation: Value<'v>,
    #[starlark(require = named, default = starlark::values::none::NoneType)]
    harness_defaults: Value<'v>,
    eval: &mut Evaluator<'v, '_, '_>,
) -> anyhow::Result<NoneType>
```

Parse `harness_defaults` as an optional bool:

```rust
let hd = if harness_defaults.is_none() {
    None
} else {
    Some(harness_defaults.unpack_bool().ok_or_else(|| {
        anyhow::anyhow!("harness_defaults must be True or False")
    })?)
};
```

Pass it into `SettingsValue { ..., harness_defaults: hd }`.

- [ ] **Step 5: Emit `harness_defaults` in `assemble_document`**

In `clash_starlark/src/eval_context.rs`, in `assemble_document()`, after the existing `on_sandbox_violation` block:

```rust
if let Some(hd) = settings.as_ref().and_then(|s| s.harness_defaults) {
    if !hd {
        doc.as_object_mut()
            .unwrap()
            .insert("harness_defaults".to_string(), serde_json::json!(false));
    }
}
```

Only emit when `false` — `true` is the default, no need to serialize it.

- [ ] **Step 6: Run tests**

Run: `cargo test -p clash-starlark settings_harness_defaults`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash_starlark/src/eval_context.rs clash_starlark/src/globals.rs
git commit -m "feat(starlark): add harness_defaults setting to settings() DSL"
```

---

### Task 2: Add `harness_defaults` field to `CompiledPolicy` and env var check

**Files:**
- Modify: `clash/src/policy/match_tree.rs:298-313` (CompiledPolicy struct)
- Modify: `clash/src/settings/env.rs` (new env var constant + check function)

- [ ] **Step 1: Write tests**

In `clash/src/settings/env.rs`, add tests for the new env var:

```rust
#[test]
fn harness_defaults_disabled_truthy() {
    assert!(is_truthy_disable_value("1"));
}
```

(The existing `is_truthy_disable_value` tests already cover the logic — this is just a sanity check that the constant is wired up.)

In `clash/src/policy/match_tree.rs` tests (or a new test), verify that `harness_defaults` deserializes correctly:

```rust
#[test]
fn compiled_policy_harness_defaults_field() {
    let json = r#"{
        "schema_version": 5,
        "default_effect": "ask",
        "sandboxes": {},
        "tree": [],
        "harness_defaults": false
    }"#;
    let policy: CompiledPolicy = serde_json::from_str(json).unwrap();
    assert_eq!(policy.harness_defaults, Some(false));
}

#[test]
fn compiled_policy_harness_defaults_absent() {
    let json = r#"{
        "schema_version": 5,
        "default_effect": "ask",
        "sandboxes": {},
        "tree": []
    }"#;
    let policy: CompiledPolicy = serde_json::from_str(json).unwrap();
    assert_eq!(policy.harness_defaults, None);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash compiled_policy_harness_defaults`
Expected: FAIL — field doesn't exist yet.

- [ ] **Step 3: Add `harness_defaults` to `CompiledPolicy`**

In `clash/src/policy/match_tree.rs`:

```rust
pub struct CompiledPolicy {
    pub sandboxes: HashMap<String, SandboxPolicy>,
    pub tree: Vec<Node>,
    #[serde(default = "default_effect")]
    pub default_effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sandbox: Option<String>,
    #[serde(default, skip_serializing_if = "ViolationAction::is_default")]
    pub on_sandbox_violation: ViolationAction,
    /// When explicitly set to `false`, harness default rules are not injected.
    /// `None` means enabled (default behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_defaults: Option<bool>,
}
```

- [ ] **Step 4: Add env var constant and helper**

In `clash/src/settings/env.rs`:

```rust
/// Environment variable to disable harness default permissions.
///
/// When set to a truthy value, harness defaults (agent-specific filesystem
/// rules like ~/.claude/ access) are not injected into the policy tree.
pub const CLASH_NO_HARNESS_DEFAULTS_ENV: &str = "CLASH_NO_HARNESS_DEFAULTS";

/// Check whether harness defaults are disabled via environment variable.
pub fn is_harness_defaults_disabled() -> bool {
    std::env::var(CLASH_NO_HARNESS_DEFAULTS_ENV)
        .ok()
        .is_some_and(|v| is_truthy_disable_value(&v))
}
```

- [ ] **Step 5: Re-export from `settings/mod.rs`**

```rust
pub use env::{
    CLASH_DISABLE_ENV, CLASH_NO_HARNESS_DEFAULTS_ENV, CLASH_PASSTHROUGH_ENV,
    is_disabled, is_harness_defaults_disabled, is_passthrough,
};
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p clash compiled_policy_harness_defaults && cargo test -p clash is_truthy`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash/src/policy/match_tree.rs clash/src/settings/env.rs clash/src/settings/mod.rs
git commit -m "feat(policy): add harness_defaults field to CompiledPolicy and env var"
```

---

### Task 3: Define per-agent harness rules and generate Node trees

**Files:**
- Create: `clash/src/harness.rs`

- [ ] **Step 1: Write tests for harness node generation**

```rust
#[cfg(test)]
mod test {
    use super::*;
    use crate::agents::AgentKind;
    use crate::policy::match_tree::{Node, Observable, Pattern, Value};

    #[test]
    fn claude_harness_nodes_not_empty() {
        let nodes = harness_nodes(AgentKind::Claude);
        assert!(!nodes.is_empty(), "Claude should have harness rules");
    }

    #[test]
    fn claude_harness_nodes_stamped_as_harness() {
        let nodes = harness_nodes(AgentKind::Claude);
        for node in &nodes {
            if let Node::Condition { source, .. } = node {
                assert_eq!(source.as_deref(), Some("harness"));
            }
        }
    }

    #[test]
    fn unknown_agent_returns_empty() {
        // Agents without defined harness paths return no nodes
        let nodes = harness_nodes(AgentKind::Copilot);
        assert!(nodes.is_empty());
    }

    #[test]
    fn harness_enabled_checks_both_sources() {
        // With no env var and no policy setting, harness is enabled
        assert!(is_harness_enabled(None));
        // Explicit false in policy disables it
        assert!(!is_harness_enabled(Some(false)));
        // Explicit true in policy keeps it enabled
        assert!(is_harness_enabled(Some(true)));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash harness`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `harness.rs`**

```rust
//! Agent harness default permissions.
//!
//! Generates lowest-priority policy rules that allow agents to access their
//! own infrastructure directories (e.g., Claude → ~/.claude/). These rules
//! are appended after all user-defined policy levels so user rules always
//! take precedence.

use crate::agents::AgentKind;
use crate::policy::match_tree::{Decision, Node, Observable, Pattern, Value};
use crate::settings::env::is_harness_defaults_disabled;

/// Check whether harness defaults should be injected.
///
/// Disabled if:
/// 1. `CLASH_NO_HARNESS_DEFAULTS` env var is set (checked first)
/// 2. `harness_defaults` is explicitly `false` in the compiled policy settings
///
/// `policy_setting` is the `CompiledPolicy.harness_defaults` field.
pub fn is_harness_enabled(policy_setting: Option<bool>) -> bool {
    if is_harness_defaults_disabled() {
        return false;
    }
    policy_setting.unwrap_or(true)
}

/// Generate harness default rules for the given agent.
///
/// Returns an empty vec for agents without defined harness paths.
/// All returned nodes are stamped with `source: "harness"`.
pub fn harness_nodes(agent: AgentKind) -> Vec<Node> {
    let paths = match agent {
        AgentKind::Claude => claude_harness_paths(),
        // Other agents can be added here as needed.
        _ => return Vec::new(),
    };

    let mut nodes = Vec::new();
    for (path, ops) in paths {
        for op in ops {
            let mut node = Node::Condition {
                observe: Observable::FsOp,
                pattern: Pattern::Literal(Value::Literal(op.to_string())),
                children: vec![Node::Condition {
                    observe: Observable::FsPath,
                    pattern: Pattern::Prefix(path.clone()),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            };
            node.stamp_source("harness");
            nodes.push(node);
        }
    }
    nodes
}

/// Claude Code harness paths: (path_value, allowed_ops).
fn claude_harness_paths() -> Vec<(Value, Vec<&'static str>)> {
    vec![
        // ~/.claude/ — memories, settings, plugin cache, skills
        (
            Value::Path(vec![Value::Env("HOME".to_string()), Value::Literal(".claude".to_string())]),
            vec!["read", "write"],
        ),
        // <project>/.claude/ — project config (read-only)
        (
            Value::Path(vec![Value::Env("PWD".to_string()), Value::Literal(".claude".to_string())]),
            vec!["read"],
        ),
        // <transcript_dir>/ — session transcripts, task output
        (
            Value::Env("TRANSCRIPT_DIR".to_string()),
            vec!["read", "write"],
        ),
    ]
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn claude_harness_nodes_not_empty() {
        let nodes = harness_nodes(AgentKind::Claude);
        assert!(!nodes.is_empty(), "Claude should have harness rules");
    }

    #[test]
    fn claude_harness_nodes_stamped_as_harness() {
        let nodes = harness_nodes(AgentKind::Claude);
        for node in &nodes {
            if let Node::Condition { source, .. } = node {
                assert_eq!(source.as_deref(), Some("harness"));
            }
        }
    }

    #[test]
    fn unknown_agent_returns_empty() {
        let nodes = harness_nodes(AgentKind::Copilot);
        assert!(nodes.is_empty());
    }

    #[test]
    fn harness_enabled_checks_policy_setting() {
        // Cannot test env var in unit tests due to process-wide mutation,
        // but we can test the policy_setting path.
        assert!(is_harness_enabled(None));
        assert!(!is_harness_enabled(Some(false)));
        assert!(is_harness_enabled(Some(true)));
    }
}
```

- [ ] **Step 4: Register the module in `clash/src/lib.rs` (or `main.rs`)**

Add `pub mod harness;` to the crate root.

- [ ] **Step 5: Run tests**

Run: `cargo test -p clash harness`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add clash/src/harness.rs clash/src/lib.rs
git commit -m "feat(harness): define per-agent harness rules with Claude paths"
```

---

### Task 4: Inject harness rules during policy loading

**Files:**
- Modify: `clash/src/settings/loader.rs:334-395` (load_or_create_with_session)
- Modify: `clash/src/settings/mod.rs:66-85` (ClashSettings struct)

- [ ] **Step 1: Write test for harness injection**

In `clash/src/settings/loader.rs` tests:

```rust
#[test]
fn harness_rules_appended_to_compiled_policy() {
    let star_policy = r#"
load("@clash//std.star", "allow", "policy", "settings")
settings(default = allow())
policy("default", rules = [])
"#;
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.star");
    std::fs::write(&policy_path, star_policy).unwrap();

    let mut settings = ClashSettings::default();
    settings.load_policy_from_path(&policy_path);
    // Inject harness rules for Claude
    settings.inject_harness_rules(Some(crate::agents::AgentKind::Claude));

    let tree = settings.decision_tree().unwrap();
    // Harness rules should have been appended
    assert!(
        !tree.tree.is_empty(),
        "policy tree should contain harness rules"
    );
}

#[test]
fn harness_rules_disabled_by_policy_setting() {
    let star_policy = r#"
load("@clash//std.star", "allow", "policy", "settings")
settings(default = allow(), harness_defaults = False)
policy("default", rules = [])
"#;
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.star");
    std::fs::write(&policy_path, star_policy).unwrap();

    let mut settings = ClashSettings::default();
    settings.load_policy_from_path(&policy_path);
    settings.inject_harness_rules(Some(crate::agents::AgentKind::Claude));

    let tree = settings.decision_tree().unwrap();
    // With harness_defaults=False, no harness rules should be present
    // The tree should be empty since the user policy had no rules
    assert!(
        tree.tree.is_empty(),
        "harness rules should not be injected when disabled"
    );
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash harness_rules_appended`
Expected: FAIL — `inject_harness_rules` doesn't exist.

- [ ] **Step 3: Add `inject_harness_rules` method to `ClashSettings`**

In `clash/src/settings/loader.rs`:

```rust
/// Inject agent-specific harness default rules into the compiled policy.
///
/// Harness rules are appended at lowest priority (after all user-defined rules).
/// They are skipped if:
/// - No agent is provided
/// - No compiled policy exists
/// - `CLASH_NO_HARNESS_DEFAULTS` env var is set
/// - `settings(harness_defaults=False)` is in the policy
pub fn inject_harness_rules(&mut self, agent: Option<AgentKind>) {
    let agent = match agent {
        Some(a) => a,
        None => return,
    };
    let compiled = match &mut self.compiled {
        Some(c) => c,
        None => return,
    };
    if !crate::harness::is_harness_enabled(compiled.harness_defaults) {
        return;
    }
    let nodes = crate::harness::harness_nodes(agent);
    if !nodes.is_empty() {
        compiled.tree.extend(nodes);
    }
}
```

- [ ] **Step 4: Call `inject_harness_rules` from `load_or_create_with_session`**

The problem is that `load_or_create_with_session` doesn't currently know the agent. We need to thread agent info through. The simplest approach: add an `agent` parameter to `HookContext`.

In `clash/src/settings/mod.rs`, add to `HookContext`:

```rust
pub struct HookContext {
    pub transcript_dir: Option<String>,
    pub agent: Option<crate::agents::AgentKind>,
}
```

Update `from_transcript_path` to set `agent: None` and add a builder method:

```rust
pub fn with_agent(mut self, agent: crate::agents::AgentKind) -> Self {
    self.agent = agent.into();
    self
}
```

Then in `load_or_create_with_session`, after `this.compiled = Some(tree)`:

```rust
// Inject harness default rules for the active agent.
let agent = _hook_ctx.and_then(|ctx| ctx.agent);
this.inject_harness_rules(agent);
```

- [ ] **Step 5: Wire up agent in hook callers**

Find where `HookContext` is constructed (in the hook command handler) and pass the agent. This is in the hook command code where `ToolUseHookInput` is parsed — the agent is already known at that point.

Search for `HookContext::from_transcript_path` usage and add `.with_agent(input.agent)` or similar.

- [ ] **Step 6: Run tests**

Run: `cargo test -p clash harness_rules`
Expected: PASS

- [ ] **Step 7: Run full check**

Run: `just check`
Expected: PASS (all existing tests still pass)

- [ ] **Step 8: Commit**

```bash
git add clash/src/settings/loader.rs clash/src/settings/mod.rs
git commit -m "feat(harness): inject harness rules during policy loading"
```

---

### Task 5: Filter harness rules in status output

**Files:**
- Modify: `clash/src/cmd/status.rs`
- Modify: `clash/src/policy/match_tree.rs` (add helper to count harness nodes)

- [ ] **Step 1: Write test for harness node counting**

In `clash/src/policy/match_tree.rs` tests:

```rust
#[test]
fn count_harness_nodes() {
    let mut policy = CompiledPolicy {
        sandboxes: HashMap::new(),
        tree: vec![
            Node::Condition {
                observe: Observable::FsOp,
                pattern: Pattern::Literal(Value::Literal("read".to_string())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: Some("harness".to_string()),
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".to_string())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: Some("~/.clash/policy.star".to_string()),
                terminal: false,
            },
        ],
        default_effect: Effect::Ask,
        default_sandbox: None,
        on_sandbox_violation: ViolationAction::default(),
        harness_defaults: None,
    };
    assert_eq!(policy.harness_node_count(), 1);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash count_harness_nodes`
Expected: FAIL — `harness_node_count()` doesn't exist.

- [ ] **Step 3: Add `harness_node_count` and `without_harness_nodes` to CompiledPolicy**

In `clash/src/policy/match_tree.rs`:

```rust
impl CompiledPolicy {
    /// Count root-level nodes stamped with source "harness".
    pub fn harness_node_count(&self) -> usize {
        self.tree.iter().filter(|n| match n {
            Node::Condition { source, .. } => source.as_deref() == Some("harness"),
            _ => false,
        }).count()
    }

    /// Return a view of the tree with harness nodes filtered out.
    /// Used for default (non-verbose) status display.
    pub fn tree_without_harness(&self) -> Vec<&Node> {
        self.tree.iter().filter(|n| match n {
            Node::Condition { source, .. } => source.as_deref() != Some("harness"),
            _ => true,
        }).collect()
    }
}
```

- [ ] **Step 4: Run test**

Run: `cargo test -p clash count_harness_nodes`
Expected: PASS

- [ ] **Step 5: Update `format_tree` to support filtering**

In `clash/src/policy/format.rs`, add a variant that takes a node slice:

```rust
/// Format selected rules as a tree with box-drawing characters.
pub fn format_tree_nodes(nodes: &[&Node]) -> Vec<String> {
    let mut lines = Vec::new();
    let len = nodes.len();
    for (i, node) in nodes.iter().enumerate() {
        let is_last = i == len - 1;
        format_tree_node(node, "", is_last, true, &mut lines);
    }
    lines
}
```

Add a `format_tree_filtered` method on `CompiledPolicy`:

```rust
/// Format rules as a tree, optionally excluding harness nodes.
pub fn format_tree_filtered(&self, include_harness: bool) -> Vec<String> {
    if include_harness {
        super::format::format_tree(self)
    } else {
        let nodes = self.tree_without_harness();
        super::format::format_tree_nodes(&nodes)
    }
}
```

- [ ] **Step 6: Update `status.rs` to filter harness rules**

In `clash/src/cmd/status.rs`, replace the existing `format_tree` call:

```rust
let lines = policy.format_tree_filtered(verbose);
if lines.is_empty() {
    println!(
        "  {}",
        style::dim(&format!(
            "(no rules — default {} applies to everything)",
            policy.default_effect
        ))
    );
} else {
    for line in &lines {
        println!("  {}", colorize_tree_line(line));
    }
}

// Show harness rule count when not verbose
if !verbose {
    let harness_count = policy.harness_node_count();
    if harness_count > 0 {
        println!(
            "\n  {}",
            style::dim(&format!(
                "{} harness rule{} active (use --verbose to show)",
                harness_count,
                if harness_count == 1 { "" } else { "s" }
            ))
        );
    }
}
```

- [ ] **Step 7: Run full check**

Run: `just check`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add clash/src/policy/match_tree.rs clash/src/policy/format.rs clash/src/cmd/status.rs
git commit -m "feat(status): filter harness rules from default output, show with --verbose"
```

---

### Task 6: End-to-end test

**Files:**
- Create: `clester/tests/scripts/harness-defaults.yaml`

- [ ] **Step 1: Write clester e2e test**

Check the existing clester test format first (look at an existing script in `clester/tests/scripts/`), then write a test that:

1. Creates a minimal policy
2. Runs `clash status` and verifies harness rules are hidden but counted
3. Runs `clash status --verbose` and verifies harness rules are shown with `[harness]` tag
4. Creates a policy with `harness_defaults=False` and verifies no harness rules appear

- [ ] **Step 2: Run the test**

Run: `just clester -- harness-defaults`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add clester/tests/scripts/harness-defaults.yaml
git commit -m "test(e2e): add harness defaults end-to-end test"
```

---

### Task 7: Documentation updates

**Files:**
- Modify: `README.md` (if harness defaults are mentioned in feature list)
- Modify: `site/` docs (if settings reference exists)

- [ ] **Step 1: Check existing docs for settings references**

Search `site/` and `README.md` for mentions of `settings()`, `CLASH_DISABLE`, `CLASH_PASSTHROUGH`, or similar configuration documentation. Update any settings reference to include `harness_defaults` and `CLASH_NO_HARNESS_DEFAULTS`.

- [ ] **Step 2: Update relevant docs**

Add harness defaults to the settings documentation, explaining:
- What they do (auto-allow agent infrastructure access)
- How to disable (env var or Starlark setting)
- That `clash status` hides them by default

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: document harness default permissions"
```
