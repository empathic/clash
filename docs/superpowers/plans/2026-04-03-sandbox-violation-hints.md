# Sandbox Violation Hints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make sandbox violation hints precise and actionable, with a configurable directive (`stop`/`workaround`/`smart`) via the `settings()` Starlark function.

**Architecture:** Add `ViolationAction` enum to the policy layer, thread it through Starlark → JSON IR → `CompiledPolicy`, and use it in `build_fs_hint()` / `build_network_hint()` to append the right directive. Improve hint formatting to include sandbox name, specific operations, and current grants.

**Tech Stack:** Rust, Starlark (clash_starlark), serde

---

### Task 1: Add `ViolationAction` enum to policy layer

**Files:**
- Modify: `clash/src/policy/sandbox_types.rs` (add enum after existing types)
- Modify: `clash/src/policy/match_tree.rs:299-310` (add field to `CompiledPolicy`)

- [ ] **Step 1: Write tests for `ViolationAction` serialization**

Add to the bottom of `clash/src/policy/sandbox_types.rs` tests (or create a test block if none exists):

```rust
#[cfg(test)]
mod violation_action_tests {
    use super::*;

    #[test]
    fn test_violation_action_default_is_stop() {
        let action: ViolationAction = Default::default();
        assert!(matches!(action, ViolationAction::Stop));
    }

    #[test]
    fn test_violation_action_deserialize_stop() {
        let action: ViolationAction = serde_json::from_str("\"stop\"").unwrap();
        assert!(matches!(action, ViolationAction::Stop));
    }

    #[test]
    fn test_violation_action_deserialize_workaround() {
        let action: ViolationAction = serde_json::from_str("\"workaround\"").unwrap();
        assert!(matches!(action, ViolationAction::Workaround));
    }

    #[test]
    fn test_violation_action_deserialize_smart() {
        let action: ViolationAction = serde_json::from_str("\"smart\"").unwrap();
        assert!(matches!(action, ViolationAction::Smart));
    }

    #[test]
    fn test_violation_action_serialize_roundtrip() {
        for action in [ViolationAction::Stop, ViolationAction::Workaround, ViolationAction::Smart] {
            let json = serde_json::to_string(&action).unwrap();
            let back: ViolationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib policy::sandbox_types::violation_action_tests`
Expected: FAIL — `ViolationAction` not defined

- [ ] **Step 3: Add `ViolationAction` enum**

In `clash/src/policy/sandbox_types.rs`, add after the existing type definitions:

```rust
/// What the model should do when a sandbox violation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    /// Stop and suggest a policy fix. Don't retry.
    #[default]
    Stop,
    /// Try an alternative approach. If no workaround is possible, suggest the policy fix.
    Workaround,
    /// Let the model assess context to decide between stop and workaround.
    Smart,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clash --lib policy::sandbox_types::violation_action_tests`
Expected: PASS

- [ ] **Step 5: Add `on_sandbox_violation` to `CompiledPolicy`**

In `clash/src/policy/match_tree.rs`, add to the `CompiledPolicy` struct after `default_sandbox`:

```rust
    /// What the model should do when a sandbox blocks an operation.
    #[serde(default, skip_serializing_if = "crate::policy::sandbox_types::ViolationAction::is_default")]
    pub on_sandbox_violation: ViolationAction,
```

Add `is_default` method to `ViolationAction` in `sandbox_types.rs`:

```rust
impl ViolationAction {
    pub fn is_default(&self) -> bool {
        matches!(self, ViolationAction::Stop)
    }
}
```

- [ ] **Step 6: Verify existing tests still pass**

Run: `cargo test -p clash --lib policy`
Expected: PASS — new field has `#[serde(default)]` so existing JSON without it still compiles

- [ ] **Step 7: Commit**

```bash
git add clash/src/policy/sandbox_types.rs clash/src/policy/match_tree.rs
git commit -m "feat(sandbox): add ViolationAction enum and on_sandbox_violation field"
```

---

### Task 2: Thread `on_sandbox_violation` through Starlark → JSON IR

**Files:**
- Modify: `clash_starlark/src/eval_context.rs:14-17` (add field to `SettingsValue`)
- Modify: `clash_starlark/src/eval_context.rs:68-106` (emit in `assemble_document`)
- Modify: `clash_starlark/src/globals.rs:~210-236` (accept new kwarg in `_register_settings`)

- [ ] **Step 1: Write test for Starlark settings with `on_sandbox_violation`**

In `clash_starlark/src/lib.rs`, add a test:

```rust
#[test]
fn settings_on_sandbox_violation() {
    let src = r#"
sandbox("box", default=["read", "execute"], net="deny")
settings(default=deny(), on_sandbox_violation="workaround")
policy("test", when(tool="Bash").then(allow(sandbox="box")))
"#;
    let json = evaluate_policy_source(src).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(doc["on_sandbox_violation"], "workaround");
}

#[test]
fn settings_on_sandbox_violation_defaults_to_absent() {
    let src = r#"
settings(default=deny())
policy("test", when(tool="Bash").then(deny()))
"#;
    let json = evaluate_policy_source(src).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(doc.get("on_sandbox_violation").is_none());
}

#[test]
fn settings_on_sandbox_violation_invalid_value() {
    let src = r#"
settings(default=deny(), on_sandbox_violation="invalid")
policy("test", when(tool="Bash").then(deny()))
"#;
    let result = evaluate_policy_source(src);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("on_sandbox_violation"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash_starlark settings_on_sandbox_violation`
Expected: FAIL — kwarg not accepted

- [ ] **Step 3: Add `on_sandbox_violation` to `SettingsValue`**

In `clash_starlark/src/eval_context.rs`, update `SettingsValue`:

```rust
pub struct SettingsValue {
    pub default_effect: String,
    pub default_sandbox: Option<String>,
    pub on_sandbox_violation: Option<String>,
}
```

- [ ] **Step 4: Emit `on_sandbox_violation` in `assemble_document`**

In `clash_starlark/src/eval_context.rs`, in `assemble_document()`, after the `default_sandbox` insertion block:

```rust
        if let Some(ref action) = settings.as_ref().and_then(|s| s.on_sandbox_violation.clone()) {
            doc.as_object_mut()
                .unwrap()
                .insert("on_sandbox_violation".to_string(), serde_json::json!(action));
        }
```

- [ ] **Step 5: Accept kwarg in `_register_settings`**

In `clash_starlark/src/globals.rs`, update the `_register_settings` function signature to accept the new parameter and validate it:

Add `on_sandbox_violation: Value<'v>` parameter (with `#[starlark(default = NoneType)]`).

After the `default_sandbox` parsing block, add:

```rust
        let osv = if on_sandbox_violation.is_none() {
            None
        } else {
            let s = on_sandbox_violation
                .unpack_str()
                .ok_or_else(|| anyhow::anyhow!("on_sandbox_violation must be a string"))?
                .to_string();
            match s.as_str() {
                "stop" | "workaround" | "smart" => {}
                _ => anyhow::bail!(
                    "on_sandbox_violation must be \"stop\", \"workaround\", or \"smart\", got \"{s}\""
                ),
            }
            Some(s)
        };
```

Update the `register_settings` call to include the new field:

```rust
        ctx.register_settings(SettingsValue {
            default_effect: default.to_string(),
            default_sandbox: ds,
            on_sandbox_violation: osv,
        })?;
```

- [ ] **Step 6: Fix any other `SettingsValue` construction sites**

Search for `SettingsValue {` in the codebase and add `on_sandbox_violation: None` to any other construction sites (e.g., in codegen or tests).

- [ ] **Step 7: Run tests to verify they pass**

Run: `cargo test -p clash_starlark settings_on_sandbox_violation`
Expected: PASS

Run: `cargo test -p clash_starlark`
Expected: PASS (no regressions)

- [ ] **Step 8: Commit**

```bash
git add clash_starlark/src/eval_context.rs clash_starlark/src/globals.rs clash_starlark/src/lib.rs
git commit -m "feat(starlark): add on_sandbox_violation setting to settings()"
```

---

### Task 3: Improve `build_fs_hint` with sandbox name, operations, and directive

**Files:**
- Modify: `clash/src/sandbox_hints/formatter.rs` (rewrite `build_fs_hint`)
- Modify: `clash/src/sandbox_hints/mod.rs:156` (pass new args to `build_fs_hint`)

- [ ] **Step 1: Update existing tests for new `build_fs_hint` signature**

In `clash/src/sandbox_hints/mod.rs`, update `test_build_hint_contains_key_info` and `test_build_hint_empty_caps`:

```rust
    #[test]
    fn test_build_hint_contains_key_info() {
        let blocked = vec![BlockedPath {
            path: "/Users/user/.fly/perms.123".into(),
            suggested_dir: "/Users/user/.fly".into(),
            current_caps: Cap::READ | Cap::EXECUTE,
        }];
        let hint = build_fs_hint("restricted", &blocked, ViolationAction::Stop);
        assert!(hint.contains("SANDBOX VIOLATION"));
        assert!(hint.contains("\"restricted\""));
        assert!(hint.contains("/Users/user/.fly"));
        assert!(hint.contains("clash sandbox add-rule"));
        assert!(hint.contains("Do NOT retry"));
    }

    #[test]
    fn test_build_hint_empty_caps() {
        let blocked = vec![BlockedPath {
            path: "/secret/file".into(),
            suggested_dir: "/secret".into(),
            current_caps: Cap::empty(),
        }];
        let hint = build_fs_hint("mybox", &blocked, ViolationAction::Stop);
        assert!(hint.contains("SANDBOX VIOLATION"));
        assert!(hint.contains("\"mybox\""));
        assert!(hint.contains("/secret"));
        assert!(hint.contains("clash sandbox add-rule"));
    }
```

Add new tests for each directive mode:

```rust
    #[test]
    fn test_build_hint_workaround_directive() {
        let blocked = vec![BlockedPath {
            path: "/foo/bar".into(),
            suggested_dir: "/foo".into(),
            current_caps: Cap::READ,
        }];
        let hint = build_fs_hint("box", &blocked, ViolationAction::Workaround);
        assert!(hint.contains("Try an alternative approach"));
        assert!(hint.contains("If no workaround is possible"));
        assert!(!hint.contains("Do NOT retry"));
    }

    #[test]
    fn test_build_hint_smart_directive() {
        let blocked = vec![BlockedPath {
            path: "/foo/bar".into(),
            suggested_dir: "/foo".into(),
            current_caps: Cap::READ,
        }];
        let hint = build_fs_hint("box", &blocked, ViolationAction::Smart);
        assert!(hint.contains("Assess"));
        assert!(!hint.contains("Do NOT retry"));
    }

    #[test]
    fn test_build_hint_shows_current_grants() {
        let blocked = vec![BlockedPath {
            path: "/foo/bar".into(),
            suggested_dir: "/foo".into(),
            current_caps: Cap::READ | Cap::EXECUTE,
        }];
        let hint = build_fs_hint("box", &blocked, ViolationAction::Stop);
        assert!(hint.contains("read+execute"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib sandbox_hints`
Expected: FAIL — `build_fs_hint` has wrong signature

- [ ] **Step 3: Rewrite `build_fs_hint` in `formatter.rs`**

Replace the entire `build_fs_hint` function in `clash/src/sandbox_hints/formatter.rs`:

```rust
use crate::policy::sandbox_types::{Cap, ViolationAction};

/// A filesystem path that was blocked by the sandbox.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct BlockedPath {
    /// The actual file path from the error message.
    pub path: String,
    /// The parent directory to suggest allowing access to.
    pub suggested_dir: String,
    /// What capabilities the sandbox currently grants for this path.
    pub current_caps: Cap,
}

/// Build advisory context for Claude when a sandbox blocks filesystem access.
pub(crate) fn build_fs_hint(
    sandbox_name: &str,
    blocked: &[BlockedPath],
    action: ViolationAction,
) -> String {
    let mut lines = vec![format!(
        "SANDBOX VIOLATION: sandbox \"{sandbox_name}\" blocked filesystem access."
    )];

    for bp in blocked {
        let grants = format_caps(bp.current_caps);
        lines.push(format!("- write to {} (sandbox grants: {grants})", bp.path));
    }

    lines.push(String::new());
    lines.push("To fix:".into());
    for bp in blocked {
        let needed = needed_caps_string(bp.current_caps);
        lines.push(format!(
            "  clash sandbox add-rule --name {sandbox_name} --path '{}' --allow '{needed}'",
            bp.suggested_dir
        ));
    }

    lines.push(String::new());
    lines.push(directive_text(action).into());

    lines.join("\n")
}

fn format_caps(caps: Cap) -> String {
    let mut parts = Vec::new();
    if caps.contains(Cap::READ) { parts.push("read"); }
    if caps.contains(Cap::WRITE) { parts.push("write"); }
    if caps.contains(Cap::CREATE) { parts.push("create"); }
    if caps.contains(Cap::DELETE) { parts.push("delete"); }
    if caps.contains(Cap::EXECUTE) { parts.push("execute"); }
    if parts.is_empty() { "none".into() } else { parts.join("+") }
}

fn needed_caps_string(current: Cap) -> String {
    let mut needed = vec!["read", "write", "create"];
    if current.contains(Cap::EXECUTE) {
        needed.push("execute");
    }
    needed.join("+")
}

fn directive_text(action: ViolationAction) -> &'static str {
    match action {
        ViolationAction::Stop => {
            "Do NOT retry — it will fail again. Fix the policy first, then re-run the command."
        }
        ViolationAction::Workaround => {
            "The sandbox restricts this path. Try an alternative approach to accomplish your goal \
             without accessing these paths. If no workaround is possible, tell the user and suggest \
             the policy fix above."
        }
        ViolationAction::Smart => {
            "Assess: if these paths look like missing dependencies or build artifacts, suggest the \
             policy fix above. If they look like paths outside the project's scope, find an \
             alternative approach instead."
        }
    }
}
```

- [ ] **Step 4: Update `resolve_sandbox_policy` to return sandbox name**

In `clash/src/sandbox_hints/mod.rs`, change the return type of `resolve_sandbox_policy` from `Option<SandboxPolicy>` to `Option<(SandboxPolicy, String)>`.

**Path 1 (decision tree re-evaluation):** Extract the name from `PolicyDecision::sandbox_name`:
```rust
        let decision = tree.evaluate(&input.tool_name, &input.tool_input);
        if let Some(sandbox) = decision.sandbox {
            let name = decision.sandbox_name
                .map(|r| r.0)
                .unwrap_or_else(|| "unnamed".to_string());
            info!("resolve_sandbox_policy: found sandbox via decision tree re-evaluation");
            return Some((sandbox, name));
        }
```

**Path 2 (rewritten command fallback):** The rewritten command uses `clash shell --sandbox <name>` (NOT `clash sandbox exec --sandbox <json>`). Update to extract the sandbox name and look it up in the compiled policy:

```rust
    // Path 2: extract --sandbox name from the rewritten `clash shell` command
    // and look up the sandbox in the compiled policy.
    let command = input.tool_input.get("command")?.as_str()?;
    if !command.contains(" shell ") || !command.contains("--sandbox") {
        info!(
            command_prefix = &command[..command.len().min(80)],
            "resolve_sandbox_policy: command does not contain shell + --sandbox"
        );
        return None;
    }

    let name = extract_sandbox_name(command)?;
    let tree = settings.policy_tree()?;
    let sandbox = tree.sandboxes.get(&name)?.clone();
    info!(
        sandbox_name = %name,
        "resolve_sandbox_policy: found sandbox via rewritten command --sandbox flag"
    );
    Some((sandbox, name))
```

Replace the `extract_policy_json` function with `extract_sandbox_name`:
```rust
/// Extract the sandbox name from a rewritten `clash shell --sandbox <name>` command.
fn extract_sandbox_name(command: &str) -> Option<String> {
    let idx = command.find("--sandbox ")?;
    let after = &command[idx + "--sandbox ".len()..];
    let name = after.split_whitespace().next()?;
    Some(name.trim_matches('\'').trim_matches('"').to_string())
}
```

- [ ] **Step 5: Update `check_for_sandbox_fs_hint` to use new return type and action**

Destructure the tuple and get `on_sandbox_violation` from settings:

```rust
    let (sandbox, sandbox_name) = match resolve_sandbox_policy(input, settings) {
        Some(s) => s,
        None => {
            info!("check_for_sandbox_fs_hint: no sandbox policy resolved, skipping");
            return None;
        }
    };

    let action = settings.policy_tree()
        .map(|t| t.on_sandbox_violation)
        .unwrap_or_default();
```

Update the final line from `Some(build_fs_hint(&blocked_paths))` to:
```rust
    Some(build_fs_hint(&sandbox_name, &blocked_paths, action))
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p clash --lib sandbox_hints`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash/src/sandbox_hints/formatter.rs clash/src/sandbox_hints/mod.rs
git commit -m "feat(sandbox): improve fs hint with sandbox name, grants, and configurable directive"
```

---

### Task 4: Improve `build_network_hint` with sandbox name and directive

**Files:**
- Modify: `clash/src/network_hints.rs:54-92` (pass sandbox name and action)
- Modify: `clash/src/network_hints.rs:136-143` (rewrite `build_network_hint`)

- [ ] **Step 1: Update existing test for new signature**

In `clash/src/network_hints.rs`, update `test_build_network_hint_contains_key_info`:

```rust
    #[test]
    fn test_build_network_hint_contains_key_info() {
        let hint = build_network_hint("restricted", ViolationAction::Stop);
        assert!(hint.contains("SANDBOX VIOLATION"));
        assert!(hint.contains("\"restricted\""));
        assert!(hint.contains("net allow"));
        assert!(hint.contains("Do NOT retry"));
    }

    #[test]
    fn test_build_network_hint_workaround() {
        let hint = build_network_hint("mybox", ViolationAction::Workaround);
        assert!(hint.contains("\"mybox\""));
        assert!(hint.contains("Try an alternative approach"));
    }

    #[test]
    fn test_build_network_hint_smart() {
        let hint = build_network_hint("mybox", ViolationAction::Smart);
        assert!(hint.contains("Assess"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib network_hints`
Expected: FAIL — `build_network_hint` has wrong signature

- [ ] **Step 3: Rewrite `build_network_hint`**

In `clash/src/network_hints.rs`, add import and update the function:

Add `use crate::policy::sandbox_types::ViolationAction;` to the imports.

```rust
fn build_network_hint(sandbox_name: &str, action: ViolationAction) -> String {
    let directive = crate::sandbox_hints::formatter::directive_text(action);
    [
        &format!("SANDBOX VIOLATION: sandbox \"{sandbox_name}\" blocked network access (policy: deny)."),
        "",
        "To fix:",
        &format!("  clash sandbox add-rule --name {sandbox_name} --net allow"),
        "",
        directive,
    ]
    .join("\n")
}
```

Make `directive_text` pub(crate) in `formatter.rs` so it can be shared.

- [ ] **Step 4: Update `check_for_sandbox_network_hint` to pass name and action**

In `check_for_sandbox_network_hint`, after the policy evaluation, extract the name and action:

```rust
    let sandbox_name = decision.sandbox_name
        .map(|r| r.0)
        .unwrap_or_else(|| "unnamed".to_string());

    let action = tree.on_sandbox_violation;
```

Update the return to:
```rust
    Some(build_network_hint(&sandbox_name, action))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clash --lib network_hints`
Expected: PASS

- [ ] **Step 6: Run all tests**

Run: `cargo test -p clash --lib`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash/src/network_hints.rs clash/src/sandbox_hints/formatter.rs
git commit -m "feat(sandbox): improve network hint with sandbox name and configurable directive"
```

---

### Task 5: Update integration test to verify end-to-end hint with sandbox name

**Files:**
- Modify: `clash/src/sandbox_hints/mod.rs` (update integration test)

- [ ] **Step 1: Update `test_check_returns_hint_with_sandbox` to verify new format**

In `clash/src/sandbox_hints/mod.rs`, update the assertion in `test_check_returns_hint_with_sandbox`:

```rust
    #[test]
    fn test_check_returns_hint_with_sandbox() {
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"{"schema_version":5,"default_effect":"deny",
  "sandboxes":{"restricted":{"default":["read","execute"],"rules":[{"effect":"allow","caps":["read"],"path":"/tmp"}],"network":"deny"}},
  "tree":[
    {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
      {"decision":{"allow":"restricted"}}
    ]}}
  ]}"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "fly logs --app scour-rs"}),
            tool_response: Some(json!(
                "Error: failed ensuring config directory perms: open /Users/emschwartz/.fly/perms.3199984107: operation not permitted"
            )),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let result = check_for_sandbox_fs_hint(&input, &settings);
        assert!(
            result.is_some(),
            "should return hint for sandboxed filesystem error"
        );
        let hint = result.unwrap();
        assert!(hint.contains("SANDBOX VIOLATION"), "hint: {hint}");
        assert!(hint.contains("\"restricted\""), "should include sandbox name, hint: {hint}");
        assert!(hint.contains(".fly"), "hint: {hint}");
        assert!(hint.contains("Do NOT retry"), "default action is stop, hint: {hint}");
    }
```

- [ ] **Step 2: Add test with `on_sandbox_violation` set to `workaround`**

```rust
    #[test]
    fn test_check_returns_hint_with_workaround_action() {
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"{"schema_version":5,"default_effect":"deny",
  "on_sandbox_violation":"workaround",
  "sandboxes":{"restricted":{"default":["read","execute"],"rules":[],"network":"deny"}},
  "tree":[
    {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
      {"decision":{"allow":"restricted"}}
    ]}}
  ]}"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "fly logs"}),
            tool_response: Some(json!(
                "open /Users/user/.fly/perms.123: operation not permitted"
            )),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let result = check_for_sandbox_fs_hint(&input, &settings);
        assert!(result.is_some());
        let hint = result.unwrap();
        assert!(hint.contains("Try an alternative approach"), "hint: {hint}");
        assert!(hint.contains("If no workaround is possible"), "hint: {hint}");
    }
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p clash --lib sandbox_hints`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `just check`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/sandbox_hints/mod.rs
git commit -m "test(sandbox): update integration tests for improved violation hints"
```

---

### Task 6: Update documentation

**Files:**
- Explore docs for sandbox/policy references and update relevant sections

- [ ] **Step 1: Find documentation files referencing sandbox settings**

Search for files in `docs/`, `site/`, and `README.md` that mention `settings()`, `sandbox`, or `on_sandbox_violation`. Update any that describe the `settings()` function to include `on_sandbox_violation`.

- [ ] **Step 2: Update relevant docs**

Add documentation for the new `on_sandbox_violation` parameter wherever `settings()` is documented. Example content:

```
### `on_sandbox_violation`

Controls model behavior when a sandbox blocks an operation. Added as a parameter to `settings()`:

```python
settings(default=deny(), on_sandbox_violation="stop")
```

Values:
- `"stop"` (default) — Tell the model to stop and suggest a policy fix
- `"workaround"` — Tell the model to try an alternative approach
- `"smart"` — Let the model assess context and decide
```

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: add on_sandbox_violation setting documentation"
```
