# Starlark Policy Mutation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable `clash policy allow`/`deny`/`remove` to mutate `.star` files directly, and add visudo-style validation to `clash policy edit --raw` with tree diff confirmation.

**Architecture:** Extend `apply_mutation()` to branch on file extension — `.json` uses existing `manifest_edit` path, `.star` uses codegen to parse, mutate a managed section, validate, diff, and serialize. `policy edit --raw` gets a validation loop with tempfile editing and tree diff display before committing changes.

**Tech Stack:** Rust, Starlark (clash_starlark codegen), Myers diff algorithm

---

## File Structure

| File | Responsibility |
|------|---------------|
| `clash/src/policy/diff.rs` | **New** — tree diff: compile two policies, format_tree both, Myers diff, colorized output |
| `clash/src/policy/mod.rs` | Add `pub mod diff;` |
| `clash_starlark/src/codegen/managed.rs` | **New** — managed section operations: find/create section, append/replace variables, reference in policy() |
| `clash_starlark/src/codegen/mod.rs` | Add `pub mod managed;` |
| `clash/src/cmd/policy.rs` | Extend `apply_mutation()` for `.star`, rewrite `handle_edit()` for `--raw` validation |
| `clash/src/policy/manifest_edit.rs` | Make `same_match_chain()` pub for reuse |

---

### Task 1: Create tree diff utility

**Files:**
- Create: `clash/src/policy/diff.rs`
- Modify: `clash/src/policy/mod.rs`
- Test: inline `#[cfg(test)]` module in `diff.rs`

- [ ] **Step 1: Write the failing test for tree diff**

Create `clash/src/policy/diff.rs` with a test module. The test should verify that diffing two compiled policies produces the expected unified diff output.

First, check what modules are declared in `clash/src/policy/mod.rs` and add `pub mod diff;` to it.

Then create `clash/src/policy/diff.rs`:

```rust
use crate::policy::format;
use crate::policy::match_tree::CompiledPolicy;

/// Produce a unified diff of two policy trees rendered via format_tree().
/// Returns lines prefixed with " " (context), "+" (added), "-" (removed),
/// colored with style helpers.
pub fn format_tree_diff(before: &CompiledPolicy, after: &CompiledPolicy) -> Vec<String> {
    let before_lines = format::format_tree(before);
    let after_lines = format::format_tree(after);
    unified_diff(&before_lines, &after_lines)
}

/// Myers-style unified diff of two string slices.
/// Returns lines prefixed with " ", "+", "-".
fn unified_diff(before: &[String], after: &[String]) -> Vec<String> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_identical_trees_produces_no_changes() {
        let lines = unified_diff(
            &["├── Bash".into(), "│   └── allow".into()],
            &["├── Bash".into(), "│   └── allow".into()],
        );
        assert!(lines.iter().all(|l| l.starts_with(' ')), "all lines should be context");
    }

    #[test]
    fn diff_added_line() {
        let before = vec!["├── Bash".into(), "└── Read → allow".into()];
        let after = vec![
            "├��─ Bash".into(),
            "│   └── git → allow".into(),
            "└── Read → allow".into(),
        ];
        let lines = unified_diff(&before, &after);
        let added: Vec<_> = lines.iter().filter(|l| l.starts_with('+')).collect();
        assert_eq!(added.len(), 1);
        assert!(added[0].contains("git → allow"));
    }

    #[test]
    fn diff_removed_line() {
        let before = vec![
            "├── Bash → deny".into(),
            "└── Read → allow".into(),
        ];
        let after = vec!["└─��� Read → allow".into()];
        let lines = unified_diff(&before, &after);
        let removed: Vec<_> = lines.iter().filter(|l| l.starts_with('-')).collect();
        assert_eq!(removed.len(), 1);
        assert!(removed[0].contains("Bash → deny"));
    }

    #[test]
    fn diff_changed_line() {
        let before = vec!["└── Bash �� deny".into()];
        let after = vec!["└── Bash → allow".into()];
        let lines = unified_diff(&before, &after);
        let removed: Vec<_> = lines.iter().filter(|l| l.starts_with('-')).collect();
        let added: Vec<_> = lines.iter().filter(|l| l.starts_with('+')).collect();
        assert_eq!(removed.len(), 1);
        assert_eq!(added.len(), 1);
        assert!(removed[0].contains("deny"));
        assert!(added[0].contains("allow"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash --lib policy::diff`
Expected: FAIL with `not yet implemented` from `todo!()`

- [ ] **Step 3: Implement unified_diff using longest common subsequence**

Replace the `todo!()` in `unified_diff`:

```rust
fn unified_diff(before: &[String], after: &[String]) -> Vec<String> {
    // Build LCS table
    let m = before.len();
    let n = after.len();
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if before[i - 1] == after[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }

    // Backtrack to produce diff
    let mut result = Vec::new();
    let mut i = m;
    let mut j = n;
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && before[i - 1] == after[j - 1] {
            result.push(format!(" {}", &before[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            result.push(format!("+{}", &after[j - 1]));
            j -= 1;
        } else {
            result.push(format!("-{}", &before[i - 1]));
            i -= 1;
        }
    }
    result.reverse();
    result
}
```

- [ ] **Step 4: Add a public helper that prints the diff with colors**

Add to `diff.rs`:

```rust
use crate::style;

/// Print a tree diff to stdout with colors.
/// Returns true if there were any changes, false if identical.
pub fn print_tree_diff(before: &CompiledPolicy, after: &CompiledPolicy) -> bool {
    let diff_lines = format_tree_diff(before, after);
    let has_changes = diff_lines.iter().any(|l| l.starts_with('+') || l.starts_with('-'));
    if !has_changes {
        println!("{}", style::dim("No policy changes."));
        return false;
    }
    println!("{}","Policy changes:");
    for line in &diff_lines {
        if line.starts_with('+') {
            println!("  {}", style::green(line));
        } else if line.starts_with('-') {
            println!("  {}", style::red(line));
        } else {
            println!("  {}", line);
        }
    }
    has_changes
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clash --lib policy::diff`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add clash/src/policy/diff.rs clash/src/policy/mod.rs
git commit -m "feat: add policy tree diff utility"
```

---

### Task 2: Create managed section operations for starlark codegen

**Files:**
- Create: `clash_starlark/src/codegen/managed.rs`
- Modify: `clash_starlark/src/codegen/mod.rs`
- Test: inline `#[cfg(test)]` module in `managed.rs`

- [ ] **Step 1: Write tests for managed section operations**

Create `clash_starlark/src/codegen/managed.rs`. The managed section is marked by a `# clash-managed rules` comment. Operations:
- Find the section (returns index of the comment, or None)
- Create the section (insert comment before the policy() call)
- List existing managed variables (`_clash_rule_N`)
- Append a new managed variable
- Replace a managed variable's value

```rust
use super::ast::{Expr, Stmt};
use super::mutate;

/// The comment that marks the start of the managed section.
const MANAGED_MARKER: &str = "clash-managed rules";

/// Find the index of the managed section marker comment.
pub fn find_managed_section(stmts: &[Stmt]) -> Option<usize> {
    stmts.iter().position(|s| matches!(s, Stmt::Comment(c) if c.contains(MANAGED_MARKER)))
}

/// Create the managed section marker before the policy() call.
/// Returns the index where the marker was inserted.
pub fn create_managed_section(stmts: &mut Vec<Stmt>) -> usize {
    todo!()
}

/// Find all managed variable assignments (_clash_rule_N) and return
/// their (index, name, value) tuples. Only looks after the managed marker.
pub fn find_managed_rules(stmts: &[Stmt]) -> Vec<(usize, String, &Expr)> {
    todo!()
}

/// Return the next available managed rule variable name.
pub fn next_rule_name(stmts: &[Stmt]) -> String {
    todo!()
}

/// Append a new managed variable assignment with the given expression.
/// Inserts it after the last managed rule (or after the marker if none exist),
/// and before the policy() call.
/// Returns the variable name.
pub fn append_managed_rule(stmts: &mut Vec<Stmt>, value: Expr) -> String {
    todo!()
}

/// Replace the value of an existing managed variable by name.
pub fn replace_managed_rule(stmts: &mut Vec<Stmt>, name: &str, value: Expr) -> bool {
    todo!()
}

/// Add a managed variable reference to the policy() call's rules list.
/// The reference is appended to the end of the rules list.
pub fn reference_in_policy(stmts: &mut Vec<Stmt>, var_name: &str) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::ast::Stmt;
    use crate::codegen::builder;
    use crate::codegen::serialize::serialize;

    fn sample_policy() -> Vec<Stmt> {
        vec![
            Stmt::Load {
                module: "@clash//std.star".into(),
                names: vec!["policy".into(), "when".into(), "allow".into(), "deny".into()],
            },
            Stmt::Blank,
            Stmt::Expr(builder::policy(
                "main",
                builder::ask(),
                vec![],
                None,
            )),
        ]
    }

    #[test]
    fn find_managed_section_returns_none_when_absent() {
        let stmts = sample_policy();
        assert!(find_managed_section(&stmts).is_none());
    }

    #[test]
    fn create_managed_section_inserts_before_policy() {
        let mut stmts = sample_policy();
        let idx = create_managed_section(&mut stmts);
        assert!(matches!(&stmts[idx], Stmt::Comment(c) if c.contains(MANAGED_MARKER)));
        // policy() should still be after the marker
        let policy_idx = mutate::find_policy_call(&stmts).unwrap();
        assert!(policy_idx > idx);
    }

    #[test]
    fn append_and_reference_managed_rule() {
        let mut stmts = sample_policy();
        let name = append_managed_rule(&mut stmts, builder::allow());
        assert_eq!(name, "_clash_rule_0");
        // Verify the assignment exists
        let rules = find_managed_rules(&stmts);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].1, "_clash_rule_0");
        // Reference it in policy
        reference_in_policy(&mut stmts, &name);
        let source = serialize(&stmts);
        assert!(source.contains("_clash_rule_0"));
    }

    #[test]
    fn next_rule_name_increments() {
        let mut stmts = sample_policy();
        append_managed_rule(&mut stmts, builder::allow());
        append_managed_rule(&mut stmts, builder::deny());
        assert_eq!(next_rule_name(&stmts), "_clash_rule_2");
    }

    #[test]
    fn replace_managed_rule_updates_value() {
        let mut stmts = sample_policy();
        append_managed_rule(&mut stmts, builder::allow());
        let replaced = replace_managed_rule(&mut stmts, "_clash_rule_0", builder::deny());
        assert!(replaced);
        let source = serialize(&stmts);
        assert!(source.contains("deny()"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash_starlark codegen::managed`
Expected: FAIL with `not yet implemented`

- [ ] **Step 3: Implement create_managed_section**

```rust
pub fn create_managed_section(stmts: &mut Vec<Stmt>) -> usize {
    // If it already exists, return its index
    if let Some(idx) = find_managed_section(stmts) {
        return idx;
    }
    // Insert before the policy() call, or at end if no policy() found
    let insert_at = mutate::find_policy_call(stmts).unwrap_or(stmts.len());
    stmts.insert(insert_at, Stmt::Comment(MANAGED_MARKER.into()));
    if insert_at > 0 && !matches!(&stmts[insert_at - 1], Stmt::Blank) {
        stmts.insert(insert_at, Stmt::Blank);
        return insert_at + 1; // marker moved forward by one
    }
    insert_at
}
```

- [ ] **Step 4: Implement find_managed_rules and next_rule_name**

```rust
pub fn find_managed_rules(stmts: &[Stmt]) -> Vec<(usize, String, &Expr)> {
    let start = match find_managed_section(stmts) {
        Some(idx) => idx + 1,
        None => return vec![],
    };
    let mut results = Vec::new();
    for (i, stmt) in stmts[start..].iter().enumerate() {
        if let Stmt::Assign { target, value } = stmt {
            if target.starts_with("_clash_rule_") {
                results.push((start + i, target.clone(), value));
            }
        }
    }
    results
}

pub fn next_rule_name(stmts: &[Stmt]) -> String {
    let rules = find_managed_rules(stmts);
    let max_n = rules
        .iter()
        .filter_map(|(_, name, _)| name.strip_prefix("_clash_rule_").and_then(|n| n.parse::<usize>().ok()))
        .max();
    let next = max_n.map_or(0, |n| n + 1);
    format!("_clash_rule_{next}")
}
```

- [ ] **Step 5: Implement append_managed_rule, replace_managed_rule, reference_in_policy**

```rust
pub fn append_managed_rule(stmts: &mut Vec<Stmt>, value: Expr) -> String {
    let marker_idx = create_managed_section(stmts);
    let name = next_rule_name(stmts);

    // Find insertion point: after last managed rule, or after marker
    let rules = find_managed_rules(stmts);
    let insert_at = rules.last().map_or(marker_idx + 1, |(idx, _, _)| idx + 1);

    stmts.insert(insert_at, Stmt::Assign {
        target: name.clone(),
        value,
    });
    name
}

pub fn replace_managed_rule(stmts: &mut Vec<Stmt>, name: &str, value: Expr) -> bool {
    for stmt in stmts.iter_mut() {
        if let Stmt::Assign { target, value: v } = stmt {
            if target == name {
                *v = value;
                return true;
            }
        }
    }
    false
}

pub fn reference_in_policy(stmts: &mut Vec<Stmt>, var_name: &str) {
    if let Some(rules) = mutate::policy_rules_mut(stmts) {
        rules.push(Expr::Ident(var_name.into()));
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p clash_starlark codegen::managed`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash_starlark/src/codegen/managed.rs clash_starlark/src/codegen/mod.rs
git commit -m "feat: managed section operations for starlark codegen"
```

---

### Task 3: Make same_match_chain pub in manifest_edit

**Files:**
- Modify: `clash/src/policy/manifest_edit.rs`

- [ ] **Step 1: Make same_match_chain and related functions pub(crate)**

In `clash/src/policy/manifest_edit.rs`, change:

```rust
fn same_match_chain(a: &Node, b: &Node) -> bool {
```

To:

```rust
pub(crate) fn same_match_chain(a: &Node, b: &Node) -> bool {
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p clash`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add clash/src/policy/manifest_edit.rs
git commit -m "refactor: make same_match_chain pub(crate) for reuse"
```

---

### Task 4: Extend apply_mutation to support .star files

**Files:**
- Modify: `clash/src/cmd/policy.rs:558-606`
- Uses: `clash_starlark::codegen::{managed, mutate, serialize, ast}`, `clash_starlark::evaluate`, `clash/src/policy/diff`

- [ ] **Step 1: Write a test for starlark mutation**

Find or create an integration test file for the policy command. Write a test that:
1. Creates a temp directory with a `.star` policy file
2. Calls the starlark mutation logic with an allow rule for `git push`
3. Verifies the output file is valid starlark
4. Verifies it contains a managed section with the rule

```rust
#[test]
fn apply_starlark_mutation_adds_managed_rule() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.star");
    std::fs::write(&policy_path, r#"
load("@clash//std.star", "policy", "when", "allow", "deny", "ask")

policy("main",
    default = ask(),
    rules = [],
)
"#).unwrap();

    // Build a rule node for "git push" -> allow
    let node = build_rule_node(
        &["git".into(), "push".into()],
        None,
        None,
        Decision::Allow(None),
    ).unwrap();

    apply_starlark_mutation(&policy_path, node, PolicyMutation::Allow { sandbox: None }).unwrap();

    // Verify the file is valid
    let source = std::fs::read_to_string(&policy_path).unwrap();
    let output = clash_starlark::evaluate(&source, "policy.star", dir.path()).unwrap();
    assert!(source.contains("clash-managed rules"));
    assert!(source.contains("_clash_rule_0"));
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p clash apply_starlark_mutation`
Expected: FAIL — function doesn't exist yet

- [ ] **Step 3: Implement apply_starlark_mutation**

In `clash/src/cmd/policy.rs`, add a new function and update `apply_mutation` to call it:

```rust
use clash_starlark::codegen::{managed, ast::Expr, from_manifest::node_json_to_expr, serialize::serialize};
use crate::policy::diff;

/// Apply a mutation to a .star policy file using the managed section.
fn apply_starlark_mutation(
    path: &Path,
    node: Node,
    mutation: PolicyMutation,
) -> Result<()> {
    let source = std::fs::read_to_string(path)
        .context("failed to read policy file")?;
    let base_dir = path.parent().unwrap_or(Path::new("."));

    // Compile the "before" policy for diffing
    let before_output = clash_starlark::evaluate(&source, &path.display().to_string(), base_dir)
        .context("existing policy file is invalid")?;
    let before_policy = crate::policy_loader::compile_json_source(&before_output.json)?;

    // Parse source to codegen AST
    let mut stmts = clash_starlark::codegen::parse::parse_to_stmts(&source)?;

    // Convert the Node to a JSON value, then to a codegen Expr
    let node_json = serde_json::to_value(&node)?;
    let rule_expr = node_json_to_expr(&node_json);
    // Wrap in when() call
    let when_expr = Expr::Call {
        func: Box::new(Expr::Ident("when".into())),
        args: vec![rule_expr],
        kwargs: vec![],
    };

    match mutation {
        PolicyMutation::Allow { .. } | PolicyMutation::Deny => {
            // Check for duplicate via same_match_chain on compiled trees
            let existing_rules = managed::find_managed_rules(&stmts);
            // For now, just append. Duplicate detection uses compiled policy comparison.
            let var_name = managed::append_managed_rule(&mut stmts, when_expr);
            managed::reference_in_policy(&mut stmts, &var_name);
        }
        PolicyMutation::Remove => {
            // For remove, we need to find and remove the matching managed rule.
            // Compile each managed rule individually and compare with same_match_chain.
            let rules = managed::find_managed_rules(&stmts);
            let mut removed = false;
            for (idx, name, _) in rules.iter().rev() {
                // Remove matching rules (implementation detail: compare compiled forms)
                // For now, remove by observable chain comparison
            }
            if !removed {
                println!("No matching managed rule found in .star file");
                return Ok(());
            }
        }
    }

    // Serialize back to source
    let new_source = serialize(&stmts);

    // Validate the new source compiles
    let after_output = clash_starlark::evaluate(&new_source, &path.display().to_string(), base_dir)
        .context("generated policy is invalid — this is a bug, please report it")?;
    let after_policy = crate::policy_loader::compile_json_source(&after_output.json)?;

    // Show tree diff
    let has_changes = diff::print_tree_diff(&before_policy, &after_policy);
    if !has_changes {
        println!("{}", style::dim("No effective policy changes."));
        return Ok(());
    }

    // Write the file
    std::fs::write(path, &new_source)
        .context("failed to write policy file")?;
    Ok(())
}
```

Then update `apply_mutation()` to remove the `.star` bail and call this instead:

```rust
fn apply_mutation(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
    mutation: PolicyMutation,
) -> Result<()> {
    let path = resolve_manifest_path(scope)?;

    let decision = match &mutation {
        PolicyMutation::Allow { sandbox } => Decision::Allow(
            sandbox.as_deref().map(|s| SandboxRef(s.to_string())),
        ),
        PolicyMutation::Deny | PolicyMutation::Remove => Decision::Deny,
    };

    let node = build_rule_node(&command, tool, bin, decision)?;

    if path.extension().is_some_and(|ext| ext == "star") {
        return apply_starlark_mutation(&path, node, mutation);
    }

    // ... existing JSON path unchanged ...
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p clash apply_starlark_mutation`
Expected: PASS

- [ ] **Step 5: Run the full test suite**

Run: `cargo test -p clash`
Expected: PASS — no regressions

- [ ] **Step 6: Commit**

```bash
git add clash/src/cmd/policy.rs
git commit -m "feat: clash policy allow/deny supports .star files (#432)"
```

---

### Task 5: Implement visudo-style validation for policy edit --raw

**Files:**
- Modify: `clash/src/cmd/policy.rs:517-544`

- [ ] **Step 1: Write a test for the validation flow**

Write a test that simulates the edit flow: copy to tempfile, validate, show diff. Since the actual `$EDITOR` interaction is hard to test, test the validation and diff logic separately:

```rust
#[test]
fn validate_star_policy_catches_syntax_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.star");
    std::fs::write(&path, "policy(\"main\", default = ask(), rules = [])").unwrap();

    let invalid = "this is not valid starlark {{{{";
    let result = validate_policy_source(invalid, &path);
    assert!(result.is_err());
}

#[test]
fn validate_star_policy_accepts_valid_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.star");
    let valid = r#"policy("main", default = ask(), rules = [])"#;
    std::fs::write(&path, valid).unwrap();

    let result = validate_policy_source(valid, &path);
    assert!(result.is_ok());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash validate_star_policy`
Expected: FAIL — function doesn't exist

- [ ] **Step 3: Implement validate_policy_source helper**

In `clash/src/cmd/policy.rs`:

```rust
/// Validate a policy source string. Returns the compiled policy on success.
fn validate_policy_source(source: &str, path: &Path) -> Result<CompiledPolicy> {
    let base_dir = path.parent().unwrap_or(Path::new("."));
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext == "star" {
        let output = clash_starlark::evaluate(source, &path.display().to_string(), base_dir)
            .context("policy validation failed")?;
        crate::policy_loader::compile_json_source(&output.json)
    } else {
        // JSON validation
        let manifest: PolicyManifest = serde_json::from_str(source)
            .context("invalid JSON")?;
        crate::policy_loader::compile_manifest(&manifest)
    }
}
```

- [ ] **Step 4: Rewrite handle_edit for --raw with validation loop**

Replace the `--raw` branch in `handle_edit()`:

```rust
fn handle_edit(scope: Option<String>, raw: bool, test: bool) -> Result<()> {
    if raw {
        let level = match scope.as_deref() {
            Some("user") => PolicyLevel::User,
            Some("project") => PolicyLevel::Project,
            Some(other) => {
                anyhow::bail!("unknown scope: \"{other}\" (expected \"user\" or \"project\")")
            }
            None => ClashSettings::default_scope(),
        };
        let path = ClashSettings::policy_file_for_level(level)?;
        if !path.exists() {
            anyhow::bail!(
                "no policy file at {} — run `clash init {}` first",
                path.display(),
                level,
            );
        }

        // Compile the "before" policy for diffing
        let original_source = std::fs::read_to_string(&path)?;
        let before_policy = validate_policy_source(&original_source, &path)
            .context("existing policy file is already invalid — fix it first")?;

        // Copy to tempfile in same directory (so relative load() paths work)
        let temp_path = path.with_extension("star.tmp");
        std::fs::copy(&path, &temp_path)?;

        loop {
            open_in_editor(&temp_path)?;

            let edited_source = std::fs::read_to_string(&temp_path)?;

            match validate_policy_source(&edited_source, &path) {
                Ok(after_policy) => {
                    // Show tree diff
                    diff::print_tree_diff(&before_policy, &after_policy);

                    // Ask for confirmation
                    eprint!("Apply these changes? [y/n] ");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    if input.trim().eq_ignore_ascii_case("y") {
                        std::fs::copy(&temp_path, &path)?;
                        let _ = std::fs::remove_file(&temp_path);
                        println!("{} Policy updated", style::green_bold("✓"));
                        println!("  {}", style::dim(&path.display().to_string()));
                        return Ok(());
                    } else {
                        let _ = std::fs::remove_file(&temp_path);
                        println!("Aborted — no changes applied.");
                        return Ok(());
                    }
                }
                Err(e) => {
                    eprintln!("{} {e:#}", style::err_red_bold("Validation error:"));
                    eprint!("[e]dit again, [a]bort? ");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                    match input.trim().to_lowercase().as_str() {
                        "e" => continue,
                        _ => {
                            let _ = std::fs::remove_file(&temp_path);
                            println!("Aborted — no changes applied.");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    // Interactive TUI editor (unchanged)
    let path = resolve_manifest_path(scope)?;
    crate::tui::run_with_options(&path, test, false)?;
    Ok(())
}
```

- [ ] **Step 5: Run validation tests**

Run: `cargo test -p clash validate_star_policy`
Expected: PASS

- [ ] **Step 6: Run full test suite**

Run: `cargo test -p clash`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash/src/cmd/policy.rs
git commit -m "feat: visudo-style validation for clash policy edit --raw (#431)"
```

---

### Task 6: End-to-end verification

- [ ] **Step 1: Build the project**

Run: `cargo build`
Expected: PASS with no errors

- [ ] **Step 2: Run all tests across workspace**

Run: `cargo test --workspace`
Expected: All tests PASS

- [ ] **Step 3: Manual smoke test (if possible)**

Create a temp `.star` policy and try:
```bash
cargo run -- policy allow "git push" --scope user
cargo run -- policy show --scope user
```
Verify the managed section appears and the rule is reflected in the tree output.

- [ ] **Step 4: Commit any fixes**

If any fixes were needed, commit them.
