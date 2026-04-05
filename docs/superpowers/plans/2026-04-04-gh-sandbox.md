# gh CLI Sandbox Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add GitHub CLI (`gh`) support to the prebuilt `git_safe` and `git_full` sandboxes by allowing read access to `~/.config/gh/**`.

**Architecture:** Single-file change to `sandboxes.star` stdlib, adding a `glob(".config/gh/**"): allow("r")` rule to both git sandbox definitions.

**Tech Stack:** Starlark (policy DSL)

---

### Task 1: Add gh config access to git_safe sandbox

**Files:**
- Modify: `clash_starlark/stdlib/sandboxes.star:37-51`
- Test: `clash_starlark/tests/` (existing sandbox compilation tests)

- [ ] **Step 1: Write a test that verifies gh config access in git_safe**

Add a test in `clash_starlark/tests/` (find the existing sandbox tests file) that evaluates a policy using `git_safe` and checks that `~/.config/gh/hosts.yml` is allowed read access. The test should:

```rust
#[test]
fn git_safe_allows_gh_config_read() {
    let source = r#"
load("@clash//sandboxes.star", "git_safe")

policy("test",
    default = deny(),
    rules = [
        when({"Bash": allow(sandbox="git_safe")}),
    ],
)
"#;
    let output = crate::evaluate(source, "test.star", Path::new(".")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    // Verify the git_safe sandbox fs rules contain .config/gh/**
    let sandboxes = doc["sandboxes"].as_object().unwrap();
    let git_safe = &sandboxes["git_safe"];
    let fs_json = serde_json::to_string(git_safe).unwrap();
    assert!(fs_json.contains(".config/gh"), "git_safe should include .config/gh access");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p clash_starlark git_safe_allows_gh_config_read`
Expected: FAIL — the sandbox doesn't include `.config/gh` yet.

- [ ] **Step 3: Add gh config read access to git_safe**

In `clash_starlark/stdlib/sandboxes.star`, modify the `git_safe` sandbox definition. Change:

```starlark
git_safe = sandbox(
    name = "git_safe",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        "$HOME": {
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git safe: fetch, pull, log, diff. Worktree-aware, network + SSH enabled.",
)
```

To:

```starlark
git_safe = sandbox(
    name = "git_safe",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        "$HOME": {
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".config/gh/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git safe: fetch, pull, log, diff, gh. Worktree-aware, network + SSH enabled.",
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p clash_starlark git_safe_allows_gh_config_read`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/sandboxes.star clash_starlark/tests/
git commit -m "feat: add gh CLI config access to git_safe sandbox (#430)"
```

### Task 2: Add gh config access to git_full sandbox

**Files:**
- Modify: `clash_starlark/stdlib/sandboxes.star:53-67`

- [ ] **Step 1: Write a test that verifies gh config access in git_full**

Same pattern as Task 1 but for `git_full`:

```rust
#[test]
fn git_full_allows_gh_config_read() {
    let source = r#"
load("@clash//sandboxes.star", "git_full")

policy("test",
    default = deny(),
    rules = [
        when({"Bash": allow(sandbox="git_full")}),
    ],
)
"#;
    let output = crate::evaluate(source, "test.star", Path::new(".")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&output.json).unwrap();
    let sandboxes = doc["sandboxes"].as_object().unwrap();
    let git_full = &sandboxes["git_full"];
    let fs_json = serde_json::to_string(git_full).unwrap();
    assert!(fs_json.contains(".config/gh"), "git_full should include .config/gh access");
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p clash_starlark git_full_allows_gh_config_read`
Expected: FAIL

- [ ] **Step 3: Add gh config read access to git_full**

In `clash_starlark/stdlib/sandboxes.star`, modify the `git_full` sandbox definition. Change:

```starlark
git_full = sandbox(
    name = "git_full",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow(FULL),
        "$HOME": {
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git full: commit, push, checkout, merge. Worktree-aware, network + SSH enabled.",
)
```

To:

```starlark
git_full = sandbox(
    name = "git_full",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow(FULL),
        "$HOME": {
            ".gitconfig": allow("r"),
            glob(".config/git/**"): allow("r"),
            glob(".config/gh/**"): allow("r"),
            glob(".ssh/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Git full: commit, push, checkout, merge, gh. Worktree-aware, network + SSH enabled.",
)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p clash_starlark git_full_allows_gh_config_read`
Expected: PASS

- [ ] **Step 5: Run all existing sandbox tests**

Run: `cargo test -p clash_starlark`
Expected: All tests PASS — no regressions.

- [ ] **Step 6: Commit**

```bash
git add clash_starlark/stdlib/sandboxes.star clash_starlark/tests/
git commit -m "feat: add gh CLI config access to git_full sandbox (#430)"
```
