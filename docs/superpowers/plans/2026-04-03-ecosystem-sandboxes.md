# Ecosystem Sandboxes & Init Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redo language sandboxes with proper `_safe`/`_full` naming, add 7 new ecosystem sandboxes, and integrate project detection + history mining into `clash init`.

**Architecture:** Each ecosystem gets a `.star` file in `clash_starlark/stdlib/` with sandbox definitions and convenience `when()` rules. A Rust `EcosystemDef` registry drives detection (file markers + audit log mining) and codegen. The init flow asks permission to scan, shows detections, and generates a mode-aware policy using the existing AST codegen infrastructure.

**Tech Stack:** Rust, Starlark (clash DSL), `clash_starlark::codegen` AST builder

---

### Task 1: Rename git sandboxes from `_ro`/`_rw` to `_safe`/`_full`

**Files:**
- Modify: `clash_starlark/stdlib/sandboxes.star`
- Modify: `clash/src/default_policy.star`
- Modify: `clash/src/cmd/init.rs` (test)
- Test: existing `just check` tests

- [ ] **Step 1: Update sandboxes.star**

In `clash_starlark/stdlib/sandboxes.star`, rename the sandbox definitions and variables:

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

Also update the file header comment to list `git_safe` / `git_full` instead of `git_ro` / `git_rw`.

- [ ] **Step 2: Update default_policy.star**

In `clash/src/default_policy.star`, update the load and references:

```starlark
load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "workspace", "git_safe", "git_full")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_safe)
                }
            }
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_full)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
```

- [ ] **Step 3: Run tests**

Run: `just check`
Expected: All tests pass, including `starter_policy_compiles` in `clash/src/cmd/init.rs`.

- [ ] **Step 4: Run e2e tests**

Run: `just clester`
Expected: All e2e tests pass. If any reference `git_ro`/`git_rw` by name, update them.

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/sandboxes.star clash/src/default_policy.star
git commit -m "refactor: rename git_ro/git_rw to git_safe/git_full"
```

---

### Task 2: Rewrite rust.star with `rust_safe` and `rust_full`

**Files:**
- Modify: `clash_starlark/stdlib/rust.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

Add a compilation test to `clash/src/cmd/init.rs` (or a new test file — follow the pattern of `starter_policy_compiles`):

```rust
#[test]
fn rust_sandbox_compiles() {
    let source = r#"
load("@clash//rust.star", "rust_safe", "rust_full")

policy("test",
    {
        Tool("Bash"): {
            ("cargo", "rustc", "rustup"): {
                glob("**"): allow(sandbox=rust_safe)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("rust sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("rust sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash rust_sandbox_compiles`
Expected: FAIL — `rust_safe` and `rust_full` don't exist yet in `rust.star`.

- [ ] **Step 3: Rewrite rust.star**

Replace the contents of `clash_starlark/stdlib/rust.star`:

```starlark
rust_safe = sandbox(
    name = "rust_safe",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        subpath("$PWD/target"): allow(),
        "$HOME": {
            glob(".cargo/**"): allow("rx"),
            glob(".rustup/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = deny(),
    doc = "Rust safe: check, clippy, test, doc, bench. Build artifacts writable, source read-only.",
)

rust_full = sandbox(
    name = "rust_full",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow(FULL),
        "$HOME": {
            glob(".cargo/**"): allow(),
            glob(".rustup/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Rust full: add, install, update. Full project + toolchain access, network enabled.",
)

rust = when({"Bash": {("cargo", "rustc", "rustup"): allow(sandbox = rust_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash rust_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `just check`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add clash_starlark/stdlib/rust.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): rewrite rust.star with rust_safe and rust_full"
```

---

### Task 3: Rewrite python.star with `python_full`

**Files:**
- Modify: `clash_starlark/stdlib/python.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn python_sandbox_compiles() {
    let source = r#"
load("@clash//python.star", "python_full")

policy("test",
    {
        Tool("Bash"): {
            ("python", "python3", "pip", "pip3", "uv", "poetry"): {
                glob("**"): allow(sandbox=python_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("python sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("python sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash python_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Rewrite python.star**

Replace the contents of `clash_starlark/stdlib/python.star`:

```starlark
python_full = sandbox(
    name = "python_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".local/**"): allow(),
            glob(".cache/pip/**"): allow(),
            glob(".virtualenvs/**"): allow(),
            glob(".pyenv/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Python full: pip install, run scripts, virtualenvs. Full project + package access.",
)

python = when({"Bash": {("python", "python3", "pip", "pip3", "uv", "poetry"): allow(sandbox = python_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash python_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/python.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): rewrite python.star with python_full"
```

---

### Task 4: Rewrite node.star with `node_full`

**Files:**
- Modify: `clash_starlark/stdlib/node.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn node_sandbox_compiles() {
    let source = r#"
load("@clash//node.star", "node_full")

policy("test",
    {
        Tool("Bash"): {
            ("node", "npm", "npx", "bun", "deno", "yarn", "pnpm"): {
                glob("**"): allow(sandbox=node_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("node sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("node sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash node_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Rewrite node.star**

Replace the contents of `clash_starlark/stdlib/node.star`:

```starlark
node_full = sandbox(
    name = "node_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".npm/**"): allow(),
            glob(".config/npm/**"): allow("r"),
            glob(".bun/**"): allow(),
            glob(".cache/yarn/**"): allow(),
            glob(".pnpm-store/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Node full: npm/bun/yarn/pnpm install, run scripts. Full project + package access.",
)

node = when({"Bash": {("node", "npm", "npx", "bun", "deno", "yarn", "pnpm"): allow(sandbox = node_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash node_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/node.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): rewrite node.star with node_full"
```

---

### Task 5: Add go.star with `go_safe` and `go_full`

**Files:**
- Create: `clash_starlark/stdlib/go.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn go_sandbox_compiles() {
    let source = r#"
load("@clash//go.star", "go_safe", "go_full")

policy("test",
    {
        Tool("Bash"): {
            "go": {
                glob("**"): allow(sandbox=go_safe)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("go sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("go sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash go_sandbox_compiles`
Expected: FAIL — `go.star` doesn't exist.

- [ ] **Step 3: Create go.star**

Create `clash_starlark/stdlib/go.star`:

```starlark
go_safe = sandbox(
    name = "go_safe",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        "$HOME": {
            glob("go/**"): allow(),
            glob(".cache/go-build/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = deny(),
    doc = "Go safe: vet, test, build. Module cache writable, source read-only.",
)

go_full = sandbox(
    name = "go_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob("go/**"): allow(),
            glob(".cache/go-build/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Go full: get, mod tidy, install. Full project access, network enabled.",
)

go = when({"Bash": {"go": allow(sandbox = go_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash go_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/go.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add go.star with go_safe and go_full"
```

---

### Task 6: Add java.star with `java_full`

**Files:**
- Create: `clash_starlark/stdlib/java.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn java_sandbox_compiles() {
    let source = r#"
load("@clash//java.star", "java_full")

policy("test",
    {
        Tool("Bash"): {
            ("gradle", "gradlew", "mvn", "mvnw", "java", "javac"): {
                glob("**"): allow(sandbox=java_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("java sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("java sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash java_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Create java.star**

Create `clash_starlark/stdlib/java.star`:

```starlark
java_full = sandbox(
    name = "java_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".gradle/**"): allow(),
            glob(".m2/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Java/JVM full: gradle, maven builds. Full project + dependency cache access.",
)

java = when({"Bash": {("gradle", "gradlew", "mvn", "mvnw", "java", "javac"): allow(sandbox = java_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash java_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/java.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add java.star with java_full"
```

---

### Task 7: Add ruby.star with `ruby_full`

**Files:**
- Create: `clash_starlark/stdlib/ruby.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn ruby_sandbox_compiles() {
    let source = r#"
load("@clash//ruby.star", "ruby_full")

policy("test",
    {
        Tool("Bash"): {
            ("ruby", "gem", "bundle", "rails"): {
                glob("**"): allow(sandbox=ruby_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("ruby sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("ruby sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash ruby_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Create ruby.star**

Create `clash_starlark/stdlib/ruby.star`:

```starlark
ruby_full = sandbox(
    name = "ruby_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".gem/**"): allow(),
            glob(".bundle/**"): allow(),
            glob(".rbenv/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Ruby full: gem install, bundle, rails. Full project + gem access.",
)

ruby = when({"Bash": {("ruby", "gem", "bundle", "rails"): allow(sandbox = ruby_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash ruby_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/ruby.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add ruby.star with ruby_full"
```

---

### Task 8: Add docker.star with `docker_safe` and `docker_full`

**Files:**
- Create: `clash_starlark/stdlib/docker.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn docker_sandbox_compiles() {
    let source = r#"
load("@clash//docker.star", "docker_safe", "docker_full")

policy("test",
    {
        Tool("Bash"): {
            ("docker", "docker-compose", "podman"): {
                glob("**"): allow(sandbox=docker_safe)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("docker sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("docker sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash docker_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Create docker.star**

Create `clash_starlark/stdlib/docker.star`:

```starlark
docker_safe = sandbox(
    name = "docker_safe",
    default = ask(),
    fs = {
        subpath("$PWD"): allow("rx"),
        "$HOME": {
            ".docker/config.json": allow("r"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Docker safe: ps, images, inspect, logs. Read-only project, Docker daemon access.",
)

docker_full = sandbox(
    name = "docker_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".docker/**"): allow("r"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Docker full: build, run, compose, push. Full project access, network enabled.",
)

docker = when({"Bash": {("docker", "docker-compose", "podman"): allow(sandbox = docker_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash docker_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/docker.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add docker.star with docker_safe and docker_full"
```

---

### Task 9: Add swift.star with `swift_full`

**Files:**
- Create: `clash_starlark/stdlib/swift.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn swift_sandbox_compiles() {
    let source = r#"
load("@clash//swift.star", "swift_full")

policy("test",
    {
        Tool("Bash"): {
            ("swift", "swiftc", "xcodebuild"): {
                glob("**"): allow(sandbox=swift_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("swift sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("swift sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash swift_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Create swift.star**

Create `clash_starlark/stdlib/swift.star`:

```starlark
swift_full = sandbox(
    name = "swift_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".swiftpm/**"): allow(),
            glob("Library/Developer/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Swift full: build, test, package resolve. Full project + SPM cache access.",
)

swift = when({"Bash": {("swift", "swiftc", "xcodebuild"): allow(sandbox = swift_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash swift_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/swift.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add swift.star with swift_full"
```

---

### Task 10: Add dotnet.star with `dotnet_full`

**Files:**
- Create: `clash_starlark/stdlib/dotnet.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn dotnet_sandbox_compiles() {
    let source = r#"
load("@clash//dotnet.star", "dotnet_full")

policy("test",
    {
        Tool("Bash"): {
            ("dotnet", "msbuild"): {
                glob("**"): allow(sandbox=dotnet_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("dotnet sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("dotnet sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash dotnet_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Create dotnet.star**

Create `clash_starlark/stdlib/dotnet.star`:

```starlark
dotnet_full = sandbox(
    name = "dotnet_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        "$HOME": {
            glob(".nuget/**"): allow(),
            glob(".dotnet/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = ".NET full: build, test, restore. Full project + NuGet cache access.",
)

dotnet = when({"Bash": {("dotnet", "msbuild"): allow(sandbox = dotnet_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash dotnet_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/dotnet.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add dotnet.star with dotnet_full"
```

---

### Task 11: Add make.star with `make_full`

**Files:**
- Create: `clash_starlark/stdlib/make.star`
- Test: `just check`

- [ ] **Step 1: Write the test**

```rust
#[test]
fn make_sandbox_compiles() {
    let source = r#"
load("@clash//make.star", "make_full")

policy("test",
    {
        Tool("Bash"): {
            ("make", "cmake", "just"): {
                glob("**"): allow(sandbox=make_full)
            }
        }
    },
)
"#;
    let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
        .expect("make sandbox starlark evaluation");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("make sandbox must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash make_sandbox_compiles`
Expected: FAIL

- [ ] **Step 3: Create make.star**

Create `clash_starlark/stdlib/make.star`:

```starlark
make_full = sandbox(
    name = "make_full",
    default = ask(),
    fs = {
        subpath("$PWD"): allow(FULL),
        glob("$TMPDIR/**"): allow(),
    },
    net = deny(),
    doc = "Make/CMake/Just full: build targets. Full project access, no network.",
)

make = when({"Bash": {("make", "cmake", "just"): allow(sandbox = make_full)}})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash make_sandbox_compiles`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/stdlib/make.star clash/src/cmd/init.rs
git commit -m "feat(sandbox): add make.star with make_full"
```

---

### Task 12: Create the ecosystem registry (`ecosystem.rs`)

**Files:**
- Create: `clash/src/ecosystem.rs`
- Modify: `clash/src/lib.rs` (or `clash/src/main.rs`) to add `mod ecosystem;`
- Test: unit tests in `ecosystem.rs`

- [ ] **Step 1: Write the failing test**

Create `clash/src/ecosystem.rs` with just the test first:

```rust
//! Ecosystem detection and registry for sandbox auto-configuration.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_rust_by_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "rust"));
    }

    #[test]
    fn detect_go_by_marker() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("go.mod"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "go"));
    }

    #[test]
    fn detect_by_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let detected = detect_ecosystems(tmp.path(), &["cargo", "docker"]);
        assert!(detected.iter().any(|e| e.name == "rust"));
        assert!(detected.iter().any(|e| e.name == "docker"));
    }

    #[test]
    fn detect_git_by_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "git"));
    }

    #[test]
    fn detect_deduplicates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        // Both marker and binary point to rust — should appear once
        let detected = detect_ecosystems(tmp.path(), &["cargo"]);
        let rust_count = detected.iter().filter(|e| e.name == "rust").count();
        assert_eq!(rust_count, 1);
    }

    #[test]
    fn detect_dotnet_by_glob() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("MyApp.csproj"), "").unwrap();
        let detected = detect_ecosystems(tmp.path(), &[]);
        assert!(detected.iter().any(|e| e.name == "dotnet"));
    }

    #[test]
    fn binary_to_ecosystem_mapping() {
        assert_eq!(ecosystem_for_binary("cargo"), Some("rust"));
        assert_eq!(ecosystem_for_binary("npm"), Some("node"));
        assert_eq!(ecosystem_for_binary("python3"), Some("python"));
        assert_eq!(ecosystem_for_binary("unknown_tool"), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash ecosystem`
Expected: FAIL — functions don't exist yet.

- [ ] **Step 3: Implement the registry and detection**

Complete `clash/src/ecosystem.rs`:

```rust
//! Ecosystem detection and registry for sandbox auto-configuration.

use std::path::Path;

/// Definition of an ecosystem for sandbox auto-configuration.
#[derive(Debug, Clone)]
pub struct EcosystemDef {
    /// Short name (e.g., "rust", "go", "node").
    pub name: &'static str,
    /// Starlark file to load (e.g., "rust.star").
    pub star_file: &'static str,
    /// Binaries that belong to this ecosystem.
    pub binaries: &'static [&'static str],
    /// Project file markers (checked in `$PWD`).
    pub markers: &'static [&'static str],
    /// Directory markers (checked in `$PWD`).
    pub dir_markers: &'static [&'static str],
    /// Glob markers for extensions (e.g., "*.csproj").
    pub glob_markers: &'static [&'static str],
    /// Safe sandbox name (None if ecosystem has only _full).
    pub safe_sandbox: Option<&'static str>,
    /// Full sandbox name.
    pub full_sandbox: &'static str,
}

/// The complete ecosystem registry.
pub const ECOSYSTEMS: &[EcosystemDef] = &[
    EcosystemDef {
        name: "git",
        star_file: "sandboxes.star",
        binaries: &["git"],
        markers: &[],
        dir_markers: &[".git"],
        glob_markers: &[],
        safe_sandbox: Some("git_safe"),
        full_sandbox: "git_full",
    },
    EcosystemDef {
        name: "rust",
        star_file: "rust.star",
        binaries: &["cargo", "rustc", "rustup"],
        markers: &["Cargo.toml"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: Some("rust_safe"),
        full_sandbox: "rust_full",
    },
    EcosystemDef {
        name: "go",
        star_file: "go.star",
        binaries: &["go"],
        markers: &["go.mod"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: Some("go_safe"),
        full_sandbox: "go_full",
    },
    EcosystemDef {
        name: "node",
        star_file: "node.star",
        binaries: &["node", "npm", "npx", "bun", "deno", "yarn", "pnpm"],
        markers: &["package.json"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "node_full",
    },
    EcosystemDef {
        name: "python",
        star_file: "python.star",
        binaries: &["python", "python3", "pip", "pip3", "uv", "poetry"],
        markers: &["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "python_full",
    },
    EcosystemDef {
        name: "ruby",
        star_file: "ruby.star",
        binaries: &["ruby", "gem", "bundle", "rails"],
        markers: &["Gemfile"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "ruby_full",
    },
    EcosystemDef {
        name: "java",
        star_file: "java.star",
        binaries: &["gradle", "gradlew", "mvn", "mvnw", "java", "javac"],
        markers: &["build.gradle", "pom.xml", "build.gradle.kts"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "java_full",
    },
    EcosystemDef {
        name: "docker",
        star_file: "docker.star",
        binaries: &["docker", "docker-compose", "podman"],
        markers: &["Dockerfile", "docker-compose.yml", "compose.yml"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: Some("docker_safe"),
        full_sandbox: "docker_full",
    },
    EcosystemDef {
        name: "swift",
        star_file: "swift.star",
        binaries: &["swift", "swiftc", "xcodebuild"],
        markers: &["Package.swift"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "swift_full",
    },
    EcosystemDef {
        name: "dotnet",
        star_file: "dotnet.star",
        binaries: &["dotnet", "msbuild"],
        markers: &[],
        dir_markers: &[],
        glob_markers: &["*.csproj", "*.sln", "*.fsproj"],
        safe_sandbox: None,
        full_sandbox: "dotnet_full",
    },
    EcosystemDef {
        name: "make",
        star_file: "make.star",
        binaries: &["make", "cmake", "just"],
        markers: &["Makefile", "CMakeLists.txt", "justfile"],
        dir_markers: &[],
        glob_markers: &[],
        safe_sandbox: None,
        full_sandbox: "make_full",
    },
];

/// Look up which ecosystem a binary belongs to.
pub fn ecosystem_for_binary(binary: &str) -> Option<&'static str> {
    ECOSYSTEMS
        .iter()
        .find(|e| e.binaries.contains(&binary))
        .map(|e| e.name)
}

/// Detect ecosystems present in a project directory.
///
/// Combines two signals:
/// - File/directory markers in `project_dir`
/// - Observed binaries from command history
///
/// Returns a deduplicated list of matching ecosystem definitions.
pub fn detect_ecosystems(
    project_dir: &Path,
    observed_binaries: &[&str],
) -> Vec<&'static EcosystemDef> {
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();

    for eco in ECOSYSTEMS {
        if seen.contains(eco.name) {
            continue;
        }

        let matched = eco.markers.iter().any(|m| project_dir.join(m).exists())
            || eco.dir_markers.iter().any(|m| project_dir.join(m).is_dir())
            || has_glob_match(project_dir, eco.glob_markers)
            || eco
                .binaries
                .iter()
                .any(|b| observed_binaries.contains(b));

        if matched {
            seen.insert(eco.name);
            result.push(eco);
        }
    }

    result
}

/// Check if any glob pattern matches a file in the directory (root level only).
fn has_glob_match(dir: &Path, patterns: &[&str]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        for pattern in patterns {
            // Simple extension matching: "*.csproj" matches "Foo.csproj"
            if let Some(ext) = pattern.strip_prefix("*.") {
                if name.ends_with(ext) {
                    return true;
                }
            }
        }
    }
    false
}
```

- [ ] **Step 4: Register the module**

Add `pub mod ecosystem;` to the appropriate `mod` declaration file in `clash/src/`. Check where other modules like `sandbox_cmd` are declared and add it alongside.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p clash ecosystem`
Expected: All 7 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add clash/src/ecosystem.rs clash/src/lib.rs
git commit -m "feat: add ecosystem registry with project detection"
```

---

### Task 13: Extract binary mining from `from_trace.rs`

**Files:**
- Modify: `clash/src/cmd/from_trace.rs`
- Test: existing tests must still pass

- [ ] **Step 1: Write the test for the extracted function**

Add a test to `clash/src/cmd/from_trace.rs`:

```rust
#[test]
fn test_mine_observed_binaries() {
    let audit = r#"{"timestamp":"1.0","session_id":"s1","tool_name":"Bash","tool_input_summary":"git status","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"2.0","session_id":"s1","tool_name":"Bash","tool_input_summary":"cargo test","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"3.0","session_id":"s1","tool_name":"Read","tool_input_summary":"/tmp/file","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}"#;

    let binaries = mine_binaries_from_content(audit);
    assert!(binaries.contains("git"));
    assert!(binaries.contains("cargo"));
    assert!(!binaries.contains("Read")); // Not a Bash binary
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash test_mine_observed_binaries`
Expected: FAIL — `mine_binaries_from_content` doesn't exist.

- [ ] **Step 3: Extract the function**

Add to `clash/src/cmd/from_trace.rs`:

```rust
/// Mine unique binary names from audit/trace JSONL content.
///
/// Returns a set of binary names observed in Bash invocations.
/// Used by both `clash init` (ecosystem detection) and `clash init --from-trace`.
pub fn mine_binaries_from_content(content: &str) -> std::collections::BTreeSet<String> {
    let mut binaries = std::collections::BTreeSet::new();

    let invocations = if content
        .lines()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| l.contains("\"tool_name\"") && l.contains("\"decision\"") && !l.contains("\"step\""))
    {
        parse_audit_jsonl(content).unwrap_or_default()
    } else {
        parse_trace_jsonl(content).unwrap_or_default()
    };

    for inv in &invocations {
        if inv.tool_name == "Bash" {
            if let Some(ref bin) = inv.binary {
                binaries.insert(bin.clone());
            }
        }
    }

    binaries
}

/// Mine binaries from all available session traces.
///
/// Scans recent clash session directories for audit/trace files and extracts
/// observed binaries. Used by `clash init` for ecosystem detection.
pub fn mine_binaries_from_history() -> std::collections::BTreeSet<String> {
    let mut all_binaries = std::collections::BTreeSet::new();

    let tmp = std::env::temp_dir();
    let readdir = match std::fs::read_dir(&tmp) {
        Ok(r) => r,
        Err(_) => return all_binaries,
    };

    for entry in readdir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("clash-") {
            continue;
        }

        // Prefer audit.jsonl for richer data
        let audit_path = entry.path().join("audit.jsonl");
        let trace_path = entry.path().join("trace.jsonl");

        let candidate = if audit_path.exists() {
            audit_path
        } else if trace_path.exists() {
            trace_path
        } else {
            continue;
        };

        if let Ok(content) = std::fs::read_to_string(&candidate) {
            all_binaries.extend(mine_binaries_from_content(&content));
        }
    }

    all_binaries
}
```

- [ ] **Step 4: Run tests to verify everything passes**

Run: `cargo test -p clash from_trace`
Expected: All existing tests + new test PASS.

- [ ] **Step 5: Commit**

```bash
git add clash/src/cmd/from_trace.rs
git commit -m "refactor: extract binary mining from from_trace for reuse in init"
```

---

### Task 14: Add `load_ecosystem` builder helper

**Files:**
- Modify: `clash_starlark/src/codegen/builder.rs`
- Test: unit test in `builder.rs`

- [ ] **Step 1: Write the test**

Add to the existing `#[cfg(test)] mod tests` in `clash_starlark/src/codegen/builder.rs`:

```rust
#[test]
fn load_ecosystem_file() {
    let stmt = load_ecosystem("rust.star", &["rust_safe", "rust_full"]);
    let src = serialize(&[stmt]);
    assert_eq!(
        src,
        "load(\"@clash//rust.star\", \"rust_safe\", \"rust_full\")\n"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash_starlark load_ecosystem_file`
Expected: FAIL

- [ ] **Step 3: Add the function**

Add to `clash_starlark/src/codegen/builder.rs` in the load statements section:

```rust
/// Load symbols from an ecosystem `.star` file (e.g., `rust.star`, `go.star`).
pub fn load_ecosystem(filename: &str, names: &[&str]) -> Stmt {
    Stmt::load(format!("@clash//{filename}"), names)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clash_starlark load_ecosystem_file`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash_starlark/src/codegen/builder.rs
git commit -m "feat(codegen): add load_ecosystem builder helper"
```

---

### Task 15: Add policy codegen from detected ecosystems

**Files:**
- Modify: `clash/src/ecosystem.rs`
- Test: unit tests

- [ ] **Step 1: Write the test**

Add to `clash/src/ecosystem.rs` tests:

```rust
#[test]
fn generate_policy_for_detected_ecosystems() {
    let ecosystems = vec![
        ECOSYSTEMS.iter().find(|e| e.name == "git").unwrap(),
        ECOSYSTEMS.iter().find(|e| e.name == "rust").unwrap(),
    ];
    let starlark = generate_policy(&ecosystems);

    // Must contain loads
    assert!(starlark.contains("@clash//sandboxes.star"), "missing sandboxes load:\n{starlark}");
    assert!(starlark.contains("@clash//rust.star"), "missing rust load:\n{starlark}");

    // Must contain mode routing
    assert!(starlark.contains("git_safe"), "missing git_safe:\n{starlark}");
    assert!(starlark.contains("git_full"), "missing git_full:\n{starlark}");
    assert!(starlark.contains("rust_safe"), "missing rust_safe:\n{starlark}");
    assert!(starlark.contains("rust_full"), "missing rust_full:\n{starlark}");

    // Must compile
    let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
        .expect("generated policy must evaluate");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("generated policy must compile");
}

#[test]
fn generate_policy_single_variant_ecosystem() {
    let ecosystems = vec![
        ECOSYSTEMS.iter().find(|e| e.name == "node").unwrap(),
    ];
    let starlark = generate_policy(&ecosystems);

    // node_full appears in both plan and edit modes
    assert!(starlark.contains("node_full"), "missing node_full:\n{starlark}");
    assert!(!starlark.contains("node_safe"), "node_safe should not exist:\n{starlark}");

    let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
        .expect("generated policy must evaluate");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("generated policy must compile");
}

#[test]
fn generate_policy_empty_ecosystems() {
    let ecosystems: Vec<&EcosystemDef> = vec![];
    let starlark = generate_policy(&ecosystems);

    // Should still produce a valid policy with just builtins
    let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
        .expect("empty policy must evaluate");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("empty policy must compile");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clash generate_policy`
Expected: FAIL — `generate_policy` doesn't exist.

- [ ] **Step 3: Implement generate_policy**

Add to `clash/src/ecosystem.rs`:

```rust
use clash_starlark::codegen::ast::{DictEntry, Expr, Stmt};
use clash_starlark::codegen::builder::*;

/// Generate a Starlark policy from a list of detected ecosystems.
///
/// Produces a mode-aware policy with:
/// - Plan mode: `_safe` variants where available, `_full` otherwise
/// - Edit/default mode: `_full` variants
/// - Unrestricted mode: `workspace` sandbox
pub fn generate_policy(ecosystems: &[&EcosystemDef]) -> String {
    let mut stmts = Vec::new();

    // --- Loads ---
    stmts.push(load_builtin());

    // Collect sandbox names needed from sandboxes.star
    let mut sandbox_imports: Vec<&str> = vec!["readonly", "workspace"];
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            if let Some(safe) = eco.safe_sandbox {
                if !sandbox_imports.contains(&safe) {
                    sandbox_imports.push(safe);
                }
            }
            if !sandbox_imports.contains(&eco.full_sandbox) {
                sandbox_imports.push(eco.full_sandbox);
            }
        }
    }
    stmts.push(load_sandboxes(&sandbox_imports));

    // Load ecosystem-specific .star files
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            continue; // Already loaded above
        }
        let mut names: Vec<&str> = Vec::new();
        if let Some(safe) = eco.safe_sandbox {
            names.push(safe);
        }
        names.push(eco.full_sandbox);
        stmts.push(load_ecosystem(eco.star_file, &names));
    }

    stmts.push(Stmt::Blank);

    // --- Policy with mode routing ---
    let mut mode_entries: Vec<DictEntry> = Vec::new();

    // Plan mode
    let plan_bash_entries = build_bash_routing(ecosystems, true);
    let mut plan_dict_entries = vec![DictEntry::new(
        Expr::call("glob", vec![Expr::string("**")]),
        allow_with_sandbox(Expr::ident("readonly")),
    )];
    if !plan_bash_entries.is_empty() {
        plan_dict_entries.push(DictEntry::new(
            Expr::call("Tool", vec![Expr::string("Bash")]),
            Expr::dict(plan_bash_entries),
        ));
    }
    mode_entries.push(DictEntry::new(
        Expr::call("mode", vec![Expr::string("plan")]),
        Expr::dict(plan_dict_entries),
    ));

    // Edit/default mode
    let edit_bash_entries = build_bash_routing(ecosystems, false);
    if !edit_bash_entries.is_empty() {
        let edit_dict = vec![DictEntry::new(
            Expr::call("Tool", vec![Expr::string("Bash")]),
            Expr::dict(edit_bash_entries),
        )];
        mode_entries.push(DictEntry::new(
            Expr::tuple(vec![
                Expr::call("mode", vec![Expr::string("edit")]),
                Expr::call("mode", vec![Expr::string("default")]),
            ]),
            Expr::dict(edit_dict),
        ));
    }

    // Unrestricted mode
    mode_entries.push(DictEntry::new(
        Expr::call("mode", vec![Expr::string("unrestricted")]),
        Expr::dict(vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            allow_with_sandbox(Expr::ident("workspace")),
        )]),
    ));

    stmts.push(Stmt::Expr(Expr::call_kwargs(
        "policy",
        vec![Expr::string("default")],
        vec![],
    )));

    // Actually build the policy call with the mode dict as the first positional arg
    // after the name
    let policy_dict = Expr::dict(mode_entries);
    let last = stmts.pop(); // Remove the placeholder
    drop(last);
    stmts.push(Stmt::Expr(Expr::call(
        "policy",
        vec![Expr::string("default"), policy_dict],
    )));

    clash_starlark::codegen::serialize(&stmts)
}

/// Build the Bash routing entries for a set of ecosystems.
///
/// If `use_safe` is true, prefer `_safe` sandbox variants (for plan mode).
/// Otherwise use `_full` variants.
fn build_bash_routing(ecosystems: &[&EcosystemDef], use_safe: bool) -> Vec<DictEntry> {
    let mut entries = Vec::new();

    for eco in ecosystems {
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clash generate_policy`
Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add clash/src/ecosystem.rs
git commit -m "feat: add policy codegen from detected ecosystems"
```

---

### Task 16: Integrate ecosystem detection into `clash init`

**Files:**
- Modify: `clash/src/cmd/init.rs`
- Test: manual testing (interactive flow)

- [ ] **Step 1: Write the test for the non-interactive path**

Add to `clash/src/cmd/init.rs` tests:

```rust
#[test]
fn detected_policy_compiles() {
    // Simulate detecting rust + git
    let ecosystems: Vec<&crate::ecosystem::EcosystemDef> = crate::ecosystem::ECOSYSTEMS
        .iter()
        .filter(|e| e.name == "rust" || e.name == "git")
        .collect();
    let starlark = crate::ecosystem::generate_policy(&ecosystems);
    let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
        .expect("detected policy must evaluate");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("detected policy must compile");
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test -p clash detected_policy_compiles`
Expected: PASS (this relies on Task 15's `generate_policy`).

- [ ] **Step 3: Add detection flow to init**

Modify `clash/src/cmd/init.rs` — add a new function and integrate it into `run()`:

```rust
use crate::ecosystem;

/// Run ecosystem detection and return a generated policy, or None if the user
/// declines or no ecosystems are detected.
fn detect_and_generate_policy() -> Result<Option<String>> {
    // Ask permission to scan
    println!();
    let scan = crate::dialog::confirm(
        "Scan your project and command history to recommend sandboxes?",
        false,
    )?;
    if !scan {
        return Ok(None);
    }

    // Detect ecosystems
    let cwd = std::env::current_dir().context("getting current directory")?;
    let observed = crate::cmd::from_trace::mine_binaries_from_history();
    let observed_refs: Vec<&str> = observed.iter().map(|s| s.as_str()).collect();
    let detected = ecosystem::detect_ecosystems(&cwd, &observed_refs);

    if detected.is_empty() {
        ui::info("No ecosystems detected.");
        return Ok(None);
    }

    // Show detections
    println!();
    ui::info("Detected ecosystems:");
    println!();
    for eco in &detected {
        let mut reasons = Vec::new();
        // Check which markers matched
        for m in eco.markers {
            if cwd.join(m).exists() {
                reasons.push(format!("found {m}"));
            }
        }
        for m in eco.dir_markers {
            if cwd.join(m).is_dir() {
                reasons.push(format!("found {m}/"));
            }
        }
        for bin in eco.binaries {
            if observed.contains(*bin) {
                reasons.push(format!("observed: {bin}"));
            }
        }
        let reason_str = if reasons.is_empty() {
            String::new()
        } else {
            format!("  ({})", reasons.join(", "))
        };
        ui::success(&format!(
            "  {:<12}{}",
            eco.name, reason_str
        ));
    }
    println!();

    // Confirm
    let include = crate::dialog::confirm(
        "Include these sandboxes in your policy?",
        false,
    )?;
    if !include {
        return Ok(None);
    }

    Ok(Some(ecosystem::generate_policy(&detected)))
}
```

- [ ] **Step 4: Wire into the `run()` function**

Modify `run()` in `clash/src/cmd/init.rs` to try detection before falling back to the starter template:

```rust
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    let mut actions = InitActions::default();

    // Try ecosystem detection first, fall back to starter template
    let (policy_path, created_new) = match detect_and_generate_policy()? {
        Some(policy_content) => {
            let path = write_detected_policy(&policy_content)?;
            (path, true)
        }
        None => ensure_starter_policy()?,
    };

    let outcome = crate::tui::run_with_options(&policy_path, false, true)?;
    if outcome == crate::tui::TuiOutcome::Aborted {
        if created_new {
            let _ = std::fs::remove_file(&policy_path);
        }
        println!();
        ui::warn("Setup cancelled. Run `clash init` to try again.");
        return Ok(());
    }
    actions.policy_created = created_new;
    actions.policy_reviewed = true;

    actions.plugin_installed = install_agent_plugin(agent)?;
    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            warn!(error = %e, "Could not install status line");
        } else {
            actions.statusline_installed = true;
        }
    }
    print_summary(&actions, agent);

    Ok(())
}

/// Write a detected/generated policy to the policy file location.
fn write_detected_policy(content: &str) -> Result<std::path::PathBuf> {
    let policy_path = ClashSettings::policy_file()?;
    let star_path = policy_path.with_extension("star");
    let dir = star_path
        .parent()
        .context("policy file path has no parent directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create {}", dir.display()))?;
    std::fs::write(&star_path, content)
        .with_context(|| format!("failed to write {}", star_path.display()))?;
    Ok(star_path)
}
```

- [ ] **Step 5: Run full test suite**

Run: `just check`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add clash/src/cmd/init.rs
git commit -m "feat(init): integrate ecosystem detection into clash init"
```

---

### Task 17: Integrate ecosystem detection into `clash init --import`

**Files:**
- Modify: `clash/src/cmd/import_settings.rs`

- [ ] **Step 1: Write the test**

Add to `clash/src/cmd/import_settings.rs` tests:

```rust
#[test]
fn test_generate_with_ecosystems_compiles() {
    use claude_settings::permission::PermissionSet;
    let perms = PermissionSet::new()
        .allow("Bash(git:*)")
        .allow("Bash(cargo:*)")
        .allow("Read");
    let settings = claude_settings::Settings::default().with_permissions(perms);
    let mut analysis = analyze_settings(&settings);

    // Simulate detecting rust + git
    let ecosystems: Vec<&crate::ecosystem::EcosystemDef> = crate::ecosystem::ECOSYSTEMS
        .iter()
        .filter(|e| e.name == "rust" || e.name == "git")
        .collect();

    let starlark = generate_starlark_from_analysis_with_ecosystems(&mut analysis, &ecosystems);

    let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
        .expect("starlark evaluation failed");
    crate::policy::compile::compile_to_tree(&output.json)
        .expect("generated policy with ecosystems must compile");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clash test_generate_with_ecosystems_compiles`
Expected: FAIL — function doesn't exist.

- [ ] **Step 3: Add ecosystem-aware generation**

Add to `clash/src/cmd/import_settings.rs`:

```rust
/// Generate a Starlark policy from analyzed settings, augmented with ecosystem sandbox loads.
fn generate_starlark_from_analysis_with_ecosystems(
    analysis: &mut ImportAnalysis,
    ecosystems: &[&crate::ecosystem::EcosystemDef],
) -> String {
    // Start with the base analysis generation
    // but add ecosystem loads and sandbox references
    dedup_stable(&mut analysis.tool_allows);
    dedup_stable(&mut analysis.tool_denies);
    dedup_stable(&mut analysis.tool_asks);

    let mut stmts = vec![
        Stmt::comment("Imported from Claude Code settings"),
        load_builtin(),
    ];

    // Add ecosystem loads
    let mut sandbox_imports: Vec<&str> = Vec::new();
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            if let Some(safe) = eco.safe_sandbox {
                if !sandbox_imports.contains(&safe) {
                    sandbox_imports.push(safe);
                }
            }
            if !sandbox_imports.contains(&eco.full_sandbox) {
                sandbox_imports.push(eco.full_sandbox);
            }
        }
    }
    if !sandbox_imports.is_empty() {
        stmts.push(load_sandboxes(&sandbox_imports));
    }
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            continue;
        }
        let mut names: Vec<&str> = Vec::new();
        if let Some(safe) = eco.safe_sandbox {
            names.push(safe);
        }
        names.push(eco.full_sandbox);
        stmts.push(Stmt::load(format!("@clash//{}", eco.star_file), &names));
    }

    stmts.push(Stmt::Blank);

    // Continue with existing analysis-based generation...
    // (rest of the existing generate_starlark_from_analysis logic)
    // This generates the sandbox, settings, and rules as before,
    // but the ecosystem loads are available for the policy.

    // Re-use existing logic from generate_starlark_from_analysis
    // by calling it and prepending the extra loads.
    // Implementation detail: either inline the existing logic
    // or factor it to accept additional loads.

    // Refactor approach: add an `extra_loads` parameter to
    // generate_starlark_from_analysis. The existing function builds `stmts`
    // starting with `load_builtin()`. Insert the ecosystem loads right after
    // the builtin load and before the sandbox definition.

    // In generate_starlark_from_analysis, change signature to:
    // fn generate_starlark_from_analysis(
    //     analysis: &mut ImportAnalysis,
    //     extra_loads: &[Stmt],
    // ) -> String
    //
    // Then insert `extra_loads` after the builtin load:
    //   stmts.push(load_builtin());
    //   stmts.extend(extra_loads.iter().cloned());
    //   stmts.push(Stmt::Blank);
    //
    // Build the extra loads from ecosystems:
    let mut extra_loads = Vec::new();
    let mut sandbox_imports: Vec<&str> = Vec::new();
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            if let Some(safe) = eco.safe_sandbox {
                sandbox_imports.push(safe);
            }
            sandbox_imports.push(eco.full_sandbox);
        }
    }
    if !sandbox_imports.is_empty() {
        extra_loads.push(load_sandboxes(&sandbox_imports));
    }
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            continue;
        }
        let mut names: Vec<&str> = Vec::new();
        if let Some(safe) = eco.safe_sandbox {
            names.push(safe);
        }
        names.push(eco.full_sandbox);
        extra_loads.push(Stmt::load(format!("@clash//{}", eco.star_file), &names));
    }

    generate_starlark_from_analysis(analysis, &extra_loads)
}
```

Also update the existing `generate_starlark_from_analysis` call sites — the one in `run()` passes `&[]` as extra_loads, and `generate_starlark_from_analysis_with_ecosystems` passes the ecosystem loads.

- [ ] **Step 4: Wire into the `run()` function**

In the `run()` function of `import_settings.rs`, add ecosystem detection after analyzing settings but before generating the policy. Follow the same consent + confirm pattern as `init.rs`.

- [ ] **Step 5: Run tests**

Run: `just check`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add clash/src/cmd/import_settings.rs
git commit -m "feat(import): integrate ecosystem detection into import flow"
```

---

### Task 18: Update clester e2e tests

**Files:**
- Modify: `clester/tests/scripts/star_sandbox_presets.yaml` (if it references `git_ro`/`git_rw`)
- Create: `clester/tests/scripts/ecosystem_sandboxes.yaml`

- [ ] **Step 1: Check existing tests for `git_ro`/`git_rw` references**

Run: `grep -r "git_ro\|git_rw" clester/`
Update any references to `git_safe`/`git_full`.

- [ ] **Step 2: Create ecosystem sandbox e2e test**

Create `clester/tests/scripts/ecosystem_sandboxes.yaml`:

```yaml
meta:
  name: ecosystem sandbox presets
  description: Verify ecosystem sandboxes compile and route correctly

clash:
  policy_star: |
    load("@clash//builtin.star", "builtins")
    load("@clash//sandboxes.star", "readonly", "workspace", "git_safe", "git_full")
    load("@clash//rust.star", "rust_safe", "rust_full")
    load("@clash//go.star", "go_safe", "go_full")
    load("@clash//node.star", "node_full")
    load("@clash//python.star", "python_full")
    load("@clash//ruby.star", "ruby_full")
    load("@clash//java.star", "java_full")
    load("@clash//docker.star", "docker_safe", "docker_full")
    load("@clash//swift.star", "swift_full")
    load("@clash//dotnet.star", "dotnet_full")
    load("@clash//make.star", "make_full")

    policy("test",
        {
            Tool("Bash"): {
                "git": { glob("**"): allow(sandbox=git_safe) },
                ("cargo", "rustc"): { glob("**"): allow(sandbox=rust_safe) },
                "go": { glob("**"): allow(sandbox=go_safe) },
                ("node", "npm"): { glob("**"): allow(sandbox=node_full) },
                ("python", "python3"): { glob("**"): allow(sandbox=python_full) },
                ("ruby", "gem", "bundle"): { glob("**"): allow(sandbox=ruby_full) },
                ("gradle", "mvn"): { glob("**"): allow(sandbox=java_full) },
                ("docker", "podman"): { glob("**"): allow(sandbox=docker_safe) },
                ("swift", "xcodebuild"): { glob("**"): allow(sandbox=swift_full) },
                ("dotnet", "msbuild"): { glob("**"): allow(sandbox=dotnet_full) },
                ("make", "cmake", "just"): { glob("**"): allow(sandbox=make_full) },
            },
        },
    )

steps:
  - name: git routed to git_safe
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow

  - name: cargo routed to rust_safe
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: cargo check
    expect:
      decision: allow

  - name: npm routed to node_full
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: npm install
    expect:
      decision: allow

  - name: make routed to make_full
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: make build
    expect:
      decision: allow
```

- [ ] **Step 3: Run e2e tests**

Run: `just clester`
Expected: All tests pass, including the new ecosystem test.

- [ ] **Step 4: Commit**

```bash
git add clester/tests/scripts/
git commit -m "test: add ecosystem sandbox e2e tests"
```

---

### Task 19: Update documentation

**Files:**
- Check and update any docs referencing `git_ro`/`git_rw`, `rust_dev`, `python_dev`, `node_dev`

- [ ] **Step 1: Search for stale references**

Run: `grep -r "git_ro\|git_rw\|rust_dev\|python_dev\|node_dev" docs/ site/ README.md`
Update any found references.

- [ ] **Step 2: Run full CI**

Run: `just ci`
Expected: All checks and e2e tests pass.

- [ ] **Step 3: Commit any doc updates**

```bash
git add -A
git commit -m "docs: update sandbox references to new naming"
```

---

### Task 20: Final validation

- [ ] **Step 1: Run full CI**

Run: `just ci`
Expected: All unit tests, lints, and e2e tests pass.

- [ ] **Step 2: Manual smoke test**

Run `clash init` in a Rust project directory and verify:
1. It asks to scan
2. Detects Rust + Git (and any other ecosystems present)
3. Shows detections with reasons
4. Generates a policy with proper `_safe`/`_full` routing
5. TUI opens for review
6. Generated policy compiles and works

- [ ] **Step 3: Verify sandbox enforcement**

Run `clash sandbox test --sandbox rust_safe -- cargo check` in a Rust project.
Expected: cargo check succeeds under the sandbox.
