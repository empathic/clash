# Clester Testing Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve clester with parallel test execution, an expressive assertion DSL (regex, filesystem, combinators), and comprehensive test coverage for init lifecycle and error scenarios.

**Architecture:** Extend the existing clester runner incrementally. New assertion types are added to the `Expectation` struct and checked in `assertions.rs`. Parallelism is added via Rayon's `par_iter` over collected scripts with buffered output. New YAML test scripts exercise init lifecycle and non-happy-path scenarios.

**Tech Stack:** Rust, Rayon (parallelism), regex crate, serde_yaml, clap

**Spec:** `docs/superpowers/specs/2026-04-03-clester-testing-improvements-design.md`

---

### Task 1: Add Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `clester/Cargo.toml`

- [ ] **Step 1: Add rayon and regex to workspace dependencies**

In the workspace `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
rayon = "1.10"
regex = "1.11"
```

- [ ] **Step 2: Add rayon and regex to clester's Cargo.toml**

In `clester/Cargo.toml`, add to `[dependencies]`:

```toml
rayon = { workspace = true }
regex = { workspace = true }
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p clester`
Expected: compiles without errors

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml clester/Cargo.toml
git commit -m "chore(clester): add rayon and regex dependencies"
```

---

### Task 2: Regex Assertions

**Files:**
- Modify: `clester/src/script.rs` — add regex fields to `Expectation`
- Modify: `clester/src/assertions.rs` — implement regex checking
- Test: run existing clester tests to verify backward compatibility

- [ ] **Step 1: Write a test script that uses regex assertions**

Create `clester/tests/scripts/assertion_regex.yaml`:

```yaml
meta:
  name: regex assertion test
  description: Verify regex matching works in assertions

clash:
  policy_star: |
    load("@clash//std.star", "when", "policy", "settings", "allow", "deny")
    settings(default=deny())
    policy("test", rules=[
        when({"Bash": {"git": allow()}}),
    ])

steps:
  - name: regex matches decision reason
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow
      reason_regex: "(?i)allow"

  - name: stdout regex on command
    command: "policy list"
    expect:
      exit_code: 0
      stdout_regex: "\\w+"
```

- [ ] **Step 2: Run it to verify it fails (fields not recognized yet)**

Run: `cargo build --bins && ./target/debug/clester validate clester/tests/scripts/assertion_regex.yaml`
Expected: Either parse error (unknown field) or the fields are silently ignored. Check which — serde_yaml with `#[serde(default)]` will ignore unknown fields only if `deny_unknown_fields` is NOT set. Since the current `Expectation` does not use `deny_unknown_fields`, the fields will be silently ignored and the test will pass vacuously. That's fine — we'll confirm the regex assertions actually work after implementing.

- [ ] **Step 3: Add regex fields to `Expectation` struct**

In `clester/src/script.rs`, add three fields to the `Expectation` struct:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct Expectation {
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub no_decision: Option<bool>,
    #[serde(default)]
    pub reason_contains: Option<String>,
    #[serde(default)]
    pub stdout_contains: Option<String>,
    #[serde(default)]
    pub stderr_contains: Option<String>,
    // New regex fields
    #[serde(default)]
    pub reason_regex: Option<String>,
    #[serde(default)]
    pub stdout_regex: Option<String>,
    #[serde(default)]
    pub stderr_regex: Option<String>,
}
```

- [ ] **Step 4: Implement regex assertion checking**

In `clester/src/assertions.rs`, add `use regex::Regex;` at the top.

After the existing `stdout_contains` / `stderr_contains` checks (around line 133), add regex checks:

```rust
// Regex: reason
if let Some(ref pattern) = expect.reason_regex {
    let re = Regex::new(pattern).context("invalid reason_regex pattern")?;
    let reason = extract_reason(result.output.as_ref());
    match reason {
        Some(r) if re.is_match(&r) => {}
        Some(r) => {
            failures.push(format!(
                "reason_regex: pattern '{}' did not match '{}'",
                pattern, r
            ));
        }
        None => {
            failures.push(format!(
                "reason_regex: no reason found in output"
            ));
        }
    }
}

// Regex: stdout
if let Some(ref pattern) = expect.stdout_regex {
    let re = Regex::new(pattern).context("invalid stdout_regex pattern")?;
    if !re.is_match(&result.stdout) {
        failures.push(format!(
            "stdout_regex: pattern '{}' did not match stdout",
            pattern
        ));
    }
}

// Regex: stderr
if let Some(ref pattern) = expect.stderr_regex {
    let re = Regex::new(pattern).context("invalid stderr_regex pattern")?;
    if !re.is_match(&result.stderr) {
        failures.push(format!(
            "stderr_regex: pattern '{}' did not match stderr",
            pattern
        ));
    }
}
```

Note: The `check` function currently returns `AssertionResult`. The regex compilation can fail, so update the function signature from `pub fn check(expect: &Expectation, result: &HookResult) -> AssertionResult` to `pub fn check(expect: &Expectation, result: &HookResult) -> Result<AssertionResult>`. Update the call site in `main.rs` accordingly (add `?` or handle the error).

- [ ] **Step 5: Update the call site in main.rs**

In `main.rs`, where `check()` is called (around line 143), change from:

```rust
let assertion = check(&step.expect, &result);
```

to:

```rust
let assertion = check(&step.expect, &result)?;
```

- [ ] **Step 6: Run the regex test script**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/assertion_regex.yaml -v`
Expected: PASS — regex patterns match

- [ ] **Step 7: Run all existing tests to verify backward compatibility**

Run: `just clester`
Expected: All existing tests still pass

- [ ] **Step 8: Commit**

```bash
git add clester/src/script.rs clester/src/assertions.rs clester/src/main.rs clester/tests/scripts/assertion_regex.yaml
git commit -m "feat(clester): add regex assertion support (reason_regex, stdout_regex, stderr_regex)"
```

---

### Task 3: Filesystem Assertions

**Files:**
- Modify: `clester/src/script.rs` — add `files` field to `Expectation`, define `FileAssertion` struct
- Modify: `clester/src/assertions.rs` — implement file checking
- Modify: `clester/src/environment.rs` — expose `home_dir` for assertion checking (already public)

- [ ] **Step 1: Write a test script that uses filesystem assertions**

Create `clester/tests/scripts/assertion_files.yaml`:

```yaml
meta:
  name: filesystem assertion test
  description: Verify file existence and content assertions

steps:
  - name: create a test file
    shell: "echo 'hello world 123' > $HOME/testfile.txt"
    expect:
      exit_code: 0

  - name: verify file exists and contains expected content
    shell: "true"
    expect:
      exit_code: 0
      files:
        - path: "testfile.txt"
          exists: true
          contains: "hello world"
          regex: "\\d+"

  - name: verify nonexistent file
    shell: "true"
    expect:
      exit_code: 0
      files:
        - path: "nonexistent.txt"
          exists: false
```

- [ ] **Step 2: Add `FileAssertion` struct and `files` field to `Expectation`**

In `clester/src/script.rs`, add the struct and update `Expectation`:

```rust
/// Assertion about a file in the test environment
#[derive(Debug, Clone, Deserialize)]
pub struct FileAssertion {
    /// Path relative to root (home_dir by default)
    pub path: String,
    /// Which root directory: "home" (default) or "project"
    #[serde(default = "FileAssertion::default_root")]
    pub root: String,
    /// Whether the file should exist
    #[serde(default)]
    pub exists: Option<bool>,
    /// Substring the file must contain
    #[serde(default)]
    pub contains: Option<String>,
    /// Regex the file content must match
    #[serde(default)]
    pub regex: Option<String>,
}

impl FileAssertion {
    fn default_root() -> String {
        "home".to_string()
    }
}
```

Add to `Expectation`:

```rust
    #[serde(default)]
    pub files: Option<Vec<FileAssertion>>,
```

- [ ] **Step 3: Implement filesystem assertion checking**

In `clester/src/assertions.rs`, update the `check` function signature to accept the environment paths:

```rust
pub fn check(
    expect: &Expectation,
    result: &HookResult,
    home_dir: &Path,
    project_dir: &Path,
) -> Result<AssertionResult>
```

Add file assertion checking after the regex checks:

```rust
// Filesystem assertions
if let Some(ref file_assertions) = expect.files {
    for fa in file_assertions {
        let base = match fa.root.as_str() {
            "project" => project_dir,
            _ => home_dir,
        };
        let full_path = base.join(&fa.path);

        let file_exists = full_path.exists();

        // Check existence
        if let Some(expected_exists) = fa.exists {
            if expected_exists && !file_exists {
                failures.push(format!(
                    "file '{}': expected to exist but does not",
                    fa.path
                ));
                continue; // Skip content checks if file doesn't exist
            }
            if !expected_exists && file_exists {
                failures.push(format!(
                    "file '{}': expected not to exist but does",
                    fa.path
                ));
                continue;
            }
        }

        // Skip content checks if file doesn't exist
        if !file_exists {
            continue;
        }

        let content = std::fs::read_to_string(&full_path)
            .with_context(|| format!("failed to read file '{}'", fa.path))?;

        // Check substring
        if let Some(ref substr) = fa.contains {
            if !content.contains(substr.as_str()) {
                failures.push(format!(
                    "file '{}': expected to contain '{}' but did not",
                    fa.path, substr
                ));
            }
        }

        // Check regex
        if let Some(ref pattern) = fa.regex {
            let re = Regex::new(pattern)
                .with_context(|| format!("invalid regex in file assertion for '{}'", fa.path))?;
            if !re.is_match(&content) {
                failures.push(format!(
                    "file '{}': regex '{}' did not match content",
                    fa.path, pattern
                ));
            }
        }
    }
}
```

- [ ] **Step 4: Update the call site in main.rs**

Pass the environment paths to `check()`:

```rust
let assertion = check(&step.expect, &result, &env.home_dir, &env.project_dir)?;
```

- [ ] **Step 5: Run the filesystem test script**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/assertion_files.yaml -v`
Expected: PASS

- [ ] **Step 6: Run all tests**

Run: `just clester`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add clester/src/script.rs clester/src/assertions.rs clester/src/main.rs clester/tests/scripts/assertion_files.yaml
git commit -m "feat(clester): add filesystem assertions (file exists, contains, regex)"
```

---

### Task 4: Assertion Combinators (all_of, any_of, not)

**Files:**
- Modify: `clester/src/script.rs` — add combinator fields to `Expectation`
- Modify: `clester/src/assertions.rs` — implement combinator logic

This is the most complex assertion change. The approach: `all_of` and `any_of` contain vectors of `Expectation` (recursive). `not` contains a boxed `Expectation`. The existing top-level fields remain and are implicitly `all_of`.

- [ ] **Step 1: Write a test script that uses combinators**

Create `clester/tests/scripts/assertion_combinators.yaml`:

```yaml
meta:
  name: combinator assertion test
  description: Verify all_of, any_of, not combinators

clash:
  policy_star: |
    load("@clash//std.star", "when", "policy", "settings", "allow", "deny")
    settings(default=deny())
    policy("test", rules=[
        when({"Bash": {"git": allow()}}),
    ])

steps:
  - name: all_of with multiple conditions
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      all_of:
        - decision: allow
        - exit_code: 0

  - name: any_of matches one condition
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: npm install
    expect:
      any_of:
        - decision: allow
        - decision: deny
      decision: deny

  - name: not inverts assertion
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow
      not:
        decision: deny
```

- [ ] **Step 2: Add combinator fields to `Expectation`**

In `clester/src/script.rs`, add to `Expectation`:

```rust
    #[serde(default)]
    pub all_of: Option<Vec<Expectation>>,
    #[serde(default)]
    pub any_of: Option<Vec<Expectation>>,
    #[serde(default)]
    pub not: Option<Box<Expectation>>,
```

- [ ] **Step 3: Refactor assertion checking to support recursion**

In `clester/src/assertions.rs`, refactor `check` into two functions — the public entry point and a recursive `check_inner`:

```rust
pub fn check(
    expect: &Expectation,
    result: &HookResult,
    home_dir: &Path,
    project_dir: &Path,
) -> Result<AssertionResult> {
    let mut all_failures = Vec::new();

    // Check leaf assertions (the existing logic)
    let leaf = check_leaf(expect, result, home_dir, project_dir)?;
    all_failures.extend(leaf.failures);

    // Check all_of: every child must pass
    if let Some(ref children) = expect.all_of {
        for child in children {
            let child_result = check(child, result, home_dir, project_dir)?;
            all_failures.extend(child_result.failures);
        }
    }

    // Check any_of: at least one child must pass
    if let Some(ref children) = expect.any_of {
        let mut any_passed = false;
        let mut child_failures = Vec::new();
        for child in children {
            let child_result = check(child, result, home_dir, project_dir)?;
            if child_result.passed {
                any_passed = true;
                break;
            }
            child_failures.extend(child_result.failures);
        }
        if !any_passed {
            all_failures.push(format!(
                "any_of: none of the alternatives passed:\n  {}",
                child_failures.join("\n  ")
            ));
        }
    }

    // Check not: child must fail
    if let Some(ref negated) = expect.not {
        let child_result = check(negated, result, home_dir, project_dir)?;
        if child_result.passed {
            all_failures.push("not: expected assertion to fail but it passed".to_string());
        }
    }

    Ok(AssertionResult {
        passed: all_failures.is_empty(),
        failures: all_failures,
    })
}

/// Check only the leaf (non-combinator) fields of an Expectation
fn check_leaf(
    expect: &Expectation,
    result: &HookResult,
    home_dir: &Path,
    project_dir: &Path,
) -> Result<AssertionResult> {
    let mut failures = Vec::new();
    // ... (all existing assertion logic: exit_code, decision, no_decision,
    //      reason_contains, stdout_contains, stderr_contains,
    //      reason_regex, stdout_regex, stderr_regex, files)
    Ok(AssertionResult {
        passed: failures.is_empty(),
        failures,
    })
}
```

Move all the existing assertion checking code from the current `check` function into `check_leaf`. The new `check` function handles combinators and delegates leaf checks.

- [ ] **Step 4: Run the combinator test script**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/assertion_combinators.yaml -v`
Expected: PASS

- [ ] **Step 5: Run all tests**

Run: `just clester`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add clester/src/script.rs clester/src/assertions.rs clester/tests/scripts/assertion_combinators.yaml
git commit -m "feat(clester): add assertion combinators (all_of, any_of, not)"
```

---

### Task 5: Parallel Test Execution with Rayon

**Files:**
- Modify: `clester/src/main.rs` — add `-j` flag, refactor `cmd_run` to use Rayon

- [ ] **Step 1: Add `-j` flag to the `Run` command**

In `clester/src/main.rs`, add to the `Run` variant:

```rust
    Run {
        path: PathBuf,
        #[arg(short, long)]
        verbose: bool,
        #[arg(long)]
        clash_bin: Option<PathBuf>,
        /// Number of parallel jobs (0 = auto, 1 = serial)
        #[arg(short = 'j', long = "jobs", default_value = "0")]
        jobs: usize,
    },
```

Update the match arm that calls `cmd_run` to pass `jobs`.

- [ ] **Step 2: Define a `ScriptResult` struct for buffered output**

Add near the top of `main.rs`:

```rust
use rayon::prelude::*;

/// Result of running a single test script
struct ScriptResult {
    script_name: String,
    step_results: Vec<StepOutcome>,
    passed: bool,
}

/// Outcome of a single step within a script
struct StepOutcome {
    step_name: String,
    passed: bool,
    failures: Vec<String>,
    /// Verbose output captured during execution
    verbose_output: Option<String>,
}
```

- [ ] **Step 3: Extract per-script execution into a function**

Create a function that runs a single script and returns a `ScriptResult`:

```rust
fn run_script(
    script_path: &Path,
    clash_bin: &Path,
    verbose: bool,
) -> ScriptResult {
    let script_name = script_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let script = match TestScript::from_file(script_path) {
        Ok(s) => s,
        Err(e) => {
            return ScriptResult {
                script_name,
                step_results: vec![StepOutcome {
                    step_name: "parse".to_string(),
                    passed: false,
                    failures: vec![format!("failed to parse script: {e}")],
                    verbose_output: None,
                }],
                passed: false,
            };
        }
    };

    let env = match TestEnvironment::setup(&script.settings, script.clash.as_ref()) {
        Ok(e) => e,
        Err(e) => {
            return ScriptResult {
                script_name,
                step_results: vec![StepOutcome {
                    step_name: "setup".to_string(),
                    passed: false,
                    failures: vec![format!("failed to setup environment: {e}")],
                    verbose_output: None,
                }],
                passed: false,
            };
        }
    };

    let mut step_results = Vec::new();
    let mut all_passed = true;

    for step in &script.steps {
        let result = if let Some(ref cmd) = step.command {
            run_command(clash_bin, &env, cmd)
        } else if let Some(ref shell_cmd) = step.shell {
            run_shell(&env, shell_cmd)
        } else {
            run_step(clash_bin, &env, step)
        };

        let (passed, failures, verbose_out) = match result {
            Ok(hook_result) => {
                let verbose_out = if verbose {
                    Some(format!(
                        "  exit_code: {}\n  stdout: {}\n  stderr: {}",
                        hook_result.exit_code,
                        hook_result.stdout.trim(),
                        hook_result.stderr.trim()
                    ))
                } else {
                    None
                };

                match check(&step.expect, &hook_result, &env.home_dir, &env.project_dir) {
                    Ok(assertion) => (assertion.passed, assertion.failures, verbose_out),
                    Err(e) => (false, vec![format!("assertion error: {e}")], verbose_out),
                }
            }
            Err(e) => (false, vec![format!("execution error: {e}")], None),
        };

        if !passed {
            all_passed = false;
        }

        step_results.push(StepOutcome {
            step_name: step.name.clone(),
            passed,
            failures,
            verbose_output: verbose_out,
        });
    }

    ScriptResult {
        script_name,
        step_results,
        passed: all_passed,
    }
}
```

- [ ] **Step 4: Refactor `cmd_run` to use Rayon**

Replace the existing serial loop in `cmd_run` with:

```rust
fn cmd_run(path: &Path, verbose: bool, clash_bin: Option<&Path>, jobs: usize) -> Result<bool> {
    let clash_bin = match clash_bin {
        Some(p) => p.to_path_buf(),
        None => find_clash_binary()?,
    };

    let scripts = collect_scripts(path)?;
    if scripts.is_empty() {
        bail!("no test scripts found at {}", path.display());
    }

    // Configure thread pool
    if jobs == 1 {
        // Serial mode — don't use rayon at all
        let results: Vec<ScriptResult> = scripts
            .iter()
            .map(|s| run_script(s, &clash_bin, verbose))
            .collect();
        print_results(&results, verbose)
    } else {
        // Parallel mode
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(if jobs == 0 { 0 } else { jobs })  // 0 = rayon auto-detects
            .build()
            .context("failed to build thread pool")?;

        let results: Vec<ScriptResult> = pool.install(|| {
            scripts
                .par_iter()
                .map(|s| run_script(s, &clash_bin, verbose))
                .collect()
        });
        print_results(&results, verbose)
    }
}
```

- [ ] **Step 5: Implement `print_results` for structured output**

```rust
fn print_results(results: &[ScriptResult], verbose: bool) -> Result<bool> {
    let mut total_steps = 0;
    let mut passed_steps = 0;
    let mut failed_scripts: Vec<(&str, Vec<&StepOutcome>)> = Vec::new();

    for script in results {
        eprintln!("--- {} ---", script.script_name);
        let mut script_failures = Vec::new();

        for step in &script.step_results {
            total_steps += 1;
            if step.passed {
                passed_steps += 1;
                eprintln!("  ✓ {}", step.step_name);
            } else {
                eprintln!("  ✗ {}", step.step_name);
                for f in &step.failures {
                    eprintln!("    → {}", f);
                }
                script_failures.push(step);
            }
            if verbose {
                if let Some(ref out) = step.verbose_output {
                    eprintln!("{}", out);
                }
            }
        }

        if !script_failures.is_empty() {
            failed_scripts.push((&script.script_name, script_failures));
        }
    }

    let failed_steps = total_steps - passed_steps;
    eprintln!(
        "\n{} scripts, {} steps — {} passed, {} failed",
        results.len(),
        total_steps,
        passed_steps,
        failed_steps
    );

    if !failed_scripts.is_empty() {
        eprintln!("\nFAILED:");
        for (name, steps) in &failed_scripts {
            for step in steps {
                let reason = step.failures.first().map(|s| s.as_str()).unwrap_or("unknown");
                eprintln!("  {} → \"{}\": {}", name, step.step_name, reason);
            }
        }
    }

    Ok(failed_steps == 0)
}
```

- [ ] **Step 6: Run all tests in parallel (default mode)**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/ -v`
Expected: All tests pass, output grouped by script

- [ ] **Step 7: Run in serial mode to verify `-j 1` works**

Run: `./target/debug/clester run clester/tests/scripts/ -j 1`
Expected: Same results, serial execution

- [ ] **Step 8: Run `just clester` to verify CI path**

Run: `just clester`
Expected: All pass (the justfile target passes ARGS through, so default `-j 0` is used)

- [ ] **Step 9: Commit**

```bash
git add clester/src/main.rs
git commit -m "feat(clester): parallel test execution with rayon (-j flag)"
```

---

### Task 6: Organize Test Script Directories

**Files:**
- Move existing `init_no_import.yaml` to `init/` subdirectory
- Create `error/` and `init/` directories

- [ ] **Step 1: Create directory structure and move init test**

```bash
mkdir -p clester/tests/scripts/init
mkdir -p clester/tests/scripts/error
git mv clester/tests/scripts/init_no_import.yaml clester/tests/scripts/init/init_no_import.yaml
```

- [ ] **Step 2: Verify clester still discovers tests recursively**

Run: `just clester`
Expected: All tests pass (clester uses recursive directory scanning)

- [ ] **Step 3: Commit**

```bash
git add clester/tests/scripts/
git commit -m "refactor(clester): organize test scripts into init/ and error/ directories"
```

---

### Task 7: Init Lifecycle Test Scripts

**Files:**
- Create: `clester/tests/scripts/init/init_full_lifecycle.yaml`
- Create: `clester/tests/scripts/init/init_idempotent.yaml`
- Create: `clester/tests/scripts/init/init_preserves_existing.yaml`
- Create: `clester/tests/scripts/init/init_multi_agent.yaml`

- [ ] **Step 1: Write the full lifecycle test**

Create `clester/tests/scripts/init/init_full_lifecycle.yaml`:

```yaml
meta:
  name: init full lifecycle
  description: Test complete clash lifecycle — init, doctor, use, uninstall, verify

steps:
  # Phase 1: Init
  - name: clash init installs hooks
    command: "init --no-import"
    expect:
      exit_code: 0
      files:
        - path: ".claude/settings.json"
          exists: true
          regex: "clash"

  # Phase 2: Doctor confirms healthy
  - name: doctor reports healthy
    command: "doctor"
    expect:
      exit_code: 0
      not:
        stderr_contains: "error"

  # Phase 3: Use — write policy, invoke hook
  - name: write a deny-all policy
    shell: |
      mkdir -p $HOME/.clash
      cat > $HOME/.clash/policy.star << 'POLICY'
      load("@clash//std.star", "when", "policy", "settings", "allow", "deny")
      settings(default=deny())
      policy("test", rules=[when({"Read": allow()})])
      POLICY
    expect:
      exit_code: 0

  - name: Read allowed by policy
    hook: pre-tool-use
    tool_name: Read
    tool_input:
      file_path: /tmp/test.txt
    expect:
      decision: allow

  - name: Bash denied by default deny
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      decision: deny

  # Phase 4: Uninstall
  - name: clash uninstall removes hooks
    command: "uninstall --yes"
    expect:
      exit_code: 0

  # Phase 5: Verify cleanup
  - name: settings file exists but clash hooks removed
    shell: "true"
    expect:
      exit_code: 0
      files:
        - path: ".claude/settings.json"
          exists: true
          not:
            contains: "clash hook"
```

- [ ] **Step 2: Run it**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/init/init_full_lifecycle.yaml -v`
Expected: PASS (adjust assertions based on actual clash behavior if needed)

- [ ] **Step 3: Write the idempotent init test**

Create `clester/tests/scripts/init/init_idempotent.yaml`:

```yaml
meta:
  name: init idempotent
  description: Running clash init twice does not break the installation

steps:
  - name: first init
    command: "init --no-import"
    expect:
      exit_code: 0

  - name: second init
    command: "init --no-import"
    expect:
      exit_code: 0

  - name: doctor still healthy after double init
    command: "doctor"
    expect:
      exit_code: 0
      not:
        stderr_contains: "error"
```

- [ ] **Step 4: Write the preserves-existing-settings test**

Create `clester/tests/scripts/init/init_preserves_existing.yaml`:

```yaml
meta:
  name: init preserves existing settings
  description: clash init does not clobber pre-existing user settings

settings:
  user:
    permissions:
      allow:
        - "Read"
        - "Glob"

steps:
  - name: verify pre-existing settings
    shell: "true"
    expect:
      exit_code: 0
      files:
        - path: ".claude/settings.json"
          exists: true
          contains: "Read"

  - name: run init
    command: "init --no-import"
    expect:
      exit_code: 0

  - name: pre-existing permissions still present
    shell: "true"
    expect:
      exit_code: 0
      files:
        - path: ".claude/settings.json"
          exists: true
          contains: "Read"
          contains: "clash"
```

- [ ] **Step 5: Write the multi-agent init test**

Create `clester/tests/scripts/init/init_multi_agent.yaml`:

```yaml
meta:
  name: init multi-agent
  description: Test clash init with different agent flags

steps:
  - name: init for gemini
    command: "init --agent gemini --no-import"
    expect:
      exit_code: 0

  - name: init for codex
    command: "init --agent codex --no-import"
    expect:
      exit_code: 0

  - name: init for default (claude)
    command: "init --no-import"
    expect:
      exit_code: 0
```

- [ ] **Step 6: Run all init tests**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/init/ -v`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add clester/tests/scripts/init/
git commit -m "test(clester): add init lifecycle, idempotent, and preserves-existing tests"
```

---

### Task 8: Non-Happy-Path Tests — Malformed Input

**Files:**
- Create: `clester/tests/scripts/error/error_invalid_starlark.yaml`
- Create: `clester/tests/scripts/error/error_invalid_hook_json.yaml`
- Create: `clester/tests/scripts/error/error_empty_policy.yaml`

- [ ] **Step 1: Write invalid Starlark test**

Create `clester/tests/scripts/error/error_invalid_starlark.yaml`:

```yaml
meta:
  name: error — invalid starlark syntax
  description: Malformed starlark policy produces a clear error, not a panic

clash:
  policy_star: |
    this is not valid starlark {{{{
    def broken(
    settings(default=

steps:
  - name: hook with broken policy
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      exit_code: 1
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 2: Write invalid hook JSON test**

Create `clester/tests/scripts/error/error_invalid_hook_json.yaml`:

```yaml
meta:
  name: error — invalid hook JSON
  description: Piping invalid JSON to a hook produces a clear error

steps:
  - name: invoke hook with garbage input
    shell: "echo 'not json {{{' | $CLASH_BIN hook pre-tool-use"
    expect:
      exit_code: 1
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

Note: This test uses `shell` to pipe raw input. The shell step needs `$CLASH_BIN` available — verify that the test environment exports this, or use the full path. If `CLASH_BIN` is not available in shell steps, we may need to add it to the environment setup (a small change to `runner.rs`'s `run_shell` to set `CLASH_BIN` env var).

- [ ] **Step 3: Write empty policy test**

Create `clester/tests/scripts/error/error_empty_policy.yaml`:

```yaml
meta:
  name: error — empty policy file
  description: An empty starlark policy file is handled gracefully

clash:
  policy_star: ""

steps:
  - name: hook with empty policy
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 4: Run the error tests and adjust assertions as needed**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/error/ -v`
Expected: All pass. Adjust exit codes and error message patterns based on actual clash behavior.

- [ ] **Step 5: Commit**

```bash
git add clester/tests/scripts/error/
git commit -m "test(clester): add malformed input error tests (invalid starlark, bad JSON, empty policy)"
```

---

### Task 9: Non-Happy-Path Tests — Missing/Conflicting State

**Files:**
- Create: `clester/tests/scripts/error/error_no_policy.yaml`
- Create: `clester/tests/scripts/error/error_conflicting_policies.yaml`
- Create: `clester/tests/scripts/error/error_corrupted_settings.yaml`
- Create: `clester/tests/scripts/error/error_missing_home.yaml`

- [ ] **Step 1: Write no-policy test**

Create `clester/tests/scripts/error/error_no_policy.yaml`:

```yaml
meta:
  name: error — no policy file
  description: Hooks work sensibly when no policy file exists

steps:
  - name: hook with no policy
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 2: Write conflicting policies test**

Create `clester/tests/scripts/error/error_conflicting_policies.yaml`:

```yaml
meta:
  name: error — conflicting user and project policies
  description: When user allows and project denies, project takes precedence

clash:
  policy_star: |
    load("@clash//std.star", "when", "policy", "settings", "allow", "deny")
    settings(default=allow())
    policy("user-policy", rules=[
        when({"Bash": allow()}),
    ])
  project_policy_star: |
    load("@clash//std.star", "when", "policy", "settings", "allow", "deny")
    settings(default=deny())
    policy("project-policy", rules=[
        when({"Bash": deny()}),
    ])

steps:
  - name: project deny overrides user allow
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      decision: deny
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 3: Write corrupted settings test**

Create `clester/tests/scripts/error/error_corrupted_settings.yaml`:

```yaml
meta:
  name: error — corrupted settings.json
  description: Clash handles corrupted settings gracefully

steps:
  - name: write corrupted settings
    shell: |
      mkdir -p $HOME/.claude
      echo '{"broken json {{{{' > $HOME/.claude/settings.json
    expect:
      exit_code: 0

  - name: doctor with corrupted settings
    command: "doctor"
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 4: Write missing home directories test**

Create `clester/tests/scripts/error/error_missing_home.yaml`:

```yaml
meta:
  name: error — missing home directories
  description: Clash commands work when expected directories do not exist

steps:
  - name: remove .claude directory
    shell: "rm -rf $HOME/.claude"
    expect:
      exit_code: 0

  - name: remove .clash directory
    shell: "rm -rf $HOME/.clash"
    expect:
      exit_code: 0

  - name: status with missing dirs
    command: "status"
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"

  - name: hook with missing dirs
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 5: Run and adjust**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/error/ -v`
Expected: All pass. Adjust assertions based on actual behavior.

- [ ] **Step 6: Commit**

```bash
git add clester/tests/scripts/error/
git commit -m "test(clester): add missing/conflicting state error tests"
```

---

### Task 10: Non-Happy-Path Tests — CLI Misuse

**Files:**
- Create: `clester/tests/scripts/error/error_bad_flags.yaml`
- Create: `clester/tests/scripts/error/error_before_init.yaml`
- Create: `clester/tests/scripts/error/error_double_uninstall.yaml`
- Create: `clester/tests/scripts/error/error_sandbox_not_found.yaml`

- [ ] **Step 1: Write bad flags test**

Create `clester/tests/scripts/error/error_bad_flags.yaml`:

```yaml
meta:
  name: error — invalid CLI flags
  description: Invalid arguments produce helpful errors

steps:
  - name: policy allow with no arguments
    command: "policy allow"
    expect:
      exit_code: 2
      not:
        stderr_regex: "panic|RUST_BACKTRACE"

  - name: sandbox create with no name
    command: "sandbox create"
    expect:
      exit_code: 2
      not:
        stderr_regex: "panic|RUST_BACKTRACE"

  - name: unknown subcommand
    command: "notacommand"
    expect:
      exit_code: 2
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 2: Write before-init test**

Create `clester/tests/scripts/error/error_before_init.yaml`:

```yaml
meta:
  name: error — commands before init
  description: Running clash commands before init gives clear guidance

steps:
  - name: policy list before init
    command: "policy list"
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"

  - name: hook before init
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: echo hello
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 3: Write double uninstall test**

Create `clester/tests/scripts/error/error_double_uninstall.yaml`:

```yaml
meta:
  name: error — double uninstall
  description: Uninstalling when not installed is handled gracefully

steps:
  - name: uninstall when never installed
    command: "uninstall --yes"
    expect:
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 4: Write sandbox not found test**

Create `clester/tests/scripts/error/error_sandbox_not_found.yaml`:

```yaml
meta:
  name: error — sandbox not found
  description: Operating on nonexistent sandbox gives clear error

steps:
  - name: delete nonexistent sandbox
    command: "sandbox delete nonexistent_sandbox_12345"
    expect:
      exit_code: 1
      stderr_contains: "not found"
      not:
        stderr_regex: "panic|RUST_BACKTRACE"
```

- [ ] **Step 5: Run all error tests**

Run: `cargo build --bins && ./target/debug/clester run clester/tests/scripts/error/ -v`
Expected: All pass. Adjust exit codes and error patterns based on actual behavior.

- [ ] **Step 6: Commit**

```bash
git add clester/tests/scripts/error/
git commit -m "test(clester): add CLI misuse error tests (bad flags, before init, double uninstall, missing sandbox)"
```

---

### Task 11: Final Verification and Cleanup

**Files:**
- Possibly modify: test scripts if adjustments needed

- [ ] **Step 1: Run full test suite in parallel**

Run: `just clester`
Expected: All tests pass

- [ ] **Step 2: Run `just check` for unit tests and linting**

Run: `just check`
Expected: All pass, no clippy warnings in clester code

- [ ] **Step 3: Run `just ci` for full CI**

Run: `just ci`
Expected: All pass

- [ ] **Step 4: Verify parallel speedup**

Run both modes and compare:
```bash
time ./target/debug/clester run clester/tests/scripts/ -j 1
time ./target/debug/clester run clester/tests/scripts/ -j 0
```
Expected: Parallel mode is measurably faster with the expanded test suite

- [ ] **Step 5: Commit any final adjustments**

```bash
git add -A
git commit -m "chore(clester): final test adjustments after full suite verification"
```
