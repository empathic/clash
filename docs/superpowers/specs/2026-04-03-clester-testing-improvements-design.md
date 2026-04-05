# Clester Testing Improvements Design

## Summary

Three improvements to the clester end-to-end test harness:

1. **Parallel test execution** via Rayon
2. **Enhanced assertion DSL** with regex matching, filesystem assertions, and combinators
3. **New test scripts** for init/onboarding lifecycle and non-happy-path scenarios

## Current State

- 16 test scripts, all run serially in a single-threaded loop
- 1 init test (`init_no_import.yaml`), no full lifecycle coverage
- Almost entirely happy-path tests
- Assertions limited to: `exit_code`, `decision`, `reason_contains`, `stdout_contains`, `stderr_contains`

## 1. Parallel Test Execution

### Runner Changes

Replace the serial `for script in scripts` loop with Rayon's `par_iter`. Each script runs in its own thread with its own `TestEnvironment` (already isolated via temp dirs).

### Output Buffering

Each script captures its step results into a `Vec<StepResult>` instead of printing inline. After all scripts complete, results are printed in the original alphabetical order.

### CLI Control

Add a `--jobs` / `-j` flag to `clester run`:

- `-j 0` (default): auto-detect cores via Rayon
- `-j 1`: serial execution (useful for debugging)
- `-j N`: explicit thread count

### Failure Handling

If any script panics or crashes, Rayon catches it. The result is recorded as a script-level failure rather than aborting the entire run.

### Summary Output

After all scripts finish, print a structured summary:

```
16 scripts, 87 steps — 85 passed, 2 failed (3.2s)

FAILED:
  star_basic_exec.yaml → step 3 "deny git push": expected deny, got allow
  init_lifecycle.yaml → step 5 "verify cleanup": file still exists: .claude/settings.json
```

## 2. Assertion DSL

### Backward Compatibility

Existing `expect` fields (`decision`, `exit_code`, `reason_contains`, `stdout_contains`, `stderr_contains`) continue to work unchanged. New features layer on top.

### Regex Matching

New fields alongside the existing substring ones:

```yaml
expect:
  stdout_regex: "^Policy loaded: \\d+ rules$"
  stderr_regex: "error:.*invalid syntax"
  reason_regex: "denied by .+ rule"
```

### Filesystem Assertions

New `files` block under `expect`, checked against the test environment's HOME/project dirs:

```yaml
expect:
  files:
    - path: ".claude/settings.json"
      exists: true
      contains: "clash"            # substring
      regex: "\"version\":\\s*\"\\d+"  # regex
    - path: ".claude/hooks.json"
      exists: false                # assert file was removed
```

Paths are relative to the test environment's HOME by default. A `root: project` field on the entry switches to the project dir.

### Combinators — `all_of`, `any_of`, `not`

```yaml
expect:
  all_of:
    - stdout_contains: "initialized"
    - exit_code: 0
    - files:
        - path: ".claude/settings.json"
          exists: true

  any_of:
    - stderr_contains: "already initialized"
    - stderr_contains: "skipping"

  not:
    stdout_contains: "error"
```

**Semantics:**

- Top-level `expect` fields are implicitly `all_of` (all must pass — same as today)
- `any_of` passes if at least one child passes
- `not` inverts a single assertion
- Combinators nest arbitrarily
- `not` at the top level covers the `stdout_not_contains` use case without dedicated fields
- Within a `files` entry, `not` scopes to that file's content assertions (e.g., `not: { contains: "clash" }` means the file must NOT contain "clash")
- At the `expect` level, `not` scopes to output/decision assertions

## 3. Init/Onboarding Lifecycle Tests

### Full Lifecycle Test (`init_full_lifecycle.yaml`)

Exercises the complete init → use → uninstall flow:

```yaml
meta:
  name: init_full_lifecycle
  description: Test full clash lifecycle from init through uninstall

steps:
  # Phase 1: Init
  - name: clash init installs hooks
    command: "init --no-import"
    expect:
      exit_code: 0
      files:
        - path: ".claude/settings.json"
          exists: true
          regex: "clash hook"

  # Phase 2: Doctor confirms healthy
  - name: doctor reports healthy
    command: "doctor"
    expect:
      exit_code: 0
      stdout_contains: "healthy"
      not:
        stdout_contains: "error"

  # Phase 3: Use it — policy + hook
  - name: set up a policy
    shell: "cat > policy.star << 'EOF'\npolicy(default='deny')\nEOF"
  - name: hook respects policy
    hook: pre-tool-use
    tool_name: Bash
    tool_input: { "command": "rm -rf /" }
    expect:
      decision: deny

  # Phase 4: Uninstall
  - name: clash uninstall cleans up
    command: "uninstall --yes"
    expect:
      exit_code: 0
      files:
        - path: ".claude/settings.json"
          exists: true
          not:
            contains: "clash"

  # Phase 5: Verify post-uninstall state
  - name: doctor reports not installed
    command: "doctor"
    expect:
      exit_code: 1
      any_of:
        - stderr_contains: "not installed"
        - stdout_contains: "not installed"
```

### Additional Init Scripts

- `init_idempotent.yaml` — running `clash init` twice doesn't break things
- `init_preserves_existing.yaml` — init doesn't clobber pre-existing user settings
- `init_multi_agent.yaml` — test `clash init --agent gemini` and other agent variants

## 4. Non-Happy-Path Test Scripts

### A. Malformed Input

- `error_invalid_starlark.yaml` — Starlark policy with syntax errors → `exit_code: 1`, `stderr_regex` matching parse error
- `error_invalid_hook_json.yaml` — garbage JSON piped to `clash hook pre-tool-use` → graceful error, not a panic
- `error_empty_policy.yaml` — empty `.star` file → graceful no-op or clear error

### B. Missing/Conflicting State

- `error_no_policy.yaml` — invoke hooks with no policy file → sensible default behavior, not a crash
- `error_conflicting_policies.yaml` — user allows, project denies same tool → verify precedence holds, output explains which won
- `error_corrupted_settings.yaml` — invalid JSON in `.claude/settings.json`, then `clash doctor` → diagnostic error, not crash
- `error_missing_home.yaml` — clash commands when expected directories don't exist

### C. CLI Misuse

- `error_bad_flags.yaml` — invalid flags/args to `clash policy allow`, `clash sandbox create` → non-zero exit, helpful error
- `error_before_init.yaml` — `clash hook pre-tool-use` and `clash policy list` before `clash init` → clear "not initialized" guidance
- `error_double_uninstall.yaml` — `clash uninstall` when not installed → graceful handling
- `error_sandbox_not_found.yaml` — `clash sandbox delete nonexistent` → clear error

### Cross-Cutting Assertions

All error tests should verify:
- No `panic` or `RUST_BACKTRACE` in stdout/stderr
- Error messages are human-readable (not raw Rust debug output)
- Exit codes are non-zero for actual errors

## Dependencies

- `rayon` crate added to workspace `Cargo.toml`
- `regex` crate (likely already a transitive dependency)

## Test Organization

```
clester/tests/scripts/
├── error/                    # Non-happy-path tests
│   ├── error_bad_flags.yaml
│   ├── error_before_init.yaml
│   ├── error_conflicting_policies.yaml
│   ├── error_corrupted_settings.yaml
│   ├── error_double_uninstall.yaml
│   ├── error_empty_policy.yaml
│   ├── error_invalid_hook_json.yaml
│   ├── error_invalid_starlark.yaml
│   ├── error_missing_home.yaml
│   ├── error_no_policy.yaml
│   └── error_sandbox_not_found.yaml
├── init/                     # Init/onboarding lifecycle
│   ├── init_full_lifecycle.yaml
│   ├── init_idempotent.yaml
│   ├── init_multi_agent.yaml
│   └── init_preserves_existing.yaml
├── ecosystem_sandboxes.yaml  # Existing tests (unchanged)
├── init_no_import.yaml
├── sandbox_cli.yaml
├── star_*.yaml
└── ...
```
