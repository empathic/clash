# Interactive Shell Policy Feedback — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give interactive shell users actionable policy feedback — hash-based prompts, specific `clash policy allow|deny <hash>` commands, and per-command policy reload.

**Architecture:** The `ExternalCommandHook` type gains a `Block` variant. The shell hook enforces deny decisions and writes audit entries so hashes are meaningful. A shared `LastDecision` state flows from the hook to the prompt. The CLI gains hash-based argument parsing for `allow`/`deny` with confirmation dialogs. Policy is reloaded before each command.

**Tech Stack:** Rust, brush shell (clash-brush-core, clash-brush-interactive), clap CLI, serde_json

---

### Task 1: Change ExternalCommandHook to support blocking commands

The current `ExternalCommandHook` returns `Option<(String, Vec<String>)>` — it can only passthrough or rewrite. It cannot block. We need an enum.

**Files:**
- Modify: `clash-brush-core/src/shell.rs:10-15`
- Modify: `clash-brush-core/src/commands.rs:576-587`
- Modify: `clash-brush-core/src/lib.rs:60`
- Modify: `clash/src/shell_cmd.rs` (update all return sites)

- [ ] **Step 1: Define `ExternalCommandAction` enum in `clash-brush-core/src/shell.rs`**

Replace the type alias and add the enum before it (around line 10-15):

```rust
/// Result of an external command hook evaluation.
#[derive(Debug)]
pub enum ExternalCommandAction {
    /// Run the command as-is (hook doesn't apply).
    Passthrough,
    /// Replace with a different command and arguments.
    Replace(String, Vec<String>),
    /// Block the command entirely. The string is a user-facing message (already printed to stderr by the hook).
    Block,
}

/// Hook called before spawning an external command. Receives the executable
/// path and string arguments. Returns an action: passthrough, replace, or block.
pub type ExternalCommandHook =
    Arc<dyn Fn(&str, &[String]) -> ExternalCommandAction + Send + Sync>;
```

- [ ] **Step 2: Update `clash-brush-core/src/lib.rs` exports (line 60)**

Add `ExternalCommandAction` to the re-export:

```rust
    CreateOptions, ExternalCommandAction, ExternalCommandHook, ProfileLoadBehavior, RcLoadBehavior, Shell, ShellBuilder,
```

- [ ] **Step 3: Update command dispatch in `clash-brush-core/src/commands.rs:576-587`**

Replace the hook handling block. You'll need `use std::io::Write as _;` at the top if not already present:

```rust
    let (effective_exe, hooked_args) = if let Some(hook) = context.shell.external_command_hook() {
        match hook(executable_path, &cmd_arg_strings) {
            crate::ExternalCommandAction::Replace(new_exe, new_args) => {
                (new_exe, Some(new_args))
            }
            crate::ExternalCommandAction::Block => {
                return Ok(crate::ExecutionResult::new(
                    crate::ExecutionExitCode::Custom(77),
                ));
            }
            crate::ExternalCommandAction::Passthrough => {
                (executable_path.to_string(), None)
            }
        }
    } else {
        (executable_path.to_string(), None)
    };
```

Note: The hook itself handles printing the denial message to stderr (not brush-core). Exit code 77 signals "blocked by policy" to the caller.

- [ ] **Step 4: Update `make_sandbox_hook` return values in `clash/src/shell_cmd.rs`**

Change all return sites to use the new enum. The function signature return type changes from `clash_brush_core::ExternalCommandHook` (same type alias, no change needed there). But the closure return type changes:

- `return None;` → `return clash_brush_core::ExternalCommandAction::Passthrough;`
- `Some(("sandbox-exec".to_string(), new_args))` → `clash_brush_core::ExternalCommandAction::Replace("sandbox-exec".to_string(), new_args)`

There are 3 `return None` sites (lines 101, 133, 171) and 1 `Some(...)` site (line 182).

- [ ] **Step 5: Update tests in `clash/src/shell_cmd.rs`**

Tests check `hook()` return values. Update to match new enum:

For `hook_wraps_with_sandbox_exec_directly`:
```rust
let result = hook("/usr/bin/git", &["push".to_string()]);
let (exe, args) = match result {
    clash_brush_core::ExternalCommandAction::Replace(exe, args) => (exe, args),
    other => panic!("expected Replace, got {other:?}"),
};
```

For `hook_returns_none_on_linux` and `hook_returns_none_without_sandbox`:
```rust
assert!(matches!(result, clash_brush_core::ExternalCommandAction::Passthrough));
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p clash-brush-core -p clash`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add clash-brush-core/src/shell.rs clash-brush-core/src/commands.rs clash-brush-core/src/lib.rs clash/src/shell_cmd.rs
git commit -m "refactor(shell): replace ExternalCommandHook Option with ExternalCommandAction enum

Adds Block variant so the hook can deny commands, not just rewrite them."
```

---

### Task 2: Make `log_decision` return the audit hash

Currently `log_decision` returns nothing. We need the hash of the entry it writes so the shell hook can use it for prompts and deny hints.

**Files:**
- Modify: `clash/src/audit.rs:282-332` (log_decision)
- Modify: `clash/src/debug/mod.rs:48-58` (extract hash computation)
- Modify: `clash/src/permissions.rs:79-88` (call site)

- [ ] **Step 1: Extract hash computation to a standalone function in `clash/src/debug/mod.rs`**

Add after the `short_hash` method (around line 59):

```rust
/// Compute the 7-character short hash from its component parts.
///
/// Same algorithm as `AuditLogEntry::short_hash()` — factored out so callers
/// that don't have a full entry can still produce a matching hash.
pub fn compute_short_hash(timestamp: &str, tool_name: &str, tool_input_summary: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    timestamp.hash(&mut hasher);
    tool_name.hash(&mut hasher);
    tool_input_summary.hash(&mut hasher);
    format!("{:07x}", hasher.finish() & 0x0FFF_FFFF)
}
```

Update `AuditLogEntry::short_hash` to delegate:

```rust
pub fn short_hash(&self) -> String {
    compute_short_hash(&self.timestamp, &self.tool_name, &self.tool_input_summary)
}
```

- [ ] **Step 2: Make `log_decision` return the hash**

Change the signature in `clash/src/audit.rs` (line 282):

```rust
pub fn log_decision(
    config: &AuditConfig,
    session_id: &str,
    tool_name: &str,
    tool_input: &serde_json::Value,
    effect: Effect,
    reason: Option<&str>,
    trace: &DecisionTrace,
    mode: Option<&str>,
) -> String {
```

At the end of the function (before the closing brace), add:

```rust
    crate::debug::compute_short_hash(&entry.timestamp, tool_name, &entry.tool_input_summary)
```

Note: `entry.timestamp` is already computed at line 307. `entry.tool_input_summary` is computed at lines 293-304. Both are available at the end of the function.

- [ ] **Step 3: Update call site in `clash/src/permissions.rs:79-88`**

Change from:

```rust
    crate::audit::log_decision(
        &settings.audit,
        &input.session_id,
        ...
    );
```

To:

```rust
    let _audit_hash = crate::audit::log_decision(
        &settings.audit,
        &input.session_id,
        ...
    );
```

The `_` prefix silences the unused warning — we'll use this hash later when improving hook feedback (Task 8).

- [ ] **Step 4: Run tests**

Run: `cargo test -p clash`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/audit.rs clash/src/debug/mod.rs clash/src/permissions.rs
git commit -m "refactor(audit): return short hash from log_decision

Extracts compute_short_hash() so callers can get the hash without
reading back from the audit log."
```

---

### Task 3: Add deny enforcement and shared decision state to the shell hook

The hook now enforces deny decisions (blocks the command) and writes audit log entries. A shared `LastDecision` state lets the prompt show the hash and effect.

**Files:**
- Modify: `clash/src/shell_cmd.rs`

- [ ] **Step 1: Add `LastDecision` type and imports at the top of `clash/src/shell_cmd.rs`**

After the existing imports (around line 20), add:

```rust
use crate::debug::compute_short_hash;
use crate::policy::Effect;

/// Last policy decision made by the shell hook — read by the prompt renderer.
#[derive(Debug, Clone)]
pub struct LastDecision {
    /// 7-char audit log hash identifying this evaluation.
    pub hash: String,
    /// The policy effect (allow/deny/ask).
    pub effect: Effect,
    /// The full command string (e.g. "git push origin main").
    pub command: String,
}

/// Thread-safe shared state for the prompt to read the last decision.
pub type SharedDecision = Arc<std::sync::Mutex<Option<LastDecision>>>;
```

- [ ] **Step 2: Update `make_sandbox_hook` to accept new parameters**

Change the signature:

```rust
fn make_sandbox_hook(
    policy: Arc<CompiledPolicy>,
    default_sandbox: Option<SandboxPolicy>,
    debug: bool,
    audit_config: crate::audit::AuditConfig,
    session_id: String,
    last_decision: SharedDecision,
) -> clash_brush_core::ExternalCommandHook {
```

- [ ] **Step 3: Add audit logging and deny enforcement inside the hook closure**

After `let decision = policy.evaluate("Bash", &tool_input);` (currently line 117), and before the sandbox handling, add:

```rust
        // Write audit log entry so the hash is meaningful for `clash policy allow <hash>`.
        let audit_hash = crate::audit::log_decision(
            &audit_config,
            &session_id,
            "Bash",
            &tool_input,
            decision.effect,
            decision.reason.as_deref(),
            &decision.trace,
            None,
        );

        // Update shared state for the prompt.
        if let Ok(mut guard) = last_decision.lock() {
            *guard = Some(LastDecision {
                hash: audit_hash.clone(),
                effect: decision.effect,
                command: command_str.clone(),
            });
        }

        // Block denied commands with actionable hints.
        if decision.effect == Effect::Deny {
            let noun = if command_str.len() > 60 {
                format!("{}...", &command_str[..60])
            } else {
                command_str.clone()
            };
            eprintln!(
                "{} blocked shell on {}",
                "\x1b[1;31mclash:\x1b[0m",
                noun,
            );
            eprintln!(
                "  clash policy allow {}          # allow this exact command",
                audit_hash,
            );
            // Show --broad hint only when there are trailing args to glob.
            let parts: Vec<&str> = command_str.split_whitespace().collect();
            if parts.len() > 2 {
                eprintln!(
                    "  clash policy allow {} --broad  # allow all {}",
                    audit_hash,
                    parts[..2].join(" "),
                );
            }
            return clash_brush_core::ExternalCommandAction::Block;
        }
```

- [ ] **Step 4: Update `run_shell` to create session and shared state**

In `run_shell()` (line 187), after loading the policy and before creating the hook:

```rust
    // Create a shell session for audit logging.
    let session_id = format!("shell-{}", uuid_v4_short());
    let _ = crate::audit::init_session(&session_id, &cwd, Some("clash-shell"), None);

    let last_decision: SharedDecision = Arc::new(std::sync::Mutex::new(None));
```

Add a helper for generating a short session ID:

```rust
fn uuid_v4_short() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{:x}-{:03x}", d.as_secs() & 0xFFFF_FFFF, d.subsec_millis())
}
```

Update the `make_sandbox_hook` call to pass the new arguments:

```rust
    let hook = make_sandbox_hook(
        Arc::new(policy),
        default_sandbox,
        debug,
        settings.audit.clone(),
        session_id,
        last_decision.clone(),
    );
```

For the interactive path, also pass `last_decision` to `run_interactive`:

```rust
    rt.block_on(async {
        if let Some(ref cmd) = command {
            run_command_string(cmd, &cwd, hook).await
        } else if !script_args.is_empty() {
            run_script(&script_args, &cwd, hook).await
        } else {
            run_interactive(&cwd, hook, last_decision).await
        }
    })
```

- [ ] **Step 5: Update `run_interactive` signature**

```rust
async fn run_interactive(
    cwd: &str,
    hook: clash_brush_core::ExternalCommandHook,
    last_decision: SharedDecision,
) -> Result<()> {
```

Store `last_decision` for later use (Task 4 will use it in the prompt). For now just accept the parameter.

- [ ] **Step 6: Run tests**

Run: `cargo test -p clash`
Expected: PASS (existing tests may need `audit_config`, `session_id`, and `last_decision` args added to `make_sandbox_hook` calls in tests)

Update `test_hook()` in tests:

```rust
fn test_hook() -> clash_brush_core::ExternalCommandHook {
    let last_decision = Arc::new(std::sync::Mutex::new(None));
    make_sandbox_hook(
        test_policy(),
        None,
        false,
        crate::audit::AuditConfig::default(),
        "test-session".to_string(),
        last_decision,
    )
}
```

- [ ] **Step 7: Add a test for deny enforcement**

```rust
#[test]
fn hook_blocks_denied_commands() {
    use clash_starlark::codegen::ast::Stmt;
    use clash_starlark::codegen::builder::*;

    // Policy that denies everything.
    let source = clash_starlark::codegen::serialize(&[
        load_std(&["deny", "policy", "settings"]),
        Stmt::Expr(settings(deny(), None)),
        Stmt::Expr(policy("test", deny(), vec![], None)),
    ]);
    let policy = Arc::new(compile_star(&source));
    let last_decision: SharedDecision = Arc::new(std::sync::Mutex::new(None));
    let hook = make_sandbox_hook(
        policy,
        None,
        false,
        crate::audit::AuditConfig::default(),
        "test-deny".to_string(),
        last_decision.clone(),
    );

    let result = hook("/usr/bin/git", &["push".to_string()]);
    assert!(
        matches!(result, clash_brush_core::ExternalCommandAction::Block),
        "denied command should be blocked"
    );

    // Shared state should reflect the denial.
    let decision = last_decision.lock().unwrap();
    let d = decision.as_ref().expect("should have a decision");
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.command, "git push");
}
```

- [ ] **Step 8: Run tests**

Run: `cargo test -p clash`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add clash/src/shell_cmd.rs
git commit -m "feat(shell): enforce deny decisions and log audit entries in interactive shell

The shell hook now blocks denied commands with actionable hints
(clash policy allow <hash>) and writes audit entries so hashes
are meaningful for policy mutations."
```

---

### Task 4: Prompt integration — show hash and decision indicator

After each command, the prompt shows `clash[hash:✓/✗/?] $` with color.

**Files:**
- Modify: `clash/src/shell_cmd.rs` (run_interactive — set PS1 variable)

- [ ] **Step 1: Set initial PS1 in `run_interactive`**

After building the shell and registering builtins (around line 332), before creating the `InteractiveShell`, set the PS1 env var:

```rust
    // Set the clash-shell prompt (no decision yet).
    shell.env.set("PS1", "clash \\$ ", false)?;
```

Note: `\\$` is the bash prompt escape for `$` (shows `#` for root).

- [ ] **Step 2: Add a `PROMPT_COMMAND` that updates PS1 from shared state**

We can't easily use PROMPT_COMMAND since it's a shell command string. Instead, we'll update PS1 directly before each prompt by hooking into the REPL loop.

The better approach: after each command execution in `run_interactive`, update the PS1 env var on the shell based on `last_decision`.

However, `run_interactive` currently just calls `interactive.run_interactively()` which is a loop we don't control iteration of.

**Alternative approach:** Use a custom wrapper around the REPL loop. Instead of calling `run_interactively()`, call `run_interactively_once()` in our own loop, updating PS1 between iterations.

But `run_interactively_once` is not `pub` — it's a private method on `InteractiveShell`.

**Simplest approach:** Make the `LastDecision` state available to the shell as an environment variable, and use a PS1 that references it. But PS1 expansion happens through bash prompt escapes, not arbitrary functions.

**Pragmatic approach:** Use `precmd_functions` (zsh-style, supported by brush). Register a Rust-side callback that updates PS1 before each prompt.

Actually, the cleanest approach is to add a `pre_prompt_hook` to `InteractiveShell` or `InteractiveOptions` — a callback that runs before each prompt composition. But that requires changing brush-interactive.

**Let's go with the simplest working approach:** Export `run_interactively_once` as public, and drive the loop from `run_interactive` in `shell_cmd.rs`. This gives us full control.

- [ ] **Step 3: Make `run_interactively_once` and related methods public**

In `clash-brush-interactive/src/interactive_shell.rs`, change:

```rust
// Line 187: change from
async fn run_interactively_once(
// to
pub async fn run_interactively_once(
```

Also need to make the pre/post loop methods callable. Looking at `run_interactively()` (lines 118-184), it does:
1. `shell.start_interactive_session()` (line 124)
2. Loop calling `run_interactively_once()` (lines 128-162)
3. `shell.end_interactive_session()` (line 165)
4. Save history (line 172)
5. `shell.on_exit()` (line 179)

We need startup/shutdown helpers. Add:

```rust
/// Initialize the interactive session (call before the first `run_interactively_once`).
pub async fn start(&mut self) -> Result<(), ShellError> {
    let mut shell = self.shell.lock().await;
    shell.start_interactive_session()?;
    Ok(())
}

/// Finalize the interactive session (call after the loop ends).
pub async fn finish(&mut self) -> Result<(), ShellError> {
    let mut shell = self.shell.lock().await;
    shell.end_interactive_session()?;
    // Try to save history.
    if let Err(e) = shell.save_history().await {
        tracing::warn!("Failed to save history: {e}");
    }
    let exit_code = shell.last_exit_status();
    drop(shell);
    let mut shell = self.shell.lock().await;
    shell.on_exit(exit_code);
    Ok(())
}
```

- [ ] **Step 4: Drive the REPL loop from `run_interactive` in `shell_cmd.rs`**

Replace the current `run_interactive` implementation:

```rust
async fn run_interactive(
    cwd: &str,
    hook: clash_brush_core::ExternalCommandHook,
    last_decision: SharedDecision,
) -> Result<()> {
    info!("starting interactive shell with sandbox hook");

    let mut shell = clash_brush_core::Shell::builder()
        .interactive(true)
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .shell_name("clash-shell".to_string())
        .profile(clash_brush_core::ProfileLoadBehavior::Skip)
        .rc(clash_brush_core::RcLoadBehavior::Skip)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

    register_builtins(&mut shell);

    // Set initial prompt (no decision yet).
    let _ = shell.env.set("PS1", "clash $ ", false);

    let shell_ref = std::sync::Arc::new(tokio::sync::Mutex::new(shell));

    let mut input = clash_brush_interactive::BasicInputBackend;
    let options = clash_brush_interactive::InteractiveOptions::default();

    let mut interactive =
        clash_brush_interactive::InteractiveShell::new(&shell_ref, &mut input, &options)
            .map_err(|e| anyhow::anyhow!("failed to create interactive shell: {e}"))?;

    // Startup banner.
    eprintln!(
        "{}",
        "\x1b[2mRun `clash policy allow|deny <id>` to change policy for any command.\x1b[0m"
    );

    interactive.start().await
        .map_err(|e| anyhow::anyhow!("failed to start interactive session: {e}"))?;

    loop {
        // Update prompt based on last decision.
        {
            let prompt_str = format_prompt(&last_decision);
            let mut sh = shell_ref.lock().await;
            let _ = sh.env.set("PS1", &prompt_str, false);
        }

        match interactive.run_interactively_once().await {
            Ok(clash_brush_interactive::InteractiveExecutionResult::Eof) => break,
            Ok(clash_brush_interactive::InteractiveExecutionResult::Executed(result)) => {
                if result.exit_code == clash_brush_core::ExecutionExitCode::ExitShell {
                    break;
                }
            }
            Ok(clash_brush_interactive::InteractiveExecutionResult::Failed(_)) => {}
            Err(e) => return Err(anyhow::anyhow!("interactive shell error: {e}")),
        }
    }

    interactive.finish().await
        .map_err(|e| anyhow::anyhow!("failed to finish interactive session: {e}"))?;

    Ok(())
}
```

- [ ] **Step 5: Add `format_prompt` helper**

```rust
/// Format the clash shell prompt based on the last policy decision.
fn format_prompt(last_decision: &SharedDecision) -> String {
    let guard = last_decision.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        None => "clash $ ".to_string(),
        Some(d) => {
            let (symbol, color) = match d.effect {
                Effect::Allow => ("✓", "\x1b[32m"),  // green
                Effect::Deny => ("✗", "\x1b[31m"),   // red
                Effect::Ask => ("?", "\x1b[33m"),     // yellow
            };
            let reset = "\x1b[0m";
            let dim = "\x1b[2m";
            // \x01 and \x02 bracket non-printing chars for readline.
            format!(
                "clash[\x01{dim}\x02{}\x01{reset}\x02:\x01{color}\x02{}\x01{reset}\x02] $ ",
                d.hash, symbol
            )
        }
    }
}
```

- [ ] **Step 6: Export `InteractiveExecutionResult` from `clash-brush-interactive`**

Check that `InteractiveExecutionResult` is public and exported from the crate root so `shell_cmd.rs` can match on it. If not, add `pub use` in `clash-brush-interactive/src/lib.rs`.

- [ ] **Step 7: Build and test manually**

Run: `cargo build -p clash`
Expected: Compiles successfully.

Then test manually:
```bash
cargo run --bin clash -- shell
```
Expected: See `clash $ ` prompt. Run a command, see `clash[hash:✓] $ ` or `clash[hash:✗] $ `.

- [ ] **Step 8: Commit**

```bash
git add clash/src/shell_cmd.rs clash-brush-interactive/src/interactive_shell.rs clash-brush-interactive/src/lib.rs
git commit -m "feat(shell): show policy decision hash and indicator in prompt

The prompt now shows clash[hash:✓/✗/?] after each command, where
the hash is the audit entry ID usable with clash policy allow|deny."
```

---

### Task 5: Policy reload before each command

Reload the policy unconditionally before each command so changes made in another terminal take effect immediately.

**Files:**
- Modify: `clash/src/shell_cmd.rs` (run_interactive loop, make_sandbox_hook)

- [ ] **Step 1: Change `policy` from `Arc<CompiledPolicy>` to reloadable**

The hook closure currently captures `policy: Arc<CompiledPolicy>`. To reload, we need the hook to read from a shared reference that gets updated.

Change the shared policy type:

```rust
type SharedPolicy = Arc<std::sync::RwLock<Arc<CompiledPolicy>>>;
```

In `run_shell`, replace:
```rust
let hook = make_sandbox_hook(Arc::new(policy), ...);
```
with:
```rust
let shared_policy: SharedPolicy = Arc::new(std::sync::RwLock::new(Arc::new(policy)));
let hook = make_sandbox_hook(shared_policy.clone(), ...);
```

- [ ] **Step 2: Update `make_sandbox_hook` to read from shared policy**

Change the first parameter:

```rust
fn make_sandbox_hook(
    shared_policy: SharedPolicy,
    default_sandbox: Option<SandboxPolicy>,
    debug: bool,
    audit_config: crate::audit::AuditConfig,
    session_id: String,
    last_decision: SharedDecision,
) -> clash_brush_core::ExternalCommandHook {
    Arc::new(move |executable_path: &str, args: &[String]| {
        // ... builtin check ...

        let policy = shared_policy.read().unwrap_or_else(|e| e.into_inner());

        let decision = policy.evaluate("Bash", &tool_input);
        // ... rest of logic uses `policy` ...
```

The sandbox resolution also needs the policy for looking up named sandboxes. Since `decision.sandbox` already contains the resolved sandbox, and `default_sandbox` is passed in, this should work without changes to the sandbox lookup.

- [ ] **Step 3: Reload policy in the REPL loop**

In `run_interactive`, before each `run_interactively_once()` call, reload:

```rust
    loop {
        // Reload policy to pick up changes from other terminals.
        if let Ok(fresh_settings) = ClashSettings::load_or_create() {
            if let Some(fresh_policy) = fresh_settings.policy_tree() {
                if let Ok(mut guard) = shared_policy.write() {
                    *guard = Arc::new(fresh_policy.clone());
                }
            }
        }

        // Update prompt...
        // run_interactively_once()...
    }
```

Pass `shared_policy` to `run_interactive`:

```rust
async fn run_interactive(
    cwd: &str,
    hook: clash_brush_core::ExternalCommandHook,
    last_decision: SharedDecision,
    shared_policy: SharedPolicy,
) -> Result<()> {
```

- [ ] **Step 4: Update tests to use SharedPolicy**

Update `test_hook()` and other test helpers:

```rust
fn test_hook() -> clash_brush_core::ExternalCommandHook {
    let last_decision = Arc::new(std::sync::Mutex::new(None));
    let shared_policy: SharedPolicy = Arc::new(std::sync::RwLock::new(test_policy()));
    make_sandbox_hook(
        shared_policy,
        None,
        false,
        crate::audit::AuditConfig::default(),
        "test-session".to_string(),
        last_decision,
    )
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p clash`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add clash/src/shell_cmd.rs
git commit -m "feat(shell): reload policy before each command

Policy is reloaded unconditionally so changes from other terminals
(e.g. clash policy allow <hash>) take effect on the next command."
```

---

### Task 6: Hash-based `clash policy allow|deny <hash>`

Add support for passing an audit log hash as the positional argument to `allow`/`deny`. Includes confirmation dialog and `--broad` flag.

**Files:**
- Modify: `clash/src/cli.rs:89-124` (add --broad and --yes flags)
- Modify: `clash/src/cmd/policy.rs:554-716` (hash resolution + confirm dialog)

- [ ] **Step 1: Add `--broad` and `--yes` flags to CLI structs in `clash/src/cli.rs`**

Add to `PolicyAllow` (after the `scope` field, around line 104):

```rust
    /// Widen the match by dropping trailing arguments and using a glob pattern.
    #[arg(long)]
    broad: bool,
    /// Skip confirmation dialog.
    #[arg(long, short = 'y')]
    yes: bool,
```

Add to `PolicyDeny` (after the `scope` field, around line 123):

```rust
    /// Widen the match by dropping trailing arguments and using a glob pattern.
    #[arg(long)]
    broad: bool,
    /// Skip confirmation dialog.
    #[arg(long, short = 'y')]
    yes: bool,
```

- [ ] **Step 2: Update the dispatch in `cmd/policy.rs` to pass the new flags**

Update `handle_allow` and `handle_deny` signatures to accept the new flags:

```rust
fn handle_allow(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    sandbox: Option<String>,
    scope: Option<String>,
    broad: bool,
    yes: bool,
) -> Result<()> {
```

```rust
fn handle_deny(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
    broad: bool,
    yes: bool,
) -> Result<()> {
```

- [ ] **Step 3: Add hash detection and resolution**

At the top of `handle_allow` (and similarly `handle_deny`), detect if the positional arg looks like a hash (single arg, all hex, 3-7 chars):

```rust
fn handle_allow(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    sandbox: Option<String>,
    scope: Option<String>,
    broad: bool,
    yes: bool,
) -> Result<()> {
    // Detect hash-based invocation: single positional arg that looks like a hex hash.
    if command.len() == 1
        && tool.is_none()
        && bin.is_none()
        && looks_like_hash(&command[0])
    {
        return handle_allow_by_hash(&command[0], sandbox, scope, broad, yes);
    }
    apply_mutation(command, tool, bin, scope, PolicyMutation::Allow { sandbox })
}
```

Add the hash detection helper:

```rust
/// Check if a string looks like an audit log hash (3-7 hex chars).
fn looks_like_hash(s: &str) -> bool {
    (3..=7).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}
```

- [ ] **Step 4: Implement `handle_allow_by_hash`**

```rust
fn handle_allow_by_hash(
    hash: &str,
    sandbox: Option<String>,
    scope: Option<String>,
    broad: bool,
    yes: bool,
) -> Result<()> {
    let entry = crate::debug::log::find_by_hash(hash)
        .context("failed to look up audit entry")?;

    // Parse the command from the tool input summary.
    let (bin_name, args) = extract_command_from_entry(&entry)?;

    let (display_args, rule_args) = if broad && args.len() > 1 {
        // Broad: keep binary + first arg, glob the rest.
        let display = format!("{} {} *", bin_name, args[0]);
        let rule = vec![args[0].as_str(), "*"];
        (display, rule)
    } else if broad && args.len() == 1 {
        // Broad with one arg: glob trailing.
        let display = format!("{} {} *", bin_name, args[0]);
        let rule = vec![args[0].as_str(), "*"];
        (display, rule)
    } else {
        // Exact: use all args.
        let display = if args.is_empty() {
            bin_name.clone()
        } else {
            format!("{} {}", bin_name, args.join(" "))
        };
        let rule: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        (display, rule)
    };

    // Confirmation dialog.
    let scope_label = scope.as_deref().unwrap_or("user");
    eprintln!();
    eprintln!("  Add rule to {} policy:", scope_label);
    eprintln!("    allow exec {}", display_args);
    eprintln!();

    if !yes {
        eprint!("  Proceed? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("  Cancelled.");
            return Ok(());
        }
    }

    let decision = crate::policy::match_tree::Decision::Allow(
        sandbox
            .as_deref()
            .map(|s| crate::policy::match_tree::SandboxRef(s.to_string())),
    );
    let node = manifest_edit::build_exec_rule(&bin_name, &rule_args, decision);

    let path = resolve_manifest_path(scope)?;
    if path.extension().is_some_and(|ext| ext == "star") {
        anyhow::bail!(
            "CLI rule mutations are not yet supported for .star files — use `clash policy edit` instead"
        );
    }
    let mut manifest = crate::policy_loader::read_manifest(&path)?;
    let result = manifest_edit::upsert_rule(&mut manifest, node);
    crate::policy_loader::write_manifest(&path, &manifest)?;

    let result_str = match result {
        manifest_edit::UpsertResult::Inserted => "Rule added",
        manifest_edit::UpsertResult::Replaced => "Rule updated (replaced existing)",
    };
    println!("{} {}", style::green_bold("✓"), result_str);
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}
```

- [ ] **Step 5: Add `handle_deny_by_hash` (similar structure)**

```rust
fn handle_deny_by_hash(
    hash: &str,
    scope: Option<String>,
    broad: bool,
    yes: bool,
) -> Result<()> {
    let entry = crate::debug::log::find_by_hash(hash)
        .context("failed to look up audit entry")?;

    let (bin_name, args) = extract_command_from_entry(&entry)?;

    let (display_args, rule_args) = if broad && !args.is_empty() {
        let display = format!("{} {} *", bin_name, args[0]);
        let rule = vec![args[0].as_str(), "*"];
        (display, rule)
    } else {
        let display = if args.is_empty() {
            bin_name.clone()
        } else {
            format!("{} {}", bin_name, args.join(" "))
        };
        let rule: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        (display, rule)
    };

    let scope_label = scope.as_deref().unwrap_or("user");
    eprintln!();
    eprintln!("  Add rule to {} policy:", scope_label);
    eprintln!("    deny exec {}", display_args);
    eprintln!();

    if !yes {
        eprint!("  Proceed? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("  Cancelled.");
            return Ok(());
        }
    }

    let node = manifest_edit::build_exec_rule(
        &bin_name,
        &rule_args,
        crate::policy::match_tree::Decision::Deny,
    );

    let path = resolve_manifest_path(scope)?;
    if path.extension().is_some_and(|ext| ext == "star") {
        anyhow::bail!(
            "CLI rule mutations are not yet supported for .star files — use `clash policy edit` instead"
        );
    }
    let mut manifest = crate::policy_loader::read_manifest(&path)?;
    let result = manifest_edit::upsert_rule(&mut manifest, node);
    crate::policy_loader::write_manifest(&path, &manifest)?;

    let result_str = match result {
        manifest_edit::UpsertResult::Inserted => "Rule added",
        manifest_edit::UpsertResult::Replaced => "Rule updated (replaced existing)",
    };
    println!("{} {}", style::green_bold("✓"), result_str);
    println!("  {}", style::dim(&path.display().to_string()));
    Ok(())
}
```

- [ ] **Step 6: Add `extract_command_from_entry` helper**

```rust
/// Extract the binary name and args from an audit log entry's tool_input_summary.
fn extract_command_from_entry(entry: &crate::debug::AuditLogEntry) -> Result<(String, Vec<String>)> {
    // The tool_input_summary is a JSON string like {"command":"git push origin main"}
    // (possibly truncated with "..." at the end).
    let summary = &entry.tool_input_summary;
    let clean = summary.trim_end_matches("...");

    // Try to parse as JSON to extract the command field.
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(clean) {
        if let Some(cmd) = val.get("command").and_then(|v| v.as_str()) {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("empty command in audit entry");
            }
            let bin = parts[0].to_string();
            let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
            return Ok((bin, args));
        }
    }

    // Fallback: try tool_name-specific extraction.
    anyhow::bail!(
        "cannot extract command from audit entry (tool: {}, summary: {})",
        entry.tool_name,
        summary
    )
}
```

- [ ] **Step 7: Update `handle_deny` to check for hash**

```rust
fn handle_deny(
    command: Vec<String>,
    tool: Option<String>,
    bin: Option<String>,
    scope: Option<String>,
    broad: bool,
    yes: bool,
) -> Result<()> {
    if command.len() == 1
        && tool.is_none()
        && bin.is_none()
        && looks_like_hash(&command[0])
    {
        return handle_deny_by_hash(&command[0], scope, broad, yes);
    }
    apply_mutation(command, tool, bin, scope, PolicyMutation::Deny)
}
```

- [ ] **Step 8: Update the CLI dispatch that calls handle_allow / handle_deny**

Find where `PolicyCmd::Allow { ... }` and `PolicyCmd::Deny { ... }` are matched (in `cmd/policy.rs` or wherever the dispatch lives) and pass the new `broad` and `yes` fields through.

- [ ] **Step 9: Default scope to user for hash-based invocations**

In `resolve_manifest_path`, when `scope` is `None`, it calls `ClashSettings::default_scope()`. For hash-based invocations, we want to default to user. The simplest approach: in `handle_allow_by_hash` and `handle_deny_by_hash`, if `scope` is None, set it to `Some("user".to_string())`:

```rust
let scope = scope.or_else(|| Some("user".to_string()));
```

- [ ] **Step 10: Run tests**

Run: `cargo test -p clash`
Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add clash/src/cli.rs clash/src/cmd/policy.rs
git commit -m "feat(policy): support hash-based clash policy allow|deny <hash>

Looks up the audit entry by hash, shows a confirmation dialog with
the rule to be added, and writes it to user-scope policy.

Includes --broad flag to widen the match with glob patterns and
--yes flag to skip confirmation for scripting."
```

---

### Task 7: Wire up the CLI dispatch and verify end-to-end

Make sure the CLI dispatch passes all the new flags through, and test the full flow.

**Files:**
- Modify: `clash/src/cmd/policy.rs` (dispatch match arms)

- [ ] **Step 1: Find and update the match arm for `PolicyCmd::Allow`**

The dispatch is likely in a `match` on `PolicyCmd` variants. Find it and add the new fields:

```rust
PolicyCmd::Allow {
    command,
    tool,
    bin,
    sandbox,
    scope,
    broad,
    yes,
} => handle_allow(command, tool, bin, sandbox, scope, broad, yes),
```

Similarly for `PolicyCmd::Deny`:

```rust
PolicyCmd::Deny {
    command,
    tool,
    bin,
    scope,
    broad,
    yes,
} => handle_deny(command, tool, bin, scope, broad, yes),
```

- [ ] **Step 2: Verify the full build**

Run: `cargo build -p clash`
Expected: Compiles without errors.

- [ ] **Step 3: Test end-to-end manually**

1. Start the shell: `clash shell`
2. See the startup banner: `Run clash policy allow|deny <id> to change policy for any command.`
3. Run a command that's allowed: `ls`
4. See prompt: `clash[abc1234:✓] $ `
5. Run a command that's denied: `git push` (if denied by policy)
6. See denial message with hash-based hints
7. See prompt: `clash[def5678:✗] $ `
8. In another terminal: `clash policy allow def5678 --yes`
9. Back in the shell, run the same command — should now be allowed (policy reloaded)

- [ ] **Step 4: Run the full test suite**

Run: `cargo test -p clash -p clash-brush-core -p clash-brush-interactive`
Expected: PASS

- [ ] **Step 5: Commit any remaining fixes**

```bash
git add -A
git commit -m "feat(shell): wire up CLI dispatch for hash-based policy commands"
```

---

### Task 8: Update hook path deny feedback to include hash

The agent hook path (`check_permission` in `permissions.rs`) should also include the hash in its deny feedback.

**Files:**
- Modify: `clash/src/permissions.rs:79-131`

- [ ] **Step 1: Use the audit hash in deny feedback**

In `check_permission`, the hash is returned from `log_decision` (from Task 2). Update the deny stderr output to include hash-based hints:

Change the deny block (lines 98-131):

```rust
    if decision.effect == Effect::Deny {
        let verb_str = tool_to_verb_str(&input.tool_name);
        let noun_summary = truncate_noun(&noun, 60);

        eprintln!(
            "{} blocked {} on {}",
            crate::style::err_red_bold("clash:"),
            verb_str,
            noun_summary
        );

        let is_explicit_deny = decision
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("denied") || r.contains("deny"));

        if is_explicit_deny {
            eprintln!(
                "  {}",
                crate::style::err_dim("This action is explicitly denied by your policy.")
            );
        } else {
            eprintln!("  {}", crate::style::err_dim(denial_explanation(&verb_str)));
        }

        eprintln!(
            "  {} {}",
            crate::style::err_dim("To allow this:"),
            crate::style::err_yellow(&format!("clash policy allow {}", audit_hash))
        );
    }
```

- [ ] **Step 2: Update `build_deny_context` to include the hash**

Change the function signature to accept the hash:

```rust
fn build_deny_context(
    tool_name: &str,
    reason: Option<&str>,
    tool_input: &serde_json::Value,
    audit_hash: &str,
) -> String {
```

Update the body to use hash-based suggestions:

```rust
    let mut lines = Vec::new();

    if is_explicit_deny {
        lines.push(format!("BLOCKED by explicit deny rule. To allow: clash policy allow {audit_hash}"));
    } else {
        lines.push(format!("BLOCKED by default deny. To allow: clash policy allow {audit_hash}"));
    }

    lines.push("Do NOT retry this tool call — it will be blocked again.".into());
```

Update the call site to pass the hash.

- [ ] **Step 3: Update tests that check deny context output**

Tests like `test_build_deny_context_contains_allow_command` and `test_deny_decision_includes_agent_context` need to be updated to pass a hash argument or check for the new format.

- [ ] **Step 4: Run tests**

Run: `cargo test -p clash`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add clash/src/permissions.rs
git commit -m "feat(hooks): include audit hash in deny feedback for agents

Agents now see 'clash policy allow <hash>' instead of generic
tool-based suggestions, matching the interactive shell experience."
```

---

### Task 9: Update documentation

**Files:**
- Modify: `README.md` or relevant docs (check what exists)

- [ ] **Step 1: Check what docs reference `clash shell` or `clash policy allow`**

Search for existing documentation that mentions these commands.

- [ ] **Step 2: Update docs to mention hash-based policy commands**

Add/update documentation for:
- `clash policy allow <hash>` / `clash policy deny <hash>`
- `--broad` flag
- `--yes` flag
- Interactive shell prompt indicators
- Policy reload behavior

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: document hash-based policy commands and shell feedback"
```
