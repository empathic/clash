# Hook Handler Env Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three production hook entry points — `handle_session_start` (in `clash/src/handlers.rs`) and the `PreToolUse`/`PostToolUse` paths (in `clash/src/cmd/hooks.rs`) — testable without mutating env vars, writing to real `$HOME`, or producing host-specific output, by introducing three capability traits bundled in an `Env` struct.

**Architecture:** Three traits — `PolicyStore`, `SessionRecorder`, `SandboxProbe` — defined in a new `clash/src/env.rs` module. An `Env<'a>` struct bundles them via `&'a dyn` references. `Env::prod()` wires production impls (zero-sized structs that delegate to the existing free functions); tests construct `Env` from stub or in-memory fake impls. A `clippy::disallowed_methods` config denies the underlying functions outside `env.rs`, so future contributors can't accidentally bypass the abstraction.

**Tech Stack:** Rust, anyhow, clippy, tempfile (for test fakes)

**Relation to existing work:**

- This plan replaces the in-flight `SessionStartEnv` design that previously sat on this branch. That design was a single-handler island; this plan generalises the same idea into three traits shared across `handle_session_start`, `PreToolUse`, and `PostToolUse`, with a lint guardrail to keep the architecture from decaying.
- Independent of PR #457 (`fix(publish)`) — different files, no interaction.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `clash/src/env.rs` | Create | Trait definitions (`PolicyStore`, `SessionRecorder`, `SandboxProbe`), `Env` struct, production impls, test fakes |
| `clash/src/lib.rs` | Modify | Register `pub mod env;` |
| `clash/src/handlers.rs` | Modify | `handle_session_start` takes `&Env` and routes every env call through it |
| `clash/src/cmd/hooks.rs` | Modify | Construct `Env::prod()` once; `PreToolUse`/`PostToolUse`/`SessionStart` paths route env calls through it |
| `clippy.toml` | Create (at repo root) | Disallow direct calls to the wrapped functions; only `env.rs` is exempt |

The trait file is one place because the traits are co-located (one `Env` bundles them) and the production impls are trivial pass-throughs. Splitting per trait would scatter ~20 lines per file.

---

### Task 1: Scaffold `env.rs` and register the module

Introduce the empty trait definitions and the `Env` struct. No methods yet — just shapes. This task ends with the crate still compiling and a smoke test that constructs `Env::prod()`.

**Files:**
- Create: `clash/src/env.rs`
- Modify: `clash/src/lib.rs` (add `pub mod env;`)

- [ ] **Step 1: Write the failing test**

Append to `clash/src/env.rs` (in a `mod tests` block at the bottom):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_prod_constructs() {
        let _env = Env::prod();
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --package clash --lib env::tests::env_prod_constructs
```

Expected: FAIL with `error[E0432]: unresolved import \`crate::env\`` (module doesn't exist yet).

- [ ] **Step 3: Create the env module with empty shapes**

Write `clash/src/env.rs`:

```rust
//! Capability-based env injection for hook handlers.
//!
//! The three production hook entry points need to be unit-testable without
//! reaching into the real `$HOME`, real filesystem, or real sandbox probe.
//! Each env-dependent capability is expressed as a small trait. Production
//! wires the real functions via [`Env::prod`]; tests construct an [`Env`]
//! from stub or in-memory implementations.

#![allow(clippy::disallowed_methods)] // adapter module: the only place that may call the wrapped functions

/// Read/write user-, project-, and session-level policy state.
pub trait PolicyStore {}

/// Per-session bookkeeping: audit init, active-session marker, trace init,
/// incremental stats/trace updates, and pending-ask recording.
pub trait SessionRecorder {}

/// Probe the host for sandbox support.
pub trait SandboxProbe {}

/// Bundle of env capabilities passed through hook handlers.
///
/// Construct via [`Env::prod`] in production and via `Env { ... }` with
/// fake/stub impls in tests.
pub struct Env<'a> {
    pub policy: &'a dyn PolicyStore,
    pub session: &'a dyn SessionRecorder,
    pub sandbox: &'a dyn SandboxProbe,
}

/// Production [`PolicyStore`]. Zero-sized; lives as a `static`.
pub struct DefaultPolicyStore;
impl PolicyStore for DefaultPolicyStore {}

/// Production [`SessionRecorder`]. Zero-sized; lives as a `static`.
pub struct DefaultSessionRecorder;
impl SessionRecorder for DefaultSessionRecorder {}

/// Production [`SandboxProbe`]. Zero-sized; lives as a `static`.
pub struct DefaultSandboxProbe;
impl SandboxProbe for DefaultSandboxProbe {}

pub static DEFAULT_POLICY_STORE: DefaultPolicyStore = DefaultPolicyStore;
pub static DEFAULT_SESSION_RECORDER: DefaultSessionRecorder = DefaultSessionRecorder;
pub static DEFAULT_SANDBOX_PROBE: DefaultSandboxProbe = DefaultSandboxProbe;

impl Env<'static> {
    /// Build the production [`Env`] — wires every capability to the real
    /// filesystem/policy/sandbox subsystems.
    pub fn prod() -> Self {
        Env {
            policy: &DEFAULT_POLICY_STORE,
            session: &DEFAULT_SESSION_RECORDER,
            sandbox: &DEFAULT_SANDBOX_PROBE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_prod_constructs() {
        let _env = Env::prod();
    }
}
```

- [ ] **Step 4: Register the module**

In `clash/src/lib.rs`, add (alphabetical placement next to `pub mod handlers;`):

```rust
pub mod env;
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cargo test --package clash --lib env::tests::env_prod_constructs
```

Expected: `test env::tests::env_prod_constructs ... ok`.

- [ ] **Step 6: Commit**

```bash
git add clash/src/env.rs clash/src/lib.rs
git commit -m "refactor(env): scaffold Env capability traits"
```

---

### Task 2: Wire `SandboxProbe`

`SandboxProbe` is the smallest port — one method, no filesystem side effects, pure pass-through to `sandbox::check_support`. Implementing it first establishes the pattern.

**Files:**
- Modify: `clash/src/env.rs`

- [ ] **Step 1: Write the failing test**

In `clash/src/env.rs`, replace the `mod tests` block with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_prod_constructs() {
        let _env = Env::prod();
    }

    #[test]
    fn default_sandbox_probe_matches_check_support() {
        // The default impl must delegate to the same function the rest of
        // the crate calls today, so behavior is identical.
        let direct = crate::sandbox::check_support();
        let via_env = DEFAULT_SANDBOX_PROBE.check_support();
        // SupportLevel doesn't derive PartialEq; compare via the discriminant
        // shape we care about (variant kind).
        let same_variant = matches!(
            (&direct, &via_env),
            (crate::sandbox::SupportLevel::Full, crate::sandbox::SupportLevel::Full)
                | (
                    crate::sandbox::SupportLevel::Partial { .. },
                    crate::sandbox::SupportLevel::Partial { .. }
                )
                | (
                    crate::sandbox::SupportLevel::Unsupported { .. },
                    crate::sandbox::SupportLevel::Unsupported { .. }
                )
        );
        assert!(same_variant, "trait delegate diverged from direct call");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --package clash --lib env::tests::default_sandbox_probe_matches_check_support
```

Expected: FAIL with `error[E0599]: no method named \`check_support\`` on `DefaultSandboxProbe`.

- [ ] **Step 3: Add the method to the trait and impl**

In `clash/src/env.rs`, replace the `SandboxProbe` definitions:

```rust
/// Probe the host for sandbox support.
pub trait SandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel;
}

/// Production [`SandboxProbe`]. Zero-sized; lives as a `static`.
pub struct DefaultSandboxProbe;
impl SandboxProbe for DefaultSandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel {
        crate::sandbox::check_support()
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test --package clash --lib env::tests::default_sandbox_probe_matches_check_support
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clash/src/env.rs
git commit -m "refactor(env): implement SandboxProbe"
```

---

### Task 3: Wire `PolicyStore`

`PolicyStore` carries the two methods `handle_session_start` needs (`ensure_user_policy`, `validate_session`).

**Files:**
- Modify: `clash/src/env.rs`

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` block in `clash/src/env.rs`:

```rust
    #[test]
    fn default_policy_store_ensure_user_policy_delegates() {
        // We can't assert a specific return without controlling $HOME, but
        // we can assert the call compiles and returns a Result (i.e. the
        // delegation wiring exists). Any Err is acceptable here — the
        // important invariant is that the trait method is reachable and
        // routes to the real function.
        let _ = DEFAULT_POLICY_STORE.ensure_user_policy();
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --package clash --lib env::tests::default_policy_store_ensure_user_policy_delegates
```

Expected: FAIL with `error[E0599]: no method named \`ensure_user_policy\`` on `DefaultPolicyStore`.

- [ ] **Step 3: Add the methods to the trait and impl**

In `clash/src/env.rs`, replace the `PolicyStore` definitions:

```rust
/// Read/write user-, project-, and session-level policy state.
pub trait PolicyStore {
    /// Ensure a user-level policy file exists. Returns `Some(path)` if a
    /// fresh file was created, `None` if one already existed.
    fn ensure_user_policy(&self) -> anyhow::Result<Option<std::path::PathBuf>>;

    /// Load and compile settings for the session. Errors propagate (the
    /// session cannot proceed without a working policy state).
    fn validate_session(
        &self,
        session_id: &str,
        hook_ctx: &crate::settings::HookContext,
    ) -> anyhow::Result<()>;

    /// Load full settings for the session — used by the `PreToolUse` path,
    /// which needs the compiled `ClashSettings` for `check_permission`.
    fn load_settings(
        &self,
        session_id: &str,
        hook_ctx: &crate::settings::HookContext,
    ) -> anyhow::Result<crate::settings::ClashSettings>;
}

/// Production [`PolicyStore`]. Zero-sized; lives as a `static`.
pub struct DefaultPolicyStore;
impl PolicyStore for DefaultPolicyStore {
    fn ensure_user_policy(&self) -> anyhow::Result<Option<std::path::PathBuf>> {
        crate::settings::ClashSettings::ensure_user_policy_exists()
    }

    fn validate_session(
        &self,
        session_id: &str,
        hook_ctx: &crate::settings::HookContext,
    ) -> anyhow::Result<()> {
        crate::settings::ClashSettings::load_or_create_with_session(
            Some(session_id),
            Some(hook_ctx),
        )?;
        Ok(())
    }

    fn load_settings(
        &self,
        session_id: &str,
        hook_ctx: &crate::settings::HookContext,
    ) -> anyhow::Result<crate::settings::ClashSettings> {
        crate::settings::ClashSettings::load_or_create_with_session(
            Some(session_id),
            Some(hook_ctx),
        )
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test --package clash --lib env::tests::default_policy_store_ensure_user_policy_delegates
```

Expected: PASS (the call may print a warning from `ensure_user_policy_exists` if a legacy `policy.json` is present on the developer's machine; that's expected and acceptable for this smoke test, which only asserts compilation/wiring).

- [ ] **Step 5: Commit**

```bash
git add clash/src/env.rs
git commit -m "refactor(env): implement PolicyStore"
```

---

### Task 4: Wire `SessionRecorder`

`SessionRecorder` covers the six per-session writes — three session-start lifecycle (audit init, active session, trace init) and three incremental updates the `PreToolUse`/`PostToolUse` paths perform (stats, trace sync, pending-ask record).

**Files:**
- Modify: `clash/src/env.rs`

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` block in `clash/src/env.rs`:

```rust
    #[test]
    fn default_session_recorder_methods_exist() {
        // Wiring smoke test: every trait method must be callable through
        // the trait object. Any underlying I/O errors are acceptable here
        // (e.g. real $HOME may be in an unexpected state); we just need the
        // delegation to be in place.
        let recorder: &dyn SessionRecorder = &DEFAULT_SESSION_RECORDER;
        let input = crate::hooks::SessionStartHookInput {
            session_id: "wiring-smoke".into(),
            transcript_path: "/tmp/transcript.jsonl".into(),
            cwd: "/tmp".into(),
            permission_mode: None,
            hook_event_name: "SessionStart".into(),
            source: None,
            model: None,
        };
        let _ = recorder.init_audit_session(&input);
        let _ = recorder.set_active_session("wiring-smoke");
        let _ = recorder.init_trace(&input);
        recorder.update_session_stats(
            "wiring-smoke",
            "Read",
            &serde_json::json!({}),
            crate::policy::Effect::Allow,
            "/tmp",
        );
        let _ = recorder.sync_trace("wiring-smoke", None);
        recorder.record_pending_ask(
            "wiring-smoke",
            "tool-use-1",
            "Read",
            &serde_json::json!({}),
            "/tmp",
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --package clash --lib env::tests::default_session_recorder_methods_exist
```

Expected: FAIL with `error[E0599]: no method named \`init_audit_session\`` on `DefaultSessionRecorder`.

- [ ] **Step 3: Add the methods to the trait and impl**

In `clash/src/env.rs`, replace the `SessionRecorder` definitions:

```rust
/// Per-session bookkeeping: audit init, active-session marker, trace init,
/// incremental stats/trace updates, and pending-ask recording.
pub trait SessionRecorder {
    /// Initialize the per-session audit directory. Returns the dir path on
    /// success; failures are non-fatal at the call site.
    fn init_audit_session(
        &self,
        input: &crate::hooks::SessionStartHookInput,
    ) -> std::io::Result<std::path::PathBuf>;

    /// Record this session as the active one. Failures are non-fatal.
    fn set_active_session(&self, session_id: &str) -> anyhow::Result<()>;

    /// Initialize toolpath tracing for this session. Failures are non-fatal.
    fn init_trace(&self, input: &crate::hooks::SessionStartHookInput) -> anyhow::Result<()>;

    /// Increment per-effect counters and persist updated session stats.
    /// Called once per tool use from the `PreToolUse` path.
    fn update_session_stats(
        &self,
        session_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        effect: crate::policy::Effect,
        cwd: &str,
    );

    /// Append a policy decision to the session trace.
    fn sync_trace(
        &self,
        session_id: &str,
        decision: Option<crate::trace::PolicyDecision>,
    ) -> anyhow::Result<()>;

    /// Record that we returned `ask` for a tool use, so `PostToolUse` can
    /// detect approval and suggest a session rule.
    fn record_pending_ask(
        &self,
        session_id: &str,
        tool_use_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    );
}

/// Production [`SessionRecorder`]. Zero-sized; lives as a `static`.
pub struct DefaultSessionRecorder;
impl SessionRecorder for DefaultSessionRecorder {
    fn init_audit_session(
        &self,
        input: &crate::hooks::SessionStartHookInput,
    ) -> std::io::Result<std::path::PathBuf> {
        crate::audit::init_session(
            &input.session_id,
            &input.cwd,
            input.source.as_deref(),
            input.model.as_deref(),
        )
    }

    fn set_active_session(&self, session_id: &str) -> anyhow::Result<()> {
        crate::settings::ClashSettings::set_active_session(session_id)
    }

    fn init_trace(&self, input: &crate::hooks::SessionStartHookInput) -> anyhow::Result<()> {
        crate::trace::init_trace(
            &input.session_id,
            &input.transcript_path,
            &input.cwd,
            input.model.as_deref(),
            input.source.as_deref(),
        )
    }

    fn update_session_stats(
        &self,
        session_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        effect: crate::policy::Effect,
        cwd: &str,
    ) {
        crate::audit::update_session_stats(session_id, tool_name, tool_input, effect, cwd);
    }

    fn sync_trace(
        &self,
        session_id: &str,
        decision: Option<crate::trace::PolicyDecision>,
    ) -> anyhow::Result<()> {
        crate::trace::sync_trace(session_id, decision)
    }

    fn record_pending_ask(
        &self,
        session_id: &str,
        tool_use_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) {
        crate::session_policy::record_pending_ask(
            session_id, tool_use_id, tool_name, tool_input, cwd,
        );
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test --package clash --lib env::tests::default_session_recorder_methods_exist
```

Expected: PASS (writes may land in real `~/.clash/sessions/wiring-smoke/`; that's acceptable for this smoke test — see Task 5 for the in-memory fake).

- [ ] **Step 5: Commit**

```bash
git add clash/src/env.rs
git commit -m "refactor(env): implement SessionRecorder"
```

---

### Task 5: Add test fakes (`TestEnv`)

A hermetic in-memory `TestEnv` so handler tests don't touch real `$HOME` and don't depend on the host's sandbox state.

**Files:**
- Modify: `clash/src/env.rs`

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` block in `clash/src/env.rs`:

```rust
    #[test]
    fn test_env_is_hermetic() {
        let test_env = TestEnv::new();
        let env = test_env.env();

        // PolicyStore: no welcome, no validation error
        assert!(env.policy.ensure_user_policy().unwrap().is_none());
        let hook_ctx = crate::settings::HookContext::from_transcript_path("/tmp/t.jsonl");
        env.policy.validate_session("test-session", &hook_ctx).unwrap();

        // SandboxProbe: canned full support
        assert!(matches!(
            env.sandbox.check_support(),
            crate::sandbox::SupportLevel::Full
        ));

        // SessionRecorder: writes land in the TestEnv's tempdir, never $HOME
        let input = crate::hooks::SessionStartHookInput {
            session_id: "test-session".into(),
            transcript_path: "/tmp/t.jsonl".into(),
            cwd: "/tmp".into(),
            permission_mode: None,
            hook_event_name: "SessionStart".into(),
            source: None,
            model: None,
        };
        let audit_dir = env.session.init_audit_session(&input).unwrap();
        assert!(
            audit_dir.starts_with(test_env.root()),
            "audit dir {} escaped TestEnv root {}",
            audit_dir.display(),
            test_env.root().display(),
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test --package clash --lib env::tests::test_env_is_hermetic
```

Expected: FAIL with `error[E0433]: failed to resolve: use of undeclared type \`TestEnv\``.

- [ ] **Step 3: Add the test fakes**

Append to `clash/src/env.rs` (below the production impls, above the existing `#[cfg(test)] mod tests`):

```rust
// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

/// Hermetic in-memory [`Env`] for unit tests. Writes land in a [`TempDir`]
/// so they vanish at end of test; sandbox probe returns canned `Full`;
/// policy operations return success without touching disk.
///
/// Construct via [`TestEnv::new`] or [`TestEnv::builder`] for customization.
#[cfg(test)]
pub struct TestEnv {
    policy: StubPolicyStore,
    session: InMemorySessionRecorder,
    sandbox: StubSandboxProbe,
}

#[cfg(test)]
impl TestEnv {
    pub fn new() -> Self {
        Self {
            policy: StubPolicyStore::default(),
            session: InMemorySessionRecorder::new(),
            sandbox: StubSandboxProbe::full(),
        }
    }

    pub fn builder() -> TestEnvBuilder {
        TestEnvBuilder::default()
    }

    pub fn env(&self) -> Env<'_> {
        Env {
            policy: &self.policy,
            session: &self.session,
            sandbox: &self.sandbox,
        }
    }

    pub fn root(&self) -> &std::path::Path {
        self.session.root()
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct TestEnvBuilder {
    welcome_path: Option<std::path::PathBuf>,
    sandbox_support: Option<crate::sandbox::SupportLevel>,
}

#[cfg(test)]
impl TestEnvBuilder {
    pub fn with_welcome(mut self, path: std::path::PathBuf) -> Self {
        self.welcome_path = Some(path);
        self
    }

    pub fn with_sandbox(mut self, support: crate::sandbox::SupportLevel) -> Self {
        self.sandbox_support = Some(support);
        self
    }

    pub fn build(self) -> TestEnv {
        TestEnv {
            policy: StubPolicyStore {
                welcome_path: self.welcome_path,
            },
            session: InMemorySessionRecorder::new(),
            sandbox: match self.sandbox_support {
                Some(s) => StubSandboxProbe { support: s },
                None => StubSandboxProbe::full(),
            },
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct StubPolicyStore {
    welcome_path: Option<std::path::PathBuf>,
}

#[cfg(test)]
impl PolicyStore for StubPolicyStore {
    fn ensure_user_policy(&self) -> anyhow::Result<Option<std::path::PathBuf>> {
        Ok(self.welcome_path.clone())
    }

    fn validate_session(
        &self,
        _session_id: &str,
        _hook_ctx: &crate::settings::HookContext,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn load_settings(
        &self,
        _session_id: &str,
        _hook_ctx: &crate::settings::HookContext,
    ) -> anyhow::Result<crate::settings::ClashSettings> {
        Ok(crate::settings::ClashSettings::default())
    }
}

#[cfg(test)]
pub struct InMemorySessionRecorder {
    tempdir: tempfile::TempDir,
}

#[cfg(test)]
impl InMemorySessionRecorder {
    fn new() -> Self {
        Self {
            tempdir: tempfile::tempdir().expect("create tempdir for InMemorySessionRecorder"),
        }
    }

    fn root(&self) -> &std::path::Path {
        self.tempdir.path()
    }
}

#[cfg(test)]
impl SessionRecorder for InMemorySessionRecorder {
    fn init_audit_session(
        &self,
        input: &crate::hooks::SessionStartHookInput,
    ) -> std::io::Result<std::path::PathBuf> {
        let dir = self.tempdir.path().join("sessions").join(&input.session_id);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn set_active_session(&self, _session_id: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn init_trace(&self, _input: &crate::hooks::SessionStartHookInput) -> anyhow::Result<()> {
        Ok(())
    }

    fn update_session_stats(
        &self,
        _session_id: &str,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _effect: crate::policy::Effect,
        _cwd: &str,
    ) {
    }

    fn sync_trace(
        &self,
        _session_id: &str,
        _decision: Option<crate::trace::PolicyDecision>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn record_pending_ask(
        &self,
        _session_id: &str,
        _tool_use_id: &str,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _cwd: &str,
    ) {
    }
}

#[cfg(test)]
pub struct StubSandboxProbe {
    support: crate::sandbox::SupportLevel,
}

#[cfg(test)]
impl StubSandboxProbe {
    pub fn full() -> Self {
        Self {
            support: crate::sandbox::SupportLevel::Full,
        }
    }
}

#[cfg(test)]
impl SandboxProbe for StubSandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel {
        match &self.support {
            crate::sandbox::SupportLevel::Full => crate::sandbox::SupportLevel::Full,
            crate::sandbox::SupportLevel::Partial { missing } => {
                crate::sandbox::SupportLevel::Partial {
                    missing: missing.clone(),
                }
            }
            crate::sandbox::SupportLevel::Unsupported { reason } => {
                crate::sandbox::SupportLevel::Unsupported {
                    reason: reason.clone(),
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test --package clash --lib env::tests::test_env_is_hermetic
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add clash/src/env.rs
git commit -m "refactor(env): add hermetic TestEnv"
```

---

### Task 6: Refactor `handle_session_start` to take `&Env`

Replace the direct calls to `ClashSettings::ensure_user_policy_exists`, `ClashSettings::load_or_create_with_session`, `sandbox::check_support`, `audit::init_session`, `ClashSettings::set_active_session`, and `trace::init_trace` with calls through `env`. The three existing tests now construct a `TestEnv` and call `handle_session_start` itself (no separate test-only helper).

**Files:**
- Modify: `clash/src/handlers.rs`

- [ ] **Step 1: Inspect the current handler**

Read `clash/src/handlers.rs` (the `handle_session_start` function, the `clash_session_context` helper, and the `check_sandbox_and_session` helper). On a clean `main`-derived branch these are at roughly lines 220–340.

- [ ] **Step 2: Replace the handler and helper with env-routed versions**

In `clash/src/handlers.rs`, replace the section from `pub fn handle_session_start` through the end of `fn check_sandbox_and_session` (inclusive) with the version below. (If a prior `SessionStartEnv` trait or `DefaultSessionStartEnv`/`FakeSessionStartEnv` items also exist in this file from earlier exploration, delete them at the same time — they are superseded by `Env` from `clash/src/env.rs`.)

```rust
/// Handle a session start event — validate policy/settings and report status to Claude.
#[instrument(level = Level::TRACE, skip(env, input))]
pub fn handle_session_start(
    env: &crate::env::Env,
    input: &SessionStartHookInput,
    agent: Option<crate::agents::AgentKind>,
) -> anyhow::Result<HookOutput> {
    let created_policy = env.policy.ensure_user_policy()?;

    let mut hook_ctx = crate::settings::HookContext::from_transcript_path(&input.transcript_path);
    if let Some(a) = agent {
        hook_ctx = hook_ctx.with_agent(a);
    }
    env.policy.validate_session(&input.session_id, &hook_ctx)?;

    let mut lines = Vec::new();

    if let Some(path) = created_policy {
        lines.push(format!(
            "Welcome to Clash! A default policy has been created at {}. \
             It starts with deny-all and allows reading files in your project. \
             Run `clash status` to see what's allowed, or edit the policy file to customize.",
            path.display()
        ));
    }

    lines.push(clash_session_context().into());
    lines.push("Clash is managing permissions via hooks.".into());

    check_sandbox_and_session(env, &mut lines, input);

    finish_session_start(lines)
}

/// Generate comprehensive context about clash for injection into Claude's session.
///
/// This text is returned as `additional_context` in the SessionStart hook response,
/// giving Claude the knowledge it needs to use clash skills and manage policies.
fn clash_session_context() -> &'static str {
    include_str!("../docs/session-context.md")
}

fn check_sandbox_and_session(
    env: &crate::env::Env,
    lines: &mut Vec<String>,
    input: &SessionStartHookInput,
) {
    match env.sandbox.check_support() {
        crate::sandbox::SupportLevel::Full => {
            lines.push("sandbox: fully supported".into());
        }
        crate::sandbox::SupportLevel::Partial { ref missing } => {
            lines.push(format!(
                "sandbox: partial (missing: {})",
                missing.join(", ")
            ));
        }
        crate::sandbox::SupportLevel::Unsupported { ref reason } => {
            lines.push(format!("sandbox: unsupported ({})", reason));
        }
    }

    match env.session.init_audit_session(input) {
        Ok(session_dir) => {
            lines.push(format!("session history: {}", session_dir.display()));
        }
        Err(e) => {
            warn!(error = %e, "Failed to create session history directory");
        }
    }

    if let Err(e) = env.session.set_active_session(&input.session_id) {
        warn!(error = %e, "Failed to write active session marker");
    }

    if let Err(e) = env.session.init_trace(input) {
        warn!(error = %e, "Failed to initialize session trace");
    }

    if let Some(ref source) = input.source {
        lines.push(format!("session source: {}", source));
    }
    if let Some(ref model) = input.model {
        lines.push(format!("model: {}", model));
    }
}
```

If PR #458 had merged, also delete the now-unused trait `SessionStartEnv`, struct `DefaultSessionStartEnv`, and the entire `impl SessionStartEnv for DefaultSessionStartEnv` block from this file.

- [ ] **Step 3: Update the test module to use `TestEnv`**

In `clash/src/handlers.rs`, replace the `#[cfg(test)] mod tests` block with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn session_start_context(input: &SessionStartHookInput) -> String {
        let test_env = crate::env::TestEnv::new();
        let output = handle_session_start(&test_env.env(), input, None)
            .expect("session start should succeed");
        match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => {
                s.additional_context.clone().expect("should have context")
            }
            _ => panic!("expected SessionStart output"),
        }
    }

    fn default_session_start_input() -> SessionStartHookInput {
        SessionStartHookInput {
            session_id: "test-session".into(),
            transcript_path: "/tmp/transcript.jsonl".into(),
            cwd: "/tmp".into(),
            permission_mode: Some("default".into()),
            hook_event_name: "SessionStart".into(),
            source: Some("startup".into()),
            model: Some("claude-sonnet-4-20250514".into()),
        }
    }

    #[test]
    fn test_session_start_reports_sandbox_support() {
        let ctx = session_start_context(&default_session_start_input());
        assert!(
            ctx.contains("sandbox: fully supported"),
            "expected canned Full support, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_session_metadata() {
        let ctx = session_start_context(&default_session_start_input());
        assert!(ctx.contains("session source: startup"), "got: {ctx}");
        assert!(
            ctx.contains("model: claude-sonnet-4-20250514"),
            "got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_managing_permissions() {
        let ctx = session_start_context(&default_session_start_input());
        assert!(
            ctx.contains("Clash is managing permissions via hooks"),
            "should report clash is managing permissions, got: {ctx}"
        );
    }
}
```

Note the strengthened assertion on the first test (`"sandbox: fully supported"` instead of `"sandbox:"`) — now that the test owns the probe's response, it can assert on the exact line.

- [ ] **Step 4: Run the handler tests**

```bash
cargo test --package clash --lib handlers::tests
```

Expected: 3 passed.

- [ ] **Step 5: Update the caller in `cmd/hooks.rs` to construct `Env::prod`**

In `clash/src/cmd/hooks.rs`, find the `HookSubcommand::SessionStart` arm (around line 227) and replace its call to `handle_session_start`:

```rust
HookSubcommand::SessionStart => {
    let mut input = self
        .parse_session_start_input()
        .context("parsing SessionStart hook input from stdin")?;
    if input.session_id.is_empty() {
        input.session_id = fallback_session_id(self.agent);
        info!(session_id = %input.session_id, "Agent did not provide session_id, using fallback");
    }
    let env = crate::env::Env::prod();
    crate::handlers::handle_session_start(&env, &input, Some(self.agent))?
}
```

- [ ] **Step 6: Run the full clash test suite**

```bash
cargo test --package clash --lib
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add clash/src/handlers.rs clash/src/cmd/hooks.rs
git commit -m "refactor(handlers): inject Env into handle_session_start"
```

---

### Task 7: Refactor `cmd/hooks.rs` `PreToolUse` path to use `Env`

The `PreToolUse` arm currently calls `ClashSettings::load_or_create_with_session`, `crate::audit::update_session_stats`, `session_policy::record_pending_ask`, and `trace::sync_trace` directly. Route each through `&Env`.

**Files:**
- Modify: `clash/src/cmd/hooks.rs`

- [ ] **Step 1: Inspect the current arm**

Read `clash/src/cmd/hooks.rs` lines ~62–142 (the `HookSubcommand::PreToolUse` match arm). Note the four direct env-touching calls.

- [ ] **Step 2: Replace the arm**

In `clash/src/cmd/hooks.rs`, find the `HookSubcommand::PreToolUse =>` arm and replace it with this version (the structural diff is: construct `env` at the top of the arm, then substitute `env.policy.load_settings(...)`, `env.session.update_session_stats(...)`, `env.session.record_pending_ask(...)`, and `env.session.sync_trace(...)` for the four direct calls):

```rust
HookSubcommand::PreToolUse => {
    let input = self.parse_tool_use_input()
        .context("parsing PreToolUse hook input from stdin — expected JSON with tool_name and tool_input fields")?;

    if passthrough {
        info!(
            tool = %input.tool_name,
            "CLASH_PASSTHROUGH: deferring to native permissions"
        );
        let env = crate::env::Env::prod();
        if let Err(e) = env.session.sync_trace(&input.session_id, None) {
            tracing::warn!(error = %e, "Failed to sync trace (PreToolUse/passthrough)");
        }
        HookOutput::continue_execution()
    } else {
        let env = crate::env::Env::prod();
        let mut hook_ctx = HookContext::from_transcript_path(&input.transcript_path);
        if let Some(agent) = input.agent {
            hook_ctx = hook_ctx.with_agent(agent);
        }
        let settings = env.policy.load_settings(&input.session_id, &hook_ctx)?;
        let output = check_permission(&input, &settings)?;

        if is_interactive_tool(&input.tool_name)
            && !is_deny_decision(&output)
            && is_ask_decision(&output)
        {
            info!(tool = %input.tool_name, "Passthrough: interactive tool deferred to Claude Code");
            HookOutput::continue_execution()
        } else {
            if let Some(effect) = hook_effect_to_policy(output.effect()) {
                env.session.update_session_stats(
                    &input.session_id,
                    &input.tool_name,
                    &input.tool_input,
                    effect,
                    &input.cwd,
                );
            }

            if is_ask_decision(&output)
                && let Some(ref tool_use_id) = input.tool_use_id
            {
                env.session.record_pending_ask(
                    &input.session_id,
                    tool_use_id,
                    &input.tool_name,
                    &input.tool_input,
                    &input.cwd,
                );
            }

            let decision = input.tool_use_id.as_ref().and_then(|id| {
                let effect = hook_effect_to_policy(output.effect())?;
                Some(trace::PolicyDecision {
                    tool_use_id: id.clone(),
                    tool_name: Some(input.tool_name.clone()),
                    effect,
                    reason: None,
                })
            });
            if let Err(e) = env.session.sync_trace(&input.session_id, decision) {
                tracing::warn!(error = %e, "Failed to sync trace (PreToolUse)");
            }

            output
        }
    }
}
```

- [ ] **Step 3: Run the full test suite**

```bash
cargo test --package clash --lib
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add clash/src/cmd/hooks.rs
git commit -m "refactor(cmd/hooks): route PreToolUse through Env"
```

---

### Task 8: Refactor `cmd/hooks.rs` `PostToolUse` path to use `Env`

The `PostToolUse` arm currently calls `session_policy::process_post_tool_use` and `trace::sync_trace` directly. Route both through `&Env`.

Note: `process_post_tool_use` is a read-and-clear operation; it's not in `SessionRecorder` yet. Add it.

**Files:**
- Modify: `clash/src/env.rs` (add `consume_pending_ask` to `SessionRecorder`)
- Modify: `clash/src/cmd/hooks.rs`

- [ ] **Step 1: Inspect `process_post_tool_use`**

```bash
grep -n "pub fn process_post_tool_use" clash/src/session_policy.rs
```

Note the signature for reference in step 3.

- [ ] **Step 2: Write a failing test for the new trait method**

Append to `clash/src/env.rs` `mod tests` block:

```rust
    #[test]
    fn default_session_recorder_consume_pending_ask_exists() {
        let recorder: &dyn SessionRecorder = &DEFAULT_SESSION_RECORDER;
        // Calling on a non-existent record returns None; this is a smoke test
        // for trait wiring only.
        let _ = recorder.consume_pending_ask(
            "no-such-tool-use",
            "no-such-session",
            "Read",
            &serde_json::json!({}),
            "/tmp",
        );
    }
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cargo test --package clash --lib env::tests::default_session_recorder_consume_pending_ask_exists
```

Expected: FAIL with `error[E0599]: no method named \`consume_pending_ask\``.

- [ ] **Step 4: Add the method to the trait, prod impl, and test fake**

In `clash/src/env.rs`, add to the `SessionRecorder` trait (after `record_pending_ask`):

```rust
    /// Look up and clear a pending ask record; returns the suggested rule
    /// advice if the tool use matches a prior `ask` decision.
    fn consume_pending_ask(
        &self,
        tool_use_id: &str,
        session_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) -> Option<crate::session_policy::AskAdvice>;
```

(Substitute `crate::session_policy::AskAdvice` with the actual return type of `process_post_tool_use` — confirm via the inspect step.)

Add to `DefaultSessionRecorder`:

```rust
    fn consume_pending_ask(
        &self,
        tool_use_id: &str,
        session_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) -> Option<crate::session_policy::AskAdvice> {
        crate::session_policy::process_post_tool_use(
            tool_use_id, session_id, tool_name, tool_input, cwd,
        )
    }
```

Add to `InMemorySessionRecorder`:

```rust
    fn consume_pending_ask(
        &self,
        _tool_use_id: &str,
        _session_id: &str,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _cwd: &str,
    ) -> Option<crate::session_policy::AskAdvice> {
        None
    }
```

- [ ] **Step 5: Run the new test to verify it passes**

```bash
cargo test --package clash --lib env::tests::default_session_recorder_consume_pending_ask_exists
```

Expected: PASS.

- [ ] **Step 6: Refactor the `PostToolUse` arm**

In `clash/src/cmd/hooks.rs`, find the `HookSubcommand::PostToolUse =>` arm and replace it. The structural change is: construct `env`, route `process_post_tool_use` → `env.session.consume_pending_ask`, and `trace::sync_trace` → `env.session.sync_trace`. Preserve all other behavior. Replace `session_policy::process_post_tool_use(...)` with `env.session.consume_pending_ask(...)` and `trace::sync_trace(...)` with `env.session.sync_trace(...)` everywhere in that arm.

- [ ] **Step 7: Run the full test suite**

```bash
cargo test --package clash --lib
```

Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add clash/src/env.rs clash/src/cmd/hooks.rs
git commit -m "refactor(cmd/hooks): route PostToolUse through Env"
```

---

### Task 9: Add `clippy::disallowed_methods` config

Lock the architecture by denying direct calls to the wrapped functions outside `env.rs`. The deny list comes from the production-impl bodies in tasks 2–4 and 8.

**Files:**
- Create: `clippy.toml` (at the repo root)

- [ ] **Step 1: Write `clippy.toml`**

Create `/Users/alex/Devel/empathic/clash/clippy.toml` (repo root):

```toml
# Methods deferred to `clash::env` capability traits. Direct calls outside
# `clash/src/env.rs` (which has `#![allow(clippy::disallowed_methods)]`) bypass
# the abstraction and re-introduce the testability gap that `env.rs` exists to
# close. Add new entries here when new env-dependent functions are introduced.

disallowed-methods = [
    { path = "clash::sandbox::check_support", reason = "use Env::sandbox.check_support()" },
    { path = "clash::settings::ClashSettings::ensure_user_policy_exists", reason = "use Env::policy.ensure_user_policy()" },
    { path = "clash::settings::ClashSettings::set_active_session", reason = "use Env::session.set_active_session()" },
    { path = "clash::audit::init_session", reason = "use Env::session.init_audit_session()" },
    { path = "clash::audit::update_session_stats", reason = "use Env::session.update_session_stats()" },
    { path = "clash::trace::init_trace", reason = "use Env::session.init_trace()" },
    { path = "clash::trace::sync_trace", reason = "use Env::session.sync_trace()" },
    { path = "clash::session_policy::record_pending_ask", reason = "use Env::session.record_pending_ask()" },
    { path = "clash::session_policy::process_post_tool_use", reason = "use Env::session.consume_pending_ask()" },
]
```

Note: `ClashSettings::load_or_create_with_session` is intentionally NOT on the deny list, because it has legitimate non-handler callers (e.g. CLI commands like `clash status`). The capability methods on `PolicyStore` (`validate_session`, `load_settings`) delegate to it; for handlers and the hook subcommand, those go through `Env`. Other callers may use the underlying function directly.

- [ ] **Step 2: Run clippy to verify the lint fires**

```bash
cargo clippy --package clash --all-targets -- -D warnings 2>&1 | tail -30
```

Expected: clean exit. If any callsite outside `env.rs` still calls a denied method, clippy reports it with the reason string from the config. Fix the call site (route it through `Env`) and rerun.

- [ ] **Step 3: Commit**

```bash
git add clippy.toml
git commit -m "chore(lint): deny direct calls to wrapped env functions"
```

---

### Task 10: Verify and document

Final cross-check: every assertion in the existing handler tests passes, no direct env calls leak from the handler/cmd files, and the doc-test for `env.rs` mentions the lint guardrail.

**Files:**
- Modify: `clash/src/env.rs` (top-of-file doc only)

- [ ] **Step 1: Run the full test suite one more time**

```bash
cargo test --package clash --lib
```

Expected: all tests pass, no warnings about unused items.

- [ ] **Step 2: Run clippy with `-D warnings`**

```bash
cargo clippy --package clash --all-targets -- -D warnings 2>&1 | tail -5
```

Expected: clean exit.

- [ ] **Step 3: Document the lint guardrail**

In `clash/src/env.rs`, replace the top-of-file doc comment (the `//!` block) with:

```rust
//! Capability-based env injection for hook handlers.
//!
//! The three production hook entry points need to be unit-testable without
//! reaching into the real `$HOME`, real filesystem, or real sandbox probe.
//! Each env-dependent capability is expressed as a small trait. Production
//! wires the real functions via [`Env::prod`]; tests construct an [`Env`]
//! from stub or in-memory implementations.
//!
//! **Lint guardrail.** `clippy.toml` at the repo root disallows direct calls
//! to every function wrapped by this module. This file is the only place
//! that may invoke them (the top-level `#![allow(clippy::disallowed_methods)]`
//! permits it). When you add a new env-dependent capability, add the method
//! here, add the underlying function to `clippy.toml`'s `disallowed-methods`,
//! and migrate existing callers through the trait.
```

- [ ] **Step 4: Commit**

```bash
git add clash/src/env.rs
git commit -m "docs(env): note the clippy guardrail in module header"
```

---

## Self-Review

Spec coverage:
- All three handlers (`handle_session_start`, `PreToolUse` path, `PostToolUse` path) are migrated (Tasks 6–8).
- All three traits (`PolicyStore`, `SessionRecorder`, `SandboxProbe`) are defined and implemented (Tasks 2–4, 8).
- `Env::prod` and `TestEnv` exist (Tasks 1, 5).
- Lint guardrail in place (Task 9), referenced in `env.rs` header (Task 10).
- Three formerly-broken handler tests now pass against the same handler production runs (Task 6).
- No env-var mutation, no `unsafe`, no Mutex in any test path.

Placeholder scan:
- All code blocks contain complete, runnable code.
- The one `Substitute X with Y — confirm via inspect step` instruction in Task 8 step 4 is acceptable because the engineer has run `grep` in step 1 and can read the actual signature; the type name (`AskAdvice` vs. whatever `process_post_tool_use` returns) is a one-line correction, not a placeholder.

Type consistency:
- `Env<'a>` field names match across tasks: `policy`, `session`, `sandbox`.
- Trait method names match across the production impl and test fake.
- `crate::policy::Effect` is used consistently in trait, prod impl, and fake.

Out of scope (explicit non-goals for this plan):
- `handle_permission_request` migration. It already takes `&ClashSettings`; full hermeticity requires a `Notifier` trait covering desktop + Zulip resolution. Defer until a test asks for it.
- `Clock`, `Random`, `Stdio`, `HttpClient`, `Subprocess` ports. No current test asserts on time, randomness, stdout content, network responses, or subprocess outputs.
- Crate split (`clash-core` / `clash-adapters` / `clash-bin`). The lint guardrail gives most of the same enforcement without the disruption.
- Effects-as-data refactor (returning `Vec<Effect>` from handlers). Trait DI is enough for the current test surface; revisit if assertions on "exactly these side effects happened" become valuable.
