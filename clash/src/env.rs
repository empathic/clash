//! Capability-based env injection for hook handlers.
//!
//! The production hook entry points (`handle_session_start` plus the
//! `PreToolUse` / `PostToolUse` / `Stop` arms in `cmd/hooks.rs`) need to be
//! unit-testable without reaching into the real `$HOME`, real filesystem,
//! or real sandbox probe. Each env-dependent capability is expressed as a
//! small trait. Production wires the real functions via [`Env::prod`];
//! tests construct an [`Env`] from stub or in-memory implementations.
//!
//! **Lint guardrail.** `clippy.toml` at the repo root disallows direct calls
//! to every function wrapped by this module. This file is the only place
//! that may invoke them (the top-level `#![allow(clippy::disallowed_methods)]`
//! permits it). When you add a new env-dependent capability, add the method
//! to the appropriate trait here, add the underlying function to
//! `clippy.toml`'s `disallowed-methods`, and migrate existing handler
//! callers through the trait. CLI commands that legitimately bypass `Env`
//! (e.g. `clash doctor`) annotate their callsite with a per-site
//! `#[allow(clippy::disallowed_methods)]` and a rationale comment.

#![allow(clippy::disallowed_methods)] // adapter module: the only place that may call the wrapped functions

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

    /// Look up and clear a pending ask record; returns suggested rule advice
    /// if the tool use matches a prior `ask` decision the user accepted.
    fn consume_pending_ask(
        &self,
        tool_use_id: &str,
        session_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) -> Option<crate::session_policy::ApprovalAdvice>;
}

/// Probe the host for sandbox support.
pub trait SandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel;
}

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

    fn consume_pending_ask(
        &self,
        tool_use_id: &str,
        session_id: &str,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) -> Option<crate::session_policy::ApprovalAdvice> {
        crate::session_policy::process_post_tool_use(
            tool_use_id,
            session_id,
            tool_name,
            tool_input,
            cwd,
        )
    }
}

/// Production [`SandboxProbe`]. Zero-sized; lives as a `static`.
pub struct DefaultSandboxProbe;
impl SandboxProbe for DefaultSandboxProbe {
    fn check_support(&self) -> crate::sandbox::SupportLevel {
        crate::sandbox::check_support()
    }
}

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

// ---------------------------------------------------------------------------
// Test fakes
// ---------------------------------------------------------------------------

/// Hermetic in-memory [`Env`] for unit tests. Writes land in a [`TempDir`]
/// so they vanish at end of test; sandbox probe returns canned `Full`;
/// policy operations return success without touching disk.
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
        let dir = self
            .tempdir
            .path()
            .join("sessions")
            .join(&input.session_id);
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

    fn consume_pending_ask(
        &self,
        _tool_use_id: &str,
        _session_id: &str,
        _tool_name: &str,
        _tool_input: &serde_json::Value,
        _cwd: &str,
    ) -> Option<crate::session_policy::ApprovalAdvice> {
        None
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_prod_constructs() {
        let _env = Env::prod();
    }

    #[test]
    fn default_sandbox_probe_matches_check_support() {
        let direct = crate::sandbox::check_support();
        let via_env = DEFAULT_SANDBOX_PROBE.check_support();
        let same_variant = matches!(
            (&direct, &via_env),
            (
                crate::sandbox::SupportLevel::Full,
                crate::sandbox::SupportLevel::Full
            ) | (
                crate::sandbox::SupportLevel::Partial { .. },
                crate::sandbox::SupportLevel::Partial { .. }
            ) | (
                crate::sandbox::SupportLevel::Unsupported { .. },
                crate::sandbox::SupportLevel::Unsupported { .. }
            )
        );
        assert!(same_variant, "trait delegate diverged from direct call");
    }

    #[test]
    fn test_env_is_hermetic() {
        let test_env = TestEnv::new();
        let env = test_env.env();

        assert!(env.policy.ensure_user_policy().unwrap().is_none());
        let hook_ctx = crate::settings::HookContext::from_transcript_path("/tmp/t.jsonl");
        env.policy.validate_session("test-session", &hook_ctx).unwrap();

        assert!(matches!(
            env.sandbox.check_support(),
            crate::sandbox::SupportLevel::Full
        ));

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
}
