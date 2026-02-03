//! Sandbox enforcement backends.
//!
//! Each platform implements `exec_sandboxed` which applies kernel-enforced
//! restrictions and then execs the target command. The restrictions are
//! inherited by all child processes and cannot be removed.
//!
//! The `SandboxBackend` trait abstracts over platform-specific enforcement,
//! enabling a `MockSandbox` for testing without kernel features.

use std::path::Path;

use claude_settings::sandbox::SandboxPolicy;
use tracing::{Level, instrument};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

/// Result of checking platform sandbox support.
#[derive(Debug)]
pub enum SupportLevel {
    /// All policy features are supported.
    Full,
    /// Some features are missing (e.g., network filtering on older kernels).
    Partial { missing: Vec<String> },
    /// Sandbox not supported on this platform/kernel.
    Unsupported { reason: String },
}

/// Error during sandbox setup or execution.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox not supported: {0}")]
    Unsupported(String),
    #[error("failed to apply sandbox: {0}")]
    Apply(String),
    #[error("failed to exec command: {0}")]
    Exec(#[from] std::io::Error),
}

/// Trait abstracting over sandbox enforcement backends.
///
/// Platform implementations (Linux/Landlock, macOS/Seatbelt) use kernel
/// mechanisms and replace the process. The `MockSandbox` records the
/// policy and command for testing without kernel features.
pub trait SandboxBackend {
    /// Apply the sandbox policy and exec the command.
    ///
    /// For real backends, this replaces the process and never returns on success.
    /// For mock backends, this records the call and returns Ok(()).
    fn apply_and_exec(
        &self,
        policy: &SandboxPolicy,
        cwd: &Path,
        command: &[String],
    ) -> Result<(), SandboxError>;

    /// Check whether this backend is supported.
    fn check_support(&self) -> SupportLevel;
}

/// A mock sandbox backend that records policy applications for testing.
///
/// Instead of applying kernel-level restrictions, it records what would
/// have been enforced, allowing unit tests to verify sandbox policy
/// generation without requiring root or kernel features.
#[cfg(test)]
pub struct MockSandbox {
    /// Recorded sandbox applications: (policy, cwd, command).
    pub applications: std::cell::RefCell<Vec<MockApplication>>,
    /// What support level to report.
    pub support: SupportLevel,
}

/// A recorded sandbox application.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct MockApplication {
    pub policy: SandboxPolicy,
    pub cwd: String,
    pub command: Vec<String>,
}

#[cfg(test)]
impl MockSandbox {
    pub fn new() -> Self {
        Self {
            applications: std::cell::RefCell::new(Vec::new()),
            support: SupportLevel::Full,
        }
    }

    pub fn with_support(mut self, support: SupportLevel) -> Self {
        self.support = support;
        self
    }

    pub fn applications(&self) -> Vec<MockApplication> {
        self.applications.borrow().clone()
    }
}

#[cfg(test)]
impl SandboxBackend for MockSandbox {
    fn apply_and_exec(
        &self,
        policy: &SandboxPolicy,
        cwd: &Path,
        command: &[String],
    ) -> Result<(), SandboxError> {
        self.applications.borrow_mut().push(MockApplication {
            policy: policy.clone(),
            cwd: cwd.to_string_lossy().into_owned(),
            command: command.to_vec(),
        });
        Ok(())
    }

    fn check_support(&self) -> SupportLevel {
        // Return Full since we can't move out of &self
        SupportLevel::Full
    }
}

/// Apply the sandbox policy and exec the command.
///
/// This function does not return on success — it replaces the current
/// process with the target command via `execvp`.
#[instrument(level = Level::TRACE, skip(policy))]
pub fn exec_sandboxed(
    policy: &SandboxPolicy,
    cwd: &Path,
    command: &[String],
) -> Result<std::convert::Infallible, SandboxError> {
    if command.is_empty() {
        return Err(SandboxError::Apply("no command specified".into()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::exec_sandboxed(policy, cwd, command)
    }

    #[cfg(target_os = "macos")]
    {
        macos::exec_sandboxed(policy, cwd, command)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(SandboxError::Unsupported(
            "sandbox only supported on Linux and macOS".into(),
        ))
    }
}

/// Check whether sandboxing is supported on the current platform.
#[instrument(level = Level::TRACE)]
pub fn check_support() -> SupportLevel {
    #[cfg(target_os = "linux")]
    {
        linux::check_support()
    }

    #[cfg(target_os = "macos")]
    {
        macos::check_support()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        SupportLevel::Unsupported {
            reason: "sandbox only supported on Linux and macOS".into(),
        }
    }
}

/// Exec a command (without sandbox), replacing the current process.
/// Used as the final step after sandbox setup.
#[instrument(level = Level::TRACE)]
pub(crate) fn do_exec(command: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    use std::ffi::CString;

    let c_command = CString::new(command[0].as_str())
        .map_err(|e| SandboxError::Apply(format!("invalid command: {}", e)))?;
    let c_args: Vec<CString> = command
        .iter()
        .map(|arg| CString::new(arg.as_str()))
        .collect::<Result<_, _>>()
        .map_err(|e| SandboxError::Apply(format!("invalid argument: {}", e)))?;
    let c_args_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::execvp(c_command.as_ptr(), c_args_ptrs.as_ptr());
    }

    // execvp only returns on error
    Err(SandboxError::Exec(std::io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_settings::sandbox::{Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxRule};

    fn simple_policy() -> SandboxPolicy {
        SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::all(),
                    path: "/tmp".into(),
                    path_match: PathMatch::Subpath,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::READ,
                    path: "/etc/shadow".into(),
                    path_match: PathMatch::Literal,
                },
            ],
            network: NetworkPolicy::Deny,
        }
    }

    #[test]
    fn mock_sandbox_records_applications() {
        let mock = MockSandbox::new();
        let policy = simple_policy();
        let cwd = Path::new("/home/user");
        let command = vec!["ls".into(), "-la".into()];

        mock.apply_and_exec(&policy, cwd, &command).unwrap();

        let apps = mock.applications();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].cwd, "/home/user");
        assert_eq!(apps[0].command, vec!["ls", "-la"]);
        assert_eq!(apps[0].policy.network, NetworkPolicy::Deny);
        assert_eq!(apps[0].policy.rules.len(), 2);
    }

    #[test]
    fn mock_sandbox_records_multiple_applications() {
        let mock = MockSandbox::new();
        let policy = simple_policy();

        mock.apply_and_exec(&policy, Path::new("/a"), &["cmd1".into()])
            .unwrap();
        mock.apply_and_exec(&policy, Path::new("/b"), &["cmd2".into()])
            .unwrap();

        let apps = mock.applications();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].cwd, "/a");
        assert_eq!(apps[1].cwd, "/b");
    }

    #[test]
    fn mock_sandbox_reports_full_support() {
        let mock = MockSandbox::new();
        assert!(matches!(mock.check_support(), SupportLevel::Full));
    }

    #[test]
    fn effective_caps_default_only() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Allow,
        };
        let caps = policy.effective_caps("/any/path", "/cwd");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn effective_caps_allow_rule() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/tmp".into(),
                path_match: PathMatch::Subpath,
            }],
            network: NetworkPolicy::Allow,
        };
        let caps = policy.effective_caps("/tmp/file.txt", "/cwd");
        assert_eq!(caps, Cap::READ | Cap::WRITE);
    }

    #[test]
    fn effective_caps_deny_overrides_allow() {
        let policy = SandboxPolicy {
            default: Cap::all(),
            rules: vec![SandboxRule {
                effect: RuleEffect::Deny,
                caps: Cap::WRITE | Cap::DELETE,
                path: "/etc".into(),
                path_match: PathMatch::Subpath,
            }],
            network: NetworkPolicy::Allow,
        };
        let caps = policy.effective_caps("/etc/passwd", "/cwd");
        // All caps minus WRITE and DELETE
        assert!(caps.contains(Cap::READ));
        assert!(caps.contains(Cap::EXECUTE));
        assert!(!caps.contains(Cap::WRITE));
        assert!(!caps.contains(Cap::DELETE));
    }

    #[test]
    fn effective_caps_deny_overrides_default_and_allow() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::WRITE,
                    path: "/data".into(),
                    path_match: PathMatch::Subpath,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE,
                    path: "/data/readonly".into(),
                    path_match: PathMatch::Subpath,
                },
            ],
            network: NetworkPolicy::Allow,
        };
        // /data/file.txt: default READ + allow WRITE = READ | WRITE
        assert_eq!(
            policy.effective_caps("/data/file.txt", "/cwd"),
            Cap::READ | Cap::WRITE
        );
        // /data/readonly/file.txt: deny WRITE overrides allow WRITE
        assert_eq!(
            policy.effective_caps("/data/readonly/file.txt", "/cwd"),
            Cap::READ
        );
    }

    #[test]
    fn effective_caps_literal_match() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Deny,
                caps: Cap::READ,
                path: "/secret.key".into(),
                path_match: PathMatch::Literal,
            }],
            network: NetworkPolicy::Allow,
        };
        // Exact match → denied
        assert_eq!(policy.effective_caps("/secret.key", "/cwd"), Cap::empty());
        // Non-match → default
        assert_eq!(policy.effective_caps("/secret.key.bak", "/cwd"), Cap::READ);
    }

    #[test]
    fn effective_caps_no_match_uses_default() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::all(),
                path: "/tmp".into(),
                path_match: PathMatch::Subpath,
            }],
            network: NetworkPolicy::Allow,
        };
        // Path outside /tmp → only default caps
        assert_eq!(
            policy.effective_caps("/home/user/file", "/cwd"),
            Cap::READ | Cap::EXECUTE
        );
    }
}
