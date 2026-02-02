//! Sandbox enforcement backends.
//!
//! Each platform implements `exec_sandboxed` which applies kernel-enforced
//! restrictions and then execs the target command. The restrictions are
//! inherited by all child processes and cannot be removed.

use std::path::Path;

use claude_settings::sandbox::SandboxPolicy;

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

/// Apply the sandbox policy and exec the command.
///
/// This function does not return on success — it replaces the current
/// process with the target command via `execvp`.
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
