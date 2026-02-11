//! Linux sandbox backend using Landlock + seccomp.
//!
//! - Landlock: kernel-enforced filesystem access control (since 5.13)
//! - seccomp-BPF: syscall filtering for network isolation
//! - PR_SET_NO_NEW_PRIVS: prevent privilege escalation via setuid

use std::collections::BTreeMap;
use std::path::Path;

use crate::policy::sandbox_types::{Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy};
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use tracing::{Level, instrument};

use super::{SandboxError, SupportLevel, do_exec};

/// Apply sandbox policy and exec the command.
#[instrument(level = Level::TRACE, skip(policy))]
pub fn exec_sandboxed(
    policy: &SandboxPolicy,
    cwd: &Path,
    command: &[String],
) -> Result<std::convert::Infallible, SandboxError> {
    let cwd_str = cwd.to_string_lossy();

    // 1. Set NO_NEW_PRIVS (must come before seccomp and landlock)
    set_no_new_privs()?;

    // 2. Install seccomp network filter if network is denied
    if policy.network == NetworkPolicy::Deny {
        install_seccomp_network_filter()?;
    }

    // 3. Apply Landlock filesystem rules
    install_landlock_rules(policy, &cwd_str)?;

    // 4. Exec the command
    do_exec(command)
}

/// Check if the current kernel supports sandboxing.
#[instrument(level = Level::TRACE)]
pub fn check_support() -> SupportLevel {
    // Try to detect Landlock ABI support
    let abi_result = std::panic::catch_unwind(|| {
        // landlock crate will check kernel support internally
        Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(ABI::V5))
    });

    match abi_result {
        Ok(Ok(_)) => SupportLevel::Full,
        Ok(Err(_)) => SupportLevel::Partial {
            missing: vec!["Landlock may not be fully supported on this kernel".into()],
        },
        Err(_) => SupportLevel::Unsupported {
            reason: "Landlock not available on this kernel".into(),
        },
    }
}

/// Prevent privilege escalation via setuid/setgid binaries.
#[instrument(level = Level::TRACE)]
fn set_no_new_privs() -> Result<(), SandboxError> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(SandboxError::Apply(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Map Cap flags to Landlock AccessFs bitflags.
#[instrument(level = Level::TRACE)]
fn cap_to_access_fs(caps: Cap) -> landlock::BitFlags<AccessFs> {
    let mut access = landlock::BitFlags::<AccessFs>::empty();

    if caps.contains(Cap::READ) {
        access |= AccessFs::ReadFile | AccessFs::ReadDir;
    }
    if caps.contains(Cap::WRITE) {
        access |= AccessFs::WriteFile | AccessFs::Truncate;
    }
    if caps.contains(Cap::CREATE) {
        access |= AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::MakeSym
            | AccessFs::MakeFifo
            | AccessFs::MakeSock;
    }
    if caps.contains(Cap::DELETE) {
        access |= AccessFs::RemoveFile | AccessFs::RemoveDir;
    }
    if caps.contains(Cap::EXECUTE) {
        access |= AccessFs::Execute;
    }

    access
}

/// Collect the effective Landlock rules from the sandbox policy.
///
/// Strategy: since Landlock is additive (you grant access to paths, default is
/// deny-all for the handled access types), we need to:
/// 1. Determine which access types we want to restrict (handle)
/// 2. For each rule path, compute effective caps and add Landlock rules
#[instrument(level = Level::TRACE, skip(policy))]
fn install_landlock_rules(policy: &SandboxPolicy, cwd: &str) -> Result<(), SandboxError> {
    let abi = ABI::V5;
    let all_access = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(all_access)
        .map_err(|e| SandboxError::Apply(format!("landlock handle_access: {}", e)))?
        .create()
        .map_err(|e| SandboxError::Apply(format!("landlock create: {}", e)))?;

    // Always allow read+execute on the root filesystem (for system binaries, libs, etc.)
    // unless the policy explicitly denies reads somewhere
    let default_access = cap_to_access_fs(policy.default);
    if !default_access.is_empty() {
        ruleset = add_path_rule(ruleset, "/", default_access)?;
    }

    // Always allow write to /dev/null
    ruleset = add_path_rule(
        ruleset,
        "/dev/null",
        AccessFs::WriteFile | AccessFs::Truncate | AccessFs::ReadFile,
    )?;

    // Apply each rule
    for rule in &policy.rules {
        if rule.path_match == PathMatch::Regex {
            // Landlock can't enforce regex path rules — skip silently.
            // Regex rules are enforced on macOS via Seatbelt SBPL.
            continue;
        }
        if rule.effect == RuleEffect::Allow {
            let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
            let access = cap_to_access_fs(rule.caps);
            // Merge with default access for this path
            let total_access = access | default_access;
            if !total_access.is_empty() {
                ruleset = add_path_rule(ruleset, &resolved, total_access)?;
            }
        }
        // Deny rules are handled by NOT granting those caps — Landlock is
        // default-deny for handled access types, so we only grant what's allowed.
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Apply(format!("landlock restrict_self: {}", e)))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Apply(
            "landlock: ruleset not enforced (kernel may not support Landlock)".into(),
        ));
    }

    Ok(())
}

/// Add a path-based rule to the Landlock ruleset.
/// Silently ignores paths that don't exist (the sandbox shouldn't fail because
/// an optional path like $TMPDIR doesn't exist).
#[instrument(level = Level::TRACE)]
fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    match PathFd::new(path) {
        Ok(fd) => ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| SandboxError::Apply(format!("landlock add_rule for '{}': {}", path, e))),
        Err(_) => {
            // Path doesn't exist — skip silently
            Ok(ruleset)
        }
    }
}

/// Install a seccomp-BPF filter to block network syscalls.
///
/// Blocks socket creation for non-AF_UNIX domains, and blocks most
/// network-related syscalls outright. AF_UNIX is preserved for IPC
/// (tools like cargo use socketpair internally).
#[instrument(level = Level::TRACE)]
fn install_seccomp_network_filter() -> Result<(), SandboxError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Block these network syscalls unconditionally
    let deny_syscalls = [
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getpeername,
        libc::SYS_getsockname,
        libc::SYS_shutdown,
        libc::SYS_sendto,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        // Also block ptrace for security
        libc::SYS_ptrace,
    ];

    for &syscall in &deny_syscalls {
        rules.insert(syscall, vec![]);
    }

    // For socket() and socketpair(): only deny if domain != AF_UNIX
    let unix_only_rule = SeccompRule::new(vec![
        SeccompCondition::new(
            0, // first argument: domain
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(|e| SandboxError::Apply(format!("seccomp condition: {}", e)))?,
    ])
    .map_err(|e| SandboxError::Apply(format!("seccomp rule: {}", e)))?;

    rules.insert(libc::SYS_socket, vec![unix_only_rule.clone()]);
    rules.insert(libc::SYS_socketpair, vec![unix_only_rule]);

    let arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        return Err(SandboxError::Apply(
            "seccomp: unsupported architecture".into(),
        ));
    };

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,    // default: allow all syscalls
        SeccompAction::Errno(1), // EPERM for filtered syscalls
        arch,
    )
    .map_err(|e| SandboxError::Apply(format!("seccomp filter: {}", e)))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| SandboxError::Apply(format!("seccomp compile: {}", e)))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| SandboxError::Apply(format!("seccomp apply: {}", e)))?;

    Ok(())
}
