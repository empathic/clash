//! macOS sandbox backend using Seatbelt (sandbox-exec / SBPL).
//!
//! Generates a Sandbox Profile Language (SBPL) profile from the SandboxPolicy
//! and applies it via `sandbox-exec -p <profile>`.

use std::path::Path;

use claude_settings::sandbox::{Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy};
use tracing::{Level, instrument};

use super::{SandboxError, SupportLevel};

/// Apply sandbox policy and exec the command via sandbox-exec.
#[instrument(level = Level::TRACE, skip(policy))]
pub fn exec_sandboxed(
    policy: &SandboxPolicy,
    cwd: &Path,
    command: &[String],
) -> Result<std::convert::Infallible, SandboxError> {
    let cwd_str = cwd.to_string_lossy();
    let profile = compile_to_sbpl(policy, &cwd_str);

    // Build: sandbox-exec -p <profile> -- <command...>
    let mut args = vec![
        "sandbox-exec".to_string(),
        "-p".to_string(),
        profile,
        "--".to_string(),
    ];
    args.extend_from_slice(command);

    super::do_exec(&args)
}

/// Check if sandbox-exec is available.
#[instrument(level = Level::TRACE)]
pub fn check_support() -> SupportLevel {
    if Path::new("/usr/bin/sandbox-exec").exists() {
        SupportLevel::Full
    } else {
        SupportLevel::Unsupported {
            reason: "/usr/bin/sandbox-exec not found".into(),
        }
    }
}

/// Compile a SandboxPolicy into a Seatbelt SBPL profile string.
#[instrument(level = Level::TRACE)]
fn compile_to_sbpl(policy: &SandboxPolicy, cwd: &str) -> String {
    let mut p = String::from("(version 1)\n(deny default)\n");

    // Always needed for basic process operation
    p += "(allow process-fork)\n";
    p += "(allow sysctl-read)\n";
    p += "(allow mach-lookup)\n";
    p += "(allow mach-register)\n";

    // Default capabilities applied to root
    emit_caps_for_path(&mut p, "/", policy.default, PathMatch::Subpath);

    // /dev/null always writable
    p += "(allow file-write* (literal \"/dev/null\"))\n";
    p += "(allow file-read-data (literal \"/dev/null\"))\n";

    // Process allow rules first, then deny rules override
    for rule in &policy.rules {
        let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
        match rule.effect {
            RuleEffect::Allow => {
                emit_caps_for_path(&mut p, &resolved, rule.caps, rule.path_match);
            }
            RuleEffect::Deny => {
                emit_deny_for_path(&mut p, &resolved, rule.caps, rule.path_match);
            }
        }
    }

    // Network
    match policy.network {
        NetworkPolicy::Deny => {
            p += "(deny network*)\n";
        }
        NetworkPolicy::Allow => {
            p += "(allow network*)\n";
        }
    }

    p
}

/// Build an SBPL path filter from a path and match type.
#[instrument(level = Level::TRACE)]
fn sbpl_filter(path: &str, path_match: PathMatch) -> String {
    match path_match {
        PathMatch::Subpath => format!("(subpath \"{}\")", path),
        PathMatch::Literal => format!("(literal \"{}\")", path),
        PathMatch::Regex => format!("(regex #\"{}\")", path),
    }
}

/// Emit SBPL allow statements for the given caps on a path.
#[instrument(level = Level::TRACE)]
fn emit_caps_for_path(profile: &mut String, path: &str, caps: Cap, path_match: PathMatch) {
    let filter = sbpl_filter(path, path_match);

    if caps.contains(Cap::READ) {
        profile.push_str(&format!("(allow file-read* {})\n", filter));
    }
    if caps.contains(Cap::WRITE) {
        profile.push_str(&format!("(allow file-write-data {})\n", filter));
    }
    if caps.contains(Cap::CREATE) {
        profile.push_str(&format!("(allow file-write-create {})\n", filter));
    }
    if caps.contains(Cap::DELETE) {
        profile.push_str(&format!("(allow file-write-unlink {})\n", filter));
    }
    if caps.contains(Cap::EXECUTE) {
        profile.push_str(&format!("(allow process-exec {})\n", filter));
    }
}

/// Emit SBPL deny statements for the given caps on a path.
#[instrument(level = Level::TRACE)]
fn emit_deny_for_path(profile: &mut String, path: &str, caps: Cap, path_match: PathMatch) {
    let filter = sbpl_filter(path, path_match);

    if caps.contains(Cap::READ) {
        profile.push_str(&format!("(deny file-read* {})\n", filter));
    }
    if caps.contains(Cap::WRITE) {
        profile.push_str(&format!("(deny file-write-data {})\n", filter));
    }
    if caps.contains(Cap::CREATE) {
        profile.push_str(&format!("(deny file-write-create {})\n", filter));
    }
    if caps.contains(Cap::DELETE) {
        profile.push_str(&format!("(deny file-write-unlink {})\n", filter));
    }
    if caps.contains(Cap::EXECUTE) {
        profile.push_str(&format!("(deny process-exec {})\n", filter));
    }
}
