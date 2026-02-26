//! macOS sandbox backend using Seatbelt (sandbox-exec / SBPL).
//!
//! Generates a Sandbox Profile Language (SBPL) profile from the SandboxPolicy
//! and applies it via `sandbox-exec -p <profile>`.

use std::path::Path;

use crate::policy::sandbox_types::{Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy};
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
pub fn compile_to_sbpl(policy: &SandboxPolicy, cwd: &str) -> String {
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

    // Process allow rules first, then deny rules override.
    // For Subpath/Literal rules, canonicalize the path to resolve symlinks
    // (e.g., /var → /private/var, /tmp → /private/tmp on macOS) so that
    // Seatbelt matches against the real filesystem path.
    for rule in &policy.rules {
        let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
        let canonical = if rule.path_match != PathMatch::Regex {
            canonicalize_or_keep(&resolved)
        } else {
            resolved
        };
        match rule.effect {
            RuleEffect::Allow => {
                emit_caps_for_path(&mut p, &canonical, rule.caps, rule.path_match);
            }
            RuleEffect::Deny => {
                emit_deny_for_path(&mut p, &canonical, rule.caps, rule.path_match);
            }
        }
    }

    // Network
    match &policy.network {
        NetworkPolicy::Deny => {
            p += "(deny network*)\n";
        }
        NetworkPolicy::Allow => {
            p += "(allow network*)\n";
        }
        NetworkPolicy::Localhost | NetworkPolicy::AllowDomains(_) => {
            // Allow only localhost connections. For Localhost, this is the
            // complete enforcement. For AllowDomains, a proxy on localhost
            // handles domain filtering.
            //
            // Seatbelt's (remote ip) filter only accepts "localhost" or "*" as
            // host — raw IPs like "127.0.0.1" are not valid. "localhost" covers
            // both IPv4 (127.0.0.1) and IPv6 (::1) loopback.
            p += "(allow network-outbound (remote ip \"localhost:*\"))\n";
            p += "(deny network*)\n";
        }
    }

    p
}

/// Resolve symlinks in a path for Seatbelt matching. Falls back to the
/// original string if canonicalization fails (e.g., path doesn't exist yet).
fn canonicalize_or_keep(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Escape a path string for use inside an SBPL string literal.
///
/// Backslashes are escaped to `\\` and double quotes are escaped to `\"`,
/// preventing a crafted path from breaking out of the Seatbelt profile
/// string literal.
fn sbpl_escape(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build an SBPL path filter from a path and match type.
///
/// For `Subpath` and `Literal` variants the path is escaped to prevent
/// injection via characters that are special inside SBPL string literals.
/// The `Regex` variant is left unescaped because its pattern comes from the
/// policy author, not from untrusted input, and regex has its own escaping
/// rules.
#[instrument(level = Level::TRACE)]
fn sbpl_filter(path: &str, path_match: PathMatch) -> String {
    match path_match {
        PathMatch::Subpath => format!("(subpath \"{}\")", sbpl_escape(path)),
        PathMatch::Literal => format!("(literal \"{}\")", sbpl_escape(path)),
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
        // WRITE grants all file-write sub-operations (data, mode, flags,
        // setattr, xattr, times, create, unlink, mkdir, etc.) — matching
        // the wildcard approach used by READ → file-read*.
        profile.push_str(&format!("(allow file-write* {})\n", filter));
    } else {
        // Without WRITE, emit only the specific sub-operations requested.
        if caps.contains(Cap::CREATE) {
            // CREATE needs file-write-create plus data/xattr/mode operations
            // because tools like `cp` must write content and metadata to
            // newly created files (not just the creation syscall).
            profile.push_str(&format!("(allow file-write-create {})\n", filter));
            profile.push_str(&format!("(allow file-write-data {})\n", filter));
            profile.push_str(&format!("(allow file-write-xattr {})\n", filter));
            profile.push_str(&format!("(allow file-write-mode {})\n", filter));
            profile.push_str(&format!("(allow file-write-flags {})\n", filter));
        }
        if caps.contains(Cap::DELETE) {
            profile.push_str(&format!("(allow file-write-unlink {})\n", filter));
        }
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
        profile.push_str(&format!("(deny file-write* {})\n", filter));
    } else {
        if caps.contains(Cap::CREATE) {
            profile.push_str(&format!("(deny file-write-create {})\n", filter));
            profile.push_str(&format!("(deny file-write-data {})\n", filter));
            profile.push_str(&format!("(deny file-write-xattr {})\n", filter));
            profile.push_str(&format!("(deny file-write-mode {})\n", filter));
            profile.push_str(&format!("(deny file-write-flags {})\n", filter));
        }
        if caps.contains(Cap::DELETE) {
            profile.push_str(&format!("(deny file-write-unlink {})\n", filter));
        }
    }
    if caps.contains(Cap::EXECUTE) {
        profile.push_str(&format!("(deny process-exec {})\n", filter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sbpl_escape ──────────────────────────────────────────────────

    #[test]
    fn escape_normal_path_unchanged() {
        assert_eq!(sbpl_escape("/usr/local/bin"), "/usr/local/bin");
    }

    #[test]
    fn escape_path_with_double_quote() {
        assert_eq!(sbpl_escape("/tmp/evil\"path"), "/tmp/evil\\\"path");
    }

    #[test]
    fn escape_path_with_backslash() {
        assert_eq!(sbpl_escape("/tmp/evil\\path"), "/tmp/evil\\\\path");
    }

    #[test]
    fn escape_path_with_both_backslash_and_quote() {
        assert_eq!(sbpl_escape("/tmp/e\\vi\"l"), "/tmp/e\\\\vi\\\"l");
    }

    // ── sbpl_filter with adversarial paths ───────────────────────────

    #[test]
    fn filter_subpath_normal() {
        assert_eq!(
            sbpl_filter("/usr/local", PathMatch::Subpath),
            "(subpath \"/usr/local\")"
        );
    }

    #[test]
    fn filter_literal_normal() {
        assert_eq!(
            sbpl_filter("/usr/local/bin/rustc", PathMatch::Literal),
            "(literal \"/usr/local/bin/rustc\")"
        );
    }

    #[test]
    fn filter_regex_normal() {
        assert_eq!(
            sbpl_filter("/tmp/build-.*", PathMatch::Regex),
            "(regex #\"/tmp/build-.*\")"
        );
    }

    #[test]
    fn filter_subpath_with_quote_injection() {
        // A malicious path that tries to close the string and inject SBPL
        let malicious = "/tmp/evil\") (allow default) (\"";
        let result = sbpl_filter(malicious, PathMatch::Subpath);
        assert_eq!(result, "(subpath \"/tmp/evil\\\") (allow default) (\\\"\")");
        // The quotes are escaped, so the SBPL string literal stays intact.
        assert!(result.starts_with("(subpath \""));
        assert!(result.ends_with("\")"));
    }

    #[test]
    fn filter_literal_with_backslash_and_quote() {
        let adversarial = "/tmp/a\\b\"c";
        let result = sbpl_filter(adversarial, PathMatch::Literal);
        assert_eq!(result, "(literal \"/tmp/a\\\\b\\\"c\")");
    }

    #[test]
    fn filter_regex_is_not_escaped() {
        // Regex variant must NOT escape — policy authors control regex content.
        let pattern = "/tmp/foo\"bar";
        let result = sbpl_filter(pattern, PathMatch::Regex);
        assert_eq!(result, "(regex #\"/tmp/foo\"bar\")");
    }

    // ── Network policy SBPL ────────────────────────────────────────

    #[test]
    fn sbpl_localhost_allows_only_loopback() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Localhost,
        };
        let profile = compile_to_sbpl(&policy, "/tmp");
        assert!(
            profile.contains("(allow network-outbound (remote ip \"localhost:*\"))"),
            "Localhost policy should allow outbound to localhost"
        );
        assert!(
            profile.contains("(deny network*)"),
            "Localhost policy should deny all other network"
        );
    }

    #[test]
    fn sbpl_localhost_same_as_allow_domains() {
        let localhost_policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Localhost,
        };
        let domains_policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::AllowDomains(vec!["example.com".into()]),
        };
        let localhost_profile = compile_to_sbpl(&localhost_policy, "/tmp");
        let domains_profile = compile_to_sbpl(&domains_policy, "/tmp");
        // Both should produce the same network section (localhost-only + deny rest)
        assert_eq!(localhost_profile, domains_profile);
    }
}
