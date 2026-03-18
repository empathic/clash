//! macOS sandbox backend using Seatbelt (sandbox-exec / SBPL).
//!
//! Generates a Sandbox Profile Language (SBPL) profile from the SandboxPolicy
//! and applies it via `sandbox-exec -p <profile>`.

use std::path::Path;

use crate::policy::sandbox_types::{Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy};
use tracing::{Level, instrument};

use super::{SandboxError, SupportLevel};

/// Apply sandbox policy and exec the command via sandbox-exec.
///
/// `trace_path` is accepted for API consistency with the platform-agnostic
/// `exec_sandboxed()` in `mod.rs`. Modern macOS does not support the SBPL
/// `(trace)` directive or the `sandbox-exec -t` flag, so tracing is a no-op.
/// Sandbox violation detection relies on stderr heuristics in PostToolUse
/// (`sandbox_fs_hints`).
#[instrument(level = Level::TRACE, skip(policy))]
pub fn exec_sandboxed(
    policy: &SandboxPolicy,
    cwd: &Path,
    command: &[String],
    _trace_path: Option<&Path>,
) -> Result<std::convert::Infallible, SandboxError> {
    let cwd_str = cwd.to_string_lossy();
    let profile = compile_to_sbpl(policy, &cwd_str);

    // Build: sandbox-exec -p <profile> -- <command...>
    let mut args = vec!["sandbox-exec".to_string()];
    args.push("-p".to_string());
    args.push(profile);
    args.push("--".to_string());
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

    // DNS resolution via mDNSResponder
    p += "(allow system-socket)\n";

    // Default capabilities applied to root
    emit_caps_for_path(&mut p, "/", policy.default, PathMatch::Subpath);

    // Root directory readable (literal, not recursive) — some commands need
    // to stat "/" itself (e.g. `ls /`, path resolution).
    p += "(allow file-read* (literal \"/\"))\n";

    // /dev/null always writable
    p += "(allow file-write* (literal \"/dev/null\"))\n";

    // Collect all ancestor directories that need literal read access so that
    // realpath() / stat() can traverse to rule paths.  Seatbelt evaluates each
    // stat() independently, so `(subpath "/Users/eliot/.cargo")` does NOT
    // implicitly allow stat("/Users") or stat("/Users/eliot").
    let mut ancestors: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // Resolve all rule paths and collect ancestors, then sort by
    // specificity before emitting.  Seatbelt uses last-match-wins, so
    // we emit broadest rules first and most specific last — ensuring a
    // specific allow on /Users/eliot overrides a broad deny on /Users.
    struct ResolvedRule {
        effect: RuleEffect,
        caps: Cap,
        path_match: PathMatch,
        canonical: String,
        resolved: String,
    }

    let mut resolved_rules: Vec<ResolvedRule> = Vec::with_capacity(policy.rules.len());

    for rule in &policy.rules {
        let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
        // Strip trailing slashes — Seatbelt's `subpath` filter requires
        // paths without trailing separators (e.g. $TMPDIR ends with "/").
        let resolved = if resolved.len() > 1 {
            resolved.trim_end_matches('/').to_string()
        } else {
            resolved
        };
        let canonical = if rule.path_match != PathMatch::Regex {
            canonicalize_or_keep(&resolved)
        } else {
            resolved.clone()
        };

        // Collect ancestor directories for path traversal (both forms)
        if rule.path_match != PathMatch::Regex {
            for path in [&canonical, &resolved] {
                let mut dir = path.as_str();
                while let Some(pos) = dir.rfind('/') {
                    if pos == 0 {
                        break; // "/" is already handled above
                    }
                    dir = &dir[..pos];
                    if !ancestors.insert(dir.to_string()) {
                        break; // Already seen this ancestor and all its parents
                    }
                }
            }
        }

        resolved_rules.push(ResolvedRule {
            effect: rule.effect,
            caps: rule.caps,
            path_match: rule.path_match,
            canonical,
            resolved,
        });
    }

    // Sort by path depth (component count) ascending so broadest rules
    // are emitted first.  Within the same depth, deny before allow so
    // that a same-level allow wins via last-match-wins.
    resolved_rules.sort_by(|a, b| {
        let depth_a = a.canonical.matches('/').count();
        let depth_b = b.canonical.matches('/').count();
        depth_a.cmp(&depth_b).then_with(|| {
            // Deny = 0 (first), Allow = 1 (last) — allow wins at same depth
            let effect_ord = |e: &RuleEffect| match e {
                RuleEffect::Deny => 0,
                RuleEffect::Allow => 1,
            };
            effect_ord(&a.effect).cmp(&effect_ord(&b.effect))
        })
    });

    for rule in &resolved_rules {
        match rule.effect {
            RuleEffect::Allow => {
                emit_caps_for_path(&mut p, &rule.canonical, rule.caps, rule.path_match);
                // Also emit for the non-canonical path if different, since
                // Seatbelt may not resolve symlinks before matching.
                if rule.canonical != rule.resolved {
                    emit_caps_for_path(&mut p, &rule.resolved, rule.caps, rule.path_match);
                }
            }
            RuleEffect::Deny => {
                emit_deny_for_path(&mut p, &rule.canonical, rule.caps, rule.path_match);
                if rule.canonical != rule.resolved {
                    emit_deny_for_path(&mut p, &rule.resolved, rule.caps, rule.path_match);
                }
            }
        }
    }

    // Allow stat()/readdir() on ancestor directories so realpath() can
    // traverse to rule paths.
    for ancestor in &ancestors {
        p += &format!(
            "(allow file-read* (literal \"{}\"))\n",
            sbpl_escape(ancestor)
        );
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

/// Resolve symlinks for Seatbelt matching, but avoid resolving firmlinks.
///
/// macOS firmlinks (e.g. `/Users` → `/System/Volumes/Data/Users`) are
/// transparent to Seatbelt — it evaluates against the firmlink path, not
/// the underlying volume path.  `std::fs::canonicalize` resolves firmlinks,
/// which produces paths that Seatbelt never sees, causing rules to silently
/// fail.
///
/// Instead we only resolve the well-known macOS symlinks that Seatbelt
/// *does* follow (`/var` → `/private/var`, `/tmp` → `/private/tmp`, etc.).
fn canonicalize_or_keep(path: &str) -> String {
    // Well-known macOS symlinks that Seatbelt resolves.
    static SYMLINK_PREFIXES: &[(&str, &str)] = &[
        ("/var/", "/private/var/"),
        ("/tmp/", "/private/tmp/"),
        ("/etc/", "/private/etc/"),
    ];

    for &(prefix, replacement) in SYMLINK_PREFIXES {
        if let Some(rest) = path.strip_prefix(prefix) {
            return format!("{}{}", replacement, rest);
        }
    }

    // Exact matches (no trailing slash)
    match path {
        "/var" => "/private/var".to_string(),
        "/tmp" => "/private/tmp".to_string(),
        "/etc" => "/private/etc".to_string(),
        _ => path.to_string(),
    }
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
    use crate::policy::sandbox_types::SandboxRule;

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
            doc: None,
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

    // ── Rule specificity ordering ─────────────────────────────────

    #[test]
    fn specific_allow_overrides_broad_deny() {
        // Reproduces the real-world bug: deny on /Users shadowed allow
        // on /Users/eliot because deny was emitted after allow.
        let policy = SandboxPolicy {
            default: Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE,
                    path: "/Users/eliot".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE | Cap::EXECUTE,
                    path: "/Users".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let profile = compile_to_sbpl(&policy, "/tmp");

        // The deny on /Users must appear BEFORE the allow on /Users/eliot
        // so that Seatbelt's last-match-wins gives the specific allow priority.
        let deny_pos = profile
            .find("(deny file-read* (subpath \"/Users\"))")
            .expect("should contain deny on /Users");
        let allow_pos = profile
            .find("(allow file-read* (subpath \"/Users/eliot\"))")
            .expect("should contain allow on /Users/eliot");
        assert!(
            deny_pos < allow_pos,
            "deny /Users (pos {deny_pos}) must come before allow /Users/eliot (pos {allow_pos})\nprofile:\n{profile}"
        );
    }

    #[test]
    fn deny_at_same_depth_loses_to_allow() {
        // When allow and deny target the same path, allow should come last
        // (and win) in the compiled profile.
        let policy = SandboxPolicy {
            default: Cap::empty() | Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE,
                    path: "/data".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::WRITE,
                    path: "/data".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let profile = compile_to_sbpl(&policy, "/tmp");
        let deny_pos = profile
            .find("(deny file-write* (subpath \"/data\"))")
            .expect("should contain deny write on /data");
        let allow_pos = profile
            .find("(allow file-write* (subpath \"/data\"))")
            .expect("should contain allow write on /data");
        assert!(
            deny_pos < allow_pos,
            "deny should come before allow at same depth\nprofile:\n{profile}"
        );
    }

    #[test]
    fn three_level_specificity() {
        // deny /Users → allow /Users/eliot → deny /Users/eliot/.ssh
        let policy = SandboxPolicy {
            default: Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ,
                    path: "/Users/eliot".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::READ,
                    path: "/Users".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::READ,
                    path: "/Users/eliot/.ssh".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let profile = compile_to_sbpl(&policy, "/tmp");

        let deny_users = profile
            .find("(deny file-read* (subpath \"/Users\"))")
            .expect("deny /Users");
        let allow_eliot = profile
            .find("(allow file-read* (subpath \"/Users/eliot\"))")
            .expect("allow /Users/eliot");
        let deny_ssh = profile
            .find("(deny file-read* (subpath \"/Users/eliot/.ssh\"))")
            .expect("deny /Users/eliot/.ssh");

        assert!(
            deny_users < allow_eliot,
            "deny /Users must come before allow /Users/eliot"
        );
        assert!(
            allow_eliot < deny_ssh,
            "allow /Users/eliot must come before deny /Users/eliot/.ssh"
        );
    }

    #[test]
    fn sbpl_localhost_same_as_allow_domains() {
        let localhost_policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Localhost,
            doc: None,
        };
        let domains_policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::AllowDomains(vec!["example.com".into()]),
            doc: None,
        };
        let localhost_profile = compile_to_sbpl(&localhost_policy, "/tmp");
        let domains_profile = compile_to_sbpl(&domains_policy, "/tmp");
        // Both should produce the same network section (localhost-only + deny rest)
        assert_eq!(localhost_profile, domains_profile);
    }
}
