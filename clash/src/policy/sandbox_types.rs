//! Sandbox capability types for kernel-enforced process restrictions.
//!
//! These types define a platform-agnostic sandbox policy that compiles to
//! Landlock+seccomp on Linux or Seatbelt SBPL on macOS.

use std::path::Path;

use serde::{Deserialize, Serialize};

bitflags::bitflags! {
    /// High-level filesystem capabilities.
    ///
    /// Each platform backend maps these to its own enforcement primitives:
    /// - Linux: Landlock `AccessFs` bitflags
    /// - macOS: Seatbelt SBPL operations
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Cap: u8 {
        /// Read files and list directories.
        const READ    = 0b0000_0001;
        /// Write/modify existing files (includes truncate).
        const WRITE   = 0b0000_0010;
        /// Create new files, directories, symlinks, etc.
        const CREATE  = 0b0000_0100;
        /// Delete (unlink) files or remove directories.
        const DELETE  = 0b0000_1000;
        /// Execute files as programs.
        const EXECUTE = 0b0001_0000;
    }
}

impl Cap {
    /// Return capabilities as a list of name strings.
    pub fn to_list(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.contains(Cap::READ) {
            names.push("read");
        }
        if self.contains(Cap::WRITE) {
            names.push("write");
        }
        if self.contains(Cap::CREATE) {
            names.push("create");
        }
        if self.contains(Cap::DELETE) {
            names.push("delete");
        }
        if self.contains(Cap::EXECUTE) {
            names.push("execute");
        }
        names
    }

    /// Parse a single capability name.
    pub fn parse_single(s: &str) -> Result<Cap, String> {
        match s {
            "read" => Ok(Cap::READ),
            "write" => Ok(Cap::WRITE),
            "create" => Ok(Cap::CREATE),
            "delete" => Ok(Cap::DELETE),
            "execute" => Ok(Cap::EXECUTE),
            "full" | "all" => Ok(Cap::all()),
            other => Err(format!("unknown capability: '{}'", other)),
        }
    }

    /// Format capabilities as a human-readable string like "read + write".
    pub fn display(&self) -> String {
        let mut parts = Vec::new();
        if self.contains(Cap::READ) {
            parts.push("read");
        }
        if self.contains(Cap::WRITE) {
            parts.push("write");
        }
        if self.contains(Cap::CREATE) {
            parts.push("create");
        }
        if self.contains(Cap::DELETE) {
            parts.push("delete");
        }
        if self.contains(Cap::EXECUTE) {
            parts.push("execute");
        }
        parts.join(" + ")
    }

    /// Compact `ls -l`-style capability string: `rwcdx`.
    ///
    /// Each position is the capability letter when set, or `-` when absent:
    /// `r`ead `w`rite `c`reate `d`elete e`x`ecute.
    ///
    /// Examples: `rwcdx` (all), `rw---` (read+write), `r---x` (read+exec).
    pub fn short(&self) -> String {
        let mut s = String::with_capacity(5);
        s.push(if self.contains(Cap::READ) { 'r' } else { '-' });
        s.push(if self.contains(Cap::WRITE) { 'w' } else { '-' });
        s.push(if self.contains(Cap::CREATE) { 'c' } else { '-' });
        s.push(if self.contains(Cap::DELETE) { 'd' } else { '-' });
        s.push(if self.contains(Cap::EXECUTE) {
            'x'
        } else {
            '-'
        });
        s
    }
}

impl Serialize for Cap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let names = self.to_list();
        let mut seq = serializer.serialize_seq(Some(names.len()))?;
        for name in &names {
            seq.serialize_element(name)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Cap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct CapVisitor;

        impl<'de> de::Visitor<'de> for CapVisitor {
            type Value = Cap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#"a list of capabilities like ["read", "write"]"#)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Cap, A::Error> {
                let mut caps = Cap::empty();
                while let Some(name) = seq.next_element::<String>()? {
                    caps |= Cap::parse_single(&name).map_err(de::Error::custom)?;
                }
                if caps.is_empty() {
                    return Err(de::Error::custom("capability list must not be empty"));
                }
                Ok(caps)
            }
        }

        deserializer.deserialize_any(CapVisitor)
    }
}

/// A sandbox policy is a list of capability rules applied to paths,
/// plus a network policy. Platform backends compile this to their
/// native enforcement (Landlock+seccomp, Seatbelt SBPL, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Default capabilities for paths not matched by any rule.
    /// Typical default: `read + execute` (can read and run, but not modify).
    pub default: Cap,

    /// List of rules. Deny rules take precedence over allow rules
    /// (matching the existing clash policy precedence model).
    #[serde(default)]
    pub rules: Vec<SandboxRule>,

    /// Network access policy.
    #[serde(default)]
    pub network: NetworkPolicy,

    /// Optional docstring describing this sandbox's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// A single sandbox rule granting or revoking capabilities on a path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRule {
    /// Whether this rule grants or revokes capabilities.
    pub effect: RuleEffect,

    /// The capabilities this rule applies to.
    pub caps: Cap,

    /// The path or pattern this rule applies to. Supports `$PWD`, `$HOME`, `$TMPDIR`.
    pub path: String,

    /// How the path is matched against the filesystem.
    #[serde(default)]
    pub path_match: PathMatch,

    /// When true, also grant this rule's access to the git worktree's
    /// shared directories (`.git/worktrees/<name>` and the main `.git/`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub follow_worktrees: bool,

    /// Optional docstring describing this rule's purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

/// How a sandbox rule's path is matched against the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PathMatch {
    /// Match this path and all descendants (recursive).
    Subpath,
    /// Match exactly this path (non-recursive).
    #[default]
    Literal,
    /// Match direct children of this path (one level deep).
    #[serde(rename = "child_of")]
    ChildOf,
    /// Match paths against a regex pattern.
    /// Supported on macOS (Seatbelt SBPL). Skipped on Linux (Landlock).
    Regex,
}

/// Whether a rule grants or revokes capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleEffect {
    Allow,
    Deny,
}

/// Network access policy for sandboxed processes.
///
/// Four modes:
/// - `Deny`: block all network at kernel level
/// - `Allow`: unrestricted network access
/// - `Localhost`: allow connections only to localhost (127.0.0.1/::1),
///   enforced at kernel level without a proxy.
/// - `AllowDomains`: domain-specific filtering via local HTTP proxy.
///   The sandbox restricts connections to localhost only; a proxy enforces
///   the domain allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// No network access. Unix domain sockets still allowed where possible.
    #[default]
    Deny,
    /// Unrestricted network access.
    Allow,
    /// Allow only localhost connections (127.0.0.1/::1). Enforced at kernel
    /// level on macOS (Seatbelt) and advisory on Linux (seccomp cannot filter
    /// connect by destination). No proxy is needed.
    Localhost,
    /// Allow network access only to specific domains via HTTP proxy.
    /// Domains support exact match and subdomain match (e.g., "github.com"
    /// also matches "api.github.com").
    AllowDomains(Vec<String>),
}

impl Serialize for NetworkPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            NetworkPolicy::Deny => serializer.serialize_str("deny"),
            NetworkPolicy::Allow => serializer.serialize_str("allow"),
            NetworkPolicy::Localhost => serializer.serialize_str("localhost"),
            NetworkPolicy::AllowDomains(domains) => {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("allow_domains", domains)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for NetworkPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de;

        struct NetworkPolicyVisitor;

        impl<'de> de::Visitor<'de> for NetworkPolicyVisitor {
            type Value = NetworkPolicy;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(r#""deny", "allow", "localhost", or {"allow_domains": [...]}"#)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<NetworkPolicy, E> {
                match value {
                    "deny" => Ok(NetworkPolicy::Deny),
                    "allow" => Ok(NetworkPolicy::Allow),
                    "localhost" => Ok(NetworkPolicy::Localhost),
                    other => Err(de::Error::unknown_variant(
                        other,
                        &["deny", "allow", "localhost"],
                    )),
                }
            }

            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<NetworkPolicy, A::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected allow_domains key"))?;
                if key == "allow_domains" {
                    let domains: Vec<String> = map.next_value()?;
                    Ok(NetworkPolicy::AllowDomains(domains))
                } else {
                    Err(de::Error::unknown_field(&key, &["allow_domains"]))
                }
            }
        }

        deserializer.deserialize_any(NetworkPolicyVisitor)
    }
}

/// Resolve symlinks in a path without resolving firmlinks.
///
/// Walks each component of the path and resolves actual symlinks via
/// `std::fs::read_link`. Unlike `std::fs::canonicalize`, this does NOT
/// resolve macOS firmlinks (e.g. `/Users` → `/System/Volumes/Data/Users`)
/// which are transparent to Seatbelt and would produce paths that never
/// match.
///
/// Falls back to the original path if resolution fails (e.g. path does
/// not exist on the current system).
pub(crate) fn resolve_symlinks(path: &str) -> String {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::{Component, Path, PathBuf};

    let path = Path::new(path);
    if !path.is_absolute() {
        return path.to_string_lossy().into_owned();
    }

    // Collect path components into a work queue so that symlink targets
    // can be spliced in for further resolution.
    let mut pending: VecDeque<OsString> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_owned()),
            _ => None,
        })
        .collect();

    let mut resolved = PathBuf::from("/");
    let mut symlink_depth: usize = 0;
    const MAX_SYMLINK_DEPTH: usize = 40;

    while let Some(component) = pending.pop_front() {
        resolved.push(&component);

        if let Ok(target) = std::fs::read_link(&resolved) {
            symlink_depth += 1;
            if symlink_depth > MAX_SYMLINK_DEPTH {
                return path.to_string_lossy().into_owned();
            }

            // Splice the target's components into the front of the queue
            // so they get resolved on subsequent iterations.
            if target.is_absolute() {
                resolved = PathBuf::from("/");
            } else {
                resolved.pop();
            }

            let target_components: Vec<OsString> = target
                .components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_owned()),
                    _ => None,
                })
                .collect();

            for (i, tc) in target_components.into_iter().enumerate() {
                pending.insert(i, tc);
            }
        }
    }

    resolved.to_string_lossy().into_owned()
}

impl SandboxPolicy {
    /// Resolve a path, expanding environment variables ($PWD, $HOME, $TMPDIR).
    ///
    /// This is a convenience wrapper around [`super::path::PathResolver`].
    /// The `cwd` parameter is used for `$PWD`; `$HOME` and `$TMPDIR` are
    /// read from the current process environment.
    pub fn resolve_path(path: &str, cwd: &str) -> String {
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        super::path::PathResolver::new(cwd, home, tmpdir).resolve_env_vars(path)
    }

    /// Expand rules that have `follow_worktrees` set by detecting if `cwd` is
    /// inside a git worktree and adding rules for the worktree's git directories.
    ///
    /// In a worktree, git data lives outside the working directory (in the main
    /// repo's `.git/`), so sandboxed processes need access to those paths for
    /// git operations to work.
    pub fn expand_worktree_rules(&self, cwd: &Path) -> SandboxPolicy {
        let has_worktree_rules = self.rules.iter().any(|r| r.follow_worktrees);
        if !has_worktree_rules {
            return self.clone();
        }

        let wt_paths = crate::git::worktree_sandbox_paths(cwd);
        if wt_paths.is_empty() {
            return self.clone();
        }

        let mut expanded = self.rules.clone();
        for rule in &self.rules {
            if !rule.follow_worktrees {
                continue;
            }
            for path in &wt_paths {
                expanded.push(SandboxRule {
                    effect: rule.effect,
                    caps: rule.caps,
                    path: path.clone(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                });
            }
        }

        SandboxPolicy {
            rules: expanded,
            ..self.clone()
        }
    }

    /// Compute the effective capabilities for a given path by evaluating all rules.
    ///
    /// Uses depth-sorted last-match-wins precedence, matching macOS Seatbelt
    /// (SBPL) evaluation semantics: rules are sorted by path depth ascending
    /// (broadest first), with deny-before-allow at the same depth. Each rule
    /// overrides previous decisions for the capabilities it covers, so deeper
    /// (more specific) rules take precedence over shallower ones, and at the
    /// same depth an allow wins over a deny.
    pub fn effective_caps(&self, path: &str, cwd: &str) -> Cap {
        struct MatchedRule {
            effect: RuleEffect,
            caps: Cap,
            depth: usize,
        }

        let mut matched: Vec<MatchedRule> = Vec::new();

        // Canonicalize the query path so that /var/foo and /private/var/foo
        // are treated identically when matching against rules.
        let canonical_path = resolve_symlinks(path);

        for rule in &self.rules {
            let rule_path = Self::resolve_path(&rule.path, cwd);
            let canonical_rule = resolve_symlinks(&rule_path);
            let matches = match rule.path_match {
                PathMatch::Subpath => {
                    canonical_path.starts_with(&canonical_rule) || canonical_path == canonical_rule
                }
                PathMatch::Literal => canonical_path == canonical_rule,
                PathMatch::ChildOf => canonical_path
                    .strip_prefix(&format!("{canonical_rule}/"))
                    .is_some_and(|rest| !rest.contains('/')),
                PathMatch::Regex => regex::Regex::new(&rule_path)
                    .map(|re| re.is_match(path))
                    .unwrap_or(false),
            };

            if matches {
                matched.push(MatchedRule {
                    effect: rule.effect,
                    caps: rule.caps,
                    depth: std::path::Path::new(&rule_path).components().count(),
                });
            }
        }

        // Sort by path depth ascending so broadest rules are applied first.
        // Within the same depth, deny before allow so that allow wins via
        // last-match-wins — matching SBPL evaluation order.
        matched.sort_by(|a, b| {
            a.depth.cmp(&b.depth).then_with(|| {
                let effect_ord = |e: &RuleEffect| match e {
                    RuleEffect::Deny => 0,
                    RuleEffect::Allow => 1,
                };
                effect_ord(&a.effect).cmp(&effect_ord(&b.effect))
            })
        });

        let mut result = self.default;
        for rule in &matched {
            match rule.effect {
                RuleEffect::Allow => result |= rule.caps,
                RuleEffect::Deny => result &= !rule.caps,
            }
        }

        result
    }

    /// Explain why a path lacks the required capabilities.
    ///
    /// Returns the most specific deny rule that covers the required caps,
    /// formatted like `"deny rwcdx in /Users (subpath)"`.
    /// Returns `None` if the path has the required capabilities.
    pub fn explain_denial(&self, path: &str, cwd: &str, required: Cap) -> Option<String> {
        let effective = self.effective_caps(path, cwd);
        if effective.contains(required) {
            return None;
        }

        // Find the deepest (most specific) deny rule that matches this path
        // and covers at least one of the required capabilities.
        let mut best: Option<(&SandboxRule, String)> = None;
        let mut best_depth: usize = 0;

        // Canonicalize query path for consistent matching across symlink forms.
        let canonical_path = resolve_symlinks(path);

        for rule in &self.rules {
            if rule.effect != RuleEffect::Deny {
                continue;
            }
            // Does this deny cover any of the required caps?
            if (rule.caps & required).is_empty() {
                continue;
            }
            let rule_path = Self::resolve_path(&rule.path, cwd);
            let canonical_rule = resolve_symlinks(&rule_path);
            let matches = match rule.path_match {
                PathMatch::Subpath => {
                    canonical_path.starts_with(&canonical_rule) || canonical_path == canonical_rule
                }
                PathMatch::Literal => canonical_path == canonical_rule,
                PathMatch::ChildOf => canonical_path
                    .strip_prefix(&format!("{canonical_rule}/"))
                    .is_some_and(|rest| !rest.contains('/')),
                PathMatch::Regex => regex::Regex::new(&rule_path)
                    .map(|re| re.is_match(path))
                    .unwrap_or(false),
            };
            if matches {
                let depth = std::path::Path::new(&rule_path).components().count();
                if best.is_none() || depth >= best_depth {
                    best_depth = depth;
                    best = Some((rule, rule_path));
                }
            }
        }

        if let Some((rule, resolved_path)) = best {
            let match_type = match rule.path_match {
                PathMatch::Subpath => "subpath",
                PathMatch::Literal => "literal",
                PathMatch::ChildOf => "child_of",
                PathMatch::Regex => "regex",
            };
            Some(format!(
                "deny {} in {} ({})",
                rule.caps.short(),
                resolved_path,
                match_type,
            ))
        } else {
            Some("no allow rule grants access to this path".to_string())
        }
    }
}

/// What the model should do when a sandbox violation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    /// Stop and suggest a policy fix. Don't retry.
    #[default]
    Stop,
    /// Try an alternative approach. If no workaround is possible, suggest the policy fix.
    Workaround,
    /// Let the model assess context to decide between stop and workaround.
    Smart,
}

impl ViolationAction {
    pub fn is_default(&self) -> bool {
        matches!(self, ViolationAction::Stop)
    }
}

/// Parse a sandbox rule from a string like "allow read + write in $PWD".
///
/// Format: `<effect> <caps> in <path>`
pub fn parse_sandbox_rule(s: &str) -> Result<SandboxRule, String> {
    // Split on " in " to separate caps from path
    let parts: Vec<&str> = s.splitn(2, " in ").collect();
    if parts.len() != 2 {
        return Err(format!(
            "expected '<effect> <caps> in <path>', got: '{}'",
            s
        ));
    }

    let caps_part = parts[0].trim();
    let path = parts[1].trim().to_string();

    // First word is the effect
    let (effect_str, caps_str) = caps_part.split_once(char::is_whitespace).ok_or_else(|| {
        format!(
            "expected 'allow <caps>' or 'deny <caps>', got: '{}'",
            caps_part
        )
    })?;

    let effect = match effect_str.trim() {
        "allow" => RuleEffect::Allow,
        "deny" => RuleEffect::Deny,
        other => return Err(format!("expected 'allow' or 'deny', got: '{}'", other)),
    };

    let caps = Cap::parse(caps_str.trim())?;

    Ok(SandboxRule {
        effect,
        caps,
        path,
        path_match: PathMatch::Subpath,
        follow_worktrees: false,
        doc: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_short() {
        assert_eq!(Cap::READ.short(), "r----");
        assert_eq!((Cap::READ | Cap::WRITE).short(), "rw---");
        assert_eq!((Cap::READ | Cap::EXECUTE).short(), "r---x");
        assert_eq!(Cap::all().short(), "rwcdx");
        assert_eq!(Cap::empty().short(), "-----");
    }

    #[test]
    fn test_cap_display() {
        assert_eq!(Cap::READ.display(), "read");
        assert_eq!((Cap::READ | Cap::WRITE).display(), "read + write");
        assert_eq!(
            Cap::all().display(),
            "read + write + create + delete + execute"
        );
    }

    #[test]
    fn test_cap_serde_roundtrip() {
        let caps = Cap::READ | Cap::WRITE | Cap::CREATE;
        let json = serde_json::to_string(&caps).unwrap();
        assert_eq!(json, r#"["read","write","create"]"#);
        let deserialized: Cap = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, caps);
    }

    #[test]
    fn test_cap_deserialize_string_rejected() {
        // Legacy string format is no longer accepted
        let result: Result<Cap, _> = serde_json::from_str(r#""read + write""#);
        assert!(result.is_err());
    }

    #[test]
    fn test_effective_caps() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE,
                    path: "/project".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE | Cap::DELETE | Cap::CREATE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            doc: None,
        };

        // Default path: read + execute
        let caps = policy.effective_caps("/etc/passwd", "/project");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);

        // Project dir: read + write + create + delete + execute (default + allow)
        let caps = policy.effective_caps("/project/src/main.rs", "/project");
        assert_eq!(
            caps,
            Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE | Cap::EXECUTE
        );

        // .git dir: deny overrides allow, so only read + execute remain
        let caps = policy.effective_caps("/project/.git/config", "/project");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn test_network_policy_localhost_serde() {
        let json = serde_json::to_string(&NetworkPolicy::Localhost).unwrap();
        assert_eq!(json, r#""localhost""#);
        let deserialized: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, NetworkPolicy::Localhost);
    }

    #[test]
    fn test_sandbox_policy_serde() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE,
                path: "$PWD".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.default, policy.default);
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.network, NetworkPolicy::Deny);
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy::resolve_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_path_pwd_replacement() {
        let result = SandboxPolicy::resolve_path("$PWD/src", "/my/project");
        assert_eq!(result, "/my/project/src");
    }

    #[test]
    fn resolve_path_home_replacement() {
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let result = SandboxPolicy::resolve_path("$HOME/.config", "/ignored");
        assert_eq!(result, format!("{}/.config", home));
    }

    #[test]
    fn resolve_path_tmpdir_replacement() {
        // SAFETY: test-only, single-threaded access
        let saved = std::env::var("TMPDIR").ok();
        unsafe { std::env::set_var("TMPDIR", "/custom/tmp") };
        let result = SandboxPolicy::resolve_path("$TMPDIR/scratch", "/ignored");
        assert_eq!(result, "/custom/tmp/scratch");
        match saved {
            Some(v) => unsafe { std::env::set_var("TMPDIR", v) },
            None => unsafe { std::env::remove_var("TMPDIR") },
        }
    }

    #[test]
    fn resolve_path_tmpdir_fallback() {
        let saved = std::env::var("TMPDIR").ok();
        unsafe { std::env::remove_var("TMPDIR") };
        let result = SandboxPolicy::resolve_path("$TMPDIR/scratch", "/ignored");
        assert_eq!(result, "/tmp/scratch");
        match saved {
            Some(v) => unsafe { std::env::set_var("TMPDIR", v) },
            None => unsafe { std::env::remove_var("TMPDIR") },
        }
    }

    #[test]
    fn resolve_path_multiple_vars() {
        unsafe { std::env::set_var("TMPDIR", "/var/tmp") };
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let result = SandboxPolicy::resolve_path("$PWD:$HOME:$TMPDIR", "/work");
        assert_eq!(result, format!("/work:{}:/var/tmp", home));
        unsafe { std::env::remove_var("TMPDIR") };
    }

    #[test]
    fn resolve_path_no_variables() {
        let result = SandboxPolicy::resolve_path("/usr/local/bin", "/ignored");
        assert_eq!(result, "/usr/local/bin");
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy::effective_caps tests
    // -----------------------------------------------------------------------

    #[test]
    fn effective_caps_regex_path_match() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: r"/project/.*\.rs$".into(),
                path_match: PathMatch::Regex,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let caps = policy.effective_caps("/project/src/main.rs", "/project");
        assert_eq!(caps, Cap::READ | Cap::WRITE);

        // Non-rs file should not match the regex rule
        let caps = policy.effective_caps("/project/src/main.py", "/project");
        assert_eq!(caps, Cap::READ);
    }

    #[test]
    fn effective_caps_literal_path_match() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/etc/hosts".into(),
                path_match: PathMatch::Literal,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // Exact match
        let caps = policy.effective_caps("/etc/hosts", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::WRITE);

        // Child path should NOT match literal
        let caps = policy.effective_caps("/etc/hosts/foo", "/ignored");
        assert_eq!(caps, Cap::READ);
    }

    #[test]
    fn effective_caps_allow_wins_at_same_depth() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::WRITE | Cap::CREATE,
                    path: "/data".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
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
        // At same depth, allow wins (last-match-wins, matching SBPL semantics)
        let caps = policy.effective_caps("/data/file.txt", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::WRITE | Cap::CREATE);
    }

    #[test]
    fn effective_caps_multiple_overlapping_rules() {
        let policy = SandboxPolicy {
            default: Cap::empty() | Cap::READ,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::all(),
                    path: "/project".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::DELETE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE | Cap::CREATE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // In /project but outside .git: full caps
        let caps = policy.effective_caps("/project/src/lib.rs", "/project");
        assert_eq!(caps, Cap::all());

        // In .git: all minus delete, write, create
        let caps = policy.effective_caps("/project/.git/HEAD", "/project");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn effective_caps_default_when_no_rules_match() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/specific/path".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // Path that matches no rules gets default
        let caps = policy.effective_caps("/unrelated/path", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn effective_caps_deeper_allow_overrides_shallower_deny() {
        // Mirrors the real "cwd" sandbox: broad deny on /Users, specific allow on $PWD
        let policy = SandboxPolicy {
            default: Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE | Cap::CREATE,
                    path: "/Users/eliot/code/project".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ,
                    path: "/Users/eliot".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ,
                    path: "/".into(),
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

        // Inside $PWD: the deeper allow overrides the shallower deny on /Users
        let caps = policy.effective_caps("/Users/eliot/code/project/src/main.rs", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::WRITE | Cap::CREATE);

        // Inside $HOME but outside $PWD: read from $HOME allow overrides /Users deny
        let caps = policy.effective_caps("/Users/eliot/.config/foo", "/ignored");
        assert_eq!(caps, Cap::READ);

        // Outside /Users entirely: default + broad allow on /
        let caps = policy.effective_caps("/etc/passwd", "/ignored");
        assert_eq!(caps, Cap::READ | Cap::EXECUTE);
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy::expand_worktree_rules tests
    // -----------------------------------------------------------------------

    #[test]
    fn expand_worktree_no_worktree_rules_unchanged() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "$PWD".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // No follow_worktrees rules → policy unchanged regardless of cwd
        let expanded = policy.expand_worktree_rules(Path::new("/any/path"));
        assert_eq!(expanded.rules.len(), 1);
    }

    #[test]
    fn expand_worktree_not_in_worktree_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("normal-repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "$PWD".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: true,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // Normal repo (not a worktree) → no expansion
        let expanded = policy.expand_worktree_rules(&repo);
        assert_eq!(expanded.rules.len(), 1);
    }

    #[test]
    fn expand_worktree_adds_git_dir_rules() {
        let tmp = tempfile::tempdir().unwrap();

        // Set up a fake worktree structure
        let main_repo = tmp.path().join("main-repo");
        let git_dir = main_repo.join(".git");
        let wt_git = git_dir.join("worktrees").join("feature");
        std::fs::create_dir_all(&wt_git).unwrap();
        std::fs::write(wt_git.join("commondir"), "../..").unwrap();
        std::fs::write(wt_git.join("HEAD"), "ref: refs/heads/feature\n").unwrap();

        let worktree = tmp.path().join("feature-worktree");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}", wt_git.display()),
        )
        .unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![
                SandboxRule {
                    effect: RuleEffect::Allow,
                    caps: Cap::READ | Cap::WRITE,
                    path: "$PWD".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: true,
                    doc: None,
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::DELETE,
                    path: "/etc".into(),
                    path_match: PathMatch::Subpath,
                    follow_worktrees: false,
                    doc: None,
                },
            ],
            network: NetworkPolicy::Deny,
            doc: None,
        };

        let expanded = policy.expand_worktree_rules(&worktree);

        // Original 2 rules + 2 new rules (git_dir + common_dir) for the
        // follow_worktrees rule
        assert_eq!(expanded.rules.len(), 4);

        // New rules should be subpath allows with the same caps
        let new_rules: Vec<_> = expanded.rules[2..].to_vec();
        for rule in &new_rules {
            assert_eq!(rule.effect, RuleEffect::Allow);
            assert_eq!(rule.caps, Cap::READ | Cap::WRITE);
            assert_eq!(rule.path_match, PathMatch::Subpath);
            assert!(!rule.follow_worktrees);
        }

        // The non-follow_worktrees rule should NOT generate extra rules
        assert_eq!(expanded.rules[1].path, "/etc");
    }

    #[test]
    fn expand_worktree_follow_worktrees_not_serialized_when_false() {
        let rule = SandboxRule {
            effect: RuleEffect::Allow,
            caps: Cap::READ,
            path: "$PWD".into(),
            path_match: PathMatch::Subpath,
            follow_worktrees: false,
            doc: None,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(!json.contains("follow_worktrees"));
    }

    #[test]
    fn expand_worktree_follow_worktrees_serialized_when_true() {
        let rule = SandboxRule {
            effect: RuleEffect::Allow,
            caps: Cap::READ,
            path: "$PWD".into(),
            path_match: PathMatch::Subpath,
            follow_worktrees: true,
            doc: None,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"follow_worktrees\":true"));
    }

    // -----------------------------------------------------------------------
    // resolve_symlinks tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_symlinks_unrelated_path_unchanged() {
        assert_eq!(resolve_symlinks("/usr/local/bin"), "/usr/local/bin");
    }

    #[test]
    fn resolve_symlinks_follows_real_symlink() {
        // Use /tmp explicitly to avoid interference from tests that mutate $TMPDIR.
        let tmp = tempfile::tempdir_in("/tmp").unwrap();
        let target = tmp.path().join("target_dir");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let resolved = resolve_symlinks(&format!("{}/child", link.display()));
        // The expected path must also be resolved since the tempdir itself
        // may live under a symlink (e.g. /var/folders on macOS).
        let expected = format!("{}/child", resolve_symlinks(&target.to_string_lossy()));
        assert_eq!(resolved, expected);
    }

    #[test]
    fn resolve_symlinks_nonexistent_path_returned_as_is() {
        let result = resolve_symlinks("/nonexistent/made/up/path");
        assert_eq!(result, "/nonexistent/made/up/path");
    }

    // macOS-specific: /var, /tmp, /etc are symlinks to /private/*
    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_var() {
        assert_eq!(
            resolve_symlinks("/var/folders/xx"),
            "/private/var/folders/xx"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_tmp() {
        assert_eq!(resolve_symlinks("/tmp/build"), "/private/tmp/build");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_etc() {
        assert_eq!(resolve_symlinks("/etc/hosts"), "/private/etc/hosts");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_exact() {
        assert_eq!(resolve_symlinks("/var"), "/private/var");
        assert_eq!(resolve_symlinks("/tmp"), "/private/tmp");
        assert_eq!(resolve_symlinks("/etc"), "/private/etc");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_symlinks_macos_already_private() {
        assert_eq!(
            resolve_symlinks("/private/var/folders"),
            "/private/var/folders"
        );
    }

    // -----------------------------------------------------------------------
    // symlink duality in effective_caps / explain_denial
    // -----------------------------------------------------------------------

    #[test]
    fn effective_caps_symlink_rule_matches_resolved_query() {
        // Create a symlink so resolve_symlinks can resolve both forms
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: link.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // Query via the resolved (real) path should match the symlink rule
        let query = format!("{}/file.txt", real_dir.display());
        let caps = policy.effective_caps(&query, "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on symlink path should match query via resolved path"
        );
    }

    #[test]
    fn effective_caps_resolved_rule_matches_symlink_query() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: real_dir.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        // Query via the symlink should match the real-path rule
        let query = format!("{}/file.txt", link.display());
        let caps = policy.effective_caps(&query, "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on real path should match query via symlink"
        );
    }

    #[test]
    fn effective_caps_symlink_deny() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ | Cap::WRITE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Deny,
                caps: Cap::WRITE,
                path: link.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let query = format!("{}/file.txt", real_dir.display());
        let caps = policy.effective_caps(&query, "/ignored");
        assert!(
            !caps.contains(Cap::WRITE),
            "deny on symlink should apply to resolved path"
        );
    }

    #[test]
    fn explain_denial_across_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &link).unwrap();

        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Deny,
                caps: Cap::READ,
                path: link.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let query = format!("{}/secret", real_dir.display());
        let explanation = policy.explain_denial(&query, "/ignored", Cap::READ);
        assert!(
            explanation.is_some(),
            "deny on symlink should explain denial for resolved path"
        );
    }

    // macOS-specific: test with /var → /private/var system symlinks
    #[cfg(target_os = "macos")]
    #[test]
    fn effective_caps_macos_var_symlink_duality() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/var/folders".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let caps = policy.effective_caps("/private/var/folders/xx/data", "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on /var/folders should match query for /private/var/folders/xx/data"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn effective_caps_macos_private_rule_matches_symlink_query() {
        let policy = SandboxPolicy {
            default: Cap::READ,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::WRITE,
                path: "/private/tmp".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };
        let caps = policy.effective_caps("/tmp/scratch", "/ignored");
        assert!(
            caps.contains(Cap::WRITE),
            "rule on /private/tmp should match query for /tmp/scratch"
        );
    }
}

#[cfg(test)]
mod violation_action_tests {
    use super::*;

    #[test]
    fn test_violation_action_default_is_stop() {
        let action: ViolationAction = Default::default();
        assert!(matches!(action, ViolationAction::Stop));
    }

    #[test]
    fn test_violation_action_deserialize_stop() {
        let action: ViolationAction = serde_json::from_str("\"stop\"").unwrap();
        assert!(matches!(action, ViolationAction::Stop));
    }

    #[test]
    fn test_violation_action_deserialize_workaround() {
        let action: ViolationAction = serde_json::from_str("\"workaround\"").unwrap();
        assert!(matches!(action, ViolationAction::Workaround));
    }

    #[test]
    fn test_violation_action_deserialize_smart() {
        let action: ViolationAction = serde_json::from_str("\"smart\"").unwrap();
        assert!(matches!(action, ViolationAction::Smart));
    }

    #[test]
    fn test_violation_action_serialize_roundtrip() {
        for action in [ViolationAction::Stop, ViolationAction::Workaround, ViolationAction::Smart] {
            let json = serde_json::to_string(&action).unwrap();
            let back: ViolationAction = serde_json::from_str(&json).unwrap();
            assert_eq!(action, back);
        }
    }
}
