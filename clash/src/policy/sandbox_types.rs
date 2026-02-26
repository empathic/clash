//! Sandbox capability types for kernel-enforced process restrictions.
//!
//! These types define a platform-agnostic sandbox policy that compiles to
//! Landlock+seccomp on Linux or Seatbelt SBPL on macOS.

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
    /// Parse a capability expression.
    ///
    /// Additive: `read + write + create`
    /// Shorthand: `all` or `full` (all capabilities)
    /// Subtractive: `all - write`, `full - delete - create`
    /// Mixed: `all - write + execute` (exclusions win)
    pub fn parse(s: &str) -> Result<Cap, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty capability expression".into());
        }

        let mut add = Cap::empty();
        let mut sub = Cap::empty();
        let mut op = '+'; // first term is implicitly additive

        let mut start = 0;
        let bytes = s.as_bytes();

        for i in 0..=bytes.len() {
            let at_op = i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-');
            if at_op || i == bytes.len() {
                let part = s[start..i].trim();
                if !part.is_empty() {
                    let cap = Self::parse_single(part)?;
                    match op {
                        '+' => add |= cap,
                        '-' => sub |= cap,
                        _ => unreachable!(),
                    }
                }
                if at_op {
                    op = bytes[i] as char;
                    start = i + 1;
                }
            }
        }

        let result = add & !sub;
        if result.is_empty() {
            return Err("capability expression resolves to empty set".into());
        }
        Ok(result)
    }

    /// Parse a single capability name.
    fn parse_single(s: &str) -> Result<Cap, String> {
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
}

impl Serialize for Cap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.display())
    }
}

impl<'de> Deserialize<'de> for Cap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Cap::parse(&s).map_err(serde::de::Error::custom)
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
}

/// How a sandbox rule's path is matched against the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PathMatch {
    /// Match this path and all descendants (recursive).
    #[default]
    Subpath,
    /// Match exactly this path (non-recursive).
    Literal,
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

impl SandboxPolicy {
    /// Resolve a path, expanding environment variables ($PWD, $HOME, $TMPDIR).
    pub fn resolve_path(path: &str, cwd: &str) -> String {
        path.replace("$PWD", cwd)
            .replace(
                "$HOME",
                &dirs::home_dir()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
            .replace(
                "$TMPDIR",
                &std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
            )
    }

    /// Compute the effective capabilities for a given path by evaluating all rules.
    ///
    /// Uses deny-overrides-allow precedence: collects all matching allows and denies,
    /// then applies denies on top.
    pub fn effective_caps(&self, path: &str, cwd: &str) -> Cap {
        let mut allowed = self.default;
        let mut denied = Cap::empty();

        for rule in &self.rules {
            let rule_path = Self::resolve_path(&rule.path, cwd);
            let matches = match rule.path_match {
                PathMatch::Subpath => path.starts_with(&rule_path) || path == rule_path,
                PathMatch::Literal => path == rule_path,
                PathMatch::Regex => regex::Regex::new(&rule_path)
                    .map(|re| re.is_match(path))
                    .unwrap_or(false),
            };

            if matches {
                match rule.effect {
                    RuleEffect::Allow => allowed |= rule.caps,
                    RuleEffect::Deny => denied |= rule.caps,
                }
            }
        }

        allowed & !denied
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cap_parse() {
        assert_eq!(Cap::parse("read").unwrap(), Cap::READ);
        assert_eq!(Cap::parse("read + write").unwrap(), Cap::READ | Cap::WRITE);
        assert_eq!(
            Cap::parse("read + write + create + delete + execute").unwrap(),
            Cap::all()
        );
        assert_eq!(Cap::parse("full").unwrap(), Cap::all());
        assert_eq!(Cap::parse("full + read").unwrap(), Cap::all()); // redundant but valid
        assert!(Cap::parse("unknown").is_err());
        assert!(Cap::parse("").is_err());
    }

    #[test]
    fn test_cap_parse_all_keyword() {
        assert_eq!(Cap::parse("all").unwrap(), Cap::all());
        assert_eq!(Cap::parse("all + read").unwrap(), Cap::all()); // redundant but valid
    }

    #[test]
    fn test_cap_parse_subtraction() {
        // all - write = read + create + delete + execute
        assert_eq!(
            Cap::parse("all - write").unwrap(),
            Cap::READ | Cap::CREATE | Cap::DELETE | Cap::EXECUTE
        );

        // full - write also works
        assert_eq!(
            Cap::parse("full - write").unwrap(),
            Cap::READ | Cap::CREATE | Cap::DELETE | Cap::EXECUTE
        );

        // multiple subtractions
        assert_eq!(
            Cap::parse("all - write - delete").unwrap(),
            Cap::READ | Cap::CREATE | Cap::EXECUTE
        );

        // subtract everything → error (empty result)
        assert!(Cap::parse("all - all").is_err());
        assert!(Cap::parse("read - read").is_err());

        // no-op subtraction (removing something not present)
        assert_eq!(
            Cap::parse("read + write - execute").unwrap(),
            Cap::READ | Cap::WRITE
        );

        // without spaces
        assert_eq!(
            Cap::parse("all-write").unwrap(),
            Cap::READ | Cap::CREATE | Cap::DELETE | Cap::EXECUTE
        );
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
        assert_eq!(json, r#""read + write + create""#);
        let deserialized: Cap = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, caps);
    }

    #[test]
    fn test_parse_sandbox_rule() {
        let rule = parse_sandbox_rule("allow read + write in $PWD").unwrap();
        assert_eq!(rule.effect, RuleEffect::Allow);
        assert_eq!(rule.caps, Cap::READ | Cap::WRITE);
        assert_eq!(rule.path, "$PWD");
        assert_eq!(rule.path_match, PathMatch::Subpath);
    }

    #[test]
    fn test_parse_sandbox_rule_deny() {
        let rule = parse_sandbox_rule("deny delete in $PWD/.git").unwrap();
        assert_eq!(rule.effect, RuleEffect::Deny);
        assert_eq!(rule.caps, Cap::DELETE);
        assert_eq!(rule.path, "$PWD/.git");
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
                },
                SandboxRule {
                    effect: RuleEffect::Deny,
                    caps: Cap::WRITE | Cap::DELETE | Cap::CREATE,
                    path: "/project/.git".into(),
                    path_match: PathMatch::Subpath,
                },
            ],
            network: NetworkPolicy::Deny,
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
            }],
            network: NetworkPolicy::Deny,
        };

        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.default, policy.default);
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.network, NetworkPolicy::Deny);
    }
}
