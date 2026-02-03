//! Structured permission parsing, querying, and mutation.
//!
//! This module provides a structured representation of Claude Code permission
//! patterns, enabling easy querying and mutation of permission rules.
//!
//! ## Permission Pattern Format
//!
//! Claude Code permissions follow these formats:
//! - `ToolName` - Matches all uses of a tool
//! - `ToolName(pattern)` - Matches tool uses with a specific pattern
//! - `ToolName(prefix:*)` - Matches tool uses with a wildcard prefix
//! - `mcp__server__tool` - MCP tool permissions
//!
//! ## Examples
//!
//! ```rust
//! use claude_settings::permission::{Permission, PermissionRule, PermissionSet};
//!
//! // Parse a permission pattern
//! let perm = Permission::parse("Bash(git status:*)").unwrap();
//! assert_eq!(perm.tool(), "Bash");
//! assert!(perm.matches("Bash", Some("git status --verbose")));
//!
//! // Create a permission set
//! let set = PermissionSet::new()
//!     .allow(Permission::parse("Bash(git:*)").unwrap())
//!     .deny(Permission::parse("Read(.env)").unwrap());
//!
//! // Query permissions
//! assert_eq!(set.check("Bash", Some("git status")), PermissionRule::Allow);
//! assert_eq!(set.check("Read", Some(".env")), PermissionRule::Deny);
//! ```

use std::fmt;
use std::str::FromStr;

use regex::Regex;
use serde::{Deserialize, Serialize};

use tracing::{Level, instrument};

use crate::error::{Result, SettingsError};
use crate::types::Permissions;

/// The rule applied to a permission (allow, ask, or deny).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionRule {
    /// Permission is granted without confirmation.
    Allow,
    /// Permission requires user confirmation.
    Ask,
    /// Permission is explicitly denied.
    Deny,
    /// No rule matches (default behavior applies).
    #[default]
    Unset,
}

/// A structured representation of a Claude Code permission pattern.
///
/// Permissions can match:
/// - A tool by name only (e.g., `Edit`)
/// - A tool with an exact pattern (e.g., `Read(.env)`)
/// - A tool with a wildcard pattern (e.g., `Bash(git:*)`)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Permission {
    /// The tool name (e.g., "Bash", "Read", "Edit").
    tool: String,
    /// The pattern to match against (if any).
    pattern: Option<PermissionPattern>,
}

/// Pattern matching mode for permissions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PermissionPattern {
    /// Exact match required.
    Exact(String),
    /// Prefix match with wildcard (e.g., "git:*" matches "git status").
    Prefix(String),
    /// Glob-style pattern (for file paths).
    Glob(String),
}

impl Permission {
    /// Creates a new permission for a tool with no pattern (matches all uses).
    #[instrument(level = Level::TRACE, skip(name))]
    pub fn for_tool(name: impl Into<String>) -> Self {
        Self {
            tool: name.into(),
            pattern: None,
        }
    }

    /// Creates a new permission with an exact pattern match.
    #[instrument(level = Level::TRACE, skip(tool, pattern))]
    pub fn exact(tool: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            pattern: Some(PermissionPattern::Exact(pattern.into())),
        }
    }

    /// Creates a new permission with a prefix wildcard match.
    #[instrument(level = Level::TRACE, skip(tool, prefix))]
    pub fn prefix(tool: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            pattern: Some(PermissionPattern::Prefix(prefix.into())),
        }
    }

    /// Creates a new permission with a glob pattern match.
    #[instrument(level = Level::TRACE, skip(tool, glob))]
    pub fn glob(tool: impl Into<String>, glob: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            pattern: Some(PermissionPattern::Glob(glob.into())),
        }
    }

    /// Parses a permission from a string pattern.
    ///
    /// Supported formats:
    /// - `ToolName` - matches all uses of the tool
    /// - `ToolName(pattern)` - exact pattern match
    /// - `ToolName(prefix:*)` - prefix wildcard match
    /// - `ToolName(glob:**/*.rs)` - glob pattern match
    #[instrument(level = Level::TRACE)]
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();

        // Check for pattern in parentheses
        if let Some(paren_start) = s.find('(') {
            if !s.ends_with(')') {
                return Err(SettingsError::InvalidPermission(format!(
                    "malformed permission pattern: {}",
                    s
                )));
            }

            let tool = s[..paren_start].to_string();
            let pattern_str = &s[paren_start + 1..s.len() - 1];

            if tool.is_empty() {
                return Err(SettingsError::InvalidPermission(
                    "empty tool name".to_string(),
                ));
            }

            let pattern = if let Some(prefix) = pattern_str.strip_suffix(":*") {
                // Prefix wildcard pattern
                PermissionPattern::Prefix(prefix.to_string())
            } else if pattern_str.contains('*') || pattern_str.contains("**") {
                // Glob pattern
                PermissionPattern::Glob(pattern_str.to_string())
            } else {
                // Exact pattern
                PermissionPattern::Exact(pattern_str.to_string())
            };

            Ok(Self {
                tool,
                pattern: Some(pattern),
            })
        } else {
            // Tool-only permission
            if s.is_empty() {
                return Err(SettingsError::InvalidPermission(
                    "empty permission".to_string(),
                ));
            }
            Ok(Self::for_tool(s))
        }
    }

    /// Returns the tool name.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Returns the pattern, if any.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn pattern(&self) -> Option<&PermissionPattern> {
        self.pattern.as_ref()
    }

    /// Returns true if this permission matches the given tool and argument.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn matches(&self, tool: &str, arg: Option<&str>) -> bool {
        if self.tool != tool {
            return false;
        }

        match (&self.pattern, arg) {
            // No pattern = matches all uses of this tool
            (None, _) => true,
            // Pattern but no arg = no match
            (Some(_), None) => false,
            // Both pattern and arg
            (Some(pattern), Some(arg)) => pattern.matches(arg),
        }
    }

    /// Converts this permission back to its string representation.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn to_pattern_string(&self) -> String {
        match &self.pattern {
            None => self.tool.clone(),
            Some(PermissionPattern::Exact(p)) => format!("{}({})", self.tool, p),
            Some(PermissionPattern::Prefix(p)) => format!("{}({}:*)", self.tool, p),
            Some(PermissionPattern::Glob(p)) => format!("{}({})", self.tool, p),
        }
    }
}

impl PermissionPattern {
    /// Returns true if this pattern matches the given argument.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn matches(&self, arg: &str) -> bool {
        match self {
            PermissionPattern::Exact(pattern) => arg == pattern,
            PermissionPattern::Prefix(prefix) => {
                arg == prefix || arg.starts_with(&format!("{} ", prefix))
            }
            PermissionPattern::Glob(glob) => glob_matches(glob, arg),
        }
    }
}

impl FromStr for Permission {
    type Err = SettingsError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Permission::parse(s)
    }
}

impl From<&str> for Permission {
    fn from(value: &str) -> Self {
        Self::parse(value).unwrap_or_else(|_| Self {
            // TODO(eliot): Is this always valid? We should consider any string a tool. We can detect it's
            // invalid if it's an empy string?
            tool: value.to_string(),
            pattern: None,
        })
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_pattern_string())
    }
}

impl Serialize for Permission {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_pattern_string())
    }
}

impl<'de> Deserialize<'de> for Permission {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Permission::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A set of permissions with rules for allow, ask, and deny.
///
/// This provides an easy-to-use API for querying and mutating permissions.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PermissionSet {
    /// Permissions that are allowed without confirmation.
    #[serde(default)]
    allow: Vec<Permission>,
    /// Permissions that require confirmation.
    #[serde(default)]
    ask: Vec<Permission>,
    /// Permissions that are denied.
    #[serde(default)]
    deny: Vec<Permission>,
}

impl PermissionSet {
    /// Creates a new empty permission set.
    #[instrument(level = Level::TRACE)]
    pub fn new() -> Self {
        Self::default()
    }

    #[instrument(level = Level::TRACE, skip(self))]
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.ask.is_empty()
    }

    /// Creates a permission set from a Permissions struct.
    #[instrument(level = Level::TRACE)]
    pub fn from_permissions(perms: &Permissions) -> Result<Self> {
        let mut set = Self::new();

        for pattern in &perms.allow {
            set.allow.push(Permission::parse(pattern)?);
        }
        for pattern in &perms.ask {
            set.ask.push(Permission::parse(pattern)?);
        }
        for pattern in &perms.deny {
            set.deny.push(Permission::parse(pattern)?);
        }

        Ok(set)
    }

    /// Converts this permission set to a Permissions struct.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn to_permissions(&self) -> Permissions {
        Permissions {
            allow: self.allow.iter().map(|p| p.to_pattern_string()).collect(),
            ask: self.ask.iter().map(|p| p.to_pattern_string()).collect(),
            deny: self.deny.iter().map(|p| p.to_pattern_string()).collect(),
        }
    }

    /// Adds a permission to the allow list.
    #[instrument(level = Level::TRACE, skip(self, perm))]
    pub fn allow(mut self, perm: impl Into<Permission>) -> Self {
        let perm = perm.into();
        if !self.allow.contains(&perm) {
            self.allow.push(perm);
        }
        self
    }

    /// Adds a permission to the ask list.
    #[instrument(level = Level::TRACE, skip(self, perm))]
    pub fn ask(mut self, perm: impl Into<Permission>) -> Self {
        let perm = perm.into();
        if !self.ask.contains(&perm) {
            self.ask.push(perm);
        }
        self
    }

    /// Adds a permission to the deny list.
    #[instrument(level = Level::TRACE, skip(self, perm))]
    pub fn deny(mut self, perm: impl Into<Permission>) -> Self {
        let perm = perm.into();
        if !self.deny.contains(&perm) {
            self.deny.push(perm);
        }
        self
    }

    /// Adds a permission to the allow list in place.
    #[instrument(level = Level::TRACE, skip(self, perm))]
    pub fn insert_allow(&mut self, perm: impl Into<Permission>) -> &mut Self {
        let perm = perm.into();
        if !self.allow.contains(&perm) {
            self.allow.push(perm);
        }
        self
    }

    /// Adds a permission to the ask list in place.
    #[instrument(level = Level::TRACE, skip(self, perm))]
    pub fn insert_ask(&mut self, perm: impl Into<Permission>) -> &mut Self {
        let perm = perm.into();
        if !self.ask.contains(&perm) {
            self.ask.push(perm);
        }
        self
    }

    /// Adds a permission to the deny list in place.
    #[instrument(level = Level::TRACE, skip(self, perm))]
    pub fn insert_deny(&mut self, perm: impl Into<Permission>) -> &mut Self {
        let perm = perm.into();
        if !self.deny.contains(&perm) {
            self.deny.push(perm);
        }
        self
    }

    /// Removes a permission from the allow list.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_allow(&mut self, perm: &Permission) -> &mut Self {
        self.allow.retain(|p| p != perm);
        self
    }

    /// Removes a permission from the ask list.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_ask(&mut self, perm: &Permission) -> &mut Self {
        self.ask.retain(|p| p != perm);
        self
    }

    /// Removes a permission from the deny list.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove_deny(&mut self, perm: &Permission) -> &mut Self {
        self.deny.retain(|p| p != perm);
        self
    }

    /// Removes a permission from all lists.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn remove(&mut self, perm: &Permission) -> &mut Self {
        self.remove_allow(perm).remove_ask(perm).remove_deny(perm)
    }

    /// Checks the permission rule for a given tool and argument.
    ///
    /// Returns the first matching rule in order: Deny > Ask > Allow > Unset
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn check(&self, tool: &str, arg: Option<&str>) -> PermissionRule {
        // Deny takes highest precedence
        for perm in &self.deny {
            if perm.matches(tool, arg) {
                return PermissionRule::Deny;
            }
        }

        // Ask takes second precedence
        for perm in &self.ask {
            if perm.matches(tool, arg) {
                return PermissionRule::Ask;
            }
        }

        // Allow takes third precedence
        for perm in &self.allow {
            if perm.matches(tool, arg) {
                return PermissionRule::Allow;
            }
        }

        PermissionRule::Unset
    }

    /// Returns true if the given tool/arg is explicitly allowed.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn is_allowed(&self, tool: &str, arg: Option<&str>) -> bool {
        self.check(tool, arg) == PermissionRule::Allow
    }

    /// Returns true if the given tool/arg is explicitly denied.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn is_denied(&self, tool: &str, arg: Option<&str>) -> bool {
        self.check(tool, arg) == PermissionRule::Deny
    }

    /// Returns true if the given tool/arg requires asking.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn requires_ask(&self, tool: &str, arg: Option<&str>) -> bool {
        self.check(tool, arg) == PermissionRule::Ask
    }

    /// Returns all allow permissions.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn allowed(&self) -> &[Permission] {
        &self.allow
    }

    /// Returns all ask permissions.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn asking(&self) -> &[Permission] {
        &self.ask
    }

    /// Returns all deny permissions.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn denied(&self) -> &[Permission] {
        &self.deny
    }

    /// Returns all permissions for a specific tool.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn for_tool(&self, tool: &str) -> ToolPermissions {
        ToolPermissions {
            tool: tool.to_string(),
            allow: self
                .allow
                .iter()
                .filter(|p| p.tool() == tool)
                .cloned()
                .collect(),
            ask: self
                .ask
                .iter()
                .filter(|p| p.tool() == tool)
                .cloned()
                .collect(),
            deny: self
                .deny
                .iter()
                .filter(|p| p.tool() == tool)
                .cloned()
                .collect(),
        }
    }

    /// Clears all permissions.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn clear(&mut self) {
        self.allow.clear();
        self.ask.clear();
        self.deny.clear();
    }

    /// Merges another permission set into this one.
    ///
    /// The `other` set takes precedence (its rules are added first in each list).
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn merge(&self, other: &Self) -> Self {
        let mut this = self.clone();
        // Add other's permissions, avoiding duplicates
        for perm in &other.allow {
            if !this.allow.contains(perm) {
                this.allow.push(perm.clone());
            }
        }
        for perm in &other.ask {
            if !this.ask.contains(perm) {
                this.ask.push(perm.clone());
            }
        }
        for perm in &other.deny {
            if !this.deny.contains(perm) {
                this.deny.push(perm.clone());
            }
        }
        this
    }
}

/// Permissions filtered for a specific tool.
#[derive(Debug, Clone)]
pub struct ToolPermissions {
    /// The tool name.
    pub tool: String,
    /// Allow permissions for this tool.
    pub allow: Vec<Permission>,
    /// Ask permissions for this tool.
    pub ask: Vec<Permission>,
    /// Deny permissions for this tool.
    pub deny: Vec<Permission>,
}

impl ToolPermissions {
    /// Checks the permission rule for a given argument.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn check(&self, arg: Option<&str>) -> PermissionRule {
        for perm in &self.deny {
            if perm.matches(&self.tool, arg) {
                return PermissionRule::Deny;
            }
        }
        for perm in &self.ask {
            if perm.matches(&self.tool, arg) {
                return PermissionRule::Ask;
            }
        }
        for perm in &self.allow {
            if perm.matches(&self.tool, arg) {
                return PermissionRule::Allow;
            }
        }
        PermissionRule::Unset
    }
}

/// Simple glob matching for file paths (public API for use by policy module).
#[instrument(level = Level::TRACE)]
pub fn glob_matches_public(pattern: &str, path: &str) -> bool {
    glob_matches(pattern, path)
}

/// Simple glob matching for file paths.
fn glob_matches(pattern: &str, path: &str) -> bool {
    // Convert glob to regex
    let regex_pattern = pattern
        .replace('.', "\\.")
        .replace("**", "<<<DOUBLESTAR>>>")
        .replace('*', "[^/]*")
        .replace("<<<DOUBLESTAR>>>", ".*")
        .replace('?', ".");

    let regex_pattern = format!("^{}$", regex_pattern);

    Regex::new(&regex_pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tool_only() {
        let perm = Permission::parse("Edit").unwrap();
        assert_eq!(perm.tool(), "Edit");
        assert!(perm.pattern().is_none());
        assert!(perm.matches("Edit", None));
        assert!(perm.matches("Edit", Some("anything")));
        assert!(!perm.matches("Read", None));
    }

    #[test]
    fn test_parse_exact_pattern() {
        let perm = Permission::parse("Read(.env)").unwrap();
        assert_eq!(perm.tool(), "Read");
        assert!(matches!(perm.pattern(), Some(PermissionPattern::Exact(_))));
        assert!(perm.matches("Read", Some(".env")));
        assert!(!perm.matches("Read", Some(".env.local")));
        assert!(!perm.matches("Read", None));
    }

    #[test]
    fn test_parse_prefix_wildcard() {
        let perm = Permission::parse("Bash(git:*)").unwrap();
        assert_eq!(perm.tool(), "Bash");
        assert!(matches!(perm.pattern(), Some(PermissionPattern::Prefix(_))));
        assert!(perm.matches("Bash", Some("git")));
        assert!(perm.matches("Bash", Some("git status")));
        assert!(perm.matches("Bash", Some("git commit -m 'test'")));
        assert!(!perm.matches("Bash", Some("gitk")));
        assert!(!perm.matches("Bash", Some("npm install")));
    }

    #[test]
    fn test_parse_glob_pattern() {
        let perm = Permission::parse("Read(**/*.rs)").unwrap();
        assert_eq!(perm.tool(), "Read");
        assert!(matches!(perm.pattern(), Some(PermissionPattern::Glob(_))));
        assert!(perm.matches("Read", Some("src/main.rs")));
        assert!(perm.matches("Read", Some("lib/utils/helper.rs")));
        assert!(!perm.matches("Read", Some("src/main.py")));
    }

    #[test]
    fn test_permission_display() {
        assert_eq!(Permission::for_tool("Edit").to_string(), "Edit");
        assert_eq!(Permission::exact("Read", ".env").to_string(), "Read(.env)");
        assert_eq!(Permission::prefix("Bash", "git").to_string(), "Bash(git:*)");
        assert_eq!(
            Permission::glob("Read", "**/*.rs").to_string(),
            "Read(**/*.rs)"
        );
    }

    #[test]
    fn test_permission_serde() {
        let perm = Permission::prefix("Bash", "git");
        let json = serde_json::to_string(&perm).unwrap();
        assert_eq!(json, "\"Bash(git:*)\"");

        let parsed: Permission = serde_json::from_str(&json).unwrap();
        assert_eq!(perm, parsed);
    }

    #[test]
    fn test_permission_set_check() {
        let set = PermissionSet::new()
            .allow(Permission::prefix("Bash", "git"))
            .deny(Permission::exact("Read", ".env"))
            .ask(Permission::for_tool("Write"));

        assert_eq!(set.check("Bash", Some("git status")), PermissionRule::Allow);
        assert_eq!(set.check("Read", Some(".env")), PermissionRule::Deny);
        assert_eq!(set.check("Write", Some("file.txt")), PermissionRule::Ask);
        assert_eq!(set.check("Edit", None), PermissionRule::Unset);
    }

    #[test]
    fn test_permission_set_precedence() {
        let set = PermissionSet::new()
            .allow(Permission::for_tool("Bash"))
            .deny(Permission::prefix("Bash", "rm"));

        // Deny takes precedence over allow
        assert_eq!(set.check("Bash", Some("rm -rf /")), PermissionRule::Deny);
        assert_eq!(set.check("Bash", Some("ls")), PermissionRule::Allow);
    }

    #[test]
    fn test_permission_set_from_permissions() {
        let perms = Permissions {
            allow: vec!["Bash(git:*)".to_string(), "Edit".to_string()],
            ask: vec!["Write".to_string()],
            deny: vec!["Read(.env)".to_string()],
        };

        let set = PermissionSet::from_permissions(&perms).unwrap();
        assert_eq!(set.allowed().len(), 2);
        assert_eq!(set.asking().len(), 1);
        assert_eq!(set.denied().len(), 1);

        let back = set.to_permissions();
        assert_eq!(perms.allow, back.allow);
        assert_eq!(perms.ask, back.ask);
        assert_eq!(perms.deny, back.deny);
    }

    #[test]
    fn test_permission_set_for_tool() {
        let set = PermissionSet::new()
            .allow(Permission::prefix("Bash", "git"))
            .allow(Permission::prefix("Bash", "npm"))
            .deny(Permission::exact("Read", ".env"));

        let bash_perms = set.for_tool("Bash");
        assert_eq!(bash_perms.allow.len(), 2);
        assert_eq!(bash_perms.deny.len(), 0);

        let read_perms = set.for_tool("Read");
        assert_eq!(read_perms.deny.len(), 1);
    }

    #[test]
    fn test_permission_set_merge() {
        let mut base = PermissionSet::new().allow(Permission::prefix("Bash", "git"));

        let overlay = PermissionSet::new()
            .allow(Permission::prefix("Bash", "npm"))
            .deny(Permission::exact("Read", ".env"));

        base = base.merge(&overlay);

        assert_eq!(base.allowed().len(), 2);
        assert_eq!(base.denied().len(), 1);
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("*.rs", "main.rs"));
        assert!(!glob_matches("*.rs", "src/main.rs"));
        assert!(glob_matches("**/*.rs", "src/main.rs"));
        assert!(glob_matches("**/*.rs", "a/b/c/d.rs"));
        assert!(glob_matches("src/*.rs", "src/lib.rs"));
        assert!(!glob_matches("src/*.rs", "src/sub/lib.rs"));
        assert!(glob_matches("src/**/*.rs", "src/sub/lib.rs"));
    }
}
