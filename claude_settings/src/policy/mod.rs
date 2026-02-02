//! Policy-based permission system using (entity, verb, noun) triples.
//!
//! This module provides an expressive policy language for controlling
//! what actions entities (agents, users, services) can perform on resources.
//!
//! ## Core Concepts
//!
//! - **Statement**: `effect(entity, verb, noun)` — a rule that matches requests
//! - **Effect**: `allow`, `deny`, or `ask`
//! - **Entity**: who is requesting (e.g., `agent:claude`, `user`, `service:mcp`)
//! - **Verb**: what action (`read`, `write`, `edit`, `execute`)
//! - **Noun**: what resource (file paths, command strings, globs)
//!
//! ## Evaluation
//!
//! 1. Collect all statements that match the request
//! 2. Apply precedence: **deny > ask > allow**
//! 3. If no match: apply the configurable default effect
//!
//! ## Negation
//!
//! `!` inverts the match on entity and noun slots:
//! - `deny(!user, read, ~/config/*)` — only users can read config
//! - `deny(agent:*, write, !~/code/proj/**)` — agents can't write outside project
//!
//! ## Example
//!
//! ```rust
//! use claude_settings::policy::{PolicyDocument, Statement, Effect, Pattern, MatchExpr, VerbPattern, Verb};
//!
//! let stmt = Statement {
//!     effect: Effect::Allow,
//!     entity: Pattern::Match(MatchExpr::Typed {
//!         entity_type: "agent".into(),
//!         name: Some("claude".into()),
//!     }),
//!     verb: VerbPattern::Exact(Verb::Execute),
//!     noun: Pattern::Match(MatchExpr::Glob("git *".into())),
//!     reason: None,
//!     delegate: None,
//!     profile: None,
//! };
//! ```

pub mod compile;
pub mod parse;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::sandbox::{Cap, NetworkPolicy};

/// A complete policy document, as loaded from a TOML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// Policy-level configuration.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Legacy-compatible simple permissions (backward compat with Claude Code format).
    #[serde(default)]
    pub permissions: Option<LegacyPermissions>,

    /// Named constraint primitives (typed maps with fs, pipe, redirect, etc.).
    #[serde(default)]
    pub constraints: HashMap<String, ConstraintDef>,

    /// Named profiles (boolean expressions over constraint/profile names).
    #[serde(default)]
    pub profiles: HashMap<String, ProfileExpr>,

    /// The list of policy statements.
    #[serde(default)]
    pub statements: Vec<Statement>,
}

/// Top-level policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default effect when no statement matches a request.
    /// - `"ask"` for interactive environments (human in the loop)
    /// - `"deny"` for headless/CI environments
    #[serde(default = "PolicyConfig::default_effect")]
    pub default: Effect,
}

impl PolicyConfig {
    fn default_effect() -> Effect {
        Effect::Ask
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: Self::default_effect(),
        }
    }
}

/// Legacy permissions format for backward compatibility with Claude Code's
/// `{ "permissions": { "allow": [...], "deny": [...], "ask": [...] } }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegacyPermissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// A single policy statement: `effect(entity, verb, noun)`.
///
/// Statements are the fundamental unit of policy. Each one matches
/// a class of requests and declares what should happen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statement {
    /// The effect this statement produces when matched.
    pub effect: Effect,

    /// Who is making the request. Supports `!` negation.
    #[serde(default = "Pattern::default_any")]
    pub entity: Pattern,

    /// What action is being performed. Does not support negation.
    #[serde(default = "VerbPattern::default_any")]
    pub verb: VerbPattern,

    /// What resource is being acted upon. Supports `!` negation.
    #[serde(default = "Pattern::default_any")]
    pub noun: Pattern,

    /// Human-readable reason (included in deny/ask messages).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Delegation configuration (required when effect = delegate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate: Option<DelegateConfig>,

    /// Optional constraint binding (profile expression).
    /// When present, the rule only matches if the constraint is satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileExpr>,
}

/// The effect a statement produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Allow the action without prompting.
    Allow,
    /// Deny the action.
    Deny,
    /// Prompt the user for confirmation.
    Ask,
    /// Delegate the decision to an external evaluator.
    Delegate,
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::Allow => write!(f, "allow"),
            Effect::Deny => write!(f, "deny"),
            Effect::Ask => write!(f, "ask"),
            Effect::Delegate => write!(f, "delegate"),
        }
    }
}

/// A pattern that may be negated with `!`.
///
/// Used for entity and noun slots in a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Matches when the inner expression matches.
    Match(MatchExpr),
    /// Matches when the inner expression does NOT match.
    Not(MatchExpr),
}

impl Pattern {
    fn default_any() -> Self {
        Pattern::Match(MatchExpr::Any)
    }

    /// Returns true if this pattern matches the given value.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Pattern::Match(expr) => expr.matches(value),
            Pattern::Not(expr) => !expr.matches(value),
        }
    }

    /// Returns true if this pattern matches the given entity,
    /// considering entity type hierarchy (e.g., `agent` matches `agent:claude`).
    pub fn matches_entity(&self, entity: &str) -> bool {
        match self {
            Pattern::Match(expr) => expr.matches_entity(entity),
            Pattern::Not(expr) => !expr.matches_entity(entity),
        }
    }
}

/// The actual matching expression (without negation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchExpr {
    /// Wildcard — matches anything.
    Any,
    /// Exact string match.
    Exact(String),
    /// Glob pattern (supports `*`, `**`, `?`).
    Glob(String),
    /// Typed entity with optional name (e.g., `agent:claude`).
    Typed {
        entity_type: String,
        name: Option<String>,
    },
}

impl MatchExpr {
    /// Returns true if this expression matches the given string value.
    /// For noun matching (file paths, command strings).
    pub fn matches(&self, value: &str) -> bool {
        match self {
            MatchExpr::Any => true,
            MatchExpr::Exact(s) => value == s,
            MatchExpr::Glob(pattern) => policy_glob_matches(pattern, value),
            MatchExpr::Typed { .. } => {
                // Typed expressions are for entities, not nouns.
                false
            }
        }
    }

    /// Returns true if this expression matches the given entity string,
    /// respecting entity type hierarchy.
    ///
    /// Entity hierarchy:
    /// - `*` matches everything
    /// - `agent` matches `agent`, `agent:claude`, `agent:codex`, etc.
    /// - `agent:claude` matches only `agent:claude`
    /// - `user` matches only `user`
    pub fn matches_entity(&self, entity: &str) -> bool {
        match self {
            MatchExpr::Any => true,
            MatchExpr::Exact(s) => entity == s,
            MatchExpr::Glob(pattern) => crate::permission::glob_matches_public(pattern, entity),
            MatchExpr::Typed {
                entity_type,
                name: None,
            } => {
                // "agent" matches "agent" and "agent:*"
                entity == entity_type.as_str() || entity.starts_with(&format!("{}:", entity_type))
            }
            MatchExpr::Typed {
                entity_type,
                name: Some(name),
            } => {
                // "agent:claude" matches only "agent:claude"
                entity == format!("{}:{}", entity_type, name)
            }
        }
    }
}

/// Verb pattern — not negatable, supports wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerbPattern {
    /// Matches any verb.
    Any,
    /// Matches a specific verb.
    Exact(Verb),
}

impl VerbPattern {
    fn default_any() -> Self {
        VerbPattern::Any
    }

    /// Returns true if this pattern matches the given verb.
    pub fn matches(&self, verb: &Verb) -> bool {
        match self {
            VerbPattern::Any => true,
            VerbPattern::Exact(v) => v == verb,
        }
    }
}

/// The set of verbs (actions) in the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    Read,
    Write,
    Edit,
    Execute,
    Delegate,
}

impl Verb {
    /// Map a Claude Code tool name to a verb.
    pub fn from_tool_name(tool: &str) -> Option<Self> {
        match tool {
            "Read" => Some(Verb::Read),
            "Write" => Some(Verb::Write),
            "Edit" => Some(Verb::Edit),
            "Bash" => Some(Verb::Execute),
            _ => None,
        }
    }

    /// Return the short tool name used in YAML rule syntax.
    pub fn rule_name(&self) -> &'static str {
        match self {
            Verb::Read => "read",
            Verb::Write => "write",
            Verb::Edit => "edit",
            Verb::Execute => "bash",
            Verb::Delegate => "delegate",
        }
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Verb::Read => write!(f, "read"),
            Verb::Write => write!(f, "write"),
            Verb::Edit => write!(f, "edit"),
            Verb::Execute => write!(f, "execute"),
            Verb::Delegate => write!(f, "delegate"),
        }
    }
}

/// A named constraint primitive with typed properties.
///
/// Each field is optional; only specified fields are checked.
/// Multiple fields are ANDed together (all must be satisfied).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintDef {
    /// Filesystem filter expression (subpath, literal, regex with boolean ops).
    /// For bash rules, `fs` generates sandbox rules instead of a permission guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FilterExpr>,
    /// Filesystem capabilities for sandbox rules (default: all).
    /// Only meaningful when `fs` is present on a bash rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<Cap>,
    /// Network policy for sandbox (deny or allow, default: allow).
    /// Only meaningful on bash rules with `fs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPolicy>,
    /// Whether pipe operators are allowed in the command string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe: Option<bool>,
    /// Whether I/O redirects are allowed in the command string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<bool>,
    /// Arguments that must not appear in the command.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "forbid-args"
    )]
    pub forbid_args: Option<Vec<String>>,
    /// Arguments that must appear in the command (at least one).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "require-args"
    )]
    pub require_args: Option<Vec<String>>,
}

/// A filesystem filter expression (SBPL-style).
///
/// Composes with boolean operators to express complex path constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterExpr {
    /// Resolved path must be under this directory.
    Subpath(String),
    /// Exactly this path.
    Literal(String),
    /// Regex match on resolved path.
    Regex(String),
    /// Both filters must match.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// At least one filter must match.
    Or(Box<FilterExpr>, Box<FilterExpr>),
    /// Filter must NOT match.
    Not(Box<FilterExpr>),
}

/// A profile expression — references to constraints/profiles composed with boolean ops.
///
/// Used in profile definitions and rule constraint bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileExpr {
    /// Reference to a named constraint or profile.
    Ref(String),
    /// Both expressions must be satisfied.
    And(Box<ProfileExpr>, Box<ProfileExpr>),
    /// At least one expression must be satisfied.
    Or(Box<ProfileExpr>, Box<ProfileExpr>),
    /// Expression must NOT be satisfied.
    Not(Box<ProfileExpr>),
}

impl fmt::Display for FilterExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterExpr::Subpath(s) => write!(f, "subpath({})", s),
            FilterExpr::Literal(s) => write!(f, "literal({})", s),
            FilterExpr::Regex(s) => write!(f, "regex({})", s),
            FilterExpr::Not(inner) => write!(f, "!{}", inner),
            FilterExpr::And(a, b) => write!(f, "{} & {}", a, b),
            FilterExpr::Or(a, b) => write!(f, "{} | {}", a, b),
        }
    }
}

impl Serialize for FilterExpr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for FilterExpr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse::parse_filter_expr(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ProfileExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileExpr::Ref(name) => write!(f, "{}", name),
            ProfileExpr::Not(inner) => write!(f, "!{}", inner),
            ProfileExpr::And(a, b) => write!(f, "{} & {}", a, b),
            ProfileExpr::Or(a, b) => write!(f, "{} | {}", a, b),
        }
    }
}

impl Serialize for ProfileExpr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProfileExpr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse::parse_profile_expr(&s).map_err(serde::de::Error::custom)
    }
}

/// Context for evaluating constraints against a specific request.
pub struct EvalContext<'a> {
    /// The entity making the request.
    pub entity: &'a str,
    /// The verb (action) being performed.
    pub verb: &'a Verb,
    /// The noun (resource) being acted on.
    pub noun: &'a str,
    /// The current working directory (for resolving relative paths).
    pub cwd: &'a str,
    /// The raw tool input JSON (for extracting command strings, file paths, etc.).
    pub tool_input: &'a serde_json::Value,
}

/// Configuration for delegating a permission decision to an external evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateConfig {
    /// The type of delegation endpoint.
    #[serde(rename = "type", default = "DelegateConfig::default_type")]
    pub delegate_type: DelegateType,

    /// The endpoint to call.
    /// - HTTP: a URL like `http://localhost:9090/evaluate`
    /// - Command: a shell command like `/usr/local/bin/policy-eval`
    pub endpoint: String,

    /// Timeout in milliseconds.
    #[serde(default = "DelegateConfig::default_timeout")]
    pub timeout_ms: u64,

    /// Action to take if the delegate is unavailable or times out.
    #[serde(default = "DelegateConfig::default_fallback")]
    pub fallback: Effect,

    /// How long to cache a delegate's response (0 = no caching).
    #[serde(default)]
    pub cache_ttl_secs: u64,

    /// Additional headers for HTTP delegates.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
}

impl DelegateConfig {
    fn default_type() -> DelegateType {
        DelegateType::Http
    }
    fn default_timeout() -> u64 {
        5000
    }
    fn default_fallback() -> Effect {
        Effect::Ask
    }
}

/// Type of delegation endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegateType {
    /// HTTP/HTTPS POST request.
    Http,
    /// Shell command (stdin/stdout JSON protocol).
    Command,
}

impl Statement {
    /// Returns true if this statement matches the given request.
    pub fn matches(&self, entity: &str, verb: &Verb, noun: &str) -> bool {
        self.entity.matches_entity(entity) && self.verb.matches(verb) && self.noun.matches(noun)
    }
}

/// Glob matching for policy patterns.
///
/// Unlike file-path globbing, `*` matches any character (including `/`)
/// because policy patterns apply to both file paths and command strings.
fn policy_glob_matches(pattern: &str, value: &str) -> bool {
    use regex::Regex;
    let regex_pattern = pattern
        .replace('.', "\\.")
        .replace("**", "<<<DOUBLESTAR>>>")
        .replace('*', ".*")
        .replace("<<<DOUBLESTAR>>>", ".*")
        .replace('?', ".");

    Regex::new(&format!("^{}$", regex_pattern))
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_expr_any() {
        assert!(MatchExpr::Any.matches("anything"));
        assert!(MatchExpr::Any.matches(""));
        assert!(MatchExpr::Any.matches_entity("agent:claude"));
    }

    #[test]
    fn test_match_expr_exact() {
        let expr = MatchExpr::Exact(".env".into());
        assert!(expr.matches(".env"));
        assert!(!expr.matches(".env.local"));
    }

    #[test]
    fn test_match_expr_glob() {
        let expr = MatchExpr::Glob("**/*.rs".into());
        assert!(expr.matches("src/main.rs"));
        assert!(expr.matches("a/b/c.rs"));
        assert!(!expr.matches("src/main.py"));

        let expr = MatchExpr::Glob("git *".into());
        assert!(expr.matches("git status"));
        assert!(expr.matches("git commit -m 'test'"));
        assert!(!expr.matches("gitk"));
    }

    #[test]
    fn test_match_expr_typed_entity() {
        // "agent" matches "agent" and "agent:*"
        let expr = MatchExpr::Typed {
            entity_type: "agent".into(),
            name: None,
        };
        assert!(expr.matches_entity("agent"));
        assert!(expr.matches_entity("agent:claude"));
        assert!(expr.matches_entity("agent:codex"));
        assert!(!expr.matches_entity("user"));
        assert!(!expr.matches_entity("service:mcp"));

        // "agent:claude" matches only "agent:claude"
        let expr = MatchExpr::Typed {
            entity_type: "agent".into(),
            name: Some("claude".into()),
        };
        assert!(expr.matches_entity("agent:claude"));
        assert!(!expr.matches_entity("agent:codex"));
        assert!(!expr.matches_entity("agent"));
    }

    #[test]
    fn test_pattern_negation() {
        let pattern = Pattern::Not(MatchExpr::Typed {
            entity_type: "user".into(),
            name: None,
        });
        // !user matches non-users
        assert!(pattern.matches_entity("agent:claude"));
        assert!(pattern.matches_entity("service:mcp"));
        assert!(!pattern.matches_entity("user"));

        let pattern = Pattern::Not(MatchExpr::Glob("~/code/proj/**".into()));
        // !~/code/proj/** matches paths outside project
        assert!(pattern.matches("/tmp/foo.txt"));
        assert!(!pattern.matches("~/code/proj/src/main.rs"));
    }

    #[test]
    fn test_verb_pattern() {
        assert!(VerbPattern::Any.matches(&Verb::Read));
        assert!(VerbPattern::Any.matches(&Verb::Execute));
        assert!(VerbPattern::Exact(Verb::Read).matches(&Verb::Read));
        assert!(!VerbPattern::Exact(Verb::Read).matches(&Verb::Write));
    }

    #[test]
    fn test_verb_from_tool_name() {
        assert_eq!(Verb::from_tool_name("Read"), Some(Verb::Read));
        assert_eq!(Verb::from_tool_name("Write"), Some(Verb::Write));
        assert_eq!(Verb::from_tool_name("Edit"), Some(Verb::Edit));
        assert_eq!(Verb::from_tool_name("Bash"), Some(Verb::Execute));
        assert_eq!(Verb::from_tool_name("Unknown"), None);
    }

    #[test]
    fn test_statement_matches() {
        let stmt = Statement {
            effect: Effect::Allow,
            entity: Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            }),
            verb: VerbPattern::Exact(Verb::Execute),
            noun: Pattern::Match(MatchExpr::Glob("git *".into())),
            reason: None,
            delegate: None,
            profile: None,
        };

        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git commit -m 'test'"));
        assert!(!stmt.matches("agent:codex", &Verb::Execute, "git status"));
        assert!(!stmt.matches("agent:claude", &Verb::Read, "git status"));
        assert!(!stmt.matches("agent:claude", &Verb::Execute, "rm -rf /"));
    }

    #[test]
    fn test_deny_non_users_from_config() {
        // deny(!user, read, ~/config/*)
        let stmt = Statement {
            effect: Effect::Deny,
            entity: Pattern::Not(MatchExpr::Typed {
                entity_type: "user".into(),
                name: None,
            }),
            verb: VerbPattern::Exact(Verb::Read),
            noun: Pattern::Match(MatchExpr::Glob("~/config/*".into())),
            reason: Some("Only users can read config".into()),
            delegate: None,
            profile: None,
        };

        // Agent trying to read config → matches (agent is !user)
        assert!(stmt.matches("agent:claude", &Verb::Read, "~/config/test.json"));
        // User trying to read config → does NOT match (user is not !user)
        assert!(!stmt.matches("user", &Verb::Read, "~/config/test.json"));
        // Agent trying to write config → does NOT match (wrong verb)
        assert!(!stmt.matches("agent:claude", &Verb::Write, "~/config/test.json"));
    }

    #[test]
    fn test_effect_display() {
        assert_eq!(Effect::Allow.to_string(), "allow");
        assert_eq!(Effect::Deny.to_string(), "deny");
        assert_eq!(Effect::Ask.to_string(), "ask");
        assert_eq!(Effect::Delegate.to_string(), "delegate");
    }
}
