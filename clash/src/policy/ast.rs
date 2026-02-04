//! AST types for the policy language.
//!
//! Contains all data structures that represent a parsed (but not compiled)
//! policy document.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use tracing::{Level, instrument};

use regex::Regex;

use super::{Effect, Verb};
use crate::policy::sandbox_types::{Cap, NetworkPolicy};

/// A complete policy document, as loaded from a YAML/TOML file.
///
/// Supports two formats:
/// - **Legacy/old format**: uses `policy`, `constraints`, `profiles` (boolean exprs),
///   `statements`, and optional `permissions`.
/// - **New format**: uses `default_config` and `profile_defs` with inline rules.
///
/// Both formats are produced by `parse_yaml()` which auto-detects the format.
/// `CompiledPolicy::compile()` dispatches based on which fields are populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// Policy-level configuration (legacy format).
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Legacy-compatible simple permissions (backward compat with Claude Code format).
    #[serde(default)]
    pub permissions: Option<LegacyPermissions>,

    /// Named constraint primitives (typed maps with fs, pipe, redirect, etc.) — legacy format.
    #[serde(default)]
    pub constraints: HashMap<String, ConstraintDef>,

    /// Named profiles (boolean expressions over constraint/profile names) — legacy format.
    #[serde(default)]
    pub profiles: HashMap<String, ProfileExpr>,

    /// The list of policy statements — legacy format.
    #[serde(default)]
    pub statements: Vec<Statement>,

    // --- New format fields ---
    /// New-format default configuration (permission + active profile name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_config: Option<DefaultConfig>,

    /// New-format profile definitions (name → ProfileDef with inline rules).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub profile_defs: HashMap<String, ProfileDef>,
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

    /// Optional constraint binding (profile expression).
    /// When present, the rule only matches if the constraint is satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileExpr>,
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
    pub(crate) fn default_any() -> Self {
        Pattern::Match(MatchExpr::Any)
    }

    /// Returns true if this pattern matches the given value.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Pattern::Match(expr) => expr.matches(value),
            Pattern::Not(expr) => !expr.matches(value),
        }
    }

    /// Returns true if this pattern matches the given entity,
    /// considering entity type hierarchy (e.g., `agent` matches `agent:claude`).
    #[instrument(level = Level::TRACE, skip(self))]
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
    #[instrument(level = Level::TRACE, skip(self))]
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
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn matches_entity(&self, entity: &str) -> bool {
        match self {
            MatchExpr::Any => true,
            MatchExpr::Exact(s) => entity == s,
            MatchExpr::Glob(pattern) => glob_matches(pattern, entity),
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
    /// Matches an arbitrary tool name (lowercased).
    Named(String),
}

impl VerbPattern {
    pub(crate) fn default_any() -> Self {
        VerbPattern::Any
    }

    /// Returns true if this pattern matches the given verb.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn matches(&self, verb: &Verb) -> bool {
        match self {
            VerbPattern::Any => true,
            VerbPattern::Exact(v) => v == verb,
            // Named variants are matched via verb_str at the compiled rule level,
            // not through Verb enum comparison.
            VerbPattern::Named(_) => false,
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
        crate::policy::parse::parse_filter_expr(&s).map_err(serde::de::Error::custom)
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
        crate::policy::parse::parse_profile_expr(&s).map_err(serde::de::Error::custom)
    }
}

impl Statement {
    /// Returns true if this statement matches the given request.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn matches(&self, entity: &str, verb: &Verb, noun: &str) -> bool {
        self.entity.matches_entity(entity) && self.verb.matches(verb) && self.noun.matches(noun)
    }
}

// ---------------------------------------------------------------------------
// New-format types (profile-based policy syntax)
// ---------------------------------------------------------------------------

/// Top-level `default:` config in the new format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    pub permission: Effect,
    pub profile: String,
}

/// A named profile definition with optional single inheritance and inline rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDef {
    pub include: Option<Vec<String>>,
    pub rules: Vec<ProfileRule>,
}

/// A single rule inside a profile: `effect verb noun` with optional inline constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileRule {
    pub effect: Effect,
    /// Arbitrary tool name or `"*"`.
    pub verb: String,
    pub noun: Pattern,
    pub constraints: Option<InlineConstraints>,
}

/// Inline constraints on a profile rule (cap-scoped fs, unified args, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InlineConstraints {
    /// Cap-scoped filesystem constraints: each entry maps caps → filter expression.
    pub fs: Option<Vec<(Cap, FilterExpr)>>,
    /// Unified args list: `"!x"` → Forbid(x), `"x"` → Require(x).
    pub args: Option<Vec<ArgSpec>>,
    pub network: Option<NetworkPolicy>,
    pub pipe: Option<bool>,
    pub redirect: Option<bool>,
}

/// An argument specification in the unified `args:` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArgSpec {
    /// `"!-delete"` → Forbid("-delete")
    Forbid(String),
    /// `"--dry-run"` → Require("--dry-run")
    Require(String),
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

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

// --- Custom serde implementations ---

impl Serialize for Pattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format_pattern_str(self))
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(crate::policy::parse::parse_pattern(&s))
    }
}

impl Serialize for VerbPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            VerbPattern::Any => serializer.serialize_str("*"),
            VerbPattern::Exact(verb) => serializer.serialize_str(&verb.to_string()),
            VerbPattern::Named(s) => serializer.serialize_str(s),
        }
    }
}

impl<'de> Deserialize<'de> for VerbPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        crate::policy::parse::parse_verb_pattern(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for MatchExpr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format_match_expr(self))
    }
}

impl<'de> Deserialize<'de> for MatchExpr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(crate::policy::parse::parse_match_expr(&s))
    }
}

pub(crate) fn format_pattern_str(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Match(expr) => format_match_expr(expr),
        Pattern::Not(expr) => format!("!{}", format_match_expr(expr)),
    }
}

pub(crate) fn format_match_expr(expr: &MatchExpr) -> String {
    match expr {
        MatchExpr::Any => "*".to_string(),
        MatchExpr::Exact(s) => s.clone(),
        MatchExpr::Glob(s) => s.clone(),
        MatchExpr::Typed {
            entity_type,
            name: None,
        } => entity_type.clone(),
        MatchExpr::Typed {
            entity_type,
            name: Some(name),
        } => format!("{}:{}", entity_type, name),
    }
}

/// Simple glob matching for patterns.
fn glob_matches(pattern: &str, path: &str) -> bool {
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
