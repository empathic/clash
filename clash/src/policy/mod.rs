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
//! use clash::policy::{PolicyDocument, Statement, Effect, Pattern, MatchExpr, VerbPattern, Verb};
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
//!     profile: None,
//! };
//! ```

pub mod ast;
pub mod compile;
pub mod edit;
pub mod error;
pub mod eval;
pub mod expr;
pub mod ir;
pub mod legacy;
pub mod parse;
pub mod sandbox_gen;
pub mod sandbox_types;

// Re-export AST types for backward compatibility.
pub use ast::{
    ArgSpec, ConstraintDef, DefaultConfig, FilterExpr, InlineConstraints, LegacyPermissions,
    MatchExpr, Pattern, PolicyConfig, PolicyDocument, ProfileDef, ProfileExpr, ProfileRule,
    Statement, VerbPattern,
};
pub use error::{CompileError, PolicyError, PolicyParseError};
pub use ir::{
    CompiledMatchExpr, CompiledPattern, CompiledPolicy, DecisionTrace, PolicyDecision, RuleMatch,
    RuleSkip,
};

use std::fmt;

use serde::{Deserialize, Serialize};
use tracing::{Level, instrument};

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
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::Allow => write!(f, "allow"),
            Effect::Deny => write!(f, "deny"),
            Effect::Ask => write!(f, "ask"),
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
}

impl Verb {
    /// Map a Claude Code tool name to a verb.
    #[instrument(level = Level::TRACE)]
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
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn rule_name(&self) -> &'static str {
        match self {
            Verb::Read => "read",
            Verb::Write => "write",
            Verb::Edit => "edit",
            Verb::Execute => "bash",
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
        }
    }
}

/// Context for evaluating constraints against a specific request.
#[derive(Debug)]
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
    /// The raw tool name string for arbitrary verb matching (new format).
    pub verb_str: &'a str,
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
    }
}
