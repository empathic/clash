//! Parsing for policy documents.
//!
//! Handles:
//! - S-expression policy parsing (via parse_sexpr module)
//! - Pest-based parsing of compact rule strings (`effect entity tool pattern`)
//! - Legacy `[permissions]` desugaring to statements

use std::collections::HashMap;

use pest::Parser;
use pest_derive::Parser;

use tracing::{Level, instrument};

use super::error::{PolicyParseError, suggest_closest};
use super::*;
use crate::policy::sandbox_types::{Cap, NetworkPolicy};

// ---------------------------------------------------------------------------
// Pest grammar
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[grammar = "policy/rule.pest"]
struct RuleParser;

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

#[instrument(level = Level::TRACE, skip(input))]
pub fn parse_policy(input: &str) -> Result<PolicyDocument, PolicyParseError> {
    super::parse_sexpr::parse_policy(input)
}

/// Parse a rule key like `"deny * *"` or `"allow bash *"` into (effect, verb, noun).
///
/// Format: `effect verb noun...` — at least 3 whitespace-separated tokens.
/// The entity slot is implicit (always the agent).
/// The noun may contain multiple tokens (e.g., "deny bash rm *" → verb="bash", noun="rm *").
pub fn parse_new_rule_key(key: &str) -> Result<(Effect, String, Pattern), PolicyParseError> {
    // Strip trailing `:` if present
    let key = key.strip_suffix(':').unwrap_or(key).trim();
    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(PolicyParseError::InvalidNewRuleKey(
            key.to_string(),
            format!(
                "expected at least 3 parts (effect verb noun...), got {}",
                parts.len()
            ),
        ));
    }

    let effect = parse_effect_str(parts[0])?;
    let verb = parts[1].to_string();
    // Everything after effect and verb is the noun pattern (e.g., "rm *" in "deny bash rm *")
    let noun_str = parts[2..].join(" ");
    let noun = parse_pattern(&noun_str);

    Ok((effect, verb, noun))
}

/// Returns rules from the included parent first, then the profile's own rules.
#[instrument(level = Level::TRACE)]
pub fn flatten_profile(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
) -> Result<Vec<ProfileRule>, PolicyParseError> {
    let mut visited = std::collections::HashSet::new();
    flatten_profile_inner(name, profiles, &mut visited)
}

fn flatten_profile_inner(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
    visited: &mut std::collections::HashSet<String>,
) -> Result<Vec<ProfileRule>, PolicyParseError> {
    if !visited.insert(name.to_string()) {
        return Err(PolicyParseError::CircularInclude {
            cycle: name.to_string(),
            path: None, // flatten doesn't track path; cycle detection does
        });
    }

    let def = profiles.get(name).ok_or_else(|| {
        let candidates: Vec<&str> = profiles.keys().map(|s| s.as_str()).collect();
        PolicyParseError::UnknownInclude {
            name: name.to_string(),
            suggestion: suggest_closest(name, &candidates),
        }
    })?;

    let mut rules = Vec::new();

    // First, collect rules from included profiles (parent rules come first, lower precedence)
    if let Some(ref includes) = def.include {
        for include in includes {
            let parent_rules = flatten_profile_inner(include, profiles, visited)?;
            rules.extend(parent_rules);
        }
    }

    // Then add own rules (higher precedence)
    rules.extend(def.rules.clone());

    Ok(rules)
}

/// Flatten sandbox config by resolving the `include:` chain.
///
/// Walks parent profiles collecting sandbox configs, then merges:
/// - `fs`: union of all entries (parent entries first)
/// - `network`: deny wins over allow
///
/// Returns `None` if no profile in the chain has a `sandbox:` block.
#[instrument(level = Level::TRACE)]
pub fn flatten_sandbox(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
) -> Result<Option<SandboxConfig>, PolicyParseError> {
    let mut visited = std::collections::HashSet::new();
    flatten_sandbox_inner(name, profiles, &mut visited)
}

fn flatten_sandbox_inner(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
    visited: &mut std::collections::HashSet<String>,
) -> Result<Option<SandboxConfig>, PolicyParseError> {
    if !visited.insert(name.to_string()) {
        return Err(PolicyParseError::CircularInclude {
            cycle: name.to_string(),
            path: None,
        });
    }

    let def = profiles.get(name).ok_or_else(|| {
        let candidates: Vec<&str> = profiles.keys().map(|s| s.as_str()).collect();
        PolicyParseError::UnknownInclude {
            name: name.to_string(),
            suggestion: suggest_closest(name, &candidates),
        }
    })?;

    // Collect sandbox configs from parents first
    let mut merged_fs: Vec<(Cap, FilterExpr)> = Vec::new();
    let mut merged_network: Option<NetworkPolicy> = None;
    let mut has_any = false;

    if let Some(ref includes) = def.include {
        for include in includes {
            if let Some(parent_sb) = flatten_sandbox_inner(include, profiles, visited)? {
                has_any = true;
                if let Some(fs) = parent_sb.fs {
                    merged_fs.extend(fs);
                }
                if parent_sb.network == Some(NetworkPolicy::Deny) {
                    merged_network = Some(NetworkPolicy::Deny);
                } else if merged_network.is_none() {
                    merged_network = parent_sb.network;
                }
            }
        }
    }

    // Then merge own sandbox config (child entries after parent)
    if let Some(ref own_sb) = def.sandbox {
        has_any = true;
        if let Some(ref fs) = own_sb.fs {
            merged_fs.extend(fs.clone());
        }
        if own_sb.network == Some(NetworkPolicy::Deny) {
            merged_network = Some(NetworkPolicy::Deny);
        } else if merged_network.is_none() {
            merged_network = own_sb.network;
        }
    }

    if !has_any {
        return Ok(None);
    }

    Ok(Some(SandboxConfig {
        fs: if merged_fs.is_empty() {
            None
        } else {
            Some(merged_fs)
        },
        network: merged_network,
    }))
}

/// Parse a single compact rule string into a `Statement`.
///
/// Format: `effect [entity] tool pattern`
///
/// The entity is optional — when omitted, it defaults to `agent` (any agent).
/// The parser detects whether entity is present by checking if the second
/// token is a known tool keyword (`bash`, `read`, `write`, `edit`, `*`).
///
/// Examples:
/// - `allow bash cargo build *`       — entity defaults to agent
/// - `allow agent:claude bash git *`  — explicit entity
/// - `deny !user read ~/config/*`     — explicit negated entity
/// - `ask * * *`                       — explicit wildcard entity
#[instrument(level = Level::TRACE)]
pub fn parse_rule(input: &str) -> Result<Statement, PolicyParseError> {
    let input = input.trim();

    // Split on ` : ` to extract optional profile expression.
    // We need to find the last ` : ` that separates the rule from the profile.
    // The rule part goes to the pest parser, the profile part is parsed separately.
    let (rule_part, profile_expr) = if let Some(colon_idx) = find_constraint_separator(input) {
        let rule_str = input[..colon_idx].trim();
        let profile_str = input[colon_idx + 1..].trim();
        let profile =
            parse_profile_expr(profile_str).map_err(|e| PolicyParseError::InvalidRule {
                rule: input.to_string(),
                message: format!("invalid constraint expression: {}", e),
            })?;
        (rule_str, Some(profile))
    } else {
        (input, None)
    };

    // Check if entity is omitted: if the second token is a known tool keyword,
    // insert the default entity "agent" (matches any agent) before parsing.
    let expanded_rule;
    let parse_input = if needs_entity_insertion(rule_part) {
        expanded_rule = insert_default_entity(rule_part);
        expanded_rule.as_str()
    } else {
        rule_part
    };

    let pairs =
        RuleParser::parse(Rule::rule, parse_input).map_err(|e| PolicyParseError::InvalidRule {
            rule: input.to_string(),
            message: e.to_string(),
        })?;

    let rule_pair = pairs.into_iter().next().unwrap();
    let mut inner = rule_pair.into_inner();

    // effect
    let effect_pair = inner.next().unwrap();
    let effect = parse_effect_str(effect_pair.as_str())?;

    // entity
    let entity_pair = inner.next().unwrap();
    let entity = parse_entity_pair(entity_pair);

    // tool → verb
    let tool_pair = inner.next().unwrap();
    let verb = parse_tool_str(tool_pair.as_str())?;

    // pattern → noun
    let pattern_pair = inner.next().unwrap();
    let noun = parse_pattern(pattern_pair.as_str().trim());

    Ok(Statement {
        effect,
        entity,
        verb,
        noun,
        reason: None,
        profile: profile_expr,
    })
}

const TOOL_KEYWORDS: &[&str] = &["bash", "read", "write", "edit"];

/// Check if the rule string is missing an entity (second token is a tool keyword).
fn needs_entity_insertion(rule: &str) -> bool {
    let mut tokens = rule.split_whitespace();
    let _effect = tokens.next(); // skip effect
    match tokens.next() {
        Some(second) => TOOL_KEYWORDS.contains(&second),
        None => false,
    }
}

/// Insert the default entity `agent` after the effect keyword.
fn insert_default_entity(rule: &str) -> String {
    // Find the end of the first whitespace-separated token (effect)
    let trimmed = rule.trim_start();
    if let Some(space_idx) = trimmed.find([' ', '\t']) {
        let effect = &trimmed[..space_idx];
        let rest = &trimmed[space_idx..];
        format!("{} agent{}", effect, rest)
    } else {
        rule.to_string()
    }
}

/// Find the position of the `:` constraint separator in a rule string.
///
/// Returns the byte offset of `:` if found, or None if the rule has no constraint.
/// We look for `:` that is NOT part of an entity type (like `agent:claude`).
/// The constraint separator `:` must have a space before it.
fn find_constraint_separator(input: &str) -> Option<usize> {
    // Walk backwards from the end, looking for ' :' pattern.
    // The entity colon (agent:claude) never has a space before the colon.
    let bytes = input.as_bytes();
    (1..bytes.len())
        .rev()
        .find(|&i| bytes[i] == b':' && bytes[i - 1] == b' ')
}

// Expression parsing delegated to expr module.
pub use super::expr::{parse_filter_expr, parse_profile_expr};

/// Format a `Statement` as a compact rule string.
///
/// When the entity is the default (any agent), it is omitted from the output.
#[instrument(level = Level::TRACE)]
pub fn format_rule(stmt: &Statement) -> String {
    let effect = stmt.effect.to_string();
    let tool = match &stmt.verb {
        VerbPattern::Any => "*".to_string(),
        VerbPattern::Exact(v) => v.rule_name().to_string(),
        VerbPattern::Named(s) => s.clone(),
    };
    let noun = super::ast::format_pattern_str(&stmt.noun);

    let base = if is_default_entity(&stmt.entity) {
        format!("{} {} {}", effect, tool, noun)
    } else {
        let entity = super::ast::format_pattern_str(&stmt.entity);
        format!("{} {} {} {}", effect, entity, tool, noun)
    };

    if let Some(ref profile) = stmt.profile {
        format!("{} : {}", base, profile)
    } else {
        base
    }
}

/// Check if an entity pattern is the default (matches any agent).
///
/// The default entity is either:
/// - `agent` (typed, no name) — matches agent and agent:*
/// - `*` (wildcard) — matches everything
///
/// Both are implicit when entity is omitted from a rule.
fn is_default_entity(entity: &Pattern) -> bool {
    match entity {
        Pattern::Match(MatchExpr::Typed {
            entity_type,
            name: None,
        }) => entity_type == "agent",
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Pattern / verb parsing (shared between rule parser and serde)
// ---------------------------------------------------------------------------

/// Parse a pattern string (used for entity and noun slots).
///
/// Syntax:
/// - `*` → `Pattern::Match(MatchExpr::Any)`
/// - `!*` → `Pattern::Not(MatchExpr::Any)`
/// - `!pattern` → `Pattern::Not(parse_match_expr(pattern))`
/// - `pattern` → `Pattern::Match(parse_match_expr(pattern))`
#[instrument(level = Level::TRACE)]
pub fn parse_pattern(s: &str) -> Pattern {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('!') {
        Pattern::Not(parse_match_expr(inner.trim()))
    } else {
        Pattern::Match(parse_match_expr(s))
    }
}

/// Parse a match expression (without negation).
///
/// Syntax:
/// - `*` → `MatchExpr::Any`
/// - `type:name` → `MatchExpr::Typed { entity_type, name }`
/// - `type:*` → `MatchExpr::Typed { entity_type, name: None }`
/// - contains `*` or `**` or `?` → `MatchExpr::Glob`
/// - otherwise → `MatchExpr::Exact`
#[instrument(level = Level::TRACE)]
pub fn parse_match_expr(s: &str) -> MatchExpr {
    let s = s.trim();
    if s == "*" {
        return MatchExpr::Any;
    }

    // Check for typed entity pattern (e.g., "agent:claude", "service:*")
    if let Some((entity_type, name)) = s.split_once(':') {
        let entity_type = entity_type.trim();
        let name = name.trim();
        if !entity_type.is_empty()
            && !entity_type.contains('/')
            && !entity_type.contains('.')
            && !entity_type.contains('~')
            && !name.starts_with("//")
        // skip URL schemes (https://, http://)
        {
            if name == "*" {
                return MatchExpr::Typed {
                    entity_type: entity_type.to_string(),
                    name: None,
                };
            } else {
                return MatchExpr::Typed {
                    entity_type: entity_type.to_string(),
                    name: Some(name.to_string()),
                };
            }
        }
    }

    // Check for glob patterns
    if s.contains('*') || s.contains("**") || s.contains('?') {
        MatchExpr::Glob(s.to_string())
    } else {
        MatchExpr::Exact(s.to_string())
    }
}

/// Parse a verb pattern string.
///
/// Syntax:
/// - `*` → `VerbPattern::Any`
/// - `read` / `write` / `edit` / `execute` → `VerbPattern::Exact(Verb)`
#[instrument(level = Level::TRACE)]
pub fn parse_verb_pattern(s: &str) -> Result<VerbPattern, String> {
    let s = s.trim();
    if s == "*" {
        return Ok(VerbPattern::Any);
    }
    match s {
        "read" => Ok(VerbPattern::Exact(Verb::Read)),
        "write" => Ok(VerbPattern::Exact(Verb::Write)),
        "edit" => Ok(VerbPattern::Exact(Verb::Edit)),
        "execute" => Ok(VerbPattern::Exact(Verb::Execute)),
        other => Ok(VerbPattern::Named(other.to_string())),
    }
}

// Re-export legacy desugaring for backward compatibility.
pub use super::legacy::desugar_claude_permissions;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_effect_str(s: &str) -> Result<Effect, PolicyParseError> {
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        other => Err(PolicyParseError::InvalidEffect(other.into())),
    }
}

fn parse_tool_str(s: &str) -> Result<VerbPattern, PolicyParseError> {
    match s {
        "*" => Ok(VerbPattern::Any),
        "bash" => Ok(VerbPattern::Exact(Verb::Execute)),
        "read" => Ok(VerbPattern::Exact(Verb::Read)),
        "write" => Ok(VerbPattern::Exact(Verb::Write)),
        "edit" => Ok(VerbPattern::Exact(Verb::Edit)),
        other => Ok(VerbPattern::Named(other.to_string())),
    }
}

/// Build a `Pattern` from a pest entity pair.
fn parse_entity_pair(pair: pest::iterators::Pair<Rule>) -> Pattern {
    let mut negated = false;
    let mut entity_value = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::negation => negated = true,
            Rule::entity_value => {
                entity_value = Some(parse_entity_value(inner));
            }
            _ => {}
        }
    }

    let expr = entity_value.unwrap_or(MatchExpr::Any);
    if negated {
        Pattern::Not(expr)
    } else {
        Pattern::Match(expr)
    }
}

fn parse_entity_value(pair: pest::iterators::Pair<Rule>) -> MatchExpr {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::wildcard => MatchExpr::Any,
        Rule::typed_entity => {
            let mut parts = inner.into_inner();
            let entity_type = parts.next().unwrap().as_str().to_string();
            let name_part = parts.next().unwrap();
            let name = match name_part.as_rule() {
                Rule::wildcard => None,
                _ => Some(name_part.as_str().to_string()),
            };
            MatchExpr::Typed { entity_type, name }
        }
        Rule::identifier => {
            // A bare identifier in entity position is an entity type (e.g., "agent", "user").
            // Treat it as Typed with no name, so "agent" matches "agent" and "agent:*".
            let s = inner.as_str();
            MatchExpr::Typed {
                entity_type: s.to_string(),
                name: None,
            }
        }
        _ => MatchExpr::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Pattern parsing ---

    #[test]
    fn test_parse_pattern_wildcard() {
        assert_eq!(parse_pattern("*"), Pattern::Match(MatchExpr::Any));
    }

    #[test]
    fn test_parse_pattern_negated_wildcard() {
        assert_eq!(parse_pattern("!*"), Pattern::Not(MatchExpr::Any));
    }

    #[test]
    fn test_parse_pattern_exact() {
        assert_eq!(
            parse_pattern(".env"),
            Pattern::Match(MatchExpr::Exact(".env".into()))
        );
    }

    #[test]
    fn test_parse_pattern_negated_exact() {
        assert_eq!(
            parse_pattern("!user"),
            Pattern::Not(MatchExpr::Exact("user".into()))
        );
    }

    #[test]
    fn test_parse_pattern_glob() {
        assert_eq!(
            parse_pattern("~/config/*"),
            Pattern::Match(MatchExpr::Glob("~/config/*".into()))
        );
    }

    #[test]
    fn test_parse_pattern_negated_glob() {
        assert_eq!(
            parse_pattern("!~/code/proj/**"),
            Pattern::Not(MatchExpr::Glob("~/code/proj/**".into()))
        );
    }

    #[test]
    fn test_parse_pattern_typed_entity() {
        assert_eq!(
            parse_pattern("agent:claude"),
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
    }

    #[test]
    fn test_parse_pattern_typed_entity_wildcard() {
        assert_eq!(
            parse_pattern("agent:*"),
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
    }

    #[test]
    fn test_parse_pattern_bare_type() {
        assert_eq!(
            parse_pattern("agent"),
            Pattern::Match(MatchExpr::Exact("agent".into()))
        );
    }

    #[test]
    fn test_parse_verb_pattern() {
        assert_eq!(parse_verb_pattern("*").unwrap(), VerbPattern::Any);
        assert_eq!(
            parse_verb_pattern("read").unwrap(),
            VerbPattern::Exact(Verb::Read)
        );
        assert_eq!(
            parse_verb_pattern("execute").unwrap(),
            VerbPattern::Exact(Verb::Execute)
        );
        assert_eq!(
            parse_verb_pattern("task").unwrap(),
            VerbPattern::Named("task".into())
        );
    }

    // --- Rule parsing (pest) ---

    #[test]
    fn test_parse_rule_simple_allow() {
        let stmt = parse_rule("allow * bash cargo build *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.entity, Pattern::Match(MatchExpr::Any));
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Execute));
        assert!(stmt.matches("agent", &Verb::Execute, "cargo build --release"));
    }

    #[test]
    fn test_parse_rule_typed_entity() {
        let stmt = parse_rule("allow agent:claude bash git *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(!stmt.matches("agent:codex", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_rule_negated_entity() {
        let stmt = parse_rule("deny !user read ~/config/*").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert!(stmt.matches("agent:claude", &Verb::Read, "~/config/test.json"));
        assert!(!stmt.matches("user", &Verb::Read, "~/config/test.json"));
    }

    #[test]
    fn test_parse_rule_wildcard_tool() {
        let stmt = parse_rule("deny agent:untrusted * ~/sensitive/**").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Any);
        assert!(stmt.matches("agent:untrusted", &Verb::Read, "~/sensitive/secrets.json"));
        assert!(stmt.matches("agent:untrusted", &Verb::Write, "~/sensitive/secrets.json"));
    }

    #[test]
    fn test_parse_rule_all_wildcards() {
        let stmt = parse_rule("ask * * *").unwrap();
        assert_eq!(stmt.effect, Effect::Ask);
        assert_eq!(stmt.entity, Pattern::Match(MatchExpr::Any));
        assert_eq!(stmt.verb, VerbPattern::Any);
        assert!(stmt.matches("anyone", &Verb::Execute, "anything"));
    }

    #[test]
    fn test_parse_rule_read_tool() {
        let stmt = parse_rule("allow * read *.rs").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Read));
        assert!(stmt.matches("agent", &Verb::Read, "main.rs"));
    }

    #[test]
    fn test_parse_rule_write_tool() {
        let stmt = parse_rule("deny * write /etc/*").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Write));
        assert!(stmt.matches("agent", &Verb::Write, "/etc/passwd"));
    }

    #[test]
    fn test_parse_rule_edit_tool() {
        let stmt = parse_rule("allow * edit src/**").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Edit));
    }

    #[test]
    fn test_parse_rule_entity_wildcard_type() {
        let stmt = parse_rule("allow agent:* bash git *").unwrap();
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:codex", &Verb::Execute, "git status"));
        assert!(!stmt.matches("user", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_rule_invalid() {
        assert!(parse_rule("").is_err());
        assert!(parse_rule("allow").is_err());
        assert!(parse_rule("allow *").is_err());
        assert!(parse_rule("allow * bash").is_err());
        assert!(parse_rule("invalid * bash *").is_err());
    }

    // --- Claude permissions desugaring ---

    #[test]
    fn test_desugar_claude_permissions_bash() {
        let perms = ClaudePermissions {
            allow: vec!["Bash(git:*)".into()],
            deny: vec![],
            ask: vec![],
        };
        let stmts = desugar_claude_permissions(&perms);
        assert_eq!(stmts.len(), 1);
        let stmt = &stmts[0];
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git commit -m 'test'"));
        assert!(!stmt.matches("agent:claude", &Verb::Execute, "npm install"));
    }

    #[test]
    fn test_desugar_claude_permissions_read() {
        let perms = ClaudePermissions {
            allow: vec!["Read".into()],
            deny: vec!["Read(.env)".into()],
            ask: vec![],
        };
        let stmts = desugar_claude_permissions(&perms);
        assert_eq!(stmts.len(), 2);

        let allow_stmt = &stmts[0];
        assert_eq!(allow_stmt.effect, Effect::Allow);
        assert!(allow_stmt.matches("agent:claude", &Verb::Read, "anything.txt"));

        let deny_stmt = &stmts[1];
        assert_eq!(deny_stmt.effect, Effect::Deny);
        assert!(deny_stmt.matches("agent:claude", &Verb::Read, ".env"));
        assert!(!deny_stmt.matches("agent:claude", &Verb::Read, ".env.local"));
    }

    #[test]
    fn test_desugar_claude_permissions_glob() {
        let perms = ClaudePermissions {
            allow: vec!["Read(**/*.rs)".into()],
            deny: vec![],
            ask: vec![],
        };
        let stmts = desugar_claude_permissions(&perms);
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].matches("agent:claude", &Verb::Read, "src/main.rs"));
        assert!(!stmts[0].matches("agent:claude", &Verb::Read, "src/main.py"));
    }

    // --- Serde roundtrips ---

    #[test]
    fn test_pattern_serde_roundtrip() {
        let patterns = vec![
            Pattern::Match(MatchExpr::Any),
            Pattern::Not(MatchExpr::Any),
            Pattern::Match(MatchExpr::Exact(".env".into())),
            Pattern::Match(MatchExpr::Glob("~/config/*".into())),
            Pattern::Not(MatchExpr::Glob("~/code/**".into())),
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            }),
        ];

        for pattern in &patterns {
            let json = serde_json::to_string(pattern).unwrap();
            let parsed: Pattern = serde_json::from_str(&json).unwrap();
            assert_eq!(pattern, &parsed, "roundtrip failed for {:?}", pattern);
        }
    }

    #[test]
    fn test_verb_pattern_serde_roundtrip() {
        let patterns = vec![
            VerbPattern::Any,
            VerbPattern::Exact(Verb::Read),
            VerbPattern::Exact(Verb::Execute),
        ];

        for pattern in &patterns {
            let json = serde_json::to_string(pattern).unwrap();
            let parsed: VerbPattern = serde_json::from_str(&json).unwrap();
            assert_eq!(pattern, &parsed, "roundtrip failed for {:?}", pattern);
        }
    }

    // --- Rule formatting roundtrip ---

    #[test]
    fn test_format_rule_roundtrip() {
        let rules = vec![
            "allow * bash cargo build *",
            "deny !user read ~/config/*",
            "ask agent:claude * *",
            "allow agent:* bash git *",
        ];
        for rule in rules {
            let stmt = parse_rule(rule).unwrap();
            let formatted = format_rule(&stmt);
            let reparsed = parse_rule(&formatted).unwrap();
            // Effects must match
            assert_eq!(
                stmt.effect, reparsed.effect,
                "effect mismatch for: {}",
                rule
            );
            // Verify the reparsed statement matches the same inputs
            assert_eq!(
                stmt.matches("agent:claude", &Verb::Execute, "cargo build --release"),
                reparsed.matches("agent:claude", &Verb::Execute, "cargo build --release"),
                "behavior mismatch for: {}",
                rule
            );
        }
    }

    // --- Implicit entity ---

    #[test]
    fn test_parse_rule_implicit_entity() {
        // When entity is omitted, "agent" is inserted as default.
        let stmt = parse_rule("allow bash git *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Execute));
        assert!(stmt.matches("agent", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_rule_implicit_entity_deny() {
        let stmt = parse_rule("deny bash rm *").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert!(stmt.matches("agent", &Verb::Execute, "rm -rf /"));
    }

    #[test]
    fn test_parse_rule_implicit_entity_read() {
        let stmt = parse_rule("allow read *.rs").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Read));
        assert!(stmt.matches("agent", &Verb::Read, "main.rs"));
    }

    #[test]
    fn test_parse_rule_implicit_entity_with_constraint() {
        let stmt = parse_rule("allow bash git * : strict-git").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.profile.is_some());
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
    }

    #[test]
    fn test_format_rule_omits_default_entity() {
        // Explicit "agent" or "agent:*" entity should be omitted in formatted output.
        let stmt = parse_rule("allow agent bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow bash git *");

        let stmt = parse_rule("allow agent:* bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow bash git *");
    }

    #[test]
    fn test_format_rule_keeps_explicit_entity() {
        // Non-default entities should be kept.
        let stmt = parse_rule("allow agent:claude bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow agent:claude bash git *");

        let stmt = parse_rule("allow * bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow * bash git *");
    }

    #[test]
    fn test_implicit_entity_roundtrip() {
        // Rules with implicit entity should roundtrip correctly.
        let rules = vec![
            "allow bash cargo build *",
            "deny bash rm *",
            "allow read *.rs",
            "allow edit src/**",
        ];
        for rule in rules {
            let stmt = parse_rule(rule).unwrap();
            let formatted = format_rule(&stmt);
            let reparsed = parse_rule(&formatted).unwrap();
            assert_eq!(
                stmt.effect, reparsed.effect,
                "effect mismatch for: {}",
                rule
            );
            assert_eq!(
                stmt.entity, reparsed.entity,
                "entity mismatch for: {}",
                rule
            );
            assert_eq!(stmt.verb, reparsed.verb, "verb mismatch for: {}", rule);
        }
    }

    // --- Filter expression parsing ---

    #[test]
    fn test_parse_filter_expr_subpath() {
        let expr = parse_filter_expr("subpath(.)").unwrap();
        assert_eq!(expr, FilterExpr::Subpath(".".into()));
    }

    #[test]
    fn test_parse_filter_expr_literal() {
        let expr = parse_filter_expr("literal(.env)").unwrap();
        assert_eq!(expr, FilterExpr::Literal(".env".into()));
    }

    #[test]
    fn test_parse_filter_expr_regex() {
        let expr = parse_filter_expr("regex(.*\\.rs$)").unwrap();
        assert_eq!(expr, FilterExpr::Regex(".*\\.rs$".into()));
    }

    #[test]
    fn test_parse_filter_expr_not() {
        let expr = parse_filter_expr("!literal(.env)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::Not(Box::new(FilterExpr::Literal(".env".into())))
        );
    }

    #[test]
    fn test_parse_filter_expr_and() {
        let expr = parse_filter_expr("subpath(.) & !literal(.env)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::And(
                Box::new(FilterExpr::Subpath(".".into())),
                Box::new(FilterExpr::Not(Box::new(FilterExpr::Literal(
                    ".env".into()
                ))))
            )
        );
    }

    #[test]
    fn test_parse_filter_expr_or() {
        let expr = parse_filter_expr("subpath(./src) | subpath(./test)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::Or(
                Box::new(FilterExpr::Subpath("./src".into())),
                Box::new(FilterExpr::Subpath("./test".into()))
            )
        );
    }

    #[test]
    fn test_parse_filter_expr_precedence() {
        // & binds tighter than |
        let expr = parse_filter_expr("subpath(./a) | subpath(./b) & !literal(.env)").unwrap();
        // Should parse as: a | (b & !.env)
        assert_eq!(
            expr,
            FilterExpr::Or(
                Box::new(FilterExpr::Subpath("./a".into())),
                Box::new(FilterExpr::And(
                    Box::new(FilterExpr::Subpath("./b".into())),
                    Box::new(FilterExpr::Not(Box::new(FilterExpr::Literal(
                        ".env".into()
                    ))))
                ))
            )
        );
    }

    #[test]
    fn test_parse_filter_expr_parens() {
        let expr = parse_filter_expr("(subpath(./a) | subpath(./b)) & !literal(.env)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::And(
                Box::new(FilterExpr::Or(
                    Box::new(FilterExpr::Subpath("./a".into())),
                    Box::new(FilterExpr::Subpath("./b".into()))
                )),
                Box::new(FilterExpr::Not(Box::new(FilterExpr::Literal(
                    ".env".into()
                ))))
            )
        );
    }

    // --- Profile expression parsing ---

    #[test]
    fn test_parse_profile_expr_ref() {
        let expr = parse_profile_expr("sandboxed").unwrap();
        assert_eq!(expr, ProfileExpr::Ref("sandboxed".into()));
    }

    #[test]
    fn test_parse_profile_expr_and() {
        let expr = parse_profile_expr("local & safe-io").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::And(
                Box::new(ProfileExpr::Ref("local".into())),
                Box::new(ProfileExpr::Ref("safe-io".into()))
            )
        );
    }

    #[test]
    fn test_parse_profile_expr_or() {
        let expr = parse_profile_expr("a | b").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::Or(
                Box::new(ProfileExpr::Ref("a".into())),
                Box::new(ProfileExpr::Ref("b".into()))
            )
        );
    }

    #[test]
    fn test_parse_profile_expr_not() {
        let expr = parse_profile_expr("!unsafe").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::Not(Box::new(ProfileExpr::Ref("unsafe".into())))
        );
    }

    #[test]
    fn test_parse_profile_expr_complex() {
        let expr = parse_profile_expr("sandboxed & git-safe-args").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::And(
                Box::new(ProfileExpr::Ref("sandboxed".into())),
                Box::new(ProfileExpr::Ref("git-safe-args".into()))
            )
        );
    }

    // --- Rule parsing with constraint suffix ---

    #[test]
    fn test_parse_rule_with_constraint() {
        let stmt = parse_rule("allow agent bash git * : strict-git").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.profile, Some(ProfileExpr::Ref("strict-git".into())));
    }

    #[test]
    fn test_parse_rule_with_inline_constraint() {
        let stmt = parse_rule("allow agent read * : local & no-secrets").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(
            stmt.profile,
            Some(ProfileExpr::And(
                Box::new(ProfileExpr::Ref("local".into())),
                Box::new(ProfileExpr::Ref("no-secrets".into()))
            ))
        );
    }

    #[test]
    fn test_parse_rule_without_constraint() {
        let stmt = parse_rule("deny agent bash rm *").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert_eq!(stmt.profile, None);
    }

    // --- Custom tool name tests ---

    #[test]
    fn test_parse_rule_custom_tool() {
        // Custom tool with explicit entity
        let stmt = parse_rule("allow * task *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.verb, VerbPattern::Named("task".into()));
        assert_eq!(stmt.entity, Pattern::Match(MatchExpr::Any));
    }

    #[test]
    fn test_parse_rule_custom_tool_with_noun() {
        let stmt = parse_rule("deny * glob *.rs").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert_eq!(stmt.verb, VerbPattern::Named("glob".into()));
    }

    #[test]
    fn test_parse_rule_custom_tool_with_entity() {
        let stmt = parse_rule("allow agent:claude websearch *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.verb, VerbPattern::Named("websearch".into()));
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
    }

    #[test]
    fn test_format_rule_custom_tool_roundtrip() {
        let rules = vec![
            "allow * task *",
            "deny * glob *.rs",
            "allow agent:claude websearch *",
        ];
        for rule in rules {
            let stmt = parse_rule(rule).unwrap();
            let formatted = format_rule(&stmt);
            let reparsed = parse_rule(&formatted).unwrap();
            assert_eq!(
                stmt.effect, reparsed.effect,
                "effect mismatch for: {}",
                rule
            );
            assert_eq!(stmt.verb, reparsed.verb, "verb mismatch for: {}", rule);
        }
    }

    #[test]
    fn test_verb_pattern_named_serde_roundtrip() {
        let pattern = VerbPattern::Named("task".into());
        let json = serde_json::to_string(&pattern).unwrap();
        let parsed: VerbPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern, parsed);
    }

    #[test]
    fn test_parse_match_expr_url_not_typed_entity() {
        // Before the bug fix, https://github.com/* was parsed as
        // Typed { entity_type: "https", name: "//github.com/*" }
        // After the fix, it should be parsed as Glob
        let expr = parse_match_expr("https://github.com/*");
        assert!(
            matches!(expr, MatchExpr::Glob(_)),
            "URL should be parsed as Glob, got {:?}",
            expr
        );
    }

    #[test]
    fn test_parse_match_expr_http_url_not_typed() {
        let expr = parse_match_expr("http://example.com/path");
        assert!(
            matches!(expr, MatchExpr::Exact(_)),
            "http URL without glob chars should be Exact, got {:?}",
            expr
        );
    }

    #[test]
    fn test_parse_pattern_negated_url() {
        // Negated URL patterns should work: !https://evil.com/*
        let pattern = parse_pattern("!https://evil.com/*");
        match pattern {
            Pattern::Not(inner) => match inner {
                MatchExpr::Glob(ref g) => assert_eq!(g, "https://evil.com/*"),
                other => panic!("expected Glob inside Not, got {:?}", other),
            },
            other => panic!("expected Not pattern, got {:?}", other),
        }
    }
}
