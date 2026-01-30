//! Parsing and deserialization for policy documents.
//!
//! Handles:
//! - YAML deserialization of policy documents
//! - Pest-based parsing of compact rule strings (`effect entity tool pattern`)
//! - Custom serde for `Pattern` (with `!` negation prefix)
//! - Custom serde for `VerbPattern` (with `*` wildcard)
//! - Legacy `[permissions]` desugaring to statements

use pest::Parser;
use pest_derive::Parser;
use serde::{Deserialize, Serialize};

use super::*;

// ---------------------------------------------------------------------------
// Pest grammar
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[grammar = "policy/rule.pest"]
struct RuleParser;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PolicyParseError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("invalid rule '{rule}': {message}")]
    InvalidRule { rule: String, message: String },

    #[error("invalid effect '{0}'")]
    InvalidEffect(String),

    #[error("invalid tool '{0}'")]
    InvalidTool(String),
}

// ---------------------------------------------------------------------------
// YAML document shape (serde)
// ---------------------------------------------------------------------------

/// Raw YAML representation that maps 1:1 to the file format.
#[derive(Debug, Serialize, Deserialize)]
struct RawPolicyYaml {
    #[serde(default = "default_ask_str")]
    default: String,

    #[serde(default)]
    rules: Vec<String>,

    /// Legacy backward-compat with Claude Code permission format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<LegacyPermissions>,
}

fn default_ask_str() -> String {
    "ask".into()
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Parse a policy document from a YAML string.
pub fn parse_yaml(input: &str) -> Result<PolicyDocument, PolicyParseError> {
    let raw: RawPolicyYaml = serde_yaml::from_str(input)?;

    let default = parse_effect_str(&raw.default)?;

    let mut statements = Vec::new();

    // Desugar legacy permissions if present.
    if let Some(ref perms) = raw.permissions {
        statements.extend(desugar_legacy(perms));
    }

    // Parse compact rule strings.
    for rule_str in &raw.rules {
        let stmt = parse_rule(rule_str)?;
        statements.push(stmt);
    }

    Ok(PolicyDocument {
        policy: PolicyConfig { default },
        permissions: raw.permissions,
        statements,
    })
}

/// Parse a single compact rule string into a `Statement`.
///
/// Format: `effect entity tool pattern`
///
/// Examples:
/// - `allow * bash cargo build *`
/// - `deny !user read ~/config/*`
/// - `ask agent:claude * *`
pub fn parse_rule(input: &str) -> Result<Statement, PolicyParseError> {
    let input = input.trim();
    let pairs =
        RuleParser::parse(Rule::rule, input).map_err(|e| PolicyParseError::InvalidRule {
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
        delegate: None,
    })
}

/// Serialize a `PolicyDocument` back to YAML.
pub fn to_yaml(doc: &PolicyDocument) -> Result<String, serde_yaml::Error> {
    let raw = RawPolicyYaml {
        default: doc.policy.default.to_string(),
        rules: doc.statements.iter().map(format_rule).collect(),
        permissions: doc.permissions.clone(),
    };
    serde_yaml::to_string(&raw)
}

/// Format a `Statement` as a compact rule string.
pub fn format_rule(stmt: &Statement) -> String {
    let effect = stmt.effect.to_string();
    let entity = format_pattern_str(&stmt.entity);
    let tool = match &stmt.verb {
        VerbPattern::Any => "*".to_string(),
        VerbPattern::Exact(v) => v.rule_name().to_string(),
    };
    let noun = format_pattern_str(&stmt.noun);
    format!("{} {} {} {}", effect, entity, tool, noun)
}

// ---------------------------------------------------------------------------
// Kept for backward compatibility — parse TOML policy documents.
// ---------------------------------------------------------------------------

/// Parse a policy document from a TOML string.
pub fn parse_toml(input: &str) -> Result<PolicyDocument, toml::de::Error> {
    toml::from_str(input)
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
/// - `read` / `write` / `edit` / `execute` / `delegate` → `VerbPattern::Exact(Verb)`
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
        "delegate" => Ok(VerbPattern::Exact(Verb::Delegate)),
        _ => Err(format!("unknown verb: {}", s)),
    }
}

/// Desugar legacy `[permissions]` block into policy statements.
///
/// Converts Claude Code format like:
/// ```yaml
/// permissions:
///   allow: ["Bash(git:*)", "Read(**/*.rs)"]
///   deny: ["Read(.env)"]
///   ask: ["Write"]
/// ```
///
/// Into equivalent statements with `entity = "agent"`.
pub fn desugar_legacy(perms: &LegacyPermissions) -> Vec<Statement> {
    let mut statements = Vec::new();

    for pattern in &perms.allow {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Allow) {
            statements.push(stmt);
        }
    }
    for pattern in &perms.deny {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Deny) {
            statements.push(stmt);
        }
    }
    for pattern in &perms.ask {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Ask) {
            statements.push(stmt);
        }
    }

    statements
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_effect_str(s: &str) -> Result<Effect, PolicyParseError> {
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        "delegate" => Ok(Effect::Delegate),
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
        other => Err(PolicyParseError::InvalidTool(other.into())),
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
            let s = inner.as_str();
            MatchExpr::Exact(s.to_string())
        }
        _ => MatchExpr::Any,
    }
}

/// Convert a single legacy permission pattern like `"Bash(git:*)"` into a Statement.
fn legacy_pattern_to_statement(pattern: &str, effect: Effect) -> Option<Statement> {
    let pattern = pattern.trim();

    // Parse "ToolName(arg)" or "ToolName"
    let (tool_name, arg) = if let Some(paren_start) = pattern.find('(') {
        if !pattern.ends_with(')') {
            return None;
        }
        let tool = &pattern[..paren_start];
        let arg = &pattern[paren_start + 1..pattern.len() - 1];
        (tool, Some(arg))
    } else {
        (pattern, None)
    };

    let verb = Verb::from_tool_name(tool_name)?;
    let verb_pattern = VerbPattern::Exact(verb);

    let noun = match arg {
        None => Pattern::Match(MatchExpr::Any),
        Some(arg) => {
            // Handle prefix pattern "git:*" → glob "git *"
            if let Some(prefix) = arg.strip_suffix(":*") {
                Pattern::Match(MatchExpr::Glob(format!("{} *", prefix)))
            } else if arg.contains('*') || arg.contains("**") || arg.contains('?') {
                Pattern::Match(MatchExpr::Glob(arg.to_string()))
            } else {
                Pattern::Match(MatchExpr::Exact(arg.to_string()))
            }
        }
    };

    Some(Statement {
        effect,
        entity: Pattern::Match(MatchExpr::Typed {
            entity_type: "agent".into(),
            name: None,
        }),
        verb: verb_pattern,
        noun,
        reason: None,
        delegate: None,
    })
}

/// Format a `Pattern` as a string for rule serialization.
fn format_pattern_str(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Match(expr) => format_match_expr(expr),
        Pattern::Not(expr) => format!("!{}", format_match_expr(expr)),
    }
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
        Ok(parse_pattern(&s))
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
        }
    }
}

impl<'de> Deserialize<'de> for VerbPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_verb_pattern(&s).map_err(serde::de::Error::custom)
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
        Ok(parse_match_expr(&s))
    }
}

fn format_match_expr(expr: &MatchExpr) -> String {
    match expr {
        MatchExpr::Any => "*".to_string(),
        MatchExpr::Exact(s) => s.clone(),
        MatchExpr::Glob(s) => s.clone(),
        MatchExpr::Typed {
            entity_type,
            name: None,
        } => format!("{}:*", entity_type),
        MatchExpr::Typed {
            entity_type,
            name: Some(name),
        } => format!("{}:{}", entity_type, name),
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
        assert!(parse_verb_pattern("unknown").is_err());
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

    // --- YAML document parsing ---

    #[test]
    fn test_parse_yaml_simple() {
        let yaml = r#"
default: ask

rules:
  - allow agent:claude bash git *
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask);
        assert_eq!(doc.statements.len(), 1);

        let stmt = &doc.statements[0];
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(!stmt.matches("agent:codex", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_yaml_multiple_rules() {
        let yaml = r#"
default: ask

rules:
  - allow * bash cargo build *
  - allow * bash cargo test *
  - deny * bash rm -rf /
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 3);
        assert_eq!(doc.statements[0].effect, Effect::Allow);
        assert_eq!(doc.statements[1].effect, Effect::Allow);
        assert_eq!(doc.statements[2].effect, Effect::Deny);
    }

    #[test]
    fn test_parse_yaml_with_negation() {
        let yaml = r#"
rules:
  - deny !user read ~/config/*
"#;
        let doc = parse_yaml(yaml).unwrap();
        let stmt = &doc.statements[0];

        assert_eq!(stmt.effect, Effect::Deny);
        assert!(stmt.matches("agent:claude", &Verb::Read, "~/config/test.json"));
        assert!(!stmt.matches("user", &Verb::Read, "~/config/test.json"));
    }

    #[test]
    fn test_parse_yaml_default_values() {
        let yaml = "rules:\n  - allow * * *.rs\n";
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask); // default
        let stmt = &doc.statements[0];
        assert!(stmt.entity.matches_entity("agent:claude"));
        assert!(stmt.entity.matches_entity("user"));
        assert!(stmt.verb.matches(&Verb::Read));
        assert!(stmt.verb.matches(&Verb::Execute));
    }

    #[test]
    fn test_parse_yaml_with_legacy_permissions() {
        let yaml = r#"
default: ask

permissions:
  allow:
    - "Bash(git:*)"
    - "Read(**/*.rs)"
  deny:
    - "Read(.env)"
  ask:
    - "Write"
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert!(doc.permissions.is_some());
        let perms = doc.permissions.as_ref().unwrap();
        assert_eq!(perms.allow.len(), 2);
        assert_eq!(perms.deny.len(), 1);
        assert_eq!(perms.ask.len(), 1);
    }

    // --- Legacy desugaring ---

    #[test]
    fn test_desugar_legacy_bash() {
        let perms = LegacyPermissions {
            allow: vec!["Bash(git:*)".into()],
            deny: vec![],
            ask: vec![],
        };
        let stmts = desugar_legacy(&perms);
        assert_eq!(stmts.len(), 1);
        let stmt = &stmts[0];
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git commit -m 'test'"));
        assert!(!stmt.matches("agent:claude", &Verb::Execute, "npm install"));
    }

    #[test]
    fn test_desugar_legacy_read() {
        let perms = LegacyPermissions {
            allow: vec!["Read".into()],
            deny: vec!["Read(.env)".into()],
            ask: vec![],
        };
        let stmts = desugar_legacy(&perms);
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
    fn test_desugar_legacy_glob() {
        let perms = LegacyPermissions {
            allow: vec!["Read(**/*.rs)".into()],
            deny: vec![],
            ask: vec![],
        };
        let stmts = desugar_legacy(&perms);
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

    // --- TOML backward compat ---

    #[test]
    fn test_parse_toml_still_works() {
        let toml_str = r#"
[policy]
default = "ask"

[[statements]]
effect = "allow"
entity = "agent:claude"
verb = "execute"
noun = "git *"
"#;
        let doc = parse_toml(toml_str).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask);
        assert_eq!(doc.statements.len(), 1);
        assert!(doc.statements[0].matches("agent:claude", &Verb::Execute, "git status"));
    }
}
