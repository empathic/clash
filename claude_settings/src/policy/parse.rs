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

    #[error("invalid filter expression: {0}")]
    InvalidFilter(String),

    #[error("invalid profile expression: {0}")]
    InvalidProfile(String),

    #[error("unknown constraint or profile '{0}'")]
    UnknownRef(String),
}

// ---------------------------------------------------------------------------
// YAML document shape (serde)
// ---------------------------------------------------------------------------

/// Raw YAML representation that maps 1:1 to the file format.
#[derive(Debug, Serialize, Deserialize)]
struct RawPolicyYaml {
    #[serde(default = "default_ask_str")]
    default: String,

    /// Named constraint primitives.
    #[serde(default)]
    constraints: HashMap<String, ConstraintDef>,

    /// Named profiles (boolean expressions over constraint names).
    #[serde(default)]
    profiles: HashMap<String, ProfileExpr>,

    #[serde(
        default,
        deserialize_with = "deserialize_rules",
        serialize_with = "serialize_rules"
    )]
    rules: Vec<String>,

    /// Legacy backward-compat with Claude Code permission format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<LegacyPermissions>,
}

fn default_ask_str() -> String {
    "ask".into()
}

/// Deserialize rules from either a YAML sequence (old format) or mapping (new format).
///
/// Old format (sequence of strings):
/// ```yaml
/// rules:
///   - "allow bash git * : strict-git"
///   - deny bash rm *
/// ```
///
/// New format (mapping of rule → constraint):
/// ```yaml
/// rules:
///   allow bash git * : strict-git
///   allow bash cargo * : sandboxed
///   deny bash rm * : []
/// ```
fn deserialize_rules<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_yaml::Value::deserialize(deserializer)?;
    match value {
        serde_yaml::Value::Sequence(seq) => seq
            .into_iter()
            .map(|v| match v {
                serde_yaml::Value::String(s) => Ok(s),
                _ => Err(Error::custom("rule must be a string")),
            })
            .collect(),
        serde_yaml::Value::Mapping(map) => {
            let mut rules = Vec::new();
            for (key, value) in map {
                let rule_key = match key {
                    serde_yaml::Value::String(s) => s,
                    _ => return Err(Error::custom("rule key must be a string")),
                };
                let constraint = match &value {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    serde_yaml::Value::Null => None,
                    serde_yaml::Value::Sequence(seq) if seq.is_empty() => None,
                    _ => {
                        return Err(Error::custom(format!(
                            "constraint for '{}' must be a string, null, or []",
                            rule_key
                        )));
                    }
                };
                if let Some(constraint) = constraint {
                    rules.push(format!("{} : {}", rule_key, constraint));
                } else {
                    rules.push(rule_key);
                }
            }
            Ok(rules)
        }
        serde_yaml::Value::Null => Ok(Vec::new()),
        _ => Err(Error::custom("rules must be a sequence or mapping")),
    }
}

/// Serialize rules as a YAML mapping (new format).
///
/// Rules with constraints are split on the ` : ` separator.
/// Rules without constraints get `[]` as the value.
fn serialize_rules<S>(rules: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(rules.len()))?;
    for rule in rules {
        if let Some(colon_idx) = find_constraint_separator(rule) {
            let key = rule[..colon_idx].trim_end();
            let value = rule[colon_idx + 1..].trim();
            map.serialize_entry(key, value)?;
        } else {
            let empty: Vec<String> = Vec::new();
            map.serialize_entry(rule.trim(), &empty)?;
        }
    }
    map.end()
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
        constraints: raw.constraints,
        profiles: raw.profiles,
        statements,
    })
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
        delegate: None,
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

// ---------------------------------------------------------------------------
// Filter expression parser (recursive descent)
// ---------------------------------------------------------------------------

/// Parse a filter expression string like `subpath(.) & !literal(.env)`.
///
/// Grammar (precedence: `!` > `&` > `|`):
///   expr     = or_expr
///   or_expr  = and_expr ( '|' and_expr )*
///   and_expr = unary ( '&' unary )*
///   unary    = '!' unary | atom
///   atom     = 'subpath(' path ')' | 'literal(' path ')' | 'regex(' pattern ')' | '(' expr ')'
pub fn parse_filter_expr(input: &str) -> Result<FilterExpr, PolicyParseError> {
    let input = input.trim();
    let tokens = tokenize_expr(input).map_err(PolicyParseError::InvalidFilter)?;
    let mut pos = 0;
    let result = parse_filter_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(PolicyParseError::InvalidFilter(format!(
            "unexpected token at position {}: {:?}",
            pos,
            tokens.get(pos)
        )));
    }
    Ok(result)
}

/// Parse a profile expression string like `sandboxed & safe-io`.
///
/// Grammar (precedence: `!` > `&` > `|`):
///   expr     = or_expr
///   or_expr  = and_expr ( '|' and_expr )*
///   and_expr = unary ( '&' unary )*
///   unary    = '!' unary | atom
///   atom     = identifier | '(' expr ')'
pub fn parse_profile_expr(input: &str) -> Result<ProfileExpr, PolicyParseError> {
    let input = input.trim();
    let tokens = tokenize_expr(input).map_err(PolicyParseError::InvalidProfile)?;
    let mut pos = 0;
    let result = parse_profile_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(PolicyParseError::InvalidProfile(format!(
            "unexpected token at position {}: {:?}",
            pos,
            tokens.get(pos)
        )));
    }
    Ok(result)
}

// -- Shared tokenizer for boolean expressions --

#[derive(Debug, Clone, PartialEq)]
enum ExprToken {
    And,           // &
    Or,            // |
    Not,           // !
    LParen,        // (
    RParen,        // )
    Ident(String), // identifier or function call like subpath(./src)
}

/// Tokenize an expression string into tokens.
/// Handles function-call syntax like `subpath(./src)` as a single Ident token.
fn tokenize_expr(input: &str) -> Result<Vec<ExprToken>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' => i += 1,
            '&' => {
                tokens.push(ExprToken::And);
                i += 1;
            }
            '|' => {
                tokens.push(ExprToken::Or);
                i += 1;
            }
            '!' => {
                tokens.push(ExprToken::Not);
                i += 1;
            }
            '(' => {
                tokens.push(ExprToken::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(ExprToken::RParen);
                i += 1;
            }
            _ => {
                // Read an identifier, possibly including a function call like subpath(./src)
                let start = i;
                // Read the identifier part
                while i < chars.len()
                    && !matches!(chars[i], ' ' | '\t' | '&' | '|' | '!' | '(' | ')')
                {
                    i += 1;
                }
                let word = &input[start..i];

                // Check if this is a function call (next non-space char is '(')
                let mut peek = i;
                while peek < chars.len() && (chars[peek] == ' ' || chars[peek] == '\t') {
                    peek += 1;
                }
                if peek < chars.len()
                    && chars[peek] == '('
                    && matches!(word, "subpath" | "literal" | "regex")
                {
                    // Consume the '(' and everything up to the matching ')'
                    i = peek + 1; // skip '('
                    let arg_start = i;
                    let mut depth = 1;
                    while i < chars.len() && depth > 0 {
                        match chars[i] {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                        if depth > 0 {
                            i += 1;
                        }
                    }
                    if depth != 0 {
                        return Err(format!("unclosed parenthesis in {}()", word));
                    }
                    let arg = input[arg_start..i].trim();
                    i += 1; // skip closing ')'
                    tokens.push(ExprToken::Ident(format!("{}({})", word, arg)));
                } else {
                    tokens.push(ExprToken::Ident(word.to_string()));
                }
            }
        }
    }
    Ok(tokens)
}

// -- Filter expression recursive descent --

fn parse_filter_or(tokens: &[ExprToken], pos: &mut usize) -> Result<FilterExpr, PolicyParseError> {
    let mut left = parse_filter_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::Or {
        *pos += 1;
        let right = parse_filter_and(tokens, pos)?;
        left = FilterExpr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_filter_and(tokens: &[ExprToken], pos: &mut usize) -> Result<FilterExpr, PolicyParseError> {
    let mut left = parse_filter_unary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::And {
        *pos += 1;
        let right = parse_filter_unary(tokens, pos)?;
        left = FilterExpr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_filter_unary(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<FilterExpr, PolicyParseError> {
    if *pos < tokens.len() && tokens[*pos] == ExprToken::Not {
        *pos += 1;
        let inner = parse_filter_unary(tokens, pos)?;
        return Ok(FilterExpr::Not(Box::new(inner)));
    }
    parse_filter_atom(tokens, pos)
}

fn parse_filter_atom(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<FilterExpr, PolicyParseError> {
    if *pos >= tokens.len() {
        return Err(PolicyParseError::InvalidFilter(
            "unexpected end of expression".into(),
        ));
    }
    match &tokens[*pos] {
        ExprToken::LParen => {
            *pos += 1;
            let expr = parse_filter_or(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != ExprToken::RParen {
                return Err(PolicyParseError::InvalidFilter(
                    "expected closing ')'".into(),
                ));
            }
            *pos += 1;
            Ok(expr)
        }
        ExprToken::Ident(s) => {
            let expr = parse_filter_function(s)?;
            *pos += 1;
            Ok(expr)
        }
        other => Err(PolicyParseError::InvalidFilter(format!(
            "unexpected token: {:?}",
            other
        ))),
    }
}

/// Parse a filter function call like `subpath(./src)`, `literal(.env)`, `regex(.*\.rs$)`.
fn parse_filter_function(s: &str) -> Result<FilterExpr, PolicyParseError> {
    if let Some(arg) = s.strip_prefix("subpath(").and_then(|s| s.strip_suffix(')')) {
        Ok(FilterExpr::Subpath(arg.to_string()))
    } else if let Some(arg) = s.strip_prefix("literal(").and_then(|s| s.strip_suffix(')')) {
        Ok(FilterExpr::Literal(arg.to_string()))
    } else if let Some(arg) = s.strip_prefix("regex(").and_then(|s| s.strip_suffix(')')) {
        Ok(FilterExpr::Regex(arg.to_string()))
    } else {
        Err(PolicyParseError::InvalidFilter(format!(
            "expected subpath(), literal(), or regex(), got '{}'",
            s
        )))
    }
}

// -- Profile expression recursive descent --

fn parse_profile_or(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    let mut left = parse_profile_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::Or {
        *pos += 1;
        let right = parse_profile_and(tokens, pos)?;
        left = ProfileExpr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_profile_and(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    let mut left = parse_profile_unary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == ExprToken::And {
        *pos += 1;
        let right = parse_profile_unary(tokens, pos)?;
        left = ProfileExpr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_profile_unary(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    if *pos < tokens.len() && tokens[*pos] == ExprToken::Not {
        *pos += 1;
        let inner = parse_profile_unary(tokens, pos)?;
        return Ok(ProfileExpr::Not(Box::new(inner)));
    }
    parse_profile_atom(tokens, pos)
}

fn parse_profile_atom(
    tokens: &[ExprToken],
    pos: &mut usize,
) -> Result<ProfileExpr, PolicyParseError> {
    if *pos >= tokens.len() {
        return Err(PolicyParseError::InvalidProfile(
            "unexpected end of expression".into(),
        ));
    }
    match &tokens[*pos] {
        ExprToken::LParen => {
            *pos += 1;
            let expr = parse_profile_or(tokens, pos)?;
            if *pos >= tokens.len() || tokens[*pos] != ExprToken::RParen {
                return Err(PolicyParseError::InvalidProfile(
                    "expected closing ')'".into(),
                ));
            }
            *pos += 1;
            Ok(expr)
        }
        ExprToken::Ident(s) => {
            let expr = ProfileExpr::Ref(s.to_string());
            *pos += 1;
            Ok(expr)
        }
        other => Err(PolicyParseError::InvalidProfile(format!(
            "unexpected token: {:?}",
            other
        ))),
    }
}

/// Serialize a `PolicyDocument` back to YAML.
pub fn to_yaml(doc: &PolicyDocument) -> Result<String, serde_yaml::Error> {
    let raw = RawPolicyYaml {
        default: doc.policy.default.to_string(),
        constraints: doc.constraints.clone(),
        profiles: doc.profiles.clone(),
        rules: doc.statements.iter().map(format_rule).collect(),
        permissions: doc.permissions.clone(),
    };
    serde_yaml::to_string(&raw)
}

/// Format a `Statement` as a compact rule string.
///
/// When the entity is the default (any agent), it is omitted from the output.
pub fn format_rule(stmt: &Statement) -> String {
    let effect = stmt.effect.to_string();
    let tool = match &stmt.verb {
        VerbPattern::Any => "*".to_string(),
        VerbPattern::Exact(v) => v.rule_name().to_string(),
    };
    let noun = format_pattern_str(&stmt.noun);

    let base = if is_default_entity(&stmt.entity) {
        format!("{} {} {}", effect, tool, noun)
    } else {
        let entity = format_pattern_str(&stmt.entity);
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
        profile: None,
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
        } => entity_type.clone(),
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

    // --- YAML with constraints and profiles ---

    #[test]
    fn test_parse_yaml_with_constraints() {
        let yaml = r#"
default: deny

constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false

profiles:
  sandboxed: local & safe-io

rules:
  - "allow agent bash git * : sandboxed"
  - deny agent bash rm *
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Deny);
        assert_eq!(doc.constraints.len(), 2);
        assert!(doc.constraints.contains_key("local"));
        assert!(doc.constraints.contains_key("safe-io"));
        assert_eq!(doc.profiles.len(), 1);
        assert!(doc.profiles.contains_key("sandboxed"));
        assert_eq!(doc.statements.len(), 2);

        // First statement has a constraint
        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::Ref("sandboxed".into()))
        );
        // Second statement has no constraint
        assert_eq!(doc.statements[1].profile, None);
    }

    // --- Mapping-format rules ---

    #[test]
    fn test_parse_yaml_mapping_format() {
        let yaml = r#"
default: ask

rules:
  allow bash git * : strict-git
  allow bash cargo * : sandboxed
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 3);

        assert_eq!(doc.statements[0].effect, Effect::Allow);
        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::Ref("strict-git".into()))
        );
        assert!(doc.statements[0].matches("agent", &Verb::Execute, "git status"));

        assert_eq!(doc.statements[1].effect, Effect::Allow);
        assert_eq!(
            doc.statements[1].profile,
            Some(ProfileExpr::Ref("sandboxed".into()))
        );

        assert_eq!(doc.statements[2].effect, Effect::Deny);
        assert_eq!(doc.statements[2].profile, None);
        assert!(doc.statements[2].matches("agent", &Verb::Execute, "rm -rf /"));
    }

    #[test]
    fn test_parse_yaml_mapping_format_no_constraint() {
        let yaml = r#"
rules:
  allow bash git * : []
  allow read * :
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 3);

        // All should have no profile/constraint
        for stmt in &doc.statements {
            assert_eq!(stmt.profile, None, "expected no constraint for: {:?}", stmt);
        }
    }

    #[test]
    fn test_parse_yaml_mapping_format_with_constraints() {
        let yaml = r#"
default: deny

constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false

profiles:
  sandboxed: local & safe-io

rules:
  allow bash git * : sandboxed
  allow read * : local
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Deny);
        assert_eq!(doc.constraints.len(), 2);
        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.statements.len(), 3);

        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::Ref("sandboxed".into()))
        );
        assert_eq!(
            doc.statements[1].profile,
            Some(ProfileExpr::Ref("local".into()))
        );
        assert_eq!(doc.statements[2].profile, None);
    }

    #[test]
    fn test_parse_yaml_mapping_format_inline_constraint() {
        let yaml = r#"
rules:
  allow edit * : local & no-secrets
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 1);
        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::And(
                Box::new(ProfileExpr::Ref("local".into())),
                Box::new(ProfileExpr::Ref("no-secrets".into()))
            ))
        );
    }

    #[test]
    fn test_parse_yaml_mapping_format_with_explicit_entity() {
        let yaml = r#"
rules:
  allow agent:claude bash git * : strict-git
  deny * bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 2);

        assert_eq!(
            doc.statements[0].entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
        assert_eq!(doc.statements[1].entity, Pattern::Match(MatchExpr::Any));
    }

    #[test]
    fn test_yaml_mapping_serialization_roundtrip() {
        let yaml = r#"
default: ask

constraints:
  safe-io:
    pipe: false

rules:
  allow bash git * : safe-io
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        let serialized = to_yaml(&doc).unwrap();
        let reparsed = parse_yaml(&serialized).unwrap();

        assert_eq!(doc.policy.default, reparsed.policy.default);
        assert_eq!(doc.statements.len(), reparsed.statements.len());
        for (a, b) in doc.statements.iter().zip(reparsed.statements.iter()) {
            assert_eq!(a.effect, b.effect);
            assert_eq!(a.profile, b.profile);
        }
    }
}
