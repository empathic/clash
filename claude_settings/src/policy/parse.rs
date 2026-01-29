//! Parsing and deserialization for policy documents.
//!
//! Handles:
//! - TOML deserialization of `PolicyDocument`
//! - Custom serde for `Pattern` (with `!` negation prefix)
//! - Custom serde for `VerbPattern` (with `*` wildcard)
//! - Legacy `[permissions]` desugaring to statements

use super::*;

/// Parse a policy document from a TOML string.
pub fn parse_toml(input: &str) -> Result<PolicyDocument, toml::de::Error> {
    toml::from_str(input)
}

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
/// ```toml
/// [permissions]
/// allow = ["Bash(git:*)", "Read(**/*.rs)"]
/// deny = ["Read(.env)"]
/// ask = ["Write"]
/// ```
///
/// Into equivalent statements with `entity = "agent"`.
pub fn desugar_legacy(perms: &LegacyPermissions) -> Vec<Statement> {
    let mut statements = Vec::new();

    for pattern in &perms.allow {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Permit) {
            statements.push(stmt);
        }
    }
    for pattern in &perms.deny {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Forbid) {
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

// --- Custom serde implementations ---

impl Serialize for Pattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Pattern::Match(expr) => format_match_expr(expr),
            Pattern::Not(expr) => format!("!{}", format_match_expr(expr)),
        };
        serializer.serialize_str(&s)
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
        // "!user" → Not(Exact("user"))
        // "user" without a colon is Exact, not Typed.
        // Entity matching handles Exact strings via direct comparison.
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
        // "agent" without colon → treated as a typed entity with no name
        // (because it doesn't contain /, ., or ~ which would make it a path)
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

    #[test]
    fn test_parse_toml_simple() {
        let toml_str = r#"
[policy]
default = "ask"

[[statements]]
effect = "permit"
entity = "agent:claude"
verb = "execute"
noun = "git *"
"#;
        let doc = parse_toml(toml_str).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask);
        assert_eq!(doc.statements.len(), 1);

        let stmt = &doc.statements[0];
        assert_eq!(stmt.effect, Effect::Permit);
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(!stmt.matches("agent:codex", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_toml_with_negation() {
        let toml_str = r#"
[[statements]]
effect = "forbid"
entity = "!user"
verb = "read"
noun = "~/config/*"
reason = "Only users can read config"
"#;
        let doc = parse_toml(toml_str).unwrap();
        let stmt = &doc.statements[0];

        assert_eq!(stmt.effect, Effect::Forbid);
        assert!(stmt.matches("agent:claude", &Verb::Read, "~/config/test.json"));
        assert!(!stmt.matches("user", &Verb::Read, "~/config/test.json"));
    }

    #[test]
    fn test_parse_toml_with_legacy_permissions() {
        let toml_str = r#"
[policy]
default = "ask"

[permissions]
allow = ["Bash(git:*)", "Read(**/*.rs)"]
deny = ["Read(.env)"]
ask = ["Write"]
"#;
        let doc = parse_toml(toml_str).unwrap();
        assert!(doc.permissions.is_some());
        let perms = doc.permissions.as_ref().unwrap();
        assert_eq!(perms.allow.len(), 2);
        assert_eq!(perms.deny.len(), 1);
        assert_eq!(perms.ask.len(), 1);
    }

    #[test]
    fn test_parse_toml_default_values() {
        let toml_str = r#"
[[statements]]
effect = "permit"
noun = "*.rs"
"#;
        let doc = parse_toml(toml_str).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask); // default
        let stmt = &doc.statements[0];
        // entity defaults to * (any)
        assert!(stmt.entity.matches_entity("agent:claude"));
        assert!(stmt.entity.matches_entity("user"));
        // verb defaults to * (any)
        assert!(stmt.verb.matches(&Verb::Read));
        assert!(stmt.verb.matches(&Verb::Execute));
    }

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
        assert_eq!(stmt.effect, Effect::Permit);
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

        // "Read" → permit(agent, read, *)
        let allow_stmt = &stmts[0];
        assert_eq!(allow_stmt.effect, Effect::Permit);
        assert!(allow_stmt.matches("agent:claude", &Verb::Read, "anything.txt"));

        // "Read(.env)" → forbid(agent, read, .env)
        let deny_stmt = &stmts[1];
        assert_eq!(deny_stmt.effect, Effect::Forbid);
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

    #[test]
    fn test_full_toml_roundtrip() {
        let toml_str = r#"
[policy]
default = "forbid"

[[statements]]
effect = "permit"
entity = "agent:claude"
verb = "execute"
noun = "git *"
reason = "Allow git commands"

[[statements]]
effect = "forbid"
entity = "!user"
verb = "read"
noun = "~/config/*"
reason = "Only users can read config"

[[statements]]
effect = "ask"
entity = "*"
verb = "*"
noun = "*"
reason = "Default: ask for everything else"
"#;
        let doc = parse_toml(toml_str).unwrap();
        assert_eq!(doc.policy.default, Effect::Forbid);
        assert_eq!(doc.statements.len(), 3);

        // Re-serialize to TOML
        let reserialized = toml::to_string_pretty(&doc).unwrap();
        let reparsed = parse_toml(&reserialized).unwrap();
        assert_eq!(reparsed.statements.len(), 3);
        assert_eq!(reparsed.policy.default, Effect::Forbid);
    }
}
