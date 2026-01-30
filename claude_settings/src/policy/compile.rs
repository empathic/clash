//! Compilation of policy documents into optimized runtime representations.
//!
//! The `CompiledPolicy` pre-compiles glob patterns into regexes and
//! organizes statements for efficient evaluation.

use regex::Regex;

use super::*;

/// A compiled policy ready for fast evaluation.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Default effect when no statement matches.
    pub default: Effect,
    /// Compiled statements in evaluation order.
    pub statements: Vec<CompiledStatement>,
}

/// A compiled statement with pre-compiled matchers.
#[derive(Debug)]
pub struct CompiledStatement {
    pub effect: Effect,
    pub entity_matcher: CompiledPattern,
    pub verb_matcher: VerbPattern,
    pub noun_matcher: CompiledPattern,
    pub reason: Option<String>,
    pub delegate: Option<DelegateConfig>,
}

/// A compiled pattern (potentially negated).
#[derive(Debug)]
pub enum CompiledPattern {
    Match(CompiledMatchExpr),
    Not(CompiledMatchExpr),
}

/// A compiled match expression with pre-compiled regex for globs.
#[derive(Debug)]
pub enum CompiledMatchExpr {
    Any,
    Exact(String),
    Glob {
        pattern: String,
        regex: Regex,
    },
    Typed {
        entity_type: String,
        name: Option<String>,
    },
}

/// Error during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid glob pattern '{pattern}': {source}")]
    InvalidGlob {
        pattern: String,
        source: regex::Error,
    },
}

impl CompiledPolicy {
    /// Compile a `PolicyDocument` into a `CompiledPolicy`.
    ///
    /// This pre-compiles all glob patterns into regexes and
    /// merges legacy permissions into the statement list.
    pub fn compile(doc: &PolicyDocument) -> Result<Self, CompileError> {
        let mut statements = Vec::new();

        // First, desugar legacy permissions if present
        if let Some(ref perms) = doc.permissions {
            let legacy = parse::desugar_legacy(perms);
            for stmt in &legacy {
                statements.push(CompiledStatement::compile(stmt)?);
            }
        }

        // Then add explicit statements (these take precedence via evaluation order,
        // but since we use forbid > ask > permit, order within the same effect
        // doesn't matter)
        for stmt in &doc.statements {
            statements.push(CompiledStatement::compile(stmt)?);
        }

        Ok(CompiledPolicy {
            default: doc.policy.default,
            statements,
        })
    }

    /// Evaluate a request against this policy.
    ///
    /// Returns the resulting effect after applying all matching statements
    /// with precedence: forbid > ask > permit > delegate.
    ///
    /// If no statement matches, returns the configured default effect.
    pub fn evaluate(&self, entity: &str, verb: &Verb, noun: &str) -> PolicyDecision {
        let mut has_permit = false;
        let mut has_ask = false;
        let mut has_forbid = false;
        let mut has_delegate = false;

        let mut forbid_reason: Option<&str> = None;
        let mut ask_reason: Option<&str> = None;
        let mut delegate_config: Option<&DelegateConfig> = None;

        for stmt in &self.statements {
            if stmt.matches(entity, verb, noun) {
                match stmt.effect {
                    Effect::Forbid => {
                        has_forbid = true;
                        if forbid_reason.is_none() {
                            forbid_reason = stmt.reason.as_deref();
                        }
                    }
                    Effect::Ask => {
                        has_ask = true;
                        if ask_reason.is_none() {
                            ask_reason = stmt.reason.as_deref();
                        }
                    }
                    Effect::Permit => {
                        has_permit = true;
                    }
                    Effect::Delegate => {
                        has_delegate = true;
                        if delegate_config.is_none() {
                            delegate_config = stmt.delegate.as_ref();
                        }
                    }
                }
            }
        }

        // Precedence: forbid > ask > permit > delegate
        if has_forbid {
            return PolicyDecision {
                effect: Effect::Forbid,
                reason: forbid_reason.map(|s| s.to_string()),
                delegate: None,
            };
        }
        if has_ask {
            return PolicyDecision {
                effect: Effect::Ask,
                reason: ask_reason.map(|s| s.to_string()),
                delegate: None,
            };
        }
        if has_permit {
            return PolicyDecision {
                effect: Effect::Permit,
                reason: None,
                delegate: None,
            };
        }
        if has_delegate {
            return PolicyDecision {
                effect: Effect::Delegate,
                reason: None,
                delegate: delegate_config.cloned(),
            };
        }

        // No match → default
        PolicyDecision {
            effect: self.default,
            reason: None,
            delegate: None,
        }
    }
}

/// The result of evaluating a policy.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: Option<String>,
    pub delegate: Option<DelegateConfig>,
}

impl CompiledStatement {
    fn compile(stmt: &Statement) -> Result<Self, CompileError> {
        Ok(CompiledStatement {
            effect: stmt.effect,
            entity_matcher: CompiledPattern::compile(&stmt.entity)?,
            verb_matcher: stmt.verb.clone(),
            noun_matcher: CompiledPattern::compile(&stmt.noun)?,
            reason: stmt.reason.clone(),
            delegate: stmt.delegate.clone(),
        })
    }

    fn matches(&self, entity: &str, verb: &Verb, noun: &str) -> bool {
        self.entity_matcher.matches_entity(entity)
            && self.verb_matcher.matches(verb)
            && self.noun_matcher.matches_noun(noun)
    }
}

impl CompiledPattern {
    fn compile(pattern: &Pattern) -> Result<Self, CompileError> {
        match pattern {
            Pattern::Match(expr) => Ok(CompiledPattern::Match(CompiledMatchExpr::compile(expr)?)),
            Pattern::Not(expr) => Ok(CompiledPattern::Not(CompiledMatchExpr::compile(expr)?)),
        }
    }

    fn matches_entity(&self, entity: &str) -> bool {
        match self {
            CompiledPattern::Match(expr) => expr.matches_entity(entity),
            CompiledPattern::Not(expr) => !expr.matches_entity(entity),
        }
    }

    fn matches_noun(&self, noun: &str) -> bool {
        match self {
            CompiledPattern::Match(expr) => expr.matches_noun(noun),
            CompiledPattern::Not(expr) => !expr.matches_noun(noun),
        }
    }
}

impl CompiledMatchExpr {
    fn compile(expr: &MatchExpr) -> Result<Self, CompileError> {
        match expr {
            MatchExpr::Any => Ok(CompiledMatchExpr::Any),
            MatchExpr::Exact(s) => Ok(CompiledMatchExpr::Exact(s.clone())),
            MatchExpr::Glob(pattern) => {
                let regex = glob_to_regex(pattern).map_err(|source| CompileError::InvalidGlob {
                    pattern: pattern.clone(),
                    source,
                })?;
                Ok(CompiledMatchExpr::Glob {
                    pattern: pattern.clone(),
                    regex,
                })
            }
            MatchExpr::Typed { entity_type, name } => Ok(CompiledMatchExpr::Typed {
                entity_type: entity_type.clone(),
                name: name.clone(),
            }),
        }
    }

    fn matches_entity(&self, entity: &str) -> bool {
        match self {
            CompiledMatchExpr::Any => true,
            CompiledMatchExpr::Exact(s) => entity == s,
            CompiledMatchExpr::Glob { regex, .. } => regex.is_match(entity),
            CompiledMatchExpr::Typed {
                entity_type,
                name: None,
            } => entity == entity_type.as_str() || entity.starts_with(&format!("{}:", entity_type)),
            CompiledMatchExpr::Typed {
                entity_type,
                name: Some(name),
            } => entity == format!("{}:{}", entity_type, name),
        }
    }

    fn matches_noun(&self, noun: &str) -> bool {
        match self {
            CompiledMatchExpr::Any => true,
            CompiledMatchExpr::Exact(s) => noun == s,
            CompiledMatchExpr::Glob { regex, .. } => regex.is_match(noun),
            CompiledMatchExpr::Typed { .. } => false,
        }
    }
}

/// Convert a glob pattern to a compiled regex.
///
/// Unlike traditional file-path globbing, `*` matches any character
/// (including `/`) because policy patterns apply to both file paths
/// and command strings. Use `*` for "anything in this segment" and
/// `**` also matches anything (they're equivalent here).
fn glob_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let regex_pattern = pattern
        .replace('.', "\\.")
        .replace("**", "<<<DOUBLESTAR>>>")
        .replace('*', ".*")
        .replace("<<<DOUBLESTAR>>>", ".*")
        .replace('?', ".");

    Regex::new(&format!("^{}$", regex_pattern))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_doc(toml_str: &str) -> CompiledPolicy {
        let doc = parse::parse_toml(toml_str).unwrap();
        CompiledPolicy::compile(&doc).unwrap()
    }

    #[test]
    fn test_simple_permit() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "permit"
entity = "agent:claude"
verb = "execute"
noun = "git *"
"#,
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Permit);

        let decision = policy.evaluate("agent:codex", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Ask); // default
    }

    #[test]
    fn test_forbid_overrides_permit() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "permit"
entity = "*"
verb = "read"
noun = "*"

[[statements]]
effect = "forbid"
entity = "*"
verb = "read"
noun = ".env"
reason = "Never read .env"
"#,
        );

        let decision = policy.evaluate("agent:claude", &Verb::Read, "src/main.rs");
        assert_eq!(decision.effect, Effect::Permit);

        let decision = policy.evaluate("agent:claude", &Verb::Read, ".env");
        assert_eq!(decision.effect, Effect::Forbid);
        assert_eq!(decision.reason.as_deref(), Some("Never read .env"));
    }

    #[test]
    fn test_ask_overrides_permit() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "permit"
entity = "agent:*"
verb = "execute"
noun = "*"

[[statements]]
effect = "ask"
entity = "agent:*"
verb = "execute"
noun = "rm *"
reason = "Destructive command"
"#,
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "ls");
        assert_eq!(decision.effect, Effect::Permit);

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "rm -rf /tmp");
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_negated_entity() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "permit"
entity = "*"
verb = "read"
noun = "~/*"

[[statements]]
effect = "forbid"
entity = "!user"
verb = "read"
noun = "~/config/*"
reason = "Only users can read config"
"#,
        );

        // Agent reading config → forbidden
        let decision = policy.evaluate("agent:claude", &Verb::Read, "~/config/test.json");
        assert_eq!(decision.effect, Effect::Forbid);

        // User reading config → permitted (forbid doesn't match user)
        let decision = policy.evaluate("user", &Verb::Read, "~/config/test.json");
        assert_eq!(decision.effect, Effect::Permit);

        // Agent reading non-config → permitted
        let decision = policy.evaluate("agent:claude", &Verb::Read, "~/docs/readme.md");
        assert_eq!(decision.effect, Effect::Permit);
    }

    #[test]
    fn test_negated_noun() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "forbid"
entity = "agent:*"
verb = "write"
noun = "!~/code/proj/**"
reason = "Can only write in project"
"#,
        );

        // Writing in project → not forbidden (noun negation doesn't match)
        let decision = policy.evaluate("agent:claude", &Verb::Write, "~/code/proj/src/main.rs");
        assert_eq!(decision.effect, Effect::Ask); // default, not matched

        // Writing outside project → forbidden
        let decision = policy.evaluate("agent:claude", &Verb::Write, "/tmp/evil.sh");
        assert_eq!(decision.effect, Effect::Forbid);
    }

    #[test]
    fn test_configurable_default() {
        let policy = compile_doc(
            r#"
[policy]
default = "forbid"
"#,
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "anything");
        assert_eq!(decision.effect, Effect::Forbid);
    }

    #[test]
    fn test_legacy_permissions_integration() {
        let policy = compile_doc(
            r#"
[permissions]
allow = ["Bash(git:*)", "Read"]
deny = ["Read(.env)"]
ask = ["Write"]
"#,
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Permit);

        let decision = policy.evaluate("agent:claude", &Verb::Read, "src/main.rs");
        assert_eq!(decision.effect, Effect::Permit);

        let decision = policy.evaluate("agent:claude", &Verb::Read, ".env");
        assert_eq!(decision.effect, Effect::Forbid);

        let decision = policy.evaluate("agent:claude", &Verb::Write, "output.txt");
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_verb_wildcard() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "forbid"
entity = "agent:untrusted"
verb = "*"
noun = "~/sensitive/**"
"#,
        );

        let decision = policy.evaluate("agent:untrusted", &Verb::Read, "~/sensitive/secrets.json");
        assert_eq!(decision.effect, Effect::Forbid);

        let decision = policy.evaluate("agent:untrusted", &Verb::Write, "~/sensitive/secrets.json");
        assert_eq!(decision.effect, Effect::Forbid);

        let decision = policy.evaluate(
            "agent:untrusted",
            &Verb::Execute,
            "~/sensitive/secrets.json",
        );
        assert_eq!(decision.effect, Effect::Forbid);

        // Different entity → not matched
        let decision = policy.evaluate("agent:claude", &Verb::Read, "~/sensitive/secrets.json");
        assert_eq!(decision.effect, Effect::Ask); // default
    }

    #[test]
    fn test_mixed_legacy_and_statements() {
        let policy = compile_doc(
            r#"
[permissions]
allow = ["Bash(git:*)"]

[[statements]]
effect = "forbid"
entity = "*"
verb = "execute"
noun = "git push *"
reason = "No pushing"
"#,
        );

        // git status → allowed by legacy
        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Permit);

        // git push → forbidden by explicit statement (forbid > permit)
        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git push origin main");
        assert_eq!(decision.effect, Effect::Forbid);
    }

    #[test]
    fn test_entity_type_hierarchy() {
        let policy = compile_doc(
            r#"
[[statements]]
effect = "permit"
entity = "agent:*"
verb = "read"
noun = "*"
"#,
        );

        let decision = policy.evaluate("agent:claude", &Verb::Read, "test.txt");
        assert_eq!(decision.effect, Effect::Permit);

        let decision = policy.evaluate("agent:codex", &Verb::Read, "test.txt");
        assert_eq!(decision.effect, Effect::Permit);

        // "user" is not an agent
        let decision = policy.evaluate("user", &Verb::Read, "test.txt");
        assert_eq!(decision.effect, Effect::Ask); // default
    }
}
