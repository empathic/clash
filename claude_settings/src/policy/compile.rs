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
        // but since we use deny > ask > allow, order within the same effect
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
    /// with precedence: deny > ask > allow > delegate.
    ///
    /// If no statement matches, returns the configured default effect.
    pub fn evaluate(&self, entity: &str, verb: &Verb, noun: &str) -> PolicyDecision {
        let mut has_allow = false;
        let mut has_ask = false;
        let mut has_deny = false;
        let mut has_delegate = false;

        let mut deny_reason: Option<&str> = None;
        let mut ask_reason: Option<&str> = None;
        let mut delegate_config: Option<&DelegateConfig> = None;

        for stmt in &self.statements {
            if stmt.matches(entity, verb, noun) {
                match stmt.effect {
                    Effect::Deny => {
                        has_deny = true;
                        if deny_reason.is_none() {
                            deny_reason = stmt.reason.as_deref();
                        }
                    }
                    Effect::Ask => {
                        has_ask = true;
                        if ask_reason.is_none() {
                            ask_reason = stmt.reason.as_deref();
                        }
                    }
                    Effect::Allow => {
                        has_allow = true;
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

        // Precedence: deny > ask > allow > delegate
        if has_deny {
            return PolicyDecision {
                effect: Effect::Deny,
                reason: deny_reason.map(|s| s.to_string()),
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
        if has_allow {
            return PolicyDecision {
                effect: Effect::Allow,
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

    fn compile_yaml(yaml: &str) -> CompiledPolicy {
        let doc = parse::parse_yaml(yaml).unwrap();
        CompiledPolicy::compile(&doc).unwrap()
    }

    #[test]
    fn test_simple_allow() {
        let policy = compile_yaml("rules:\n  - allow agent:claude bash git *\n");

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:codex", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Ask); // default
    }

    #[test]
    fn test_deny_overrides_allow() {
        let policy = compile_yaml(
            "\
rules:
  - allow * read *
  - deny * read .env
",
        );

        let decision = policy.evaluate("agent:claude", &Verb::Read, "src/main.rs");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:claude", &Verb::Read, ".env");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_ask_overrides_allow() {
        let policy = compile_yaml(
            "\
rules:
  - allow agent:* bash *
  - ask agent:* bash rm *
",
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "ls");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "rm -rf /tmp");
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_negated_entity() {
        let policy = compile_yaml(
            "\
rules:
  - allow * read ~/*
  - deny !user read ~/config/*
",
        );

        // Agent reading config → denied
        let decision = policy.evaluate("agent:claude", &Verb::Read, "~/config/test.json");
        assert_eq!(decision.effect, Effect::Deny);

        // User reading config → allowed (deny doesn't match user)
        let decision = policy.evaluate("user", &Verb::Read, "~/config/test.json");
        assert_eq!(decision.effect, Effect::Allow);

        // Agent reading non-config → allowed
        let decision = policy.evaluate("agent:claude", &Verb::Read, "~/docs/readme.md");
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn test_negated_noun() {
        let policy = compile_yaml("rules:\n  - deny agent:* write !~/code/proj/**\n");

        // Writing in project → not denied (noun negation doesn't match)
        let decision = policy.evaluate("agent:claude", &Verb::Write, "~/code/proj/src/main.rs");
        assert_eq!(decision.effect, Effect::Ask); // default, not matched

        // Writing outside project → denied
        let decision = policy.evaluate("agent:claude", &Verb::Write, "/tmp/evil.sh");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_configurable_default() {
        let policy = compile_yaml("default: deny\n");

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "anything");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_legacy_permissions_integration() {
        let policy = compile_yaml(
            "\
permissions:
  allow:
    - \"Bash(git:*)\"
    - \"Read\"
  deny:
    - \"Read(.env)\"
  ask:
    - \"Write\"
",
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:claude", &Verb::Read, "src/main.rs");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:claude", &Verb::Read, ".env");
        assert_eq!(decision.effect, Effect::Deny);

        let decision = policy.evaluate("agent:claude", &Verb::Write, "output.txt");
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_verb_wildcard() {
        let policy = compile_yaml("rules:\n  - deny agent:untrusted * ~/sensitive/**\n");

        let decision = policy.evaluate("agent:untrusted", &Verb::Read, "~/sensitive/secrets.json");
        assert_eq!(decision.effect, Effect::Deny);

        let decision = policy.evaluate("agent:untrusted", &Verb::Write, "~/sensitive/secrets.json");
        assert_eq!(decision.effect, Effect::Deny);

        let decision = policy.evaluate(
            "agent:untrusted",
            &Verb::Execute,
            "~/sensitive/secrets.json",
        );
        assert_eq!(decision.effect, Effect::Deny);

        // Different entity → not matched
        let decision = policy.evaluate("agent:claude", &Verb::Read, "~/sensitive/secrets.json");
        assert_eq!(decision.effect, Effect::Ask); // default
    }

    #[test]
    fn test_mixed_legacy_and_rules() {
        let policy = compile_yaml(
            "\
permissions:
  allow:
    - \"Bash(git:*)\"
rules:
  - deny * bash git push *
",
        );

        // git status → allowed by legacy
        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);

        // git push → denied by explicit rule (deny > allow)
        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git push origin main");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_entity_type_hierarchy() {
        let policy = compile_yaml("rules:\n  - allow agent:* read *\n");

        let decision = policy.evaluate("agent:claude", &Verb::Read, "test.txt");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:codex", &Verb::Read, "test.txt");
        assert_eq!(decision.effect, Effect::Allow);

        // "user" is not an agent
        let decision = policy.evaluate("user", &Verb::Read, "test.txt");
        assert_eq!(decision.effect, Effect::Ask); // default
    }
}
