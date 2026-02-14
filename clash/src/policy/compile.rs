//! Compilation of policy documents into optimized runtime representations.
//!
//! The `CompiledPolicy` pre-compiles glob patterns into regexes and
//! organizes statements for efficient evaluation.

use std::collections::HashMap;
use std::sync::OnceLock;

use tracing::{Level, instrument};

use super::ast::UrlSpec;
use super::error::CompileError;
use super::ir::{
    CompiledConstraintDef, CompiledFilterExpr, CompiledInlineConstraints, CompiledMatchExpr,
    CompiledPattern, CompiledPolicy, CompiledProfileRule, CompiledSandboxConfig,
};
use super::*;
use regex::Regex;

/// Name of the built-in profile that grants access to `~/.clash/`.
/// Users can override this by defining a profile with the same name.
const BUILTIN_CLASH_PROFILE: &str = "__clash_internal__";

/// Name of the built-in profile that always allows Claude Code meta-tools
/// (e.g. AskUserQuestion, ExitPlanMode). Users can override this by
/// defining a profile with the same name.
const BUILTIN_CLAUDE_PROFILE: &str = "__claude_internal__";

static BUILTIN_CLASH_RULES: OnceLock<Vec<ProfileRule>> = OnceLock::new();
static BUILTIN_CLAUDE_RULES: OnceLock<Vec<ProfileRule>> = OnceLock::new();

impl CompiledPolicy {
    /// Returns true if this policy has any compiled rules.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn has_profile_rules(&self) -> bool {
        !self.active_profile_rules.is_empty()
    }

    /// Compile a `PolicyDocument` into a `CompiledPolicy`.
    ///
    /// This pre-compiles all glob patterns into regexes and
    /// merges legacy permissions into the statement list.
    #[instrument(level = Level::TRACE)]
    pub fn compile(doc: &PolicyDocument) -> Result<Self, CompileError> {
        // Compile constraint definitions
        let mut constraints = HashMap::new();
        for (name, def) in &doc.constraints {
            constraints.insert(name.clone(), CompiledConstraintDef::compile(def)?);
        }

        // Build the unified rule list: desugared Claude permissions first,
        // then explicit `rules:` statements, then new-format profile rules.
        let mut active_profile_rules: Vec<CompiledProfileRule> = Vec::new();
        if let Some(ref perms) = doc.permissions {
            let legacy = parse::desugar_claude_permissions(perms);
            for stmt in &legacy {
                active_profile_rules.push(statement_to_profile_rule(stmt)?);
            }
        }
        for stmt in &doc.statements {
            active_profile_rules.push(statement_to_profile_rule(stmt)?);
        }

        // Compile new-format profile rules if present and append after legacy rules.
        // Also flatten and compile profile-level sandbox config.
        let mut profile_sandbox: Option<CompiledSandboxConfig> = None;
        if let Some(ref default_config) = doc.default_config {
            let flat_rules = parse::flatten_profile(&default_config.profile, &doc.profile_defs)
                .map_err(|e| CompileError::ProfileError(e.to_string()))?;

            // Expand fs-level rules into concrete tool rules.
            let expanded = expand_fs_rules(&flat_rules);
            for rule in &expanded {
                active_profile_rules.push(CompiledProfileRule::compile(rule)?);
            }

            // Flatten and compile profile-level sandbox
            let flat_sandbox = parse::flatten_sandbox(&default_config.profile, &doc.profile_defs)
                .map_err(|e| CompileError::ProfileError(e.to_string()))?;
            if let Some(ref sb) = flat_sandbox {
                profile_sandbox = Some(CompiledSandboxConfig::compile(sb)?);
            }

            // Warn if profile sandbox is present but bash allow rules also have fs:
            if profile_sandbox.is_some() {
                for rule in &expanded {
                    if rule.effect == Effect::Allow
                        && rule.verb == "bash"
                        && rule.constraints.as_ref().is_some_and(|c| c.fs.is_some())
                    {
                        tracing::warn!(
                            "profile '{}' has a sandbox block — `fs:` on bash rule 'allow bash {}' will be ignored for sandbox generation",
                            default_config.profile,
                            crate::policy::ast::format_pattern_str(&rule.noun),
                        );
                    }
                }
            }
        }

        // Inject built-in __clash_internal__ profile rules unless the user
        // has defined their own override in profile_defs.
        if !doc.profile_defs.contains_key(BUILTIN_CLASH_PROFILE) {
            for rule in builtin_clash_rules() {
                active_profile_rules.push(CompiledProfileRule::compile(rule)?);
            }
        }

        // Inject built-in __claude_internal__ profile rules unless the user
        // has defined their own override in profile_defs.
        if !doc.profile_defs.contains_key(BUILTIN_CLAUDE_PROFILE) {
            for rule in builtin_claude_rules() {
                active_profile_rules.push(CompiledProfileRule::compile(rule)?);
            }
        }

        Ok(CompiledPolicy {
            default: doc.policy.default,
            constraints,
            profiles: doc.profiles.clone(),
            active_profile_rules,
            profile_sandbox,
        })
    }
}

/// Expand `__fs__` marker rules into concrete tool rules.
///
/// An fs rule like `(allow (fs read write) (subpath .))` was parsed as a
/// `ProfileRule` with verb `__fs__` and the capabilities stored in constraints.fs.
/// This function expands each such rule into concrete tool rules:
///
/// - `Cap::READ` → `allow read *` with fs constraint
/// - `Cap::WRITE` → `allow edit *` with fs constraint
/// - `Cap::WRITE | Cap::CREATE` → `allow write *` with fs constraint
///
/// Non-fs rules pass through unchanged.
fn expand_fs_rules(rules: &[ProfileRule]) -> Vec<ProfileRule> {
    use crate::policy::parse_sexpr::FS_RULE_VERB;
    use crate::policy::sandbox_types::Cap;

    let mut result = Vec::new();
    for rule in rules {
        if rule.verb != FS_RULE_VERB {
            result.push(rule.clone());
            continue;
        }

        // Extract caps and filter from the fs constraint.
        let (caps, filter) = match rule.constraints.as_ref().and_then(|c| c.fs.as_ref()) {
            Some(entries) if !entries.is_empty() => (entries[0].0, entries[0].1.clone()),
            _ => continue, // malformed fs rule, skip
        };

        // READ → allow read *
        if caps.contains(Cap::READ) {
            result.push(ProfileRule {
                effect: rule.effect,
                verb: "read".to_string(),
                noun: Pattern::Match(MatchExpr::Any),
                constraints: Some(InlineConstraints {
                    fs: Some(vec![(Cap::READ, filter.clone())]),
                    ..Default::default()
                }),
            });
        }

        // WRITE → allow edit *
        if caps.contains(Cap::WRITE) {
            result.push(ProfileRule {
                effect: rule.effect,
                verb: "edit".to_string(),
                noun: Pattern::Match(MatchExpr::Any),
                constraints: Some(InlineConstraints {
                    fs: Some(vec![(Cap::WRITE, filter.clone())]),
                    ..Default::default()
                }),
            });
        }

        // WRITE or CREATE → allow write * (Write tool needs WRITE | CREATE)
        // If the user grants either WRITE or CREATE, the Write tool is allowed.
        if caps.contains(Cap::WRITE) || caps.contains(Cap::CREATE) {
            let write_caps = caps & (Cap::WRITE | Cap::CREATE);
            result.push(ProfileRule {
                effect: rule.effect,
                verb: "write".to_string(),
                noun: Pattern::Match(MatchExpr::Any),
                constraints: Some(InlineConstraints {
                    fs: Some(vec![(write_caps, filter.clone())]),
                    ..Default::default()
                }),
            });
        }
    }
    result
}

/// Lazily parsed built-in rules for the `__clash_internal__` profile.
///
/// See `builtin_clash_profile.sexp` for the rule definitions and rationale.
/// Users can override by defining a profile named `__clash_internal__`
/// in their policy's `profiles:` section.
fn builtin_clash_rules() -> &'static [ProfileRule] {
    BUILTIN_CLASH_RULES.get_or_init(|| {
        super::parse_sexpr::parse_profile_rules(include_str!("../builtin_clash_profile.sexp"))
            .expect("builtin_clash_profile.sexp is invalid")
            .rules
    })
}

/// Lazily parsed built-in rules for the `__claude_internal__` profile.
///
/// See `builtin_claude_profile.sexp` for the rule definitions.
/// Users can override by defining a profile named `__claude_internal__`
/// in their policy's `profiles:` section.
fn builtin_claude_rules() -> &'static [ProfileRule] {
    BUILTIN_CLAUDE_RULES.get_or_init(|| {
        super::parse_sexpr::parse_profile_rules(include_str!("../builtin_claude_profile.sexp"))
            .expect("builtin_claude_profile.sexp is invalid")
            .rules
    })
}

/// Convert a legacy `Statement` into a `CompiledProfileRule`.
///
/// This bridges the legacy format into the unified evaluation path:
/// - `VerbPattern::Any` → `"*"`
/// - `VerbPattern::Exact(v)` → `v.rule_name()`
/// - Entity pattern → `entity_matcher: Some(...)`
/// - Profile expression → `profile_guard` (evaluated at runtime via constraint/profile maps)
/// - No inline constraints (legacy uses profile_guard for all constraint logic)
fn statement_to_profile_rule(stmt: &Statement) -> Result<CompiledProfileRule, CompileError> {
    let verb = match &stmt.verb {
        VerbPattern::Any => "*".to_string(),
        VerbPattern::Exact(v) => v.rule_name().to_string(),
        VerbPattern::Named(s) => s.clone(),
    };

    let entity_matcher = Some(CompiledPattern::compile(&stmt.entity)?);
    let noun_matcher = CompiledPattern::compile(&stmt.noun)?;

    Ok(CompiledProfileRule {
        effect: stmt.effect,
        verb,
        noun_matcher,
        constraints: None,
        entity_matcher,
        reason: stmt.reason.clone(),
        profile_guard: stmt.profile.clone(),
    })
}

impl CompiledProfileRule {
    pub(crate) fn compile(rule: &ProfileRule) -> Result<Self, CompileError> {
        let noun_matcher = CompiledPattern::compile(&rule.noun)?;
        let constraints = match &rule.constraints {
            Some(ic) => Some(CompiledInlineConstraints::compile(ic)?),
            None => None,
        };
        Ok(CompiledProfileRule {
            effect: rule.effect,
            verb: rule.verb.clone(),
            noun_matcher,
            constraints,
            entity_matcher: None,
            reason: None,
            profile_guard: None,
        })
    }
}

impl CompiledInlineConstraints {
    pub(crate) fn compile(ic: &InlineConstraints) -> Result<Self, CompileError> {
        let fs = match &ic.fs {
            Some(entries) => {
                let mut compiled = Vec::new();
                for (caps, filter) in entries {
                    compiled.push((*caps, CompiledFilterExpr::compile(filter)?));
                }
                Some(compiled)
            }
            None => None,
        };

        let mut forbid_args = Vec::new();
        let mut require_args = Vec::new();
        if let Some(ref args) = ic.args {
            for spec in args {
                match spec {
                    ArgSpec::Forbid(s) => forbid_args.push(s.clone()),
                    ArgSpec::Require(s) => require_args.push(s.clone()),
                }
            }
        }

        let mut forbid_urls = Vec::new();
        let mut require_urls = Vec::new();
        if let Some(ref urls) = ic.url {
            for spec in urls {
                match spec {
                    UrlSpec::Forbid(s) => forbid_urls.push(s.clone()),
                    UrlSpec::Require(s) => require_urls.push(s.clone()),
                }
            }
        }

        Ok(CompiledInlineConstraints {
            fs,
            forbid_args,
            require_args,
            forbid_urls,
            require_urls,
            network: ic.network,
            pipe: ic.pipe,
            redirect: ic.redirect,
        })
    }
}

impl CompiledConstraintDef {
    pub(crate) fn compile(def: &ConstraintDef) -> Result<Self, CompileError> {
        let fs = match &def.fs {
            Some(expr) => Some(CompiledFilterExpr::compile(expr)?),
            None => None,
        };
        Ok(CompiledConstraintDef {
            fs,
            caps: def.caps,
            network: def.network,
            pipe: def.pipe,
            redirect: def.redirect,
            forbid_args: def.forbid_args.clone(),
            require_args: def.require_args.clone(),
        })
    }
}

impl CompiledFilterExpr {
    pub(crate) fn compile(expr: &FilterExpr) -> Result<Self, CompileError> {
        match expr {
            FilterExpr::Subpath(s) => Ok(CompiledFilterExpr::Subpath(s.clone())),
            FilterExpr::Literal(s) => Ok(CompiledFilterExpr::Literal(s.clone())),
            FilterExpr::Regex(pattern) => {
                let regex =
                    Regex::new(pattern).map_err(|source| CompileError::InvalidFilterRegex {
                        pattern: pattern.clone(),
                        source,
                    })?;
                Ok(CompiledFilterExpr::Regex(regex))
            }
            FilterExpr::And(a, b) => Ok(CompiledFilterExpr::And(
                Box::new(CompiledFilterExpr::compile(a)?),
                Box::new(CompiledFilterExpr::compile(b)?),
            )),
            FilterExpr::Or(a, b) => Ok(CompiledFilterExpr::Or(
                Box::new(CompiledFilterExpr::compile(a)?),
                Box::new(CompiledFilterExpr::compile(b)?),
            )),
            FilterExpr::Not(inner) => Ok(CompiledFilterExpr::Not(Box::new(
                CompiledFilterExpr::compile(inner)?,
            ))),
        }
    }
}

impl CompiledPattern {
    pub(crate) fn compile(pattern: &Pattern) -> Result<Self, CompileError> {
        match pattern {
            Pattern::Match(expr) => Ok(CompiledPattern::Match(CompiledMatchExpr::compile(expr)?)),
            Pattern::Not(expr) => Ok(CompiledPattern::Not(CompiledMatchExpr::compile(expr)?)),
        }
    }
}

impl CompiledMatchExpr {
    pub(crate) fn compile(expr: &MatchExpr) -> Result<Self, CompileError> {
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
    use crate::policy::sandbox_types::{Cap, NetworkPolicy, RuleEffect};

    fn compile(input: &str) -> CompiledPolicy {
        let doc = parse::parse_policy(input).unwrap();
        CompiledPolicy::compile(&doc).unwrap()
    }

    fn make_ctx<'a>(
        entity: &'a str,
        verb: &'a Verb,
        noun: &'a str,
        cwd: &'a str,
        tool_input: &'a serde_json::Value,
        verb_str: &'a str,
    ) -> EvalContext<'a> {
        EvalContext {
            entity,
            verb,
            noun,
            cwd,
            tool_input,
            verb_str,
        }
    }

    #[test]
    fn test_simple_allow() {
        let policy = compile("(default ask main)\n(profile main\n  (allow bash \"git *\"))\n");

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);

        // In s-expr profiles, rules match all agents implicitly
        let decision = policy.evaluate("agent:codex", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn test_deny_overrides_allow() {
        let policy =
            compile("(default ask main)\n(profile main\n  (allow read *)\n  (deny read .env))\n");

        let decision = policy.evaluate("agent:claude", &Verb::Read, "src/main.rs");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:claude", &Verb::Read, ".env");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_ask_overrides_allow() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *)\n  (ask bash \"rm *\"))\n",
        );

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "ls");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "rm -rf /tmp");
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_negated_noun() {
        let policy =
            compile("(default ask main)\n(profile main\n  (deny write \"!~/code/proj/**\"))\n");

        // Writing in project → not denied (noun negation doesn't match)
        let decision = policy.evaluate("agent:claude", &Verb::Write, "~/code/proj/src/main.rs");
        assert_eq!(decision.effect, Effect::Ask); // default, not matched

        // Writing outside project → denied
        let decision = policy.evaluate("agent:claude", &Verb::Write, "/tmp/evil.sh");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_configurable_default() {
        let policy = compile("(default deny main)\n(profile main)\n");

        let decision = policy.evaluate("agent:claude", &Verb::Execute, "anything");
        assert_eq!(decision.effect, Effect::Deny);
    }

    // --- Constraint tests ---

    #[test]
    fn test_constraint_fs_subpath() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow read *\n    (fs (read (subpath /home/user/project)))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/src/main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Path outside project → constraint fails, rule doesn't match → default
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/etc/passwd",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask); // default
    }

    #[test]
    fn test_constraint_fs_subpath_dot() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow read *\n    (fs (read (subpath .)))))\n",
        );

        // Path under cwd → matches
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/src/main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Path outside cwd → doesn't match
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/etc/passwd",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_constraint_fs_literal() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow read *\n    (fs (read (not (literal .env))))))\n",
        );

        // Non-.env file → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/src/main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // .env file → constraint fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/.env",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_constraint_pipe_false() {
        let policy =
            compile("(default ask main)\n(profile main\n  (allow bash *\n    (pipe deny)))\n");

        // Command without pipe → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Command with pipe → constraint fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "cat foo | grep bar",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_constraint_redirect_false() {
        let policy =
            compile("(default ask main)\n(profile main\n  (allow bash *\n    (redirect deny)))\n");

        // Command without redirect → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Command with redirect → constraint fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "echo hello > file.txt",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_constraint_forbid_args() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash \"git *\"\n    (args (not \"--force\") (not \"--hard\"))))\n",
        );

        // Command without forbidden args → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "git push origin main",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Command with --force → constraint fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "git push --force origin main",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_constraint_require_args() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (args \"--dry-run\")))\n",
        );

        // Command with --dry-run → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "cargo publish --dry-run",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Command without --dry-run → constraint fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "cargo publish",
            cwd: "/home/user",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_profile_composition() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (subpath .)))\n    (pipe deny)\n    (redirect deny)))\n",
        );

        // Both constraints satisfied → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Pipe violated → constraint fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls | grep foo",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_inline_constraint_expression() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow read *\n    (fs (read (and (subpath .) (not (literal .env)))))))\n",
        );

        // Normal file → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/src/main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // .env → no-secrets fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/.env",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_rules_without_constraint_still_work() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash \"git *\")\n  (deny bash \"rm *\"))\n",
        );

        let decision = policy.evaluate("agent", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent", &Verb::Execute, "rm -rf /");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_deny_with_constraint() {
        // deny rule with constraint: only denies when constraint is satisfied
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash \"git *\")\n  (deny bash \"git push *\"\n    (args (not \"--force\"))))\n",
        );

        // git push without --force → has-force constraint fails (no forbidden arg present),
        // so the deny rule doesn't match → falls through to allow
        // Wait - forbid-args means "these must NOT appear". So for has-force constraint,
        // the constraint is satisfied when --force is NOT present.
        // We actually want the deny to fire when --force IS present.
        // The constraint acts as an additional guard: deny only applies when constraint is satisfied.
        // So if forbid-args: [--force] is satisfied (meaning --force is NOT in the command),
        // the deny would fire. That's backwards from what we want.
        //
        // The right way: use a positive "matcher" approach. For now, test the actual behavior:
        // git push --force → forbid_args check fails (arg IS present) → constraint NOT satisfied → deny doesn't match → allow matches
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "git push --force origin main",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        // The deny has constraint has-force which has forbid-args: [--force]
        // --force IS present → forbid-args check fails → constraint not satisfied → deny doesn't match
        // The allow rule has no constraint → matches → allow
        assert_eq!(decision.effect, Effect::Allow);

        // git push without --force → forbid-args check passes → constraint satisfied → deny matches
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "git push origin main",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Deny);
    }

    // --- Helper function tests ---

    #[test]
    fn test_command_has_pipe() {
        use super::super::eval::command_has_pipe;
        assert!(command_has_pipe("cat foo | grep bar"));
        assert!(command_has_pipe("ls | wc -l"));
        assert!(!command_has_pipe("echo 'hello | world'"));
        assert!(!command_has_pipe("echo hello"));
        assert!(!command_has_pipe("grep -E 'a|b' file"));
    }

    #[test]
    fn test_command_has_redirect() {
        use super::super::eval::command_has_redirect;
        assert!(command_has_redirect("echo hello > file.txt"));
        assert!(command_has_redirect("echo hello >> file.txt"));
        assert!(command_has_redirect("cat < input.txt"));
        assert!(!command_has_redirect("echo 'hello > world'"));
        assert!(!command_has_redirect("echo hello"));
    }

    #[test]
    fn test_resolve_path() {
        use super::super::eval::resolve_path;
        use std::path::PathBuf;
        assert_eq!(
            resolve_path("/absolute/path", "/cwd"),
            PathBuf::from("/absolute/path")
        );
        assert_eq!(
            resolve_path(".", "/home/user/project"),
            PathBuf::from("/home/user/project")
        );
        assert_eq!(
            resolve_path("./src/main.rs", "/home/user/project"),
            PathBuf::from("/home/user/project/src/main.rs")
        );
        assert_eq!(
            resolve_path("../other/file", "/home/user/project"),
            PathBuf::from("/home/user/other/file")
        );
        assert_eq!(
            resolve_path("relative.txt", "/home/user"),
            PathBuf::from("/home/user/relative.txt")
        );

        // Tilde expansion
        let home = dirs::home_dir().unwrap();
        assert_eq!(resolve_path("~", "/cwd"), home);
        assert_eq!(resolve_path("~/.clash", "/cwd"), home.join(".clash"));
        assert_eq!(
            resolve_path("~/.clash/policy.sexp", "/cwd"),
            home.join(".clash/policy.sexp")
        );
    }

    #[test]
    fn test_fs_filter_with_compound_expr() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow read *\n    (fs (read (or (subpath /home/user/project/src) (subpath /home/user/project/test))))))\n",
        );

        // In src → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/src/main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // In test → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/test/test_main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Outside both → fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/etc/passwd",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    // --- Sandbox generation tests ---

    #[test]
    fn test_sandbox_generated_from_fs_subpath() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (full (subpath .)))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Should have a sandbox policy generated from the fs constraint
        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.default, Cap::READ | Cap::EXECUTE);
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].effect, RuleEffect::Allow);
        assert_eq!(sandbox.rules[0].caps, Cap::all()); // no caps constraint → all
        assert_eq!(sandbox.rules[0].path, "/home/user/project");
        assert_eq!(
            sandbox.rules[0].path_match,
            crate::policy::sandbox_types::PathMatch::Subpath
        );
    }

    #[test]
    fn test_sandbox_caps_intersection() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (\"read + execute\" (subpath .)))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.rules.len(), 1);
        // caps should be intersected: read + execute
        assert_eq!(sandbox.rules[0].caps, Cap::READ | Cap::EXECUTE);
    }

    #[test]
    fn test_sandbox_network_deny_wins() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (subpath .)))\n    (network deny)))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.network, NetworkPolicy::Deny);
    }

    #[test]
    fn test_no_sandbox_for_non_bash() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow read *\n    (fs (read (subpath .)))))\n",
        );

        // Read verb: fs acts as permission guard, no sandbox generated
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Read,
            noun: "/home/user/project/src/main.rs",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "read",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        assert!(decision.sandbox.is_none());
    }

    #[test]
    fn test_no_sandbox_without_fs() {
        let policy =
            compile("(default ask main)\n(profile main\n  (allow bash *\n    (pipe deny)))\n");

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        // No fs in any constraint → no sandbox
        assert!(decision.sandbox.is_none());
    }

    #[test]
    fn test_sandbox_not_filter_generates_deny() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (not (subpath .git))))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        let sandbox = decision.sandbox.expect("expected sandbox policy");
        // Not(Subpath(.git)) → Deny rule for .git
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].effect, RuleEffect::Deny);
        assert_eq!(sandbox.rules[0].path, "/home/user/project/.git");
        assert_eq!(
            sandbox.rules[0].path_match,
            crate::policy::sandbox_types::PathMatch::Subpath
        );
    }

    #[test]
    fn test_sandbox_regex_generates_rule() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (regex \"\\\\.env\")))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Regex fs generates a sandbox rule with PathMatch::Regex
        // (enforced on macOS via Seatbelt SBPL, skipped on Linux)
        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(
            sandbox.rules[0].path_match,
            crate::policy::sandbox_types::PathMatch::Regex
        );
        assert_eq!(sandbox.rules[0].path, "\\.env");
    }

    #[test]
    fn test_fs_on_bash_no_longer_gates_matching() {
        // fs: subpath(.) used to check the command string as a path (broken).
        // Now fs is skipped for bash rules — the rule always matches
        // regardless of the command string, and fs generates sandbox instead.
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (subpath /home/user/project)))))\n",
        );

        // Command "ls -la" doesn't look like a path under /home/user/project,
        // but the rule should still match because fs is skipped for bash.
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        assert!(decision.sandbox.is_some());
    }

    #[test]
    fn test_sandbox_literal_non_recursive() {
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (literal .env)))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "cat .env",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].path, "/home/user/project/.env");
        assert_eq!(
            sandbox.rules[0].path_match,
            crate::policy::sandbox_types::PathMatch::Literal
        );
    }

    #[test]
    fn test_sandbox_no_sandbox_when_allow_has_no_profile() {
        let policy = compile("(default ask main)\n(profile main\n  (allow bash *))\n");

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls -la",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        // No profile → no sandbox
        assert!(decision.sandbox.is_none());
    }

    #[test]
    fn test_sandbox_network_default_allow() {
        // When no network policy is specified, default is allow
        let policy = compile(
            "(default ask main)\n(profile main\n  (allow bash *\n    (fs (execute (subpath .)))))\n",
        );

        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "ls",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
    }

    // -----------------------------------------------------------------------
    // New-format evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_format_deny_overrides_allow() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow bash *)\n  (deny bash \"rm *\"))\n",
        );

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "git status",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "rm -rf /",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);
    }

    #[test]
    fn test_new_format_cap_scoped_fs_permission_guard() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow read *\n    (fs (read (subpath /home/user/project)))))\n",
        );

        // File under project → allowed (read cap intersects fs entry)
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            "/home/user/project/src/main.rs",
            "/home/user/project",
            &serde_json::Value::Null,
            "read",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // File outside project → fs guard fails → default
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            "/etc/passwd",
            "/home/user/project",
            &serde_json::Value::Null,
            "read",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_new_format_cap_scoped_fs_sandbox() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow bash *\n    (fs (\"read + write + create\" (subpath .)))\n    (network deny)))\n",
        );

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "ls -la",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        let sandbox = decision.sandbox.expect("expected sandbox");
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].caps, Cap::READ | Cap::WRITE | Cap::CREATE);
        assert_eq!(sandbox.rules[0].path, "/home/user/project");
        assert_eq!(sandbox.network, NetworkPolicy::Deny);
    }

    #[test]
    fn test_new_format_args_forbid() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow bash *\n    (args (not \"-delete\"))))\n",
        );

        // Command without -delete → allowed
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "git push origin main",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // Command with -delete → forbidden arg → constraint fails → default
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "find . -delete",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_new_format_arbitrary_verb() {
        let policy = compile("(default deny test)\n(profile test\n  (allow safe-read *))\n");

        // Matching verb_str
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "anything",
            "",
            &serde_json::Value::Null,
            "safe-read",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // Non-matching verb_str
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "anything",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);
    }

    #[test]
    fn test_new_format_include_rules_merged() {
        let policy = compile(
            "(default ask child)\n(profile parent\n  (deny bash \"rm *\"))\n(profile child\n  (include parent)\n  (allow bash *))\n",
        );

        // "git status" matches child's allow bash * → allowed
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "git status",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // "rm -rf /" matches parent's deny AND child's allow → deny wins
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "rm -rf /",
            "",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);
    }

    #[test]
    fn test_new_format_no_match_returns_default() {
        let policy = compile("(default deny test)\n(profile test\n  (allow bash *))\n");

        // "read" verb_str doesn't match "bash" rule → no match → default (deny)
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            "test.txt",
            "",
            &serde_json::Value::Null,
            "read",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);
    }

    #[test]
    fn test_new_format_wildcard_verb() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (deny * *\n    (fs (\"read + write\" (subpath ~/.ssh))))\n  (allow bash *))\n",
        );

        // bash command → matches both deny * * and allow bash *
        // But the deny has an fs guard which is cap-scoped — for bash/execute,
        // fs generates sandbox not permission guard, so deny matches unconditionally
        // if the noun matches. Since noun is "*", and "ls" matches, deny applies.
        // Actually: the deny rule has verb "*" which matches "bash",
        // and noun "*" which matches "ls". The fs constraint is on the deny rule.
        // For bash, fs is NOT a permission guard — it generates sandbox.
        // So the deny matches. deny > allow → Deny.
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "ls",
            "/home/user",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);
    }

    // ---- Property-based tests (proptest) ----

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Strategy for generating a random verb.
        fn arb_verb() -> impl Strategy<Value = (&'static str, Verb)> {
            prop_oneof![
                Just(("bash", Verb::Execute)),
                Just(("read", Verb::Read)),
                Just(("write", Verb::Write)),
                Just(("edit", Verb::Edit)),
            ]
        }

        /// Strategy for generating noun/pattern strings.
        /// Nouns with spaces must be quoted in s-expr.
        fn arb_noun() -> impl Strategy<Value = (String, String)> {
            prop_oneof![
                Just(("*".to_string(), "*".to_string())),
                Just(("\"git *\"".to_string(), "git status".to_string())),
                Just(("\"rm *\"".to_string(), "rm -rf".to_string())),
                Just(("ls".to_string(), "ls".to_string())),
                Just(("\"/tmp/*\"".to_string(), "/tmp/foo".to_string())),
                Just(("src/main.rs".to_string(), "src/main.rs".to_string())),
                Just((".env".to_string(), ".env".to_string())),
            ]
        }

        /// Strategy for generating an effect.
        fn arb_effect() -> impl Strategy<Value = &'static str> {
            prop_oneof![Just("allow"), Just("deny"), Just("ask"),]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            /// Deny always beats allow regardless of rule order.
            #[test]
            fn deny_overrides_allow(
                (verb_str, verb) in arb_verb(),
                (noun_pattern, noun_eval) in arb_noun(),
            ) {
                // Policy with allow first, then deny on the same triple
                let sexpr = format!(
                    "(default ask main)\n(profile main\n  (allow {} {})\n  (deny {} {}))\n",
                    verb_str, noun_pattern, verb_str, noun_pattern
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate("agent:claude", &verb, &noun_eval);
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "deny should override allow for {} {}", verb_str, noun_eval);
                    }
                }

                // Reverse order: deny first, then allow
                let sexpr = format!(
                    "(default ask main)\n(profile main\n  (deny {} {})\n  (allow {} {}))\n",
                    verb_str, noun_pattern, verb_str, noun_pattern
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate("agent:claude", &verb, &noun_eval);
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "deny should override allow (reversed) for {} {}", verb_str, noun_eval);
                    }
                }
            }

            /// Ask overrides allow regardless of rule order.
            #[test]
            fn ask_overrides_allow(
                (verb_str, verb) in arb_verb(),
                (noun_pattern, noun_eval) in arb_noun(),
            ) {
                let sexpr = format!(
                    "(default ask main)\n(profile main\n  (allow {} {})\n  (ask {} {}))\n",
                    verb_str, noun_pattern, verb_str, noun_pattern
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate("agent:claude", &verb, &noun_eval);
                        prop_assert_eq!(decision.effect, Effect::Ask,
                            "ask should override allow for {} {}", verb_str, noun_eval);
                    }
                }
            }

            /// Deny overrides ask regardless of rule order.
            #[test]
            fn deny_overrides_ask(
                (verb_str, verb) in arb_verb(),
                (noun_pattern, noun_eval) in arb_noun(),
            ) {
                let sexpr = format!(
                    "(default ask main)\n(profile main\n  (ask {} {})\n  (deny {} {}))\n",
                    verb_str, noun_pattern, verb_str, noun_pattern
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate("agent:claude", &verb, &noun_eval);
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "deny should override ask for {} {}", verb_str, noun_eval);
                    }
                }
            }

            /// Determinism: same policy + same input → same output.
            #[test]
            fn deterministic_evaluation(
                (verb_str, verb) in arb_verb(),
                (noun_pattern, noun_eval) in arb_noun(),
                effect1 in arb_effect(),
                effect2 in arb_effect(),
            ) {
                let sexpr = format!(
                    "(default ask main)\n(profile main\n  ({} {} {})\n  ({} {} {}))\n",
                    effect1, verb_str, noun_pattern,
                    effect2, verb_str, noun_pattern,
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let d1 = policy.evaluate("agent:claude", &verb, &noun_eval);
                        let d2 = policy.evaluate("agent:claude", &verb, &noun_eval);
                        prop_assert_eq!(d1.effect, d2.effect,
                            "same policy + input should give same result");
                    }
                }
            }

            /// Monotonicity: adding a deny rule never produces a less-restrictive result.
            #[test]
            fn monotonicity_deny_addition(
                (verb_str, verb) in arb_verb(),
                (noun_pattern, noun_eval) in arb_noun(),
                base_effect in arb_effect(),
            ) {
                // Evaluate with just the base rule
                let sexpr_base = format!(
                    "(default ask main)\n(profile main\n  ({} {} {}))\n",
                    base_effect, verb_str, noun_pattern,
                );
                // Evaluate with base + deny
                let sexpr_deny = format!(
                    "(default ask main)\n(profile main\n  ({} {} {})\n  (deny {} {}))\n",
                    base_effect, verb_str, noun_pattern,
                    verb_str, noun_pattern,
                );

                if let (Ok(doc_base), Ok(doc_deny)) =
                    (parse::parse_policy(&sexpr_base), parse::parse_policy(&sexpr_deny))
                {
                    if let (Ok(p_base), Ok(p_deny)) =
                        (CompiledPolicy::compile(&doc_base), CompiledPolicy::compile(&doc_deny))
                    {
                        let d_base = p_base.evaluate("agent:claude", &verb, &noun_eval);
                        let d_deny = p_deny.evaluate("agent:claude", &verb, &noun_eval);

                        // Restrictiveness: Deny > Ask > Allow
                        let restrictiveness = |e: Effect| -> u8 {
                            match e {
                                Effect::Deny => 3,
                                Effect::Ask => 2,
                                Effect::Allow => 1,
                            }
                        };

                        prop_assert!(
                            restrictiveness(d_deny.effect) >= restrictiveness(d_base.effect),
                            "adding deny rule should not make result less restrictive: base={:?}, with_deny={:?}",
                            d_base.effect, d_deny.effect,
                        );
                    }
                }
            }

            /// Default fallback: when no rules match, the configured default applies.
            #[test]
            fn default_fallback(
                (verb_str, verb) in arb_verb(),
            ) {
                // Policy with rules that only match a specific noun, default: deny
                let sexpr = format!(
                    "(default deny main)\n(profile main\n  (allow {} specific_file))\n",
                    verb_str,
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        // Query with non-matching noun
                        let decision = policy.evaluate("agent:other", &verb, "other_file");
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "no match should fall back to configured default (deny)");
                    }
                }

                // Same test with default: ask (the default default)
                let sexpr = format!(
                    "(default ask main)\n(profile main\n  (allow {} specific_file))\n",
                    verb_str,
                );
                if let Ok(doc) = parse::parse_policy(&sexpr) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate("agent:other", &verb, "other_file");
                        prop_assert_eq!(decision.effect, Effect::Ask,
                            "no match should fall back to default (ask)");
                    }
                }
            }
        }

        /// Negation symmetry on nouns.
        #[test]
        fn noun_negation_symmetry() {
            let policy = compile(
                "(default ask main)\n(profile main\n  (allow bash *)\n  (deny bash \"!git *\"))\n",
            );

            // git status should be allowed (deny !git* doesn't match git commands)
            let decision = policy.evaluate("agent:claude", &Verb::Execute, "git status");
            assert_eq!(decision.effect, Effect::Allow);

            // rm -rf should be denied (deny !git* matches rm)
            let decision = policy.evaluate("agent:claude", &Verb::Execute, "rm -rf /");
            assert_eq!(decision.effect, Effect::Deny);
        }

        // ---- Metamorphic tests ----
        //
        // These verify that adding an unreachable rule doesn't change the outcome.

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            /// Adding a rule for a non-matching noun doesn't change the result.
            #[test]
            fn unreachable_noun_rule_is_inert(
                (verb_str, verb) in arb_verb(),
                effect in arb_effect(),
                extra_effect in arb_effect(),
            ) {
                // Base: rule for "git *"
                let sexpr_base = format!(
                    "(default ask main)\n(profile main\n  ({} {} \"git *\"))\n",
                    effect, verb_str,
                );
                // Extended: same + rule for "npm *" (never queried with npm)
                let sexpr_ext = format!(
                    "(default ask main)\n(profile main\n  ({} {} \"git *\")\n  ({} {} \"npm *\"))\n",
                    effect, verb_str,
                    extra_effect, verb_str,
                );

                if let (Ok(doc_base), Ok(doc_ext)) =
                    (parse::parse_policy(&sexpr_base), parse::parse_policy(&sexpr_ext))
                {
                    if let (Ok(p_base), Ok(p_ext)) =
                        (CompiledPolicy::compile(&doc_base), CompiledPolicy::compile(&doc_ext))
                    {
                        let d_base = p_base.evaluate("agent:claude", &verb, "git status");
                        let d_ext = p_ext.evaluate("agent:claude", &verb, "git status");
                        prop_assert_eq!(d_base.effect, d_ext.effect,
                            "unreachable noun rule should not change result");
                    }
                }
            }

            /// Adding a rule for a non-matching verb doesn't change the result.
            #[test]
            fn unreachable_verb_rule_is_inert(
                effect in arb_effect(),
                extra_effect in arb_effect(),
                (noun_pattern, noun_eval) in arb_noun(),
            ) {
                // Base: rule for bash
                let sexpr_base = format!(
                    "(default ask main)\n(profile main\n  ({} bash {}))\n",
                    effect, noun_pattern,
                );
                // Extended: same + rule for read (never queried with read)
                let sexpr_ext = format!(
                    "(default ask main)\n(profile main\n  ({} bash {})\n  ({} read some_other_file))\n",
                    effect, noun_pattern,
                    extra_effect,
                );

                if let (Ok(doc_base), Ok(doc_ext)) =
                    (parse::parse_policy(&sexpr_base), parse::parse_policy(&sexpr_ext))
                {
                    if let (Ok(p_base), Ok(p_ext)) =
                        (CompiledPolicy::compile(&doc_base), CompiledPolicy::compile(&doc_ext))
                    {
                        let d_base = p_base.evaluate("agent:claude", &Verb::Execute, &noun_eval);
                        let d_ext = p_ext.evaluate("agent:claude", &Verb::Execute, &noun_eval);
                        prop_assert_eq!(d_base.effect, d_ext.effect,
                            "unreachable verb rule should not change result");
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Built-in __clash_internal__ profile tests
    // -----------------------------------------------------------------------

    /// Helper: path under ~/.clash/ using the actual home directory.
    fn clash_path(relative: &str) -> String {
        let home = dirs::home_dir().unwrap();
        format!("{}/{}", home.to_string_lossy(), relative)
    }

    #[test]
    fn test_builtin_allows_read_clash_dir() {
        // Minimal policy with no user-defined __clash_internal__
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // Read ~/.clash/policy.sexp → allowed by built-in profile
        let noun = clash_path(".clash/policy.sexp");
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            &noun,
            "/home/user/project",
            &serde_json::Value::Null,
            "read",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "built-in __clash_internal__ should allow reading ~/.clash/"
        );
    }

    #[test]
    fn test_builtin_does_not_allow_write_clash_dir() {
        // Built-in only allows Read, not Write/Edit
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // Write to ~/.clash/policy.sexp → NOT allowed (no built-in write rule)
        let noun = clash_path(".clash/policy.sexp");
        let ctx = make_ctx(
            "agent",
            &Verb::Write,
            &noun,
            "/home/user/project",
            &serde_json::Value::Null,
            "write",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "built-in should not allow Write tool to ~/.clash/ (only Read)"
        );
    }

    #[test]
    fn test_builtin_clash_init_asks() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // `clash init` via full path → ask (mutation requires consent)
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/tmp/clash-dev/clash-plugin/bin/clash init",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "clash init should ask (mutation requires consent)"
        );
    }

    #[test]
    fn test_builtin_clash_init_force_asks() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // `clash init --force` also matches → ask (mutation)
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash init --force",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "clash init --force should ask (mutation requires consent)"
        );
    }

    #[test]
    fn test_builtin_clash_migrate_asks() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // `clash migrate` via full path → ask (mutation requires consent)
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/tmp/clash-dev/clash-plugin/bin/clash migrate",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "clash migrate should ask (mutation requires consent)"
        );
    }

    #[test]
    fn test_builtin_non_clash_bash_no_clash_sandbox() {
        // Non-clash bash commands should NOT get ~/.clash/ in their sandbox
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "ls -la",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        // No allow rules match "ls -la" → default ask
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "non-clash bash commands should not be allowed by built-in"
        );
    }

    #[test]
    fn test_builtin_does_not_allow_outside_clash_dir() {
        // Policy with only deny rules — nothing else allowed
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // Read /etc/passwd → not covered by built-in, falls to default (ask)
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            "/etc/passwd",
            "/home/user/project",
            &serde_json::Value::Null,
            "read",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "built-in should not allow access outside ~/.clash/"
        );
    }

    #[test]
    fn test_user_can_override_builtin_profile() {
        // User defines __clash_internal__ in their profile_defs — built-in should NOT be injected
        let policy = compile(
            "(default ask main)\n(profile __clash_internal__\n  (deny read *\n    (fs (read (subpath ~/.clash)))))\n(profile main\n  (include __clash_internal__)\n  (allow bash \"git *\"))\n",
        );

        // Read from ~/.clash/ → denied by user's override
        let noun = clash_path(".clash/policy.sexp");
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            &noun,
            "/home/user/project",
            &serde_json::Value::Null,
            "read",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Deny,
            "user-defined __clash_internal__ should override built-in"
        );
    }

    #[test]
    fn test_default_policy_includes_builtin() {
        // The default policy template should work with the built-in profile
        let policy = compile(crate::settings::DEFAULT_POLICY);

        // Read ~/.clash/policy.sexp from a project dir → allowed
        let noun = clash_path(".clash/policy.sexp");
        let ctx = make_ctx(
            "agent",
            &Verb::Read,
            &noun,
            "/home/user/project",
            &serde_json::Value::Null,
            "read",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "default policy + built-in should allow reading ~/.clash/"
        );
    }

    #[test]
    fn test_default_policy_clash_init_asks() {
        let policy = compile(crate::settings::DEFAULT_POLICY);

        // clash init via full path → ask (built-in __clash_internal__ profile
        // matches clash commands; mutations like init require consent)
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/tmp/clash-dev/clash-plugin/bin/clash init",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "default policy: clash init should ask via __clash_internal__ built-in"
        );
    }

    // -----------------------------------------------------------------------
    // Sandbox-first fs rule expansion
    // -----------------------------------------------------------------------

    #[test]
    fn test_fs_rule_expansion() {
        let input = r#"
(default deny main)
(profile main
  (allow (fs read write) (subpath .)))
"#;
        let policy = compile(input);
        let cwd = "/home/user/project";

        // Read tool should be allowed within cwd
        let ti = serde_json::json!({"file_path": "./src/main.rs"});
        let ctx = make_ctx("agent", &Verb::Read, "./src/main.rs", cwd, &ti, "read");
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "fs read should allow Read tool"
        );

        // Edit tool should be allowed within cwd
        let ti = serde_json::json!({"file_path": "./src/main.rs"});
        let ctx = make_ctx("agent", &Verb::Edit, "./src/main.rs", cwd, &ti, "edit");
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "fs write should allow Edit tool"
        );

        // Write tool should be allowed (write + create)
        let ti = serde_json::json!({"file_path": "./src/new_file.rs"});
        let ctx = make_ctx(
            "agent",
            &Verb::Write,
            "./src/new_file.rs",
            cwd,
            &ti,
            "write",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "fs write should allow Write tool"
        );

        // Bash should NOT be allowed (no explicit bash rule)
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "ls",
            cwd,
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Deny, "no bash rule means deny");
    }

    #[test]
    fn test_fs_read_only_expansion() {
        let input = r#"
(default deny main)
(profile main
  (allow (fs read) (subpath .)))
"#;
        let policy = compile(input);
        let cwd = "/home/user/project";

        // Read should be allowed
        let ti = serde_json::json!({"file_path": "./file.txt"});
        let ctx = make_ctx("agent", &Verb::Read, "./file.txt", cwd, &ti, "read");
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Edit should NOT be allowed (read-only)
        let ti = serde_json::json!({"file_path": "./file.txt"});
        let ctx = make_ctx("agent", &Verb::Edit, "./file.txt", cwd, &ti, "edit");
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Deny);
    }

    // -----------------------------------------------------------------------
    // Read-only clash commands: allow without prompting
    // -----------------------------------------------------------------------

    #[test]
    fn test_builtin_clash_policy_show_allowed() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash policy show",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "clash policy show should be allowed (read-only)"
        );
    }

    #[test]
    fn test_builtin_clash_policy_schema_allowed() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash policy schema --json",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "clash policy schema should be allowed (read-only)"
        );
    }

    #[test]
    fn test_builtin_clash_policy_add_rule_dry_run_allowed() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // --dry-run preview → constrained-allow beats unconstrained-ask
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash policy add-rule --dry-run \"allow bash git *\"",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "clash policy add-rule --dry-run should be allowed (preview only)"
        );
    }

    #[test]
    fn test_builtin_clash_policy_remove_rule_dry_run_allowed() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash policy remove-rule --dry-run \"deny bash rm *\"",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "clash policy remove-rule --dry-run should be allowed (preview only)"
        );
    }

    // -----------------------------------------------------------------------
    // Mutation clash commands: require human consent (ask)
    // -----------------------------------------------------------------------

    #[test]
    fn test_builtin_clash_policy_add_rule_asks() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        // Without --dry-run → actual mutation → ask
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash policy add-rule \"allow bash git *\"",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "clash policy add-rule should ask (mutation requires consent)"
        );
    }

    #[test]
    fn test_builtin_clash_policy_remove_rule_asks() {
        let policy = compile("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash policy remove-rule \"deny bash rm *\"",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "clash policy remove-rule should ask (mutation requires consent)"
        );
    }

    // -----------------------------------------------------------------------
    // Built-in __claude_internal__ profile tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_builtin_asks_askuserquestion() {
        let policy = compile("(default deny main)\n(profile main)\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "",
            "/home/user/project",
            &serde_json::Value::Null,
            "askuserquestion",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "built-in __claude_internal__ should ask for AskUserQuestion"
        );
    }

    #[test]
    fn test_builtin_allows_exitplanmode() {
        let policy = compile("(default ask main)\n(profile main)\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "",
            "/home/user/project",
            &serde_json::Value::Null,
            "exitplanmode",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "built-in __claude_internal__ should allow ExitPlanMode"
        );
    }

    #[test]
    fn test_builtin_applies_correct_effect_to_all_claude_meta_tools() {
        // Use deny as default so we can distinguish allow vs ask vs default
        let policy = compile("(default deny main)\n(profile main)\n");

        for rule in super::builtin_claude_rules() {
            let ctx = make_ctx(
                "agent",
                &Verb::Execute,
                "",
                "/home/user/project",
                &serde_json::Value::Null,
                &rule.verb,
            );
            let decision = policy.evaluate_with_context(&ctx);
            assert_eq!(
                decision.effect, rule.effect,
                "built-in __claude_internal__ should {:?} for {}",
                rule.effect, rule.verb
            );
        }
    }

    #[test]
    fn test_builtin_does_not_allow_bash_via_claude_internal() {
        // Bash should NOT be allowed by __claude_internal__
        let policy = compile("(default ask main)\n(profile main)\n");

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "ls -la",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Ask,
            "bash should not be allowed by __claude_internal__"
        );
    }

    #[test]
    fn test_user_can_override_claude_internal_profile() {
        // User defines __claude_internal__ in their profile_defs
        let policy = compile(
            "(default ask main)\n(profile __claude_internal__\n  (deny askuserquestion *))\n(profile main\n  (include __claude_internal__))\n",
        );

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "",
            "/home/user/project",
            &serde_json::Value::Null,
            "askuserquestion",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(
            decision.effect,
            Effect::Deny,
            "user-defined __claude_internal__ should override built-in"
        );
    }

    #[test]
    fn test_new_format_url_require() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow webfetch *\n    (url \"github.com\")))\n",
        );

        // URL matching required domain → allowed
        let input = serde_json::json!({"url": "https://github.com/foo/bar"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/foo/bar",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // URL not matching required domain → constraint fails → default (ask)
        let input = serde_json::json!({"url": "https://evil.com/malware"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://evil.com/malware",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_new_format_url_forbid() {
        let policy = compile(
            "(default allow test)\n(profile test\n  (deny webfetch *\n    (url \"evil.com\")))\n",
        );

        // URL matching forbidden domain → denied
        let input = serde_json::json!({"url": "https://evil.com/malware"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://evil.com/malware",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);

        // URL not matching forbidden domain → falls through to default (allow)
        let input = serde_json::json!({"url": "https://github.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);
    }

    #[test]
    fn test_new_format_url_wildcard_subdomain() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow webfetch *\n    (url \"*.github.com\")))\n",
        );

        // Subdomain matches → allowed
        let input = serde_json::json!({"url": "https://api.github.com/repos"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://api.github.com/repos",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // Non-matching domain → default (ask)
        let input = serde_json::json!({"url": "https://example.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://example.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_new_format_url_full_glob() {
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow webfetch *\n    (url \"https://github.com/*\")))\n",
        );

        // Full URL glob matches → allowed
        let input = serde_json::json!({"url": "https://github.com/anthropics/claude"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/anthropics/claude",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // Non-matching URL → default (ask)
        let input = serde_json::json!({"url": "https://evil.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://evil.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_url_noun_pattern_after_bug_fix() {
        // After fixing the URL-as-entity parsing bug, URL noun patterns should work
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow webfetch \"https://github.com/*\"))\n",
        );

        let input = serde_json::json!({"url": "https://github.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // Non-matching URL → default (ask)
        let input = serde_json::json!({"url": "https://evil.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://evil.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    // ── Constraint specificity tests ──────────────────────────────────

    #[test]
    fn test_constrained_allow_beats_unconstrained_ask() {
        // A URL-constrained allow should beat an unconstrained ask
        // when the URL matches the constraint.
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow webfetch *\n    (url \"github.com\"))\n  (ask webfetch *))\n",
        );

        // URL matches constraint → constrained allow wins over unconstrained ask
        let input = serde_json::json!({"url": "https://github.com/anthropics/claude"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/anthropics/claude",
            "",
            &input,
            "webfetch",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        assert!(
            decision.trace.final_resolution.contains("constrained"),
            "resolution should mention specificity: {}",
            decision.trace.final_resolution
        );

        // URL does not match constraint → unconstrained ask applies
        let input = serde_json::json!({"url": "https://example.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://example.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_constrained_ask_beats_constrained_allow() {
        // When both ask and allow have constraints, ask wins (same tier).
        let policy = compile(
            "(default allow test)\n(profile test\n  (allow webfetch *\n    (url \"github.com\"))\n  (ask webfetch *\n    (url \"github.com\")))\n",
        );

        let input = serde_json::json!({"url": "https://github.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_deny_beats_constrained_allow() {
        // Deny always wins, even over constrained allow.
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow webfetch *\n    (url \"github.com\"))\n  (deny webfetch *))\n",
        );

        let input = serde_json::json!({"url": "https://github.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/foo",
            "",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Deny);
    }

    #[test]
    fn test_fs_only_constraints_not_active_for_webfetch() {
        // An allow * * rule with only fs constraints should NOT count as
        // "constrained" for webfetch, since fs guards are irrelevant for
        // non-read/write/edit verbs.
        let policy = compile(
            "(default deny test)\n(profile base\n  (allow * *\n    (fs (\"read + write + execute + create + delete\" (subpath /home/user/project)))))\n(profile test\n  (include base)\n  (ask webfetch *))\n",
        );

        // The ask webfetch * is unconstrained. The allow * * has fs constraints
        // but those are not "active" for webfetch. Both are Tier 0.
        // Within Tier 0: ask > allow.
        let input = serde_json::json!({"url": "https://example.com"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://example.com",
            "/home/user/project",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_constrained_allow_with_fs_broad_allow_and_ask() {
        // Real-world scenario: fs-constrained broad allows + URL-constrained
        // webfetch allow + unconstrained webfetch ask.
        let policy = compile(
            "(default ask test)\n(profile cwd\n  (allow * *\n    (fs (\"read + write + execute + create + delete\" (subpath /home/user/project)))))\n(profile test\n  (include cwd)\n  (allow webfetch *\n    (url \"github.com\"))\n  (ask webfetch *))\n",
        );

        // github.com → constrained allow (Tier 1) beats unconstrained ask (Tier 0)
        let input = serde_json::json!({"url": "https://github.com/foo"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://github.com/foo",
            "/home/user/project",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // example.com → constrained allow skipped, Tier 0: ask > allow
        let input = serde_json::json!({"url": "https://example.com"});
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "https://example.com",
            "/home/user/project",
            &input,
            "webfetch",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    #[test]
    fn test_constrained_args_allow_beats_unconstrained_ask() {
        // Args-constrained allow should beat unconstrained ask for bash.
        let policy = compile(
            "(default ask test)\n(profile test\n  (allow bash \"git *\"\n    (args \"--dry-run\"))\n  (ask bash *))\n",
        );

        // git diff --dry-run → constrained allow (has require-args) beats unconstrained ask
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "git diff --dry-run",
            "/home/user",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Allow);

        // git push (no --dry-run) → constrained allow skipped, unconstrained ask
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "git push",
            "/home/user",
            &serde_json::Value::Null,
            "bash",
        );
        assert_eq!(policy.evaluate_with_context(&ctx).effect, Effect::Ask);
    }

    // --- Profile-level sandbox tests ---

    #[test]
    fn test_profile_sandbox_generates_sandbox_policy() {
        let policy = compile(
            "(default deny main)\n(profile main\n  (sandbox\n    (fs read execute (subpath .))\n    (fs write create (subpath ./target))\n    (network allow))\n  (allow bash \"cargo *\")\n  (allow bash \"git status\")\n  (deny bash \"git push*\"))\n",
        );

        // Allowed bash command gets a sandbox
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "cargo build",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision
            .sandbox
            .expect("profile sandbox should produce SandboxPolicy");
        assert!(!sandbox.rules.is_empty(), "sandbox should have rules");
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
    }

    #[test]
    fn test_profile_sandbox_deny_rules_unaffected() {
        let policy = compile(
            "(default deny main)\n(profile main\n  (sandbox\n    (fs read execute (subpath .))\n    (network allow))\n  (allow bash \"git *\")\n  (deny bash \"git push*\"))\n",
        );

        // Denied command stays denied
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "git push origin main",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Deny);
        assert!(decision.sandbox.is_none());
    }

    #[test]
    fn test_profile_sandbox_backward_compat_no_sandbox_block() {
        // When no sandbox: block exists, per-rule fs: still generates sandbox
        let policy = compile(
            "(default deny main)\n(profile main\n  (allow bash \"cargo *\"\n    (fs (\"read + execute\" (subpath .)) (\"write + create\" (subpath ./target)))\n    (network allow)))\n",
        );

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "cargo build",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision
            .sandbox
            .expect("per-rule fs should still generate sandbox");
        assert!(!sandbox.rules.is_empty());
    }

    #[test]
    fn test_profile_sandbox_network_deny() {
        let policy = compile(
            "(default deny main)\n(profile main\n  (sandbox\n    (fs read execute (subpath .))\n    (network deny))\n  (allow bash *))\n",
        );

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "curl example.com",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision.sandbox.expect("should have sandbox");
        assert_eq!(sandbox.network, NetworkPolicy::Deny);
    }

    #[test]
    fn test_profile_sandbox_include_merge() {
        let policy = compile(
            "(default deny child)\n(profile parent\n  (sandbox\n    (fs read execute (subpath .))\n    (network deny))\n  (allow bash \"git *\"))\n(profile child\n  (include parent)\n  (sandbox\n    (fs write create (subpath ./target))\n    (network allow))\n  (allow bash \"cargo *\"))\n",
        );

        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "cargo build",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision.sandbox.expect("should have merged sandbox");
        // deny wins for network
        assert_eq!(sandbox.network, NetworkPolicy::Deny);
        // Should have rules from both parent and child fs entries
        assert!(
            sandbox.rules.len() >= 2,
            "should have rules from both parent and child, got {}",
            sandbox.rules.len()
        );
    }

    #[test]
    fn test_sandbox_for_active_profile_uses_profile_sandbox() {
        let policy = compile(
            "(default deny main)\n(profile main\n  (sandbox\n    (fs read execute (subpath .))\n    (fs write create (subpath ./target))\n    (network deny))\n  (allow bash \"cargo *\")\n  (allow bash \"git status\"))\n",
        );

        let sandbox = policy
            .sandbox_for_active_profile("/home/user/project")
            .expect("profile sandbox should generate SandboxPolicy");
        assert_eq!(sandbox.network, NetworkPolicy::Deny);
        assert!(!sandbox.rules.is_empty());
    }
}
