//! Compilation of policy documents into optimized runtime representations.
//!
//! The `CompiledPolicy` pre-compiles glob patterns into regexes and
//! organizes statements for efficient evaluation.

use std::collections::HashMap;

use tracing::{Level, instrument};

use super::error::CompileError;
use super::ir::{
    CompiledConstraintDef, CompiledFilterExpr, CompiledInlineConstraints, CompiledMatchExpr,
    CompiledPattern, CompiledPolicy, CompiledProfileRule,
};
use super::*;
use crate::policy::sandbox_types::Cap;
use regex::Regex;

/// Name of the built-in profile that grants access to `~/.clash/`.
/// Users can override this by defining a profile with the same name.
const BUILTIN_CLASH_PROFILE: &str = "__clash_internal__";

/// Name of the built-in profile that always allows Claude Code meta-tools
/// (e.g. AskUserQuestion, ExitPlanMode). Users can override this by
/// defining a profile with the same name.
const BUILTIN_CLAUDE_PROFILE: &str = "__claude_internal__";

/// Tools covered by the `__claude_internal__` built-in, with per-tool effects.
/// Most are `Allow` (pure workflow tools), but some warrant `Ask`.
const CLAUDE_INTERNAL_TOOLS: &[(&str, Effect)] = &[
    ("askuserquestion", Effect::Ask),
    ("exitplanmode", Effect::Ask),
    ("enterplanmode", Effect::Allow),
    ("taskcreate", Effect::Allow),
    ("taskupdate", Effect::Allow),
    ("tasklist", Effect::Allow),
    ("taskget", Effect::Allow),
    ("taskoutput", Effect::Allow),
    ("taskstop", Effect::Allow),
    ("skill", Effect::Allow),
    ("sendmessage", Effect::Allow),
    ("teammate", Effect::Allow),
];

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
        if let Some(ref default_config) = doc.default_config {
            let flat_rules = parse::flatten_profile(&default_config.profile, &doc.profile_defs)
                .map_err(|e| CompileError::ProfileError(e.to_string()))?;
            for rule in &flat_rules {
                active_profile_rules.push(CompiledProfileRule::compile(rule)?);
            }
        }

        // Inject built-in __clash_internal__ profile rules unless the user
        // has defined their own override in profile_defs.
        if !doc.profile_defs.contains_key(BUILTIN_CLASH_PROFILE) {
            for rule in &Self::builtin_clash_rules() {
                active_profile_rules.push(CompiledProfileRule::compile(rule)?);
            }
        }

        // Inject built-in __claude_internal__ profile rules unless the user
        // has defined their own override in profile_defs.
        if !doc.profile_defs.contains_key(BUILTIN_CLAUDE_PROFILE) {
            for rule in &Self::builtin_claude_rules() {
                active_profile_rules.push(CompiledProfileRule::compile(rule)?);
            }
        }

        Ok(CompiledPolicy {
            default: doc.policy.default,
            constraints,
            profiles: doc.profiles.clone(),
            active_profile_rules,
        })
    }

    /// Built-in rules for the `__clash_internal__` profile.
    ///
    /// Three rules:
    /// 1. Allow `Read` tool access to `~/.clash/` (so Claude can inspect the policy).
    /// 2. Allow `Bash` commands matching `*clash init*` to write to `~/.clash/`
    ///    (sandbox includes `~/.clash/` only for the clash binary, not all commands).
    /// 3. Allow `Bash` commands matching `*clash policy*` to read/write `~/.clash/`
    ///    (so `clash policy add-rule` / `remove-rule` can modify the policy file).
    ///
    /// Users can override by defining a profile named `__clash_internal__`
    /// in their policy's `profiles:` section.
    fn builtin_clash_rules() -> Vec<ProfileRule> {
        vec![
            // Allow reading ~/.clash/ files (so Claude can inspect/explain the policy)
            ProfileRule {
                effect: Effect::Allow,
                verb: "read".to_string(),
                noun: Pattern::Match(MatchExpr::Any),
                constraints: Some(InlineConstraints {
                    fs: Some(vec![(
                        Cap::READ,
                        FilterExpr::Subpath("~/.clash".to_string()),
                    )]),
                    ..Default::default()
                }),
            },
            // Allow `clash init` (and --force) to write to ~/.clash/ via sandbox.
            // Pattern ends with `clash init*` so it matches the clash binary
            // whether invoked via full path or just `clash init` from PATH.
            ProfileRule {
                effect: Effect::Allow,
                verb: "bash".to_string(),
                noun: Pattern::Match(MatchExpr::Glob("*clash init*".to_string())),
                constraints: Some(InlineConstraints {
                    fs: Some(vec![(
                        Cap::READ | Cap::WRITE | Cap::EXECUTE | Cap::CREATE | Cap::DELETE,
                        FilterExpr::Subpath("~/.clash".to_string()),
                    )]),
                    ..Default::default()
                }),
            },
            // Allow `clash policy` subcommands to read/write ~/.clash/.
            ProfileRule {
                effect: Effect::Allow,
                verb: "bash".to_string(),
                noun: Pattern::Match(MatchExpr::Glob("*clash policy*".to_string())),
                constraints: Some(InlineConstraints {
                    fs: Some(vec![(
                        Cap::READ | Cap::WRITE | Cap::EXECUTE | Cap::CREATE | Cap::DELETE,
                        FilterExpr::Subpath("~/.clash".to_string()),
                    )]),
                    ..Default::default()
                }),
            },
        ]
    }

    /// Built-in rules for the `__claude_internal__` profile.
    ///
    /// Always allows Claude Code meta-tools that don't interact with the
    /// user's filesystem or system (e.g. AskUserQuestion, ExitPlanMode).
    ///
    /// Users can override by defining a profile named `__claude_internal__`
    /// in their policy's `profiles:` section.
    fn builtin_claude_rules() -> Vec<ProfileRule> {
        CLAUDE_INTERNAL_TOOLS
            .iter()
            .map(|(tool, effect)| ProfileRule {
                effect: *effect,
                verb: tool.to_string(),
                noun: Pattern::Match(MatchExpr::Any),
                constraints: None,
            })
            .collect()
    }
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

        Ok(CompiledInlineConstraints {
            fs,
            forbid_args,
            require_args,
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

    fn compile_yaml(yaml: &str) -> CompiledPolicy {
        let doc = parse::parse_yaml(yaml).unwrap();
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

    // --- Constraint tests ---

    #[test]
    fn test_constraint_fs_subpath() {
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(/home/user/project)
rules:
  - \"allow * read * : local\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
rules:
  - \"allow * read * : local\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  no-env:
    fs: \"!literal(.env)\"
rules:
  - \"allow * read * : no-env\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  safe-io:
    pipe: false
rules:
  - \"allow * bash * : safe-io\"
",
        );

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
        let policy = compile_yaml(
            "\
constraints:
  safe-io:
    redirect: false
rules:
  - \"allow * bash * : safe-io\"
",
        );

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
        let policy = compile_yaml(
            "\
constraints:
  git-safe:
    forbid-args:
      - --force
      - --hard
rules:
  - \"allow * bash git * : git-safe\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  dry-run:
    require-args:
      - --dry-run
rules:
  - \"allow * bash * : dry-run\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false
profiles:
  sandboxed: local & safe-io
rules:
  - \"allow * bash * : sandboxed\"
",
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
    fn test_profile_nested_composition() {
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false
  git-safe-args:
    forbid-args:
      - --force
      - --hard
profiles:
  sandboxed: local & safe-io
  strict-git: sandboxed & git-safe-args
rules:
  - \"allow * bash git * : strict-git\"
",
        );

        // All constraints satisfied → allowed
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "git status",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // --force violates git-safe-args → fails
        let ctx = EvalContext {
            entity: "agent",
            verb: &Verb::Execute,
            noun: "git push --force origin main",
            cwd: "/home/user/project",
            tool_input: &serde_json::Value::Null,
            verb_str: "bash",
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn test_inline_constraint_expression() {
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
  no-secrets:
    fs: \"!literal(.env)\"
rules:
  - \"allow * read * : local & no-secrets\"
",
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
        let policy = compile_yaml(
            "\
rules:
  - allow * bash git *
  - deny * bash rm *
",
        );

        let decision = policy.evaluate("agent", &Verb::Execute, "git status");
        assert_eq!(decision.effect, Effect::Allow);

        let decision = policy.evaluate("agent", &Verb::Execute, "rm -rf /");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn test_deny_with_constraint() {
        // deny rule with constraint: only denies when constraint is satisfied
        let policy = compile_yaml(
            "\
constraints:
  has-force:
    forbid-args:
      - --force
rules:
  - allow * bash git *
  - \"deny * bash git push * : has-force\"
",
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
            resolve_path("~/.clash/policy.yaml", "/cwd"),
            home.join(".clash/policy.yaml")
        );
    }

    #[test]
    fn test_fs_filter_with_compound_expr() {
        let policy = compile_yaml(
            "\
constraints:
  test-dirs:
    fs: \"subpath(/home/user/project/src) | subpath(/home/user/project/test)\"
rules:
  - \"allow * read * : test-dirs\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
rules:
  - \"allow * bash * : local\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
  read-only:
    caps: read + execute
rules:
  - \"allow * bash * : local & read-only\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
    network: deny
rules:
  - \"allow * bash * : local\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
rules:
  - \"allow * read * : local\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  safe-io:
    pipe: false
rules:
  - \"allow * bash * : safe-io\"
",
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
        // No fs in any constraint → no sandbox
        assert!(decision.sandbox.is_none());
    }

    #[test]
    fn test_sandbox_not_filter_generates_deny() {
        let policy = compile_yaml(
            "\
constraints:
  no-git:
    fs: \"!subpath(.git)\"
rules:
  - \"allow * bash * : no-git\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  no-env:
    fs: \"regex(\\\\.env)\"
rules:
  - \"allow * bash * : no-env\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(/home/user/project)
rules:
  - \"allow * bash * : local\"
",
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
        let policy = compile_yaml(
            "\
constraints:
  env-file:
    fs: literal(.env)
rules:
  - \"allow * bash * : env-file\"
",
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
        let policy = compile_yaml(
            "\
rules:
  - allow * bash *
",
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
        // No profile → no sandbox
        assert!(decision.sandbox.is_none());
    }

    #[test]
    fn test_sandbox_network_default_allow() {
        // When no network policy is specified, default is allow
        let policy = compile_yaml(
            "\
constraints:
  local:
    fs: subpath(.)
rules:
  - \"allow * bash * : local\"
",
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
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      allow bash *:
      deny bash rm *:
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      allow read *:
        fs:
          read: subpath(/home/user/project)
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      allow bash *:
        fs:
          read + write + create: subpath(.)
        network: deny
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      allow bash *:
        args: ["!-delete"]
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: deny
  profile: test

profiles:
  test:
    rules:
      allow safe-read *:
        args: []
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: ask
  profile: child

profiles:
  parent:
    rules:
      deny bash rm *:
  child:
    include: parent
    rules:
      allow bash *:
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: deny
  profile: test

profiles:
  test:
    rules:
      allow bash *:
"#;
        let policy = compile_yaml(yaml);

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
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      deny * *:
        fs:
          read + write: "subpath(~/.ssh)"
      allow bash *:
"#;
        let policy = compile_yaml(yaml);

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

        /// Strategy for generating entity strings.
        fn arb_entity() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("agent:claude".to_string()),
                Just("agent:codex".to_string()),
                Just("user".to_string()),
                Just("*".to_string()),
            ]
        }

        /// Strategy for generating noun/pattern strings.
        fn arb_noun() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("*".to_string()),
                Just("git *".to_string()),
                Just("rm *".to_string()),
                Just("ls".to_string()),
                Just("/tmp/*".to_string()),
                Just("src/main.rs".to_string()),
                Just(".env".to_string()),
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
                entity in arb_entity(),
                (verb_str, verb) in arb_verb(),
                noun in arb_noun(),
            ) {
                // Policy with allow first, then deny on the same triple
                let yaml = format!(
                    "rules:\n  - allow {} {} {}\n  - deny {} {} {}\n",
                    entity, verb_str, noun, entity, verb_str, noun
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate(&entity, &verb, &noun);
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "deny should override allow for {} {} {}", entity, verb_str, noun);
                    }
                }

                // Reverse order: deny first, then allow
                let yaml = format!(
                    "rules:\n  - deny {} {} {}\n  - allow {} {} {}\n",
                    entity, verb_str, noun, entity, verb_str, noun
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate(&entity, &verb, &noun);
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "deny should override allow (reversed) for {} {} {}", entity, verb_str, noun);
                    }
                }
            }

            /// Ask overrides allow regardless of rule order.
            #[test]
            fn ask_overrides_allow(
                entity in arb_entity(),
                (verb_str, verb) in arb_verb(),
                noun in arb_noun(),
            ) {
                let yaml = format!(
                    "rules:\n  - allow {} {} {}\n  - ask {} {} {}\n",
                    entity, verb_str, noun, entity, verb_str, noun
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate(&entity, &verb, &noun);
                        prop_assert_eq!(decision.effect, Effect::Ask,
                            "ask should override allow for {} {} {}", entity, verb_str, noun);
                    }
                }
            }

            /// Deny overrides ask regardless of rule order.
            #[test]
            fn deny_overrides_ask(
                entity in arb_entity(),
                (verb_str, verb) in arb_verb(),
                noun in arb_noun(),
            ) {
                let yaml = format!(
                    "rules:\n  - ask {} {} {}\n  - deny {} {} {}\n",
                    entity, verb_str, noun, entity, verb_str, noun
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate(&entity, &verb, &noun);
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "deny should override ask for {} {} {}", entity, verb_str, noun);
                    }
                }
            }

            /// Determinism: same policy + same input → same output.
            #[test]
            fn deterministic_evaluation(
                entity in arb_entity(),
                (verb_str, verb) in arb_verb(),
                noun in arb_noun(),
                effect1 in arb_effect(),
                effect2 in arb_effect(),
            ) {
                let yaml = format!(
                    "rules:\n  - {} {} {} {}\n  - {} {} {} {}\n",
                    effect1, entity, verb_str, noun,
                    effect2, entity, verb_str, noun,
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let d1 = policy.evaluate(&entity, &verb, &noun);
                        let d2 = policy.evaluate(&entity, &verb, &noun);
                        prop_assert_eq!(d1.effect, d2.effect,
                            "same policy + input should give same result");
                    }
                }
            }

            /// Monotonicity: adding a deny rule never produces a less-restrictive result.
            #[test]
            fn monotonicity_deny_addition(
                entity in arb_entity(),
                (verb_str, verb) in arb_verb(),
                noun in arb_noun(),
                base_effect in arb_effect(),
            ) {
                // Evaluate with just the base rule
                let yaml_base = format!(
                    "rules:\n  - {} {} {} {}\n",
                    base_effect, entity, verb_str, noun,
                );
                // Evaluate with base + deny
                let yaml_deny = format!(
                    "rules:\n  - {} {} {} {}\n  - deny {} {} {}\n",
                    base_effect, entity, verb_str, noun,
                    entity, verb_str, noun,
                );

                if let (Ok(doc_base), Ok(doc_deny)) =
                    (parse::parse_yaml(&yaml_base), parse::parse_yaml(&yaml_deny))
                {
                    if let (Ok(p_base), Ok(p_deny)) =
                        (CompiledPolicy::compile(&doc_base), CompiledPolicy::compile(&doc_deny))
                    {
                        let d_base = p_base.evaluate(&entity, &verb, &noun);
                        let d_deny = p_deny.evaluate(&entity, &verb, &noun);

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
                // Policy with rules that only match a specific entity/noun, default: deny
                let yaml = format!(
                    "default: deny\nrules:\n  - allow agent:special {} specific_file\n",
                    verb_str,
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        // Query with non-matching entity/noun
                        let decision = policy.evaluate("agent:other", &verb, "other_file");
                        prop_assert_eq!(decision.effect, Effect::Deny,
                            "no match should fall back to configured default (deny)");
                    }
                }

                // Same test with default: ask (the default default)
                let yaml = format!(
                    "default: ask\nrules:\n  - allow agent:special {} specific_file\n",
                    verb_str,
                );
                if let Ok(doc) = parse::parse_yaml(&yaml) {
                    if let Ok(policy) = CompiledPolicy::compile(&doc) {
                        let decision = policy.evaluate("agent:other", &verb, "other_file");
                        prop_assert_eq!(decision.effect, Effect::Ask,
                            "no match should fall back to default (ask)");
                    }
                }
            }
        }

        /// Negation symmetry: `!pattern` matches iff `pattern` doesn't match.
        /// This is a regular test using targeted cases since proptest can't easily
        /// generate the internal types.
        #[test]
        fn negation_symmetry() {
            // Allow everything, deny not-user (i.e., only user can read)
            let yaml = "\
rules:
  - allow * read *
  - deny !user read ~/config/*
";
            let policy = compile_yaml(yaml);

            // user should be allowed (deny !user doesn't match user)
            let decision = policy.evaluate("user", &Verb::Read, "~/config/settings");
            assert_eq!(decision.effect, Effect::Allow);

            // agent:claude should be denied (deny !user matches agent:claude)
            let decision = policy.evaluate("agent:claude", &Verb::Read, "~/config/settings");
            assert_eq!(decision.effect, Effect::Deny);
        }

        /// Negation symmetry on nouns.
        #[test]
        fn noun_negation_symmetry() {
            let yaml = "\
rules:
  - allow * bash *
  - deny * bash !git *
";
            let policy = compile_yaml(yaml);

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

            /// Adding an unreachable rule (for a different entity) doesn't change the result.
            #[test]
            fn unreachable_entity_rule_is_inert(
                (verb_str, verb) in arb_verb(),
                effect in arb_effect(),
                extra_effect in arb_effect(),
                noun in arb_noun(),
            ) {
                // Base policy: one rule for agent:claude
                let yaml_base = format!(
                    "rules:\n  - {} agent:claude {} {}\n",
                    effect, verb_str, noun,
                );
                // Extended: same + an extra rule for agent:unreachable (never queried)
                let yaml_ext = format!(
                    "rules:\n  - {} agent:claude {} {}\n  - {} agent:unreachable {} {}\n",
                    effect, verb_str, noun,
                    extra_effect, verb_str, noun,
                );

                if let (Ok(doc_base), Ok(doc_ext)) =
                    (parse::parse_yaml(&yaml_base), parse::parse_yaml(&yaml_ext))
                {
                    if let (Ok(p_base), Ok(p_ext)) =
                        (CompiledPolicy::compile(&doc_base), CompiledPolicy::compile(&doc_ext))
                    {
                        let d_base = p_base.evaluate("agent:claude", &verb, &noun);
                        let d_ext = p_ext.evaluate("agent:claude", &verb, &noun);
                        prop_assert_eq!(d_base.effect, d_ext.effect,
                            "unreachable entity rule should not change result");
                    }
                }
            }

            /// Adding a rule for a non-matching noun doesn't change the result.
            #[test]
            fn unreachable_noun_rule_is_inert(
                (verb_str, verb) in arb_verb(),
                effect in arb_effect(),
                extra_effect in arb_effect(),
            ) {
                // Base: rule for "git *"
                let yaml_base = format!(
                    "rules:\n  - {} * {} git *\n",
                    effect, verb_str,
                );
                // Extended: same + rule for "npm *" (never queried with npm)
                let yaml_ext = format!(
                    "rules:\n  - {} * {} git *\n  - {} * {} npm *\n",
                    effect, verb_str,
                    extra_effect, verb_str,
                );

                if let (Ok(doc_base), Ok(doc_ext)) =
                    (parse::parse_yaml(&yaml_base), parse::parse_yaml(&yaml_ext))
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
                noun in arb_noun(),
            ) {
                // Base: rule for bash
                let yaml_base = format!(
                    "rules:\n  - {} * bash {}\n",
                    effect, noun,
                );
                // Extended: same + rule for read (never queried with read)
                let yaml_ext = format!(
                    "rules:\n  - {} * bash {}\n  - {} * read some_other_file\n",
                    effect, noun,
                    extra_effect,
                );

                if let (Ok(doc_base), Ok(doc_ext)) =
                    (parse::parse_yaml(&yaml_base), parse::parse_yaml(&yaml_ext))
                {
                    if let (Ok(p_base), Ok(p_ext)) =
                        (CompiledPolicy::compile(&doc_base), CompiledPolicy::compile(&doc_ext))
                    {
                        let d_base = p_base.evaluate("agent:claude", &Verb::Execute, &noun);
                        let d_ext = p_ext.evaluate("agent:claude", &Verb::Execute, &noun);
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
        let policy = compile_yaml("rules:\n  - deny * bash rm *\n");

        // Read ~/.clash/policy.yaml → allowed by built-in profile
        let noun = clash_path(".clash/policy.yaml");
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
        let policy = compile_yaml("default: ask\nrules:\n  - deny * bash rm *\n");

        // Write to ~/.clash/policy.yaml → NOT allowed (no built-in write rule)
        let noun = clash_path(".clash/policy.yaml");
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
    fn test_builtin_clash_init_gets_sandbox() {
        let policy = compile_yaml("rules:\n  - deny * bash rm *\n");

        // `clash init` via full path → allowed with sandbox including ~/.clash/
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/tmp/clash-dev/clash-plugin/bin/clash init",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision
            .sandbox
            .expect("should have sandbox from built-in fs constraint");
        assert!(
            sandbox
                .rules
                .iter()
                .any(|r| r.path.contains(".clash") && r.effect == RuleEffect::Allow),
            "sandbox should include ~/.clash/ allow rule, got: {:?}",
            sandbox.rules
        );
    }

    #[test]
    fn test_builtin_clash_init_force_gets_sandbox() {
        let policy = compile_yaml("rules:\n  - deny * bash rm *\n");

        // `clash init --force` also matches
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/path/to/clash init --force",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        assert!(decision.sandbox.is_some());
    }

    #[test]
    fn test_builtin_non_clash_bash_no_clash_sandbox() {
        // Non-clash bash commands should NOT get ~/.clash/ in their sandbox
        let policy = compile_yaml("default: ask\nrules:\n  - deny * bash rm *\n");

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
        let policy = compile_yaml("default: ask\nrules:\n  - deny * bash rm *\n");

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
        let yaml = r#"
default:
  permission: ask
  profile: main

profiles:
  __clash_internal__:
    rules:
      deny read *:
        fs:
          read: subpath(~/.clash)
  main:
    include: [__clash_internal__]
    rules:
      allow bash git *:
"#;
        let policy = compile_yaml(yaml);

        // Read from ~/.clash/ → denied by user's override
        let noun = clash_path(".clash/policy.yaml");
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
        let policy = compile_yaml(crate::settings::DEFAULT_POLICY);

        // Read ~/.clash/policy.yaml from a project dir → allowed
        let noun = clash_path(".clash/policy.yaml");
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
    fn test_default_policy_clash_init_sandbox() {
        let policy = compile_yaml(crate::settings::DEFAULT_POLICY);

        // clash init via full path → allowed with ~/.clash/ in sandbox
        let ctx = make_ctx(
            "agent",
            &Verb::Execute,
            "/tmp/clash-dev/clash-plugin/bin/clash init",
            "/home/user/project",
            &serde_json::Value::Null,
            "bash",
        );
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision.sandbox.expect("should have sandbox");
        assert!(
            sandbox
                .rules
                .iter()
                .any(|r| r.path.contains(".clash") && r.effect == RuleEffect::Allow),
            "default policy sandbox should include ~/.clash/ for clash init, got: {:?}",
            sandbox.rules
        );
    }

    // -----------------------------------------------------------------------
    // Built-in __claude_internal__ profile tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_builtin_asks_askuserquestion() {
        let policy = compile_yaml("default: deny\n");

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
        let policy = compile_yaml("default: ask\n");

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
        let policy = compile_yaml("default: deny\n");

        for (tool, expected_effect) in super::CLAUDE_INTERNAL_TOOLS {
            let ctx = make_ctx(
                "agent",
                &Verb::Execute,
                "",
                "/home/user/project",
                &serde_json::Value::Null,
                tool,
            );
            let decision = policy.evaluate_with_context(&ctx);
            assert_eq!(
                decision.effect, *expected_effect,
                "built-in __claude_internal__ should {:?} for {}",
                expected_effect, tool
            );
        }
    }

    #[test]
    fn test_builtin_does_not_allow_bash_via_claude_internal() {
        // Bash should NOT be allowed by __claude_internal__
        let policy = compile_yaml("default: ask\n");

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
        let yaml = r#"
default:
  permission: ask
  profile: main

profiles:
  __claude_internal__:
    rules:
      deny askuserquestion *:
  main:
    include: [__claude_internal__]
"#;
        let policy = compile_yaml(yaml);

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
}
