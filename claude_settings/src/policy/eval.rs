//! Policy evaluation engine.
//!
//! Evaluates requests against compiled policies using the deny > ask > allow > delegate
//! precedence model. Sandbox generation is delegated to `sandbox_gen`.

use std::path::{Path, PathBuf};

use tracing::{Level, instrument};

use super::ir::{
    CompiledConstraintDef, CompiledFilterExpr, CompiledInlineConstraints, CompiledMatchExpr,
    CompiledPattern, CompiledPolicy, CompiledStatement, PolicyDecision,
};
use super::sandbox_gen::filter_to_sandbox_rules;
use super::*;
use crate::sandbox::{Cap, NetworkPolicy, RuleEffect, SandboxPolicy};

impl CompiledPolicy {
    /// Evaluate a request against this policy (backward-compatible version).
    ///
    /// Returns the resulting effect after applying all matching statements
    /// with precedence: deny > ask > allow > delegate.
    ///
    /// If no statement matches, returns the configured default effect.
    ///
    /// This version creates a minimal `EvalContext` without cwd or tool_input.
    /// For full constraint evaluation, use `evaluate_with_context`.
    #[instrument(level = Level::TRACE, skip(self), fields(entity, verb, noun))]
    pub fn evaluate(&self, entity: &str, verb: &Verb, noun: &str) -> PolicyDecision {
        let verb_str = verb.rule_name();
        let ctx = EvalContext {
            entity,
            verb,
            noun,
            cwd: "",
            tool_input: &serde_json::Value::Null,
            verb_str,
        };
        self.evaluate_with_context(&ctx)
    }

    /// Evaluate a request against this policy with full context.
    ///
    /// The `EvalContext` provides cwd and tool_input for constraint evaluation.
    /// Dispatches to new-format evaluation if active_profile_rules is non-empty.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn evaluate_with_context(&self, ctx: &EvalContext) -> PolicyDecision {
        if !self.active_profile_rules.is_empty() {
            return self.evaluate_new_format(ctx);
        }

        let mut has_allow = false;
        let mut has_ask = false;
        let mut has_deny = false;
        let mut has_delegate = false;

        let mut deny_reason: Option<&str> = None;
        let mut ask_reason: Option<&str> = None;
        let mut delegate_config: Option<&DelegateConfig> = None;

        // Track profiles from matched allow statements (for sandbox generation).
        let mut allow_profiles: Vec<&ProfileExpr> = Vec::new();

        let mut explanation: Vec<String> = Vec::new();

        for stmt in &self.statements {
            if !stmt.matches(ctx.entity, ctx.verb, ctx.noun) {
                continue;
            }

            // Statement pattern matched — now check profile/constraint
            let profile_result = self.check_profile(&stmt.profile, ctx);
            if let Err(ref reason) = profile_result {
                explanation.push(format!(
                    "skipped: {} (constraint failed: {})",
                    describe_statement(stmt),
                    reason
                ));
                continue;
            }

            explanation.push(format!("matched: {}", describe_statement(stmt),));

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
                    if let Some(ref profile) = stmt.profile {
                        allow_profiles.push(profile);
                    }
                }
                Effect::Delegate => {
                    has_delegate = true;
                    if delegate_config.is_none() {
                        delegate_config = stmt.delegate.as_ref();
                    }
                }
            }
        }

        // Precedence: deny > ask > allow > delegate
        if has_deny {
            explanation.push(format!(
                "result: deny (deny > ask > allow; {} deny, {} ask, {} allow matched)",
                if has_deny { 1 } else { 0 },
                if has_ask { "1+" } else { "0" },
                if has_allow { "1+" } else { "0" },
            ));
            return PolicyDecision {
                effect: Effect::Deny,
                reason: deny_reason.map(|s| s.to_string()),
                explanation,
                delegate: None,
                sandbox: None,
            };
        }
        if has_ask {
            explanation.push("result: ask (ask > allow)".into());
            return PolicyDecision {
                effect: Effect::Ask,
                reason: ask_reason.map(|s| s.to_string()),
                explanation,
                delegate: None,
                sandbox: None,
            };
        }
        if has_allow {
            explanation.push("result: allow".into());
            // For bash commands, generate sandbox from matched allow profiles.
            let sandbox = if *ctx.verb == Verb::Execute {
                self.generate_sandbox_from_profiles(&allow_profiles, ctx.cwd)
            } else {
                None
            };
            return PolicyDecision {
                effect: Effect::Allow,
                reason: None,
                explanation,
                delegate: None,
                sandbox,
            };
        }
        if has_delegate {
            explanation.push("result: delegate".into());
            return PolicyDecision {
                effect: Effect::Delegate,
                reason: None,
                explanation,
                delegate: delegate_config.cloned(),
                sandbox: None,
            };
        }

        // No match → default
        explanation.push(format!("no rules matched; default: {}", self.default));
        PolicyDecision {
            effect: self.default,
            reason: None,
            explanation,
            delegate: None,
            sandbox: None,
        }
    }

    /// Check if a profile expression is satisfied for the given context.
    /// If no profile is specified, the check passes (unconditional rule).
    fn check_profile(
        &self,
        profile: &Option<ProfileExpr>,
        ctx: &EvalContext,
    ) -> Result<(), String> {
        match profile {
            None => Ok(()),
            Some(expr) => self.eval_profile_expr(expr, ctx),
        }
    }

    /// Evaluate a profile expression recursively.
    /// Returns `Ok(())` if satisfied, or `Err(reason)` explaining why not.
    fn eval_profile_expr(&self, expr: &ProfileExpr, ctx: &EvalContext) -> Result<(), String> {
        match expr {
            ProfileExpr::Ref(name) => {
                // First check if it's a named profile (composite)
                if let Some(profile_expr) = self.profiles.get(name) {
                    return self.eval_profile_expr(profile_expr, ctx);
                }
                // Then check if it's a named constraint (primitive)
                if let Some(constraint) = self.constraints.get(name) {
                    return constraint.eval(ctx);
                }
                // Unknown reference — fail closed (constraint not satisfied)
                Err(format!("unknown constraint or profile '{}'", name))
            }
            ProfileExpr::And(a, b) => {
                self.eval_profile_expr(a, ctx)?;
                self.eval_profile_expr(b, ctx)
            }
            ProfileExpr::Or(a, b) => {
                let a_result = self.eval_profile_expr(a, ctx);
                if a_result.is_ok() {
                    return Ok(());
                }
                let b_result = self.eval_profile_expr(b, ctx);
                if b_result.is_ok() {
                    return Ok(());
                }
                // Both failed — combine reasons
                Err(format!(
                    "({}) OR ({})",
                    a_result.unwrap_err(),
                    b_result.unwrap_err()
                ))
            }
            ProfileExpr::Not(inner) => match self.eval_profile_expr(inner, ctx) {
                Ok(()) => Err("NOT(satisfied)".into()),
                Err(_) => Ok(()),
            },
        }
    }

    // -----------------------------------------------------------------------
    // New-format evaluation
    // -----------------------------------------------------------------------

    /// Evaluate using the new profile-based format.
    ///
    /// For each rule in the flattened active profile:
    /// - Match verb string against `ctx.verb_str`
    /// - Match noun pattern
    /// - Check inline constraints (pipe, redirect, args)
    /// - Cap-scoped fs: for non-bash verbs, check as permission guard;
    ///   for bash, collect for sandbox generation
    ///
    /// Precedence: deny > ask > allow (same as legacy).
    #[instrument(level = Level::TRACE, skip(self))]
    fn evaluate_new_format(&self, ctx: &EvalContext) -> PolicyDecision {
        let mut has_allow = false;
        let mut has_ask = false;
        let mut has_deny = false;

        // Collect cap-scoped fs entries from matched allow rules (for sandbox).
        let mut allow_fs_entries: Vec<(&CompiledFilterExpr, Cap)> = Vec::new();
        let mut merged_network = NetworkPolicy::Allow;

        let mut explanation: Vec<String> = Vec::new();

        for rule in &self.active_profile_rules {
            let rule_desc = format!("{} {} *", rule.effect, rule.verb);

            // Match verb: "*" matches anything, otherwise exact match
            let verb_matches = rule.verb == "*" || rule.verb == ctx.verb_str;
            if !verb_matches {
                continue;
            }

            // Match noun
            if !rule.noun_matcher.matches_noun(ctx.noun) {
                continue;
            }

            // Check inline constraints
            if let Err(reason) = check_new_constraints(&rule.constraints, ctx) {
                explanation.push(format!("skipped: {} ({})", rule_desc, reason));
                continue;
            }

            // Cap-scoped fs permission guard for non-bash verbs
            if *ctx.verb != Verb::Execute {
                if let Err(reason) = check_cap_scoped_fs_guard(&rule.constraints, ctx) {
                    explanation.push(format!("skipped: {} ({})", rule_desc, reason));
                    continue;
                }
            }

            explanation.push(format!("matched: {} -> {}", rule_desc, rule.effect));

            match rule.effect {
                Effect::Deny => {
                    has_deny = true;
                }
                Effect::Ask => {
                    has_ask = true;
                }
                Effect::Allow => {
                    has_allow = true;
                    // Collect fs entries for sandbox generation (bash only)
                    if *ctx.verb == Verb::Execute {
                        if let Some(ref constraints) = rule.constraints {
                            if let Some(ref fs_entries) = constraints.fs {
                                for (caps, compiled_fs) in fs_entries {
                                    allow_fs_entries.push((compiled_fs, *caps));
                                }
                            }
                            if let Some(net) = constraints.network {
                                if net == NetworkPolicy::Deny {
                                    merged_network = NetworkPolicy::Deny;
                                }
                            }
                        }
                    }
                }
                Effect::Delegate => {
                    // Not supported in new format
                }
            }
        }

        // Precedence: deny > ask > allow
        if has_deny {
            explanation.push("result: deny (deny > ask > allow)".into());
            return PolicyDecision {
                effect: Effect::Deny,
                reason: None,
                explanation,
                delegate: None,
                sandbox: None,
            };
        }
        if has_ask {
            explanation.push("result: ask (ask > allow)".into());
            return PolicyDecision {
                effect: Effect::Ask,
                reason: None,
                explanation,
                delegate: None,
                sandbox: None,
            };
        }
        if has_allow {
            explanation.push("result: allow".into());
            let sandbox = if *ctx.verb == Verb::Execute && !allow_fs_entries.is_empty() {
                let mut rules = Vec::new();
                for (fs_expr, caps) in &allow_fs_entries {
                    filter_to_sandbox_rules(fs_expr, RuleEffect::Allow, *caps, ctx.cwd, &mut rules);
                }
                Some(SandboxPolicy {
                    default: Cap::READ | Cap::EXECUTE,
                    rules,
                    network: merged_network,
                })
            } else {
                None
            };
            return PolicyDecision {
                effect: Effect::Allow,
                reason: None,
                explanation,
                delegate: None,
                sandbox,
            };
        }

        // No match → default
        explanation.push(format!("no rules matched; default: {}", self.default));
        PolicyDecision {
            effect: self.default,
            reason: None,
            explanation,
            delegate: None,
            sandbox: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Statement matching
// ---------------------------------------------------------------------------

impl CompiledStatement {
    pub(crate) fn matches(&self, entity: &str, verb: &Verb, noun: &str) -> bool {
        self.entity_matcher.matches_entity(entity)
            && self.verb_matcher.matches(verb)
            && self.noun_matcher.matches_noun(noun)
    }
}

// ---------------------------------------------------------------------------
// Pattern and MatchExpr matching
// ---------------------------------------------------------------------------

impl CompiledPattern {
    pub(crate) fn matches_entity(&self, entity: &str) -> bool {
        match self {
            CompiledPattern::Match(expr) => expr.matches_entity(entity),
            CompiledPattern::Not(expr) => !expr.matches_entity(entity),
        }
    }

    pub(crate) fn matches_noun(&self, noun: &str) -> bool {
        match self {
            CompiledPattern::Match(expr) => expr.matches_noun(noun),
            CompiledPattern::Not(expr) => !expr.matches_noun(noun),
        }
    }
}

impl CompiledMatchExpr {
    pub(crate) fn matches_entity(&self, entity: &str) -> bool {
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

    pub(crate) fn matches_noun(&self, noun: &str) -> bool {
        match self {
            CompiledMatchExpr::Any => true,
            CompiledMatchExpr::Exact(s) => noun == s,
            CompiledMatchExpr::Glob { regex, .. } => regex.is_match(noun),
            CompiledMatchExpr::Typed { .. } => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint evaluation
// ---------------------------------------------------------------------------

impl CompiledConstraintDef {
    /// Evaluate this constraint against the given context.
    /// All specified fields must be satisfied (AND).
    ///
    /// For bash (Execute) commands, the `fs` check is skipped because `fs` constraints
    /// generate sandbox rules rather than acting as permission guards.
    ///
    /// Returns `Ok(())` if satisfied, or `Err(reason)` explaining why not.
    pub(crate) fn eval(&self, ctx: &EvalContext) -> Result<(), String> {
        // For bash commands, skip fs check — fs generates sandbox rules instead.
        // For other verbs (read/write/edit), fs acts as a permission guard.
        if *ctx.verb != Verb::Execute {
            if let Some(ref fs) = self.fs
                && !fs.matches(ctx.noun, ctx.cwd)
            {
                return Err(format!(
                    "fs constraint: '{}' does not match filter",
                    ctx.noun
                ));
            }
        }

        // Check pipe constraint (only relevant for bash commands)
        if let Some(allow_pipe) = self.pipe
            && !allow_pipe
            && command_has_pipe(ctx.noun)
        {
            return Err("pipe constraint: command contains '|'".into());
        }

        // Check redirect constraint (only relevant for bash commands)
        if let Some(allow_redirect) = self.redirect
            && !allow_redirect
            && command_has_redirect(ctx.noun)
        {
            return Err("redirect constraint: command contains '>' or '<'".into());
        }

        // Check forbidden arguments
        if let Some(ref forbidden) = self.forbid_args {
            let args = tokenize_command(ctx.noun);
            for forbidden_arg in forbidden {
                if args.iter().any(|a| a == forbidden_arg) {
                    return Err(format!(
                        "forbid-args: found forbidden arg '{}'",
                        forbidden_arg
                    ));
                }
            }
        }

        // Check required arguments (at least one must be present)
        if let Some(ref required) = self.require_args {
            let args = tokenize_command(ctx.noun);
            if !required.iter().any(|req| args.iter().any(|a| a == req)) {
                return Err(format!(
                    "require-args: none of {:?} found in command",
                    required
                ));
            }
        }

        Ok(())
    }
}

impl CompiledFilterExpr {
    /// Check if the given path matches this filter expression.
    ///
    /// The path is resolved relative to `cwd` before matching.
    pub(crate) fn matches(&self, path: &str, cwd: &str) -> bool {
        match self {
            CompiledFilterExpr::Subpath(base) => {
                let resolved = resolve_path(path, cwd);
                let base_resolved = resolve_path(base, cwd);
                resolved.starts_with(&base_resolved)
            }
            CompiledFilterExpr::Literal(expected) => {
                let resolved = resolve_path(path, cwd);
                let expected_resolved = resolve_path(expected, cwd);
                resolved == expected_resolved
            }
            CompiledFilterExpr::Regex(regex) => {
                let resolved = resolve_path(path, cwd);
                let resolved_str = resolved.to_string_lossy();
                regex.is_match(&resolved_str)
            }
            CompiledFilterExpr::And(a, b) => a.matches(path, cwd) && b.matches(path, cwd),
            CompiledFilterExpr::Or(a, b) => a.matches(path, cwd) || b.matches(path, cwd),
            CompiledFilterExpr::Not(inner) => !inner.matches(path, cwd),
        }
    }
}

// ---------------------------------------------------------------------------
// New-format constraint checking (free functions)
// ---------------------------------------------------------------------------

/// Check non-fs inline constraints (pipe, redirect, args).
/// Returns `Ok(())` if satisfied, or `Err(reason)` explaining why not.
fn check_new_constraints(
    constraints: &Option<CompiledInlineConstraints>,
    ctx: &EvalContext,
) -> Result<(), String> {
    let constraints = match constraints {
        Some(c) => c,
        None => return Ok(()),
    };

    // Check pipe
    if let Some(allow_pipe) = constraints.pipe
        && !allow_pipe
        && command_has_pipe(ctx.noun)
    {
        return Err("pipe constraint: command contains '|'".into());
    }

    // Check redirect
    if let Some(allow_redirect) = constraints.redirect
        && !allow_redirect
        && command_has_redirect(ctx.noun)
    {
        return Err("redirect constraint: command contains '>' or '<'".into());
    }

    // Check forbidden args
    if !constraints.forbid_args.is_empty() {
        let args = tokenize_command(ctx.noun);
        for forbidden in &constraints.forbid_args {
            if args.iter().any(|a| *a == forbidden) {
                return Err(format!("forbid-args: found forbidden arg '{}'", forbidden));
            }
        }
    }

    // Check required args (at least one must be present)
    if !constraints.require_args.is_empty() {
        let args = tokenize_command(ctx.noun);
        if !constraints
            .require_args
            .iter()
            .any(|req| args.iter().any(|a| *a == req))
        {
            return Err(format!(
                "require-args: none of {:?} found in command",
                constraints.require_args
            ));
        }
    }

    Ok(())
}

/// Cap-scoped fs permission guard for non-bash verbs.
///
/// Maps the verb to a capability, then checks if any fs entry's caps
/// intersect with the verb's cap. If they do, the noun must match
/// that filter expression.
///
/// Returns `Ok(())` if satisfied, or `Err(reason)` explaining why not.
fn check_cap_scoped_fs_guard(
    constraints: &Option<CompiledInlineConstraints>,
    ctx: &EvalContext,
) -> Result<(), String> {
    let constraints = match constraints {
        Some(c) => c,
        None => return Ok(()),
    };

    let fs_entries = match &constraints.fs {
        Some(entries) => entries,
        None => return Ok(()),
    };

    // Map verb to cap
    let verb_cap = match ctx.verb {
        Verb::Read => Cap::READ,
        Verb::Write => Cap::WRITE | Cap::CREATE,
        Verb::Edit => Cap::WRITE,
        Verb::Execute => return Ok(()), // bash uses sandbox path
        Verb::Delegate => return Ok(()),
    };

    // Check if any fs entry's caps intersect with the verb's cap.
    // If so, the noun must match that filter.
    for (caps, filter) in fs_entries {
        if caps.intersects(verb_cap) {
            // This fs entry is relevant — noun must match
            if !filter.matches(ctx.noun, ctx.cwd) {
                return Err(format!(
                    "fs guard: '{}' does not match filter for {} cap",
                    ctx.noun,
                    ctx.verb.rule_name()
                ));
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Statement description (for explanation strings)
// ---------------------------------------------------------------------------

/// Build a human-readable description of a statement for explanations.
fn describe_statement(stmt: &CompiledStatement) -> String {
    let verb = match &stmt.verb_matcher {
        VerbPattern::Any => "*",
        VerbPattern::Exact(v) => v.rule_name(),
    };
    let profile_suffix = if stmt.profile.is_some() {
        format!(" : {}", stmt.profile.as_ref().unwrap())
    } else {
        String::new()
    };
    format!(
        "{} {} {} -> {}{}",
        stmt.effect, verb, "*", stmt.effect, profile_suffix,
    )
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Resolve a path relative to cwd. Handles `.` as cwd.
pub(crate) fn resolve_path(path: &str, cwd: &str) -> PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        // Use lexical normalization for absolute paths
        lexical_normalize(p)
    } else if path == "." {
        lexical_normalize(Path::new(cwd))
    } else if path.starts_with("./") || path.starts_with("..") {
        lexical_normalize(&Path::new(cwd).join(path))
    } else {
        // Bare relative path — resolve against cwd
        lexical_normalize(&Path::new(cwd).join(path))
    }
}

/// Lexical path normalization (no filesystem access).
/// Removes `.` and resolves `..` components.
pub(crate) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {} // skip '.'
            std::path::Component::ParentDir => {
                // Pop the last component if there is one (and it's not ..)
                if !components.is_empty() {
                    components.pop();
                }
            }
            other => components.push(other),
        }
    }
    components.iter().collect()
}

/// Check if a command string contains shell pipe operators.
pub(crate) fn command_has_pipe(command: &str) -> bool {
    // Look for unquoted pipe characters
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = ' ';

    for ch in command.chars() {
        match ch {
            '\'' if !in_double_quote && prev_char != '\\' => in_single_quote = !in_single_quote,
            '"' if !in_single_quote && prev_char != '\\' => in_double_quote = !in_double_quote,
            '|' if !in_single_quote && !in_double_quote => return true,
            _ => {}
        }
        prev_char = ch;
    }
    false
}

/// Check if a command string contains shell redirect operators.
pub(crate) fn command_has_redirect(command: &str) -> bool {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = ' ';

    for ch in command.chars() {
        match ch {
            '\'' if !in_double_quote && prev_char != '\\' => in_single_quote = !in_single_quote,
            '"' if !in_single_quote && prev_char != '\\' => in_double_quote = !in_double_quote,
            '>' | '<' if !in_single_quote && !in_double_quote => return true,
            _ => {}
        }
        prev_char = ch;
    }
    false
}

/// Tokenize a command string by splitting on whitespace.
/// Simple tokenization — does not handle shell quoting.
pub(crate) fn tokenize_command(command: &str) -> Vec<&str> {
    command.split_whitespace().collect()
}
