//! Policy evaluation engine.
//!
//! Evaluates requests against compiled policies using specificity-aware
//! precedence: deny always wins, then constrained rules beat unconstrained
//! rules, then ask > allow within the same tier. Sandbox generation is
//! handled by `sandbox_gen`.

use std::path::{Path, PathBuf};

use tracing::{Level, instrument};

use super::ir::{
    CompiledConstraintDef, CompiledFilterExpr, CompiledInlineConstraints, CompiledMatchExpr,
    CompiledPattern, CompiledPolicy, CompiledProfileRule, DecisionTrace, PolicyDecision, RuleMatch,
    RuleSkip,
};
use super::sandbox_gen::filter_to_sandbox_rules;
use super::*;
use crate::policy::sandbox_types::{Cap, NetworkPolicy, RuleEffect, SandboxPolicy};

impl CompiledPolicy {
    /// Evaluate a request against this policy (backward-compatible version).
    ///
    /// Returns the resulting effect after applying all matching statements
    /// with precedence: deny > ask > allow.
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
    /// Uses a single unified evaluation path over `active_profile_rules`,
    /// which contains both legacy-converted rules and new-format rules.
    ///
    /// For each rule:
    /// 1. Entity matching (legacy-converted rules only)
    /// 2. Verb matching (string-based)
    /// 3. Noun matching (compiled pattern)
    /// 4. Inline constraint checking (new-format rules)
    /// 5. Cap-scoped fs permission guard (non-bash, new-format rules)
    /// 6. Profile guard evaluation (legacy-converted rules)
    ///
    /// Specificity-aware precedence:
    /// - Deny always wins
    /// - Constrained rules (with active url/args/pipe/redirect/fs constraints)
    ///   beat unconstrained rules among non-deny effects
    /// - Within the same constraint tier: ask > allow
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn evaluate_with_context(&self, ctx: &EvalContext) -> PolicyDecision {
        let mut has_allow = false;
        let mut has_ask = false;
        let mut has_deny = false;
        let mut has_constrained_allow = false;
        let mut has_constrained_ask = false;

        let mut deny_reason: Option<&str> = None;
        let mut ask_reason: Option<&str> = None;
        let mut constrained_ask_reason: Option<&str> = None;

        // Collect cap-scoped fs entries from matched allow rules (for sandbox, new-format).
        let mut allow_fs_entries: Vec<(&CompiledFilterExpr, Cap)> = Vec::new();
        let mut merged_network = NetworkPolicy::Allow;

        // Track profile guards from matched allow rules (for sandbox, legacy-converted).
        let mut allow_profile_guards: Vec<&ProfileExpr> = Vec::new();

        let mut matched_rules: Vec<RuleMatch> = Vec::new();
        let mut skipped_rules: Vec<RuleSkip> = Vec::new();

        for (rule_index, rule) in self.active_profile_rules.iter().enumerate() {
            let rule_desc = describe_rule(rule);

            // 1. Entity matching (legacy-converted rules have entity_matcher)
            if let Some(ref entity_matcher) = rule.entity_matcher
                && !entity_matcher.matches_entity(ctx.entity)
            {
                continue;
            }

            // 2. Match verb: "*" matches anything, otherwise exact match
            if rule.verb != "*" && rule.verb != ctx.verb_str {
                continue;
            }

            // 3. Match noun
            if !rule.noun_matcher.matches_noun(ctx.noun) {
                continue;
            }

            // 4. Check inline constraints (new-format rules; None for legacy = Ok)
            if let Err(reason) = check_new_constraints(&rule.constraints, ctx) {
                skipped_rules.push(RuleSkip {
                    rule_index,
                    description: rule_desc,
                    reason,
                });
                continue;
            }

            // 5. Cap-scoped fs permission guard for non-bash verbs (new-format rules)
            if ctx.verb_str != "bash"
                && let Err(reason) = check_cap_scoped_fs_guard(&rule.constraints, ctx)
            {
                skipped_rules.push(RuleSkip {
                    rule_index,
                    description: rule_desc,
                    reason,
                });
                continue;
            }

            // 6. Profile guard (legacy-converted rules)
            if let Err(reason) = self.check_profile(&rule.profile_guard, ctx) {
                skipped_rules.push(RuleSkip {
                    rule_index,
                    description: rule_desc,
                    reason: format!("constraint failed: {}", reason),
                });
                continue;
            }

            let active_constraints = has_active_constraints(&rule.constraints, ctx.verb);
            matched_rules.push(RuleMatch {
                rule_index,
                description: rule_desc,
                effect: rule.effect,
                has_active_constraints: active_constraints,
            });

            match rule.effect {
                Effect::Deny => {
                    has_deny = true;
                    if deny_reason.is_none() {
                        deny_reason = rule.reason.as_deref();
                    }
                }
                Effect::Ask => {
                    has_ask = true;
                    if ask_reason.is_none() {
                        ask_reason = rule.reason.as_deref();
                    }
                    if active_constraints {
                        has_constrained_ask = true;
                        if constrained_ask_reason.is_none() {
                            constrained_ask_reason = rule.reason.as_deref();
                        }
                    }
                }
                Effect::Allow => {
                    has_allow = true;
                    if active_constraints {
                        has_constrained_allow = true;
                    }
                    // Collect inline constraint fs entries (new-format, bash only)
                    if ctx.verb_str == "bash"
                        && let Some(ref constraints) = rule.constraints
                    {
                        if let Some(ref fs_entries) = constraints.fs {
                            for (caps, compiled_fs) in fs_entries {
                                allow_fs_entries.push((compiled_fs, *caps));
                            }
                        }
                        if constraints.network == Some(NetworkPolicy::Deny) {
                            merged_network = NetworkPolicy::Deny;
                        }
                    }
                    // Collect profile guards (legacy-converted, for sandbox generation)
                    if let Some(ref profile_guard) = rule.profile_guard {
                        allow_profile_guards.push(profile_guard);
                    }
                }
            }
        }

        // Precedence: deny > (specificity-aware) ask/allow
        //
        // 1. Deny always wins (safety is absolute)
        // 2. Among non-deny rules, constrained rules beat unconstrained:
        //    - Constrained ask > constrained allow (same tier, ask > allow)
        //    - Constrained allow > unconstrained ask (specificity wins)
        // 3. Within unconstrained: ask > allow (original behavior)
        if has_deny {
            let trace = DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution: "result: deny (deny > ask > allow)".into(),
            };
            return PolicyDecision {
                effect: Effect::Deny,
                reason: deny_reason.map(|s| s.to_string()),
                trace,
                sandbox: None,
            };
        }

        // Tier 1: constrained rules take precedence over unconstrained
        if has_constrained_ask || has_constrained_allow {
            if has_constrained_ask {
                let trace = DecisionTrace {
                    matched_rules,
                    skipped_rules,
                    final_resolution: "result: ask (constrained ask > constrained allow)".into(),
                };
                return PolicyDecision {
                    effect: Effect::Ask,
                    reason: constrained_ask_reason.map(|s| s.to_string()),
                    trace,
                    sandbox: None,
                };
            }
            // has_constrained_allow only
            let sandbox = if ctx.verb_str == "bash" {
                self.generate_unified_sandbox(
                    &allow_fs_entries,
                    merged_network,
                    &allow_profile_guards,
                    ctx.cwd,
                )
            } else {
                None
            };
            let resolution = if has_ask {
                "result: allow (constrained allow > unconstrained ask)"
            } else {
                "result: allow"
            };
            let trace = DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution: resolution.into(),
            };
            return PolicyDecision {
                effect: Effect::Allow,
                reason: None,
                trace,
                sandbox,
            };
        }

        // Tier 0: unconstrained rules — original behavior
        if has_ask {
            let trace = DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution: "result: ask (ask > allow)".into(),
            };
            return PolicyDecision {
                effect: Effect::Ask,
                reason: ask_reason.map(|s| s.to_string()),
                trace,
                sandbox: None,
            };
        }
        if has_allow {
            let sandbox = if ctx.verb_str == "bash" {
                self.generate_unified_sandbox(
                    &allow_fs_entries,
                    merged_network,
                    &allow_profile_guards,
                    ctx.cwd,
                )
            } else {
                None
            };
            let trace = DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution: "result: allow".into(),
            };
            return PolicyDecision {
                effect: Effect::Allow,
                reason: None,
                trace,
                sandbox,
            };
        }

        // No match → default
        let trace = DecisionTrace {
            matched_rules,
            skipped_rules,
            final_resolution: format!("no rules matched; default: {}", self.default),
        };
        PolicyDecision {
            effect: self.default,
            reason: None,
            trace,
            sandbox: None,
        }
    }

    /// Generate a sandbox policy from ALL allow rules in the active profile.
    ///
    /// Unlike `generate_unified_sandbox` (which uses only rules that matched a
    /// specific request), this collects sandbox-relevant constraints from every
    /// allow rule regardless of matching. This provides a profile-wide sandbox
    /// for the `clash sandbox exec --profile` CLI.
    pub fn sandbox_for_active_profile(&self, cwd: &str) -> Option<SandboxPolicy> {
        let mut inline_fs_entries: Vec<(&CompiledFilterExpr, Cap)> = Vec::new();
        let mut merged_network = NetworkPolicy::Allow;
        let mut profile_guards: Vec<&ProfileExpr> = Vec::new();

        for rule in &self.active_profile_rules {
            if rule.effect != Effect::Allow {
                continue;
            }

            if let Some(ref constraints) = rule.constraints {
                if let Some(ref fs_entries) = constraints.fs {
                    for (caps, compiled_fs) in fs_entries {
                        inline_fs_entries.push((compiled_fs, *caps));
                    }
                }
                if constraints.network == Some(NetworkPolicy::Deny) {
                    merged_network = NetworkPolicy::Deny;
                }
            }

            if let Some(ref profile_guard) = rule.profile_guard {
                profile_guards.push(profile_guard);
            }
        }

        self.generate_unified_sandbox(&inline_fs_entries, merged_network, &profile_guards, cwd)
    }

    /// Generate a sandbox policy from both inline constraints and profile guards.
    ///
    /// Two sources are merged:
    /// - Inline constraint fs entries: cap-scoped `(filter, cap)` pairs from new-format rules
    /// - Profile guard expressions: legacy-format profile expressions evaluated via
    ///   `generate_sandbox_from_profiles()`
    ///
    /// If neither source produces fs constraints, returns `None`.
    fn generate_unified_sandbox(
        &self,
        inline_fs_entries: &[(&CompiledFilterExpr, Cap)],
        inline_network: NetworkPolicy,
        profile_guards: &[&ProfileExpr],
        cwd: &str,
    ) -> Option<SandboxPolicy> {
        let has_inline = !inline_fs_entries.is_empty();
        let profile_sandbox = self.generate_sandbox_from_profiles(profile_guards, cwd);

        if !has_inline && profile_sandbox.is_none() {
            return None;
        }

        let mut rules = Vec::new();
        let mut network = inline_network;

        // Collect rules from inline constraint fs entries
        for (fs_expr, caps) in inline_fs_entries {
            filter_to_sandbox_rules(fs_expr, RuleEffect::Allow, *caps, cwd, &mut rules);
        }

        // Merge in rules from profile-guard-based sandbox
        if let Some(profile_sb) = profile_sandbox {
            rules.extend(profile_sb.rules);
            if profile_sb.network == NetworkPolicy::Deny {
                network = NetworkPolicy::Deny;
            }
        }

        Some(SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules,
            network,
        })
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
}

// ---------------------------------------------------------------------------
// Statement matching
// ---------------------------------------------------------------------------

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
        if ctx.verb_str != "bash"
            && let Some(ref fs) = self.fs
            && !fs.matches(ctx.noun, ctx.cwd)
        {
            return Err(format!(
                "fs constraint: '{}' does not match filter",
                ctx.noun
            ));
        }

        let empty = Vec::new();
        let forbid_args = self.forbid_args.as_deref().unwrap_or(&empty);
        let require_args = self.require_args.as_deref().unwrap_or(&empty);

        check_shell_constraints(
            ctx.noun,
            self.pipe,
            self.redirect,
            forbid_args,
            require_args,
        )
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

/// Check if a rule has inline constraints that were actively evaluated for
/// the given verb. Used for specificity-aware precedence: constrained rules
/// beat unconstrained rules among non-deny effects.
///
/// "Active" means the constraint actually narrows the set of matching requests:
/// - URL, args, pipe, redirect constraints are always active when present
/// - Fs constraints are only active for read/write/edit (where they act as
///   permission guards), NOT for bash/webfetch/etc. (where fs is either used
///   for sandbox generation or skipped entirely)
fn has_active_constraints(constraints: &Option<CompiledInlineConstraints>, verb: &Verb) -> bool {
    let c = match constraints {
        Some(c) => c,
        None => return false,
    };

    // Tool-input constraints always count
    if !c.require_urls.is_empty() || !c.forbid_urls.is_empty() {
        return true;
    }
    if !c.forbid_args.is_empty() || !c.require_args.is_empty() {
        return true;
    }
    if c.pipe.is_some() || c.redirect.is_some() {
        return true;
    }

    // Fs constraints count only for verbs where the fs guard is evaluated
    if matches!(verb, Verb::Read | Verb::Write | Verb::Edit)
        && let Some(ref fs) = c.fs
        && !fs.is_empty()
    {
        return true;
    }

    false
}

/// Shared logic for checking pipe, redirect, forbid-args, and require-args
/// constraints against a command string.
///
/// Used by both `CompiledConstraintDef::eval()` (legacy named constraints) and
/// `check_new_constraints()` (new-format inline constraints).
fn check_shell_constraints(
    noun: &str,
    pipe: Option<bool>,
    redirect: Option<bool>,
    forbid_args: &[String],
    require_args: &[String],
) -> Result<(), String> {
    // Check pipe constraint
    if let Some(allow_pipe) = pipe
        && !allow_pipe
        && command_has_pipe(noun)
    {
        return Err("pipe constraint: command contains '|'".into());
    }

    // Check redirect constraint
    if let Some(allow_redirect) = redirect
        && !allow_redirect
        && command_has_redirect(noun)
    {
        return Err("redirect constraint: command contains '>' or '<'".into());
    }

    // Check forbidden arguments
    if !forbid_args.is_empty() {
        let args = tokenize_command(noun);
        for forbidden_arg in forbid_args {
            if args.iter().any(|a| a == forbidden_arg) {
                return Err(format!(
                    "forbid-args: found forbidden arg '{}'",
                    forbidden_arg
                ));
            }
        }
    }

    // Check required arguments (at least one must be present)
    if !require_args.is_empty() {
        let args = tokenize_command(noun);
        if !require_args.iter().any(|req| args.iter().any(|a| a == req)) {
            return Err(format!(
                "require-args: none of {:?} found in command",
                require_args
            ));
        }
    }

    Ok(())
}

/// Check non-fs inline constraints (pipe, redirect, args, url).
/// Returns `Ok(())` if satisfied, or `Err(reason)` explaining why not.
fn check_new_constraints(
    constraints: &Option<CompiledInlineConstraints>,
    ctx: &EvalContext,
) -> Result<(), String> {
    let constraints = match constraints {
        Some(c) => c,
        None => return Ok(()),
    };

    check_shell_constraints(
        ctx.noun,
        constraints.pipe,
        constraints.redirect,
        &constraints.forbid_args,
        &constraints.require_args,
    )?;

    check_url_constraints(ctx, &constraints.forbid_urls, &constraints.require_urls)
}

/// Check URL constraints against the request's URL.
///
/// The URL is extracted from `tool_input.url`, falling back to the noun.
/// Patterns without `://` are matched against the URL's host (domain matching).
/// Patterns with `://` are matched against the full URL (glob matching).
fn check_url_constraints(
    ctx: &EvalContext,
    forbid_urls: &[String],
    require_urls: &[String],
) -> Result<(), String> {
    if forbid_urls.is_empty() && require_urls.is_empty() {
        return Ok(());
    }

    let url = ctx
        .tool_input
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or(ctx.noun);

    let host = extract_url_host(url);

    for pattern in forbid_urls {
        if url_pattern_matches(pattern, url, &host) {
            return Err(format!(
                "url constraint: URL matches forbidden pattern '{}'",
                pattern
            ));
        }
    }

    if !require_urls.is_empty()
        && !require_urls
            .iter()
            .any(|p| url_pattern_matches(p, url, &host))
    {
        return Err(format!(
            "url constraint: URL does not match any required pattern {:?}",
            require_urls
        ));
    }

    Ok(())
}

/// Extract the host from a URL string.
///
/// Finds `://`, takes everything after it until the next `/`, `?`, `#`, or end,
/// then strips any port suffix.
fn extract_url_host(url: &str) -> String {
    let after_scheme = url.find("://").map(|i| &url[i + 3..]).unwrap_or(url);

    let host_port = after_scheme
        .find(['/', '?', '#'])
        .map(|i| &after_scheme[..i])
        .unwrap_or(after_scheme);

    // Strip port
    if let Some(colon) = host_port.rfind(':')
        && host_port[colon + 1..].chars().all(|c| c.is_ascii_digit())
    {
        return host_port[..colon].to_string();
    }

    host_port.to_string()
}

/// Check if a pattern matches a URL.
///
/// Patterns with `://` are full URL globs matched against the entire URL.
/// Patterns without `://` are domain patterns matched against the host.
fn url_pattern_matches(pattern: &str, full_url: &str, host: &str) -> bool {
    if pattern.contains("://") {
        super::ast::policy_glob_matches(pattern, full_url)
    } else {
        domain_matches(pattern, host)
    }
}

/// Check if a host matches a domain pattern.
///
/// - `"github.com"` matches `"github.com"` exactly.
/// - `"*.github.com"` matches `"api.github.com"`, `"raw.github.com"`, etc.
fn domain_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{}", suffix))
    } else {
        host == pattern
    }
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
        Verb::Execute => return Ok(()), // unknown tools (bash filtered upstream)
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
// Rule description (for explanation strings)
// ---------------------------------------------------------------------------

/// Build a human-readable description of a profile rule for explanations.
fn describe_rule(rule: &CompiledProfileRule) -> String {
    let noun_str = format_compiled_pattern(&rule.noun_matcher);
    let profile_suffix = if let Some(ref guard) = rule.profile_guard {
        format!(" : {}", guard)
    } else {
        String::new()
    };
    format!(
        "{} {} {} -> {}{}",
        rule.effect, rule.verb, noun_str, rule.effect, profile_suffix,
    )
}

/// Format a compiled pattern back to its source representation.
fn format_compiled_pattern(pattern: &CompiledPattern) -> String {
    match pattern {
        CompiledPattern::Match(expr) => format_compiled_match_expr(expr),
        CompiledPattern::Not(expr) => format!("!{}", format_compiled_match_expr(expr)),
    }
}

/// Format a compiled match expression back to its source representation.
fn format_compiled_match_expr(expr: &CompiledMatchExpr) -> String {
    match expr {
        CompiledMatchExpr::Any => "*".to_string(),
        CompiledMatchExpr::Exact(s) => s.clone(),
        CompiledMatchExpr::Glob { pattern, .. } => pattern.clone(),
        CompiledMatchExpr::Typed {
            entity_type,
            name: None,
        } => entity_type.to_string(),
        CompiledMatchExpr::Typed {
            entity_type,
            name: Some(name),
        } => format!("{}:{}", entity_type, name),
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Resolve a path relative to cwd. Handles `.` as cwd and `~` as home dir.
pub(crate) fn resolve_path(path: &str, cwd: &str) -> PathBuf {
    // Expand tilde to home directory
    let expanded: std::borrow::Cow<str> = if path == "~" {
        dirs::home_dir()
            .map(|p| std::borrow::Cow::Owned(p.to_string_lossy().into_owned()))
            .unwrap_or(std::borrow::Cow::Borrowed(path))
    } else if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .map(|p| std::borrow::Cow::Owned(format!("{}/{}", p.to_string_lossy(), rest)))
            .unwrap_or(std::borrow::Cow::Borrowed(path))
    } else {
        std::borrow::Cow::Borrowed(path)
    };

    let p = Path::new(expanded.as_ref());
    if p.is_absolute() {
        lexical_normalize(p)
    } else if expanded.as_ref() == "." {
        lexical_normalize(Path::new(cwd))
    } else if expanded.starts_with("./") || expanded.starts_with("..") {
        lexical_normalize(&Path::new(cwd).join(expanded.as_ref()))
    } else {
        // Bare relative path — resolve against cwd
        lexical_normalize(&Path::new(cwd).join(expanded.as_ref()))
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

// ---------------------------------------------------------------------------
// ShellScanner — shared quote-tracking state machine
// ---------------------------------------------------------------------------

/// Context for a character yielded by [`ShellScanner`].
///
/// Each item tells the caller whether the character is inside quotes and what
/// the previous (unescaped) character was, so callers can make per-character
/// decisions without reimplementing the quoting state machine.
struct ShellChar {
    ch: char,
    /// `true` when the character is inside single or double quotes (or escaped).
    quoted: bool,
    /// `true` when this character is a quoting delimiter (an opening/closing
    /// quote mark) rather than content. Tokenizers use this to strip delimiters
    /// while keeping quoted content like `'` inside double quotes.
    is_delimiter: bool,
    /// The previous non-escaped character (used for detecting `$(` sequences).
    prev: char,
}

/// Iterator that walks a command string while tracking POSIX-sh quoting state.
///
/// Yields one [`ShellChar`] per *logical* character, automatically handling:
/// - Single-quote regions (no escapes inside)
/// - Double-quote regions (`\"` and `\\` are the only escapes)
/// - Backslash escapes outside quotes
///
/// Characters that are part of the quoting syntax itself (the quote delimiters,
/// escape backslashes) are NOT yielded. Only content characters are produced,
/// each annotated with quoting context.
struct ShellScanner<'a> {
    chars: std::iter::Peekable<std::str::Chars<'a>>,
    in_single_quote: bool,
    in_double_quote: bool,
    prev_char: char,
}

impl<'a> ShellScanner<'a> {
    fn new(command: &'a str) -> Self {
        Self {
            chars: command.chars().peekable(),
            in_single_quote: false,
            in_double_quote: false,
            prev_char: ' ',
        }
    }
}

impl Iterator for ShellScanner<'_> {
    type Item = ShellChar;

    fn next(&mut self) -> Option<ShellChar> {
        let ch = self.chars.next()?;

        // Inside single quotes: everything is literal until the closing quote.
        if self.in_single_quote {
            let is_closing = ch == '\'';
            if is_closing {
                self.in_single_quote = false;
            }
            let item = ShellChar {
                ch,
                quoted: true,
                is_delimiter: is_closing,
                prev: self.prev_char,
            };
            self.prev_char = ch;
            return Some(item);
        }

        // Inside double quotes: backslash escapes `"` and `\` only.
        if self.in_double_quote {
            if ch == '"' {
                self.in_double_quote = false;
                let item = ShellChar {
                    ch,
                    quoted: true,
                    is_delimiter: true,
                    prev: self.prev_char,
                };
                self.prev_char = ch;
                return Some(item);
            }
            if ch == '\\'
                && let Some(&next) = self.chars.peek()
                && (next == '"' || next == '\\')
            {
                // Consume the escaped character and yield it as content.
                self.chars.next();
                let item = ShellChar {
                    ch: next,
                    quoted: true,
                    is_delimiter: false,
                    prev: self.prev_char,
                };
                self.prev_char = next;
                return Some(item);
            }
            // Backslash before other chars is literal inside double quotes.
            let item = ShellChar {
                ch,
                quoted: true,
                is_delimiter: false,
                prev: self.prev_char,
            };
            self.prev_char = ch;
            return Some(item);
        }

        // Outside quotes.
        match ch {
            '\'' => {
                self.in_single_quote = true;
                let item = ShellChar {
                    ch,
                    quoted: true,
                    is_delimiter: true,
                    prev: self.prev_char,
                };
                self.prev_char = ch;
                Some(item)
            }
            '"' => {
                self.in_double_quote = true;
                let item = ShellChar {
                    ch,
                    quoted: true,
                    is_delimiter: true,
                    prev: self.prev_char,
                };
                self.prev_char = ch;
                Some(item)
            }
            '\\' => {
                // Backslash escapes the next character.
                if let Some(next) = self.chars.next() {
                    let item = ShellChar {
                        ch: next,
                        quoted: true,
                        is_delimiter: false,
                        prev: self.prev_char,
                    };
                    self.prev_char = next;
                    Some(item)
                } else {
                    // Trailing backslash with nothing after it.
                    let item = ShellChar {
                        ch,
                        quoted: false,
                        is_delimiter: false,
                        prev: self.prev_char,
                    };
                    self.prev_char = ch;
                    Some(item)
                }
            }
            _ => {
                let item = ShellChar {
                    ch,
                    quoted: false,
                    is_delimiter: false,
                    prev: self.prev_char,
                };
                self.prev_char = ch;
                Some(item)
            }
        }
    }
}

/// Check if a [`ShellChar`] represents an unquoted command substitution
/// (`$(` or backtick).
///
/// Shared helper used by both `command_has_pipe` and `command_has_redirect`,
/// which conservatively treat command substitutions as dangerous.
fn has_unquoted_command_substitution(sc: &ShellChar) -> bool {
    if sc.quoted {
        return false;
    }
    matches!(
        sc.ch,
        '`' | '(' if sc.ch == '`' || sc.prev == '$'
    )
}

/// Check if a command string contains shell pipe operators.
///
/// Also conservatively returns true for unquoted command substitution (`$(` or
/// backtick), since those may contain pipes or redirects internally.
pub(crate) fn command_has_pipe(command: &str) -> bool {
    for sc in ShellScanner::new(command) {
        if has_unquoted_command_substitution(&sc) {
            return true;
        }
        if !sc.quoted && sc.ch == '|' {
            return true;
        }
    }
    false
}

/// Check if a command string contains shell redirect operators.
///
/// Also conservatively returns true for unquoted command substitution (`$(` or
/// backtick), since those may contain pipes or redirects internally.
pub(crate) fn command_has_redirect(command: &str) -> bool {
    for sc in ShellScanner::new(command) {
        if has_unquoted_command_substitution(&sc) {
            return true;
        }
        if !sc.quoted && (sc.ch == '>' || sc.ch == '<') {
            return true;
        }
    }
    false
}

/// Tokenize a command string with shell-aware quoting.
///
/// Handles POSIX sh quoting rules:
/// - Single quotes: everything inside is literal (no escapes at all)
/// - Double quotes: backslash escapes `"` and `\` inside
/// - Outside quotes: backslash escapes the next character
/// - Quotes are stripped from resulting tokens
///
/// Does NOT handle command substitution, variable expansion, or other shell
/// features — only quoting/escaping for accurate argument splitting.
pub(crate) fn tokenize_command(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();

    for sc in ShellScanner::new(command) {
        if sc.is_delimiter {
            // Skip quote delimiters — they are stripped from tokens.
            continue;
        }
        if sc.quoted {
            // Quoted content character — always append to current token.
            current.push(sc.ch);
        } else if sc.ch.is_whitespace() {
            // Unquoted whitespace — finish the current token.
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            // Unquoted non-whitespace — accumulate.
            current.push(sc.ch);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_basic_splitting() {
        assert_eq!(
            tokenize_command("git push --force"),
            vec!["git", "push", "--force"]
        );
        assert_eq!(tokenize_command("ls -la /tmp"), vec!["ls", "-la", "/tmp"]);
        assert_eq!(tokenize_command("  spaced   out  "), vec!["spaced", "out"]);
        assert_eq!(tokenize_command(""), Vec::<String>::new());
        assert_eq!(tokenize_command("single"), vec!["single"]);
    }

    #[test]
    fn test_tokenize_single_quoted_args() {
        // Single quotes: everything is literal, no escapes
        assert_eq!(
            tokenize_command("echo 'hello world'"),
            vec!["echo", "hello world"]
        );
        assert_eq!(
            tokenize_command("grep -E 'a|b' file"),
            vec!["grep", "-E", "a|b", "file"]
        );
        // Backslash is literal inside single quotes
        assert_eq!(
            tokenize_command("echo 'back\\slash'"),
            vec!["echo", "back\\slash"]
        );
        // Security: quoted --force must be stripped to --force
        assert_eq!(
            tokenize_command("git push '--force'"),
            vec!["git", "push", "--force"]
        );
    }

    #[test]
    fn test_tokenize_double_quoted_args() {
        assert_eq!(
            tokenize_command(r#"echo "hello world""#),
            vec!["echo", "hello world"]
        );
        // Backslash escapes " and \ inside double quotes
        assert_eq!(
            tokenize_command(r#"echo "say \"hi\"""#),
            vec!["echo", r#"say "hi""#]
        );
        assert_eq!(
            tokenize_command(r#"echo "back\\slash""#),
            vec!["echo", "back\\slash"]
        );
        // Backslash before other chars is literal
        assert_eq!(
            tokenize_command(r#"echo "hello\nworld""#),
            vec!["echo", "hello\\nworld"]
        );
        // Security: double-quoted --force must be stripped to --force
        assert_eq!(
            tokenize_command(r#"git push "--force""#),
            vec!["git", "push", "--force"]
        );
    }

    #[test]
    fn test_tokenize_backslash_escapes() {
        // Outside quotes, backslash escapes the next character
        assert_eq!(
            tokenize_command(r"echo hello\ world"),
            vec!["echo", "hello world"]
        );
        assert_eq!(
            tokenize_command(r"echo back\\slash"),
            vec!["echo", "back\\slash"]
        );
    }

    #[test]
    fn test_tokenize_mixed_quoting() {
        // Mixed single and double quotes
        assert_eq!(
            tokenize_command(r#"cmd 'single' "double" plain"#),
            vec!["cmd", "single", "double", "plain"]
        );
        // Adjacent quoting styles merge into one token
        assert_eq!(
            tokenize_command(r#"echo 'hello'" world""#),
            vec!["echo", "hello world"]
        );
        // Single quote inside double quotes is literal
        assert_eq!(tokenize_command(r#"echo "it's""#), vec!["echo", "it's"]);
        // Double quote inside single quotes is literal
        assert_eq!(
            tokenize_command(r#"echo '"hello"'"#),
            vec!["echo", r#""hello""#]
        );
    }

    #[test]
    fn test_command_has_pipe_with_substitution() {
        // Unquoted command substitution should be detected
        assert!(command_has_pipe("echo $(cat foo)"));
        assert!(command_has_pipe("echo `cat foo`"));
        // Quoted command substitution should NOT be detected
        assert!(!command_has_pipe("echo '$(cat foo)'"));
        assert!(!command_has_pipe("echo '`cat foo`'"));
    }

    #[test]
    fn test_command_has_redirect_with_substitution() {
        // Unquoted command substitution should be detected
        assert!(command_has_redirect("echo $(cat foo)"));
        assert!(command_has_redirect("echo `cat foo`"));
        // Quoted command substitution should NOT be detected
        assert!(!command_has_redirect("echo '$(cat foo)'"));
        assert!(!command_has_redirect("echo '`cat foo`'"));
    }

    #[test]
    fn test_command_has_pipe_single_quote_backslash() {
        // Backslash is NOT an escape char inside single quotes (POSIX sh).
        // 'hello\' ends the single-quoted region at the second quote.
        // Then | is unquoted, so this should be detected as having a pipe.
        assert!(command_has_pipe("echo 'hello\\' | grep x"));
    }

    #[test]
    fn test_extract_url_host_basic() {
        assert_eq!(extract_url_host("https://github.com/foo"), "github.com");
        assert_eq!(extract_url_host("http://example.com"), "example.com");
        assert_eq!(
            extract_url_host("https://api.github.com/repos"),
            "api.github.com"
        );
    }

    #[test]
    fn test_extract_url_host_with_port() {
        assert_eq!(extract_url_host("http://localhost:8080/path"), "localhost");
        assert_eq!(
            extract_url_host("https://example.com:443/foo"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_url_host_with_query_and_fragment() {
        assert_eq!(
            extract_url_host("https://example.com/path?q=1"),
            "example.com"
        );
        assert_eq!(
            extract_url_host("https://example.com#section"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_url_host_no_scheme() {
        // Fallback: no :// means the whole string is treated as host
        assert_eq!(extract_url_host("github.com"), "github.com");
    }

    #[test]
    fn test_domain_matches_exact() {
        assert!(domain_matches("github.com", "github.com"));
        assert!(!domain_matches("github.com", "evil.com"));
        assert!(!domain_matches("github.com", "notgithub.com"));
    }

    #[test]
    fn test_domain_matches_wildcard() {
        assert!(domain_matches("*.github.com", "api.github.com"));
        assert!(domain_matches("*.github.com", "raw.github.com"));
        // The wildcard suffix itself should also match
        assert!(domain_matches("*.github.com", "github.com"));
        // Should NOT match unrelated domains
        assert!(!domain_matches("*.github.com", "evil.com"));
        assert!(!domain_matches("*.github.com", "fakegithub.com"));
    }

    #[test]
    fn test_url_pattern_matches_domain() {
        // Plain domain patterns delegate to domain_matches
        assert!(url_pattern_matches(
            "github.com",
            "https://github.com/foo",
            "github.com"
        ));
        assert!(!url_pattern_matches(
            "github.com",
            "https://evil.com/foo",
            "evil.com"
        ));
    }

    #[test]
    fn test_url_pattern_matches_full_url_glob() {
        // Patterns with :// use full URL glob matching
        assert!(url_pattern_matches(
            "https://github.com/*",
            "https://github.com/foo/bar",
            "github.com"
        ));
        assert!(!url_pattern_matches(
            "https://github.com/*",
            "https://evil.com/foo",
            "evil.com"
        ));
    }
}
