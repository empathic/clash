//! Policy evaluation engine.
//!
//! Evaluates requests against compiled policies using the deny > ask > allow
//! precedence model. Sandbox generation is handled by `sandbox_gen`.

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
    /// Precedence: deny > ask > allow.
    #[instrument(level = Level::TRACE, skip(self))]
    pub fn evaluate_with_context(&self, ctx: &EvalContext) -> PolicyDecision {
        let mut has_allow = false;
        let mut has_ask = false;
        let mut has_deny = false;

        let mut deny_reason: Option<&str> = None;
        let mut ask_reason: Option<&str> = None;

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

            matched_rules.push(RuleMatch {
                rule_index,
                description: rule_desc,
                effect: rule.effect,
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
                }
                Effect::Allow => {
                    has_allow = true;
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

        // Precedence: deny > ask > allow
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
        if ctx.verb_str != "bash" {
            if let Some(ref fs) = self.fs
                && !fs.matches(ctx.noun, ctx.cwd)
            {
                return Err(format!(
                    "fs constraint: '{}' does not match filter",
                    ctx.noun
                ));
            }
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

    check_shell_constraints(
        ctx.noun,
        constraints.pipe,
        constraints.redirect,
        &constraints.forbid_args,
        &constraints.require_args,
    )
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
    let profile_suffix = if let Some(ref guard) = rule.profile_guard {
        format!(" : {}", guard)
    } else {
        String::new()
    };
    format!(
        "{} {} * -> {}{}",
        rule.effect, rule.verb, rule.effect, profile_suffix,
    )
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

/// Check if a command string contains shell pipe operators.
///
/// Also conservatively returns true for unquoted command substitution (`$(` or
/// backtick), since those may contain pipes or redirects internally.
pub(crate) fn command_has_pipe(command: &str) -> bool {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = ' ';
    let mut escaped = false;

    for ch in command.chars() {
        if escaped {
            escaped = false;
            prev_char = ch;
            continue;
        }
        if !in_single_quote && !in_double_quote && ch == '\\' {
            escaped = true;
            prev_char = ch;
            continue;
        }
        match ch {
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote && prev_char != '\\' => in_double_quote = !in_double_quote,
            '|' if !in_single_quote && !in_double_quote => return true,
            '(' if !in_single_quote && !in_double_quote && prev_char == '$' => return true,
            '`' if !in_single_quote && !in_double_quote => return true,
            _ => {}
        }
        prev_char = ch;
    }
    false
}

/// Check if a command string contains shell redirect operators.
///
/// Also conservatively returns true for unquoted command substitution (`$(` or
/// backtick), since those may contain pipes or redirects internally.
pub(crate) fn command_has_redirect(command: &str) -> bool {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = ' ';
    let mut escaped = false;

    for ch in command.chars() {
        if escaped {
            escaped = false;
            prev_char = ch;
            continue;
        }
        if !in_single_quote && !in_double_quote && ch == '\\' {
            escaped = true;
            prev_char = ch;
            continue;
        }
        match ch {
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote && prev_char != '\\' => in_double_quote = !in_double_quote,
            '>' | '<' if !in_single_quote && !in_double_quote => return true,
            '(' if !in_single_quote && !in_double_quote && prev_char == '$' => return true,
            '`' if !in_single_quote && !in_double_quote => return true,
            _ => {}
        }
        prev_char = ch;
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
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_single_quote {
            // Inside single quotes: everything is literal until closing quote
            if ch == '\'' {
                in_single_quote = false;
            } else {
                current.push(ch);
            }
        } else if in_double_quote {
            // Inside double quotes: backslash escapes " and \ only
            if ch == '"' {
                in_double_quote = false;
            } else if ch == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == '"' || next == '\\' {
                        current.push(next);
                        chars.next();
                    } else {
                        // Backslash is literal if not followed by " or \
                        current.push(ch);
                    }
                } else {
                    current.push(ch);
                }
            } else {
                current.push(ch);
            }
        } else {
            // Outside quotes
            match ch {
                '\'' => in_single_quote = true,
                '"' => in_double_quote = true,
                '\\' => {
                    // Backslash escapes the next character
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            }
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
}
