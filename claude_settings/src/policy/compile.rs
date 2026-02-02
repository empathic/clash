//! Compilation of policy documents into optimized runtime representations.
//!
//! The `CompiledPolicy` pre-compiles glob patterns into regexes and
//! organizes statements for efficient evaluation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use regex::Regex;
use super::*;
use crate::sandbox::{Cap, NetworkPolicy, RuleEffect, SandboxPolicy, SandboxRule};

/// A compiled policy ready for fast evaluation.
#[derive(Debug)]
pub struct CompiledPolicy {
    /// Default effect when no statement matches.
    pub default: Effect,
    /// Compiled statements in evaluation order.
    pub statements: Vec<CompiledStatement>,
    /// Compiled constraint definitions (name → compiled constraint).
    constraints: HashMap<String, CompiledConstraintDef>,
    /// Profile definitions (name → profile expression).
    profiles: HashMap<String, ProfileExpr>,
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
    /// Optional constraint binding (profile expression).
    pub profile: Option<ProfileExpr>,
}

/// A compiled constraint definition with pre-compiled regexes.
#[derive(Debug)]
struct CompiledConstraintDef {
    fs: Option<CompiledFilterExpr>,
    caps: Option<Cap>,
    network: Option<NetworkPolicy>,
    pipe: Option<bool>,
    redirect: Option<bool>,
    forbid_args: Option<Vec<String>>,
    require_args: Option<Vec<String>>,
}

/// A compiled filter expression with pre-compiled regexes.
#[derive(Debug)]
enum CompiledFilterExpr {
    Subpath(String),
    Literal(String),
    Regex(Regex),
    And(Box<CompiledFilterExpr>, Box<CompiledFilterExpr>),
    Or(Box<CompiledFilterExpr>, Box<CompiledFilterExpr>),
    Not(Box<CompiledFilterExpr>),
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
    #[error("invalid regex in filter '{pattern}': {source}")]
    InvalidFilterRegex {
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

        // Compile constraint definitions
        let mut constraints = HashMap::new();
        for (name, def) in &doc.constraints {
            constraints.insert(name.clone(), CompiledConstraintDef::compile(def)?);
        }

        Ok(CompiledPolicy {
            default: doc.policy.default,
            statements,
            constraints,
            profiles: doc.profiles.clone(),
        })
    }

    /// Evaluate a request against this policy (backward-compatible version).
    ///
    /// Returns the resulting effect after applying all matching statements
    /// with precedence: deny > ask > allow > delegate.
    ///
    /// If no statement matches, returns the configured default effect.
    ///
    /// This version creates a minimal `EvalContext` without cwd or tool_input.
    /// For full constraint evaluation, use `evaluate_with_context`.
    pub fn evaluate(&self, entity: &str, verb: &Verb, noun: &str) -> PolicyDecision {
        let ctx = EvalContext {
            entity,
            verb,
            noun,
            cwd: "",
            tool_input: &serde_json::Value::Null,
        };
        self.evaluate_with_context(&ctx)
    }

    /// Evaluate a request against this policy with full context.
    ///
    /// The `EvalContext` provides cwd and tool_input for constraint evaluation.
    pub fn evaluate_with_context(&self, ctx: &EvalContext) -> PolicyDecision {
        let mut has_allow = false;
        let mut has_ask = false;
        let mut has_deny = false;
        let mut has_delegate = false;

        let mut deny_reason: Option<&str> = None;
        let mut ask_reason: Option<&str> = None;
        let mut delegate_config: Option<&DelegateConfig> = None;

        // Track profiles from matched allow statements (for sandbox generation).
        let mut allow_profiles: Vec<&ProfileExpr> = Vec::new();

        for stmt in &self.statements {
            if stmt.matches(ctx.entity, ctx.verb, ctx.noun)
                && self.check_profile(&stmt.profile, ctx)
            {
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
        }

        // Precedence: deny > ask > allow > delegate
        if has_deny {
            return PolicyDecision {
                effect: Effect::Deny,
                reason: deny_reason.map(|s| s.to_string()),
                delegate: None,
                sandbox: None,
            };
        }
        if has_ask {
            return PolicyDecision {
                effect: Effect::Ask,
                reason: ask_reason.map(|s| s.to_string()),
                delegate: None,
                sandbox: None,
            };
        }
        if has_allow {
            // For bash commands, generate sandbox from matched allow profiles.
            let sandbox = if *ctx.verb == Verb::Execute {
                self.generate_sandbox_from_profiles(&allow_profiles, ctx.cwd)
            } else {
                None
            };
            return PolicyDecision {
                effect: Effect::Allow,
                reason: None,
                delegate: None,
                sandbox,
            };
        }
        if has_delegate {
            return PolicyDecision {
                effect: Effect::Delegate,
                reason: None,
                delegate: delegate_config.cloned(),
                sandbox: None,
            };
        }

        // No match → default
        PolicyDecision {
            effect: self.default,
            reason: None,
            delegate: None,
            sandbox: None,
        }
    }

    /// Check if a profile expression is satisfied for the given context.
    /// If no profile is specified, the check passes (unconditional rule).
    fn check_profile(&self, profile: &Option<ProfileExpr>, ctx: &EvalContext) -> bool {
        match profile {
            None => true,
            Some(expr) => self.eval_profile_expr(expr, ctx),
        }
    }

    /// Evaluate a profile expression recursively.
    fn eval_profile_expr(&self, expr: &ProfileExpr, ctx: &EvalContext) -> bool {
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
                false
            }
            ProfileExpr::And(a, b) => {
                self.eval_profile_expr(a, ctx) && self.eval_profile_expr(b, ctx)
            }
            ProfileExpr::Or(a, b) => {
                self.eval_profile_expr(a, ctx) || self.eval_profile_expr(b, ctx)
            }
            ProfileExpr::Not(inner) => !self.eval_profile_expr(inner, ctx),
        }
    }

    /// Generate a sandbox policy from the profiles of matched allow statements.
    ///
    /// Walks each profile expression tree collecting `fs`, `caps`, and `network`
    /// from referenced constraints. Then generates sandbox rules from the `fs` filters.
    ///
    /// Composition rules:
    /// - `caps`: intersection (most restrictive wins)
    /// - `network`: deny wins over allow
    /// - `fs` rules: all collected into one sandbox rule list
    /// - No `fs` in any constraint → no sandbox generated
    fn generate_sandbox_from_profiles(
        &self,
        profiles: &[&ProfileExpr],
        cwd: &str,
    ) -> Option<SandboxPolicy> {
        let mut all_fs: Vec<(&CompiledFilterExpr, RuleEffect)> = Vec::new();
        let mut merged_caps: Option<Cap> = None;
        let mut merged_network = NetworkPolicy::Allow;

        for profile in profiles {
            self.collect_profile_sandbox_parts(
                profile,
                &mut all_fs,
                &mut merged_caps,
                &mut merged_network,
            );
        }

        // No fs constraints → no sandbox
        if all_fs.is_empty() {
            return None;
        }

        // Determine final caps for sandbox rules.
        // If no explicit caps were specified, use all caps.
        let final_caps = merged_caps.unwrap_or(Cap::all());

        // Generate sandbox rules from collected fs expressions.
        let mut rules = Vec::new();
        for (fs_expr, effect) in &all_fs {
            filter_to_sandbox_rules(fs_expr, *effect, final_caps, cwd, &mut rules);
        }

        Some(SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules,
            network: merged_network,
        })
    }

    /// Walk a profile expression tree collecting sandbox-relevant parts
    /// (fs filters, caps, network) from referenced constraints.
    fn collect_profile_sandbox_parts<'a>(
        &'a self,
        expr: &ProfileExpr,
        fs_exprs: &mut Vec<(&'a CompiledFilterExpr, RuleEffect)>,
        caps: &mut Option<Cap>,
        network: &mut NetworkPolicy,
    ) {
        match expr {
            ProfileExpr::Ref(name) => {
                // First check if it's a named profile (composite) — recurse
                if let Some(profile_expr) = self.profiles.get(name) {
                    self.collect_profile_sandbox_parts(profile_expr, fs_exprs, caps, network);
                    return;
                }
                // Then check if it's a named constraint (primitive)
                if let Some(constraint) = self.constraints.get(name) {
                    if let Some(ref fs) = constraint.fs {
                        fs_exprs.push((fs, RuleEffect::Allow));
                    }
                    if let Some(c) = constraint.caps {
                        // Intersection: most restrictive wins
                        *caps = Some(caps.map_or(c, |existing| existing & c));
                    }
                    if let Some(n) = constraint.network {
                        // Deny wins over allow
                        if n == NetworkPolicy::Deny {
                            *network = NetworkPolicy::Deny;
                        }
                    }
                }
            }
            ProfileExpr::And(a, b) => {
                self.collect_profile_sandbox_parts(a, fs_exprs, caps, network);
                self.collect_profile_sandbox_parts(b, fs_exprs, caps, network);
            }
            ProfileExpr::Or(a, b) => {
                self.collect_profile_sandbox_parts(a, fs_exprs, caps, network);
                self.collect_profile_sandbox_parts(b, fs_exprs, caps, network);
            }
            ProfileExpr::Not(inner) => {
                // For Not, we collect fs with flipped effect
                let mut inner_fs: Vec<(&CompiledFilterExpr, RuleEffect)> = Vec::new();
                self.collect_profile_sandbox_parts(inner, &mut inner_fs, caps, network);
                for (fs, effect) in inner_fs {
                    let flipped = match effect {
                        RuleEffect::Allow => RuleEffect::Deny,
                        RuleEffect::Deny => RuleEffect::Allow,
                    };
                    fs_exprs.push((fs, flipped));
                }
            }
        }
    }
}

/// Walk a `CompiledFilterExpr` tree and produce sandbox rules.
///
/// | FilterExpr          | SandboxRule                                              |
/// |---------------------|----------------------------------------------------------|
/// | Subpath(".")        | Allow <caps> in <resolved-cwd>, Subpath                  |
/// | Literal(".env")     | Allow <caps> in <resolved-path>, Literal                 |
/// | Regex(...)          | Allow <caps> matching <pattern>, Regex (macOS only)      |
/// | Not(inner)          | Flip effect: Allow↔Deny                                  |
/// | And(a, b) / Or(a,b) | Collect rules from both sides                            |
fn filter_to_sandbox_rules(
    expr: &CompiledFilterExpr,
    effect: RuleEffect,
    caps: Cap,
    cwd: &str,
    rules: &mut Vec<SandboxRule>,
) {
    use crate::sandbox::PathMatch;

    match expr {
        CompiledFilterExpr::Subpath(base) => {
            let resolved = resolve_path(base, cwd);
            rules.push(SandboxRule {
                effect,
                caps,
                path: resolved.to_string_lossy().into_owned(),
                path_match: PathMatch::Subpath,
            });
        }
        CompiledFilterExpr::Literal(path) => {
            let resolved = resolve_path(path, cwd);
            rules.push(SandboxRule {
                effect,
                caps,
                path: resolved.to_string_lossy().into_owned(),
                path_match: PathMatch::Literal,
            });
        }
        CompiledFilterExpr::Regex(regex) => {
            rules.push(SandboxRule {
                effect,
                caps,
                path: regex.to_string(),
                path_match: PathMatch::Regex,
            });
        }
        CompiledFilterExpr::And(a, b) | CompiledFilterExpr::Or(a, b) => {
            filter_to_sandbox_rules(a, effect, caps, cwd, rules);
            filter_to_sandbox_rules(b, effect, caps, cwd, rules);
        }
        CompiledFilterExpr::Not(inner) => {
            let flipped = match effect {
                RuleEffect::Allow => RuleEffect::Deny,
                RuleEffect::Deny => RuleEffect::Allow,
            };
            filter_to_sandbox_rules(inner, flipped, caps, cwd, rules);
        }
    }
}

/// The result of evaluating a policy.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: Option<String>,
    pub delegate: Option<DelegateConfig>,
    /// Per-command sandbox policy generated from `fs`/`caps`/`network` constraints.
    /// Only present for bash (Execute) commands that matched allow rules with `fs` constraints.
    pub sandbox: Option<SandboxPolicy>,
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
            profile: stmt.profile.clone(),
        })
    }

    fn matches(&self, entity: &str, verb: &Verb, noun: &str) -> bool {
        self.entity_matcher.matches_entity(entity)
            && self.verb_matcher.matches(verb)
            && self.noun_matcher.matches_noun(noun)
    }
}

impl CompiledConstraintDef {
    fn compile(def: &ConstraintDef) -> Result<Self, CompileError> {
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

    /// Evaluate this constraint against the given context.
    /// All specified fields must be satisfied (AND).
    ///
    /// For bash (Execute) commands, the `fs` check is skipped because `fs` constraints
    /// generate sandbox rules rather than acting as permission guards.
    fn eval(&self, ctx: &EvalContext) -> bool {
        // For bash commands, skip fs check — fs generates sandbox rules instead.
        // For other verbs (read/write/edit), fs acts as a permission guard.
        if *ctx.verb != Verb::Execute {
            if let Some(ref fs) = self.fs
                && !fs.matches(ctx.noun, ctx.cwd)
            {
                return false;
            }
        }

        // Check pipe constraint (only relevant for bash commands)
        if let Some(allow_pipe) = self.pipe
            && !allow_pipe
            && command_has_pipe(ctx.noun)
        {
            return false;
        }

        // Check redirect constraint (only relevant for bash commands)
        if let Some(allow_redirect) = self.redirect
            && !allow_redirect
            && command_has_redirect(ctx.noun)
        {
            return false;
        }

        // Check forbidden arguments
        if let Some(ref forbidden) = self.forbid_args {
            let args = tokenize_command(ctx.noun);
            for forbidden_arg in forbidden {
                if args.iter().any(|a| a == forbidden_arg) {
                    return false;
                }
            }
        }

        // Check required arguments (at least one must be present)
        if let Some(ref required) = self.require_args {
            let args = tokenize_command(ctx.noun);
            if !required.iter().any(|req| args.iter().any(|a| a == req)) {
                return false;
            }
        }

        true
    }
}

impl CompiledFilterExpr {
    fn compile(expr: &FilterExpr) -> Result<Self, CompileError> {
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

    /// Check if the given path matches this filter expression.
    ///
    /// The path is resolved relative to `cwd` before matching.
    fn matches(&self, path: &str, cwd: &str) -> bool {
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
// Helper functions for constraint evaluation
// ---------------------------------------------------------------------------

/// Resolve a path relative to cwd. Handles `.` as cwd.
fn resolve_path(path: &str, cwd: &str) -> PathBuf {
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
fn lexical_normalize(path: &Path) -> PathBuf {
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
fn command_has_pipe(command: &str) -> bool {
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
fn command_has_redirect(command: &str) -> bool {
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
fn tokenize_command(command: &str) -> Vec<&str> {
    command.split_whitespace().collect()
}

// ---------------------------------------------------------------------------
// CompiledPattern and CompiledMatchExpr (unchanged)
// ---------------------------------------------------------------------------

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
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Deny);
    }

    // --- Helper function tests ---

    #[test]
    fn test_command_has_pipe() {
        assert!(command_has_pipe("cat foo | grep bar"));
        assert!(command_has_pipe("ls | wc -l"));
        assert!(!command_has_pipe("echo 'hello | world'"));
        assert!(!command_has_pipe("echo hello"));
        assert!(!command_has_pipe("grep -E 'a|b' file"));
    }

    #[test]
    fn test_command_has_redirect() {
        assert!(command_has_redirect("echo hello > file.txt"));
        assert!(command_has_redirect("echo hello >> file.txt"));
        assert!(command_has_redirect("cat < input.txt"));
        assert!(!command_has_redirect("echo 'hello > world'"));
        assert!(!command_has_redirect("echo hello"));
    }

    #[test]
    fn test_resolve_path() {
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
        assert_eq!(sandbox.rules[0].path_match, crate::sandbox::PathMatch::Subpath);
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
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        let sandbox = decision.sandbox.expect("expected sandbox policy");
        // Not(Subpath(.git)) → Deny rule for .git
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].effect, RuleEffect::Deny);
        assert_eq!(sandbox.rules[0].path, "/home/user/project/.git");
        assert_eq!(sandbox.rules[0].path_match, crate::sandbox::PathMatch::Subpath);
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
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        // Regex fs generates a sandbox rule with PathMatch::Regex
        // (enforced on macOS via Seatbelt SBPL, skipped on Linux)
        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].path_match, crate::sandbox::PathMatch::Regex);
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
        };
        let decision = policy.evaluate_with_context(&ctx);
        assert_eq!(decision.effect, Effect::Allow);

        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].path, "/home/user/project/.env");
        assert_eq!(sandbox.rules[0].path_match, crate::sandbox::PathMatch::Literal);
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
        };
        let decision = policy.evaluate_with_context(&ctx);
        let sandbox = decision.sandbox.expect("expected sandbox policy");
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
    }
}
