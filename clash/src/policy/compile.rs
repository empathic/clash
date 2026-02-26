//! Compiler: AST → DecisionTree.
//!
//! Resolves `(include ...)` references, flattens rules, groups them by
//! capability domain, sorts by specificity, and detects conflicts.

use std::collections::HashMap;

use anyhow::{Result, bail};
use regex::Regex;

use crate::policy::Effect;

use super::ast::*;
use super::decision_tree::*;
use super::specificity::Specificity;

/// Environment variable resolver used during compilation to expand `(env NAME)`.
pub trait EnvResolver {
    fn resolve(&self, name: &str) -> Result<String>;
}

/// Default resolver that reads from `std::env`.
///
/// Session-level variables (e.g. `TRANSCRIPT_DIR`) that are normally provided
/// by hook context fall back to a sentinel path when not set, so that internal
/// policies always compile even outside a hook invocation.
pub struct StdEnvResolver;

/// Sentinel path for session variables not available outside a hook context.
/// Points under `/dev/null` which cannot be a real directory, so `(subpath ...)`
/// rules referencing it effectively match nothing.
pub const UNAVAILABLE_SESSION_PATH: &str = "/dev/null/.clash-no-session";

/// Session-level variables with safe defaults for when no hook context exists.
const SESSION_VAR_DEFAULTS: &[(&str, &str)] = &[("TRANSCRIPT_DIR", UNAVAILABLE_SESSION_PATH)];

impl EnvResolver for StdEnvResolver {
    fn resolve(&self, name: &str) -> Result<String> {
        match std::env::var(name) {
            Ok(val) => Ok(val),
            Err(_) => {
                for &(var, default) in SESSION_VAR_DEFAULTS {
                    if name == var {
                        return Ok(default.to_string());
                    }
                }
                anyhow::bail!("environment variable not set: {name}")
            }
        }
    }
}

/// Compile a policy source string into a decision tree, injecting internal policies.
pub fn compile_policy(source: &str) -> Result<DecisionTree> {
    compile_policy_with_internals(source, &StdEnvResolver, crate::settings::INTERNAL_POLICIES)
}

/// Compile with a custom environment resolver (useful for testing).
/// Does NOT inject internal policies — existing tests use this directly.
pub fn compile_policy_with_env(source: &str, env: &dyn EnvResolver) -> Result<DecisionTree> {
    let ast = super::parse::parse(source)?;
    compile_ast(&ast, env)
}

/// Compile policies from multiple levels and merge into a single decision tree.
///
/// Each level is compiled independently (so conflict detection is per-level),
/// then rules are merged with level-aware precedence. Higher-precedence levels'
/// rules are placed before lower-precedence rules at the same specificity,
/// ensuring they match first.
///
/// Internal policies are injected once into the merged tree (not per-level).
///
/// `levels` should contain `(PolicyLevel, source_text)` pairs.
pub fn compile_multi_level(
    levels: &[(crate::settings::PolicyLevel, &str)],
) -> Result<DecisionTree> {
    compile_multi_level_with_internals(levels, &StdEnvResolver, crate::settings::INTERNAL_POLICIES)
}

/// Multi-level compilation with configurable env resolver and internals.
pub fn compile_multi_level_with_internals(
    levels: &[(crate::settings::PolicyLevel, &str)],
    env: &dyn EnvResolver,
    internals: &[(&str, &str)],
) -> Result<DecisionTree> {
    use crate::settings::PolicyLevel;

    if levels.is_empty() {
        bail!("no policy levels to compile");
    }

    // Compile each level independently (no internal policies yet).
    let mut level_trees: Vec<(PolicyLevel, DecisionTree)> = Vec::new();
    for (level, source) in levels {
        let tree = compile_policy_with_env(source, env)
            .map_err(|e| anyhow::anyhow!("{} policy: {}", level.name(), e))?;
        level_trees.push((*level, tree));
    }

    // Determine which level's (default ...) wins: highest precedence.
    // Sort in precedence order (highest first).
    level_trees.sort_by(|a, b| b.0.cmp(&a.0));

    let version = level_trees[0].1.version;
    let default_effect = level_trees[0].1.default;
    let policy_name = level_trees[0].1.policy_name.clone();

    // Merge rules from all levels, tagging with origin_level.
    let mut exec_rules = Vec::new();
    let mut fs_rules = Vec::new();
    let mut net_rules = Vec::new();
    let mut tool_rules = Vec::new();
    let mut sandbox_policies = HashMap::new();

    // Insert rules in precedence order (highest first) so that for same
    // specificity, higher-precedence rules come first.
    for (level, tree) in &level_trees {
        for rule in &tree.exec_rules {
            exec_rules.push(clone_compiled_rule(rule, Some(*level)));
        }
        for rule in &tree.fs_rules {
            fs_rules.push(clone_compiled_rule(rule, Some(*level)));
        }
        for rule in &tree.net_rules {
            net_rules.push(clone_compiled_rule(rule, Some(*level)));
        }
        for rule in &tree.tool_rules {
            tool_rules.push(clone_compiled_rule(rule, Some(*level)));
        }
        for (name, rules) in &tree.sandbox_policies {
            sandbox_policies.entry(name.clone()).or_insert_with(|| {
                rules
                    .iter()
                    .map(|r| clone_compiled_rule(r, Some(*level)))
                    .collect()
            });
        }
    }

    // Stable sort by specificity (most specific first). Since we inserted
    // higher-precedence levels first, stable sort preserves level ordering
    // within the same specificity.
    let sort_fn = |a: &CompiledRule, b: &CompiledRule| {
        b.specificity
            .partial_cmp(&a.specificity)
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    exec_rules.sort_by(sort_fn);
    fs_rules.sort_by(sort_fn);
    net_rules.sort_by(sort_fn);
    tool_rules.sort_by(sort_fn);

    let mut merged = DecisionTree {
        version,
        default: default_effect,
        policy_name,
        exec_rules,
        fs_rules,
        net_rules,
        tool_rules,
        sandbox_policies,
    };

    // Inject internal policies into the merged tree.
    inject_internals(&mut merged, env, internals)?;
    Ok(merged)
}

/// Clone a CompiledRule, setting origin_level. CompiledRule can't derive Clone
/// because it contains Regex, so we reconstruct it.
fn clone_compiled_rule(
    rule: &CompiledRule,
    level: Option<crate::settings::PolicyLevel>,
) -> CompiledRule {
    let compiled_matcher = compile_matcher(&rule.source.matcher, &StdEnvResolver)
        .expect("rule was already compiled once");
    CompiledRule {
        effect: rule.effect,
        matcher: compiled_matcher,
        source: rule.source.clone(),
        specificity: rule.specificity,
        sandbox: rule.sandbox.clone(),
        origin_policy: rule.origin_policy.clone(),
        origin_level: level,
    }
}

/// Inject internal policies into a merged DecisionTree.
fn inject_internals(
    tree: &mut DecisionTree,
    env: &dyn EnvResolver,
    internals: &[(&str, &str)],
) -> Result<()> {
    for (name, source) in internals {
        let int_ast = super::parse::parse(source)?;
        for tl in &int_ast {
            if let TopLevel::Policy { body, .. } = tl {
                for item in body {
                    if let PolicyItem::Rule(rule) = item {
                        let specificity = Specificity::from_matcher(&rule.matcher);
                        let compiled_matcher = compile_matcher(&rule.matcher, env)?;
                        let sandbox_key = match &rule.sandbox {
                            Some(SandboxRef::Named(n)) => Some(n.clone()),
                            Some(SandboxRef::Inline(inline_rules)) => {
                                let key = format!("__internal_inline_sandbox_{name}__");
                                let mut compiled_sandbox_rules = Vec::new();
                                for r in inline_rules {
                                    let sp = Specificity::from_matcher(&r.matcher);
                                    let cm = compile_matcher(&r.matcher, env)?;
                                    compiled_sandbox_rules.push(CompiledRule {
                                        effect: r.effect,
                                        matcher: cm,
                                        source: r.clone(),
                                        specificity: sp,
                                        sandbox: None,
                                        origin_policy: None,
                                        origin_level: None,
                                    });
                                }
                                tree.sandbox_policies
                                    .insert(key.clone(), compiled_sandbox_rules);
                                Some(key)
                            }
                            None => None,
                        };
                        let compiled = CompiledRule {
                            effect: rule.effect,
                            matcher: compiled_matcher,
                            source: rule.clone(),
                            specificity,
                            sandbox: sandbox_key,
                            origin_policy: Some(name.to_string()),
                            origin_level: None,
                        };
                        match &rule.matcher {
                            CapMatcher::Exec(_) => tree.exec_rules.push(compiled),
                            CapMatcher::Fs(_) => tree.fs_rules.push(compiled),
                            CapMatcher::Net(_) => tree.net_rules.push(compiled),
                            CapMatcher::Tool(_) => tree.tool_rules.push(compiled),
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Compile with internal policies injected.
///
/// 1. Parses user source
/// 2. Checks which internal policy names the user already defined (override)
/// 3. For non-overridden ones, parses embedded source, appends TopLevel::Policy items
/// 4. Prepends `(include "__internal_X__")` to the active policy body
/// 5. Calls existing compile_ast
pub fn compile_policy_with_internals(
    source: &str,
    env: &dyn EnvResolver,
    internals: &[(&str, &str)],
) -> Result<DecisionTree> {
    let mut ast = super::parse::parse(source)?;

    // Collect user-defined policy names.
    let user_policies: std::collections::HashSet<String> = ast
        .iter()
        .filter_map(|tl| match tl {
            TopLevel::Policy { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();

    // Find the active policy name.
    let active_policy = ast
        .iter()
        .find_map(|tl| match tl {
            TopLevel::Default { policy, .. } => Some(policy.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "main".to_string());

    // Parse and inject non-overridden internal policies.
    let mut internal_includes = Vec::new();
    for (name, int_source) in internals {
        if user_policies.contains(*name) {
            continue; // user overrides this internal policy
        }
        let int_ast = super::parse::parse(int_source)?;
        for tl in int_ast {
            if let TopLevel::Policy { .. } = &tl {
                ast.push(tl);
                internal_includes.push(name.to_string());
            }
        }
    }

    // Prepend include directives for internal policies to the active policy.
    if !internal_includes.is_empty() {
        for tl in &mut ast {
            if let TopLevel::Policy { name, body } = tl
                && *name == active_policy
            {
                let mut new_body: Vec<PolicyItem> = internal_includes
                    .iter()
                    .map(|n| PolicyItem::Include(n.clone()))
                    .collect();
                new_body.append(body);
                *body = new_body;
                break;
            }
        }
    }

    let tree = compile_ast(&ast, env)?;
    Ok(tree)
}

/// Compile a parsed AST into a decision tree.
fn compile_ast(top_levels: &[TopLevel], env: &dyn EnvResolver) -> Result<DecisionTree> {
    // Validate the declared policy syntax version.
    let version = super::version::extract_version(top_levels)?;
    super::version::validate_version(version)?;

    // Find the default declaration.
    let default_decl = top_levels
        .iter()
        .find_map(|tl| match tl {
            TopLevel::Default { effect, policy } => Some((*effect, policy.as_str())),
            _ => None,
        })
        .unwrap_or((Effect::Deny, "main"));

    let (default_effect, active_policy) = default_decl;

    // Build a map of policy name → body.
    let mut policies: HashMap<&str, &[PolicyItem]> = HashMap::new();
    for tl in top_levels {
        if let TopLevel::Policy { name, body } = tl {
            policies.insert(name.as_str(), body);
        }
    }

    // Flatten the active policy, resolving includes.
    let mut rules: Vec<(Rule, String)> = Vec::new();
    let mut visited = Vec::new();
    flatten_policy(active_policy, &policies, &mut rules, &mut visited)?;

    // Group rules by capability domain and compile.
    let mut exec_rules = Vec::new();
    let mut fs_rules = Vec::new();
    let mut net_rules = Vec::new();
    let mut tool_rules = Vec::new();
    let mut sandbox_policies = HashMap::new();
    let mut inline_counter = 0usize;

    for (rule, origin) in &rules {
        // Resolve sandbox reference to a key name.
        let sandbox_key = match &rule.sandbox {
            Some(SandboxRef::Named(name)) => {
                if !policies.contains_key(name.as_str()) {
                    bail!(
                        "sandbox reference \"{}\" not found: no (policy \"{}\") defined",
                        name,
                        name
                    );
                }
                Some(name.clone())
            }
            Some(SandboxRef::Inline(inline_rules)) => {
                let key = format!("__inline_sandbox_{inline_counter}__");
                inline_counter += 1;
                let mut compiled_sandbox_rules = Vec::new();
                for r in inline_rules {
                    let specificity = Specificity::from_matcher(&r.matcher);
                    let compiled_matcher = compile_matcher(&r.matcher, env)?;
                    compiled_sandbox_rules.push(CompiledRule {
                        effect: r.effect,
                        matcher: compiled_matcher,
                        source: r.clone(),
                        specificity,
                        sandbox: None,
                        origin_policy: None,
                        origin_level: None,
                    });
                }
                sandbox_policies.insert(key.clone(), compiled_sandbox_rules);
                Some(key)
            }
            None => None,
        };

        let specificity = Specificity::from_matcher(&rule.matcher);
        let compiled_matcher = compile_matcher(&rule.matcher, env)?;
        let compiled = CompiledRule {
            effect: rule.effect,
            matcher: compiled_matcher,
            source: rule.clone(),
            specificity,
            sandbox: sandbox_key,
            origin_policy: Some(origin.clone()),
            origin_level: None,
        };
        match &rule.matcher {
            CapMatcher::Exec(_) => exec_rules.push(compiled),
            CapMatcher::Fs(_) => fs_rules.push(compiled),
            CapMatcher::Net(_) => net_rules.push(compiled),
            CapMatcher::Tool(_) => tool_rules.push(compiled),
        }
    }

    // Compile named sandbox policies: for each named sandbox reference,
    // compile the referenced policy's rules into a standalone rule set.
    // (Inline sandbox policies were already compiled above.)
    let sandbox_names: Vec<String> = exec_rules
        .iter()
        .filter_map(|r| r.sandbox.clone())
        .collect();
    for sandbox_name in &sandbox_names {
        if sandbox_policies.contains_key(sandbox_name) {
            continue;
        }
        if let Some(body) = policies.get(sandbox_name.as_str()) {
            let mut sandbox_rules = Vec::new();
            for item in *body {
                if let PolicyItem::Rule(rule) = item {
                    let specificity = Specificity::from_matcher(&rule.matcher);
                    let compiled_matcher = compile_matcher(&rule.matcher, env)?;
                    sandbox_rules.push(CompiledRule {
                        effect: rule.effect,
                        matcher: compiled_matcher,
                        source: rule.clone(),
                        specificity,
                        sandbox: None,
                        origin_policy: None,
                        origin_level: None,
                    });
                }
            }
            sandbox_policies.insert(sandbox_name.clone(), sandbox_rules);
        }
    }

    // Sort by specificity (most specific first).
    let sort_fn = |a: &CompiledRule, b: &CompiledRule| {
        b.specificity
            .partial_cmp(&a.specificity)
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    exec_rules.sort_by(sort_fn);
    fs_rules.sort_by(sort_fn);
    net_rules.sort_by(sort_fn);
    tool_rules.sort_by(sort_fn);

    // Detect conflicts: same specificity, different effects.
    detect_conflicts(&exec_rules, "exec")?;
    detect_conflicts(&fs_rules, "fs")?;
    detect_conflicts(&net_rules, "net")?;
    detect_conflicts(&tool_rules, "tool")?;

    Ok(DecisionTree {
        version,
        default: default_effect,
        policy_name: active_policy.to_string(),
        exec_rules,
        fs_rules,
        net_rules,
        tool_rules,
        sandbox_policies,
    })
}

/// Recursively flatten a policy, resolving `(include ...)` references.
/// Each rule is tagged with the name of the policy it originated from.
fn flatten_policy(
    name: &str,
    policies: &HashMap<&str, &[PolicyItem]>,
    rules: &mut Vec<(Rule, String)>,
    visited: &mut Vec<String>,
) -> Result<()> {
    if visited.contains(&name.to_string()) {
        bail!("circular include detected: {name}");
    }
    visited.push(name.to_string());

    let body = policies
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("policy not found: {name}"))?;

    for item in *body {
        match item {
            PolicyItem::Include(target) => {
                flatten_policy(target, policies, rules, visited)?;
            }
            PolicyItem::Rule(rule) => {
                rules.push((rule.clone(), name.to_string()));
            }
        }
    }

    visited.pop();
    Ok(())
}

/// Detect conflicting rules: same specificity, overlapping matchers, different effects.
fn detect_conflicts(rules: &[CompiledRule], domain: &str) -> Result<()> {
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            if rules[i].specificity == rules[j].specificity
                && rules[i].effect != rules[j].effect
                && matchers_may_overlap(&rules[i].source.matcher, &rules[j].source.matcher)
            {
                bail!(
                    "conflicting {domain} rules with equal specificity: \
                     {} ({}) vs {} ({})",
                    rules[i].source,
                    rules[i].effect,
                    rules[j].source,
                    rules[j].effect,
                );
            }
        }
    }
    Ok(())
}

/// Conservative overlap check: returns `false` only when we can prove two
/// matchers can never match the same request (e.g. different literals in the
/// same position). Returns `true` (may overlap) when uncertain.
fn matchers_may_overlap(a: &CapMatcher, b: &CapMatcher) -> bool {
    match (a, b) {
        (CapMatcher::Exec(ea), CapMatcher::Exec(eb)) => {
            if !patterns_may_overlap(&ea.bin, &eb.bin) {
                return false;
            }
            // If either has :has patterns, be conservative (may overlap).
            if !ea.has_args.is_empty() || !eb.has_args.is_empty() {
                return true;
            }
            // Both purely positional: check args pairwise.
            for (pa, pb) in ea.args.iter().zip(eb.args.iter()) {
                if !patterns_may_overlap(pa, pb) {
                    return false;
                }
            }
            true
        }
        (CapMatcher::Fs(fa), CapMatcher::Fs(fb)) => {
            if !ops_may_overlap(&fa.op, &fb.op) {
                return false;
            }
            match (&fa.path, &fb.path) {
                (Some(pa), Some(pb)) => path_filters_may_overlap(pa, pb),
                _ => true,
            }
        }
        (CapMatcher::Net(na), CapMatcher::Net(nb)) => {
            if !patterns_may_overlap(&na.domain, &nb.domain) {
                return false;
            }
            match (&na.path, &nb.path) {
                (Some(pa), Some(pb)) => path_filters_may_overlap(pa, pb),
                _ => true,
            }
        }
        (CapMatcher::Tool(ta), CapMatcher::Tool(tb)) => patterns_may_overlap(&ta.name, &tb.name),
        // Different capability domains never overlap.
        _ => false,
    }
}

/// Two patterns may overlap unless both are distinct literals.
fn patterns_may_overlap(a: &Pattern, b: &Pattern) -> bool {
    match (a, b) {
        (Pattern::Literal(la), Pattern::Literal(lb)) => la == lb,
        _ => true, // conservatively assume overlap
    }
}

/// Two op patterns may overlap unless they specify disjoint single ops.
fn ops_may_overlap(a: &OpPattern, b: &OpPattern) -> bool {
    match (a, b) {
        (OpPattern::Single(oa), OpPattern::Single(ob)) => oa == ob,
        _ => true,
    }
}

/// Two path filters may overlap unless both are distinct literals.
fn path_filters_may_overlap(a: &PathFilter, b: &PathFilter) -> bool {
    match (a, b) {
        (PathFilter::Literal(la), PathFilter::Literal(lb)) => la == lb,
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Matcher compilation (AST → IR with pre-compiled regexes)
// ---------------------------------------------------------------------------

fn compile_matcher(matcher: &CapMatcher, env: &dyn EnvResolver) -> Result<CompiledMatcher> {
    match matcher {
        CapMatcher::Exec(m) => {
            let bin = compile_pattern(&m.bin)?;
            let args = m.args.iter().map(compile_pattern).collect::<Result<_>>()?;
            let has_args = m
                .has_args
                .iter()
                .map(compile_pattern)
                .collect::<Result<_>>()?;
            Ok(CompiledMatcher::Exec(CompiledExec {
                bin,
                args,
                has_args,
            }))
        }
        CapMatcher::Fs(m) => {
            let path = match &m.path {
                Some(pf) => Some(compile_path_filter(pf, env)?),
                None => None,
            };
            Ok(CompiledMatcher::Fs(CompiledFs {
                op: m.op.clone(),
                path,
            }))
        }
        CapMatcher::Net(m) => {
            let domain = compile_pattern(&m.domain)?;
            let path = match &m.path {
                Some(pf) => Some(compile_path_filter(pf, env)?),
                None => None,
            };
            Ok(CompiledMatcher::Net(CompiledNet { domain, path }))
        }
        CapMatcher::Tool(m) => {
            let name = compile_pattern(&m.name)?;
            Ok(CompiledMatcher::Tool(CompiledTool { name }))
        }
    }
}

fn compile_pattern(pattern: &Pattern) -> Result<CompiledPattern> {
    match pattern {
        Pattern::Any => Ok(CompiledPattern::Any),
        Pattern::Literal(s) => Ok(CompiledPattern::Literal(s.clone())),
        Pattern::Regex(r) => {
            let regex = Regex::new(r).map_err(|e| anyhow::anyhow!("invalid regex /{r}/: {e}"))?;
            Ok(CompiledPattern::Regex(std::sync::Arc::new(regex)))
        }
        Pattern::Or(ps) => {
            let compiled = ps.iter().map(compile_pattern).collect::<Result<_>>()?;
            Ok(CompiledPattern::Or(compiled))
        }
        Pattern::Not(p) => {
            let inner = compile_pattern(p)?;
            Ok(CompiledPattern::Not(Box::new(inner)))
        }
    }
}

fn compile_path_filter(pf: &PathFilter, env: &dyn EnvResolver) -> Result<CompiledPathFilter> {
    match pf {
        PathFilter::Subpath(expr, worktree) => {
            let resolved = resolve_path_expr(expr, env)?;
            if *worktree {
                // When :worktree is set, expand to include git worktree directories.
                // If the resolved path is inside a git worktree, produce an Or of
                // the original path plus the backing git directories.
                let wt_paths = crate::git::worktree_sandbox_paths(std::path::Path::new(&resolved));
                if wt_paths.is_empty() {
                    Ok(CompiledPathFilter::Subpath(resolved))
                } else {
                    let mut filters = vec![CompiledPathFilter::Subpath(resolved)];
                    for p in wt_paths {
                        filters.push(CompiledPathFilter::Subpath(p));
                    }
                    Ok(CompiledPathFilter::Or(filters))
                }
            } else {
                Ok(CompiledPathFilter::Subpath(resolved))
            }
        }
        PathFilter::Literal(s) => Ok(CompiledPathFilter::Literal(s.clone())),
        PathFilter::Regex(r) => {
            let regex =
                Regex::new(r).map_err(|e| anyhow::anyhow!("invalid path regex /{r}/: {e}"))?;
            Ok(CompiledPathFilter::Regex(std::sync::Arc::new(regex)))
        }
        PathFilter::Or(fs) => {
            let compiled = fs
                .iter()
                .map(|f| compile_path_filter(f, env))
                .collect::<Result<_>>()?;
            Ok(CompiledPathFilter::Or(compiled))
        }
        PathFilter::Not(f) => {
            let inner = compile_path_filter(f, env)?;
            Ok(CompiledPathFilter::Not(Box::new(inner)))
        }
    }
}

fn resolve_path_expr(expr: &PathExpr, env: &dyn EnvResolver) -> Result<String> {
    match expr {
        PathExpr::Static(s) => Ok(s.clone()),
        PathExpr::Env(name) => env.resolve(name),
        PathExpr::Join(parts) => {
            let mut result = String::new();
            for part in parts {
                result.push_str(&resolve_path_expr(part, env)?);
            }
            Ok(result)
        }
    }
}

// ---------------------------------------------------------------------------
// Shadow detection
// ---------------------------------------------------------------------------

/// Information about a shadowed rule.
#[derive(Debug, Clone)]
pub struct ShadowInfo {
    /// The index of the rule that shadows this one (in the same rule list).
    pub shadowed_by_index: usize,
    /// The level of the rule that does the shadowing.
    pub shadowed_by_level: crate::settings::PolicyLevel,
}

/// Shadow information across all rule categories in a decision tree.
#[derive(Debug, Default)]
pub struct AllShadows {
    pub exec: HashMap<usize, ShadowInfo>,
    pub fs: HashMap<usize, ShadowInfo>,
    pub net: HashMap<usize, ShadowInfo>,
    pub tool: HashMap<usize, ShadowInfo>,
}

/// Detect shadowed rules in a list of compiled rules.
///
/// A rule at index `i` is "shadowed" when an earlier rule at index `j` (higher
/// precedence because the list is sorted most-specific-first, with stable
/// ordering by level within equal specificity):
///
/// 1. Comes from a **different** and **higher** `origin_level`.
/// 2. Has the **same or higher** specificity (i.e. `>=`).
/// 3. Has matchers that **may overlap** with rule `i`.
///
/// Rules with `origin_level == None` (internal/builtin) are skipped entirely.
/// Two rules at the same origin level don't shadow each other — that is normal
/// specificity ordering within one policy file.
///
/// Returns a map from rule index to shadow info.
pub fn detect_shadows(rules: &[CompiledRule]) -> HashMap<usize, ShadowInfo> {
    let mut shadows = HashMap::new();

    for i in 0..rules.len() {
        let Some(level_i) = rules[i].origin_level else {
            continue;
        };

        for j in 0..i {
            let Some(level_j) = rules[j].origin_level else {
                continue;
            };

            // Only cross-level shadowing: different levels, j is higher.
            if level_j <= level_i {
                continue;
            }

            // The shadowing rule must have the same or higher specificity.
            if rules[j].specificity < rules[i].specificity {
                continue;
            }

            // Matchers must potentially overlap.
            if !matchers_may_overlap(&rules[j].source.matcher, &rules[i].source.matcher) {
                continue;
            }

            shadows.insert(
                i,
                ShadowInfo {
                    shadowed_by_index: j,
                    shadowed_by_level: level_j,
                },
            );
            // Only record the first (highest-precedence) shadow.
            break;
        }
    }

    shadows
}

/// Detect all shadows across all rule categories in a decision tree.
pub fn detect_all_shadows(tree: &DecisionTree) -> AllShadows {
    AllShadows {
        exec: detect_shadows(&tree.exec_rules),
        fs: detect_shadows(&tree.fs_rules),
        net: detect_shadows(&tree.net_rules),
        tool: detect_shadows(&tree.tool_rules),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::PolicyLevel;

    /// Test env resolver that returns fixed values.
    struct TestEnv(HashMap<String, String>);

    impl TestEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }

    impl EnvResolver for TestEnv {
        fn resolve(&self, name: &str) -> Result<String> {
            self.0
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not set: {name}"))
        }
    }

    #[test]
    fn compile_basic_policy() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny  (exec "git" "push" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.default, Effect::Deny);
        assert_eq!(tree.policy_name, "main");
        assert_eq!(tree.exec_rules.len(), 2);
        // Most specific first: "git push *" before "git *"
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
        assert_eq!(tree.exec_rules[1].effect, Effect::Allow);
    }

    #[test]
    fn compile_with_includes() {
        let source = r#"
(default deny "main")
(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))
(policy "main"
  (include "cwd-access")
  (allow (exec "git" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.fs_rules.len(), 1);
    }

    #[test]
    fn compile_circular_include_error() {
        let source = r#"
(default deny "a")
(policy "a" (include "b"))
(policy "b" (include "a"))
"#;
        let env = TestEnv::new(&[]);
        let err = compile_policy_with_env(source, &env).unwrap_err();
        assert!(err.to_string().contains("circular include"));
    }

    #[test]
    fn compile_conflict_detection() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny  (exec "git" *)))
"#;
        // Same matcher, different effects = conflict.
        let env = TestEnv::new(&[]);
        let err = compile_policy_with_env(source, &env).unwrap_err();
        assert!(err.to_string().contains("conflicting exec rules"));
    }

    #[test]
    fn no_conflict_different_literals() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny  (exec "npm" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.exec_rules.len(), 2);
    }

    #[test]
    fn compile_no_conflict_same_effect() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (allow (exec "npm" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.exec_rules.len(), 2);
    }

    #[test]
    fn compile_no_conflict_different_specificity() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.exec_rules.len(), 2);
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
    }

    #[test]
    fn compile_env_resolution() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env HOME)))))
"#;
        let env = TestEnv::new(&[("HOME", "/home/user")]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.fs_rules.len(), 1);
        match &tree.fs_rules[0].matcher {
            CompiledMatcher::Fs(f) => match &f.path {
                Some(CompiledPathFilter::Subpath(p)) => assert_eq!(p, "/home/user"),
                other => panic!("expected Subpath, got {other:?}"),
            },
            other => panic!("expected Fs, got {other:?}"),
        }
    }

    #[test]
    fn compile_join_resolution() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath (join (env HOME) "/.clash")))))
"#;
        let env = TestEnv::new(&[("HOME", "/home/user")]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.fs_rules.len(), 1);
        match &tree.fs_rules[0].matcher {
            CompiledMatcher::Fs(f) => match &f.path {
                Some(CompiledPathFilter::Subpath(p)) => assert_eq!(p, "/home/user/.clash"),
                other => panic!("expected Subpath, got {other:?}"),
            },
            other => panic!("expected Fs, got {other:?}"),
        }
    }

    #[test]
    fn compile_missing_env_error() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env NONEXISTENT)))))
"#;
        let env = TestEnv::new(&[]);
        let err = compile_policy_with_env(source, &env).unwrap_err();
        assert!(err.to_string().contains("not set: NONEXISTENT"));
    }

    #[test]
    fn compile_regex_patterns() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny (net /.*\.evil\.com/)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.net_rules.len(), 1);
        match &tree.net_rules[0].matcher {
            CompiledMatcher::Net(n) => {
                assert!(n.domain.matches("foo.evil.com"));
                assert!(!n.domain.matches("github.com"));
            }
            other => panic!("expected Net, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_to_source() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        let regenerated = tree.to_source();
        assert!(regenerated.contains(r#"(default deny "main")"#));
        assert!(regenerated.contains("(deny (exec \"git\" \"push\" *))"));
        assert!(regenerated.contains("(allow (exec \"git\" *))"));
    }

    #[test]
    fn compile_sandbox_reference_valid() {
        let source = r#"
(default deny "main")
(policy "cargo-env"
  (allow (fs read (subpath (env PWD))))
  (allow (net "crates.io")))
(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env"))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.exec_rules[0].sandbox, Some("cargo-env".into()));
        assert!(tree.sandbox_policies.contains_key("cargo-env"));
        assert_eq!(tree.sandbox_policies["cargo-env"].len(), 2);
    }

    #[test]
    fn compile_sandbox_reference_missing() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "cargo" *) :sandbox "nonexistent"))
"#;
        let env = TestEnv::new(&[]);
        let err = compile_policy_with_env(source, &env).unwrap_err();
        assert!(
            err.to_string()
                .contains("sandbox reference \"nonexistent\" not found"),
            "got: {}",
            err
        );
    }

    #[test]
    fn compile_inline_sandbox() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "clash" "bug" *) :sandbox (allow (net *))))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.exec_rules.len(), 1);
        // Inline sandbox should be stored under a synthetic key.
        let sandbox_key = tree.exec_rules[0]
            .sandbox
            .as_ref()
            .expect("should have sandbox key");
        assert!(
            sandbox_key.starts_with("__inline_sandbox_"),
            "expected synthetic key, got: {sandbox_key}"
        );
        // The sandbox policy should contain one net rule.
        let sandbox_rules = &tree.sandbox_policies[sandbox_key];
        assert_eq!(sandbox_rules.len(), 1);
        assert_eq!(sandbox_rules[0].effect, Effect::Allow);
        assert!(matches!(&sandbox_rules[0].matcher, CompiledMatcher::Net(_)));
    }

    #[test]
    fn compile_inline_sandbox_multiple_rules() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "cargo" *) :sandbox (allow (net *)) (allow (fs read (subpath "/tmp")))))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        let sandbox_key = tree.exec_rules[0]
            .sandbox
            .as_ref()
            .expect("should have sandbox key");
        let sandbox_rules = &tree.sandbox_policies[sandbox_key];
        assert_eq!(sandbox_rules.len(), 2);
    }

    #[test]
    fn compile_with_internals_injects_rules() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let internal = r#"
(policy "__internal_test__"
  (allow (fs read (subpath "/test"))))
"#;
        let env = TestEnv::new(&[]);
        let tree =
            compile_policy_with_internals(user_source, &env, &[("__internal_test__", internal)])
                .unwrap();
        // User rule + internal rule.
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.fs_rules.len(), 1);
        // Check provenance.
        assert_eq!(tree.exec_rules[0].origin_policy.as_deref(), Some("main"));
        assert_eq!(
            tree.fs_rules[0].origin_policy.as_deref(),
            Some("__internal_test__")
        );
    }

    #[test]
    fn compile_with_internals_user_overrides() {
        let user_source = r#"
(default deny "main")
(policy "__internal_test__"
  (deny (fs read (subpath "/custom"))))
(policy "main"
  (include "__internal_test__")
  (allow (exec "git" *)))
"#;
        let internal = r#"
(policy "__internal_test__"
  (allow (fs read (subpath "/test"))))
"#;
        let env = TestEnv::new(&[]);
        let tree =
            compile_policy_with_internals(user_source, &env, &[("__internal_test__", internal)])
                .unwrap();
        // User override should win — deny instead of allow.
        assert_eq!(tree.fs_rules.len(), 1);
        assert_eq!(tree.fs_rules[0].effect, Effect::Deny);
    }

    #[test]
    fn compile_with_internals_no_internals() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_internals(user_source, &env, &[]).unwrap();
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.fs_rules.len(), 0);
    }

    #[test]
    fn compile_provenance_tracking() {
        let source = r#"
(default deny "main")
(policy "shared"
  (allow (fs read (subpath "/shared"))))
(policy "main"
  (include "shared")
  (deny (exec "git" "push" *))
  (allow (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(source, &env).unwrap();
        assert_eq!(tree.fs_rules[0].origin_policy.as_deref(), Some("shared"));
        assert_eq!(tree.exec_rules[0].origin_policy.as_deref(), Some("main"));
        assert_eq!(tree.exec_rules[1].origin_policy.as_deref(), Some("main"));
    }

    #[test]
    fn compile_full_example() {
        let source = r#"
(default deny "main")

(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")

  (deny  (exec "git" "push" *))
  (deny  (exec "git" "reset" *))
  (ask   (exec "git" "commit" *))
  (allow (exec "git" *))

  (allow (fs (or read write) (subpath (env PWD))))
  (deny  (fs write ".env"))

  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(source, &env).unwrap();

        assert_eq!(tree.default, Effect::Deny);
        assert_eq!(tree.exec_rules.len(), 4);
        assert_eq!(tree.fs_rules.len(), 3);
        assert_eq!(tree.net_rules.len(), 2);
        assert_eq!(tree.exec_rules.last().unwrap().effect, Effect::Allow);
    }

    // -----------------------------------------------------------------------
    // Multi-level policy tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_level_user_only() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree =
            compile_multi_level_with_internals(&[(PolicyLevel::User, user_source)], &env, &[])
                .unwrap();
        assert_eq!(tree.default, Effect::Deny);
        assert_eq!(tree.policy_name, "main");
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.exec_rules[0].effect, Effect::Allow);
    }

    #[test]
    fn test_multi_level_project_only() {
        let project_source = r#"
(default allow "main")
(policy "main"
  (deny (exec "rm" *))
  (deny (net "evil.com")))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[(PolicyLevel::Project, project_source)],
            &env,
            &[],
        )
        .unwrap();
        assert_eq!(tree.default, Effect::Allow);
        assert_eq!(tree.policy_name, "main");
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
        assert_eq!(tree.net_rules.len(), 1);
    }

    #[test]
    fn test_multi_level_project_overrides_user() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" "push" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // Both rules should be present.
        assert_eq!(tree.exec_rules.len(), 2);
        // "git push *" is more specific, so it comes first and denies.
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::Project));
        // "git *" is less specific, comes second and allows.
        assert_eq!(tree.exec_rules[1].effect, Effect::Allow);
        assert_eq!(tree.exec_rules[1].origin_level, Some(PolicyLevel::User));
    }

    #[test]
    fn test_multi_level_default_from_highest_level() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default allow "proj")
(policy "proj"
  (deny (exec "rm" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // Project has higher precedence, so its default wins.
        assert_eq!(tree.default, Effect::Allow);
        assert_eq!(tree.policy_name, "proj");
    }

    #[test]
    fn test_multi_level_origin_level_set() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (allow (fs read (subpath "/home"))))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "rm" *))
  (deny (net "evil.com")))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // All user rules should have User origin_level.
        for rule in &tree.exec_rules {
            if rule.effect == Effect::Allow {
                assert_eq!(rule.origin_level, Some(PolicyLevel::User));
            }
        }
        // All project rules should have Project origin_level.
        for rule in &tree.exec_rules {
            if rule.effect == Effect::Deny {
                assert_eq!(rule.origin_level, Some(PolicyLevel::Project));
            }
        }
        assert_eq!(tree.fs_rules[0].origin_level, Some(PolicyLevel::User));
        assert_eq!(tree.net_rules[0].origin_level, Some(PolicyLevel::Project));
    }

    #[test]
    fn test_multi_level_both_rules_present() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (allow (net "github.com")))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "rm" *))
  (allow (fs read (subpath "/project"))))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // Rules from both levels should be present in the merged tree.
        assert_eq!(tree.exec_rules.len(), 2); // git * from user + rm * from project
        assert_eq!(tree.net_rules.len(), 1); // github.com from user
        assert_eq!(tree.fs_rules.len(), 1); // /project from project
    }

    #[test]
    fn test_multi_level_user_specificity_wins() {
        // A more-specific user rule should beat a less-specific project rule
        // because specificity sorting puts it first.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" "commit" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        assert_eq!(tree.exec_rules.len(), 2);
        // "git commit *" is more specific and should come first (allow from user).
        assert_eq!(tree.exec_rules[0].effect, Effect::Allow);
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::User));
        // "git *" is less specific and comes second (deny from project).
        assert_eq!(tree.exec_rules[1].effect, Effect::Deny);
        assert_eq!(tree.exec_rules[1].origin_level, Some(PolicyLevel::Project));
    }

    #[test]
    fn test_multi_level_with_internals() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "rm" *)))
"#;
        let internal = r#"
(policy "__internal_test__"
  (allow (fs read (subpath "/internal"))))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[("__internal_test__", internal)],
        )
        .unwrap();
        // exec rules from both levels.
        assert_eq!(tree.exec_rules.len(), 2);
        // Internal fs rule injected once.
        assert_eq!(tree.fs_rules.len(), 1);
        assert_eq!(
            tree.fs_rules[0].origin_policy.as_deref(),
            Some("__internal_test__")
        );
        // Internal rules have no origin_level.
        assert_eq!(tree.fs_rules[0].origin_level, None);
    }

    #[test]
    fn test_multi_level_session_overrides_all() {
        // Session (level=2) should override both Project (level=1) and User (level=0)
        // when rules have the same specificity.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let session_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
                (PolicyLevel::Session, session_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // All three levels contribute a rule for "git *" at the same specificity.
        assert_eq!(tree.exec_rules.len(), 3);
        // Session rule should come first (highest precedence, stable sort).
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::Session));
    }

    #[test]
    fn test_multi_level_three_levels() {
        // All three levels present; session wins when it has a matching rule,
        // and rules from all levels are merged.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (allow (net "github.com")))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "rm" *))
  (allow (fs read (subpath "/project"))))
"#;
        let session_source = r#"
(default allow "session")
(policy "session"
  (deny (exec "git" "push" *))
  (deny (net "evil.com")))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
                (PolicyLevel::Session, session_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // Session is highest precedence, so its default wins.
        assert_eq!(tree.default, Effect::Allow);
        assert_eq!(tree.policy_name, "session");
        // exec rules: "git push *" (session), "git *" (user), "rm *" (project) = 3.
        assert_eq!(tree.exec_rules.len(), 3);
        // "git push *" is most specific and from session, should be first.
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::Session));
        // net rules: "evil.com" (session) + "github.com" (user) = 2.
        assert_eq!(tree.net_rules.len(), 2);
        // fs rules: "/project" from project = 1.
        assert_eq!(tree.fs_rules.len(), 1);
        assert_eq!(tree.fs_rules[0].origin_level, Some(PolicyLevel::Project));
    }

    #[test]
    fn test_multi_level_session_falls_through() {
        // Session has no matching rule for exec, so project/user rules apply.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" "push" *)))
"#;
        let session_source = r#"
(default deny "main")
(policy "main"
  (deny (net "evil.com")))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
                (PolicyLevel::Session, session_source),
            ],
            &env,
            &[],
        )
        .unwrap();
        // Session contributes no exec rules, so user and project exec rules apply.
        assert_eq!(tree.exec_rules.len(), 2);
        // "git push *" (project) is more specific, comes first.
        assert_eq!(tree.exec_rules[0].effect, Effect::Deny);
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::Project));
        // "git *" (user) is less specific, comes second.
        assert_eq!(tree.exec_rules[1].effect, Effect::Allow);
        assert_eq!(tree.exec_rules[1].origin_level, Some(PolicyLevel::User));
        // Session's net rule should still be present.
        assert_eq!(tree.net_rules.len(), 1);
        assert_eq!(tree.net_rules[0].origin_level, Some(PolicyLevel::Session));
    }

    // -----------------------------------------------------------------------
    // Shadow detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn shadow_none_when_single_level() {
        // Rules from a single level should never shadow each other.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny  (exec "git" "push" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree =
            compile_multi_level_with_internals(&[(PolicyLevel::User, user_source)], &env, &[])
                .unwrap();
        let shadows = detect_shadows(&tree.exec_rules);
        assert!(
            shadows.is_empty(),
            "single-level rules should not shadow each other"
        );
    }

    #[test]
    fn shadow_higher_level_shadows_lower_same_specificity() {
        // Project-level "git *" should shadow user-level "git *" because
        // Project has higher precedence and same specificity.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();

        assert_eq!(tree.exec_rules.len(), 2);
        // Project rule comes first (higher precedence at same specificity).
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::Project));
        assert_eq!(tree.exec_rules[1].origin_level, Some(PolicyLevel::User));

        let shadows = detect_shadows(&tree.exec_rules);
        assert_eq!(shadows.len(), 1, "user rule should be shadowed");
        let info = shadows.get(&1).expect("rule at index 1 should be shadowed");
        assert_eq!(info.shadowed_by_index, 0);
        assert_eq!(info.shadowed_by_level, PolicyLevel::Project);
    }

    #[test]
    fn shadow_no_shadow_when_lower_is_more_specific() {
        // User-level "git commit *" is more specific than project-level "git *".
        // More specific rules always win regardless of level, so no shadow.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" "commit" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();

        assert_eq!(tree.exec_rules.len(), 2);
        // "git commit *" is more specific, comes first (user).
        assert_eq!(tree.exec_rules[0].origin_level, Some(PolicyLevel::User));
        // "git *" is less specific, comes second (project).
        assert_eq!(tree.exec_rules[1].origin_level, Some(PolicyLevel::Project));

        let shadows = detect_shadows(&tree.exec_rules);
        assert!(
            shadows.is_empty(),
            "more-specific lower-level rule should not be shadowed"
        );
    }

    #[test]
    fn shadow_no_shadow_when_matchers_dont_overlap() {
        // Project denies "rm *", user allows "git *" — completely different
        // binaries, so no overlap and no shadow.
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "rm" *)))
"#;
        let env = TestEnv::new(&[]);
        let tree = compile_multi_level_with_internals(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();

        let shadows = detect_shadows(&tree.exec_rules);
        assert!(
            shadows.is_empty(),
            "non-overlapping matchers should not shadow"
        );
    }
}
