//! Compiler: AST → DecisionTree.
//!
//! Resolves `(include ...)` references, flattens rules, groups them by
//! capability domain, sorts by specificity, and detects conflicts.

use std::collections::HashMap;

use anyhow::{Result, bail};
use regex::Regex;

use crate::policy::Effect;

use super::ast::*;
use super::ir::*;
use super::specificity::Specificity;

/// Environment variable resolver used during compilation to expand `(env NAME)`.
pub trait EnvResolver {
    fn resolve(&self, name: &str) -> Result<String>;
}

/// Default resolver that reads from `std::env`.
pub struct StdEnvResolver;

impl EnvResolver for StdEnvResolver {
    fn resolve(&self, name: &str) -> Result<String> {
        std::env::var(name).map_err(|_| anyhow::anyhow!("environment variable not set: {name}"))
    }
}

/// Compile a policy source string into a decision tree.
pub fn compile_policy(source: &str) -> Result<DecisionTree> {
    compile_policy_with_env(source, &StdEnvResolver)
}

/// Compile with a custom environment resolver (useful for testing).
pub fn compile_policy_with_env(source: &str, env: &dyn EnvResolver) -> Result<DecisionTree> {
    let ast = super::parse::parse(source)?;
    compile_ast(&ast, env)
}

/// Compile a parsed AST into a decision tree.
fn compile_ast(top_levels: &[TopLevel], env: &dyn EnvResolver) -> Result<DecisionTree> {
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
    let mut rules = Vec::new();
    let mut visited = Vec::new();
    flatten_policy(active_policy, &policies, &mut rules, &mut visited)?;

    // Group rules by capability domain and compile.
    let mut exec_rules = Vec::new();
    let mut fs_rules = Vec::new();
    let mut net_rules = Vec::new();

    for rule in &rules {
        // Validate sandbox references point to existing policies.
        if let Some(ref sandbox_name) = rule.sandbox
            && !policies.contains_key(sandbox_name.as_str())
        {
            bail!(
                "sandbox reference \"{}\" not found: no (policy \"{}\") defined",
                sandbox_name,
                sandbox_name
            );
        }

        let specificity = Specificity::from_matcher(&rule.matcher);
        let compiled_matcher = compile_matcher(&rule.matcher, env)?;
        let compiled = CompiledRule {
            effect: rule.effect,
            matcher: compiled_matcher,
            source: rule.clone(),
            specificity,
            sandbox: rule.sandbox.clone(),
        };
        match &rule.matcher {
            CapMatcher::Exec(_) => exec_rules.push(compiled),
            CapMatcher::Fs(_) => fs_rules.push(compiled),
            CapMatcher::Net(_) => net_rules.push(compiled),
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

    // Detect conflicts: same specificity, different effects.
    detect_conflicts(&exec_rules, "exec")?;
    detect_conflicts(&fs_rules, "fs")?;
    detect_conflicts(&net_rules, "net")?;

    // Compile sandbox policies: for each sandbox reference, compile the
    // referenced policy's rules into a standalone rule set.
    let mut sandbox_policies = HashMap::new();
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
                    });
                }
            }
            sandbox_policies.insert(sandbox_name.clone(), sandbox_rules);
        }
    }

    Ok(DecisionTree {
        default: default_effect,
        policy_name: active_policy.to_string(),
        exec_rules,
        fs_rules,
        net_rules,
        sandbox_policies,
    })
}

/// Recursively flatten a policy, resolving `(include ...)` references.
fn flatten_policy(
    name: &str,
    policies: &HashMap<&str, &[PolicyItem]>,
    rules: &mut Vec<Rule>,
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
                rules.push(rule.clone());
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
        (CapMatcher::Net(na), CapMatcher::Net(nb)) => patterns_may_overlap(&na.domain, &nb.domain),
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
            Ok(CompiledMatcher::Net(CompiledNet { domain }))
        }
    }
}

fn compile_pattern(pattern: &Pattern) -> Result<CompiledPattern> {
    match pattern {
        Pattern::Any => Ok(CompiledPattern::Any),
        Pattern::Literal(s) => Ok(CompiledPattern::Literal(s.clone())),
        Pattern::Regex(r) => {
            let regex = Regex::new(r).map_err(|e| anyhow::anyhow!("invalid regex /{r}/: {e}"))?;
            Ok(CompiledPattern::Regex(regex))
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
        PathFilter::Subpath(expr) => {
            let resolved = resolve_path_expr(expr, env)?;
            Ok(CompiledPathFilter::Subpath(resolved))
        }
        PathFilter::Literal(s) => Ok(CompiledPathFilter::Literal(s.clone())),
        PathFilter::Regex(r) => {
            let regex =
                Regex::new(r).map_err(|e| anyhow::anyhow!("invalid path regex /{r}/: {e}"))?;
            Ok(CompiledPathFilter::Regex(regex))
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
