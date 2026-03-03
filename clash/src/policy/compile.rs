//! Compiler: AST → DecisionTree.
//!
//! Resolves `(include ...)` references, flattens rules, groups them by
//! capability domain, sorts by specificity, and detects conflicts.

use std::collections::HashMap;

use anyhow::{Result, bail};
use regex::Regex;

use crate::policy::Effect;
use crate::policy::ast::FsOp;
use crate::policy::sandbox_types::{
    Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy, SandboxRule,
};
use crate::policy::tree::{IdAllocator, MatchArm, Node, NodeMeta, PolicyTree, Predicate};

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

/// Compile a policy source string directly to a `PolicyTree`.
///
/// - v1 policies: parse → DecisionTree → `from_decision_tree()`
/// - v2 policies: parse → `compile_tree_ast()` (builds PolicyTree directly)
pub fn compile_to_tree(source: &str, env: &dyn EnvResolver) -> Result<PolicyTree> {
    let ast = super::parse::parse(source)?;
    let version = super::version::extract_version(&ast)?;
    super::version::validate_version(version)?;

    if version >= 2 {
        compile_tree_ast(&ast, env)
    } else {
        let dt = compile_ast(&ast, env)?;
        Ok(PolicyTree::from_decision_tree(dt))
    }
}

/// Compile a v2 AST directly into a PolicyTree.
fn compile_tree_ast(top_levels: &[TopLevel], env: &dyn EnvResolver) -> Result<PolicyTree> {
    let version = super::version::extract_version(top_levels)?;

    // Resolve active policy: (use "name") takes priority, then (default _ "name"), then "main".
    let use_policy = top_levels.iter().find_map(|tl| match tl {
        TopLevel::Use(name) => Some(name.as_str()),
        _ => None,
    });
    let default_decl = top_levels.iter().find_map(|tl| match tl {
        TopLevel::Default { effect, policy } => Some((*effect, policy.as_str())),
        _ => None,
    });
    let active_policy = use_policy
        .or(default_decl.map(|(_, p)| p))
        .unwrap_or("main");

    // Build policy name → body map.
    let mut policies: HashMap<&str, &[PolicyItem]> = HashMap::new();
    for tl in top_levels {
        if let TopLevel::Policy { name, body } = tl {
            policies.insert(name.as_str(), body);
        }
    }

    // Flatten the active policy, resolving includes, keeping v2 items.
    let mut items: Vec<(PolicyItem, String)> = Vec::new();
    let mut visited = Vec::new();
    flatten_policy_v2(active_policy, &policies, &mut items, &mut visited)?;

    // Resolve default effect: last bare PolicyItem::Effect in the flattened body
    // takes priority, then (default effect _), then Deny.
    let body_effect = items.iter().rev().find_map(|(item, _)| match item {
        PolicyItem::Effect(e) => Some(*e),
        _ => None,
    });
    let default_effect = body_effect
        .or(default_decl.map(|(e, _)| e))
        .unwrap_or(Effect::Deny);

    // Build the tree.
    let mut ids = IdAllocator::new();

    // Compile flat rules for backward-compat display (only top-level Rule items).
    let mut exec_rules = Vec::new();
    let mut fs_rules = Vec::new();
    let mut net_rules = Vec::new();
    let mut tool_rules = Vec::new();
    let mut sandbox_policies_map = HashMap::new();

    // Build tree children from items.
    let mut tree_children = Vec::new();
    for (item, origin) in &items {
        let node = compile_policy_item_to_node(
            item,
            origin,
            env,
            &mut ids,
            &mut exec_rules,
            &mut fs_rules,
            &mut net_rules,
            &mut tool_rules,
            &mut sandbox_policies_map,
            &policies,
        )?;
        if let Some(n) = node {
            tree_children.push(n);
        }
    }

    // Sort flat rules by specificity.
    let sort_fn = |a: &CompiledRule, b: &CompiledRule| {
        b.specificity
            .partial_cmp(&a.specificity)
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    exec_rules.sort_by(sort_fn);
    fs_rules.sort_by(sort_fn);
    net_rules.sort_by(sort_fn);
    tool_rules.sort_by(sort_fn);

    let root_id = ids.alloc(NodeMeta {
        description: "root sequence".into(),
        ..Default::default()
    });
    let root = Node::Sequence {
        id: root_id,
        children: tree_children,
    };

    Ok(PolicyTree {
        version,
        default: default_effect,
        policy_name: active_policy.to_string(),
        root,
        node_meta: ids.node_meta,
        exec_rules,
        fs_rules,
        net_rules,
        tool_rules,
        sandbox_policies: sandbox_policies_map,
    })
}

/// Flatten a v2 policy, resolving includes while preserving When/Sandbox items.
fn flatten_policy_v2(
    name: &str,
    policies: &HashMap<&str, &[PolicyItem]>,
    items: &mut Vec<(PolicyItem, String)>,
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
                flatten_policy_v2(target, policies, items, visited)?;
            }
            _ => {
                items.push((item.clone(), name.to_string()));
            }
        }
    }

    visited.pop();
    Ok(())
}

/// Compile a single PolicyItem into a tree Node.
///
/// For flat rules, also adds to the flat rule lists for backward-compat display.
#[allow(clippy::too_many_arguments)]
fn compile_policy_item_to_node(
    item: &PolicyItem,
    origin: &str,
    env: &dyn EnvResolver,
    ids: &mut IdAllocator,
    exec_rules: &mut Vec<CompiledRule>,
    fs_rules: &mut Vec<CompiledRule>,
    net_rules: &mut Vec<CompiledRule>,
    tool_rules: &mut Vec<CompiledRule>,
    sandbox_policies: &mut HashMap<String, Vec<CompiledRule>>,
    policies: &HashMap<&str, &[PolicyItem]>,
) -> Result<Option<Node>> {
    match item {
        PolicyItem::Include(_) => Ok(None), // already flattened
        PolicyItem::Rule(rule) => {
            // Compile to both flat rule list (display) and tree node.
            let specificity = Specificity::from_matcher(&rule.matcher);
            let compiled_matcher = compile_matcher(&rule.matcher, env)?;

            // Handle sandbox references for flat rules.
            let sandbox_key = resolve_sandbox_ref(&rule.sandbox, env, sandbox_policies, policies)?;

            let compiled = CompiledRule {
                effect: rule.effect,
                matcher: compiled_matcher,
                source: rule.clone(),
                specificity,
                sandbox: sandbox_key.clone(),
                origin_policy: Some(origin.to_string()),
                origin_level: None,
            };
            match &rule.matcher {
                CapMatcher::Exec(_) => exec_rules.push(compiled),
                CapMatcher::Fs(_) => fs_rules.push(compiled),
                CapMatcher::Net(_) => net_rules.push(compiled),
                CapMatcher::Tool(_) => tool_rules.push(compiled),
            }

            // Build tree node: When { predicate, Leaf }
            let predicate = match &rule.matcher {
                CapMatcher::Exec(m) => Predicate::Command(compile_exec_to_compiled(m, env)?),
                CapMatcher::Fs(m) => Predicate::Fs(compile_fs_to_compiled(m, env)?),
                CapMatcher::Net(m) => Predicate::Net(compile_net_to_compiled(m, env)?),
                CapMatcher::Tool(m) => Predicate::Tool(compile_tool_to_compiled(m)?),
            };

            let leaf_id = ids.alloc(NodeMeta {
                description: rule.to_string(),
                origin_policy: Some(origin.to_string()),
                ..Default::default()
            });
            let leaf = Node::Leaf {
                id: leaf_id,
                effect: rule.effect,
            };

            let when_id = ids.alloc(NodeMeta {
                description: rule.to_string(),
                origin_policy: Some(origin.to_string()),
                sandbox_name: sandbox_key,
                ..Default::default()
            });
            Ok(Some(Node::When {
                id: when_id,
                predicate,
                body: Box::new(leaf),
            }))
        }
        PolicyItem::When {
            observable,
            pattern,
            body,
        } => {
            // Compile the when guard (observable + pattern) into a Predicate.
            let compiled_pred = compile_when_guard(observable, pattern, env)?;

            // Compile body items recursively.
            let mut child_nodes = Vec::new();
            for child_item in body {
                let node = compile_policy_item_to_node(
                    child_item,
                    origin,
                    env,
                    ids,
                    exec_rules,
                    fs_rules,
                    net_rules,
                    tool_rules,
                    sandbox_policies,
                    policies,
                )?;
                if let Some(n) = node {
                    child_nodes.push(n);
                }
            }

            let body_node = if child_nodes.len() == 1 {
                child_nodes.pop().unwrap()
            } else {
                let seq_id = ids.alloc(NodeMeta {
                    description: format!("when body ({} items)", child_nodes.len()),
                    origin_policy: Some(origin.to_string()),
                    ..Default::default()
                });
                Node::Sequence {
                    id: seq_id,
                    children: child_nodes,
                }
            };

            let when_id = ids.alloc(NodeMeta {
                description: format!("(when ({observable} ...) ...)"),
                origin_policy: Some(origin.to_string()),
                ..Default::default()
            });
            Ok(Some(Node::When {
                id: when_id,
                predicate: compiled_pred,
                body: Box::new(body_node),
            }))
        }
        PolicyItem::Match(block) => {
            // Compile a policy-level match block into a Node::Match.
            compile_policy_match_to_node(block, origin, env, ids)
        }
        PolicyItem::Sandbox { body } => {
            // Compile sandbox items into a SandboxPolicy.
            let policy = compile_sandbox_items(body, env)?;

            let sandbox_id = ids.alloc(NodeMeta {
                description: "(sandbox ...)".to_string(),
                origin_policy: Some(origin.to_string()),
                ..Default::default()
            });
            Ok(Some(Node::Sandbox {
                id: sandbox_id,
                policy,
            }))
        }
        PolicyItem::Effect(effect) => {
            let leaf_id = ids.alloc(NodeMeta {
                description: format!(":{effect}"),
                origin_policy: Some(origin.to_string()),
                ..Default::default()
            });
            Ok(Some(Node::Leaf {
                id: leaf_id,
                effect: *effect,
            }))
        }
    }
}

/// Compile sandbox items (flat rules + match blocks) into a SandboxPolicy.
fn compile_sandbox_items(items: &[SandboxItem], env: &dyn EnvResolver) -> Result<SandboxPolicy> {
    let mut sandbox_rules: Vec<SandboxRule> = Vec::new();
    let mut network = NetworkPolicy::Deny;

    for item in items {
        match item {
            SandboxItem::Rule(rule) => {
                // Same as v1 sandbox_from_rules logic.
                let effect = match rule.effect {
                    Effect::Allow => RuleEffect::Allow,
                    Effect::Deny => RuleEffect::Deny,
                    Effect::Ask => {
                        bail!(":ask is not allowed in sandbox rules")
                    }
                };
                compile_sandbox_rule_to_policy(
                    &rule.matcher,
                    effect,
                    env,
                    &mut sandbox_rules,
                    &mut network,
                )?;
            }
            SandboxItem::Match(block) => {
                compile_match_to_sandbox(block, env, &mut sandbox_rules, &mut network)?;
            }
        }
    }

    // Add temp directory rules (reuse common logic).
    for path in DecisionTree::temp_directory_paths() {
        sandbox_rules.push(SandboxRule {
            effect: RuleEffect::Allow,
            caps: Cap::all(),
            path,
            path_match: PathMatch::Subpath,
        });
    }

    Ok(SandboxPolicy {
        default: Cap::READ | Cap::EXECUTE,
        rules: sandbox_rules,
        network,
    })
}

/// Compile a capability matcher into sandbox rules/network policy.
fn compile_sandbox_rule_to_policy(
    matcher: &CapMatcher,
    effect: RuleEffect,
    env: &dyn EnvResolver,
    sandbox_rules: &mut Vec<SandboxRule>,
    network: &mut NetworkPolicy,
) -> Result<()> {
    match matcher {
        CapMatcher::Fs(m) => {
            let caps = op_pattern_to_sandbox_caps(&m.op);
            match &m.path {
                Some(pf) => {
                    let compiled_pf = compile_path_filter(pf, env)?;
                    path_filter_to_sandbox_rules_compiled(
                        &compiled_pf,
                        effect,
                        caps,
                        sandbox_rules,
                    );
                }
                None => {
                    sandbox_rules.push(SandboxRule {
                        effect,
                        caps,
                        path: "/".to_string(),
                        path_match: PathMatch::Subpath,
                    });
                }
            }
        }
        CapMatcher::Net(m) => {
            if effect == RuleEffect::Allow {
                let compiled_domain = compile_pattern(&m.domain)?;
                match &compiled_domain {
                    CompiledPattern::Any => {
                        *network = NetworkPolicy::Allow;
                    }
                    _ => {
                        if *network != NetworkPolicy::Allow {
                            let mut domains = match network {
                                NetworkPolicy::AllowDomains(d) => d.clone(),
                                _ => Vec::new(),
                            };
                            DecisionTree::extract_domains_from_pattern(
                                &compiled_domain,
                                &mut domains,
                            );
                            if !domains.is_empty() {
                                *network = NetworkPolicy::AllowDomains(domains);
                            }
                        }
                    }
                }
            }
        }
        CapMatcher::Exec(_) | CapMatcher::Tool(_) => {
            // Sandbox restricts fs/net only.
        }
    }
    Ok(())
}

/// Compile a match block inside a sandbox into SandboxPolicy components.
fn compile_match_to_sandbox(
    block: &MatchBlock,
    env: &dyn EnvResolver,
    sandbox_rules: &mut Vec<SandboxRule>,
    network: &mut NetworkPolicy,
) -> Result<()> {
    match &block.observable {
        Observable::HttpDomain => {
            // Each arm adds to NetworkPolicy.
            for arm in &block.arms {
                let effect = match arm.effect {
                    Effect::Allow => RuleEffect::Allow,
                    Effect::Deny => RuleEffect::Deny,
                    Effect::Ask => bail!(":ask not allowed in sandbox"),
                };
                if effect == RuleEffect::Allow {
                    match &arm.pattern {
                        ArmPattern::Single(Pattern::Any) => {
                            *network = NetworkPolicy::Allow;
                        }
                        ArmPattern::Single(pat) => {
                            if *network != NetworkPolicy::Allow {
                                let mut domains = match network {
                                    NetworkPolicy::AllowDomains(d) => d.clone(),
                                    _ => Vec::new(),
                                };
                                let compiled = compile_pattern(pat)?;
                                DecisionTree::extract_domains_from_pattern(&compiled, &mut domains);
                                if !domains.is_empty() {
                                    *network = NetworkPolicy::AllowDomains(domains);
                                }
                            }
                        }
                        _ => bail!("ctx.http.domain match arm must be a single pattern"),
                    }
                }
                // :deny arms for ctx.http.domain are implicitly handled by deny-default.
            }
        }
        Observable::HttpMethod | Observable::HttpPort | Observable::HttpPath => {
            // Deferred for MVP — skip.
        }
        Observable::FsPath => {
            // Each arm → SandboxRule with all caps.
            for arm in &block.arms {
                let effect = match arm.effect {
                    Effect::Allow => RuleEffect::Allow,
                    Effect::Deny => RuleEffect::Deny,
                    Effect::Ask => bail!(":ask not allowed in sandbox"),
                };
                compile_arm_path_to_sandbox(&arm.pattern, effect, Cap::all(), env, sandbox_rules)?;
            }
        }
        Observable::FsAction => {
            // Each arm → SandboxRule for that op on all paths.
            for arm in &block.arms {
                let effect = match arm.effect {
                    Effect::Allow => RuleEffect::Allow,
                    Effect::Deny => RuleEffect::Deny,
                    Effect::Ask => bail!(":ask not allowed in sandbox"),
                };
                let caps = action_pattern_to_caps(&arm.pattern)?;
                sandbox_rules.push(SandboxRule {
                    effect,
                    caps,
                    path: "/".to_string(),
                    path_match: PathMatch::Subpath,
                });
            }
        }
        Observable::Tuple(obs) => {
            // Handle [ctx.fs.action ctx.fs.path] tuple.
            if obs.len() == 2
                && matches!(obs[0], Observable::FsAction)
                && matches!(obs[1], Observable::FsPath)
            {
                for arm in &block.arms {
                    let effect = match arm.effect {
                        Effect::Allow => RuleEffect::Allow,
                        Effect::Deny => RuleEffect::Deny,
                        Effect::Ask => bail!(":ask not allowed in sandbox"),
                    };
                    match &arm.pattern {
                        ArmPattern::Tuple(elems) if elems.len() == 2 => {
                            // First element: ctx.fs.action → caps.
                            let caps = match &elems[0] {
                                ArmPatternElement::Pat(pat) => {
                                    action_pattern_to_caps_from_pat(pat)?
                                }
                                _ => Cap::all(),
                            };
                            // Second element: ctx.fs.path → sandbox rules.
                            match &elems[1] {
                                ArmPatternElement::Path(pf) => {
                                    let compiled_pf = compile_path_filter(pf, env)?;
                                    path_filter_to_sandbox_rules_compiled(
                                        &compiled_pf,
                                        effect,
                                        caps,
                                        sandbox_rules,
                                    );
                                }
                                ArmPatternElement::Pat(Pattern::Any) => {
                                    sandbox_rules.push(SandboxRule {
                                        effect,
                                        caps,
                                        path: "/".to_string(),
                                        path_match: PathMatch::Subpath,
                                    });
                                }
                                ArmPatternElement::Pat(Pattern::Literal(s)) => {
                                    sandbox_rules.push(SandboxRule {
                                        effect,
                                        caps,
                                        path: s.clone(),
                                        path_match: PathMatch::Subpath,
                                    });
                                }
                                other => {
                                    bail!(
                                        "unsupported path pattern in [ctx.fs.action ctx.fs.path] arm: {other:?}"
                                    )
                                }
                            }
                        }
                        ArmPattern::Single(Pattern::Any) => {
                            // Wildcard arm: all caps, all paths.
                            sandbox_rules.push(SandboxRule {
                                effect,
                                caps: Cap::all(),
                                path: "/".to_string(),
                                path_match: PathMatch::Subpath,
                            });
                        }
                        other => {
                            bail!(
                                "expected tuple pattern for [ctx.fs.action ctx.fs.path], got: {other:?}"
                            )
                        }
                    }
                }
            } else {
                bail!("unsupported observable tuple: only [ctx.fs.action ctx.fs.path] is supported")
            }
        }
        Observable::FsExists => {
            // Deferred — requires runtime stat check.
        }
        Observable::ProcessCommand | Observable::ProcessArgs => {
            // Process observables don't apply to sandbox rules.
        }
        Observable::ToolName | Observable::ToolArgs | Observable::ToolArgField(_) => {
            // Tool context observables don't apply to sandbox rules.
        }
        Observable::AgentName => {
            // Agent context observables don't apply to sandbox rules.
        }
        Observable::State => {
            // State observable doesn't apply to sandbox rules.
        }
        Observable::Command | Observable::Tool | Observable::Agent => {
            // Command/tool/agent observables don't apply to sandbox rules (sandbox restricts fs/net only).
        }
    }
    Ok(())
}

/// Convert an arm path pattern into sandbox rules.
fn compile_arm_path_to_sandbox(
    pattern: &ArmPattern,
    effect: RuleEffect,
    caps: Cap,
    env: &dyn EnvResolver,
    sandbox_rules: &mut Vec<SandboxRule>,
) -> Result<()> {
    match pattern {
        ArmPattern::SinglePath(pf) => {
            let compiled_pf = compile_path_filter(pf, env)?;
            path_filter_to_sandbox_rules_compiled(&compiled_pf, effect, caps, sandbox_rules);
        }
        ArmPattern::Single(Pattern::Any) => {
            sandbox_rules.push(SandboxRule {
                effect,
                caps,
                path: "/".to_string(),
                path_match: PathMatch::Subpath,
            });
        }
        ArmPattern::Single(Pattern::Literal(s)) => {
            sandbox_rules.push(SandboxRule {
                effect,
                caps,
                path: s.clone(),
                path_match: PathMatch::Subpath,
            });
        }
        other => bail!("unsupported path arm pattern: {other:?}"),
    }
    Ok(())
}

/// Convert an action pattern to Cap flags.
fn action_pattern_to_caps(pattern: &ArmPattern) -> Result<Cap> {
    match pattern {
        ArmPattern::Single(pat) => action_pattern_to_caps_from_pat(pat),
        _ => bail!("expected single pattern for ctx.fs.action arm"),
    }
}

/// Convert a Pattern (from ctx.fs.action position) to Cap flags.
fn action_pattern_to_caps_from_pat(pat: &Pattern) -> Result<Cap> {
    match pat {
        Pattern::Any => Ok(Cap::all()),
        Pattern::Literal(s) => match s.as_str() {
            "read" => Ok(Cap::READ),
            "write" => Ok(Cap::WRITE | Cap::CREATE),
            "create" => Ok(Cap::CREATE),
            "delete" => Ok(Cap::DELETE),
            other => bail!("unknown fs action: {other}"),
        },
        Pattern::Or(pats) => {
            let mut caps = Cap::empty();
            for p in pats {
                caps |= action_pattern_to_caps_from_pat(p)?;
            }
            Ok(caps)
        }
        _ => Ok(Cap::all()), // conservative fallback
    }
}

/// Convert an OpPattern to sandbox Cap.
fn op_pattern_to_sandbox_caps(op: &OpPattern) -> Cap {
    match op {
        OpPattern::Any => Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE,
        OpPattern::Single(FsOp::Read) => Cap::READ,
        OpPattern::Single(FsOp::Write) => Cap::WRITE | Cap::CREATE,
        OpPattern::Single(FsOp::Create) => Cap::CREATE,
        OpPattern::Single(FsOp::Delete) => Cap::DELETE,
        OpPattern::Or(ops) => {
            let mut caps = Cap::empty();
            for op in ops {
                caps |= match op {
                    FsOp::Read => Cap::READ,
                    FsOp::Write => Cap::WRITE | Cap::CREATE,
                    FsOp::Create => Cap::CREATE,
                    FsOp::Delete => Cap::DELETE,
                };
            }
            caps
        }
    }
}

/// Convert a CompiledPathFilter into SandboxRules.
fn path_filter_to_sandbox_rules_compiled(
    pf: &CompiledPathFilter,
    effect: RuleEffect,
    caps: Cap,
    sandbox_rules: &mut Vec<SandboxRule>,
) {
    match pf {
        CompiledPathFilter::Subpath(path) => {
            sandbox_rules.push(SandboxRule {
                effect,
                caps,
                path: path.clone(),
                path_match: PathMatch::Subpath,
            });
        }
        CompiledPathFilter::Literal(path) => {
            sandbox_rules.push(SandboxRule {
                effect,
                caps,
                path: path.clone(),
                path_match: PathMatch::Literal,
            });
        }
        CompiledPathFilter::Regex(re) => {
            sandbox_rules.push(SandboxRule {
                effect,
                caps,
                path: re.as_str().to_string(),
                path_match: PathMatch::Regex,
            });
        }
        CompiledPathFilter::Or(filters) => {
            for f in filters {
                path_filter_to_sandbox_rules_compiled(f, effect, caps, sandbox_rules);
            }
        }
        CompiledPathFilter::Not(_) => {
            // Can't easily represent negation in sandbox rules — skip.
        }
    }
}

/// Resolve a sandbox reference to a key name (reused from v1 logic).
fn resolve_sandbox_ref(
    sandbox: &Option<SandboxRef>,
    env: &dyn EnvResolver,
    sandbox_policies: &mut HashMap<String, Vec<CompiledRule>>,
    policies: &HashMap<&str, &[PolicyItem]>,
) -> Result<Option<String>> {
    match sandbox {
        Some(SandboxRef::Named(name)) => {
            if !policies.contains_key(name.as_str()) {
                bail!(
                    "sandbox reference \"{}\" not found: no (policy \"{}\") defined",
                    name,
                    name
                );
            }
            // Compile the named sandbox policy if not already done.
            if !sandbox_policies.contains_key(name) {
                if let Some(body) = policies.get(name.as_str()) {
                    let mut rules = Vec::new();
                    for item in *body {
                        if let PolicyItem::Rule(rule) = item {
                            let sp = Specificity::from_matcher(&rule.matcher);
                            let cm = compile_matcher(&rule.matcher, env)?;
                            rules.push(CompiledRule {
                                effect: rule.effect,
                                matcher: cm,
                                source: rule.clone(),
                                specificity: sp,
                                sandbox: None,
                                origin_policy: None,
                                origin_level: None,
                            });
                        }
                    }
                    sandbox_policies.insert(name.clone(), rules);
                }
            }
            Ok(Some(name.clone()))
        }
        Some(SandboxRef::Inline(inline_rules)) => {
            let key = format!("__v2_inline_sandbox_{}__", sandbox_policies.len());
            let mut compiled_rules = Vec::new();
            for r in inline_rules {
                let sp = Specificity::from_matcher(&r.matcher);
                let cm = compile_matcher(&r.matcher, env)?;
                compiled_rules.push(CompiledRule {
                    effect: r.effect,
                    matcher: cm,
                    source: r.clone(),
                    specificity: sp,
                    sandbox: None,
                    origin_policy: None,
                    origin_level: None,
                });
            }
            sandbox_policies.insert(key.clone(), compiled_rules);
            Ok(Some(key))
        }
        None => Ok(None),
    }
}

// Helper: compile ExecMatcher → CompiledExec
fn compile_exec_to_compiled(m: &ExecMatcher, _env: &dyn EnvResolver) -> Result<CompiledExec> {
    let bin = compile_pattern(&m.bin)?;
    let args = m.args.iter().map(compile_pattern).collect::<Result<_>>()?;
    let has_args = m
        .has_args
        .iter()
        .map(compile_pattern)
        .collect::<Result<_>>()?;
    Ok(CompiledExec {
        bin,
        args,
        has_args,
    })
}

// Helper: compile FsMatcher → CompiledFs
fn compile_fs_to_compiled(m: &FsMatcher, env: &dyn EnvResolver) -> Result<CompiledFs> {
    let path = match &m.path {
        Some(pf) => Some(compile_path_filter(pf, env)?),
        None => None,
    };
    Ok(CompiledFs {
        op: m.op.clone(),
        path,
    })
}

// Helper: compile NetMatcher → CompiledNet
fn compile_net_to_compiled(m: &NetMatcher, env: &dyn EnvResolver) -> Result<CompiledNet> {
    let domain = compile_pattern(&m.domain)?;
    let path = match &m.path {
        Some(pf) => Some(compile_path_filter(pf, env)?),
        None => None,
    };
    Ok(CompiledNet { domain, path })
}

// Helper: compile ToolMatcher → CompiledTool
fn compile_tool_to_compiled(m: &ToolMatcher) -> Result<CompiledTool> {
    let name = compile_pattern(&m.name)?;
    Ok(CompiledTool { name })
}

/// Compile a when guard (Observable + ArmPattern) into a tree Predicate.
fn compile_when_guard(
    observable: &Observable,
    pattern: &ArmPattern,
    env: &dyn EnvResolver,
) -> Result<Predicate> {
    match observable {
        Observable::Command => {
            if let ArmPattern::Exec(m) = pattern {
                Ok(Predicate::Command(compile_exec_to_compiled(m, env)?))
            } else {
                bail!("command observable requires an exec pattern")
            }
        }
        Observable::Tool => {
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("tool observable requires a single pattern"),
            };
            Ok(Predicate::Tool(compile_tool_to_compiled(&ToolMatcher {
                name: pat.clone(),
            })?))
        }
        Observable::Agent => {
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("agent observable requires a single pattern"),
            };
            Ok(Predicate::Agent(compile_tool_to_compiled(&ToolMatcher {
                name: pat.clone(),
            })?))
        }
        Observable::HttpDomain => {
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("ctx.http.domain observable requires a single pattern"),
            };
            let domain = compile_pattern(pat)?;
            Ok(Predicate::Net(CompiledNet { domain, path: None }))
        }
        Observable::HttpMethod | Observable::HttpPort | Observable::HttpPath => {
            // Deferred — always true for now
            Ok(Predicate::True)
        }
        Observable::FsAction => {
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("ctx.fs.action observable requires a single pattern"),
            };
            let op = pattern_to_op_pattern(pat)?;
            Ok(Predicate::Fs(CompiledFs { op, path: None }))
        }
        Observable::FsPath => {
            let pf = match pattern {
                ArmPattern::SinglePath(pf) => pf,
                ArmPattern::Single(Pattern::Any) => {
                    return Ok(Predicate::Fs(CompiledFs {
                        op: OpPattern::Any,
                        path: None,
                    }));
                }
                _ => bail!("ctx.fs.path observable requires a path filter pattern"),
            };
            let compiled_pf = compile_path_filter(pf, env)?;
            Ok(Predicate::Fs(CompiledFs {
                op: OpPattern::Any,
                path: Some(compiled_pf),
            }))
        }
        Observable::FsExists => {
            // Deferred — always true for now
            Ok(Predicate::True)
        }
        Observable::ProcessCommand => {
            // ctx.process.command in a when guard: match on binary name
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("ctx.process.command observable requires a single pattern"),
            };
            let compiled = compile_pattern(pat)?;
            Ok(Predicate::Command(CompiledExec {
                bin: compiled,
                args: vec![],
                has_args: vec![],
            }))
        }
        Observable::ProcessArgs | Observable::ToolArgs | Observable::State => {
            // Deferred — always true for now
            Ok(Predicate::True)
        }
        Observable::ToolArgField(_) => {
            // Nullable field accessor in when guard: always true (field presence
            // is checked at match-dispatch time, not guard time).
            Ok(Predicate::True)
        }
        Observable::ToolName => {
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("ctx.tool.name observable requires a single pattern"),
            };
            Ok(Predicate::Tool(compile_tool_to_compiled(&ToolMatcher {
                name: pat.clone(),
            })?))
        }
        Observable::AgentName => {
            let pat = match pattern {
                ArmPattern::Single(p) => p,
                _ => bail!("ctx.agent.name observable requires a single pattern"),
            };
            Ok(Predicate::Agent(compile_tool_to_compiled(&ToolMatcher {
                name: pat.clone(),
            })?))
        }
        Observable::Tuple(_) => {
            bail!("tuple observables are not supported in when guards")
        }
    }
}

/// Convert a Pattern to an OpPattern (for ctx.fs.action when guards).
fn pattern_to_op_pattern(pat: &Pattern) -> Result<OpPattern> {
    match pat {
        Pattern::Any => Ok(OpPattern::Any),
        Pattern::Literal(s) => {
            let op = match s.as_str() {
                "read" => FsOp::Read,
                "write" => FsOp::Write,
                "create" => FsOp::Create,
                "delete" => FsOp::Delete,
                other => bail!("unknown fs action: {other}"),
            };
            Ok(OpPattern::Single(op))
        }
        Pattern::Or(pats) => {
            let mut ops = Vec::new();
            for p in pats {
                if let Pattern::Literal(s) = p {
                    let op = match s.as_str() {
                        "read" => FsOp::Read,
                        "write" => FsOp::Write,
                        "create" => FsOp::Create,
                        "delete" => FsOp::Delete,
                        other => bail!("unknown fs action: {other}"),
                    };
                    ops.push(op);
                } else {
                    bail!("expected literal fs action in (or ...) pattern")
                }
            }
            Ok(OpPattern::Or(ops))
        }
        _ => bail!("unsupported pattern type for ctx.fs.action"),
    }
}

/// Compile a policy-level match block into a Node::Match.
fn compile_policy_match_to_node(
    block: &MatchBlock,
    origin: &str,
    env: &dyn EnvResolver,
    ids: &mut IdAllocator,
) -> Result<Option<Node>> {
    let ir_observable = compile_observable_to_ir(&block.observable)?;

    let mut ir_arms = Vec::new();
    for arm in &block.arms {
        let ir_pattern = compile_arm_pattern_to_ir(&arm.pattern, &block.observable, env)?;
        let leaf_id = ids.alloc(NodeMeta {
            description: format!("match arm: {} → {}", arm.pattern, arm.effect_keyword()),
            origin_policy: Some(origin.to_string()),
            ..Default::default()
        });
        let body = Node::Leaf {
            id: leaf_id,
            effect: arm.effect,
        };
        ir_arms.push(MatchArm {
            pattern: ir_pattern,
            body,
        });
    }

    let match_id = ids.alloc(NodeMeta {
        description: format!("(match {} ...)", block.observable),
        origin_policy: Some(origin.to_string()),
        ..Default::default()
    });

    Ok(Some(Node::Match {
        id: match_id,
        observable: ir_observable,
        arms: ir_arms,
    }))
}

/// Compile an AST Observable to an IR Observable.
fn compile_observable_to_ir(obs: &Observable) -> Result<crate::policy::tree::Observable> {
    use crate::policy::tree as ir;
    match obs {
        Observable::Command => Ok(ir::Observable::Command),
        Observable::Tool => Ok(ir::Observable::Tool),
        Observable::HttpDomain => Ok(ir::Observable::HttpDomain),
        Observable::HttpMethod => Ok(ir::Observable::HttpMethod),
        Observable::HttpPort => Ok(ir::Observable::HttpPort),
        Observable::HttpPath => Ok(ir::Observable::HttpPath),
        Observable::FsAction => Ok(ir::Observable::FsAction),
        Observable::FsPath => Ok(ir::Observable::FsPath),
        Observable::FsExists => Ok(ir::Observable::FsExists),
        Observable::ProcessCommand => Ok(ir::Observable::ProcessCommand),
        Observable::ProcessArgs => Ok(ir::Observable::ProcessArgs),
        Observable::ToolName => Ok(ir::Observable::ToolName),
        Observable::ToolArgs => Ok(ir::Observable::ToolArgs),
        Observable::Agent => Ok(ir::Observable::Agent),
        Observable::AgentName => Ok(ir::Observable::AgentName),
        Observable::ToolArgField(field) => Ok(ir::Observable::ToolArgField(field.clone())),
        Observable::State => Ok(ir::Observable::State),
        Observable::Tuple(obs) => {
            let inner = obs
                .iter()
                .map(compile_observable_to_ir)
                .collect::<Result<_>>()?;
            Ok(ir::Observable::Tuple(inner))
        }
    }
}

/// Compile an AST ArmPattern to an IR MatchPattern.
fn compile_arm_pattern_to_ir(
    pattern: &ArmPattern,
    _observable: &Observable,
    env: &dyn EnvResolver,
) -> Result<crate::policy::tree::MatchPattern> {
    use crate::policy::tree as ir;
    match pattern {
        ArmPattern::Exec(m) => {
            let compiled = compile_exec_to_compiled(m, env)?;
            Ok(ir::MatchPattern::Exec(compiled))
        }
        ArmPattern::Single(p) => {
            let compiled = compile_pattern(p)?;
            Ok(ir::MatchPattern::Single(compiled))
        }
        ArmPattern::SinglePath(pf) => {
            let compiled = compile_path_filter(pf, env)?;
            Ok(ir::MatchPattern::PathFilter(compiled))
        }
        ArmPattern::Tuple(elems) => {
            let compiled = elems
                .iter()
                .map(|e| match e {
                    ArmPatternElement::Pat(p) => compile_pattern(p),
                    ArmPatternElement::Path(_pf) => {
                        // Path elements in tuple patterns: use Any pattern as placeholder.
                        // Tuple path matching is handled at sandbox level, not tree eval.
                        Ok(CompiledPattern::Any)
                    }
                })
                .collect::<Result<_>>()?;
            Ok(ir::MatchPattern::Tuple(compiled))
        }
    }
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

/// Inject internal policy definitions and includes into a parsed AST.
///
/// 1. Checks which internal policy names the user already defined (override)
/// 2. For non-overridden ones, parses embedded source, appends `TopLevel::Policy` items
/// 3. Prepends `(include "__internal_X__")` to the active policy body
fn inject_internal_includes(ast: &mut Vec<TopLevel>, internals: &[(&str, &str)]) -> Result<()> {
    // Collect user-defined policy names.
    let user_policies: std::collections::HashSet<String> = ast
        .iter()
        .filter_map(|tl| match tl {
            TopLevel::Policy { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();

    // Find the active policy name: (use ...) takes priority over (default ...).
    let active_policy = ast
        .iter()
        .find_map(|tl| match tl {
            TopLevel::Use(name) => Some(name.clone()),
            _ => None,
        })
        .or_else(|| {
            ast.iter().find_map(|tl| match tl {
                TopLevel::Default { policy, .. } => Some(policy.clone()),
                _ => None,
            })
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
        for tl in ast.iter_mut() {
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

    Ok(())
}

/// Compile with internal policies injected (returns flat `DecisionTree`).
pub fn compile_policy_with_internals(
    source: &str,
    env: &dyn EnvResolver,
    internals: &[(&str, &str)],
) -> Result<DecisionTree> {
    let mut ast = super::parse::parse(source)?;
    inject_internal_includes(&mut ast, internals)?;
    compile_ast(&ast, env)
}

/// Compile a policy source with internal policies, returning a `PolicyTree`.
///
/// Dispatches v1 → `DecisionTree` → `from_decision_tree()`, v2 → `compile_tree_ast()`.
pub fn compile_to_tree_with_internals(
    source: &str,
    env: &dyn EnvResolver,
    internals: &[(&str, &str)],
) -> Result<PolicyTree> {
    let mut ast = super::parse::parse(source)?;
    inject_internal_includes(&mut ast, internals)?;

    let version = super::version::extract_version(&ast)?;
    super::version::validate_version(version)?;

    if version >= 2 {
        compile_tree_ast(&ast, env)
    } else {
        let dt = compile_ast(&ast, env)?;
        Ok(PolicyTree::from_decision_tree(dt))
    }
}

/// Compile multiple policy levels with internals, returning a merged `PolicyTree`.
///
/// Injects internal policies into the lowest-precedence level, compiles each
/// level to a `PolicyTree`, then merges with `DenyOverrides` semantics.
pub fn compile_multi_level_to_tree(
    levels: &[(crate::settings::PolicyLevel, &str)],
    env: &dyn EnvResolver,
    internals: &[(&str, &str)],
) -> Result<PolicyTree> {
    use crate::settings::PolicyLevel;

    if levels.is_empty() {
        bail!("no policy levels to compile");
    }

    if levels.len() == 1 {
        return compile_to_tree_with_internals(levels[0].1, env, internals);
    }

    // Sort by precedence (lowest first) so index 0 gets internals.
    let mut sorted: Vec<(PolicyLevel, &str)> = levels.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    // Compile each level; inject internals into lowest-precedence.
    let mut level_trees = Vec::new();
    for (i, (level, source)) in sorted.iter().enumerate() {
        let tree = if i == 0 {
            compile_to_tree_with_internals(source, env, internals)
                .map_err(|e| anyhow::anyhow!("{} policy: {}", level.name(), e))?
        } else {
            compile_to_tree(source, env)
                .map_err(|e| anyhow::anyhow!("{} policy: {}", level.name(), e))?
        };
        level_trees.push(tree);
    }

    // Reverse for highest-precedence-first order.
    level_trees.reverse();

    Ok(PolicyTree::merge_levels(level_trees))
}

/// Compile a parsed AST into a decision tree.
fn compile_ast(top_levels: &[TopLevel], env: &dyn EnvResolver) -> Result<DecisionTree> {
    // Validate the declared policy syntax version.
    let version = super::version::extract_version(top_levels)?;
    super::version::validate_version(version)?;

    // Find the active policy: (use ...) takes priority over (default ...).
    let use_policy = top_levels.iter().find_map(|tl| match tl {
        TopLevel::Use(name) => Some(name.as_str()),
        _ => None,
    });
    let default_decl = top_levels.iter().find_map(|tl| match tl {
        TopLevel::Default { effect, policy } => Some((*effect, policy.as_str())),
        _ => None,
    });
    let active_policy = use_policy
        .or(default_decl.map(|(_, p)| p))
        .unwrap_or("main");
    let default_effect = default_decl.map(|(e, _)| e).unwrap_or(Effect::Deny);

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
            // v2 items are handled by compile_tree_ast, not flat compilation.
            // For v1 flatten, skip them (they won't appear in v1 policies).
            PolicyItem::When { .. }
            | PolicyItem::Match(_)
            | PolicyItem::Sandbox { .. }
            | PolicyItem::Effect(_) => {}
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
    detect_all_shadows_from_rules(
        &tree.exec_rules,
        &tree.fs_rules,
        &tree.net_rules,
        &tree.tool_rules,
    )
}

/// Detect shadows from flat rule slices (used by both DecisionTree and PolicyTree).
pub fn detect_all_shadows_from_rules(
    exec_rules: &[CompiledRule],
    fs_rules: &[CompiledRule],
    net_rules: &[CompiledRule],
    tool_rules: &[CompiledRule],
) -> AllShadows {
    AllShadows {
        exec: detect_shadows(exec_rules),
        fs: detect_shadows(fs_rules),
        net: detect_shadows(net_rules),
        tool: detect_shadows(tool_rules),
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

    // -----------------------------------------------------------------------
    // v2 compile_to_tree tests
    // -----------------------------------------------------------------------

    #[test]
    fn compile_to_tree_v1_policy() {
        let source = r#"
(version 1)
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (allow (fs read (subpath "/home/user"))))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();
        assert_eq!(tree.version, 1);
        assert_eq!(tree.default, Effect::Deny);
        assert_eq!(tree.policy_name, "main");
        // v1 policies should still populate flat rule lists.
        assert_eq!(tree.exec_rules.len(), 1);
        assert_eq!(tree.fs_rules.len(), 1);
    }

    #[test]
    fn compile_to_tree_v2_basic() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (command "git" *) :allow)
  (when (command "cargo")
    (sandbox
      (match ctx.http.domain
        "crates.io" :allow
        * :deny))))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();
        assert_eq!(tree.version, 2);
        assert_eq!(tree.default, Effect::Deny);
        // v2 when blocks don't populate flat rule lists.
        assert_eq!(tree.exec_rules.len(), 0);
    }

    #[test]
    fn compile_to_tree_v2_example_policy() {
        let source = r#"
(version 2)
(default deny "main")
(def tmpdirs ["/tmp" "/var/folders"])
(policy "rust"
  (when (command (or "cargo" "rustc"))
    (sandbox
      (match ctx.http.domain
        (or "github.com" "crates.io") :allow)
      (match [ctx.fs.action ctx.fs.path]
        ["read" (subpath "/home/user/project")] :allow
        [* (subpath "/tmp")] :allow))))
(policy "web"
  (when (tool (or "WebSearch" "WebFetch"))
    (sandbox
      (match ctx.http.domain
        "github.com" :allow
        * :deny))))
(policy "main"
  (include "rust")
  (include "web"))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_to_tree(source, &env).unwrap();
        assert_eq!(tree.version, 2);
        assert_eq!(tree.default, Effect::Deny);
        assert_eq!(tree.policy_name, "main");
    }

    #[test]
    fn compile_to_tree_v2_evaluate_when_match() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (command "cargo")
    (sandbox
      (match ctx.http.domain
        "crates.io" :allow
        * :deny)
      (match [ctx.fs.action ctx.fs.path]
        ["read" (subpath "/home/user")] :allow
        [* (subpath "/tmp")] :allow))))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        // cargo command should match the when predicate → Allow (via sandbox).
        let input = serde_json::json!({
            "command": "cargo build"
        });
        let decision = tree.evaluate("Bash", &input, "/home/user");
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "cargo should be allowed via sandbox"
        );
        assert!(decision.sandbox.is_some(), "should have sandbox policy");
    }

    #[test]
    fn compile_to_tree_v2_no_match_uses_default() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (command "cargo")
    (sandbox
      (match ctx.http.domain
        "crates.io" :allow))))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        // "git" doesn't match the when predicate → default deny.
        let input = serde_json::json!({
            "command": "git status"
        });
        let decision = tree.evaluate("Bash", &input, "/home/user");
        assert_eq!(decision.effect, Effect::Deny, "git should hit default deny");
    }

    #[test]
    fn compile_to_tree_with_internals_v2() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (command "cargo")
    (sandbox
      (match ctx.http.domain
        "crates.io" :allow))))
"#;
        let internals: &[(&str, &str)] = &[(
            "__test_internal__",
            r#"(policy "__test_internal__" (allow (exec "git" *)))"#,
        )];
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree_with_internals(source, &env, internals).unwrap();

        // git should be allowed via the injected internal policy.
        let input = serde_json::json!({ "command": "git status" });
        let decision = tree.evaluate("Bash", &input, "/home/user");
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "git should be allowed via internal policy"
        );
    }

    #[test]
    fn compile_multi_level_to_tree_basic() {
        let user_source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (allow (fs read (subpath "/home/user"))))
"#;
        let project_source = r#"
(default deny "main")
(policy "main"
  (deny (exec "git" "push" *)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_multi_level_to_tree(
            &[
                (PolicyLevel::User, user_source),
                (PolicyLevel::Project, project_source),
            ],
            &env,
            &[],
        )
        .unwrap();

        // "git push" should be denied (project deny overrides user allow).
        let input = serde_json::json!({ "command": "git push origin main" });
        let decision = tree.evaluate("Bash", &input, "/home/user");
        assert_eq!(decision.effect, Effect::Deny, "git push should be denied");

        // "git status" should be allowed (user allows, project has no match).
        let input = serde_json::json!({ "command": "git status" });
        let decision = tree.evaluate("Bash", &input, "/home/user");
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "git status should be allowed"
        );
    }

    #[test]
    fn compile_to_tree_v2_agent_when_allows() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (agent "Explore") :allow))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        let input = serde_json::json!({ "subagent_type": "Explore" });
        let decision = tree.evaluate("Agent", &input, "/home/user");
        assert_eq!(
            decision.effect,
            Effect::Allow,
            "agent Explore should be allowed"
        );
    }

    #[test]
    fn compile_to_tree_v2_agent_when_denies_other() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (agent "Explore") :allow))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        let input = serde_json::json!({ "subagent_type": "Plan" });
        let decision = tree.evaluate("Agent", &input, "/home/user");
        assert_eq!(
            decision.effect,
            Effect::Deny,
            "agent Plan should hit default deny"
        );
    }

    #[test]
    fn compile_to_tree_v2_agent_or_pattern() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (agent (or "Explore" "Verify")) :ask))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        let input = serde_json::json!({ "subagent_type": "Verify" });
        let decision = tree.evaluate("Agent", &input, "/home/user");
        assert_eq!(decision.effect, Effect::Ask, "agent Verify should be :ask");
    }

    #[test]
    fn compile_to_tree_v2_agent_does_not_match_tool() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (agent "Explore") :allow))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        // A normal tool (not Agent) should not match the agent predicate.
        let input = serde_json::json!({});
        let decision = tree.evaluate("WebFetch", &input, "/home/user");
        assert_eq!(
            decision.effect,
            Effect::Deny,
            "non-agent tool should not match agent predicate"
        );
    }

    #[test]
    fn compile_to_tree_v2_ctx_agent_name_match() {
        let source = r#"
(version 2)
(default deny "main")
(policy "main"
  (when (agent *)
    (match ctx.agent.name
      "Explore" :allow
      "Plan" :allow
      * :ask)))
"#;
        let env = TestEnv::new(&[("PWD", "/home/user")]);
        let tree = compile_to_tree(source, &env).unwrap();

        let input = serde_json::json!({ "subagent_type": "Explore" });
        let decision = tree.evaluate("Agent", &input, "/home/user");
        assert_eq!(decision.effect, Effect::Allow);

        let input = serde_json::json!({ "subagent_type": "Unknown" });
        let decision = tree.evaluate("Agent", &input, "/home/user");
        assert_eq!(decision.effect, Effect::Ask);
    }
}
