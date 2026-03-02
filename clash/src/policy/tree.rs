//! Tree-shaped policy IR.
//!
//! Replaces the flat `DecisionTree` for evaluation. Old flat syntax compiles
//! to degenerate linear trees via `from_decision_tree()`. The tree structure
//! supports future `when`/`match`/`sandbox` syntax (Phase 2).

use std::collections::HashMap;

use tracing::{debug, trace};

use crate::policy::Effect;
use crate::policy::ast::FsOp;
use crate::policy::decision_tree::{
    CompiledExec, CompiledFs, CompiledMatcher, CompiledNet, CompiledPattern, CompiledRule,
    CompiledTool, DecisionTree,
};
use crate::policy::eval::{CapQuery, tool_to_queries};
use crate::policy::ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
use crate::policy::sandbox_types::SandboxPolicy;
use crate::settings::PolicyLevel;

/// Stable node identifier, used as index into `PolicyTree::node_meta`.
pub type NodeId = u32;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A compiled policy in tree form, ready for evaluation.
#[derive(Debug, Clone)]
pub struct PolicyTree {
    /// Policy syntax version (1 if absent).
    pub version: u32,
    /// Default effect when no rule matches.
    pub default: Effect,
    /// Name of the active policy.
    pub policy_name: String,
    /// Root evaluation node.
    pub root: Node,
    /// Per-node metadata, indexed by `NodeId`.
    pub node_meta: Vec<NodeMeta>,

    // -- Backward-compat flat views (moved from DecisionTree) ---------------
    /// Flat exec rules sorted by specificity (for display / shadow detection).
    pub exec_rules: Vec<CompiledRule>,
    /// Flat fs rules sorted by specificity.
    pub fs_rules: Vec<CompiledRule>,
    /// Flat net rules sorted by specificity.
    pub net_rules: Vec<CompiledRule>,
    /// Flat tool rules sorted by specificity.
    pub tool_rules: Vec<CompiledRule>,
    /// Pre-compiled sandbox policy rules indexed by name.
    pub sandbox_policies: HashMap<String, Vec<CompiledRule>>,
}

/// A node in the evaluation tree.
#[derive(Debug, Clone)]
pub enum Node {
    /// Try children in order; first `Some(verdict)` wins.
    Sequence { id: NodeId, children: Vec<Node> },
    /// Evaluate ALL children; combine with deny > ask > allow.
    DenyOverrides { id: NodeId, children: Vec<Node> },
    /// If predicate matches, evaluate body; else skip (return None).
    When {
        id: NodeId,
        predicate: Predicate,
        body: Box<Node>,
    },
    /// Resolve observable, try arms in order; first match wins. (Phase 2)
    Match {
        id: NodeId,
        observable: Observable,
        arms: Vec<MatchArm>,
    },
    /// Return Allow + attached sandbox policy. (Phase 2)
    Sandbox { id: NodeId },
    /// Return the effect unconditionally.
    Leaf { id: NodeId, effect: Effect },
}

/// A predicate that gates a `When` node.
#[derive(Debug, Clone)]
pub enum Predicate {
    /// Matches exec queries (binary + args).
    Command(CompiledExec),
    /// Matches filesystem queries (op + path).
    Fs(CompiledFs),
    /// Matches network queries (domain + optional path).
    Net(CompiledNet),
    /// Matches tool queries (tool name).
    Tool(CompiledTool),
    /// Always matches.
    True,
}

/// An observable value for `Match` dispatch. (Phase 2)
#[derive(Debug, Clone)]
pub enum Observable {
    ProxyMethod,
    ProxyDomain,
    FsAction,
    FsPath,
    Tuple(Vec<Observable>),
}

/// One arm of a `Match` node. (Phase 2)
#[derive(Debug, Clone)]
pub struct MatchArm {
    pub pattern: MatchPattern,
    pub body: Node,
}

/// Pattern in a `Match` arm. (Phase 2)
#[derive(Debug, Clone)]
pub enum MatchPattern {
    Single(CompiledPattern),
    Tuple(Vec<CompiledPattern>),
}

/// Metadata associated with a node, indexed by `NodeId`.
#[derive(Debug, Clone, Default)]
pub struct NodeMeta {
    /// Node identifier (same as index in `node_meta` vec).
    pub id: NodeId,
    /// Human-readable description (typically the rule source text).
    pub description: String,
    /// Which named policy this node originated from.
    pub origin_policy: Option<String>,
    /// Which policy level (User/Project/Session) this node came from.
    pub origin_level: Option<PolicyLevel>,
    /// Original AST rule (for round-trip / display).
    pub source_rule: Option<crate::policy::ast::Rule>,
    /// Index in the domain's flat rule list (for backward-compat trace).
    pub rule_index: Option<usize>,
    /// Sandbox policy name referenced by this node's rule.
    pub sandbox_name: Option<String>,
}

/// Query context built from a tool invocation, used by predicate matching.
#[derive(Debug)]
pub struct QueryContext {
    pub tool_name: String,
    pub bin: Option<String>,
    pub args: Vec<String>,
    pub fs_op: Option<FsOp>,
    pub fs_path: Option<String>,
    pub net_domain: Option<String>,
    pub net_path: Option<String>,
    pub cwd: String,
}

// ---------------------------------------------------------------------------
// ID allocator (used during tree construction)
// ---------------------------------------------------------------------------

struct IdAllocator {
    next_id: NodeId,
    node_meta: Vec<NodeMeta>,
}

impl IdAllocator {
    fn new() -> Self {
        Self {
            next_id: 0,
            node_meta: Vec::new(),
        }
    }

    fn alloc(&mut self, mut meta: NodeMeta) -> NodeId {
        let id = self.next_id;
        self.next_id += 1;
        meta.id = id;
        self.node_meta.push(meta);
        id
    }
}

// ---------------------------------------------------------------------------
// Predicate matching
// ---------------------------------------------------------------------------

impl Predicate {
    /// Whether this predicate is relevant to the given query context.
    ///
    /// Irrelevant predicates are silently skipped (no trace entry), matching
    /// the old evaluator's behavior of only walking domain-specific rule lists.
    fn is_relevant(&self, ctx: &QueryContext) -> bool {
        match self {
            Predicate::Command(_) => ctx.bin.is_some(),
            Predicate::Fs(_) => ctx.fs_op.is_some(),
            Predicate::Net(_) => ctx.net_domain.is_some(),
            // Tool predicates are relevant only when no other domain matched,
            // matching the old `_ =>` fallthrough in tool_to_queries.
            Predicate::Tool(_) => {
                ctx.bin.is_none() && ctx.fs_op.is_none() && ctx.net_domain.is_none()
            }
            Predicate::True => true,
        }
    }

    /// Test whether this predicate matches the query context.
    fn matches(&self, ctx: &QueryContext) -> bool {
        match self {
            Predicate::Command(exec) => {
                if let Some(ref bin) = ctx.bin {
                    let arg_refs: Vec<&str> = ctx.args.iter().map(|s| s.as_str()).collect();
                    exec.matches(bin, &arg_refs)
                } else {
                    false
                }
            }
            Predicate::Fs(fs) => {
                if let (Some(op), Some(path)) = (ctx.fs_op, &ctx.fs_path) {
                    fs.matches(op, path)
                } else {
                    false
                }
            }
            Predicate::Net(net) => {
                if let Some(ref domain) = ctx.net_domain {
                    net.matches(domain, ctx.net_path.as_deref())
                } else {
                    false
                }
            }
            Predicate::Tool(tool) => tool.matches(&ctx.tool_name),
            Predicate::True => true,
        }
    }
}

impl QueryContext {
    /// Build a `QueryContext` from capability queries produced by `tool_to_queries`.
    fn from_queries(tool_name: &str, queries: &[CapQuery], cwd: &str) -> Self {
        let mut ctx = Self {
            tool_name: tool_name.to_string(),
            bin: None,
            args: Vec::new(),
            fs_op: None,
            fs_path: None,
            net_domain: None,
            net_path: None,
            cwd: cwd.to_string(),
        };

        for query in queries {
            match query {
                CapQuery::Exec { bin, args } => {
                    ctx.bin = Some(bin.clone());
                    ctx.args.clone_from(args);
                }
                CapQuery::Fs { op, path } => {
                    ctx.fs_op = Some(*op);
                    ctx.fs_path = Some(path.clone());
                }
                CapQuery::Net { domain, path } => {
                    ctx.net_domain = Some(domain.clone());
                    ctx.net_path = path.clone();
                }
                CapQuery::Tool { .. } => {
                    // tool_name is already set from the parameter
                }
            }
        }

        ctx
    }
}

// ---------------------------------------------------------------------------
// Bridge: DecisionTree -> PolicyTree
// ---------------------------------------------------------------------------

impl PolicyTree {
    /// Convert a flat `DecisionTree` into a tree-shaped `PolicyTree`.
    ///
    /// Old flat rules compile to a degenerate tree:
    /// ```text
    /// DenyOverrides [
    ///     Sequence [When+Leaf, When+Leaf, ...],  // exec
    ///     Sequence [When+Leaf, When+Leaf, ...],  // fs
    ///     Sequence [When+Leaf, When+Leaf, ...],  // net
    ///     Sequence [When+Leaf, When+Leaf, ...],  // tool
    /// ]
    /// ```
    pub fn from_decision_tree(dt: DecisionTree) -> Self {
        let mut ids = IdAllocator::new();

        let exec_seq = domain_to_sequence(&dt.exec_rules, &mut ids);
        let fs_seq = domain_to_sequence(&dt.fs_rules, &mut ids);
        let net_seq = domain_to_sequence(&dt.net_rules, &mut ids);
        let tool_seq = domain_to_sequence(&dt.tool_rules, &mut ids);

        let root_id = ids.alloc(NodeMeta {
            description: "root deny-overrides".into(),
            ..Default::default()
        });

        let root = Node::DenyOverrides {
            id: root_id,
            children: vec![exec_seq, fs_seq, net_seq, tool_seq],
        };

        Self {
            version: dt.version,
            default: dt.default,
            policy_name: dt.policy_name,
            root,
            node_meta: ids.node_meta,
            exec_rules: dt.exec_rules,
            fs_rules: dt.fs_rules,
            net_rules: dt.net_rules,
            tool_rules: dt.tool_rules,
            sandbox_policies: dt.sandbox_policies,
        }
    }
}

/// Convert a domain's flat rule list into a `Sequence` of `When { Leaf }` nodes.
fn domain_to_sequence(rules: &[CompiledRule], ids: &mut IdAllocator) -> Node {
    let mut children = Vec::with_capacity(rules.len());

    for (idx, rule) in rules.iter().enumerate() {
        let predicate = compiled_rule_to_predicate(rule);

        // Leaf node (holds the effect)
        let leaf_id = ids.alloc(NodeMeta {
            description: rule.source.to_string(),
            origin_policy: rule.origin_policy.clone(),
            origin_level: rule.origin_level,
            source_rule: Some(rule.source.clone()),
            rule_index: Some(idx),
            ..Default::default()
        });
        let leaf = Node::Leaf {
            id: leaf_id,
            effect: rule.effect,
        };

        // When node wrapping the leaf
        let when_id = ids.alloc(NodeMeta {
            description: rule.source.to_string(),
            origin_policy: rule.origin_policy.clone(),
            origin_level: rule.origin_level,
            source_rule: Some(rule.source.clone()),
            rule_index: Some(idx),
            sandbox_name: rule.sandbox.clone(),
            ..Default::default()
        });
        let when = Node::When {
            id: when_id,
            predicate,
            body: Box::new(leaf),
        };

        children.push(when);
    }

    let seq_id = ids.alloc(NodeMeta {
        description: format!("domain sequence ({} rules)", rules.len()),
        ..Default::default()
    });

    Node::Sequence {
        id: seq_id,
        children,
    }
}

/// Extract a `Predicate` from a `CompiledRule`'s matcher.
fn compiled_rule_to_predicate(rule: &CompiledRule) -> Predicate {
    match &rule.matcher {
        CompiledMatcher::Exec(e) => Predicate::Command(e.clone()),
        CompiledMatcher::Fs(f) => Predicate::Fs(f.clone()),
        CompiledMatcher::Net(n) => Predicate::Net(n.clone()),
        CompiledMatcher::Tool(t) => Predicate::Tool(t.clone()),
    }
}

// ---------------------------------------------------------------------------
// Tree evaluation
// ---------------------------------------------------------------------------

impl PolicyTree {
    /// Evaluate a tool request against this policy tree.
    ///
    /// Returns a `PolicyDecision` with effect, reason, trace, and optional
    /// sandbox policy. Produces identical output to `DecisionTree::evaluate`.
    pub fn evaluate(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) -> PolicyDecision {
        let queries = tool_to_queries(tool_name, tool_input, cwd);
        debug!(
            tool_name,
            query_count = queries.len(),
            "evaluating tool request (tree)"
        );

        if queries.is_empty() {
            return PolicyDecision {
                effect: self.default,
                reason: None,
                trace: DecisionTrace {
                    matched_rules: vec![],
                    skipped_rules: vec![],
                    final_resolution: format!(
                        "no capability query for tool '{}', default: {}",
                        tool_name, self.default
                    ),
                },
                sandbox: None,
            };
        }

        let ctx = QueryContext::from_queries(tool_name, &queries, cwd);
        let mut matched_rules = Vec::new();
        let mut skipped_rules = Vec::new();
        let mut sandbox_name: Option<String> = None;

        self.eval_node(
            &self.root,
            &ctx,
            &mut matched_rules,
            &mut skipped_rules,
            &mut sandbox_name,
        );

        // No rules matched -> use default.
        if matched_rules.is_empty() {
            return PolicyDecision {
                effect: self.default,
                reason: None,
                trace: DecisionTrace {
                    matched_rules,
                    skipped_rules,
                    final_resolution: format!("no rules matched, default: {}", self.default),
                },
                sandbox: None,
            };
        }

        // Deny-overrides: deny > ask > allow.
        let effect = matched_rules
            .iter()
            .map(|m| m.effect)
            .reduce(|acc, e| match (acc, e) {
                (Effect::Deny, _) | (_, Effect::Deny) => Effect::Deny,
                (Effect::Ask, _) | (_, Effect::Ask) => Effect::Ask,
                _ => Effect::Allow,
            })
            .unwrap_or(self.default);

        let reason = if effect == Effect::Deny || effect == Effect::Ask {
            matched_rules
                .iter()
                .find(|m| m.effect == effect)
                .map(|m| m.description.clone())
        } else {
            None
        };

        let final_resolution = if matched_rules.len() == 1 {
            format!("result: {}", effect)
        } else {
            let effects: Vec<String> = matched_rules.iter().map(|m| m.effect.to_string()).collect();
            format!("resolved {} from [{}]", effect, effects.join(", "))
        };

        // Build sandbox policy if allowed.
        let sandbox = if effect == Effect::Allow {
            sandbox_name
                .and_then(|name| self.build_sandbox_policy(&name, cwd))
                .or_else(|| self.build_implicit_sandbox())
        } else {
            None
        };

        PolicyDecision {
            effect,
            reason,
            trace: DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution,
            },
            sandbox,
        }
    }

    /// Recursively evaluate a node, collecting matches/skips into the trace.
    ///
    /// Returns `Some(effect)` when a verdict is reached, `None` to skip.
    fn eval_node(
        &self,
        node: &Node,
        ctx: &QueryContext,
        matched: &mut Vec<RuleMatch>,
        skipped: &mut Vec<RuleSkip>,
        sandbox_name: &mut Option<String>,
    ) -> Option<Effect> {
        match node {
            Node::DenyOverrides { children, .. } => {
                let mut effects = Vec::new();
                for child in children {
                    if let Some(eff) =
                        self.eval_node(child, ctx, matched, skipped, sandbox_name)
                    {
                        effects.push(eff);
                    }
                }
                if effects.is_empty() {
                    None
                } else {
                    Some(
                        effects
                            .into_iter()
                            .reduce(|acc, e| match (acc, e) {
                                (Effect::Deny, _) | (_, Effect::Deny) => Effect::Deny,
                                (Effect::Ask, _) | (_, Effect::Ask) => Effect::Ask,
                                _ => Effect::Allow,
                            })
                            .unwrap(),
                    )
                }
            }

            Node::Sequence { children, .. } => {
                for child in children {
                    if let Some(eff) =
                        self.eval_node(child, ctx, matched, skipped, sandbox_name)
                    {
                        return Some(eff);
                    }
                }
                None
            }

            Node::When {
                id,
                predicate,
                body,
            } => {
                let meta = &self.node_meta[*id as usize];

                // Skip silently if this predicate's domain is irrelevant.
                if !predicate.is_relevant(ctx) {
                    return None;
                }

                if predicate.matches(ctx) {
                    trace!(
                        node_id = id,
                        description = %meta.description,
                        "when predicate matched"
                    );

                    // Capture sandbox name from first matching exec rule.
                    if meta.sandbox_name.is_some() && sandbox_name.is_none() {
                        *sandbox_name = meta.sandbox_name.clone();
                    }

                    // For flat-bridge When+Leaf nodes, record the match at
                    // the When level and return the Leaf effect directly.
                    if let Some(idx) = meta.rule_index {
                        let effect = match body.as_ref() {
                            Node::Leaf { effect, .. } => *effect,
                            _ => {
                                return self.eval_node(body, ctx, matched, skipped, sandbox_name);
                            }
                        };

                        let mut description = meta.description.clone();
                        if let Some(ref sb) = meta.sandbox_name {
                            description.push_str(&format!(" [sandbox: {sb}]"));
                        }

                        matched.push(RuleMatch {
                            rule_index: idx,
                            description,
                            effect,
                            has_active_constraints: false,
                        });

                        Some(effect)
                    } else {
                        // Generic When (Phase 2): just eval the body.
                        self.eval_node(body, ctx, matched, skipped, sandbox_name)
                    }
                } else {
                    // Record skip (only for flat-bridge nodes with a rule_index).
                    if let Some(idx) = meta.rule_index {
                        let mut description = meta.description.clone();
                        if let Some(ref sb) = meta.sandbox_name {
                            description.push_str(&format!(" [sandbox: {sb}]"));
                        }
                        skipped.push(RuleSkip {
                            rule_index: idx,
                            description,
                            reason: "pattern mismatch".to_string(),
                        });
                    }
                    None
                }
            }

            Node::Leaf { effect, .. } => {
                // Bare leaf (not wrapped by When) — return effect directly.
                Some(*effect)
            }

            // Phase 2 nodes — not yet implemented.
            Node::Match { .. } | Node::Sandbox { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox helpers (delegate to DecisionTree's shared implementation)
// ---------------------------------------------------------------------------

impl PolicyTree {
    /// Build a `SandboxPolicy` from a named sandbox policy's compiled rules.
    pub fn build_sandbox_policy(&self, name: &str, _cwd: &str) -> Option<SandboxPolicy> {
        let rules = self.sandbox_policies.get(name)?;
        DecisionTree::sandbox_from_rules(rules.iter())
    }

    /// Build an implicit `SandboxPolicy` from this policy's own fs/net rules.
    pub fn build_implicit_sandbox(&self) -> Option<SandboxPolicy> {
        DecisionTree::sandbox_from_rules(self.fs_rules.iter().chain(self.net_rules.iter()))
    }

    /// Reconstruct the source text from the preserved AST nodes.
    pub fn to_source(&self) -> String {
        use std::collections::BTreeMap;

        let mut out = String::new();
        out.push_str(&format!(
            "(default {} \"{}\")\n",
            self.default, self.policy_name
        ));

        let all_rules: Vec<&CompiledRule> = self
            .exec_rules
            .iter()
            .chain(&self.fs_rules)
            .chain(&self.net_rules)
            .chain(&self.tool_rules)
            .collect();

        if all_rules.is_empty() {
            return out;
        }

        let mut groups: BTreeMap<&str, Vec<&CompiledRule>> = BTreeMap::new();
        let mut seen_origins: Vec<&str> = Vec::new();
        for rule in &all_rules {
            let origin = rule.origin_policy.as_deref().unwrap_or(&self.policy_name);
            if !seen_origins.contains(&origin) {
                seen_origins.push(origin);
            }
            groups.entry(origin).or_default().push(rule);
        }

        let mut included = Vec::new();
        for &origin in &seen_origins {
            if origin != self.policy_name {
                let rules = &groups[origin];
                out.push_str(&format!("\n(policy \"{}\"", origin));
                for rule in rules {
                    out.push_str(&format!("\n  {}", rule.source));
                }
                if rules.is_empty() {
                    out.push_str(")\n");
                } else {
                    out.push_str("\n)\n");
                }
                included.push(origin);
            }
        }

        let has_content = |inc: &[&str], rules: Option<&&Vec<&CompiledRule>>| -> bool {
            !inc.is_empty() || rules.is_some_and(|r| !r.is_empty())
        };
        if let Some(active_rules) = groups.get(self.policy_name.as_str()) {
            out.push_str(&format!("\n(policy \"{}\"", self.policy_name));
            for inc in &included {
                out.push_str(&format!("\n  (include \"{}\")", inc));
            }
            for rule in active_rules {
                out.push_str(&format!("\n  {}", rule.source));
            }
            if has_content(&included, Some(&active_rules)) {
                out.push_str("\n)\n");
            } else {
                out.push_str(")\n");
            }
        } else if !included.is_empty() {
            out.push_str(&format!("\n(policy \"{}\"", self.policy_name));
            for inc in &included {
                out.push_str(&format!("\n  (include \"{}\")", inc));
            }
            out.push_str("\n)\n");
        }

        out
    }

}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::policy::Effect;
    use crate::policy::compile::{EnvResolver, compile_policy_with_env};
    use crate::policy::sandbox_types::NetworkPolicy;

    use super::*;

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
        fn resolve(&self, name: &str) -> anyhow::Result<String> {
            self.0
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not set: {name}"))
        }
    }

    fn compile_tree(source: &str) -> PolicyTree {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let dt = compile_policy_with_env(source, &env).unwrap();
        PolicyTree::from_decision_tree(dt)
    }

    // -- Parallel evaluation: old DecisionTree vs new PolicyTree --------

    fn assert_same_decision(
        source: &str,
        tool_name: &str,
        tool_input: serde_json::Value,
        cwd: &str,
    ) {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let dt = compile_policy_with_env(source, &env).unwrap();
        let pt = PolicyTree::from_decision_tree(dt.clone());

        let old = dt.evaluate(tool_name, &tool_input, cwd);
        let new = pt.evaluate(tool_name, &tool_input, cwd);

        assert_eq!(old.effect, new.effect, "effect mismatch for {tool_name}");
        assert_eq!(old.reason, new.reason, "reason mismatch for {tool_name}");
        assert_eq!(
            old.trace.matched_rules.len(),
            new.trace.matched_rules.len(),
            "matched_rules count mismatch for {tool_name}"
        );
        assert_eq!(
            old.trace.skipped_rules.len(),
            new.trace.skipped_rules.len(),
            "skipped_rules count mismatch for {tool_name}"
        );
        assert_eq!(
            old.trace.final_resolution, new.trace.final_resolution,
            "final_resolution mismatch for {tool_name}"
        );
        assert_eq!(
            old.sandbox.is_some(),
            new.sandbox.is_some(),
            "sandbox presence mismatch for {tool_name}"
        );

        for (i, (om, nm)) in old
            .trace
            .matched_rules
            .iter()
            .zip(new.trace.matched_rules.iter())
            .enumerate()
        {
            assert_eq!(om.rule_index, nm.rule_index, "matched[{i}].rule_index");
            assert_eq!(om.description, nm.description, "matched[{i}].description");
            assert_eq!(om.effect, nm.effect, "matched[{i}].effect");
        }
        for (i, (os, ns)) in old
            .trace
            .skipped_rules
            .iter()
            .zip(new.trace.skipped_rules.iter())
            .enumerate()
        {
            assert_eq!(os.rule_index, ns.rule_index, "skipped[{i}].rule_index");
            assert_eq!(os.description, ns.description, "skipped[{i}].description");
            assert_eq!(os.reason, ns.reason, "skipped[{i}].reason");
        }
    }

    #[test]
    fn parallel_bash_deny() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#;
        assert_same_decision(
            source,
            "Bash",
            json!({"command": "git push origin main"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_bash_allow() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#;
        assert_same_decision(
            source,
            "Bash",
            json!({"command": "git status"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_read_allowed() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env PWD)))))
"#;
        assert_same_decision(
            source,
            "Read",
            json!({"file_path": "/home/user/project/src/main.rs"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_read_denied() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env PWD)))))
"#;
        assert_same_decision(
            source,
            "Read",
            json!({"file_path": "/etc/passwd"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_webfetch_allow() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        assert_same_decision(
            source,
            "WebFetch",
            json!({"url": "https://github.com/foo/bar"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_webfetch_deny() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        assert_same_decision(
            source,
            "WebFetch",
            json!({"url": "https://malware.evil.com/payload"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_unknown_tool_default() {
        let source = r#"
(default ask "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        assert_same_decision(
            source,
            "SomeUnknownTool",
            json!({"foo": "bar"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_tool_rule() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (tool)))
"#;
        assert_same_decision(
            source,
            "AskUserQuestion",
            json!({"questions": []}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_full_pipeline() {
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
        let cwd = "/home/user/project";
        assert_same_decision(source, "Bash", json!({"command": "git push origin main"}), cwd);
        assert_same_decision(source, "Bash", json!({"command": "git status"}), cwd);
        assert_same_decision(source, "Bash", json!({"command": "git commit -m fix"}), cwd);
        assert_same_decision(
            source,
            "Read",
            json!({"file_path": "/home/user/project/Cargo.toml"}),
            cwd,
        );
        assert_same_decision(source, "Read", json!({"file_path": "/etc/shadow"}), cwd);
        assert_same_decision(
            source,
            "WebFetch",
            json!({"url": "https://github.com/foo"}),
            cwd,
        );
        assert_same_decision(
            source,
            "WebFetch",
            json!({"url": "https://x.evil.com/bad"}),
            cwd,
        );
        assert_same_decision(source, "MagicTool", json!({}), cwd);
    }

    #[test]
    fn parallel_sandbox_exec() {
        let source = r#"
(default deny "main")
(policy "cargo-env"
  (allow (fs read (subpath (env PWD)))))
(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env"))
"#;
        assert_same_decision(
            source,
            "Bash",
            json!({"command": "cargo build"}),
            "/home/user/project",
        );
    }

    #[test]
    fn parallel_env_prefix() {
        let source = r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#;
        assert_same_decision(
            source,
            "Bash",
            json!({"command": "GIT_SSH_COMMAND=ssh git push origin main"}),
            "/home/user/project",
        );
    }

    // -- Tree-specific tests -----------------------------------------------

    #[test]
    fn sequence_first_wins() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *))
  (deny  (exec "git" "status")))
"#;
        // "deny git status" is more specific -> sorted first -> deny wins
        let tree = compile_tree(source);
        let decision =
            tree.evaluate("Bash", &json!({"command": "git status"}), "/home/user/project");
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn when_skip_no_match() {
        let source = r#"
(default ask "main")
(policy "main"
  (allow (exec "git" *)))
"#;
        let tree = compile_tree(source);
        let decision = tree.evaluate("Bash", &json!({"command": "ls"}), "/home/user/project");
        assert_eq!(decision.effect, Effect::Ask);
        assert!(decision.trace.skipped_rules.len() >= 1);
    }

    #[test]
    fn from_decision_tree_preserves_metadata() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let dt = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#,
            &env,
        )
        .unwrap();
        let pt = PolicyTree::from_decision_tree(dt);

        assert_eq!(pt.version, 1);
        assert_eq!(pt.default, Effect::Deny);
        assert_eq!(pt.policy_name, "main");
        assert_eq!(pt.exec_rules.len(), 1);

        let when_metas: Vec<_> = pt
            .node_meta
            .iter()
            .filter(|m| m.rule_index.is_some())
            .collect();
        assert!(!when_metas.is_empty());
        assert!(when_metas[0].description.contains("exec"));
    }

    #[test]
    fn implicit_sandbox_from_tree() {
        let source = r#"
(default deny "main")
(policy "main"
  (allow (exec))
  (allow (fs (or write create) (subpath (env PWD))))
  (allow (net)))
"#;
        let tree = compile_tree(source);
        let sandbox = tree
            .build_implicit_sandbox()
            .expect("should have implicit sandbox");
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
    }
}
