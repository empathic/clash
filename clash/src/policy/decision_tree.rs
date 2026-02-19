//! Decision tree IR — the compiled form of a policy.
//!
//! Rules are pre-compiled with regex patterns and sorted by specificity.
//! The decision tree groups rules by capability domain for efficient lookup.

use std::collections::HashMap;

use regex::Regex;

use crate::policy::Effect;
use crate::policy::sandbox_types::{
    Cap, NetworkPolicy, PathMatch, RuleEffect, SandboxPolicy, SandboxRule,
};

use super::ast::{self, FsOp, OpPattern, Rule};
use super::specificity::Specificity;

/// A compiled policy decision tree, ready for evaluation.
#[derive(Debug)]
pub struct DecisionTree {
    /// The default effect when no rule matches.
    pub default: Effect,
    /// The name of the active policy.
    pub policy_name: String,
    /// Compiled exec rules, sorted by specificity (most specific first).
    pub exec_rules: Vec<CompiledRule>,
    /// Compiled fs rules, sorted by specificity (most specific first).
    pub fs_rules: Vec<CompiledRule>,
    /// Compiled net rules, sorted by specificity (most specific first).
    pub net_rules: Vec<CompiledRule>,
    /// Compiled tool rules, sorted by specificity (most specific first).
    pub tool_rules: Vec<CompiledRule>,
    /// Pre-compiled sandbox policy rules indexed by name. Each contains the
    /// compiled fs/net rules from the referenced `(policy ...)` block.
    pub sandbox_policies: HashMap<String, Vec<CompiledRule>>,
}

/// A single compiled rule with pre-built regexes and a specificity rank.
#[derive(Debug)]
pub struct CompiledRule {
    /// The effect this rule produces.
    pub effect: Effect,
    /// Pre-compiled matcher for efficient evaluation.
    pub matcher: CompiledMatcher,
    /// The original AST rule (preserved for round-trip printing).
    pub source: Rule,
    /// Computed specificity rank.
    pub specificity: Specificity,
    /// Optional sandbox policy name (only for exec rules).
    pub sandbox: Option<String>,
    /// The policy this rule originated from (e.g. "main", "__internal_clash__").
    pub origin_policy: Option<String>,
    /// The policy level this rule originated from (User, Project, etc.).
    pub origin_level: Option<crate::settings::PolicyLevel>,
}

/// A pre-compiled capability matcher.
#[derive(Debug)]
pub enum CompiledMatcher {
    Exec(CompiledExec),
    Fs(CompiledFs),
    Net(CompiledNet),
    Tool(CompiledTool),
}

/// Pre-compiled exec matcher.
#[derive(Debug)]
pub struct CompiledExec {
    pub bin: CompiledPattern,
    /// Positional argument patterns.
    pub args: Vec<CompiledPattern>,
    /// Orderless `:has` argument patterns.
    pub has_args: Vec<CompiledPattern>,
}

/// Pre-compiled fs matcher.
#[derive(Debug)]
pub struct CompiledFs {
    pub op: ast::OpPattern,
    pub path: Option<CompiledPathFilter>,
}

/// Pre-compiled net matcher.
#[derive(Debug)]
pub struct CompiledNet {
    pub domain: CompiledPattern,
}

/// Pre-compiled tool matcher.
#[derive(Debug)]
pub struct CompiledTool {
    pub name: CompiledPattern,
}

/// A pattern with pre-compiled regex (if applicable).
#[derive(Debug)]
pub enum CompiledPattern {
    Any,
    Literal(String),
    Regex(Regex),
    Or(Vec<CompiledPattern>),
    Not(Box<CompiledPattern>),
}

/// A pre-compiled path filter.
#[derive(Debug)]
pub enum CompiledPathFilter {
    Subpath(String), // resolved path (env vars expanded)
    Literal(String),
    Regex(Regex),
    Or(Vec<CompiledPathFilter>),
    Not(Box<CompiledPathFilter>),
}

impl DecisionTree {
    /// Build a `SandboxPolicy` from a named sandbox policy's compiled rules.
    ///
    /// Walks the pre-compiled fs/net rules, converting AST types into
    /// sandbox types (Cap, SandboxRule, NetworkPolicy). Returns `None` if
    /// no fs rules are found (no filesystem restrictions = no sandbox needed).
    pub fn build_sandbox_policy(&self, name: &str, _cwd: &str) -> Option<SandboxPolicy> {
        let rules = self.sandbox_policies.get(name)?;
        Self::sandbox_from_rules(rules.iter())
    }

    /// Build an implicit `SandboxPolicy` from this policy's own fs/net rules.
    ///
    /// When an exec rule has no explicit `:sandbox` reference, the policy's
    /// own fs and net rules define what the spawned process can do. This
    /// ensures that `(allow (exec))` alongside `(allow (fs write (subpath
    /// (env PWD))))` actually restricts bash writes to PWD — consistent with
    /// how the fs rules constrain tool-level file operations.
    pub fn build_implicit_sandbox(&self) -> Option<SandboxPolicy> {
        Self::sandbox_from_rules(self.fs_rules.iter().chain(self.net_rules.iter()))
    }

    /// Shared implementation: convert a set of compiled rules into a
    /// `SandboxPolicy` by extracting fs and net constraints.
    fn sandbox_from_rules<'a>(
        rules: impl Iterator<Item = &'a CompiledRule>,
    ) -> Option<SandboxPolicy> {
        let mut sandbox_rules: Vec<SandboxRule> = Vec::new();
        let mut network = NetworkPolicy::Deny;

        for rule in rules {
            let effect = match rule.effect {
                Effect::Allow => RuleEffect::Allow,
                Effect::Deny => RuleEffect::Deny,
                Effect::Ask => RuleEffect::Allow, // treat ask as allow in sandbox context
            };

            match &rule.matcher {
                CompiledMatcher::Fs(fs) => {
                    let caps = op_pattern_to_caps(&fs.op);
                    match &fs.path {
                        Some(filter) => {
                            path_filter_to_sandbox_rules(filter, effect, caps, &mut sandbox_rules);
                        }
                        None => {
                            // No path filter = unrestricted for this op
                            sandbox_rules.push(SandboxRule {
                                effect,
                                caps,
                                path: "/".to_string(),
                                path_match: PathMatch::Subpath,
                            });
                        }
                    }
                }
                CompiledMatcher::Net(_) => {
                    if rule.effect == Effect::Allow {
                        network = NetworkPolicy::Allow;
                    }
                }
                CompiledMatcher::Exec(_) | CompiledMatcher::Tool(_) => {
                    // Sandbox restricts fs/net, not exec/tool — skip.
                }
            }
        }

        if sandbox_rules.is_empty() {
            return None;
        }

        Some(SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: sandbox_rules,
            network,
        })
    }

    /// Reconstruct the source text from the preserved AST nodes.
    ///
    /// Groups rules by their origin policy, emitting separate `(policy ...)`
    /// blocks and `(include ...)` directives for included policies.
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

        // Group rules by origin policy, preserving insertion order via BTreeMap.
        let mut groups: BTreeMap<&str, Vec<&CompiledRule>> = BTreeMap::new();
        let mut seen_origins: Vec<&str> = Vec::new();
        for rule in &all_rules {
            let origin = rule.origin_policy.as_deref().unwrap_or(&self.policy_name);
            if !seen_origins.contains(&origin) {
                seen_origins.push(origin);
            }
            groups.entry(origin).or_default().push(rule);
        }

        // Emit non-active policies first, then the active policy with includes.
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

        // Active policy with includes.
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
            // Active policy has no direct rules but includes others.
            out.push_str(&format!("\n(policy \"{}\"", self.policy_name));
            for inc in &included {
                out.push_str(&format!("\n  (include \"{}\")", inc));
            }
            out.push_str("\n)\n");
        }

        out
    }
}

impl CompiledPattern {
    /// Test if this pattern matches a string value.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            CompiledPattern::Any => true,
            CompiledPattern::Literal(s) => s == value,
            CompiledPattern::Regex(r) => r.is_match(value),
            CompiledPattern::Or(ps) => ps.iter().any(|p| p.matches(value)),
            CompiledPattern::Not(p) => !p.matches(value),
        }
    }
}

impl CompiledPathFilter {
    /// Test if this path filter matches a resolved path.
    pub fn matches(&self, path: &str) -> bool {
        match self {
            CompiledPathFilter::Subpath(base) => {
                path == base || path.starts_with(&format!("{base}/"))
            }
            CompiledPathFilter::Literal(s) => s == path,
            CompiledPathFilter::Regex(r) => r.is_match(path),
            CompiledPathFilter::Or(fs) => fs.iter().any(|f| f.matches(path)),
            CompiledPathFilter::Not(f) => !f.matches(path),
        }
    }
}

impl CompiledExec {
    /// Test if this exec matcher matches a binary name and argument list.
    pub fn matches(&self, bin: &str, args: &[&str]) -> bool {
        if !self.bin.matches(bin) {
            return false;
        }

        // 1. Check positional args left-to-right.
        for (i, pat) in self.args.iter().enumerate() {
            match args.get(i) {
                Some(arg) => {
                    if !pat.matches(arg) {
                        return false;
                    }
                }
                None => {
                    // No arg at this position — only matches if pattern is Any.
                    if !matches!(pat, CompiledPattern::Any) {
                        return false;
                    }
                }
            }
        }

        // 2. If we have :has patterns, check them against the remaining args
        //    (those not consumed by positional matching).
        if !self.has_args.is_empty() {
            let remaining = if self.args.is_empty() {
                args
            } else {
                args.get(self.args.len()..).unwrap_or(&[])
            };
            if !Self::matches_has(&self.has_args, remaining) {
                return false;
            }
        }

        true
    }

    /// Set-membership matching: each non-wildcard pattern must match at least
    /// one argument, regardless of order. Each argument can satisfy at most one
    /// pattern (greedy left-to-right).
    fn matches_has(patterns: &[CompiledPattern], args: &[&str]) -> bool {
        let mut used = vec![false; args.len()];
        for pat in patterns {
            if matches!(pat, CompiledPattern::Any) {
                continue; // wildcard is redundant in :has mode
            }
            let found = args
                .iter()
                .enumerate()
                .find(|(i, arg)| !used[*i] && pat.matches(arg));
            match found {
                Some((i, _)) => used[i] = true,
                None => return false,
            }
        }
        true
    }
}

impl CompiledFs {
    /// Test if this fs matcher matches a filesystem operation and resolved path.
    pub fn matches(&self, op: ast::FsOp, path: &str) -> bool {
        // Check operation filter.
        match &self.op {
            ast::OpPattern::Any => {}
            ast::OpPattern::Single(expected) => {
                if *expected != op {
                    return false;
                }
            }
            ast::OpPattern::Or(ops) => {
                if !ops.contains(&op) {
                    return false;
                }
            }
        }
        // Check path filter.
        match &self.path {
            None => true,
            Some(pf) => pf.matches(path),
        }
    }
}

impl CompiledNet {
    /// Test if this net matcher matches a domain string.
    pub fn matches(&self, domain: &str) -> bool {
        self.domain.matches(domain)
    }
}

impl CompiledTool {
    /// Test if this tool matcher matches a tool name.
    pub fn matches(&self, name: &str) -> bool {
        self.name.matches(name)
    }
}

// ---------------------------------------------------------------------------
// Sandbox generation helpers
// ---------------------------------------------------------------------------

/// Convert a single `FsOp` to a sandbox `Cap` flag.
fn fsop_to_cap(op: &FsOp) -> Cap {
    match op {
        FsOp::Read => Cap::READ,
        FsOp::Write => Cap::WRITE,
        FsOp::Create => Cap::CREATE,
        FsOp::Delete => Cap::DELETE,
    }
}

/// Convert an `OpPattern` to combined `Cap` flags.
fn op_pattern_to_caps(op: &OpPattern) -> Cap {
    match op {
        OpPattern::Any => Cap::READ | Cap::WRITE | Cap::CREATE | Cap::DELETE,
        OpPattern::Single(fsop) => fsop_to_cap(fsop),
        OpPattern::Or(ops) => ops.iter().fold(Cap::empty(), |acc, o| acc | fsop_to_cap(o)),
    }
}

/// Recursively flatten a `CompiledPathFilter` into `SandboxRule` entries.
fn path_filter_to_sandbox_rules(
    filter: &CompiledPathFilter,
    effect: RuleEffect,
    caps: Cap,
    rules: &mut Vec<SandboxRule>,
) {
    match filter {
        CompiledPathFilter::Subpath(s) => {
            rules.push(SandboxRule {
                effect,
                caps,
                path: s.clone(),
                path_match: PathMatch::Subpath,
            });
        }
        CompiledPathFilter::Literal(s) => {
            rules.push(SandboxRule {
                effect,
                caps,
                path: s.clone(),
                path_match: PathMatch::Literal,
            });
        }
        CompiledPathFilter::Regex(r) => {
            rules.push(SandboxRule {
                effect,
                caps,
                path: r.as_str().to_string(),
                path_match: PathMatch::Regex,
            });
        }
        CompiledPathFilter::Or(filters) => {
            for f in filters {
                path_filter_to_sandbox_rules(f, effect, caps, rules);
            }
        }
        CompiledPathFilter::Not(inner) => {
            let flipped = match effect {
                RuleEffect::Allow => RuleEffect::Deny,
                RuleEffect::Deny => RuleEffect::Allow,
            };
            path_filter_to_sandbox_rules(inner, flipped, caps, rules);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::policy::compile::{EnvResolver, compile_policy_with_env};

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

    #[test]
    fn build_sandbox_policy_fs_and_net() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "build-env"
  (allow (fs (or read write) (subpath (env PWD))))
  (deny  (fs write "/home/user/project/.git"))
  (allow (net "crates.io")))
(policy "main"
  (allow (exec "cargo" *) :sandbox "build-env"))
"#,
            &env,
        )
        .unwrap();

        let sandbox = tree
            .build_sandbox_policy("build-env", "/home/user/project")
            .expect("should produce sandbox");

        // Default: read + execute
        assert_eq!(sandbox.default, Cap::READ | Cap::EXECUTE);

        // Two fs rules: one allow subpath, one deny literal
        assert_eq!(sandbox.rules.len(), 2);

        let allow_rule = &sandbox.rules[0];
        assert_eq!(allow_rule.effect, RuleEffect::Allow);
        assert_eq!(allow_rule.caps, Cap::READ | Cap::WRITE);
        assert_eq!(allow_rule.path, "/home/user/project");
        assert_eq!(allow_rule.path_match, PathMatch::Subpath);

        let deny_rule = &sandbox.rules[1];
        assert_eq!(deny_rule.effect, RuleEffect::Deny);
        assert_eq!(deny_rule.caps, Cap::WRITE);
        assert_eq!(deny_rule.path, "/home/user/project/.git");
        assert_eq!(deny_rule.path_match, PathMatch::Literal);

        // Net: allow (because we have an allow net rule)
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
    }

    #[test]
    fn has_mode_order_independent() {
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (deny (exec "git" :has "push" "--force")))
"#,
            &env,
        )
        .unwrap();

        let rule = &tree.exec_rules[0];
        let m = match &rule.matcher {
            CompiledMatcher::Exec(e) => e,
            _ => panic!(),
        };

        // Order shouldn't matter.
        assert!(m.matches("git", &["push", "--force"]));
        assert!(m.matches("git", &["--force", "push"]));
        assert!(m.matches("git", &["--force", "push", "origin"]));
        assert!(m.matches("git", &["--verbose", "push", "--force"]));

        // Missing a required arg should fail.
        assert!(!m.matches("git", &["push"]));
        assert!(!m.matches("git", &["--force"]));
        assert!(!m.matches("git", &[]));

        // Wrong binary should fail.
        assert!(!m.matches("hg", &["push", "--force"]));
    }

    #[test]
    fn has_mode_with_regex() {
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (deny (exec "git" :has "push" /--force/)))
"#,
            &env,
        )
        .unwrap();

        let rule = &tree.exec_rules[0];
        let m = match &rule.matcher {
            CompiledMatcher::Exec(e) => e,
            _ => panic!(),
        };

        assert!(m.matches("git", &["push", "--force"]));
        assert!(m.matches("git", &["--force-with-lease", "push"]));
        assert!(!m.matches("git", &["push", "--verbose"]));
    }

    #[test]
    fn has_mode_with_wildcard_redundant() {
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (deny (exec "git" :has "push" *)))
"#,
            &env,
        )
        .unwrap();

        let rule = &tree.exec_rules[0];
        let m = match &rule.matcher {
            CompiledMatcher::Exec(e) => e,
            _ => panic!(),
        };

        // Wildcard is redundant in :has — only "push" matters.
        assert!(m.matches("git", &["push"]));
        assert!(m.matches("git", &["push", "origin"]));
        assert!(!m.matches("git", &["pull"]));
    }

    #[test]
    fn has_mode_single_arg() {
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (deny (exec "git" :has "push")))
"#,
            &env,
        )
        .unwrap();

        let rule = &tree.exec_rules[0];
        let m = match &rule.matcher {
            CompiledMatcher::Exec(e) => e,
            _ => panic!(),
        };

        assert!(m.matches("git", &["push"]));
        assert!(m.matches("git", &["--verbose", "push"]));
        assert!(m.matches("git", &["push", "origin", "main"]));
        assert!(!m.matches("git", &["pull"]));
        assert!(!m.matches("git", &[]));
    }

    #[test]
    fn has_mode_mixed_positional() {
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (deny (exec "git" "push" :has "--force")))
"#,
            &env,
        )
        .unwrap();

        let rule = &tree.exec_rules[0];
        let m = match &rule.matcher {
            CompiledMatcher::Exec(e) => e,
            _ => panic!(),
        };

        // arg[0] must be "push", remaining must contain "--force".
        assert!(m.matches("git", &["push", "--force"]));
        assert!(m.matches("git", &["push", "--force", "origin"]));
        assert!(m.matches("git", &["push", "origin", "--force"]));

        // "--force" before "push" fails because "push" is positional at arg[0].
        assert!(!m.matches("git", &["--force", "push"]));
        // Missing --force.
        assert!(!m.matches("git", &["push", "origin"]));
        // Wrong subcommand.
        assert!(!m.matches("git", &["pull", "--force"]));
    }

    #[test]
    fn build_sandbox_policy_missing_name_returns_none() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "cargo" *)))
"#,
            &env,
        )
        .unwrap();

        assert!(
            tree.build_sandbox_policy("nonexistent", "/home/user/project")
                .is_none()
        );
    }

    #[test]
    fn implicit_sandbox_from_fs_rules() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (allow (exec))
  (allow (fs (or write create) (subpath (env PWD))))
  (allow (net)))
"#,
            &env,
        )
        .unwrap();

        // Exec rule has no explicit sandbox, but implicit sandbox should
        // be built from the policy's own fs/net rules.
        assert!(tree.exec_rules[0].sandbox.is_none());
        let sandbox = tree
            .build_implicit_sandbox()
            .expect("should produce implicit sandbox");

        // fs rule: allow write+create under PWD
        assert_eq!(sandbox.rules.len(), 1);
        assert_eq!(sandbox.rules[0].effect, RuleEffect::Allow);
        assert_eq!(sandbox.rules[0].caps, Cap::WRITE | Cap::CREATE);
        assert_eq!(sandbox.rules[0].path, "/home/user/project");
        assert_eq!(sandbox.rules[0].path_match, PathMatch::Subpath);

        // net rule: allow (because policy has allow net)
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
    }

    #[test]
    fn implicit_sandbox_none_without_fs_rules() {
        let env = TestEnv::new(&[]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (allow (exec))
  (allow (net)))
"#,
            &env,
        )
        .unwrap();

        // No fs rules → no implicit sandbox
        assert!(tree.build_implicit_sandbox().is_none());
    }

    #[test]
    fn explicit_sandbox_overrides_implicit() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "custom-sandbox"
  (allow (fs read (subpath "/custom"))))
(policy "main"
  (allow (exec "cargo" *) :sandbox "custom-sandbox")
  (allow (fs (or write create) (subpath (env PWD)))))
"#,
            &env,
        )
        .unwrap();

        // The explicit sandbox should use the custom policy, not the implicit one.
        let explicit = tree
            .build_sandbox_policy("custom-sandbox", "/home/user/project")
            .expect("explicit sandbox");
        assert_eq!(explicit.rules.len(), 1);
        assert_eq!(explicit.rules[0].path, "/custom");

        // The implicit sandbox uses the policy's own fs rules.
        let implicit = tree.build_implicit_sandbox().expect("implicit sandbox");
        assert_eq!(implicit.rules.len(), 1);
        assert_eq!(implicit.rules[0].path, "/home/user/project");
    }
}
