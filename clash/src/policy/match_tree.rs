//! Match tree IR — a uniform trie for policy evaluation.
//!
//! Replaces the multi-node-type tree with a single `Condition` node type.
//! Capability domains (exec/fs/net) become Starlark compile-time sugar,
//! not IR concepts. Evaluation is a single DFS pass.

use std::collections::HashMap;
use std::sync::Arc;

use crate::policy::Effect;
use crate::policy::ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
use crate::policy::sandbox_types::SandboxPolicy;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// A value that can be resolved at eval time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    /// Resolve an environment variable.
    Env(String),
    /// A literal string.
    Literal(String),
    /// Join segments with `/`.
    Path(Vec<Value>),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Env(env) => write!(f, "${env}"),
            Value::Literal(lit) => write!(f, "'{lit}'"),
            Value::Path(values) => write!(f, "{values:#?}"),
        }
    }
}

impl Value {
    /// Resolve this value to a string.
    pub fn resolve(&self) -> String {
        match self {
            Value::Env(var) => std::env::var(var).unwrap_or_default(),
            Value::Literal(s) => s.clone(),
            Value::Path(parts) => parts
                .iter()
                .map(|p| p.resolve())
                .collect::<Vec<_>>()
                .join("/"),
        }
    }
}

// ---------------------------------------------------------------------------
// Pattern types
// ---------------------------------------------------------------------------

/// A pattern for matching against observable values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    /// Matches anything.
    Wildcard,
    /// Matches the resolved value of a `Value`.
    Literal(Value),
    /// Matches against a compiled regex.
    Regex(
        #[serde(
            serialize_with = "serialize_regex",
            deserialize_with = "deserialize_regex"
        )]
        Arc<Regex>,
    ),
    /// Matches if any sub-pattern matches.
    AnyOf(Vec<Pattern>),
    /// Matches if the sub-pattern does NOT match.
    Not(Box<Pattern>),
    /// Matches if the string starts with the resolved value (subpath matching).
    /// Matches both exact (path == prefix) and children (path starts with prefix + "/").
    Prefix(Value),
}

fn serialize_regex<S: serde::Serializer>(re: &Arc<Regex>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(re.as_str())
}

fn deserialize_regex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Arc<Regex>, D::Error> {
    let s = String::deserialize(d)?;
    Regex::new(&s)
        .map(Arc::new)
        .map_err(serde::de::Error::custom)
}

impl Pattern {
    /// Test whether this pattern matches a string value.
    pub fn matches(&self, value: &str) -> bool {
        match self {
            Pattern::Wildcard => true,
            Pattern::Literal(v) => v.resolve() == value,
            Pattern::Regex(re) => re.is_match(value),
            Pattern::AnyOf(pats) => pats.iter().any(|p| p.matches(value)),
            Pattern::Not(p) => !p.matches(value),
            Pattern::Prefix(v) => {
                let prefix = v.resolve();
                value == prefix || value.starts_with(&format!("{prefix}/"))
            }
        }
    }

    /// Specificity score for sorting. Higher = more specific.
    pub fn specificity(&self) -> u8 {
        match self {
            Pattern::Wildcard => 0,
            Pattern::Not(_) => 1,
            Pattern::AnyOf(_) => 1,
            Pattern::Regex(_) => 2,
            Pattern::Prefix(_) => 3,
            Pattern::Literal(_) => 4,
        }
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Pattern::Wildcard, Pattern::Wildcard) => true,
            (Pattern::Literal(a), Pattern::Literal(b)) => a == b,
            (Pattern::Regex(a), Pattern::Regex(b)) => a.as_str() == b.as_str(),
            (Pattern::AnyOf(a), Pattern::AnyOf(b)) => a == b,
            (Pattern::Not(a), Pattern::Not(b)) => a == b,
            (Pattern::Prefix(a), Pattern::Prefix(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Pattern {}

// ---------------------------------------------------------------------------
// Observable
// ---------------------------------------------------------------------------

/// What to observe from the query context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observable {
    /// The tool name (e.g. "Bash", "Read", "Write").
    ToolName,
    /// The hook type.
    HookType,
    /// The agent name.
    AgentName,
    /// A positional argument (0-indexed).
    PositionalArg(i32),
    /// Scan all args — true if any matches.
    HasArg,
    /// A named argument by key.
    NamedArg(String),
    /// A path into structured tool_input JSON.
    NestedField(Vec<String>),
    /// Capability: filesystem operation ("read" or "write").
    /// Mapped from tool name: Read/Glob/Grep → "read", Write/Edit → "write".
    FsOp,
    /// Capability: resolved filesystem path.
    /// Extracted from tool_input: file_path, path, or pattern field.
    FsPath,
    /// Capability: network domain.
    /// Extracted from WebFetch URL or "*" for WebSearch.
    NetDomain,
    /// The permission mode (e.g. "default", "plan").
    /// From Claude Code's permission_mode hook field.
    Mode,
}

impl Observable {
    /// Specificity score for sorting. Higher = more specific.
    pub fn specificity(&self) -> u8 {
        match self {
            Observable::ToolName => 1,
            Observable::HookType => 1,
            Observable::AgentName => 1,
            Observable::PositionalArg(_) => 2,
            Observable::HasArg => 1,
            Observable::NamedArg(_) => 2,
            Observable::NestedField(path) => 2 + path.len().min(3) as u8,
            Observable::FsOp => 1,
            Observable::FsPath => 2,
            Observable::NetDomain => 2,
            Observable::Mode => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox reference
// ---------------------------------------------------------------------------

/// Reference to a named sandbox definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRef(pub String);

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/// A leaf decision in the match tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allow, optionally with a sandbox.
    Allow(Option<SandboxRef>),
    /// Deny.
    Deny,
    /// Ask the user, optionally with a sandbox.
    Ask(Option<SandboxRef>),
}

impl Decision {
    pub fn effect(&self) -> Effect {
        match self {
            Decision::Allow(_) => Effect::Allow,
            Decision::Deny => Effect::Deny,
            Decision::Ask(_) => Effect::Ask,
        }
    }

    pub fn sandbox_ref(&self) -> Option<&SandboxRef> {
        match self {
            Decision::Allow(sb) | Decision::Ask(sb) => sb.as_ref(),
            Decision::Deny => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// A node in the match tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Node {
    /// A condition node: observe a value and test it against a pattern.
    Condition {
        observe: Observable,
        pattern: Pattern,
        /// Children sorted by specificity (most specific first).
        children: Vec<Node>,
        /// Optional docstring describing this rule's purpose.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        doc: Option<String>,
        /// Optional source provenance (e.g. policy level name).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        /// When true, asserts that no more positional args exist after this one.
        /// Analogous to `$` in regex — the match is exhaustive.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        terminal: bool,
    },
    /// A leaf decision.
    Decision(Decision),
}

impl Node {
    /// Stamp source provenance on a root-level Condition node if it has none.
    ///
    /// Leaves (`Decision`) and already-stamped nodes are left unchanged.
    pub fn stamp_source(&mut self, source: &str) {
        if let Node::Condition {
            source: slot @ None,
            ..
        } = self
        {
            *slot = Some(source.to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// CompiledPolicy
// ---------------------------------------------------------------------------

/// A fully compiled match-tree policy, ready for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// Named sandbox definitions.
    pub sandboxes: HashMap<String, SandboxPolicy>,
    /// Root-level children of the tree.
    pub tree: Vec<Node>,
    /// Default effect when no rule matches.
    #[serde(default = "default_effect")]
    pub default_effect: Effect,
    /// Name of the default sandbox (used by `clash shell` when no rule-specific sandbox matches).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sandbox: Option<String>,
}

fn default_effect() -> Effect {
    Effect::Ask
}

// ---------------------------------------------------------------------------
// PolicyManifest — on-disk policy.json representation
// ---------------------------------------------------------------------------

/// On-disk `policy.json` representation. Parsed at the loader level;
/// `includes` are resolved and merged before the inner `CompiledPolicy` is used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifest {
    /// Starlark files to include (evaluated and merged at load time).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<IncludeEntry>,
    /// The inline policy (tree, sandboxes, default_effect, etc.).
    #[serde(flatten)]
    pub policy: CompiledPolicy,
}

/// A single include directive in `policy.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludeEntry {
    /// Path to a `.star` file. `@clash//` prefix resolves to the embedded stdlib;
    /// other paths are relative to the directory containing `policy.json`.
    pub path: String,
}

impl CompiledPolicy {
    /// Return the number of root-level rule branches.
    pub fn rule_count(&self) -> usize {
        self.tree.len()
    }

    /// Format rules as human-readable lines for display (flat, denormalized).
    pub fn format_rules(&self) -> Vec<String> {
        super::format::format_rules(self)
    }

    /// Format rules as a tree with box-drawing characters.
    pub fn format_tree(&self) -> Vec<String> {
        super::format::format_tree(self)
    }
}

// ---------------------------------------------------------------------------
// Query context for evaluation
// ---------------------------------------------------------------------------

/// The context passed to the evaluator, extracted from a tool invocation.
#[derive(Debug)]
pub struct QueryContext {
    /// The tool name (e.g. "Bash", "Read").
    pub tool_name: String,
    /// Positional args (for Bash: parsed command parts).
    pub args: Vec<String>,
    /// The full tool_input JSON.
    pub tool_input: serde_json::Value,
    /// Hook type, if this is a hook invocation.
    pub hook_type: Option<String>,
    /// Agent name, if this is an agent invocation.
    pub agent_name: Option<String>,
    /// Capability: filesystem operation ("read" or "write"), if applicable.
    pub fs_op: Option<String>,
    /// Capability: resolved filesystem path, if applicable.
    pub fs_path: Option<String>,
    /// Capability: network domain, if applicable.
    pub net_domain: Option<String>,
    /// Permission mode from Claude Code (e.g. "default", "plan").
    pub mode: Option<String>,
}

impl QueryContext {
    /// Build a QueryContext from a tool invocation.
    pub fn from_tool(tool_name: &str, tool_input: &serde_json::Value) -> Self {
        let args = match tool_name {
            "Bash" => {
                let command = tool_input
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let parts: Vec<&str> = command.split_whitespace().collect();
                let (bin, rest) = parse_bash_bin_args(&parts);
                let mut args = vec![bin];
                args.extend(rest);
                args
            }
            _ => vec![],
        };

        // Extract capability-level fields from tool invocations.
        let (fs_op, fs_path) = match tool_name {
            "Read" => (
                Some("read".to_string()),
                tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .map(resolve_relative_path),
            ),
            "Glob" | "Grep" => (
                Some("read".to_string()),
                tool_input
                    .get("path")
                    .or_else(|| tool_input.get("pattern"))
                    .and_then(|v| v.as_str())
                    .map(resolve_relative_path),
            ),
            "Write" | "Edit" => (
                Some("write".to_string()),
                tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .map(resolve_relative_path),
            ),
            _ => (None, None),
        };

        let net_domain = match tool_name {
            "WebFetch" => tool_input
                .get("url")
                .and_then(|v| v.as_str())
                .and_then(extract_domain),
            "WebSearch" => Some("*".to_string()),
            _ => None,
        };

        QueryContext {
            tool_name: tool_name.to_string(),
            args,
            tool_input: tool_input.clone(),
            hook_type: None,
            agent_name: None,
            fs_op,
            fs_path,
            net_domain,
            mode: None,
        }
    }

    /// Extract the value of an observable from this context.
    fn extract(&self, obs: &Observable) -> Option<Vec<String>> {
        match obs {
            Observable::ToolName => Some(vec![self.tool_name.clone()]),
            Observable::HookType => self.hook_type.clone().map(|h| vec![h]),
            Observable::AgentName => self.agent_name.clone().map(|a| vec![a]),
            Observable::PositionalArg(i) => {
                let idx = *i as usize;
                self.args.get(idx).map(|a| vec![a.clone()])
            }
            Observable::HasArg => Some(self.args.clone()),
            Observable::NamedArg(name) => self
                .tool_input
                .get(name)
                .and_then(|v| v.as_str())
                .map(|s| vec![s.to_string()]),
            Observable::NestedField(path) => {
                let mut current = &self.tool_input;
                for segment in path {
                    current = current.get(segment)?;
                }
                current.as_str().map(|s| vec![s.to_string()])
            }
            Observable::FsOp => self.fs_op.clone().map(|op| vec![op]),
            Observable::FsPath => self.fs_path.clone().map(|p| vec![p]),
            Observable::NetDomain => self.net_domain.clone().map(|d| vec![d]),
            Observable::Mode => self.mode.clone().map(|m| vec![m]),
        }
    }
}

/// Resolve a potentially relative path against CWD.
fn resolve_relative_path(path: &str) -> String {
    super::path::PathResolver::from_env().resolve_relative(path)
}

/// Extract the domain from a URL string.
fn extract_domain(url: &str) -> Option<String> {
    // Simple extraction: skip scheme, take host
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = without_scheme.split('/').next()?;
    // Strip port if present
    let domain = host.split(':').next()?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

// ---------------------------------------------------------------------------
// Bash command parsing utilities
// ---------------------------------------------------------------------------

/// Extract the binary name and arguments from whitespace-split Bash command tokens,
/// skipping leading environment variable assignments, the `env` utility, and
/// transparent prefix commands (`time`, `nice`, etc.).
pub(crate) fn parse_bash_bin_args(parts: &[&str]) -> (String, Vec<String>) {
    let mut i = 0;

    loop {
        while i < parts.len() && is_env_assignment(parts[i]) {
            i += 1;
        }

        if i < parts.len() && parts[i] == "env" {
            i += 1;
            while i < parts.len() && is_env_assignment(parts[i]) {
                i += 1;
            }
            continue;
        }

        if i < parts.len()
            && let Some(skip) = transparent_prefix_skip(parts[i], parts.get(i + 1..).unwrap_or(&[]))
        {
            i += 1 + skip;
            continue;
        }

        break;
    }

    match parts.get(i) {
        Some(bin) => (
            bin.to_string(),
            parts[i + 1..].iter().map(|s| s.to_string()).collect(),
        ),
        None => (String::new(), vec![]),
    }
}

fn is_env_assignment(token: &str) -> bool {
    match token.find('=') {
        Some(0) | None => false,
        Some(pos) => {
            let name = &token[..pos];
            let mut chars = name.chars();
            match chars.next() {
                Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
                }
                _ => false,
            }
        }
    }
}

fn transparent_prefix_skip(cmd: &str, rest: &[&str]) -> Option<usize> {
    match cmd {
        "time" => Some(skip_flags(rest, &["-f", "-o"])),
        "command" => {
            if rest.first().is_some_and(|f| *f == "-v" || *f == "-V") {
                None
            } else {
                Some(skip_flags(rest, &[]))
            }
        }
        "nice" => Some(skip_flags(rest, &["-n"])),
        "nohup" => Some(0),
        "timeout" => {
            let flags = skip_flags(rest, &["-s", "-k", "--signal", "--kill-after"]);
            if flags < rest.len() {
                Some(flags + 1)
            } else {
                Some(flags)
            }
        }
        _ => None,
    }
}

fn skip_flags(tokens: &[&str], value_flags: &[&str]) -> usize {
    let mut i = 0;
    while i < tokens.len() && tokens[i].starts_with('-') {
        let flag = tokens[i];
        i += 1;
        if flag.contains('=') {
            continue;
        }
        if value_flags.contains(&flag) && i < tokens.len() {
            i += 1;
        }
    }
    i
}

// ---------------------------------------------------------------------------
// Evaluation trace
// ---------------------------------------------------------------------------

/// Trace of the DFS evaluation for debugging.
#[derive(Debug, Clone, Default)]
pub struct EvalTrace {
    /// Branches entered that produced a decision.
    pub matched: Vec<TraceEntry>,
    /// Branches where pattern didn't match.
    pub skipped: Vec<TraceEntry>,
    /// Branches entered but no decision found (backtracked).
    pub dead_ends: Vec<TraceEntry>,
}

/// A single trace entry recording a node visit.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// Path of observables traversed to reach this node.
    pub path: Vec<String>,
    /// The observable at this node.
    pub observable: String,
    /// The pattern tested.
    pub pattern_desc: String,
    /// The value tested against.
    pub tested_value: Option<String>,
}

// ---------------------------------------------------------------------------
// DFS Evaluator
// ---------------------------------------------------------------------------

/// Evaluate the match tree against a query context.
///
/// Returns the first decision found via DFS, or None if no branch matches.
pub fn eval(nodes: &[Node], ctx: &QueryContext) -> Option<Decision> {
    for node in nodes {
        match node {
            Node::Decision(d) => return Some(d.clone()),
            Node::Condition {
                observe,
                pattern,
                children,
                terminal,
                ..
            } => {
                if matches_observable(observe, pattern, *terminal, ctx)
                    && let Some(d) = eval(children, ctx)
                {
                    return Some(d);
                }
            }
        }
    }
    None
}

/// Evaluate with tracing, recording which branches were taken/skipped.
pub fn eval_traced(
    nodes: &[Node],
    ctx: &QueryContext,
    trace: &mut EvalTrace,
    path: &mut Vec<String>,
) -> Option<Decision> {
    for node in nodes {
        match node {
            Node::Decision(d) => return Some(d.clone()),
            Node::Condition {
                observe,
                pattern,
                children,
                terminal,
                ..
            } => {
                let obs_name = format!("{observe:?}");
                let pat_desc = format!("{pattern:?}");
                let values = ctx.extract(observe);
                let tested = values.as_ref().map(|vs| vs.join(", "));

                if matches_observable(observe, pattern, *terminal, ctx) {
                    path.push(obs_name.clone());
                    if let Some(d) = eval_traced(children, ctx, trace, path) {
                        trace.matched.push(TraceEntry {
                            path: path.clone(),
                            observable: obs_name,
                            pattern_desc: pat_desc,
                            tested_value: tested,
                        });
                        path.pop();
                        return Some(d);
                    }
                    // Entered but no decision found — dead end.
                    trace.dead_ends.push(TraceEntry {
                        path: path.clone(),
                        observable: obs_name,
                        pattern_desc: pat_desc,
                        tested_value: tested,
                    });
                    path.pop();
                } else {
                    trace.skipped.push(TraceEntry {
                        path: path.clone(),
                        observable: obs_name,
                        pattern_desc: pat_desc,
                        tested_value: tested,
                    });
                }
            }
        }
    }
    None
}

/// Walk the tree and return the index path to the first matching decision.
fn find_match_path_dfs(nodes: &[Node], ctx: &QueryContext) -> Option<Vec<usize>> {
    for (i, node) in nodes.iter().enumerate() {
        match node {
            Node::Decision(_) => return Some(vec![i]),
            Node::Condition {
                observe,
                pattern,
                children,
                terminal,
                ..
            } => {
                if matches_observable(observe, pattern, *terminal, ctx)
                    && let Some(mut child_path) = find_match_path_dfs(children, ctx)
                {
                    child_path.insert(0, i);
                    return Some(child_path);
                }
            }
        }
    }
    None
}

/// Test whether an observable matches a pattern in the given context.
///
/// When `terminal` is true and the observable is a `PositionalArg(i)`,
/// additionally asserts that no more positional args exist after index `i`.
/// This is analogous to `$` in regex — the match is exhaustive.
fn matches_observable(
    obs: &Observable,
    pattern: &Pattern,
    terminal: bool,
    ctx: &QueryContext,
) -> bool {
    match obs {
        Observable::HasArg => {
            // HasArg: true if ANY arg matches the pattern
            ctx.args.iter().any(|arg| pattern.matches(arg))
        }
        Observable::PositionalArg(i) if terminal => {
            let idx = *i as usize;
            match ctx.args.get(idx) {
                Some(val) if pattern.matches(val) => ctx.args.len() == idx + 1,
                _ => false,
            }
        }
        Observable::ToolName => {
            // Tool name matching is case-insensitive and supports canonical aliases.
            // All of these match tool_name="Bash": "Bash", "bash", "shell", "Shell".
            let tool = &ctx.tool_name;
            let tool_lower = tool.to_lowercase();
            let canonical = crate::agents::internal_to_canonical(tool);

            // Build the set of names this tool is known by.
            let mut aliases = vec![tool.clone(), tool_lower.clone()];
            if let Some(c) = canonical {
                aliases.push(c.to_string());
                let c_lower = c.to_lowercase();
                if c_lower != c {
                    aliases.push(c_lower);
                }
            }

            match pattern {
                Pattern::Wildcard => true,
                Pattern::Literal(v) => {
                    let pat = v.resolve();
                    let pat_lower = pat.to_lowercase();
                    // Direct or case-insensitive match against any alias
                    aliases.iter().any(|a| a == &pat || a.to_lowercase() == pat_lower)
                    // Or the pattern is a canonical name that resolves to this tool
                    || crate::agents::canonical_to_internal(&pat)
                        .is_some_and(|resolved| resolved.eq_ignore_ascii_case(tool))
                }
                _ => {
                    // Regex, AnyOf, Not, Prefix — match against all aliases
                    aliases.iter().any(|v| pattern.matches(v))
                }
            }
        }
        _ => {
            // For all other observables, extract the value and match
            if let Some(values) = ctx.extract(obs) {
                values.iter().any(|v| pattern.matches(v))
            } else {
                // No value available — only Wildcard matches
                matches!(pattern, Pattern::Wildcard)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CompiledPolicy evaluation
// ---------------------------------------------------------------------------

impl CompiledPolicy {
    /// Evaluate this policy against a tool invocation.
    pub fn evaluate(&self, tool_name: &str, tool_input: &serde_json::Value) -> PolicyDecision {
        let ctx = QueryContext::from_tool(tool_name, tool_input);
        self.evaluate_ctx(&ctx)
    }

    /// Evaluate this policy with mode and agent context.
    pub fn evaluate_with_mode(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
        mode: Option<&str>,
    ) -> PolicyDecision {
        self.evaluate_with_context(tool_name, tool_input, mode, None)
    }

    /// Evaluate this policy with mode and agent context.
    pub fn evaluate_with_context(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
        mode: Option<&str>,
        agent_name: Option<&str>,
    ) -> PolicyDecision {
        let mut ctx = QueryContext::from_tool(tool_name, tool_input);
        ctx.mode = mode.map(|m| m.to_string());
        ctx.agent_name = agent_name.map(|a| a.to_string());
        self.evaluate_ctx(&ctx)
    }

    /// Find the index path through the tree to the first matching decision.
    ///
    /// Returns `Some(vec![root_idx, child_idx, ...])` if a rule matched,
    /// or `None` if no rule matched (default effect applies).
    pub fn find_match_path(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
    ) -> Option<Vec<usize>> {
        let ctx = QueryContext::from_tool(tool_name, tool_input);
        find_match_path_dfs(&self.tree, &ctx)
    }

    /// Evaluate this policy against a prepared query context.
    pub fn evaluate_ctx(&self, ctx: &QueryContext) -> PolicyDecision {
        let mut trace = EvalTrace::default();
        let mut path = Vec::new();

        let decision = eval_traced(&self.tree, ctx, &mut trace, &mut path);

        match decision {
            Some(d) => {
                let mut effect = d.effect();
                let cwd_path = std::env::current_dir().unwrap_or_default();
                let sandbox = d
                    .sandbox_ref()
                    .and_then(|sr| self.sandboxes.get(&sr.0))
                    .cloned()
                    .map(|sbx| sbx.expand_worktree_rules(&cwd_path));

                // For non-Bash tools with file operations, enforce sandbox fs
                // rules at policy level (there's no OS sandbox wrapper for these).
                let mut sandbox_denial: Option<String> = None;
                if effect == Effect::Allow
                    && ctx.tool_name != "Bash"
                    && let Some(ref sbx) = sandbox
                    && let Some(ref fs_op) = ctx.fs_op
                    && let Some(ref fs_path) = ctx.fs_path
                    && fs_path.starts_with('/')
                {
                    use crate::policy::sandbox_types::Cap;
                    let required = match fs_op.as_str() {
                        "read" => Cap::READ,
                        "write" => Cap::WRITE | Cap::CREATE,
                        _ => Cap::empty(),
                    };
                    let cwd = cwd_path.to_string_lossy().to_string();
                    if let Some(explanation) = sbx.explain_denial(fs_path, &cwd, required) {
                        effect = Effect::Deny;
                        let sandbox_name =
                            d.sandbox_ref().map(|sr| sr.0.as_str()).unwrap_or("unnamed");
                        sandbox_denial = Some(format!("sandbox '{sandbox_name}': {explanation}"));
                    }
                }

                let resolution = match sandbox_denial {
                    Some(ref detail) => format!("result: {effect} ({detail})"),
                    None => format!("result: {effect}"),
                };

                PolicyDecision {
                    effect,
                    reason: Some(resolution.clone()),
                    trace: self.build_decision_trace(&trace, &resolution),
                    sandbox,
                    sandbox_name: d.sandbox_ref().cloned(),
                }
            }
            None => {
                let resolution = format!("no rules matched, default: {}", self.default_effect);

                PolicyDecision {
                    effect: self.default_effect,
                    reason: Some(resolution.clone()),
                    trace: self.build_decision_trace(&trace, &resolution),
                    sandbox: None,
                    sandbox_name: None,
                }
            }
        }
    }

    fn build_decision_trace(&self, trace: &EvalTrace, resolution: &str) -> DecisionTrace {
        let mut matched_rules = Vec::new();
        let mut skipped_rules = Vec::new();

        for (i, entry) in trace.matched.iter().enumerate() {
            matched_rules.push(RuleMatch {
                rule_index: i,
                description: format!(
                    "{}={}",
                    entry.observable,
                    entry.tested_value.as_deref().unwrap_or("?")
                ),
                effect: Effect::Allow, // filled by caller context
                has_active_constraints: true,
                node_id: None,
            });
        }

        for (i, entry) in trace.skipped.iter().enumerate() {
            skipped_rules.push(RuleSkip {
                rule_index: i,
                description: format!("{}: {}", entry.observable, entry.pattern_desc),
                reason: format!(
                    "pattern mismatch (value: {})",
                    entry.tested_value.as_deref().unwrap_or("absent")
                ),
            });
        }

        DecisionTrace {
            matched_rules,
            skipped_rules,
            final_resolution: resolution.to_string(),
        }
    }

    /// Validate that all sandbox references resolve.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        self.validate_nodes(&self.tree, &mut errors);
        errors
    }

    fn validate_nodes(&self, nodes: &[Node], errors: &mut Vec<String>) {
        for node in nodes {
            match node {
                Node::Decision(d) => {
                    if let Some(sr) = d.sandbox_ref()
                        && !self.sandboxes.contains_key(&sr.0)
                    {
                        errors.push(format!(
                            "sandbox reference '{}' not found in sandboxes map",
                            sr.0
                        ));
                    }
                }
                Node::Condition { children, .. } => {
                    self.validate_nodes(children, errors);
                }
            }
        }
    }

    /// Return platform-specific warnings for sandbox policies.
    ///
    /// These are non-fatal: the policy is valid but some rules behave
    /// differently on certain platforms.
    pub fn platform_warnings(&self) -> Vec<String> {
        use crate::policy::sandbox_types::{NetworkPolicy, PathMatch};

        let mut warnings = Vec::new();
        for (name, sandbox) in &self.sandboxes {
            for rule in &sandbox.rules {
                if rule.path_match == PathMatch::Regex {
                    warnings.push(format!(
                        "sandbox '{}': regex path rule '{}' is not enforced on Linux \
                         (Landlock cannot match regex paths)",
                        name, rule.path,
                    ));
                }
            }
            if let NetworkPolicy::AllowDomains(domains) = &sandbox.network {
                warnings.push(format!(
                    "sandbox '{}': domain filtering ({}) is advisory on Linux \
                     (relies on HTTP_PROXY which programs can bypass)",
                    name,
                    domains.join(", "),
                ));
            }
        }
        warnings
    }
}

// ---------------------------------------------------------------------------
// Compact: merge duplicate siblings + sort by specificity
// ---------------------------------------------------------------------------

impl Node {
    /// Merge sibling `Condition` nodes that share the same `(observe, pattern)`,
    /// combining their children, then sort by specificity. Recurses into children.
    pub fn compact(nodes: Vec<Node>) -> Vec<Node> {
        let mut out: Vec<Node> = Vec::new();

        // Merge duplicates via linear scan (no Hash needed, trees are small).
        for node in nodes {
            match node {
                Node::Condition {
                    observe,
                    pattern,
                    children,
                    doc,
                    source,
                    terminal,
                } => {
                    if let Some(existing) = out.iter_mut().find_map(|n| match n {
                        Node::Condition {
                            observe: o,
                            pattern: p,
                            children: c,
                            doc: d,
                            ..
                        } if *o == observe && *p == pattern => Some((c, d)),
                        _ => None,
                    }) {
                        existing.0.extend(children);
                        if existing.1.is_none() {
                            *existing.1 = doc;
                        }
                    } else {
                        out.push(Node::Condition {
                            observe,
                            pattern,
                            children,
                            doc,
                            source,
                            terminal,
                        });
                    }
                }
                decision => out.push(decision),
            }
        }

        // Recurse into children.
        for node in &mut out {
            if let Node::Condition { children, .. } = node {
                *children = Self::compact(std::mem::take(children));
            }
        }

        // Sort: Conditions before Decisions, then by specificity (most specific first).
        // TODO: unpack the nodes and do a direct comparison instead of a silly mapping to 8bit numbers
        out.sort_by(|a, b| Self::sort_key(b).cmp(&Self::sort_key(a)));

        out
    }

    /// Sort key: `(is_condition, pattern_specificity, observable_specificity)`.
    /// Higher values sort first (via reverse comparison in `compact`).
    fn sort_key(node: &Node) -> (u8, u8, u8) {
        match node {
            Node::Condition {
                observe, pattern, ..
            } => (1, pattern.specificity(), observe.specificity()),
            Node::Decision(_) => (0, 0, 0),
        }
    }
}

/// Detect unreachable branches: warn if a Wildcard precedes more specific siblings.
pub fn detect_unreachable(nodes: &[Node]) -> Vec<String> {
    let mut warnings = Vec::new();
    detect_unreachable_inner(nodes, &mut warnings, &[]);
    warnings
}

fn detect_unreachable_inner(nodes: &[Node], warnings: &mut Vec<String>, path: &[String]) {
    let mut seen_wildcard = false;
    for node in nodes {
        match node {
            Node::Condition {
                observe,
                pattern,
                children,
                ..
            } => {
                if seen_wildcard {
                    warnings.push(format!(
                        "unreachable branch at {:?}: {:?} after wildcard",
                        path, observe
                    ));
                }
                if matches!(pattern, Pattern::Wildcard) {
                    seen_wildcard = true;
                }
                let mut child_path = path.to_vec();
                child_path.push(format!("{observe:?}"));
                detect_unreachable_inner(children, warnings, &child_path);
            }
            Node::Decision(_) => {
                if seen_wildcard {
                    warnings.push(format!(
                        "unreachable decision at {:?}: decision after wildcard",
                        path
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx(tool: &str, command: &str) -> QueryContext {
        let input = if tool == "Bash" {
            serde_json::json!({"command": command})
        } else {
            serde_json::json!({})
        };
        QueryContext::from_tool(tool, &input)
    }

    #[test]
    fn simple_decision() {
        let nodes = vec![Node::Decision(Decision::Allow(None))];
        let ctx = make_ctx("Bash", "echo hello");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn tool_name_match() {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];
        let ctx = make_ctx("Bash", "echo hello");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn tool_name_mismatch() {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Read".into())),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];
        let ctx = make_ctx("Bash", "echo hello");
        assert_eq!(eval(&nodes, &ctx), None);
    }

    #[test]
    fn terminal_exact_match() {
        // terminal: true on arg[1] means "git commit" matches but "git commit --amend" does not
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::PositionalArg(0),
                pattern: Pattern::Literal(Value::Literal("git".into())),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(1),
                    pattern: Pattern::Literal(Value::Literal("commit".into())),
                    children: vec![Node::Decision(Decision::Deny)],
                    doc: None,
                    source: None,
                    terminal: true,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }];

        // Exact match: "git commit" → deny
        let ctx = make_ctx("Bash", "git commit");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Deny));

        // Extra args: "git commit --amend" → no match (terminal blocks it)
        let ctx = make_ctx("Bash", "git commit --amend");
        assert_eq!(eval(&nodes, &ctx), None);

        // Different subcommand: "git push" → no match
        let ctx = make_ctx("Bash", "git push");
        assert_eq!(eval(&nodes, &ctx), None);
    }

    #[test]
    fn terminal_single_binary() {
        // terminal: true on arg[0] means "ls" matches but "ls -la" does not
        let nodes = vec![Node::Condition {
            observe: Observable::PositionalArg(0),
            pattern: Pattern::Literal(Value::Literal("ls".into())),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: true,
        }];

        let ctx = make_ctx("Bash", "ls");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));

        let ctx = make_ctx("Bash", "ls -la");
        assert_eq!(eval(&nodes, &ctx), None);
    }

    #[test]
    fn non_terminal_allows_extra_args() {
        // terminal: false (default) means "git commit --amend" still matches "git commit"
        let nodes = vec![Node::Condition {
            observe: Observable::PositionalArg(0),
            pattern: Pattern::Literal(Value::Literal("git".into())),
            children: vec![Node::Condition {
                observe: Observable::PositionalArg(1),
                pattern: Pattern::Literal(Value::Literal("commit".into())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }];

        let ctx = make_ctx("Bash", "git commit --amend");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn positional_arg_match() {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::PositionalArg(0),
                pattern: Pattern::Literal(Value::Literal("git".into())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }];
        let ctx = make_ctx("Bash", "git push");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn has_arg_match() {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::HasArg,
                pattern: Pattern::Literal(Value::Literal("--force".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }];
        let ctx = make_ctx("Bash", "git push --force origin main");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Deny));
    }

    #[test]
    fn has_arg_no_match() {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Literal(Value::Literal("Bash".into())),
            children: vec![Node::Condition {
                observe: Observable::HasArg,
                pattern: Pattern::Literal(Value::Literal("--force".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            }],
            doc: None,
            source: None,
            terminal: false,
        }];
        let ctx = make_ctx("Bash", "git push origin main");
        assert_eq!(eval(&nodes, &ctx), None);
    }

    #[test]
    fn specificity_ordering() {
        // More specific (Literal) should come before less specific (Wildcard)
        let nodes = vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Wildcard,
                children: vec![Node::Decision(Decision::Ask(None))],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            },
        ];
        let nodes = Node::compact(nodes);
        // Literal should be first after sorting
        let ctx = make_ctx("Bash", "echo hello");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn backtracking() {
        // First branch matches ToolName but has no matching child,
        // should backtrack and try the second branch.
        let nodes = vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(0),
                    pattern: Pattern::Literal(Value::Literal("cargo".into())),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Wildcard,
                children: vec![Node::Decision(Decision::Ask(None))],
                doc: None,
                source: None,
                terminal: false,
            },
        ];
        // "git push" matches Bash but not cargo, so should backtrack to wildcard
        let ctx = make_ctx("Bash", "git push");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Ask(None)));
    }

    #[test]
    fn nested_field_match() {
        let nodes = vec![Node::Condition {
            observe: Observable::NestedField(vec!["file_path".into()]),
            pattern: Pattern::Regex(Arc::new(Regex::new(r".*\.rs$").unwrap())),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];
        let input = serde_json::json!({"file_path": "/src/main.rs"});
        let ctx = QueryContext::from_tool("Edit", &input);
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn regex_pattern() {
        let nodes = vec![Node::Condition {
            observe: Observable::PositionalArg(0),
            pattern: Pattern::Regex(Arc::new(Regex::new(r"^cargo").unwrap())),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];
        let ctx = make_ctx("Bash", "cargo-clippy check");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));
    }

    #[test]
    fn any_of_pattern() {
        let nodes = vec![Node::Condition {
            observe: Observable::PositionalArg(0),
            pattern: Pattern::AnyOf(vec![
                Pattern::Literal(Value::Literal("cargo".into())),
                Pattern::Literal(Value::Literal("rustc".into())),
            ]),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];

        let ctx = make_ctx("Bash", "rustc main.rs");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));

        let ctx = make_ctx("Bash", "gcc main.c");
        assert_eq!(eval(&nodes, &ctx), None);
    }

    #[test]
    fn not_pattern() {
        let nodes = vec![Node::Condition {
            observe: Observable::PositionalArg(0),
            pattern: Pattern::Not(Box::new(Pattern::Literal(Value::Literal("rm".into())))),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];

        let ctx = make_ctx("Bash", "ls -la");
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Allow(None)));

        let ctx = make_ctx("Bash", "rm -rf /");
        assert_eq!(eval(&nodes, &ctx), None);
    }

    #[test]
    fn sandbox_ref_validation() {
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![Node::Decision(Decision::Allow(Some(SandboxRef(
                "missing".into(),
            ))))],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };
        let errors = policy.validate();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("missing"));
    }

    #[test]
    fn sandbox_ref_valid() {
        let mut sandboxes = HashMap::new();
        sandboxes.insert(
            "cwd_access".to_string(),
            SandboxPolicy {
                default: crate::policy::sandbox_types::Cap::READ,
                rules: vec![],
                network: crate::policy::sandbox_types::NetworkPolicy::Deny,
                doc: None,
            },
        );
        let policy = CompiledPolicy {
            sandboxes,
            tree: vec![Node::Decision(Decision::Allow(Some(SandboxRef(
                "cwd_access".into(),
            ))))],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };
        assert!(policy.validate().is_empty());
    }

    #[test]
    fn compiled_policy_evaluate() {
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![
                Node::Condition {
                    observe: Observable::ToolName,
                    pattern: Pattern::Literal(Value::Literal("Bash".into())),
                    children: vec![Node::Condition {
                        observe: Observable::PositionalArg(0),
                        pattern: Pattern::Literal(Value::Literal("git".into())),
                        children: vec![
                            Node::Condition {
                                observe: Observable::HasArg,
                                pattern: Pattern::Literal(Value::Literal("--force".into())),
                                children: vec![Node::Decision(Decision::Deny)],
                                doc: None,
                                source: None,
                                terminal: false,
                            },
                            Node::Decision(Decision::Allow(None)),
                        ],
                        doc: None,
                        source: None,
                        terminal: false,
                    }],
                    doc: None,
                    source: None,
                    terminal: false,
                },
                Node::Condition {
                    observe: Observable::ToolName,
                    pattern: Pattern::Wildcard,
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                },
            ],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };

        // git push → allow
        let d = policy.evaluate("Bash", &serde_json::json!({"command": "git push"}));
        assert_eq!(d.effect, Effect::Allow);

        // git push --force → deny
        let d = policy.evaluate("Bash", &serde_json::json!({"command": "git push --force"}));
        assert_eq!(d.effect, Effect::Deny);

        // Read tool → allow (wildcard match)
        let d = policy.evaluate("Read", &serde_json::json!({}));
        assert_eq!(d.effect, Effect::Allow);
    }

    #[test]
    fn unreachable_branch_detection() {
        let nodes = vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Wildcard,
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            },
        ];
        let warnings = detect_unreachable(&nodes);
        assert!(!warnings.is_empty());
    }

    #[test]
    fn value_env_resolve() {
        // SAFETY: test-only, single-threaded access
        unsafe { std::env::set_var("MATCH_TREE_TEST_VAR", "test_value") };
        let v = Value::Env("MATCH_TREE_TEST_VAR".into());
        assert_eq!(v.resolve(), "test_value");
        unsafe { std::env::remove_var("MATCH_TREE_TEST_VAR") };
    }

    #[test]
    fn value_path_resolve() {
        let v = Value::Path(vec![
            Value::Literal("/home".into()),
            Value::Literal("user".into()),
            Value::Literal(".ssh".into()),
        ]);
        assert_eq!(v.resolve(), "/home/user/.ssh");
    }

    #[test]
    fn eval_trace_collection() {
        let nodes = vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Read".into())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            },
        ];

        let ctx = make_ctx("Bash", "echo hello");
        let mut trace = EvalTrace::default();
        let mut path = Vec::new();
        let result = eval_traced(&nodes, &ctx, &mut trace, &mut path);

        assert_eq!(result, Some(Decision::Deny));
        assert_eq!(trace.skipped.len(), 1); // Read was skipped
        assert_eq!(trace.matched.len(), 1); // Bash matched
    }

    #[test]
    fn pattern_specificity_order() {
        assert!(
            Pattern::Literal(Value::Literal("x".into())).specificity()
                > Pattern::Regex(Arc::new(Regex::new("x").unwrap())).specificity()
        );
        assert!(
            Pattern::Regex(Arc::new(Regex::new("x").unwrap())).specificity()
                > Pattern::Wildcard.specificity()
        );
        assert!(Pattern::AnyOf(vec![]).specificity() > Pattern::Wildcard.specificity());
    }

    #[test]
    fn named_arg_match() {
        let nodes = vec![Node::Condition {
            observe: Observable::NamedArg("file_path".into()),
            pattern: Pattern::Regex(Arc::new(Regex::new(r"\.env").unwrap())),
            children: vec![Node::Decision(Decision::Deny)],
            doc: None,
            source: None,
            terminal: false,
        }];
        let input = serde_json::json!({"file_path": "/project/.env"});
        let ctx = QueryContext::from_tool("Write", &input);
        assert_eq!(eval(&nodes, &ctx), Some(Decision::Deny));
    }

    #[test]
    fn env_var_prefix_stripped_in_bash() {
        // Simulates: exe("cargo").allow() with command "SOME_ENV=foo cargo check"
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(0),
                    pattern: Pattern::Literal(Value::Literal("cargo".into())),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };

        // Plain command should match
        let input = serde_json::json!({"command": "cargo check"});
        let ctx = QueryContext::from_tool("Bash", &input);
        assert_eq!(ctx.args[0], "cargo");
        let result = policy.evaluate_ctx(&ctx);
        assert_eq!(result.effect, Effect::Allow);

        // Env-prefixed command should also match
        let input2 = serde_json::json!({"command": "SOME_ENV=foo cargo check"});
        let ctx2 = QueryContext::from_tool("Bash", &input2);
        assert_eq!(ctx2.args[0], "cargo", "env var prefix should be stripped");
        let result2 = policy.evaluate_ctx(&ctx2);
        assert_eq!(result2.effect, Effect::Allow);

        // Multiple env vars
        let input3 = serde_json::json!({"command": "A=1 B=2 cargo build"});
        let ctx3 = QueryContext::from_tool("Bash", &input3);
        assert_eq!(ctx3.args[0], "cargo");

        // env utility
        let input4 = serde_json::json!({"command": "env RUST_BACKTRACE=1 cargo test"});
        let ctx4 = QueryContext::from_tool("Bash", &input4);
        assert_eq!(ctx4.args[0], "cargo");
    }

    #[test]
    fn serde_roundtrip() {
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("Bash".into())),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            }],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let deserialized: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.tree.len(), 1);
        assert_eq!(deserialized.default_effect, Effect::Deny);
    }

    // -----------------------------------------------------------------------
    // resolve_relative_path tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_relative_path_absolute_unchanged() {
        let result = resolve_relative_path("/usr/bin/ls");
        assert_eq!(result, "/usr/bin/ls");
    }

    #[test]
    fn resolve_relative_path_prepends_pwd() {
        // SAFETY: test-only, single-threaded access
        unsafe { std::env::set_var("PWD", "/home/user/project") };
        let result = resolve_relative_path("src/main.rs");
        assert_eq!(result, "/home/user/project/src/main.rs");
        unsafe { std::env::remove_var("PWD") };
    }

    #[test]
    fn resolve_relative_path_empty() {
        unsafe { std::env::set_var("PWD", "/home/user") };
        let result = resolve_relative_path("");
        // Empty path has no leading slash, so gets PWD prepended
        assert_eq!(result, "/home/user/");
        unsafe { std::env::remove_var("PWD") };
    }

    #[test]
    fn resolve_relative_path_no_leading_slash() {
        unsafe { std::env::set_var("PWD", "/workspace") };
        let result = resolve_relative_path("foo/bar.txt");
        assert_eq!(result, "/workspace/foo/bar.txt");
        unsafe { std::env::remove_var("PWD") };
    }

    // -----------------------------------------------------------------------
    // extract_domain tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_domain_https_url() {
        assert_eq!(
            extract_domain("https://example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_domain_with_port() {
        assert_eq!(
            extract_domain("https://example.com:8080/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_domain_with_path() {
        assert_eq!(
            extract_domain("https://api.github.com/repos/owner/repo"),
            Some("api.github.com".into())
        );
    }

    #[test]
    fn extract_domain_http_url() {
        assert_eq!(
            extract_domain("http://example.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_domain_without_scheme() {
        assert_eq!(
            extract_domain("example.com/path"),
            Some("example.com".into())
        );
    }

    #[test]
    fn extract_domain_empty_input() {
        assert_eq!(extract_domain(""), None);
    }

    #[test]
    fn extract_domain_scheme_only() {
        assert_eq!(extract_domain("https://"), None);
    }

    // -----------------------------------------------------------------------
    // Value::resolve tests
    // -----------------------------------------------------------------------

    #[test]
    fn value_literal_resolve() {
        let v = Value::Literal("hello".into());
        assert_eq!(v.resolve(), "hello");
    }

    #[test]
    fn value_env_resolve_missing() {
        let v = Value::Env("NONEXISTENT_CLASH_TEST_VAR_XYZ".into());
        assert_eq!(v.resolve(), "");
    }

    #[test]
    fn value_path_resolve_with_env() {
        unsafe { std::env::set_var("CLASH_TEST_HOME", "/home/testuser") };
        let v = Value::Path(vec![
            Value::Env("CLASH_TEST_HOME".into()),
            Value::Literal("projects".into()),
        ]);
        assert_eq!(v.resolve(), "/home/testuser/projects");
        unsafe { std::env::remove_var("CLASH_TEST_HOME") };
    }

    // -----------------------------------------------------------------------
    // Pattern::matches tests
    // -----------------------------------------------------------------------

    #[test]
    fn pattern_prefix_exact_match() {
        let pat = Pattern::Prefix(Value::Literal("/home/user".into()));
        assert!(pat.matches("/home/user"));
    }

    #[test]
    fn pattern_prefix_child_path() {
        let pat = Pattern::Prefix(Value::Literal("/home/user".into()));
        assert!(pat.matches("/home/user/documents/file.txt"));
    }

    #[test]
    fn pattern_prefix_non_child_similar() {
        // "/home/username" should NOT match prefix "/home/user"
        let pat = Pattern::Prefix(Value::Literal("/home/user".into()));
        assert!(!pat.matches("/home/username"));
    }

    #[test]
    fn pattern_literal_with_env() {
        unsafe { std::env::set_var("CLASH_TEST_TOOL", "Bash") };
        let pat = Pattern::Literal(Value::Env("CLASH_TEST_TOOL".into()));
        assert!(pat.matches("Bash"));
        assert!(!pat.matches("Read"));
        unsafe { std::env::remove_var("CLASH_TEST_TOOL") };
    }

    #[test]
    fn pattern_wildcard_matches_anything() {
        assert!(Pattern::Wildcard.matches(""));
        assert!(Pattern::Wildcard.matches("anything"));
        assert!(Pattern::Wildcard.matches("/some/path"));
    }

    #[test]
    fn pattern_any_of_matches_any() {
        let pat = Pattern::AnyOf(vec![
            Pattern::Literal(Value::Literal("cat".into())),
            Pattern::Literal(Value::Literal("dog".into())),
        ]);
        assert!(pat.matches("cat"));
        assert!(pat.matches("dog"));
        assert!(!pat.matches("fish"));
    }

    #[test]
    fn pattern_not_inverts() {
        let pat = Pattern::Not(Box::new(Pattern::Literal(Value::Literal("rm".into()))));
        assert!(pat.matches("ls"));
        assert!(!pat.matches("rm"));
    }

    // -----------------------------------------------------------------------
    // QueryContext::from_tool tests
    // -----------------------------------------------------------------------

    #[test]
    fn from_tool_bash_parses_args() {
        let input = serde_json::json!({"command": "git push origin main"});
        let ctx = QueryContext::from_tool("Bash", &input);
        assert_eq!(ctx.tool_name, "Bash");
        assert_eq!(ctx.args[0], "git");
        assert!(ctx.args.contains(&"push".to_string()));
        assert!(ctx.fs_op.is_none());
        assert!(ctx.net_domain.is_none());
    }

    #[test]
    fn from_tool_read_extracts_path() {
        let input = serde_json::json!({"file_path": "/src/main.rs"});
        let ctx = QueryContext::from_tool("Read", &input);
        assert_eq!(ctx.tool_name, "Read");
        assert_eq!(ctx.fs_op.as_deref(), Some("read"));
        assert_eq!(ctx.fs_path.as_deref(), Some("/src/main.rs"));
        assert!(ctx.args.is_empty());
    }

    #[test]
    fn from_tool_write_extracts_path() {
        let input = serde_json::json!({"file_path": "/tmp/output.txt"});
        let ctx = QueryContext::from_tool("Write", &input);
        assert_eq!(ctx.fs_op.as_deref(), Some("write"));
        assert_eq!(ctx.fs_path.as_deref(), Some("/tmp/output.txt"));
    }

    #[test]
    fn from_tool_edit_extracts_path() {
        let input = serde_json::json!({"file_path": "/project/lib.rs"});
        let ctx = QueryContext::from_tool("Edit", &input);
        assert_eq!(ctx.fs_op.as_deref(), Some("write"));
        assert_eq!(ctx.fs_path.as_deref(), Some("/project/lib.rs"));
    }

    #[test]
    fn from_tool_glob_extracts_path() {
        let input = serde_json::json!({"path": "/src", "pattern": "*.rs"});
        let ctx = QueryContext::from_tool("Glob", &input);
        assert_eq!(ctx.fs_op.as_deref(), Some("read"));
        assert_eq!(ctx.fs_path.as_deref(), Some("/src"));
    }

    #[test]
    fn from_tool_grep_falls_back_to_pattern() {
        let input = serde_json::json!({"pattern": "/some/path"});
        let ctx = QueryContext::from_tool("Grep", &input);
        assert_eq!(ctx.fs_op.as_deref(), Some("read"));
        assert_eq!(ctx.fs_path.as_deref(), Some("/some/path"));
    }

    #[test]
    fn from_tool_webfetch_extracts_domain() {
        let input = serde_json::json!({"url": "https://api.github.com/repos"});
        let ctx = QueryContext::from_tool("WebFetch", &input);
        assert_eq!(ctx.net_domain.as_deref(), Some("api.github.com"));
        assert!(ctx.fs_op.is_none());
    }

    #[test]
    fn from_tool_websearch_wildcard_domain() {
        let input = serde_json::json!({"query": "rust async"});
        let ctx = QueryContext::from_tool("WebSearch", &input);
        assert_eq!(ctx.net_domain.as_deref(), Some("*"));
    }

    #[test]
    fn from_tool_unknown_empty() {
        let input = serde_json::json!({"some": "data"});
        let ctx = QueryContext::from_tool("UnknownTool", &input);
        assert_eq!(ctx.tool_name, "UnknownTool");
        assert!(ctx.args.is_empty());
        assert!(ctx.fs_op.is_none());
        assert!(ctx.fs_path.is_none());
        assert!(ctx.net_domain.is_none());
    }

    // -----------------------------------------------------------------------
    // platform_warnings tests
    // -----------------------------------------------------------------------

    #[test]
    fn platform_warnings_regex_path() {
        use crate::policy::sandbox_types::*;

        let policy = CompiledPolicy {
            sandboxes: HashMap::from([(
                "dev".to_string(),
                SandboxPolicy {
                    default: Cap::READ | Cap::EXECUTE,
                    rules: vec![SandboxRule {
                        effect: RuleEffect::Allow,
                        caps: Cap::WRITE,
                        path: r"/tmp/build-\d+".to_string(),
                        path_match: PathMatch::Regex,
                        follow_worktrees: false,
                        doc: None,
                    }],
                    network: NetworkPolicy::Deny,
                    doc: None,
                },
            )]),
            tree: vec![],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };
        let warnings = policy.platform_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("regex"));
        assert!(warnings[0].contains("Linux"));
    }

    #[test]
    fn platform_warnings_allow_domains() {
        use crate::policy::sandbox_types::*;

        let policy = CompiledPolicy {
            sandboxes: HashMap::from([(
                "net".to_string(),
                SandboxPolicy {
                    default: Cap::READ | Cap::EXECUTE,
                    rules: vec![],
                    network: NetworkPolicy::AllowDomains(vec!["github.com".to_string()]),
                    doc: None,
                },
            )]),
            tree: vec![],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };
        let warnings = policy.platform_warnings();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("advisory"));
        assert!(warnings[0].contains("Linux"));
    }

    #[test]
    fn platform_warnings_none_for_clean_policy() {
        use crate::policy::sandbox_types::*;

        let policy = CompiledPolicy {
            sandboxes: HashMap::from([(
                "dev".to_string(),
                SandboxPolicy {
                    default: Cap::READ | Cap::EXECUTE,
                    rules: vec![SandboxRule {
                        effect: RuleEffect::Allow,
                        caps: Cap::WRITE,
                        path: "/tmp".to_string(),
                        path_match: PathMatch::Subpath,
                        follow_worktrees: false,
                        doc: None,
                    }],
                    network: NetworkPolicy::Deny,
                    doc: None,
                },
            )]),
            tree: vec![],
            default_effect: Effect::Deny,
            default_sandbox: None,
        };
        assert!(policy.platform_warnings().is_empty());
    }

    // -----------------------------------------------------------------------
    // Canonical tool name matching tests
    // -----------------------------------------------------------------------

    /// Helper: test if a ToolName pattern matches a given tool name in context.
    fn tool_name_matches(pattern_str: &str, context_tool: &str) -> bool {
        let pattern = Pattern::Literal(Value::Literal(pattern_str.to_string()));
        let ctx = QueryContext::from_tool(context_tool, &serde_json::json!({}));
        matches_observable(&Observable::ToolName, &pattern, false, &ctx)
    }

    #[test]
    fn canonical_shell_matches_bash() {
        assert!(tool_name_matches("shell", "Bash"));
    }

    #[test]
    fn canonical_read_matches_read() {
        assert!(tool_name_matches("read", "Read"));
    }

    #[test]
    fn canonical_write_matches_write() {
        assert!(tool_name_matches("write", "Write"));
    }

    #[test]
    fn canonical_edit_matches_edit() {
        assert!(tool_name_matches("edit", "Edit"));
    }

    #[test]
    fn canonical_web_fetch_matches_webfetch() {
        assert!(tool_name_matches("web_fetch", "WebFetch"));
    }

    #[test]
    fn canonical_web_search_matches_websearch() {
        assert!(tool_name_matches("web_search", "WebSearch"));
    }

    #[test]
    fn case_insensitive_bash_matches() {
        assert!(tool_name_matches("bash", "Bash"));
        assert!(tool_name_matches("BASH", "Bash"));
        assert!(tool_name_matches("Bash", "Bash"));
    }

    #[test]
    fn case_insensitive_shell_matches() {
        assert!(tool_name_matches("Shell", "Bash"));
        assert!(tool_name_matches("SHELL", "Bash"));
    }

    #[test]
    fn internal_name_still_matches() {
        // Writing the internal name directly should still work
        assert!(tool_name_matches("Bash", "Bash"));
        assert!(tool_name_matches("Read", "Read"));
        assert!(tool_name_matches("WebFetch", "WebFetch"));
    }

    #[test]
    fn unknown_tool_does_not_match() {
        assert!(!tool_name_matches("shell", "Read"));
        assert!(!tool_name_matches("run_shell_command", "Bash"));
    }

    #[test]
    fn wildcard_matches_any_tool() {
        let pattern = Pattern::Wildcard;
        let ctx = QueryContext::from_tool("Bash", &serde_json::json!({}));
        assert!(matches_observable(&Observable::ToolName, &pattern, false, &ctx));
    }
}
