//! Policy evaluation engine for WASM.
//!
//! Adapted from `clash/src/policy/match_tree.rs` with environment variable
//! resolution replaced by a thread-local map suitable for browser contexts.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};

// ── Thread-local environment (replaces std::env for WASM) ───────

thread_local! {
    static ENV: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
}

pub fn set_env(env: HashMap<String, String>) {
    ENV.with(|e| *e.borrow_mut() = env);
}

fn get_env(name: &str) -> String {
    ENV.with(|e| e.borrow().get(name).cloned().unwrap_or_default())
}

// ── Effect ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
    Ask,
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::Allow => write!(f, "allow"),
            Effect::Deny => write!(f, "deny"),
            Effect::Ask => write!(f, "ask"),
        }
    }
}

// ── Value ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    Env(String),
    Literal(String),
    Path(Vec<Value>),
}

impl Value {
    pub fn resolve(&self) -> String {
        match self {
            Value::Env(var) => get_env(var),
            Value::Literal(s) => s.clone(),
            Value::Path(parts) => parts
                .iter()
                .map(|p| p.resolve())
                .collect::<Vec<_>>()
                .join("/"),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Env(env) => write!(f, "${env}"),
            Value::Literal(lit) => write!(f, "{lit}"),
            Value::Path(parts) => {
                let strs: Vec<String> = parts.iter().map(|v| format!("{v}")).collect();
                write!(f, "{}", strs.join("/"))
            }
        }
    }
}

// ── Pattern ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    Wildcard,
    Literal(Value),
    Regex(
        #[serde(serialize_with = "ser_regex", deserialize_with = "de_regex")]
        Arc<Regex>,
    ),
    AnyOf(Vec<Pattern>),
    Not(Box<Pattern>),
    Prefix(Value),
}

fn ser_regex<S: serde::Serializer>(re: &Arc<Regex>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(re.as_str())
}

fn de_regex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Arc<Regex>, D::Error> {
    let s = String::deserialize(d)?;
    Regex::new(&s)
        .map(Arc::new)
        .map_err(serde::de::Error::custom)
}

impl Pattern {
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

// ── Observable ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observable {
    ToolName,
    HookType,
    AgentName,
    PositionalArg(i32),
    HasArg,
    NamedArg(String),
    NestedField(Vec<String>),
    FsOp,
    FsPath,
    NetDomain,
}

// ── SandboxRef + Decision ───────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRef(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow(Option<SandboxRef>),
    Deny,
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

// ── Sandbox types (data only, no enforcement) ───────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    #[serde(default)]
    pub default: serde_json::Value,
    #[serde(default)]
    pub rules: Vec<SandboxRule>,
    #[serde(default)]
    pub network: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRule {
    #[serde(default)]
    pub effect: String,
    #[serde(default)]
    pub caps: serde_json::Value,
    #[serde(default)]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_match: Option<String>,
    #[serde(default)]
    pub follow_worktrees: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
}

// ── Node ────────────────────────────────────────────────────────

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Node {
    Condition {
        observe: Observable,
        pattern: Pattern,
        children: Vec<Node>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        doc: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        terminal: bool,
    },
    Decision(Decision),
}

impl Node {
    pub fn compact(nodes: Vec<Node>) -> Vec<Node> {
        let mut out: Vec<Node> = Vec::new();
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
        for node in &mut out {
            if let Node::Condition { children, .. } = node {
                *children = Self::compact(std::mem::take(children));
            }
        }
        out
    }
}

// ── CompiledPolicy ──────────────────────────────────────────────

fn default_effect() -> Effect {
    Effect::Ask
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub sandboxes: HashMap<String, SandboxPolicy>,
    pub tree: Vec<Node>,
    #[serde(default = "default_effect")]
    pub default_effect: Effect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_sandbox: Option<String>,
}

// ── PolicyDecision + trace ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub effect: Effect,
    pub reason: Option<String>,
    pub trace: DecisionTrace,
    pub sandbox: Option<SandboxPolicy>,
    pub sandbox_name: Option<SandboxRef>,
}

#[derive(Debug, Clone)]
pub struct DecisionTrace {
    pub matched_rules: Vec<RuleMatch>,
    pub skipped_rules: Vec<RuleSkip>,
    pub final_resolution: String,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub description: String,
    pub effect: Effect,
}

#[derive(Debug, Clone)]
pub struct RuleSkip {
    pub description: String,
    pub reason: String,
}

impl DecisionTrace {
    pub fn render_human(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for skip in &self.skipped_rules {
            lines.push(format!(
                "Rule '{}' was skipped: {}",
                skip.description,
                if skip.reason.contains("pattern mismatch") {
                    "pattern does not match this request"
                } else {
                    &skip.reason
                }
            ));
        }
        for m in &self.matched_rules {
            lines.push(format!(
                "Rule '{}' matched — action {}",
                m.description,
                match m.effect {
                    Effect::Allow => "allowed",
                    Effect::Deny => "denied",
                    Effect::Ask => "requires approval",
                }
            ));
        }
        let resolution = &self.final_resolution;
        if let Some(effect) = resolution.strip_prefix("result: ") {
            lines.push(format!("Final decision: {effect}"));
        } else if resolution.starts_with("no rules matched") {
            let default = resolution.rsplit("default: ").next().unwrap_or("ask");
            lines.push(format!("No rules matched. Defaulting to {default}."));
        } else {
            lines.push(resolution.to_string());
        }
        lines
    }
}

// ── QueryContext ─────────────────────────────────────────────────

#[derive(Debug)]
pub struct QueryContext {
    pub tool_name: String,
    pub args: Vec<String>,
    pub tool_input: serde_json::Value,
    pub hook_type: Option<String>,
    pub agent_name: Option<String>,
    pub fs_op: Option<String>,
    pub fs_path: Option<String>,
    pub net_domain: Option<String>,
}

impl QueryContext {
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

        let (fs_op, fs_path) = match tool_name {
            "Read" => (
                Some("read".into()),
                tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .map(resolve_path),
            ),
            "Glob" | "Grep" => (
                Some("read".into()),
                tool_input
                    .get("path")
                    .or_else(|| tool_input.get("pattern"))
                    .and_then(|v| v.as_str())
                    .map(resolve_path),
            ),
            "Write" | "Edit" => (
                Some("write".into()),
                tool_input
                    .get("file_path")
                    .and_then(|v| v.as_str())
                    .map(resolve_path),
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
        }
    }

    fn extract(&self, obs: &Observable) -> Option<Vec<String>> {
        match obs {
            Observable::ToolName => Some(vec![self.tool_name.clone()]),
            Observable::HookType => self.hook_type.clone().map(|h| vec![h]),
            Observable::AgentName => self.agent_name.clone().map(|a| vec![a]),
            Observable::PositionalArg(i) => {
                self.args.get(*i as usize).map(|a| vec![a.clone()])
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
        }
    }
}

fn resolve_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        let cwd = get_env("PWD");
        if cwd.is_empty() {
            path.to_string()
        } else {
            format!("{cwd}/{path}")
        }
    }
}

fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = without_scheme.split('/').next()?;
    let domain = host.split(':').next()?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

// ── Bash command parsing ────────────────────────────────────────

fn parse_bash_bin_args(parts: &[&str]) -> (String, Vec<String>) {
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
        if i < parts.len() {
            if let Some(skip) =
                transparent_prefix_skip(parts[i], parts.get(i + 1..).unwrap_or(&[]))
            {
                i += 1 + skip;
                continue;
            }
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

// ── DFS Evaluation ──────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct EvalTrace {
    matched: Vec<TraceEntry>,
    skipped: Vec<TraceEntry>,
}

#[derive(Debug, Clone)]
struct TraceEntry {
    observable: String,
    pattern_desc: String,
    tested_value: Option<String>,
}

fn eval_traced(
    nodes: &[Node],
    ctx: &QueryContext,
    trace: &mut EvalTrace,
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
                let values = ctx.extract(observe);
                let tested = values.as_ref().map(|vs| vs.join(", "));
                if matches_observable(observe, pattern, *terminal, ctx) {
                    if let Some(d) = eval_traced(children, ctx, trace) {
                        trace.matched.push(TraceEntry {
                            observable: format!("{observe:?}"),
                            pattern_desc: format!("{pattern:?}"),
                            tested_value: tested,
                        });
                        return Some(d);
                    }
                } else {
                    trace.skipped.push(TraceEntry {
                        observable: format!("{observe:?}"),
                        pattern_desc: format!("{pattern:?}"),
                        tested_value: tested,
                    });
                }
            }
        }
    }
    None
}

fn matches_observable(
    obs: &Observable,
    pattern: &Pattern,
    terminal: bool,
    ctx: &QueryContext,
) -> bool {
    match obs {
        Observable::HasArg => ctx.args.iter().any(|arg| pattern.matches(arg)),
        Observable::PositionalArg(i) if terminal => {
            let idx = *i as usize;
            match ctx.args.get(idx) {
                Some(val) if pattern.matches(val) => ctx.args.len() == idx + 1,
                _ => false,
            }
        }
        _ => {
            if let Some(values) = ctx.extract(obs) {
                values.iter().any(|v| pattern.matches(v))
            } else {
                matches!(pattern, Pattern::Wildcard)
            }
        }
    }
}

// ── CompiledPolicy evaluation ───────────────────────────────────

impl CompiledPolicy {
    pub fn evaluate(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
    ) -> PolicyDecision {
        let ctx = QueryContext::from_tool(tool_name, tool_input);
        let mut trace = EvalTrace::default();
        let decision = eval_traced(&self.tree, &ctx, &mut trace);

        match decision {
            Some(d) => {
                let effect = d.effect();
                let sandbox = d
                    .sandbox_ref()
                    .and_then(|sr| self.sandboxes.get(&sr.0))
                    .cloned();
                let resolution = format!("result: {effect}");

                PolicyDecision {
                    effect,
                    reason: Some(resolution.clone()),
                    trace: self.build_trace(&trace, &resolution, effect),
                    sandbox,
                    sandbox_name: d.sandbox_ref().cloned(),
                }
            }
            None => {
                let resolution =
                    format!("no rules matched, default: {}", self.default_effect);
                PolicyDecision {
                    effect: self.default_effect,
                    reason: Some(resolution.clone()),
                    trace: self.build_trace(&trace, &resolution, self.default_effect),
                    sandbox: None,
                    sandbox_name: None,
                }
            }
        }
    }

    fn build_trace(
        &self,
        trace: &EvalTrace,
        resolution: &str,
        effect: Effect,
    ) -> DecisionTrace {
        DecisionTrace {
            matched_rules: trace
                .matched
                .iter()
                .map(|e| RuleMatch {
                    description: format!(
                        "{}={}",
                        e.observable,
                        e.tested_value.as_deref().unwrap_or("?")
                    ),
                    effect,
                })
                .collect(),
            skipped_rules: trace
                .skipped
                .iter()
                .map(|e| RuleSkip {
                    description: format!("{}: {}", e.observable, e.pattern_desc),
                    reason: format!(
                        "pattern mismatch (value: {})",
                        e.tested_value.as_deref().unwrap_or("absent")
                    ),
                })
                .collect(),
            final_resolution: resolution.to_string(),
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        self.validate_nodes(&self.tree, &mut errors);
        errors
    }

    fn validate_nodes(&self, nodes: &[Node], errors: &mut Vec<String>) {
        for node in nodes {
            match node {
                Node::Decision(d) => {
                    if let Some(sr) = d.sandbox_ref() {
                        if !self.sandboxes.contains_key(&sr.0) {
                            errors.push(format!(
                                "sandbox reference '{}' not found",
                                sr.0
                            ));
                        }
                    }
                }
                Node::Condition { children, .. } => {
                    self.validate_nodes(children, errors);
                }
            }
        }
    }
}

// ── Rule formatting ─────────────────────────────────────────────

pub fn format_rules(policy: &CompiledPolicy) -> Vec<String> {
    let mut lines = Vec::new();
    for node in &policy.tree {
        format_node(node, &mut lines, &mut vec![]);
    }
    lines.push(format!("Default: {}", policy.default_effect));
    lines
}

fn format_node(node: &Node, lines: &mut Vec<String>, path: &mut Vec<String>) {
    match node {
        Node::Decision(d) => {
            let effect = d.effect();
            let sandbox = d
                .sandbox_ref()
                .map(|s| format!(" (sandbox: {})", s.0))
                .unwrap_or_default();
            if path.is_empty() {
                lines.push(format!("{effect}{sandbox}"));
            } else {
                lines.push(format!("{} → {effect}{sandbox}", path.join(" → ")));
            }
        }
        Node::Condition {
            observe,
            pattern,
            children,
            ..
        } => {
            let desc = format_condition(observe, pattern);
            path.push(desc);
            for child in children {
                format_node(child, lines, path);
            }
            path.pop();
        }
    }
}

fn format_condition(obs: &Observable, pat: &Pattern) -> String {
    let obs_str = match obs {
        Observable::ToolName => "ToolName".into(),
        Observable::PositionalArg(i) => format!("Arg[{i}]"),
        Observable::HasArg => "HasArg".into(),
        Observable::NamedArg(n) => format!("Named({n})"),
        Observable::FsOp => "FsOp".into(),
        Observable::FsPath => "FsPath".into(),
        Observable::NetDomain => "NetDomain".into(),
        Observable::HookType => "HookType".into(),
        Observable::AgentName => "AgentName".into(),
        Observable::NestedField(f) => format!("Field({})", f.join(".")),
    };
    let pat_str = match pat {
        Pattern::Wildcard => "*".into(),
        Pattern::Literal(v) => format!("{v}"),
        Pattern::Regex(re) => format!("/{}/", re.as_str()),
        Pattern::AnyOf(pats) => {
            let strs: Vec<String> = pats
                .iter()
                .map(|p| match p {
                    Pattern::Literal(v) => format!("{v}"),
                    Pattern::Regex(re) => format!("/{}/", re.as_str()),
                    _ => format!("{p:?}"),
                })
                .collect();
            format!("[{}]", strs.join("|"))
        }
        Pattern::Not(p) => format!("!{p:?}"),
        Pattern::Prefix(v) => format!("{v}/**"),
    };
    format!("{obs_str}={pat_str}")
}
