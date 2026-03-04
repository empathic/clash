//! AST types for the policy language.
//!
//! All types derive `Serialize` and `Deserialize` so the AST serves as the
//! serialization IR — policies are authored and stored as JSON/YAML.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::policy::Effect;

// ---------------------------------------------------------------------------
// PolicyDocument — top-level serde type
// ---------------------------------------------------------------------------

fn default_schema_version() -> u32 {
    4
}

/// A complete policy document — the top-level unit of serialization.
///
/// Replaces the former `Vec<TopLevel>` representation with an explicit struct
/// that carries document-level metadata as fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDocument {
    /// Schema version (currently 4).
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// The entry policy to evaluate (formerly `(use "name")`).
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_policy: Option<String>,
    /// Default effect for unmatched requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_effect: Option<Effect>,
    /// Named policy definitions.
    pub policies: Vec<PolicyDef>,
}

/// A named policy containing rules and includes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDef {
    pub name: String,
    pub body: Vec<PolicyItem>,
}

// ---------------------------------------------------------------------------
// PolicyItem — items inside a policy block
// ---------------------------------------------------------------------------

/// An item inside a policy block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyItem {
    /// Import rules from another policy by name.
    Include(String),
    /// A permission rule: effect + capability matcher.
    Rule(Rule),
    /// Conditional block: when an observable matches a pattern, apply body.
    When {
        observable: Observable,
        pattern: ArmPattern,
        body: Vec<PolicyItem>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_eq: bool,
    },
    /// Dispatch block: match an observable against multiple arms.
    Match(MatchBlock),
    /// Bare effect (only inside `when` bodies).
    Effect(Effect),
}

// ---------------------------------------------------------------------------
// Rule and capability matchers
// ---------------------------------------------------------------------------

/// A single permission rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub effect: Effect,
    #[serde(flatten)]
    pub matcher: CapMatcher,
    /// Optional sandbox policy for exec rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxRef>,
}

/// How a sandbox is specified on an exec rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRef {
    /// Reference a named policy.
    Named(String),
    /// Inline rules.
    Inline(Vec<Rule>),
}

/// A capability matcher — one of the four capability domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapMatcher {
    Exec(ExecMatcher),
    Fs(FsMatcher),
    Net(NetMatcher),
    Tool(ToolMatcher),
}

/// Matches command execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecMatcher {
    /// Binary pattern. `Pattern::Any` if omitted.
    #[serde(default = "Pattern::any")]
    pub bin: Pattern,
    /// Positional argument patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<Pattern>,
    /// Orderless argument patterns (`:has` in the old syntax).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub has_args: Vec<Pattern>,
}

/// Matches filesystem operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsMatcher {
    /// Operation filter.
    #[serde(default = "OpPattern::any")]
    pub op: OpPattern,
    /// Path filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathFilter>,
}

/// Matches network access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetMatcher {
    /// Domain pattern.
    #[serde(default = "Pattern::any")]
    pub domain: Pattern,
    /// Optional URL path filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathFilter>,
}

/// Matches tools by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolMatcher {
    /// Tool name pattern.
    #[serde(default = "Pattern::any")]
    pub name: Pattern,
}

// ---------------------------------------------------------------------------
// OpPattern / FsOp
// ---------------------------------------------------------------------------

/// A filesystem operation pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpPattern {
    /// Matches any operation.
    Any,
    /// A single operation.
    Single(FsOp),
    /// Matches any of the listed operations.
    Or(Vec<FsOp>),
}

impl OpPattern {
    pub fn any() -> Self {
        OpPattern::Any
    }
}

/// Filesystem operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsOp {
    Read,
    Write,
    Create,
    Delete,
}

// ---------------------------------------------------------------------------
// Pattern
// ---------------------------------------------------------------------------

/// A general-purpose pattern used for matching strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pattern {
    /// `"*"` — matches anything.
    Any,
    /// Exact string match.
    Literal(String),
    /// Regex match.
    Regex(String),
    /// Matches any of.
    Or(Vec<Pattern>),
    /// Negation.
    Not(Box<Pattern>),
}

impl Pattern {
    pub fn any() -> Self {
        Pattern::Any
    }
}

// ---------------------------------------------------------------------------
// PathFilter / PathExpr
// ---------------------------------------------------------------------------

/// A path filter used in fs/net matchers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathFilter {
    /// Recursive subtree match.
    Subpath {
        path: PathExpr,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        worktree: bool,
    },
    /// Exact file match.
    Literal(String),
    /// Regex on resolved path.
    Regex(String),
    /// Or combinator.
    Or(Vec<PathFilter>),
    /// Negation.
    Not(Box<PathFilter>),
}

/// A path expression that may reference environment variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathExpr {
    /// A static path string.
    Static(String),
    /// Resolved from an environment variable at compile time.
    Env(String),
    /// Concatenate resolved parts.
    Join(Vec<PathExpr>),
}

// ---------------------------------------------------------------------------
// Observable — custom string-based serde
// ---------------------------------------------------------------------------

/// Unified observable reference for `when` guards and `match` dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observable {
    /// `command` — invocation-type predicate matching exec queries.
    Command,
    /// `tool` — invocation-type predicate matching tool queries.
    Tool,
    /// `agent` — invocation-type predicate matching subagent spawning.
    Agent,
    /// `mcp` — invocation-type predicate matching MCP tool invocations.
    Mcp,

    // -- ctx.http namespace --
    HttpDomain,
    HttpMethod,
    HttpPort,
    HttpPath,

    // -- ctx.fs namespace --
    FsAction,
    FsPath,
    FsExists,

    // -- ctx.process namespace --
    ProcessCommand,
    ProcessArgs,

    // -- ctx.tool namespace --
    ToolName,
    ToolArgs,
    /// `ctx.tool.args.<field>?` — nullable accessor for a specific tool argument field.
    ToolArgField(String),

    // -- ctx.agent namespace --
    AgentName,

    // -- ctx.mcp namespace --
    McpServer,
    McpTool,

    // -- ctx.state --
    State,

    /// Tuple of observables.
    Tuple(Vec<Observable>),
}

impl Observable {
    /// Return the canonical string name for this observable.
    pub fn as_str(&self) -> String {
        match self {
            Observable::Command => "command".into(),
            Observable::Tool => "tool".into(),
            Observable::Agent => "agent".into(),
            Observable::Mcp => "mcp".into(),
            Observable::HttpDomain => "ctx.http.domain".into(),
            Observable::HttpMethod => "ctx.http.method".into(),
            Observable::HttpPort => "ctx.http.port".into(),
            Observable::HttpPath => "ctx.http.path".into(),
            Observable::FsAction => "ctx.fs.action".into(),
            Observable::FsPath => "ctx.fs.path".into(),
            Observable::FsExists => "ctx.fs.exists".into(),
            Observable::ProcessCommand => "ctx.process.command".into(),
            Observable::ProcessArgs => "ctx.process.args".into(),
            Observable::ToolName => "ctx.tool.name".into(),
            Observable::ToolArgs => "ctx.tool.args".into(),
            Observable::ToolArgField(field) => format!("ctx.tool.args.{field}?"),
            Observable::AgentName => "ctx.agent.name".into(),
            Observable::McpServer => "ctx.mcp.server".into(),
            Observable::McpTool => "ctx.mcp.tool".into(),
            Observable::State => "ctx.state".into(),
            Observable::Tuple(obs) => {
                let parts: Vec<String> = obs.iter().map(|o| o.as_str()).collect();
                format!("[{}]", parts.join(" "))
            }
        }
    }

    /// Parse an observable from its string name.
    pub fn from_str_name(s: &str) -> Result<Self, String> {
        match s {
            "command" => Ok(Observable::Command),
            "tool" => Ok(Observable::Tool),
            "agent" => Ok(Observable::Agent),
            "mcp" => Ok(Observable::Mcp),
            "ctx.http.domain" => Ok(Observable::HttpDomain),
            "ctx.http.method" => Ok(Observable::HttpMethod),
            "ctx.http.port" => Ok(Observable::HttpPort),
            "ctx.http.path" => Ok(Observable::HttpPath),
            "ctx.fs.action" => Ok(Observable::FsAction),
            "ctx.fs.path" => Ok(Observable::FsPath),
            "ctx.fs.exists" => Ok(Observable::FsExists),
            "ctx.process.command" => Ok(Observable::ProcessCommand),
            "ctx.process.args" => Ok(Observable::ProcessArgs),
            "ctx.tool.name" => Ok(Observable::ToolName),
            "ctx.tool.args" => Ok(Observable::ToolArgs),
            "ctx.agent.name" => Ok(Observable::AgentName),
            "ctx.mcp.server" => Ok(Observable::McpServer),
            "ctx.mcp.tool" => Ok(Observable::McpTool),
            "ctx.state" => Ok(Observable::State),
            s if s.starts_with("ctx.tool.args.") && s.ends_with('?') => {
                let field = s
                    .strip_prefix("ctx.tool.args.")
                    .unwrap()
                    .strip_suffix('?')
                    .unwrap();
                Ok(Observable::ToolArgField(field.to_string()))
            }
            s if s.starts_with('[') && s.ends_with(']') => {
                let inner = &s[1..s.len() - 1];
                let parts: Result<Vec<Observable>, String> = inner
                    .split_whitespace()
                    .map(Observable::from_str_name)
                    .collect();
                Ok(Observable::Tuple(parts?))
            }
            _ => Err(format!("unknown observable: {s:?}")),
        }
    }
}

impl fmt::Display for Observable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Observable {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for Observable {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Observable::from_str_name(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// SandboxItem (used in compiled sandbox blocks)
// ---------------------------------------------------------------------------

/// An item inside a sandbox block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxItem {
    /// A flat rule.
    Rule(Rule),
    /// A match dispatch block.
    Match(MatchBlock),
}

// ---------------------------------------------------------------------------
// Match types
// ---------------------------------------------------------------------------

/// A match dispatch block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchBlock {
    pub observable: Observable,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Effect>,
    pub arms: Vec<MatchArmAst>,
}

/// One arm of a `match` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchArmAst {
    pub pattern: ArmPattern,
    pub effect: Effect,
}

impl MatchArmAst {
    /// Display the effect as a keyword.
    pub fn effect_keyword(&self) -> &'static str {
        match self.effect {
            Effect::Allow => ":allow",
            Effect::Deny => ":deny",
            Effect::Ask => ":ask",
        }
    }
}

/// Pattern in a match arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArmPattern {
    /// A single pattern.
    Single(Pattern),
    /// A single path pattern.
    SinglePath(PathFilter),
    /// An exec-style pattern for `command` observable.
    Exec(ExecMatcher),
    /// A tuple pattern.
    Tuple(Vec<ArmPatternElement>),
}

/// An element in a tuple match arm pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArmPatternElement {
    /// A general pattern.
    Pat(Pattern),
    /// A path filter.
    Path(PathFilter),
}

// ---------------------------------------------------------------------------
// Display implementations (human-readable, not s-expr)
// ---------------------------------------------------------------------------

impl fmt::Display for FsOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsOp::Read => write!(f, "read"),
            FsOp::Write => write!(f, "write"),
            FsOp::Create => write!(f, "create"),
            FsOp::Delete => write!(f, "delete"),
        }
    }
}

// ---------------------------------------------------------------------------
// Display impls (JSON-ish human-readable output)
// ---------------------------------------------------------------------------

macro_rules! display_as_json {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl fmt::Display for $ty {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    match serde_json::to_string(self) {
                        Ok(s) => write!(f, "{s}"),
                        Err(_) => write!(f, "{:?}", self),
                    }
                }
            }
        )+
    };
}

display_as_json!(
    Rule,
    CapMatcher,
    PolicyItem,
    ArmPattern,
    ExecMatcher,
    FsMatcher,
    NetMatcher,
    ToolMatcher,
    OpPattern,
    Pattern,
    PathFilter,
    PathExpr,
);

// ---------------------------------------------------------------------------
// Test strategies (proptest)
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod strategies {
    use proptest::prelude::*;

    use super::*;

    /// Generate a safe identifier string.
    fn arb_identifier() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9_-]{0,12}".prop_map(|s| s.to_string())
    }

    /// Generate an arbitrary Pattern (max depth controlled by recursion limit).
    pub fn arb_pattern() -> impl Strategy<Value = Pattern> {
        arb_pattern_inner(3)
    }

    fn arb_pattern_inner(depth: u32) -> impl Strategy<Value = Pattern> {
        if depth == 0 {
            prop_oneof![
                Just(Pattern::Any),
                arb_identifier().prop_map(Pattern::Literal),
            ]
            .boxed()
        } else {
            prop_oneof![
                4 => Just(Pattern::Any),
                4 => arb_identifier().prop_map(Pattern::Literal),
                1 => prop::collection::vec(arb_pattern_inner(depth - 1), 2..=4)
                    .prop_map(Pattern::Or),
                1 => arb_pattern_inner(depth - 1)
                    .prop_map(|p| Pattern::Not(Box::new(p))),
            ]
            .boxed()
        }
    }

    /// Generate an arbitrary OpPattern.
    pub fn arb_op_pattern() -> impl Strategy<Value = OpPattern> {
        prop_oneof![
            Just(OpPattern::Any),
            Just(OpPattern::Single(FsOp::Read)),
            Just(OpPattern::Single(FsOp::Write)),
            Just(OpPattern::Single(FsOp::Create)),
            Just(OpPattern::Single(FsOp::Delete)),
            prop::collection::vec(
                prop_oneof![
                    Just(FsOp::Read),
                    Just(FsOp::Write),
                    Just(FsOp::Create),
                    Just(FsOp::Delete),
                ],
                2..=4,
            )
            .prop_map(OpPattern::Or),
        ]
    }

    /// Generate an arbitrary PathExpr.
    pub fn arb_path_expr() -> impl Strategy<Value = PathExpr> {
        arb_path_expr_inner(2)
    }

    fn arb_path_expr_inner(depth: u32) -> impl Strategy<Value = PathExpr> {
        if depth == 0 {
            prop_oneof![
                arb_identifier().prop_map(|s| PathExpr::Static(format!("/tmp/{s}"))),
                Just(PathExpr::Env("HOME".into())),
                Just(PathExpr::Env("PWD".into())),
            ]
            .boxed()
        } else {
            prop_oneof![
                3 => arb_identifier().prop_map(|s| PathExpr::Static(format!("/tmp/{s}"))),
                2 => Just(PathExpr::Env("HOME".into())),
                1 => prop::collection::vec(arb_path_expr_inner(depth - 1), 2..=3)
                    .prop_map(PathExpr::Join),
            ]
            .boxed()
        }
    }

    /// Generate an arbitrary PathFilter.
    pub fn arb_path_filter() -> impl Strategy<Value = PathFilter> {
        arb_path_filter_inner(2)
    }

    fn arb_path_filter_inner(depth: u32) -> impl Strategy<Value = PathFilter> {
        if depth == 0 {
            prop_oneof![
                arb_identifier().prop_map(|s| PathFilter::Literal(format!("/tmp/{s}"))),
                (arb_path_expr(), proptest::bool::ANY)
                    .prop_map(|(expr, wt)| PathFilter::Subpath { path: expr, worktree: wt }),
            ]
            .boxed()
        } else {
            prop_oneof![
                3 => arb_identifier().prop_map(|s| PathFilter::Literal(format!("/tmp/{s}"))),
                2 => (arb_path_expr(), proptest::bool::ANY)
                    .prop_map(|(expr, wt)| PathFilter::Subpath { path: expr, worktree: wt }),
                1 => prop::collection::vec(arb_path_filter_inner(depth - 1), 2..=3)
                    .prop_map(PathFilter::Or),
                1 => arb_path_filter_inner(depth - 1)
                    .prop_map(|pf| PathFilter::Not(Box::new(pf))),
            ]
            .boxed()
        }
    }

    /// Generate an arbitrary CapMatcher.
    pub fn arb_cap_matcher() -> impl Strategy<Value = CapMatcher> {
        prop_oneof![
            arb_exec_matcher().prop_map(CapMatcher::Exec),
            arb_fs_matcher().prop_map(CapMatcher::Fs),
            arb_net_matcher().prop_map(CapMatcher::Net),
            arb_tool_matcher().prop_map(CapMatcher::Tool),
        ]
    }

    fn arb_exec_matcher() -> impl Strategy<Value = ExecMatcher> {
        (
            arb_pattern(),
            prop::collection::vec(arb_pattern(), 0..=3),
            prop::collection::vec(arb_pattern(), 0..=2),
        )
            .prop_map(|(bin, args, has_args)| ExecMatcher {
                bin,
                args,
                has_args,
            })
    }

    fn arb_fs_matcher() -> impl Strategy<Value = FsMatcher> {
        (arb_op_pattern(), proptest::option::of(arb_path_filter()))
            .prop_map(|(op, path)| FsMatcher { op, path })
    }

    fn arb_net_matcher() -> impl Strategy<Value = NetMatcher> {
        (arb_pattern(), proptest::option::of(arb_path_filter()))
            .prop_map(|(domain, path)| NetMatcher { domain, path })
    }

    fn arb_tool_matcher() -> impl Strategy<Value = ToolMatcher> {
        arb_pattern().prop_map(|name| ToolMatcher { name })
    }

    fn arb_effect() -> impl Strategy<Value = Effect> {
        prop_oneof![Just(Effect::Allow), Just(Effect::Deny), Just(Effect::Ask)]
    }

    /// Generate an arbitrary Rule (without sandbox).
    pub fn arb_rule() -> impl Strategy<Value = Rule> {
        (arb_effect(), arb_cap_matcher()).prop_map(|(effect, matcher)| Rule {
            effect,
            matcher,
            sandbox: None,
        })
    }

    /// Generate an arbitrary Rule that may have an inline sandbox.
    pub fn arb_rule_with_sandbox() -> impl Strategy<Value = Rule> {
        (
            arb_effect(),
            arb_exec_matcher(),
            proptest::option::of(prop::collection::vec(
                (arb_effect(), arb_cap_matcher()).prop_map(|(effect, matcher)| Rule {
                    effect,
                    matcher,
                    sandbox: None,
                }),
                1..=3,
            )),
        )
            .prop_map(|(effect, exec, sandbox_rules)| Rule {
                effect,
                matcher: CapMatcher::Exec(exec),
                sandbox: sandbox_rules.map(SandboxRef::Inline),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_policy_document() {
        let doc = PolicyDocument {
            schema_version: 4,
            use_policy: Some("main".into()),
            default_effect: Some(Effect::Deny),
            policies: vec![
                PolicyDef {
                    name: "cwd-access".into(),
                    body: vec![PolicyItem::Rule(Rule {
                        effect: Effect::Allow,
                        matcher: CapMatcher::Fs(FsMatcher {
                            op: OpPattern::Single(FsOp::Read),
                            path: Some(PathFilter::Subpath {
                                path: PathExpr::Env("PWD".into()),
                                worktree: true,
                            }),
                        }),
                        sandbox: None,
                    })],
                },
                PolicyDef {
                    name: "main".into(),
                    body: vec![PolicyItem::Include("cwd-access".into())],
                },
            ],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let deserialized: PolicyDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, deserialized);
    }

    #[test]
    fn observable_serde_roundtrip() {
        let obs = Observable::HttpDomain;
        let json = serde_json::to_string(&obs).unwrap();
        assert_eq!(json, "\"ctx.http.domain\"");
        let deserialized: Observable = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, deserialized);
    }

    #[test]
    fn observable_tool_arg_field_roundtrip() {
        let obs = Observable::ToolArgField("file_path".into());
        let json = serde_json::to_string(&obs).unwrap();
        assert_eq!(json, "\"ctx.tool.args.file_path?\"");
        let deserialized: Observable = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, deserialized);
    }

    #[test]
    fn observable_tuple_roundtrip() {
        let obs = Observable::Tuple(vec![Observable::FsAction, Observable::FsPath]);
        let json = serde_json::to_string(&obs).unwrap();
        let deserialized: Observable = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, deserialized);
    }

    // JSON roundtrip for arbitrary rules
    use proptest::prelude::*;
    use super::strategies::*;

    proptest! {
        #[test]
        fn rule_json_roundtrips(rule in arb_rule()) {
            let json = serde_json::to_string(&rule).unwrap();
            let deserialized: Rule = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(rule, deserialized);
        }
    }
}
