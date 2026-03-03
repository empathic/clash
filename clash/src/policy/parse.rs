//! Parser: s-expression tokens → AST.
//!
//! Consumes the generic `SExpr` tree from `sexpr.rs` and produces typed
//! `TopLevel` nodes. Errors are reported with source spans.

use std::collections::{HashMap, HashSet};

use anyhow::{Result, bail, ensure};

use crate::policy::Effect;
use crate::policy::sexpr::{self, BRACKET_MARKER, SExpr};

use super::ast::*;

/// Def-macro bindings: name → raw s-expression value.
type Defs = HashMap<String, SExpr>;

/// If the SExpr is a bracket list of strings/atoms, return the string values.
/// This preserves backwards compatibility with `(def name ["a" "b" ...])`.
fn try_as_string_list(sexpr: &SExpr) -> Option<Vec<String>> {
    if let SExpr::List(children, _) = sexpr {
        if !children.is_empty() && matches!(&children[0], SExpr::Atom(s, _) if s == BRACKET_MARKER)
        {
            let mut values = Vec::new();
            for child in &children[1..] {
                match child {
                    SExpr::Str(s, _) | SExpr::Atom(s, _) => values.push(s.clone()),
                    _ => return None,
                }
            }
            return Some(values);
        }
    }
    None
}

/// Parse a policy source string into a list of top-level declarations.
///
/// Pass 1: extract version and collect all `def`/`policy` names (for forward
///         reference detection).
/// Pass 2: parse forms sequentially, accumulating `def` bindings and declared
///         policy names so that references are only valid after declaration.
pub fn parse(source: &str) -> Result<Vec<TopLevel>> {
    let sexprs = sexpr::parse(source).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Pass 1: extract version and collect all def/policy names.
    let mut version: u32 = 1;
    let mut all_def_names: HashSet<String> = HashSet::new();
    let mut all_policy_names: HashSet<String> = HashSet::new();
    for expr in &sexprs {
        if let Some(list) = expr.as_list() {
            if !list.is_empty() {
                if let Some("version") = list[0].as_str() {
                    if list.len() == 2 {
                        if let Some(v_str) = list[1].as_str() {
                            if let Ok(v) = v_str.parse::<u32>() {
                                version = v;
                            }
                        }
                    }
                }
                if let Some("def") = list[0].as_str() {
                    if list.len() >= 2 {
                        if let Some(name) = list[1].as_str() {
                            all_def_names.insert(name.to_string());
                        }
                    }
                }
                if let Some("policy") = list[0].as_str() {
                    if list.len() >= 2 {
                        if let SExpr::Str(name, _) = &list[1] {
                            all_policy_names.insert(name.clone());
                        }
                    }
                }
            }
        }
    }

    // Pass 2: parse forms sequentially, building defs incrementally.
    let mut ctx = ParseContext {
        version,
        defs: Defs::new(),
        all_def_names,
        declared_policies: HashSet::new(),
        all_policy_names,
    };

    let mut result = Vec::new();
    for expr in &sexprs {
        // Pre-register policy name before parsing body so self-references
        // are caught by circular-include detection, not forward-reference.
        if let Some(list) = expr.as_list() {
            if list.len() >= 2 {
                if let Some("policy") = list[0].as_str() {
                    if let SExpr::Str(name, _) = &list[1] {
                        ctx.declared_policies.insert(name.clone());
                    }
                }
            }
        }

        let tl = parse_top_level(expr, &ctx)?;

        // Register def bindings after parsing so subsequent forms can use them.
        if let TopLevel::Def { name, value } = &tl {
            ctx.defs.insert(name.clone(), value.clone());
        }

        result.push(tl);
    }

    Ok(result)
}

/// Parsing context carried through the parse tree.
struct ParseContext {
    version: u32,
    defs: Defs,
    /// All def names in the file (for detecting forward references).
    all_def_names: HashSet<String>,
    /// Policy names declared before the current form.
    declared_policies: HashSet<String>,
    /// All policy names in the file (for detecting forward references).
    all_policy_names: HashSet<String>,
}

fn parse_top_level(expr: &SExpr, ctx: &ParseContext) -> Result<TopLevel> {
    let list = require_list(expr, "top-level form")?;
    let head = require_atom(&list[0], "top-level keyword")?;
    match head {
        "version" => parse_version(list),
        "default" => parse_default(list),
        "policy" => parse_policy(list, ctx),
        "use" => {
            require_v2(ctx, "use")?;
            parse_use(list)
        }
        "def" => {
            require_v2(ctx, "def")?;
            parse_def(list)
        }
        other => bail!("unknown top-level form: {other}"),
    }
}

fn require_v2(ctx: &ParseContext, form: &str) -> Result<()> {
    ensure!(ctx.version >= 2, "({form}) requires (version 2) or higher");
    Ok(())
}

fn parse_version(list: &[SExpr]) -> Result<TopLevel> {
    ensure!(
        list.len() == 2,
        "(version) expects exactly 1 argument: version number"
    );
    let atom = require_atom(&list[1], "version number")?;
    let v: u32 = atom
        .parse()
        .map_err(|_| anyhow::anyhow!("(version) expects an integer, got: {atom}"))?;
    ensure!(v >= 1, "(version) must be at least 1, got: {v}");
    Ok(TopLevel::Version(v))
}

fn parse_default(list: &[SExpr]) -> Result<TopLevel> {
    ensure!(
        list.len() == 3,
        "(default) expects exactly 2 arguments: effect and policy name"
    );
    let effect = parse_effect(&list[1])?;
    let policy = require_string(&list[2], "policy name")?;
    Ok(TopLevel::Default {
        effect,
        policy: policy.to_string(),
    })
}

fn parse_use(list: &[SExpr]) -> Result<TopLevel> {
    ensure!(
        list.len() == 2,
        "(use) expects exactly 1 argument: policy name"
    );
    let name = require_string(&list[1], "policy name")?;
    Ok(TopLevel::Use(name.to_string()))
}

fn parse_def(list: &[SExpr]) -> Result<TopLevel> {
    ensure!(
        list.len() == 3,
        "(def) expects exactly 2 arguments: name and value"
    );
    let name = require_atom(&list[1], "def name")?.to_string();
    let value = list[2].clone();
    Ok(TopLevel::Def { name, value })
}

fn parse_policy(list: &[SExpr], ctx: &ParseContext) -> Result<TopLevel> {
    ensure!(list.len() >= 2, "(policy) requires a name");
    let name = require_string(&list[1], "policy name")?.to_string();
    let body = list[2..]
        .iter()
        .map(|e| parse_policy_item(e, ctx))
        .collect::<Result<_>>()?;
    Ok(TopLevel::Policy { name, body })
}

fn parse_policy_item(expr: &SExpr, ctx: &ParseContext) -> Result<PolicyItem> {
    // v2: bare effect keywords (:allow, :deny, :ask) as policy body items.
    if ctx.version >= 2 {
        if let SExpr::Atom(s, _) = expr {
            match s.as_str() {
                ":allow" => return Ok(PolicyItem::Effect(Effect::Allow)),
                ":deny" => return Ok(PolicyItem::Effect(Effect::Deny)),
                ":ask" => return Ok(PolicyItem::Effect(Effect::Ask)),
                _ => {
                    // Def expansion: bare atom matching a def name → splice expression
                    if let Some(def_value) = ctx.defs.get(s.as_str()) {
                        return parse_policy_item(def_value, ctx);
                    }
                }
            }
        }
    }
    let list = require_list(expr, "policy item")?;
    let head = require_atom(&list[0], "policy item keyword")?;
    match head {
        "include" => {
            ensure!(list.len() == 2, "(include) expects exactly 1 argument");
            let name = require_string(&list[1], "include target")?;
            if ctx.version >= 2
                && ctx.all_policy_names.contains(name)
                && !ctx.declared_policies.contains(name)
            {
                bail!("name '{}' referenced before declaration", name);
            }
            Ok(PolicyItem::Include(name.to_string()))
        }
        "when" => {
            require_v2(ctx, "when")?;
            parse_when_block(list, ctx)
        }
        "match" => {
            require_v2(ctx, "match")?;
            let block = parse_match_block(list, ctx)?;
            Ok(PolicyItem::Match(block))
        }
        "sandbox" => {
            require_v2(ctx, "sandbox")?;
            if ctx.version >= 3 {
                bail!(
                    "(sandbox ...) is removed in version 3. \
                     Use (match ctx.http.domain ...) and (match ctx.fs.path ...) instead; \
                     constraints are derived automatically from the decision tree. \
                     Run `clash policy upgrade` to migrate."
                );
            }
            parse_sandbox_block(list, ctx)
        }
        "allow" | "deny" | "ask" => {
            if ctx.version >= 2 {
                bail!(
                    "({head} ...) flat rules are not supported in version 2. \
                     Use (when ...) blocks instead."
                );
            }
            let effect = parse_effect_str(head)?;
            ensure!(
                list.len() >= 2,
                "({head}) expects at least 1 capability matcher"
            );
            let matcher = parse_cap_matcher(&list[1], ctx)?;

            // Scan remaining elements for :sandbox "name" keyword arg.
            let sandbox = parse_keyword_sandbox(&list[2..], ctx)?;

            Ok(PolicyItem::Rule(Rule {
                effect,
                matcher,
                sandbox,
            }))
        }
        other => bail!("unknown policy item: {other}"),
    }
}

/// Parse an optional `:sandbox` keyword argument from remaining elements.
///
/// Accepts either a named reference or inline rules:
///   `:sandbox "name"`
///   `:sandbox (allow (net *)) (allow (fs read ...))`
fn parse_keyword_sandbox(rest: &[SExpr], ctx: &ParseContext) -> Result<Option<SandboxRef>> {
    if rest.is_empty() {
        return Ok(None);
    }
    match &rest[0] {
        SExpr::Atom(s, _) if s == ":sandbox" => {
            ensure!(rest.len() >= 2, ":sandbox requires an argument");
            match &rest[1] {
                SExpr::Str(name, _) => {
                    ensure!(
                        rest.len() == 2,
                        "unexpected elements after :sandbox \"{name}\""
                    );
                    Ok(Some(SandboxRef::Named(name.clone())))
                }
                SExpr::List(..) => {
                    let mut rules = Vec::new();
                    for expr in &rest[1..] {
                        rules.push(parse_inline_sandbox_rule(expr, ctx)?);
                    }
                    Ok(Some(SandboxRef::Inline(rules)))
                }
                other => bail!("expected string or rule after :sandbox, got {:?}", other),
            }
        }
        other => bail!("unexpected element in rule: {:?}", other),
    }
}

/// Parse a single inline sandbox rule: `(effect (matcher))`.
///
/// Inline sandbox rules cannot themselves have `:sandbox` annotations.
fn parse_inline_sandbox_rule(expr: &SExpr, ctx: &ParseContext) -> Result<Rule> {
    let list = require_list(expr, "inline sandbox rule")?;
    ensure!(!list.is_empty(), "empty inline sandbox rule");
    let head = require_atom(&list[0], "inline sandbox rule effect")?;
    let effect = parse_effect_str(head)?;
    ensure!(
        list.len() >= 2,
        "inline sandbox rule ({head}) expects a capability matcher"
    );
    let matcher = parse_cap_matcher(&list[1], ctx)?;
    ensure!(
        list.len() == 2,
        "inline sandbox rules cannot have :sandbox annotations"
    );
    Ok(Rule {
        effect,
        matcher,
        sandbox: None,
    })
}

fn parse_cap_matcher(expr: &SExpr, ctx: &ParseContext) -> Result<CapMatcher> {
    let list = require_list(expr, "capability matcher")?;
    let head = require_atom(&list[0], "capability kind")?;
    match head {
        "exec" => parse_exec_matcher(&list[1..], ctx).map(CapMatcher::Exec),
        "fs" => parse_fs_matcher(&list[1..], ctx).map(CapMatcher::Fs),
        "net" => parse_net_matcher(&list[1..], ctx).map(CapMatcher::Net),
        "tool" => parse_tool_matcher(&list[1..], ctx).map(CapMatcher::Tool),
        other => bail!("unknown capability: {other}"),
    }
}

fn parse_exec_matcher(args: &[SExpr], ctx: &ParseContext) -> Result<ExecMatcher> {
    if args.is_empty() {
        return Ok(ExecMatcher {
            bin: Pattern::Any,
            args: vec![],
            has_args: vec![],
        });
    }
    let bin = parse_pattern(&args[0], ctx)?;

    // Parse positional args until we hit `:has`, then parse the rest as
    // orderless patterns.
    let mut positional = Vec::new();
    let mut has = Vec::new();
    let mut saw_has = false;

    for expr in &args[1..] {
        if !saw_has {
            if let SExpr::Atom(s, _) = expr
                && s == ":has"
            {
                saw_has = true;
                continue;
            }
            positional.push(parse_pattern(expr, ctx)?);
        } else {
            has.push(parse_pattern(expr, ctx)?);
        }
    }

    Ok(ExecMatcher {
        bin,
        args: positional,
        has_args: has,
    })
}

fn parse_fs_matcher(args: &[SExpr], ctx: &ParseContext) -> Result<FsMatcher> {
    if args.is_empty() {
        return Ok(FsMatcher {
            op: OpPattern::Any,
            path: None,
        });
    }
    let op = parse_op_pattern(&args[0])?;
    let path = if args.len() > 1 {
        Some(parse_path_filter(&args[1], ctx)?)
    } else {
        None
    };
    Ok(FsMatcher { op, path })
}

fn parse_net_matcher(args: &[SExpr], ctx: &ParseContext) -> Result<NetMatcher> {
    if args.is_empty() {
        return Ok(NetMatcher {
            domain: Pattern::Any,
            path: None,
        });
    }
    ensure!(
        args.len() <= 2,
        "(net) expects at most 2 arguments (domain and optional path filter)"
    );
    let domain = parse_pattern(&args[0], ctx)?;
    let path = if args.len() > 1 {
        Some(parse_path_filter(&args[1], ctx)?)
    } else {
        None
    };
    Ok(NetMatcher { domain, path })
}

fn parse_tool_matcher(args: &[SExpr], ctx: &ParseContext) -> Result<ToolMatcher> {
    if args.is_empty() {
        return Ok(ToolMatcher { name: Pattern::Any });
    }
    ensure!(args.len() == 1, "(tool) expects at most 1 argument");
    let name = parse_pattern(&args[0], ctx)?;
    Ok(ToolMatcher { name })
}

fn parse_op_pattern(expr: &SExpr) -> Result<OpPattern> {
    match expr {
        SExpr::Atom(s, _) if s == "*" => Ok(OpPattern::Any),
        SExpr::Atom(s, _) => {
            let op = parse_fs_op(s)?;
            Ok(OpPattern::Single(op))
        }
        SExpr::List(children, _) => {
            let head = require_atom(&children[0], "op pattern keyword")?;
            match head {
                "or" => {
                    let ops = children[1..]
                        .iter()
                        .map(|c| {
                            let name = require_atom(c, "fs operation")?;
                            parse_fs_op(name)
                        })
                        .collect::<Result<_>>()?;
                    Ok(OpPattern::Or(ops))
                }
                other => bail!("unknown op pattern form: {other}"),
            }
        }
        _ => bail!("expected operation pattern"),
    }
}

fn parse_fs_op(s: &str) -> Result<FsOp> {
    match s {
        "read" => Ok(FsOp::Read),
        "write" => Ok(FsOp::Write),
        "create" => Ok(FsOp::Create),
        "delete" => Ok(FsOp::Delete),
        other => bail!("unknown fs operation: {other}"),
    }
}

fn parse_pattern(expr: &SExpr, ctx: &ParseContext) -> Result<Pattern> {
    match expr {
        SExpr::Atom(s, _) if s == "*" => Ok(Pattern::Any),
        SExpr::Atom(s, _) => {
            // Def expansion: bare atom matching a def name
            if let Some(def_value) = ctx.defs.get(s.as_str()) {
                if let Some(values) = try_as_string_list(def_value) {
                    // Bracket list → Or(literals) (backwards compat)
                    Ok(Pattern::Or(
                        values.iter().map(|v| Pattern::Literal(v.clone())).collect(),
                    ))
                } else {
                    // Arbitrary expression → parse as pattern
                    parse_pattern(def_value, ctx)
                }
            } else if ctx.version >= 2 && ctx.all_def_names.contains(s.as_str()) {
                bail!("name '{}' referenced before declaration", s)
            } else {
                Ok(Pattern::Literal(s.clone()))
            }
        }
        SExpr::Str(s, _) => Ok(Pattern::Literal(s.clone())),
        SExpr::Regex(r, _) => Ok(Pattern::Regex(r.clone())),
        SExpr::List(children, _) => {
            ensure!(!children.is_empty(), "empty list in pattern position");
            let head = require_atom(&children[0], "pattern keyword")?;
            match head {
                "or" => {
                    let ps = children[1..]
                        .iter()
                        .map(|e| parse_pattern(e, ctx))
                        .collect::<Result<_>>()?;
                    Ok(Pattern::Or(ps))
                }
                "not" => {
                    ensure!(children.len() == 2, "(not) expects exactly 1 argument");
                    let inner = parse_pattern(&children[1], ctx)?;
                    Ok(Pattern::Not(Box::new(inner)))
                }
                other => bail!("unknown pattern form: {other}"),
            }
        }
    }
}

fn parse_path_filter(expr: &SExpr, ctx: &ParseContext) -> Result<PathFilter> {
    match expr {
        SExpr::Str(s, _) => Ok(PathFilter::Literal(s.clone())),
        SExpr::Atom(s, _) => Ok(PathFilter::Literal(s.clone())),
        SExpr::Regex(r, _) => Ok(PathFilter::Regex(r.clone())),
        SExpr::List(children, _) => {
            ensure!(!children.is_empty(), "empty list in path filter position");
            let head = require_atom(&children[0], "path filter keyword")?;
            match head {
                "subpath" => {
                    // (subpath path_expr) or (subpath :worktree path_expr)
                    let (worktree, expr_idx) = if children.len() >= 2 {
                        if let SExpr::Atom(s, _) = &children[1] {
                            if s == ":worktree" {
                                (true, 2)
                            } else {
                                (false, 1)
                            }
                        } else {
                            (false, 1)
                        }
                    } else {
                        (false, 1)
                    };
                    ensure!(
                        children.len() == expr_idx + 1,
                        "(subpath) expects exactly 1 path expression{}",
                        if worktree { " after :worktree" } else { "" }
                    );
                    let path_expr = parse_path_expr(&children[expr_idx], ctx)?;
                    Ok(PathFilter::Subpath(path_expr, worktree))
                }
                "or" => {
                    let fs = children[1..]
                        .iter()
                        .map(|e| parse_path_filter(e, ctx))
                        .collect::<Result<_>>()?;
                    Ok(PathFilter::Or(fs))
                }
                "not" => {
                    ensure!(children.len() == 2, "(not) expects exactly 1 argument");
                    let inner = parse_path_filter(&children[1], ctx)?;
                    Ok(PathFilter::Not(Box::new(inner)))
                }
                other => bail!("unknown path filter form: {other}"),
            }
        }
    }
}

fn parse_path_expr(expr: &SExpr, ctx: &ParseContext) -> Result<PathExpr> {
    match expr {
        SExpr::Str(s, _) => Ok(PathExpr::Static(s.clone())),
        SExpr::Atom(s, _) => {
            // $VAR shorthand: $PWD → (env PWD)
            if let Some(var_name) = s.strip_prefix('$') {
                Ok(PathExpr::Env(var_name.to_string()))
            } else if let Some(def_value) = ctx.defs.get(s.as_str()) {
                if try_as_string_list(def_value).is_some() {
                    // Bracket list defs expand at the path_filter level, not here.
                    Ok(PathExpr::Static(s.clone()))
                } else {
                    // Compound expression → try to parse as path expr
                    parse_path_expr(def_value, ctx)
                }
            } else if ctx.version >= 2 && ctx.all_def_names.contains(s.as_str()) {
                bail!("name '{}' referenced before declaration", s)
            } else {
                Ok(PathExpr::Static(s.clone()))
            }
        }
        SExpr::List(children, _) => {
            ensure!(!children.is_empty(), "empty list in path expression");
            let head = require_atom(&children[0], "path expression keyword")?;
            match head {
                "env" => {
                    ensure!(children.len() == 2, "(env) expects exactly 1 argument");
                    let name = require_string_or_atom(&children[1], "env var name")?;
                    Ok(PathExpr::Env(name.to_string()))
                }
                "join" | "joinpath" => {
                    ensure!(children.len() >= 3, "({head}) expects at least 2 arguments");
                    let parts = children[1..]
                        .iter()
                        .map(|e| parse_path_expr(e, ctx))
                        .collect::<Result<_>>()?;
                    Ok(PathExpr::Join(parts))
                }
                other => bail!("unknown path expression form: {other}"),
            }
        }
        _ => bail!("expected path expression"),
    }
}

// ---------------------------------------------------------------------------
// v2 parse functions: when / sandbox / match
// ---------------------------------------------------------------------------

/// Parse `(when (observable pattern) body...)` → `PolicyItem::When`.
///
/// Body items can be regular policy items or effect keywords (`:allow`/`:deny`/`:ask`).
fn parse_when_block(list: &[SExpr], ctx: &ParseContext) -> Result<PolicyItem> {
    ensure!(
        list.len() >= 3,
        "(when) expects a guard and at least one body item"
    );
    let (observable, pattern) = parse_when_guard(&list[1], ctx)?;
    let body = list[2..]
        .iter()
        .map(|e| parse_when_body_item(e, ctx))
        .collect::<Result<_>>()?;
    Ok(PolicyItem::When {
        observable,
        pattern,
        body,
    })
}

/// Parse a single body item inside a `(when ...)` block.
///
/// Accepts `:allow`/`:deny`/`:ask` atoms as inline effects, or delegates to
/// `parse_policy_item` for structured items like `(sandbox ...)`.
fn parse_when_body_item(expr: &SExpr, ctx: &ParseContext) -> Result<PolicyItem> {
    if let SExpr::Atom(s, _) = expr {
        match s.as_str() {
            ":allow" => return Ok(PolicyItem::Effect(Effect::Allow)),
            ":deny" => return Ok(PolicyItem::Effect(Effect::Deny)),
            ":ask" => return Ok(PolicyItem::Effect(Effect::Ask)),
            _ => {
                // Def expansion: bare atom matching a def name → splice expression
                if let Some(def_value) = ctx.defs.get(s.as_str()) {
                    return parse_when_body_item(def_value, ctx);
                }
            }
        }
    }
    parse_policy_item(expr, ctx)
}

/// Parse a when guard `(observable pattern)` → `(Observable, ArmPattern)`.
///
/// Handles invocation-type guards and ctx.* observable guards:
/// - `(command ...)` → Observable::Command + ArmPattern::Exec
/// - `(tool ...)` → Observable::Tool + ArmPattern::Single
/// - `(ctx.http.domain ...)` → Observable::HttpDomain + ArmPattern::Single
/// - `(ctx.fs.action ...)` → Observable::FsAction + ArmPattern::Single
/// - `(ctx.fs.path ...)` → Observable::FsPath + ArmPattern::SinglePath
///
/// Deprecated flat names (`proxy.domain`, `fs.action`, etc.) are accepted with warnings.
fn parse_when_guard(expr: &SExpr, ctx: &ParseContext) -> Result<(Observable, ArmPattern)> {
    let list = require_list(expr, "when guard")?;
    ensure!(!list.is_empty(), "empty when guard");
    let head = require_atom(&list[0], "guard keyword")?;

    // Map deprecated names to their canonical ctx.* equivalents.
    let (canonical, deprecated) = match head {
        "proxy.domain" => {
            tracing::warn!("deprecated when guard `proxy.domain`: use `ctx.http.domain`");
            ("ctx.http.domain", true)
        }
        "proxy.method" => {
            tracing::warn!("deprecated when guard `proxy.method`: use `ctx.http.method`");
            ("ctx.http.method", true)
        }
        "fs.action" => {
            tracing::warn!("deprecated when guard `fs.action`: use `ctx.fs.action`");
            ("ctx.fs.action", true)
        }
        "fs.path" => {
            tracing::warn!("deprecated when guard `fs.path`: use `ctx.fs.path`");
            ("ctx.fs.path", true)
        }
        other => (other, false),
    };
    let _ = deprecated; // suppress unused warning

    match canonical {
        // Invocation-type guards
        "command" => {
            let m = parse_exec_matcher(&list[1..], ctx)?;
            Ok((Observable::Command, ArmPattern::Exec(m)))
        }
        "tool" => {
            let m = parse_tool_matcher(&list[1..], ctx)?;
            Ok((Observable::Tool, ArmPattern::Single(m.name)))
        }
        "agent" => {
            let m = parse_tool_matcher(&list[1..], ctx)?;
            Ok((Observable::Agent, ArmPattern::Single(m.name)))
        }

        // ctx.http guards
        "ctx.http.domain" => {
            ensure!(
                list.len() == 2,
                "(ctx.http.domain) guard expects exactly 1 pattern"
            );
            let pat = parse_pattern(&list[1], ctx)?;
            Ok((Observable::HttpDomain, ArmPattern::Single(pat)))
        }
        "ctx.http.method" => {
            ensure!(
                list.len() == 2,
                "(ctx.http.method) guard expects exactly 1 pattern"
            );
            let pat = parse_pattern(&list[1], ctx)?;
            Ok((Observable::HttpMethod, ArmPattern::Single(pat)))
        }

        // ctx.fs guards
        "ctx.fs.action" => {
            ensure!(
                list.len() == 2,
                "(ctx.fs.action) guard expects exactly 1 pattern"
            );
            let pat = parse_pattern(&list[1], ctx)?;
            Ok((Observable::FsAction, ArmPattern::Single(pat)))
        }
        "ctx.fs.path" => {
            ensure!(
                list.len() == 2,
                "(ctx.fs.path) guard expects exactly 1 path filter"
            );
            let pf = parse_path_filter(&list[1], ctx)?;
            Ok((Observable::FsPath, ArmPattern::SinglePath(pf)))
        }

        // ctx.tool.args.<field>? — nullable dynamic field when guard
        other if other.starts_with("ctx.tool.args.") => {
            let observable = parse_tool_arg_field(other)?;
            ensure!(list.len() == 2, "({other}) guard expects exactly 1 pattern");
            // Try path filter first, fall back to general pattern
            if let Ok(pf) = try_parse_arm_path_filter(&list[1], ctx) {
                Ok((observable, ArmPattern::SinglePath(pf)))
            } else {
                let pat = parse_pattern(&list[1], ctx)?;
                Ok((observable, ArmPattern::Single(pat)))
            }
        }

        other => bail!(
            "unknown when guard: {other} (expected 'command', 'tool', 'agent', \
             'ctx.http.domain', 'ctx.http.method', 'ctx.fs.action', or 'ctx.fs.path')"
        ),
    }
}

/// Parse `(sandbox items...)` → `PolicyItem::Sandbox`.
fn parse_sandbox_block(list: &[SExpr], ctx: &ParseContext) -> Result<PolicyItem> {
    ensure!(list.len() >= 2, "(sandbox) expects at least one item");
    let mut body = Vec::new();
    for expr in &list[1..] {
        body.push(parse_sandbox_item(expr, ctx)?);
    }
    Ok(PolicyItem::Sandbox { body })
}

/// Parse a single item inside a `(sandbox ...)` block.
fn parse_sandbox_item(expr: &SExpr, ctx: &ParseContext) -> Result<SandboxItem> {
    let list = require_list(expr, "sandbox item")?;
    ensure!(!list.is_empty(), "empty sandbox item");
    let head = require_atom(&list[0], "sandbox item keyword")?;
    match head {
        "match" => {
            let block = parse_sandbox_match_block(list, ctx)?;
            Ok(SandboxItem::Match(block))
        }
        "allow" | "deny" | "ask" => {
            let effect = parse_effect_str(head)?;
            ensure!(
                list.len() >= 2,
                "({head}) expects at least 1 capability matcher"
            );
            let matcher = parse_cap_matcher(&list[1], ctx)?;
            Ok(SandboxItem::Rule(Rule {
                effect,
                matcher,
                sandbox: None,
            }))
        }
        other => bail!("unknown sandbox item: {other} (expected 'match', 'allow', 'deny')"),
    }
}

/// Parse `(match observable arm...)` → `MatchBlock`.
///
/// When `in_sandbox` is true, `:ask` is rejected in arm effects.
fn parse_match_block_inner(
    list: &[SExpr],
    ctx: &ParseContext,
    in_sandbox: bool,
) -> Result<MatchBlock> {
    ensure!(
        list.len() >= 4,
        "(match) expects an observable and at least one pattern/effect pair"
    );
    let observable = parse_observable(&list[1])?;
    let (default, arms) = parse_match_arms(&list[2..], &observable, ctx, in_sandbox)?;
    Ok(MatchBlock {
        observable,
        default,
        arms,
    })
}

/// Parse `(match ...)` at policy level (`:ask` allowed).
fn parse_match_block(list: &[SExpr], ctx: &ParseContext) -> Result<MatchBlock> {
    parse_match_block_inner(list, ctx, false)
}

/// Parse `(match ...)` inside a sandbox block (`:ask` rejected).
fn parse_sandbox_match_block(list: &[SExpr], ctx: &ParseContext) -> Result<MatchBlock> {
    parse_match_block_inner(list, ctx, true)
}

/// Parse an observable reference: `command`, `tool`, or any `ctx.*` observable,
/// plus deprecated flat names (`proxy.domain`, `fs.action`, etc.).
fn parse_observable(expr: &SExpr) -> Result<Observable> {
    match expr {
        SExpr::Atom(s, _) => match s.as_str() {
            // Invocation-type observables (unchanged)
            "command" => Ok(Observable::Command),
            "tool" => Ok(Observable::Tool),
            "agent" => Ok(Observable::Agent),

            // ctx.http namespace
            "ctx.http.domain" => Ok(Observable::HttpDomain),
            "ctx.http.method" => Ok(Observable::HttpMethod),
            "ctx.http.port" => Ok(Observable::HttpPort),
            "ctx.http.path" => Ok(Observable::HttpPath),

            // ctx.fs namespace
            "ctx.fs.action" => Ok(Observable::FsAction),
            "ctx.fs.path" => Ok(Observable::FsPath),
            "ctx.fs.exists" => Ok(Observable::FsExists),

            // ctx.process namespace
            "ctx.process.command" => Ok(Observable::ProcessCommand),
            "ctx.process.args" => Ok(Observable::ProcessArgs),

            // ctx.tool namespace
            "ctx.tool.name" => Ok(Observable::ToolName),
            "ctx.tool.args" => Ok(Observable::ToolArgs),

            // ctx.agent namespace
            "ctx.agent.name" => Ok(Observable::AgentName),

            // ctx.state
            "ctx.state" => Ok(Observable::State),

            // ctx.tool.args.<field>? — nullable dynamic field accessor
            other if other.starts_with("ctx.tool.args.") => parse_tool_arg_field(other),

            // Deprecated flat names — accept with warning
            "proxy.domain" => {
                tracing::warn!("deprecated observable `proxy.domain`: use `ctx.http.domain`");
                Ok(Observable::HttpDomain)
            }
            "proxy.method" => {
                tracing::warn!("deprecated observable `proxy.method`: use `ctx.http.method`");
                Ok(Observable::HttpMethod)
            }
            "fs.action" => {
                tracing::warn!("deprecated observable `fs.action`: use `ctx.fs.action`");
                Ok(Observable::FsAction)
            }
            "fs.path" => {
                tracing::warn!("deprecated observable `fs.path`: use `ctx.fs.path`");
                Ok(Observable::FsPath)
            }

            other => bail!("unknown observable: {other}"),
        },
        SExpr::List(children, _) => {
            // Bracket list: [fs.action fs.path] → Tuple
            ensure!(
                !children.is_empty()
                    && matches!(&children[0], SExpr::Atom(s, _) if s == BRACKET_MARKER),
                "expected observable name or [...] tuple"
            );
            ensure!(
                children.len() >= 3,
                "observable tuple needs at least 2 elements"
            );
            let obs = children[1..]
                .iter()
                .map(parse_observable)
                .collect::<Result<_>>()?;
            Ok(Observable::Tuple(obs))
        }
        _ => bail!("expected observable reference"),
    }
}

/// Parse a `ctx.tool.args.<field>?` nullable dynamic field accessor.
///
/// The `?` suffix is required for dynamic fields — bare `ctx.tool.args.<field>`
/// is a validation error because the field may not exist for all tool invocations.
fn parse_tool_arg_field(atom: &str) -> Result<Observable> {
    let suffix = &atom["ctx.tool.args.".len()..];
    if let Some(field) = suffix.strip_suffix('?') {
        ensure!(
            !field.is_empty(),
            "ctx.tool.args.? requires a field name before the ? suffix"
        );
        ensure!(
            field
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "invalid field name in ctx.tool.args.{field}? \
             (must be alphanumeric, underscore, or hyphen)"
        );
        Ok(Observable::ToolArgField(field.to_string()))
    } else {
        bail!(
            "dynamic field `{atom}` may not exist for all tools — \
             add ? suffix: {atom}?"
        )
    }
}

/// Parse match arms: alternating pattern/effect pairs, with optional leading `(default :effect)`.
///
/// Each arm is `pattern :effect` where pattern can be:
/// - A simple pattern: `"github.com"`, `*`, `(or ...)`, `(not ...)`
/// - A path pattern: `(subpath $PWD)`
/// - An exec pattern (for command observable): `("git" *)`, `*`
/// - A tuple pattern: `["read" (subpath $PWD)]`
///
/// A leading `(default :effect)` form sets the fallthrough for unmatched arms.
/// When `in_sandbox` is true, `:ask` is rejected in effect keywords.
fn parse_match_arms(
    exprs: &[SExpr],
    observable: &Observable,
    ctx: &ParseContext,
    in_sandbox: bool,
) -> Result<(Option<Effect>, Vec<MatchArmAst>)> {
    // Check for leading (default :effect) form.
    let (default, arm_exprs) = if let Some(first) = exprs.first() {
        if let Some(list) = first.as_list() {
            if !list.is_empty() {
                if let Some("default") = list[0].as_str() {
                    ensure!(
                        list.len() == 2,
                        "(default) inside match expects exactly 1 effect"
                    );
                    let effect = parse_match_effect_keyword(&list[1], in_sandbox)?;
                    (Some(effect), &exprs[1..])
                } else {
                    (None, exprs)
                }
            } else {
                (None, exprs)
            }
        } else {
            (None, exprs)
        }
    } else {
        (None, exprs)
    };

    ensure!(
        arm_exprs.len() % 2 == 0,
        "match arms must be pattern/effect pairs (got odd number of elements)"
    );
    let mut arms = Vec::new();
    for pair in arm_exprs.chunks(2) {
        let pattern = parse_arm_pattern(&pair[0], observable, ctx)?;
        let effect = parse_match_effect_keyword(&pair[1], in_sandbox)?;
        arms.push(MatchArmAst { pattern, effect });
    }
    Ok((default, arms))
}

/// Parse a pattern in match-arm position, guided by the observable type.
fn parse_arm_pattern(
    expr: &SExpr,
    observable: &Observable,
    ctx: &ParseContext,
) -> Result<ArmPattern> {
    // Check for bracket tuple pattern: [...]
    if let SExpr::List(children, _) = expr {
        if !children.is_empty() {
            if let SExpr::Atom(s, _) = &children[0] {
                if s == BRACKET_MARKER {
                    return parse_tuple_arm_pattern(&children[1..], observable, ctx);
                }
            }
        }
    }

    // Command observable: parse as ExecMatcher
    if matches!(observable, Observable::Command) {
        return parse_command_arm_pattern(expr, ctx);
    }

    // For path-capable observables, try to parse as path filter first
    if observable_is_path(observable) {
        if let Ok(pf) = try_parse_arm_path_filter(expr, ctx) {
            return Ok(ArmPattern::SinglePath(pf));
        }
    }

    // Fall back to general pattern (tool, ctx.http.domain, ctx.fs.action, etc.)
    let p = parse_pattern(expr, ctx)?;
    Ok(ArmPattern::Single(p))
}

/// Parse a command arm pattern: `("git" *)`, `("git" "push" :has "--force")`, or bare `*`.
fn parse_command_arm_pattern(expr: &SExpr, ctx: &ParseContext) -> Result<ArmPattern> {
    match expr {
        // Bare `*` → match-all exec
        SExpr::Atom(s, _) if s == "*" => Ok(ArmPattern::Exec(ExecMatcher {
            bin: Pattern::Any,
            args: vec![],
            has_args: vec![],
        })),
        // Parenthesized list: ("git" "push" *) or ("git" :has "--force")
        SExpr::List(children, _) if !children.is_empty() => {
            // Must not be a bracket list
            if let SExpr::Atom(s, _) = &children[0] {
                if s == BRACKET_MARKER {
                    bail!("tuple pattern [...] is not valid for command observable");
                }
            }
            let m = parse_exec_matcher(children, ctx)?;
            Ok(ArmPattern::Exec(m))
        }
        _ => bail!("expected exec pattern (\"bin\" args...) or * for command match arm"),
    }
}

/// Parse a bracket tuple arm pattern: `["read" (subpath $PWD)]`.
fn parse_tuple_arm_pattern(
    elements: &[SExpr],
    observable: &Observable,
    ctx: &ParseContext,
) -> Result<ArmPattern> {
    let obs_components = match observable {
        Observable::Tuple(obs) => obs,
        _ => bail!("tuple pattern [...] requires a tuple observable"),
    };
    ensure!(
        elements.len() == obs_components.len(),
        "tuple pattern has {} elements but observable has {}",
        elements.len(),
        obs_components.len()
    );

    let mut elems = Vec::new();
    for (element, obs) in elements.iter().zip(obs_components.iter()) {
        if observable_is_path(obs) {
            match try_parse_arm_path_filter(element, ctx) {
                Ok(pf) => {
                    elems.push(ArmPatternElement::Path(pf));
                    continue;
                }
                Err(e) => {
                    // Propagate validation errors; only swallow "not a path
                    // filter" fallthrough so we can retry as a plain pattern.
                    if !e.to_string().contains("not a path filter") {
                        return Err(e);
                    }
                }
            }
        }
        let p = parse_pattern(element, ctx)?;
        elems.push(ArmPatternElement::Pat(p));
    }
    Ok(ArmPattern::Tuple(elems))
}

/// Try to parse an expression as a path filter in arm context.
/// Returns Err if it doesn't look like a path filter.
fn try_parse_arm_path_filter(expr: &SExpr, ctx: &ParseContext) -> Result<PathFilter> {
    match expr {
        SExpr::List(children, _) if !children.is_empty() => {
            if let SExpr::Atom(s, _) = &children[0] {
                if s == "subpath" || s == "or" || s == "not" {
                    return parse_path_filter(expr, ctx);
                }
            }
            bail!("not a path filter")
        }
        SExpr::Atom(s, _) => {
            // Def expansion: bare atom that is a def name
            if let Some(def_value) = ctx.defs.get(s.as_str()) {
                if let Some(values) = try_as_string_list(def_value) {
                    // Bracket list → Or(Subpath(Static(v))) (backwards compat)
                    return Ok(PathFilter::Or(
                        values
                            .iter()
                            .map(|v| PathFilter::Subpath(PathExpr::Static(v.clone()), false))
                            .collect(),
                    ));
                }
                // Arbitrary expression → try to parse as path filter
                return try_parse_arm_path_filter(def_value, ctx);
            }
            if ctx.version >= 2 && ctx.all_def_names.contains(s.as_str()) {
                bail!("name '{}' referenced before declaration", s);
            }
            bail!("not a path filter")
        }
        _ => bail!("not a path filter"),
    }
}

/// Check if an observable refers to a path value.
///
/// ToolArgField is included because tool arguments may contain file paths
/// that users want to match with `(subpath ...)` patterns.
fn observable_is_path(obs: &Observable) -> bool {
    matches!(obs, Observable::FsPath | Observable::ToolArgField(_))
}

/// Parse an effect keyword in match arm position: `:allow`, `:deny`, `:ask`.
///
/// When `in_sandbox` is true, `:ask` is rejected (sandbox can only :allow or :deny).
fn parse_match_effect_keyword(expr: &SExpr, in_sandbox: bool) -> Result<Effect> {
    let s = require_atom(expr, "effect keyword")?;
    match s {
        ":allow" => Ok(Effect::Allow),
        ":deny" => Ok(Effect::Deny),
        ":ask" => {
            if in_sandbox {
                bail!(
                    ":ask is not allowed in sandbox match arms (sandbox can only :allow or :deny)"
                )
            }
            Ok(Effect::Ask)
        }
        other => bail!("expected :allow, :deny, or :ask, got: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_effect(expr: &SExpr) -> Result<Effect> {
    let s = require_atom(expr, "effect")?;
    parse_effect_str(s)
}

fn parse_effect_str(s: &str) -> Result<Effect> {
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        other => bail!("unknown effect: {other}"),
    }
}

fn require_list<'a>(expr: &'a SExpr, context: &str) -> Result<&'a [SExpr]> {
    expr.as_list()
        .ok_or_else(|| anyhow::anyhow!("expected list for {context}, got {:?}", expr))
}

fn require_atom<'a>(expr: &'a SExpr, context: &str) -> Result<&'a str> {
    match expr {
        SExpr::Atom(s, _) => Ok(s.as_str()),
        _ => bail!("expected atom for {context}, got {:?}", expr),
    }
}

fn require_string<'a>(expr: &'a SExpr, context: &str) -> Result<&'a str> {
    match expr {
        SExpr::Str(s, _) => Ok(s.as_str()),
        _ => bail!(
            "expected quoted string for {context}, got {:?} (names must be quoted)",
            expr
        ),
    }
}

fn require_string_or_atom<'a>(expr: &'a SExpr, context: &str) -> Result<&'a str> {
    expr.as_str()
        .ok_or_else(|| anyhow::anyhow!("expected string or atom for {context}, got {:?}", expr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_form() {
        let ast = parse(r#"(default deny "main")"#).unwrap();
        assert_eq!(ast.len(), 1);
        match &ast[0] {
            TopLevel::Default { effect, policy } => {
                assert_eq!(*effect, Effect::Deny);
                assert_eq!(policy, "main");
            }
            _ => panic!("expected Default"),
        }
    }

    #[test]
    fn parse_empty_policy() {
        let ast = parse(r#"(policy "empty")"#).unwrap();
        match &ast[0] {
            TopLevel::Policy { name, body } => {
                assert_eq!(name, "empty");
                assert!(body.is_empty());
            }
            _ => panic!("expected Policy"),
        }
    }

    #[test]
    fn parse_exec_rule() {
        let ast = parse(r#"(policy "p" (deny (exec "git" "push" *)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        assert_eq!(rule.effect, Effect::Deny);
        assert_eq!(rule.sandbox, None);
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert_eq!(m.bin, Pattern::Literal("git".into()));
                assert_eq!(m.args.len(), 2);
                assert_eq!(m.args[0], Pattern::Literal("push".into()));
                assert_eq!(m.args[1], Pattern::Any);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_fs_rule() {
        let ast =
            parse(r#"(policy "p" (allow (fs (or read write) (subpath (env PWD)))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => {
                assert_eq!(m.op, OpPattern::Or(vec![FsOp::Read, FsOp::Write]));
                match &m.path {
                    Some(PathFilter::Subpath(PathExpr::Env(name), false)) => {
                        assert_eq!(name, "PWD");
                    }
                    other => panic!("expected Subpath(Env(PWD)), got {other:?}"),
                }
            }
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn parse_net_regex() {
        let ast = parse(r#"(policy "p" (deny (net /.*\.evil\.com/)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Net(m) => {
                assert_eq!(m.domain, Pattern::Regex(r".*\.evil\.com".into()));
            }
            _ => panic!("expected Net"),
        }
    }

    #[test]
    fn parse_include() {
        let ast = parse(r#"(policy "main" (include "cwd-access"))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::Include(name) => assert_eq!(name, "cwd-access"),
            _ => panic!("expected Include"),
        }
    }

    #[test]
    fn parse_or_pattern() {
        let ast = parse(r#"(policy "p" (allow (exec (or "npm" "cargo" "pip") *)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => match &m.bin {
                Pattern::Or(ps) => {
                    assert_eq!(ps.len(), 3);
                    assert_eq!(ps[0], Pattern::Literal("npm".into()));
                }
                other => panic!("expected Or pattern, got {other:?}"),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn parse_sandbox_keyword() {
        let ast = parse(r#"(policy "p" (allow (exec "cargo" *) :sandbox "cargo-env"))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        assert_eq!(rule.effect, Effect::Allow);
        assert_eq!(rule.sandbox, Some(SandboxRef::Named("cargo-env".into())));
    }

    #[test]
    fn parse_error_sandbox_without_value() {
        let err = parse(r#"(policy "p" (allow (exec "cargo" *) :sandbox))"#).unwrap_err();
        assert!(
            err.to_string().contains(":sandbox requires an argument"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_bare_atom_policy_name() {
        let err = parse("(policy main (allow (exec)))").unwrap_err();
        assert!(
            err.to_string().contains("expected quoted string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_bare_atom_default_name() {
        let err = parse("(default deny main)").unwrap_err();
        assert!(
            err.to_string().contains("expected quoted string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_bare_atom_include_name() {
        let err = parse(r#"(policy "main" (include cwd-access))"#).unwrap_err();
        assert!(
            err.to_string().contains("expected quoted string"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_full_example() {
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
  (allow (exec (or "npm" "cargo" "pip") *))

  (allow (fs (or read write) (subpath (env PWD))))
  (deny  (fs write ".env"))

  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        let ast = parse(source).unwrap();
        assert_eq!(ast.len(), 3);
    }

    #[test]
    fn round_trip_parse_display_parse() {
        let source = r#"
(default deny "main")

(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")
  (deny  (exec "git" "push" *))
  (allow (exec "git" *))
  (allow (exec "cargo" *) :sandbox "cargo-env")
  (allow (fs (or read write) (subpath (env PWD))))
  (deny  (fs write ".env"))
  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#;
        let ast1 = parse(source).unwrap();
        // Display each top-level form and re-parse.
        let printed: String = ast1
            .iter()
            .map(|tl| tl.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_has_keyword() {
        let ast = parse(r#"(policy "p" (deny (exec "git" :has "push" "--force")))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert_eq!(m.bin, Pattern::Literal("git".into()));
                assert!(m.args.is_empty());
                assert_eq!(m.has_args.len(), 2);
                assert_eq!(m.has_args[0], Pattern::Literal("push".into()));
                assert_eq!(m.has_args[1], Pattern::Literal("--force".into()));
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_has_with_positional_prefix() {
        let ast = parse(r#"(policy "p" (deny (exec "git" "push" :has "--force" "--no-verify")))"#)
            .unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert_eq!(m.bin, Pattern::Literal("git".into()));
                assert_eq!(m.args.len(), 1);
                assert_eq!(m.args[0], Pattern::Literal("push".into()));
                assert_eq!(m.has_args.len(), 2);
                assert_eq!(m.has_args[0], Pattern::Literal("--force".into()));
                assert_eq!(m.has_args[1], Pattern::Literal("--no-verify".into()));
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_has_with_regex() {
        let ast = parse(r#"(policy "p" (deny (exec "git" :has "push" /--force/)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert!(!m.has_args.is_empty());
                assert_eq!(m.has_args[1], Pattern::Regex("--force".into()));
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_has_with_not() {
        let ast =
            parse(r#"(policy "p" (deny (exec "git" :has "push" (not "--dry-run"))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert!(!m.has_args.is_empty());
                assert_eq!(
                    m.has_args[1],
                    Pattern::Not(Box::new(Pattern::Literal("--dry-run".into())))
                );
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn round_trip_has() {
        let source = r#"(policy "p" (deny (exec "git" :has "push" "--force")))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn round_trip_mixed_positional_has() {
        let source = r#"(policy "p" (deny (exec "git" "push" :has "--force")))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_positional_unchanged() {
        // Ensure regular positional parsing still works and does not produce has_args.
        let ast = parse(r#"(policy "p" (deny (exec "git" "push" *)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Exec(m) => {
                assert!(m.has_args.is_empty());
                assert_eq!(m.args.len(), 2);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn parse_join_path_expr() {
        let ast = parse(r#"(policy "p" (allow (fs read (subpath (join (env HOME) "/.clash")))))"#)
            .unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => match &m.path {
                Some(PathFilter::Subpath(PathExpr::Join(parts), false)) => {
                    assert_eq!(parts.len(), 2);
                    assert_eq!(parts[0], PathExpr::Env("HOME".into()));
                    assert_eq!(parts[1], PathExpr::Static("/.clash".into()));
                }
                other => panic!("expected Subpath(Join(...)), got {other:?}"),
            },
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn round_trip_join() {
        let source = r#"(policy "p" (allow (fs read (subpath (join (env HOME) "/.clash")))))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_nested_join() {
        let ast = parse(
            r#"(policy "p" (allow (fs read (subpath (join (join (env HOME) "/.config") "/clash")))))"#,
        )
        .unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => match &m.path {
                Some(PathFilter::Subpath(PathExpr::Join(parts), false)) => {
                    assert_eq!(parts.len(), 2);
                    assert!(matches!(&parts[0], PathExpr::Join(_)));
                }
                other => panic!("expected Subpath(Join(...)), got {other:?}"),
            },
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn parse_join_needs_two_args() {
        let err =
            parse(r#"(policy "p" (allow (fs read (subpath (join (env HOME))))))"#).unwrap_err();
        assert!(
            err.to_string()
                .contains("(join) expects at least 2 arguments"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_error_unknown_effect() {
        let err = parse(r#"(policy "p" (boom (exec)))"#).unwrap_err();
        assert!(err.to_string().contains("unknown policy item: boom"));
    }

    #[test]
    fn parse_error_unknown_capability() {
        let err = parse(r#"(policy "p" (allow (foobar)))"#).unwrap_err();
        assert!(err.to_string().contains("unknown capability: foobar"));
    }

    #[test]
    fn parse_inline_sandbox_single_rule() {
        let ast =
            parse(r#"(policy "p" (allow (exec "clash" *) :sandbox (allow (net *))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.sandbox {
            Some(SandboxRef::Inline(rules)) => {
                assert_eq!(rules.len(), 1);
                assert_eq!(rules[0].effect, Effect::Allow);
                assert!(matches!(&rules[0].matcher, CapMatcher::Net(_)));
                assert!(rules[0].sandbox.is_none());
            }
            other => panic!("expected Inline sandbox, got {other:?}"),
        }
    }

    #[test]
    fn parse_inline_sandbox_multiple_rules() {
        let ast = parse(
            r#"(policy "p" (allow (exec "cargo" *) :sandbox (allow (net *)) (allow (fs read (subpath "/tmp")))))"#,
        )
        .unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.sandbox {
            Some(SandboxRef::Inline(rules)) => {
                assert_eq!(rules.len(), 2);
                assert!(matches!(&rules[0].matcher, CapMatcher::Net(_)));
                assert!(matches!(&rules[1].matcher, CapMatcher::Fs(_)));
            }
            other => panic!("expected Inline sandbox, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_nested_sandbox_in_inline() {
        let err = parse(
            r#"(policy "p" (allow (exec "x" *) :sandbox (allow (exec "y" *) :sandbox "z")))"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("cannot have :sandbox"),
            "got: {}",
            err
        );
    }

    #[test]
    fn round_trip_inline_sandbox() {
        let source = r#"(policy "p" (allow (exec "clash" *) :sandbox (allow (net *)) (deny (net /.*\.evil\.com/))))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_worktree_flag() {
        let ast =
            parse(r#"(policy "p" (allow (fs write (subpath :worktree (env PWD)))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => match &m.path {
                Some(PathFilter::Subpath(PathExpr::Env(name), worktree)) => {
                    assert_eq!(name, "PWD");
                    assert!(worktree, "expected worktree flag to be true");
                }
                other => panic!("expected Subpath with worktree, got {other:?}"),
            },
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn parse_subpath_without_worktree() {
        let ast = parse(r#"(policy "p" (allow (fs read (subpath (env HOME)))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => match &m.path {
                Some(PathFilter::Subpath(PathExpr::Env(name), worktree)) => {
                    assert_eq!(name, "HOME");
                    assert!(!worktree, "expected worktree flag to be false");
                }
                other => panic!("expected Subpath without worktree, got {other:?}"),
            },
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn round_trip_worktree() {
        let source = r#"(policy "p" (allow (fs write (subpath :worktree (env PWD)))))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    #[test]
    fn parse_net_with_subpath() {
        let ast =
            parse(r#"(policy "p" (allow (net "github.com" (subpath "/owner/repo"))))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Net(m) => {
                assert_eq!(m.domain, Pattern::Literal("github.com".into()));
                match &m.path {
                    Some(PathFilter::Subpath(PathExpr::Static(s), false)) => {
                        assert_eq!(s, "/owner/repo");
                    }
                    other => panic!("expected Subpath, got {other:?}"),
                }
            }
            _ => panic!("expected Net"),
        }
    }

    #[test]
    fn parse_net_with_regex_path() {
        let ast = parse(r#"(policy "p" (deny (net "api.github.com" /\/admin\/.*/)))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Net(m) => {
                assert_eq!(m.domain, Pattern::Literal("api.github.com".into()));
                match &m.path {
                    Some(PathFilter::Regex(r)) => {
                        assert_eq!(r, r"\/admin\/.*");
                    }
                    other => panic!("expected Regex path, got {other:?}"),
                }
            }
            _ => panic!("expected Net"),
        }
    }

    #[test]
    fn parse_net_with_literal_path() {
        let ast = parse(r#"(policy "p" (allow (net "github.com" "/owner/repo/pulls")))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Net(m) => {
                assert_eq!(m.domain, Pattern::Literal("github.com".into()));
                match &m.path {
                    Some(PathFilter::Literal(s)) => {
                        assert_eq!(s, "/owner/repo/pulls");
                    }
                    other => panic!("expected Literal path, got {other:?}"),
                }
            }
            _ => panic!("expected Net"),
        }
    }

    #[test]
    fn parse_net_without_path_unchanged() {
        let ast = parse(r#"(policy "p" (allow (net "github.com")))"#).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Net(m) => {
                assert_eq!(m.domain, Pattern::Literal("github.com".into()));
                assert!(m.path.is_none());
            }
            _ => panic!("expected Net"),
        }
    }

    #[test]
    fn parse_net_too_many_args() {
        let err =
            parse(r#"(policy "p" (allow (net "github.com" (subpath "/a") extra)))"#).unwrap_err();
        assert!(
            err.to_string().contains("at most 2 arguments"),
            "got: {}",
            err
        );
    }

    #[test]
    fn round_trip_net_with_path() {
        let source = r#"(policy "p" (allow (net "github.com" (subpath "/owner/repo"))))"#;
        let ast1 = parse(source).unwrap();
        let printed = ast1[0].to_string();
        let ast2 = parse(&printed).unwrap();
        assert_eq!(ast1, ast2, "round-trip failed:\n{printed}");
    }

    // -----------------------------------------------------------------------
    // v2 parser tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_def() {
        let ast = parse(r#"(version 2)(def tmpdirs ["/tmp" "/var/folders"])"#).unwrap();
        assert_eq!(ast.len(), 2);
        match &ast[1] {
            TopLevel::Def { name, value } => {
                assert_eq!(name, "tmpdirs");
                // Value is stored as raw SExpr bracket list
                let values = try_as_string_list(value).expect("expected bracket list");
                assert_eq!(values, vec!["/tmp", "/var/folders"]);
            }
            other => panic!("expected Def, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_requires_v2() {
        let err = parse(r#"(version 1)(def tmpdirs ["/tmp"])"#).unwrap_err();
        assert!(
            err.to_string().contains("requires (version 2)"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_when_block() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo" *) :allow))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                assert!(matches!(observable, Observable::Command));
                match pattern {
                    ArmPattern::Exec(m) => {
                        assert_eq!(m.bin, Pattern::Literal("cargo".into()));
                        assert_eq!(m.args, vec![Pattern::Any]);
                    }
                    _ => panic!("expected Exec pattern"),
                }
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], PolicyItem::Effect(Effect::Allow)));
            }
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_when_effect_shorthand_all_effects() {
        for (kw, effect) in [
            (":allow", Effect::Allow),
            (":deny", Effect::Deny),
            (":ask", Effect::Ask),
        ] {
            let source = format!(r#"(version 2)(policy "p" (when (command "git" *) {kw}))"#);
            let ast = parse(&source).unwrap();
            let body = match &ast[1] {
                TopLevel::Policy { body, .. } => body,
                _ => panic!(),
            };
            match &body[0] {
                PolicyItem::When { body, .. } => {
                    assert_eq!(body.len(), 1);
                    assert!(
                        matches!(&body[0], PolicyItem::Effect(e) if *e == effect),
                        "expected Effect({effect:?}) for {kw}"
                    );
                }
                other => panic!("expected When, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_v2_rejects_flat_rules() {
        let source = r#"(version 2)(policy "p" (allow (exec "git" *)))"#;
        let err = parse(source).unwrap_err();
        assert!(
            err.to_string()
                .contains("flat rules are not supported in version 2"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_when_requires_v2() {
        let err = parse(r#"(policy "p" (when (command "cargo") (allow (exec))))"#).unwrap_err();
        assert!(
            err.to_string().contains("requires (version 2)"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_when_tool_predicate() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (tool (or "WebSearch" "WebFetch")) :allow))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                assert!(matches!(observable, Observable::Tool));
                match pattern {
                    ArmPattern::Single(pat) => {
                        assert!(matches!(pat, Pattern::Or(ps) if ps.len() == 2));
                    }
                    _ => panic!("expected Single pattern"),
                }
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], PolicyItem::Effect(Effect::Allow)));
            }
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_when_agent_predicate() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (agent "Explore") :allow))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                assert!(matches!(observable, Observable::Agent));
                match pattern {
                    ArmPattern::Single(Pattern::Literal(s)) => assert_eq!(s, "Explore"),
                    _ => panic!("expected Single(Literal) pattern"),
                }
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], PolicyItem::Effect(Effect::Allow)));
            }
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_when_agent_or_predicate() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (agent (or "Explore" "Verify")) :ask))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                assert!(matches!(observable, Observable::Agent));
                match pattern {
                    ArmPattern::Single(pat) => {
                        assert!(matches!(pat, Pattern::Or(ps) if ps.len() == 2));
                    }
                    _ => panic!("expected Single pattern"),
                }
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], PolicyItem::Effect(Effect::Ask)));
            }
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_ctx_agent_name_observable() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (agent *)
                (match ctx.agent.name
                  "Explore" :allow
                  * :deny)))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            other => panic!("expected When, got {other:?}"),
        };
        match &when_body[0] {
            PolicyItem::Match(block) => {
                assert_eq!(block.observable, Observable::AgentName);
                assert_eq!(block.arms.len(), 2);
                assert_eq!(block.arms[0].effect, Effect::Allow);
                assert!(
                    matches!(&block.arms[0].pattern, ArmPattern::Single(Pattern::Literal(s)) if s == "Explore")
                );
            }
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn parse_sandbox_with_match() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match ctx.http.domain
                    "github.com" :allow
                    "crates.io" :allow))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        // when → sandbox → match
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            other => panic!("expected When, got {other:?}"),
        };
        let sandbox_body = match &when_body[0] {
            PolicyItem::Sandbox { body } => body,
            other => panic!("expected Sandbox, got {other:?}"),
        };
        match &sandbox_body[0] {
            SandboxItem::Match(block) => {
                assert_eq!(block.observable, Observable::HttpDomain);
                assert_eq!(block.arms.len(), 2);
                assert_eq!(block.arms[0].effect, Effect::Allow);
                assert!(
                    matches!(&block.arms[0].pattern, ArmPattern::Single(Pattern::Literal(s)) if s == "github.com")
                );
            }
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn parse_match_tuple_observable() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match [fs.action fs.path]
                    ["read" (subpath (env PWD))] :allow
                    [* (subpath "/tmp")] :allow))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        let sandbox_body = match &when_body[0] {
            PolicyItem::Sandbox { body } => body,
            _ => panic!(),
        };
        match &sandbox_body[0] {
            SandboxItem::Match(block) => {
                assert!(matches!(&block.observable, Observable::Tuple(obs) if obs.len() == 2));
                assert_eq!(block.arms.len(), 2);
                // First arm: ["read" (subpath (env PWD))]
                match &block.arms[0].pattern {
                    ArmPattern::Tuple(elems) => {
                        assert_eq!(elems.len(), 2);
                        assert!(
                            matches!(&elems[0], ArmPatternElement::Pat(Pattern::Literal(s)) if s == "read")
                        );
                        assert!(
                            matches!(&elems[1], ArmPatternElement::Path(PathFilter::Subpath(PathExpr::Env(name), false)) if name == "PWD")
                        );
                    }
                    other => panic!("expected Tuple, got {other:?}"),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_dollar_var_shorthand() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match [fs.action fs.path]
                    ["read" (subpath $PWD)] :allow))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        let sandbox_body = match &when_body[0] {
            PolicyItem::Sandbox { body } => body,
            _ => panic!(),
        };
        match &sandbox_body[0] {
            SandboxItem::Match(block) => {
                match &block.arms[0].pattern {
                    ArmPattern::Tuple(elems) => {
                        // $PWD should parse as PathExpr::Env("PWD")
                        assert!(
                            matches!(&elems[1], ArmPatternElement::Path(PathFilter::Subpath(PathExpr::Env(name), false)) if name == "PWD")
                        );
                    }
                    other => panic!("expected Tuple, got {other:?}"),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_joinpath_alias() {
        let source = r#"
            (policy "p"
              (allow (fs read (subpath (joinpath (env PWD) "targets")))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[0] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let rule = match &body[0] {
            PolicyItem::Rule(r) => r,
            _ => panic!(),
        };
        match &rule.matcher {
            CapMatcher::Fs(m) => match &m.path {
                Some(PathFilter::Subpath(PathExpr::Join(parts), false)) => {
                    assert_eq!(parts.len(), 2);
                    assert_eq!(parts[0], PathExpr::Env("PWD".into()));
                    assert_eq!(parts[1], PathExpr::Static("targets".into()));
                }
                other => panic!("expected Subpath(Join(...)), got {other:?}"),
            },
            _ => panic!("expected Fs"),
        }
    }

    #[test]
    fn parse_def_expansion_in_pattern() {
        let source = r#"
            (version 2)
            (def builders ["cargo" "rustc"])
            (policy "p"
              (when (command builders *) :allow))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                assert!(matches!(observable, Observable::Command));
                match pattern {
                    ArmPattern::Exec(m) => {
                        // def "builders" should expand to Or(["cargo", "rustc"])
                        match &m.bin {
                            Pattern::Or(ps) => {
                                assert_eq!(ps.len(), 2);
                                assert_eq!(ps[0], Pattern::Literal("cargo".into()));
                                assert_eq!(ps[1], Pattern::Literal("rustc".into()));
                            }
                            other => panic!("expected Or pattern from def, got {other:?}"),
                        }
                    }
                    _ => panic!("expected Exec pattern"),
                }
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], PolicyItem::Effect(Effect::Allow)));
            }
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_expansion_in_path_filter() {
        let source = r#"
            (version 2)
            (def tmpdirs ["/tmp" "/var/folders"])
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match [fs.action fs.path]
                    [* (subpath tmpdirs)] :allow))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        let sandbox_body = match &when_body[0] {
            PolicyItem::Sandbox { body } => body,
            _ => panic!(),
        };
        match &sandbox_body[0] {
            SandboxItem::Match(block) => {
                match &block.arms[0].pattern {
                    ArmPattern::Tuple(elems) => {
                        // tmpdirs in subpath position should expand
                        match &elems[1] {
                            ArmPatternElement::Path(PathFilter::Subpath(
                                PathExpr::Static(s),
                                false,
                            )) => {
                                // The def name is passed through as static since
                                // expansion happens at try_parse_arm_path_filter level
                                // Actually, `(subpath tmpdirs)` parses the inner as
                                // parse_path_expr which sees atom "tmpdirs" → Static("tmpdirs")
                                // Def expansion for path filters happens when bare atom
                                // appears directly as the arm pattern element
                                assert_eq!(s, "tmpdirs");
                            }
                            other => panic!("got {other:?}"),
                        }
                    }
                    other => panic!("expected Tuple, got {other:?}"),
                }
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ask_in_sandbox_match_rejected() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match ctx.http.domain
                    "github.com" :ask))))
        "#;
        let err = parse(source).unwrap_err();
        assert!(
            err.to_string().contains(":ask is not allowed"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_match_wildcard_arm() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match ctx.http.domain
                    "github.com" :allow
                    * :deny))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        let sandbox_body = match &when_body[0] {
            PolicyItem::Sandbox { body } => body,
            _ => panic!(),
        };
        match &sandbox_body[0] {
            SandboxItem::Match(block) => {
                assert_eq!(block.arms.len(), 2);
                assert!(matches!(
                    &block.arms[1].pattern,
                    ArmPattern::Single(Pattern::Any)
                ));
                assert_eq!(block.arms[1].effect, Effect::Deny);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_match_not_pattern() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match ctx.http.method
                    (not "GET") :deny))))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[1] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        let sandbox_body = match &when_body[0] {
            PolicyItem::Sandbox { body } => body,
            _ => panic!(),
        };
        match &sandbox_body[0] {
            SandboxItem::Match(block) => {
                assert_eq!(block.observable, Observable::HttpMethod);
                assert!(matches!(&block.arms[0].pattern,
                    ArmPattern::Single(Pattern::Not(inner)) if matches!(&**inner, Pattern::Literal(s) if s == "GET")));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_sandbox_requires_v2() {
        let err = parse(r#"(policy "p" (sandbox (allow (net *))))"#).unwrap_err();
        assert!(
            err.to_string().contains("requires (version 2)"),
            "got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // def with arbitrary expressions (gh-220)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_def_with_match_block() {
        let source = r#"
            (version 2)
            (def github-net
              (match proxy.domain
                "github.com" :allow))
        "#;
        let ast = parse(source).unwrap();
        match &ast[1] {
            TopLevel::Def { name, value } => {
                assert_eq!(name, "github-net");
                // Value should be a raw SExpr list (match ...)
                assert!(value.as_list().is_some(), "expected list, got {value:?}");
            }
            other => panic!("expected Def, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_compound_spliced_in_when_body() {
        let source = r#"
            (version 2)
            (def github-net
              (match proxy.domain
                "github.com" :allow))
            (policy "p"
              (when (command "cargo" *)
                github-net))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        // The def reference should have been spliced as a Match block
        match &when_body[0] {
            PolicyItem::Match(block) => {
                assert!(matches!(block.observable, Observable::HttpDomain));
                assert_eq!(block.arms.len(), 1);
                assert_eq!(
                    block.arms[0].pattern,
                    ArmPattern::Single(Pattern::Literal("github.com".into()))
                );
                assert_eq!(block.arms[0].effect, Effect::Allow);
            }
            other => panic!("expected Match from def splice, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_compound_spliced_in_policy_body() {
        let source = r#"
            (version 2)
            (def my-when
              (when (command "git" *) :allow))
            (policy "p"
              my-when)
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                assert!(matches!(observable, Observable::Command));
                match pattern {
                    ArmPattern::Exec(m) => {
                        assert_eq!(m.bin, Pattern::Literal("git".into()));
                    }
                    _ => panic!("expected Exec pattern"),
                }
                assert_eq!(body.len(), 1);
                assert!(matches!(&body[0], PolicyItem::Effect(Effect::Allow)));
            }
            other => panic!("expected When from def splice, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_or_pattern_spliced() {
        let source = r#"
            (version 2)
            (def github-domains (or "github.com" "api.github.com"))
            (policy "p"
              (when (command "curl" *)
                (match proxy.domain
                  github-domains :allow)))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        let when_body = match &body[0] {
            PolicyItem::When { body, .. } => body,
            _ => panic!(),
        };
        match &when_body[0] {
            PolicyItem::Match(block) => {
                // The (or ...) pattern from def should be spliced as Pattern::Or
                match &block.arms[0].pattern {
                    ArmPattern::Single(Pattern::Or(ps)) => {
                        assert_eq!(ps.len(), 2);
                        assert_eq!(ps[0], Pattern::Literal("github.com".into()));
                        assert_eq!(ps[1], Pattern::Literal("api.github.com".into()));
                    }
                    other => panic!("expected Or pattern, got {other:?}"),
                }
            }
            other => panic!("expected Match, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_bracket_list_backwards_compat() {
        // Existing bracket list syntax must continue to work identically
        let source = r#"
            (version 2)
            (def builders ["cargo" "rustc"])
            (policy "p"
              (when (command builders *) :allow))
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!(),
        };
        match &body[0] {
            PolicyItem::When { pattern, .. } => match pattern {
                ArmPattern::Exec(m) => match &m.bin {
                    Pattern::Or(ps) => {
                        assert_eq!(ps.len(), 2);
                        assert_eq!(ps[0], Pattern::Literal("cargo".into()));
                        assert_eq!(ps[1], Pattern::Literal("rustc".into()));
                    }
                    other => panic!("expected Or pattern, got {other:?}"),
                },
                _ => panic!("expected Exec pattern"),
            },
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_def_display_roundtrip_bracket_list() {
        let source = r#"(version 2)(def tmpdirs ["/tmp" "/var/folders"])"#;
        let ast = parse(source).unwrap();
        let displayed = ast[1].to_string();
        assert_eq!(displayed, r#"(def tmpdirs ["/tmp" "/var/folders"])"#);
    }

    #[test]
    fn parse_def_display_roundtrip_compound() {
        let source = r#"(version 2)(def my-net (match proxy.domain "github.com" :allow))"#;
        let ast = parse(source).unwrap();
        let displayed = ast[1].to_string();
        assert_eq!(
            displayed,
            r#"(def my-net (match proxy.domain "github.com" :allow))"#
        );
    }

    // -----------------------------------------------------------------------
    // Forward reference validation (validation rule 9)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_def_forward_reference_rejected() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command builders *) :allow))
            (def builders ["cargo" "rustc"])
        "#;
        let err = parse(source).unwrap_err();
        assert!(
            err.to_string()
                .contains("name 'builders' referenced before declaration"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_def_forward_reference_in_path_filter_rejected() {
        let source = r#"
            (version 2)
            (policy "p"
              (when (command "cargo")
                (sandbox
                  (match [fs.action fs.path]
                    [* (subpath tmpdirs)] :allow))))
            (def tmpdirs ["/tmp" "/var/folders"])
        "#;
        let err = parse(source).unwrap_err();
        assert!(
            err.to_string()
                .contains("name 'tmpdirs' referenced before declaration"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_include_forward_reference_rejected() {
        let source = r#"
            (version 2)
            (use "main")
            (policy "main"
              (include "helpers"))
            (policy "helpers"
              (when (command "git" *) :allow))
        "#;
        let err = parse(source).unwrap_err();
        assert!(
            err.to_string()
                .contains("name 'helpers' referenced before declaration"),
            "got: {}",
            err
        );
    }

    #[test]
    fn parse_valid_declaration_order_succeeds() {
        let source = r#"
            (version 2)
            (use "main")
            (def builders ["cargo" "rustc"])
            (policy "helpers"
              (when (command builders *) :allow))
            (policy "main"
              (include "helpers"))
        "#;
        let ast = parse(source).unwrap();
        assert_eq!(ast.len(), 5);
    }

    #[test]
    fn parse_v1_include_forward_reference_allowed() {
        // v1 policies do not enforce forward reference prohibition.
        let source = r#"
            (default deny "main")
            (policy "main"
              (include "helpers")
              (allow (exec "git" *)))
            (policy "helpers"
              (allow (fs read (subpath (env PWD)))))
        "#;
        let ast = parse(source).unwrap();
        assert_eq!(ast.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Nullable accessor tests (ctx.tool.args.<field>?)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_nullable_accessor_in_match() {
        let source = r#"
            (version 2)
            (use "main")
            (policy "main"
              (match ctx.tool.args.file_path?
                (subpath "/home") :allow
                * :deny)
              :deny)
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!("expected Policy"),
        };
        let block = match &body[0] {
            PolicyItem::Match(b) => b,
            other => panic!("expected Match, got {other:?}"),
        };
        assert_eq!(
            block.observable,
            Observable::ToolArgField("file_path".into())
        );
        assert_eq!(block.arms.len(), 2);
    }

    #[test]
    fn parse_nullable_accessor_in_when_guard() {
        let source = r#"
            (version 2)
            (use "main")
            (policy "main"
              (when (ctx.tool.args.file_path? (subpath "/home")) :allow)
              :deny)
        "#;
        let ast = parse(source).unwrap();
        let body = match &ast[2] {
            TopLevel::Policy { body, .. } => body,
            _ => panic!("expected Policy"),
        };
        match &body[0] {
            PolicyItem::When {
                observable,
                pattern,
                ..
            } => {
                assert_eq!(*observable, Observable::ToolArgField("file_path".into()));
                assert!(matches!(pattern, ArmPattern::SinglePath(_)));
            }
            other => panic!("expected When, got {other:?}"),
        }
    }

    #[test]
    fn parse_error_bare_dynamic_field_without_question_mark() {
        let source = r#"
            (version 2)
            (use "main")
            (policy "main"
              (match ctx.tool.args.file_path
                * :deny)
              :deny)
        "#;
        let err = parse(source).unwrap_err();
        assert!(
            err.to_string().contains("add ? suffix"),
            "expected actionable error about ? suffix, got: {}",
            err
        );
    }

    #[test]
    fn parse_nullable_accessor_display_roundtrip() {
        let obs = Observable::ToolArgField("file_path".into());
        assert_eq!(obs.to_string(), "ctx.tool.args.file_path?");
    }
}
