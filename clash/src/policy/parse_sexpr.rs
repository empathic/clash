//! Semantic parser: s-expression tree → `PolicyDocument`.
//!
//! Converts the generic s-expression tree from `sexpr.rs` into the typed
//! AST used by the rest of the policy system (`ast.rs`).

use std::collections::HashMap;

use super::ast::{
    ArgSpec, DefaultConfig, FilterExpr, InlineConstraints, PolicyConfig, ProfileDef, ProfileRule,
    SandboxConfig, UrlSpec,
};
use super::error::{PolicyParseError, suggest_closest};
use super::sexpr::{self, SExpr};
use super::{Effect, Pattern};
use crate::policy::sandbox_types::{Cap, NetworkPolicy};

/// Marker for fs-level rules in the profile before expansion.
/// These are stored as ProfileRule entries with a special verb prefix
/// that `compile.rs` will recognize and expand.
pub(crate) const FS_RULE_VERB: &str = "__fs__";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse an s-expression policy string into a `PolicyDocument`.
pub fn parse_policy(input: &str) -> Result<super::PolicyDocument, PolicyParseError> {
    let exprs = sexpr::parse(input).map_err(|e| PolicyParseError::InvalidRule {
        rule: format!("{}:{}", e.line, e.col),
        message: e.message,
    })?;

    let mut default_config: Option<DefaultConfig> = None;
    let mut profile_defs: HashMap<String, ProfileDef> = HashMap::new();

    for expr in &exprs {
        let list = expr.as_list().ok_or_else(|| {
            sexpr_error(
                expr,
                "expected a top-level form like (default ...) or (profile ...)",
            )
        })?;
        if list.is_empty() {
            return Err(sexpr_error(expr, "empty list at top level"));
        }

        let head = list[0]
            .as_str()
            .ok_or_else(|| sexpr_error(&list[0], "expected form name (default, profile)"))?;

        match head {
            "default" => {
                default_config = Some(parse_default(list)?);
            }
            "profile" => {
                let (name, def) = parse_profile(list)?;
                profile_defs.insert(name, def);
            }
            other => {
                return Err(sexpr_error(
                    &list[0],
                    &format!(
                        "unknown top-level form '{}'; expected 'default' or 'profile'",
                        other
                    ),
                ));
            }
        }
    }

    let dc = default_config.ok_or_else(|| PolicyParseError::InvalidRule {
        rule: "(default ...)".into(),
        message: "missing (default (permission <effect>) (profile <name>)) form".into(),
    })?;

    // Validate active profile exists.
    if !profile_defs.contains_key(&dc.profile) {
        let candidates: Vec<&str> = profile_defs.keys().map(|s| s.as_str()).collect();
        return Err(PolicyParseError::UnknownInclude {
            name: dc.profile.clone(),
            suggestion: suggest_closest(&dc.profile, &candidates),
        });
    }

    // Validate all includes.
    for def in profile_defs.values() {
        if let Some(ref includes) = def.include {
            for include in includes {
                if !profile_defs.contains_key(include) {
                    let candidates: Vec<&str> = profile_defs.keys().map(|s| s.as_str()).collect();
                    return Err(PolicyParseError::UnknownInclude {
                        name: include.clone(),
                        suggestion: suggest_closest(include, &candidates),
                    });
                }
            }
        }
    }

    // Detect circular includes.
    for name in profile_defs.keys() {
        let mut visited = std::collections::HashSet::new();
        let mut path = Vec::new();
        detect_circular_include(name, &profile_defs, &mut visited, &mut path)?;
    }

    Ok(super::PolicyDocument {
        policy: PolicyConfig {
            default: dc.permission,
        },
        permissions: None,
        constraints: Default::default(),
        profiles: Default::default(),
        statements: Vec::new(),
        default_config: Some(dc),
        profile_defs,
    })
}

/// Parse a standalone list of s-expr rules into a `ProfileDef`.
///
/// Used for builtin profiles (e.g. `__clash_internal__`, `__claude_internal__`)
/// where the input is bare rules without a `(profile ...)` wrapper.
///
/// ```scheme
/// (allow read *
///   (fs (read (subpath "~/.clash"))))
/// (allow bash "*clash policy show*")
/// ```
pub fn parse_profile_rules(input: &str) -> Result<ProfileDef, PolicyParseError> {
    let exprs = sexpr::parse(input).map_err(|e| PolicyParseError::InvalidRule {
        rule: format!("{}:{}", e.line, e.col),
        message: e.message,
    })?;

    let mut rules = Vec::new();
    for expr in &exprs {
        let list = expr
            .as_list()
            .ok_or_else(|| sexpr_error(expr, "expected a rule form like (allow ...)"))?;
        if list.is_empty() {
            return Err(sexpr_error(expr, "empty rule form"));
        }
        let head = list[0]
            .as_str()
            .ok_or_else(|| sexpr_error(&list[0], "expected effect (allow, deny, ask)"))?;
        match head {
            "allow" | "deny" | "ask" => {
                let effect = parse_effect(&list[0])?;
                rules.extend(parse_rule_body(effect, &list[1..])?);
            }
            other => {
                return Err(sexpr_error(
                    &list[0],
                    &format!("expected effect (allow, deny, ask), got '{}'", other),
                ));
            }
        }
    }

    Ok(ProfileDef {
        include: None,
        sandbox: None,
        rules,
    })
}

// ---------------------------------------------------------------------------
// (default (permission <effect>) (profile <name>))
// ---------------------------------------------------------------------------

fn parse_default(list: &[SExpr]) -> Result<DefaultConfig, PolicyParseError> {
    // Expect: (default (permission <effect>) (profile <name>))
    // The sub-forms can appear in any order.
    if list.len() != 3 {
        return Err(sexpr_error(
            &list[0],
            "expected (default (permission <effect>) (profile <name>))",
        ));
    }

    let mut permission: Option<Effect> = None;
    let mut profile: Option<String> = None;

    for item in &list[1..] {
        let sub = item.as_list().ok_or_else(|| {
            sexpr_error(
                item,
                "expected (permission <effect>) or (profile <name>) inside default",
            )
        })?;
        if sub.len() != 2 {
            return Err(sexpr_error(
                item,
                "expected (permission <effect>) or (profile <name>)",
            ));
        }
        let head = sub[0]
            .as_str()
            .ok_or_else(|| sexpr_error(&sub[0], "expected 'permission' or 'profile'"))?;
        match head {
            "permission" => {
                permission = Some(parse_effect(&sub[1])?);
            }
            "profile" => {
                profile = Some(atom_str(&sub[1], "profile name")?);
            }
            other => {
                return Err(sexpr_error(
                    &sub[0],
                    &format!(
                        "unknown field '{}' in default; expected 'permission' or 'profile'",
                        other
                    ),
                ));
            }
        }
    }

    let permission = permission
        .ok_or_else(|| sexpr_error(&list[0], "missing (permission <effect>) in default form"))?;
    let profile =
        profile.ok_or_else(|| sexpr_error(&list[0], "missing (profile <name>) in default form"))?;

    Ok(DefaultConfig {
        permission,
        profile,
    })
}

// ---------------------------------------------------------------------------
// (profile <name> <body...>)
// ---------------------------------------------------------------------------

fn parse_profile(list: &[SExpr]) -> Result<(String, ProfileDef), PolicyParseError> {
    if list.len() < 2 {
        return Err(sexpr_error(&list[0], "expected (profile <name> ...)"));
    }
    let name = atom_str(&list[1], "profile name")?;

    let mut includes: Vec<String> = Vec::new();
    let mut sandbox: Option<SandboxConfig> = None;
    let mut rules: Vec<ProfileRule> = Vec::new();

    for item in &list[2..] {
        let sub = item
            .as_list()
            .ok_or_else(|| sexpr_error(item, "expected a form inside profile"))?;
        if sub.is_empty() {
            return Err(sexpr_error(item, "empty form inside profile"));
        }

        let head = sub[0]
            .as_str()
            .ok_or_else(|| sexpr_error(&sub[0], "expected form name"))?;

        match head {
            "include" => {
                for inc in &sub[1..] {
                    includes.push(any_str(inc, "include name")?);
                }
            }
            "sandbox" => {
                sandbox = Some(parse_sandbox_block(&sub[1..])?);
            }
            "allow" | "deny" | "ask" => {
                let effect = parse_effect(&sub[0])?;
                rules.extend(parse_rule_body(effect, &sub[1..])?);
            }
            other => {
                return Err(sexpr_error(
                    &sub[0],
                    &format!(
                        "unknown form '{}' inside profile; expected include, sandbox, allow, deny, or ask",
                        other
                    ),
                ));
            }
        }
    }

    Ok((
        name,
        ProfileDef {
            include: if includes.is_empty() {
                None
            } else {
                Some(includes)
            },
            sandbox,
            rules,
        },
    ))
}

// ---------------------------------------------------------------------------
// Rule body: the part after allow/deny/ask
// ---------------------------------------------------------------------------

/// Parse the body after an effect keyword.
///
/// Forms:
/// - `(allow bash *)` → tool rule
/// - `(allow bash "git *" (args (forbid "--force")))` → tool rule with constraints
/// - `(allow (fs read write) (subpath .))` → fs rule (stored for expansion)
/// - `(allow (network (domain "github.com")))` → network rule
fn parse_rule_body(effect: Effect, body: &[SExpr]) -> Result<Vec<ProfileRule>, PolicyParseError> {
    if body.is_empty() {
        return Err(PolicyParseError::InvalidRule {
            rule: format!("{}", effect),
            message: "rule body is empty".into(),
        });
    }

    // Check if first arg is a list — could be (fs ...) or (network ...)
    if let Some(inner) = body[0].as_list()
        && !inner.is_empty()
        && let Some(head) = inner[0].as_str()
    {
        match head {
            "fs" => return parse_fs_rule(effect, inner, &body[1..]),
            "network" => return parse_network_rule(effect, inner),
            _ => {}
        }
    }

    // Tool rule: verb noun [constraints...]
    parse_tool_rule(effect, body)
}

/// Parse a tool rule: `bash *` or `bash "git *" (args (forbid "--force"))`.
fn parse_tool_rule(effect: Effect, body: &[SExpr]) -> Result<Vec<ProfileRule>, PolicyParseError> {
    if body.is_empty() {
        return Err(PolicyParseError::InvalidRule {
            rule: format!("{}", effect),
            message: "expected verb and noun".into(),
        });
    }

    let verb = any_str(&body[0], "verb (tool name)")?;
    let noun = if body.len() > 1 {
        let noun_str = any_str(&body[1], "noun pattern")?;
        super::parse::parse_pattern(&noun_str)
    } else {
        Pattern::Match(super::ast::MatchExpr::Any)
    };

    // Parse optional constraint forms after verb and noun.
    let constraints = if body.len() > 2 {
        Some(parse_constraint_forms(&body[2..])?)
    } else {
        None
    };

    Ok(vec![ProfileRule {
        effect,
        verb,
        noun,
        constraints,
    }])
}

/// Parse `(fs read write)` rule + filter expressions.
///
/// `(allow (fs read write) (subpath .))` →
/// Store as a special fs-rule ProfileRule that compile.rs will expand.
fn parse_fs_rule(
    effect: Effect,
    fs_inner: &[SExpr],
    filters: &[SExpr],
) -> Result<Vec<ProfileRule>, PolicyParseError> {
    // Parse capabilities from (fs read write ...)
    let cap_strs: Vec<String> = fs_inner[1..]
        .iter()
        .map(|e| any_str(e, "capability"))
        .collect::<Result<Vec<_>, _>>()?;
    let cap_str = cap_strs.join(" + ");
    let caps = Cap::parse(&cap_str)
        .map_err(|e| PolicyParseError::InvalidCapScopedFs(cap_str.clone(), e))?;

    // Parse filter expressions.
    if filters.is_empty() {
        return Err(PolicyParseError::InvalidFilter(
            "fs rule requires a filter expression like (subpath .)".into(),
        ));
    }

    let filter = parse_filter_sexpr(&filters[0])?;

    // Store as a ProfileRule with special verb prefix for later expansion.
    // The caps and filter are encoded in InlineConstraints.fs.
    Ok(vec![ProfileRule {
        effect,
        verb: FS_RULE_VERB.to_string(),
        noun: Pattern::Match(super::ast::MatchExpr::Any),
        constraints: Some(InlineConstraints {
            fs: Some(vec![(caps, filter)]),
            ..Default::default()
        }),
    }])
}

/// Parse a filter expression from an s-expr node.
///
/// Forms:
/// - `(subpath .)` → FilterExpr::Subpath
/// - `(literal .env)` → FilterExpr::Literal
/// - `(regex ".*\\.rs$")` → FilterExpr::Regex
/// - Atom `.` or `"~/.clash"` → treated as Subpath shorthand
fn parse_filter_sexpr(expr: &SExpr) -> Result<FilterExpr, PolicyParseError> {
    match expr {
        SExpr::Atom(s, _) | SExpr::Str(s, _) => {
            // Bare path treated as subpath shorthand.
            Ok(FilterExpr::Subpath(s.clone()))
        }
        SExpr::List(children, _) => {
            if children.is_empty() {
                return Err(sexpr_error(expr, "empty filter expression"));
            }
            let head = children[0]
                .as_str()
                .ok_or_else(|| sexpr_error(&children[0], "expected filter type"))?;
            match head {
                "subpath" => {
                    if children.len() != 2 {
                        return Err(sexpr_error(expr, "expected (subpath <path>)"));
                    }
                    let path = any_str(&children[1], "path")?;
                    Ok(FilterExpr::Subpath(path))
                }
                "literal" => {
                    if children.len() != 2 {
                        return Err(sexpr_error(expr, "expected (literal <path>)"));
                    }
                    let path = any_str(&children[1], "path")?;
                    Ok(FilterExpr::Literal(path))
                }
                "regex" => {
                    if children.len() != 2 {
                        return Err(sexpr_error(expr, "expected (regex <pattern>)"));
                    }
                    let pattern = any_str(&children[1], "regex pattern")?;
                    Ok(FilterExpr::Regex(pattern))
                }
                "and" => {
                    if children.len() != 3 {
                        return Err(sexpr_error(expr, "expected (and <filter> <filter>)"));
                    }
                    let a = parse_filter_sexpr(&children[1])?;
                    let b = parse_filter_sexpr(&children[2])?;
                    Ok(FilterExpr::And(Box::new(a), Box::new(b)))
                }
                "or" => {
                    if children.len() != 3 {
                        return Err(sexpr_error(expr, "expected (or <filter> <filter>)"));
                    }
                    let a = parse_filter_sexpr(&children[1])?;
                    let b = parse_filter_sexpr(&children[2])?;
                    Ok(FilterExpr::Or(Box::new(a), Box::new(b)))
                }
                "not" => {
                    if children.len() != 2 {
                        return Err(sexpr_error(expr, "expected (not <filter>)"));
                    }
                    let inner = parse_filter_sexpr(&children[1])?;
                    Ok(FilterExpr::Not(Box::new(inner)))
                }
                other => Err(sexpr_error(
                    &children[0],
                    &format!(
                        "unknown filter type '{}'; expected subpath, literal, regex, and, or, not",
                        other
                    ),
                )),
            }
        }
    }
}

/// Parse a `(network ...)` rule.
fn parse_network_rule(
    effect: Effect,
    inner: &[SExpr],
) -> Result<Vec<ProfileRule>, PolicyParseError> {
    // For now, (allow (network (domain "github.com"))) is stored as a
    // constraint on a wildcard rule. We can refine this later.
    let mut urls = Vec::new();
    for item in &inner[1..] {
        if let Some(sub) = item.as_list()
            && !sub.is_empty()
            && sub[0].is_atom("domain")
        {
            for d in &sub[1..] {
                let domain = any_str(d, "domain")?;
                match effect {
                    Effect::Deny => urls.push(UrlSpec::Forbid(domain)),
                    _ => urls.push(UrlSpec::Require(domain)),
                }
            }
        }
    }

    Ok(vec![ProfileRule {
        effect,
        verb: "*".to_string(),
        noun: Pattern::Match(super::ast::MatchExpr::Any),
        constraints: Some(InlineConstraints {
            url: if urls.is_empty() { None } else { Some(urls) },
            ..Default::default()
        }),
    }])
}

// ---------------------------------------------------------------------------
// Sandbox block
// ---------------------------------------------------------------------------

/// Parse the sandbox block body.
///
/// ```scheme
/// (sandbox
///   (fs full (subpath .))
///   (fs read (subpath "~/.cargo"))
///   (network deny))
/// ```
fn parse_sandbox_block(items: &[SExpr]) -> Result<SandboxConfig, PolicyParseError> {
    let mut fs_entries: Vec<(Cap, FilterExpr)> = Vec::new();
    let mut network: Option<NetworkPolicy> = None;

    for item in items {
        let sub = item.as_list().ok_or_else(|| {
            sexpr_error(item, "expected (fs ...) or (network ...) inside sandbox")
        })?;
        if sub.is_empty() {
            return Err(sexpr_error(item, "empty form inside sandbox"));
        }
        let head = sub[0]
            .as_str()
            .ok_or_else(|| sexpr_error(&sub[0], "expected fs or network"))?;

        match head {
            "fs" => {
                // (fs <caps...> <filter>)
                // Everything between "fs" and the last element is caps,
                // and the last element is the filter.
                if sub.len() < 3 {
                    return Err(sexpr_error(item, "expected (fs <caps...> <filter>)"));
                }
                let cap_parts: Vec<String> = sub[1..sub.len() - 1]
                    .iter()
                    .map(|e| any_str(e, "capability"))
                    .collect::<Result<Vec<_>, _>>()?;
                let cap_str = cap_parts.join(" + ");
                let caps = Cap::parse(&cap_str)
                    .map_err(|e| PolicyParseError::InvalidCapScopedFs(cap_str, e))?;
                let filter = parse_filter_sexpr(sub.last().unwrap())?;
                fs_entries.push((caps, filter));
            }
            "network" => {
                if sub.len() != 2 {
                    return Err(sexpr_error(
                        item,
                        "expected (network allow) or (network deny)",
                    ));
                }
                let policy_str = any_str(&sub[1], "network policy")?;
                network = Some(match policy_str.as_str() {
                    "allow" => NetworkPolicy::Allow,
                    "deny" => NetworkPolicy::Deny,
                    _ => {
                        return Err(sexpr_error(
                            &sub[1],
                            &format!(
                                "unknown network policy '{}'; expected allow or deny",
                                policy_str
                            ),
                        ));
                    }
                });
            }
            other => {
                return Err(sexpr_error(
                    &sub[0],
                    &format!("unknown sandbox entry '{}'; expected fs or network", other),
                ));
            }
        }
    }

    Ok(SandboxConfig {
        fs: if fs_entries.is_empty() {
            None
        } else {
            Some(fs_entries)
        },
        network,
    })
}

// ---------------------------------------------------------------------------
// Inline constraints
// ---------------------------------------------------------------------------

/// Parse constraint forms that follow a tool rule's verb and noun.
///
/// ```scheme
/// (allow bash "cargo *"
///   (args (forbid "--force"))
///   (url "github.com")
///   (fs (read (subpath .))))
/// ```
fn parse_constraint_forms(forms: &[SExpr]) -> Result<InlineConstraints, PolicyParseError> {
    let mut constraints = InlineConstraints::default();

    for form in forms {
        let sub = form.as_list().ok_or_else(|| {
            sexpr_error(
                form,
                "expected a constraint form like (args ...) or (url ...)",
            )
        })?;
        if sub.is_empty() {
            return Err(sexpr_error(form, "empty constraint form"));
        }
        let head = sub[0]
            .as_str()
            .ok_or_else(|| sexpr_error(&sub[0], "expected constraint type"))?;

        match head {
            "args" => {
                let mut args = Vec::new();
                for item in &sub[1..] {
                    if let Some(inner) = item.as_list() {
                        if inner.len() == 2 {
                            let kind = inner[0].as_str().unwrap_or("");
                            let val = any_str(&inner[1], "arg value")?;
                            match kind {
                                "not" | "forbid" => args.push(ArgSpec::Forbid(val)),
                                "require" => args.push(ArgSpec::Require(val)),
                                _ => {
                                    return Err(sexpr_error(
                                        &inner[0],
                                        "expected (not ...) or (require ...)",
                                    ));
                                }
                            }
                        }
                    } else {
                        // Bare string → Require
                        let s = any_str(item, "arg")?;
                        args.push(ArgSpec::Require(s));
                    }
                }
                constraints.args = Some(args);
            }
            "url" => {
                let mut urls = Vec::new();
                for item in &sub[1..] {
                    if let Some(inner_list) = item.as_list() {
                        if inner_list.len() == 2 {
                            let kind = inner_list[0].as_str().unwrap_or("");
                            let val = any_str(&inner_list[1], "url value")?;
                            match kind {
                                "not" | "forbid" => urls.push(UrlSpec::Forbid(val)),
                                _ => {
                                    return Err(sexpr_error(
                                        &inner_list[0],
                                        "expected (not ...) in url constraint",
                                    ));
                                }
                            }
                        }
                    } else {
                        // Bare string → Require
                        let s = any_str(item, "url")?;
                        urls.push(UrlSpec::Require(s));
                    }
                }
                constraints.url = Some(urls);
            }
            "fs" => {
                let mut fs_entries = Vec::new();
                for item in &sub[1..] {
                    let inner = item.as_list().ok_or_else(|| {
                        sexpr_error(item, "expected (caps (filter)) inside fs constraint")
                    })?;
                    if inner.len() < 2 {
                        return Err(sexpr_error(item, "expected (caps filter) in fs constraint"));
                    }
                    // Similar to sandbox fs: caps then filter
                    let cap_parts: Vec<String> = inner[..inner.len() - 1]
                        .iter()
                        .map(|e| any_str(e, "capability"))
                        .collect::<Result<Vec<_>, _>>()?;
                    let cap_str = cap_parts.join(" + ");
                    let caps = Cap::parse(&cap_str)
                        .map_err(|e| PolicyParseError::InvalidCapScopedFs(cap_str, e))?;
                    let filter = parse_filter_sexpr(inner.last().unwrap())?;
                    fs_entries.push((caps, filter));
                }
                constraints.fs = Some(fs_entries);
            }
            "network" => {
                if sub.len() != 2 {
                    return Err(sexpr_error(
                        form,
                        "expected (network allow) or (network deny)",
                    ));
                }
                let policy_str = any_str(&sub[1], "network policy")?;
                constraints.network = Some(match policy_str.as_str() {
                    "allow" => NetworkPolicy::Allow,
                    "deny" => NetworkPolicy::Deny,
                    _ => {
                        return Err(sexpr_error(
                            &sub[1],
                            &format!("unknown network policy '{}'", policy_str),
                        ));
                    }
                });
            }
            "pipe" => {
                if sub.len() != 2 {
                    return Err(sexpr_error(form, "expected (pipe true) or (pipe false)"));
                }
                let val = any_str(&sub[1], "boolean")?;
                constraints.pipe = Some(val == "true");
            }
            "redirect" => {
                if sub.len() != 2 {
                    return Err(sexpr_error(
                        form,
                        "expected (redirect true) or (redirect false)",
                    ));
                }
                let val = any_str(&sub[1], "boolean")?;
                constraints.redirect = Some(val == "true");
            }
            other => {
                return Err(sexpr_error(
                    &sub[0],
                    &format!(
                        "unknown constraint '{}'; expected args, url, fs, network, pipe, or redirect",
                        other
                    ),
                ));
            }
        }
    }

    Ok(constraints)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_effect(expr: &SExpr) -> Result<Effect, PolicyParseError> {
    let s = expr
        .as_str()
        .ok_or_else(|| sexpr_error(expr, "expected effect (allow, deny, ask)"))?;
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        other => Err(PolicyParseError::InvalidEffect(other.to_string())),
    }
}

/// Extract a string from an Atom or Str node.
fn any_str(expr: &SExpr, context: &str) -> Result<String, PolicyParseError> {
    expr.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| sexpr_error(expr, &format!("expected {} (got a list)", context)))
}

/// Extract a string that must be an unquoted atom.
fn atom_str(expr: &SExpr, context: &str) -> Result<String, PolicyParseError> {
    match expr {
        SExpr::Atom(s, _) => Ok(s.clone()),
        _ => Err(sexpr_error(expr, &format!("expected {} as atom", context))),
    }
}

fn sexpr_error(expr: &SExpr, message: &str) -> PolicyParseError {
    let span = expr.span();
    PolicyParseError::InvalidRule {
        rule: format!("offset {}", span.start),
        message: message.to_string(),
    }
}

fn detect_circular_include(
    name: &str,
    defs: &HashMap<String, ProfileDef>,
    visited: &mut std::collections::HashSet<String>,
    path: &mut Vec<String>,
) -> Result<(), PolicyParseError> {
    if visited.contains(name) {
        path.push(name.to_string());
        return Err(PolicyParseError::CircularInclude {
            cycle: name.to_string(),
            path: Some(path.join(" -> ")),
        });
    }
    visited.insert(name.to_string());
    path.push(name.to_string());

    if let Some(def) = defs.get(name)
        && let Some(ref includes) = def.include
    {
        for include in includes {
            detect_circular_include(include, defs, visited, path)?;
        }
    }

    path.pop();
    visited.remove(name);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_policy() {
        let input = r#"
(default (permission deny) (profile main))
(profile main)
"#;
        let doc = parse_policy(input).unwrap();
        assert_eq!(
            doc.default_config.as_ref().unwrap().permission,
            Effect::Deny
        );
        assert_eq!(doc.default_config.as_ref().unwrap().profile, "main");
        assert!(doc.profile_defs.contains_key("main"));
    }

    #[test]
    fn parse_profile_with_rules() {
        let input = r#"
(default (permission deny) (profile main))
(profile main
  (allow bash *)
  (deny bash "git push*")
  (ask bash "git commit*"))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        assert_eq!(main.rules.len(), 3);
        assert_eq!(main.rules[0].effect, Effect::Allow);
        assert_eq!(main.rules[0].verb, "bash");
        assert_eq!(main.rules[1].effect, Effect::Deny);
        assert_eq!(main.rules[2].effect, Effect::Ask);
    }

    #[test]
    fn parse_profile_with_include() {
        let input = r#"
(default (permission deny) (profile main))
(profile cwd-read
  (allow read *))
(profile main
  (include cwd-read)
  (allow bash *))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        assert_eq!(main.include.as_ref().unwrap(), &["cwd-read"]);
    }

    #[test]
    fn parse_fs_rule() {
        let input = r#"
(default (permission deny) (profile main))
(profile main
  (allow (fs read write) (subpath .)))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        assert_eq!(main.rules.len(), 1);
        assert_eq!(main.rules[0].verb, FS_RULE_VERB);
        let fs = main.rules[0]
            .constraints
            .as_ref()
            .unwrap()
            .fs
            .as_ref()
            .unwrap();
        assert_eq!(fs[0].0, Cap::READ | Cap::WRITE);
        assert!(matches!(&fs[0].1, FilterExpr::Subpath(s) if s == "."));
    }

    #[test]
    fn parse_sandbox_block() {
        let input = r#"
(default (permission deny) (profile main))
(profile main
  (sandbox
    (fs full (subpath .))
    (network deny))
  (allow bash *))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        let sb = main.sandbox.as_ref().unwrap();
        assert!(sb.fs.is_some());
        assert_eq!(sb.network, Some(NetworkPolicy::Deny));
    }

    #[test]
    fn parse_tool_with_constraints() {
        let input = r#"
(default (permission deny) (profile main))
(profile main
  (allow bash "cargo *"
    (args (forbid "--force"))))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        assert_eq!(main.rules.len(), 1);
        let c = main.rules[0].constraints.as_ref().unwrap();
        let args = c.args.as_ref().unwrap();
        assert_eq!(args[0], ArgSpec::Forbid("--force".to_string()));
    }

    #[test]
    fn parse_url_constraints() {
        let input = r#"
(default (permission deny) (profile main))
(profile main
  (allow webfetch *
    (url "github.com")))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        let c = main.rules[0].constraints.as_ref().unwrap();
        let urls = c.url.as_ref().unwrap();
        assert_eq!(urls[0], UrlSpec::Require("github.com".to_string()));
    }

    #[test]
    fn error_missing_default() {
        let input = "(profile main)";
        let err = parse_policy(input).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn error_unknown_profile() {
        let input = r#"
(default (permission deny) (profile nonexistent))
(profile main)
"#;
        let err = parse_policy(input).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn error_circular_include() {
        let input = r#"
(default (permission deny) (profile a))
(profile a (include b))
(profile b (include a))
"#;
        let err = parse_policy(input).unwrap_err();
        assert!(err.to_string().contains("circular"));
    }

    #[test]
    fn parse_full_policy() {
        let input = r#"
; Full example policy
(default (permission deny) (profile main))

(profile cwd-read
  (allow (fs read) (subpath .)))

(profile main
  (include cwd-read)

  ; Filesystem access
  (allow (fs read write) (subpath .))
  (allow (fs read) (subpath "~/.clash"))

  ; Network access
  (allow (network (domain "github.com")))

  ; Sandbox for bash
  (sandbox
    (fs full (subpath .))
    (network deny))

  ; Tool rules
  (allow bash *)
  (deny bash "git push*")
  (ask bash "git commit*")

  ; Constrained tool rules
  (allow webfetch *
    (url "github.com"))
  (allow bash "cargo *"
    (args (forbid "--force"))))
"#;
        let doc = parse_policy(input).unwrap();
        assert!(doc.profile_defs.contains_key("main"));
        assert!(doc.profile_defs.contains_key("cwd-read"));

        let main = &doc.profile_defs["main"];
        assert!(main.sandbox.is_some());
        assert!(
            main.include
                .as_ref()
                .unwrap()
                .contains(&"cwd-read".to_string())
        );
        // fs rules + network rule + tool rules + constrained rules
        assert!(main.rules.len() >= 7);
    }

    #[test]
    fn parse_inline_fs_constraint() {
        let input = r#"
(default (permission deny) (profile main))
(profile main
  (allow read *
    (fs (read (subpath .)))))
"#;
        let doc = parse_policy(input).unwrap();
        let main = &doc.profile_defs["main"];
        let c = main.rules[0].constraints.as_ref().unwrap();
        let fs = c.fs.as_ref().unwrap();
        assert_eq!(fs[0].0, Cap::READ);
    }
}
