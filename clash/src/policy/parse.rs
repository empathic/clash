//! Parsing and deserialization for policy documents.
//!
//! Handles:
//! - YAML deserialization of policy documents
//! - Pest-based parsing of compact rule strings (`effect entity tool pattern`)
//! - Custom serde for `Pattern` (with `!` negation prefix)
//! - Custom serde for `VerbPattern` (with `*` wildcard)
//! - Legacy `[permissions]` desugaring to statements

use std::collections::HashMap;

use pest::Parser;
use pest_derive::Parser;
use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use tracing::{Level, instrument};

use super::error::{PolicyParseError, suggest_closest};
use super::*;
use crate::policy::sandbox_types::{Cap, NetworkPolicy};

// ---------------------------------------------------------------------------
// Pest grammar
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[grammar = "policy/rule.pest"]
struct RuleParser;

// ---------------------------------------------------------------------------
// YAML document shape (serde)
// ---------------------------------------------------------------------------

/// Raw YAML representation that maps 1:1 to the file format.
#[derive(Debug, Serialize, Deserialize)]
struct RawPolicyYaml {
    #[serde(default = "default_ask_str")]
    default: String,

    /// Named constraint primitives.
    #[serde(default)]
    constraints: HashMap<String, ConstraintDef>,

    /// Named profiles (boolean expressions over constraint names).
    #[serde(default)]
    profiles: HashMap<String, ProfileExpr>,

    #[serde(
        default,
        deserialize_with = "deserialize_rules",
        serialize_with = "serialize_rules"
    )]
    rules: Vec<String>,

    /// Legacy backward-compat with Claude Code permission format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    permissions: Option<LegacyPermissions>,
}

fn default_ask_str() -> String {
    "ask".into()
}

/// Deserialize rules from either a YAML sequence (old format) or mapping (new format).
///
/// Old format (sequence of strings):
/// ```yaml
/// rules:
///   - "allow bash git * : strict-git"
///   - deny bash rm *
/// ```
///
/// New format (mapping of rule → constraint):
/// ```yaml
/// rules:
///   allow bash git * : strict-git
///   allow bash cargo * : sandboxed
///   deny bash rm * : []
/// ```
fn deserialize_rules<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_yaml::Value::deserialize(deserializer)?;
    match value {
        serde_yaml::Value::Sequence(seq) => seq
            .into_iter()
            .map(|v| match v {
                serde_yaml::Value::String(s) => Ok(s),
                _ => Err(Error::custom("rule must be a string")),
            })
            .collect(),
        serde_yaml::Value::Mapping(map) => {
            let mut rules = Vec::new();
            for (key, value) in map {
                let rule_key = match key {
                    serde_yaml::Value::String(s) => s,
                    _ => return Err(Error::custom("rule key must be a string")),
                };
                let constraint = match &value {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    serde_yaml::Value::Null => None,
                    serde_yaml::Value::Sequence(seq) if seq.is_empty() => None,
                    _ => {
                        return Err(Error::custom(format!(
                            "constraint for '{}' must be a string, null, or []",
                            rule_key
                        )));
                    }
                };
                if let Some(constraint) = constraint {
                    rules.push(format!("{} : {}", rule_key, constraint));
                } else {
                    rules.push(rule_key);
                }
            }
            Ok(rules)
        }
        serde_yaml::Value::Null => Ok(Vec::new()),
        _ => Err(Error::custom("rules must be a sequence or mapping")),
    }
}

/// Serialize rules as a YAML mapping (new format).
///
/// Rules with constraints are split on the ` : ` separator.
/// Rules without constraints get `[]` as the value.
fn serialize_rules<S>(rules: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(rules.len()))?;
    for rule in rules {
        if let Some(colon_idx) = find_constraint_separator(rule) {
            let key = rule[..colon_idx].trim_end();
            let value = rule[colon_idx + 1..].trim();
            map.serialize_entry(key, value)?;
        } else {
            let empty: Vec<String> = Vec::new();
            map.serialize_entry(rule.trim(), &empty)?;
        }
    }
    map.end()
}

// ---------------------------------------------------------------------------
// Public parsing API
// ---------------------------------------------------------------------------

/// Parse a policy document from a YAML string.
///
/// Auto-detects old vs new format:
/// - New format: `default:` is a YAML mapping `{ permission: ..., profile: ... }`
/// - Old format: `default:` is a scalar string like `"ask"`
#[instrument(level = Level::TRACE, skip(input))]
pub fn parse_yaml(input: &str) -> Result<PolicyDocument, PolicyParseError> {
    // Parse as generic Value first to detect format.
    let value: serde_yaml::Value = serde_yaml::from_str(input)?;

    if is_new_format(&value) {
        return parse_new_format(value);
    }

    parse_old_format(input)
}

/// Detect whether the YAML value uses the new format.
///
/// New format has `default:` as a mapping (with `permission` and `profile` keys).
/// Old format has `default:` as a scalar string or missing.
fn is_new_format(value: &serde_yaml::Value) -> bool {
    if let serde_yaml::Value::Mapping(map) = value {
        if let Some(default_val) = map.get(&serde_yaml::Value::String("default".into())) {
            return default_val.is_mapping();
        }
    }
    false
}

/// Parse the old/legacy policy format.
fn parse_old_format(input: &str) -> Result<PolicyDocument, PolicyParseError> {
    let raw: RawPolicyYaml = serde_yaml::from_str(input)?;

    let default = parse_effect_str(&raw.default)?;

    let mut statements = Vec::new();

    // Desugar legacy permissions if present.
    if let Some(ref perms) = raw.permissions {
        statements.extend(desugar_legacy(perms));
    }

    // Parse compact rule strings.
    for rule_str in &raw.rules {
        let stmt = parse_rule(rule_str)?;
        statements.push(stmt);
    }

    Ok(PolicyDocument {
        policy: PolicyConfig { default },
        permissions: raw.permissions,
        constraints: raw.constraints,
        profiles: raw.profiles,
        statements,
        default_config: None,
        profile_defs: Default::default(),
    })
}

// ---------------------------------------------------------------------------
// New-format parser
// ---------------------------------------------------------------------------

/// Parse the new profile-based policy format.
///
/// ```yaml
/// default:
///   permission: ask
///   profile: research
///
/// profiles:
///   safe-ssh:
///     rules:
///       deny * *:
///         fs:
///           read + write: subpath(~/.ssh)
///   research:
///     include: safe-ssh
///     rules:
///       allow bash *:
///         args: ["!-delete"]
///         fs:
///           read: "!regex(\\./)"
/// ```
fn parse_new_format(value: serde_yaml::Value) -> Result<PolicyDocument, PolicyParseError> {
    let map = match value {
        serde_yaml::Value::Mapping(m) => m,
        _ => {
            return Err(PolicyParseError::Yaml(serde_yaml::Error::custom(
                "expected mapping at top level",
            )));
        }
    };

    // Parse `default: { permission: ..., profile: ... }`
    let default_val = map
        .get(&serde_yaml::Value::String("default".into()))
        .ok_or_else(|| {
            PolicyParseError::Yaml(serde_yaml::Error::custom("missing 'default' key"))
        })?;
    let default_config = parse_new_default(default_val)?;

    // Parse `profiles: { name: { include: ..., rules: ... } }`
    let mut profile_defs = HashMap::new();
    if let Some(profiles_val) = map.get(&serde_yaml::Value::String("profiles".into())) {
        let profiles_map = profiles_val.as_mapping().ok_or_else(|| {
            PolicyParseError::Yaml(serde_yaml::Error::custom("'profiles' must be a mapping"))
        })?;
        for (name_val, def_val) in profiles_map {
            let name = name_val.as_str().ok_or_else(|| {
                PolicyParseError::Yaml(serde_yaml::Error::custom("profile name must be a string"))
            })?;
            let def = parse_new_profile_def(def_val)?;
            profile_defs.insert(name.to_string(), def);
        }
    }

    // Validate that the active profile exists
    if !profile_defs.contains_key(&default_config.profile) {
        let candidates: Vec<&str> = profile_defs.keys().map(|s| s.as_str()).collect();
        return Err(PolicyParseError::UnknownInclude {
            name: default_config.profile.clone(),
            suggestion: suggest_closest(&default_config.profile, &candidates),
        });
    }

    // Validate all includes
    for (_name, def) in &profile_defs {
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

    // Detect circular includes
    for name in profile_defs.keys() {
        let mut visited = std::collections::HashSet::new();
        let mut path = Vec::new();
        detect_circular_include(name, &profile_defs, &mut visited, &mut path)?;
    }

    Ok(PolicyDocument {
        policy: PolicyConfig {
            default: default_config.permission,
        },
        permissions: None,
        constraints: Default::default(),
        profiles: Default::default(),
        statements: Vec::new(),
        default_config: Some(default_config),
        profile_defs,
    })
}

/// Parse `default: { permission: ask, profile: research }`.
fn parse_new_default(value: &serde_yaml::Value) -> Result<DefaultConfig, PolicyParseError> {
    let map = value.as_mapping().ok_or_else(|| {
        PolicyParseError::Yaml(serde_yaml::Error::custom(
            "'default' must be a mapping with 'permission' and 'profile'",
        ))
    })?;

    let permission_str = map
        .get(&serde_yaml::Value::String("permission".into()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyParseError::Yaml(serde_yaml::Error::custom(
                "'default.permission' is required and must be a string",
            ))
        })?;
    let permission = parse_effect_str(permission_str)?;

    let profile = map
        .get(&serde_yaml::Value::String("profile".into()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PolicyParseError::Yaml(serde_yaml::Error::custom(
                "'default.profile' is required and must be a string",
            ))
        })?
        .to_string();

    Ok(DefaultConfig {
        permission,
        profile,
    })
}

/// Parse a profile definition: `{ include: ..., rules: { ... } }`.
fn parse_new_profile_def(value: &serde_yaml::Value) -> Result<ProfileDef, PolicyParseError> {
    let map = value.as_mapping().ok_or_else(|| {
        PolicyParseError::Yaml(serde_yaml::Error::custom("profile def must be a mapping"))
    })?;

    let include = map
        .get(&serde_yaml::Value::String("include".into()))
        .map(|v| match v {
            serde_yaml::Value::String(s) => Ok(vec![s.clone()]),
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .map(|item| {
                    item.as_str().map(|s| s.to_string()).ok_or_else(|| {
                        PolicyParseError::Yaml(serde_yaml::Error::custom(
                            "include list items must be strings",
                        ))
                    })
                })
                .collect(),
            _ => Err(PolicyParseError::Yaml(serde_yaml::Error::custom(
                "'include' must be a string or list of strings",
            ))),
        })
        .transpose()?;

    let mut rules = Vec::new();
    if let Some(rules_val) = map.get(&serde_yaml::Value::String("rules".into())) {
        let rules_map = rules_val.as_mapping().ok_or_else(|| {
            PolicyParseError::Yaml(serde_yaml::Error::custom("'rules' must be a mapping"))
        })?;
        for (key_val, constraint_val) in rules_map {
            let key = key_val.as_str().ok_or_else(|| {
                PolicyParseError::Yaml(serde_yaml::Error::custom("rule key must be a string"))
            })?;
            let (effect, verb, noun) = parse_new_rule_key(key)?;
            let constraints = parse_inline_constraints(constraint_val)?;
            rules.push(ProfileRule {
                effect,
                verb,
                noun,
                constraints,
            });
        }
    }

    Ok(ProfileDef { include, rules })
}

/// Parse a rule key like `"deny * *"` or `"allow bash *"` into (effect, verb, noun).
///
/// Format: `effect verb noun...` — at least 3 whitespace-separated tokens.
/// The entity slot is implicit (always the agent).
/// The noun may contain multiple tokens (e.g., "deny bash rm *" → verb="bash", noun="rm *").
fn parse_new_rule_key(key: &str) -> Result<(Effect, String, Pattern), PolicyParseError> {
    // Strip trailing `:` if present (YAML mapping keys may include it)
    let key = key.strip_suffix(':').unwrap_or(key).trim();
    let parts: Vec<&str> = key.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(PolicyParseError::InvalidNewRuleKey(
            key.to_string(),
            format!(
                "expected at least 3 parts (effect verb noun...), got {}",
                parts.len()
            ),
        ));
    }

    let effect = parse_effect_str(parts[0])?;
    let verb = parts[1].to_string();
    // Everything after effect and verb is the noun pattern (e.g., "rm *" in "deny bash rm *")
    let noun_str = parts[2..].join(" ");
    let noun = parse_pattern(&noun_str);

    Ok((effect, verb, noun))
}

/// Parse inline constraints from the YAML value of a rule.
///
/// The value can be:
/// - null / `[]` → no constraints
/// - a mapping with optional keys: `fs`, `args`, `network`, `pipe`, `redirect`
fn parse_inline_constraints(
    value: &serde_yaml::Value,
) -> Result<Option<InlineConstraints>, PolicyParseError> {
    match value {
        serde_yaml::Value::Null => Ok(None),
        serde_yaml::Value::Sequence(seq) if seq.is_empty() => Ok(None),
        serde_yaml::Value::Mapping(map) if map.is_empty() => Ok(None),
        serde_yaml::Value::Mapping(map) => {
            let mut constraints = InlineConstraints::default();

            if let Some(fs_val) = map.get(&serde_yaml::Value::String("fs".into())) {
                constraints.fs = Some(parse_cap_scoped_fs(fs_val)?);
            }

            if let Some(args_val) = map.get(&serde_yaml::Value::String("args".into())) {
                constraints.args = Some(parse_args_list(args_val)?);
            }

            if let Some(net_val) = map.get(&serde_yaml::Value::String("network".into())) {
                let net_str = net_val.as_str().ok_or_else(|| {
                    PolicyParseError::Yaml(serde_yaml::Error::custom("'network' must be a string"))
                })?;
                constraints.network = Some(match net_str {
                    "deny" => NetworkPolicy::Deny,
                    "allow" => NetworkPolicy::Allow,
                    _ => {
                        return Err(PolicyParseError::Yaml(serde_yaml::Error::custom(format!(
                            "unknown network policy: '{}'",
                            net_str
                        ))));
                    }
                });
            }

            if let Some(pipe_val) = map.get(&serde_yaml::Value::String("pipe".into())) {
                constraints.pipe = pipe_val.as_bool();
            }

            if let Some(redir_val) = map.get(&serde_yaml::Value::String("redirect".into())) {
                constraints.redirect = redir_val.as_bool();
            }

            Ok(Some(constraints))
        }
        _ => Err(PolicyParseError::Yaml(serde_yaml::Error::custom(
            "rule constraint must be null, [], or a mapping",
        ))),
    }
}

/// Parse cap-scoped filesystem constraints.
///
/// ```yaml
/// fs:
///   read + write: subpath(~/.ssh)
///   read: "!regex(\\./)"
/// ```
///
/// Each key is a capability expression (parsed with `Cap::parse`),
/// each value is a filter expression (parsed with `parse_filter_expr`).
fn parse_cap_scoped_fs(
    value: &serde_yaml::Value,
) -> Result<Vec<(Cap, FilterExpr)>, PolicyParseError> {
    let map = value.as_mapping().ok_or_else(|| {
        PolicyParseError::Yaml(serde_yaml::Error::custom(
            "'fs' must be a mapping of caps → filter expression",
        ))
    })?;

    let mut entries = Vec::new();
    for (cap_key, filter_val) in map {
        let cap_str = cap_key.as_str().ok_or_else(|| {
            PolicyParseError::InvalidCapScopedFs(
                format!("{:?}", cap_key),
                "cap key must be a string".into(),
            )
        })?;
        let caps = Cap::parse(cap_str)
            .map_err(|e| PolicyParseError::InvalidCapScopedFs(cap_str.to_string(), e))?;
        let filter_str = filter_val.as_str().ok_or_else(|| {
            PolicyParseError::InvalidCapScopedFs(
                cap_str.to_string(),
                "filter value must be a string".into(),
            )
        })?;
        let filter = parse_filter_expr(filter_str)?;
        entries.push((caps, filter));
    }

    Ok(entries)
}

/// Parse a unified `args:` list.
///
/// ```yaml
/// args: ["!-delete", "--dry-run"]
/// ```
///
/// `"!x"` → `ArgSpec::Forbid("x")`, `"x"` → `ArgSpec::Require("x")`
fn parse_args_list(value: &serde_yaml::Value) -> Result<Vec<ArgSpec>, PolicyParseError> {
    let seq = value
        .as_sequence()
        .ok_or_else(|| PolicyParseError::InvalidArg("'args' must be a sequence".into()))?;

    let mut specs = Vec::new();
    for item in seq {
        let s = item
            .as_str()
            .ok_or_else(|| PolicyParseError::InvalidArg("each arg must be a string".into()))?;
        if let Some(inner) = s.strip_prefix('!') {
            specs.push(ArgSpec::Forbid(inner.to_string()));
        } else {
            specs.push(ArgSpec::Require(s.to_string()));
        }
    }

    Ok(specs)
}

/// Flatten a profile by resolving its `include:` chain.
///
/// Returns rules from the included parent first, then the profile's own rules.
#[instrument(level = Level::TRACE)]
pub fn flatten_profile(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
) -> Result<Vec<ProfileRule>, PolicyParseError> {
    let mut visited = std::collections::HashSet::new();
    flatten_profile_inner(name, profiles, &mut visited)
}

fn flatten_profile_inner(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
    visited: &mut std::collections::HashSet<String>,
) -> Result<Vec<ProfileRule>, PolicyParseError> {
    if !visited.insert(name.to_string()) {
        return Err(PolicyParseError::CircularInclude {
            cycle: name.to_string(),
            path: None, // flatten doesn't track path; cycle detection does
        });
    }

    let def = profiles.get(name).ok_or_else(|| {
        let candidates: Vec<&str> = profiles.keys().map(|s| s.as_str()).collect();
        PolicyParseError::UnknownInclude {
            name: name.to_string(),
            suggestion: suggest_closest(name, &candidates),
        }
    })?;

    let mut rules = Vec::new();

    // First, collect rules from included profiles (parent rules come first, lower precedence)
    if let Some(ref includes) = def.include {
        for include in includes {
            let parent_rules = flatten_profile_inner(include, profiles, visited)?;
            rules.extend(parent_rules);
        }
    }

    // Then add own rules (higher precedence)
    rules.extend(def.rules.clone());

    Ok(rules)
}

/// Detect circular includes by walking the include chain.
fn detect_circular_include(
    name: &str,
    profiles: &HashMap<String, ProfileDef>,
    visited: &mut std::collections::HashSet<String>,
    path: &mut Vec<String>,
) -> Result<(), PolicyParseError> {
    if !visited.insert(name.to_string()) {
        path.push(name.to_string());
        let cycle_path = path.join(" -> ");
        return Err(PolicyParseError::CircularInclude {
            cycle: name.to_string(),
            path: Some(cycle_path),
        });
    }
    path.push(name.to_string());
    if let Some(def) = profiles.get(name) {
        if let Some(ref includes) = def.include {
            for include in includes {
                detect_circular_include(include, profiles, visited, path)?;
            }
        }
    }
    path.pop();
    Ok(())
}

/// Parse a single compact rule string into a `Statement`.
///
/// Format: `effect [entity] tool pattern`
///
/// The entity is optional — when omitted, it defaults to `agent` (any agent).
/// The parser detects whether entity is present by checking if the second
/// token is a known tool keyword (`bash`, `read`, `write`, `edit`, `*`).
///
/// Examples:
/// - `allow bash cargo build *`       — entity defaults to agent
/// - `allow agent:claude bash git *`  — explicit entity
/// - `deny !user read ~/config/*`     — explicit negated entity
/// - `ask * * *`                       — explicit wildcard entity
#[instrument(level = Level::TRACE)]
pub fn parse_rule(input: &str) -> Result<Statement, PolicyParseError> {
    let input = input.trim();

    // Split on ` : ` to extract optional profile expression.
    // We need to find the last ` : ` that separates the rule from the profile.
    // The rule part goes to the pest parser, the profile part is parsed separately.
    let (rule_part, profile_expr) = if let Some(colon_idx) = find_constraint_separator(input) {
        let rule_str = input[..colon_idx].trim();
        let profile_str = input[colon_idx + 1..].trim();
        let profile =
            parse_profile_expr(profile_str).map_err(|e| PolicyParseError::InvalidRule {
                rule: input.to_string(),
                message: format!("invalid constraint expression: {}", e),
            })?;
        (rule_str, Some(profile))
    } else {
        (input, None)
    };

    // Check if entity is omitted: if the second token is a known tool keyword,
    // insert the default entity "agent" (matches any agent) before parsing.
    let expanded_rule;
    let parse_input = if needs_entity_insertion(rule_part) {
        expanded_rule = insert_default_entity(rule_part);
        expanded_rule.as_str()
    } else {
        rule_part
    };

    let pairs =
        RuleParser::parse(Rule::rule, parse_input).map_err(|e| PolicyParseError::InvalidRule {
            rule: input.to_string(),
            message: e.to_string(),
        })?;

    let rule_pair = pairs.into_iter().next().unwrap();
    let mut inner = rule_pair.into_inner();

    // effect
    let effect_pair = inner.next().unwrap();
    let effect = parse_effect_str(effect_pair.as_str())?;

    // entity
    let entity_pair = inner.next().unwrap();
    let entity = parse_entity_pair(entity_pair);

    // tool → verb
    let tool_pair = inner.next().unwrap();
    let verb = parse_tool_str(tool_pair.as_str())?;

    // pattern → noun
    let pattern_pair = inner.next().unwrap();
    let noun = parse_pattern(pattern_pair.as_str().trim());

    Ok(Statement {
        effect,
        entity,
        verb,
        noun,
        reason: None,
        profile: profile_expr,
    })
}

const TOOL_KEYWORDS: &[&str] = &["bash", "read", "write", "edit"];

/// Check if the rule string is missing an entity (second token is a tool keyword).
fn needs_entity_insertion(rule: &str) -> bool {
    let mut tokens = rule.split_whitespace();
    let _effect = tokens.next(); // skip effect
    match tokens.next() {
        Some(second) => TOOL_KEYWORDS.contains(&second),
        None => false,
    }
}

/// Insert the default entity `agent` after the effect keyword.
fn insert_default_entity(rule: &str) -> String {
    // Find the end of the first whitespace-separated token (effect)
    let trimmed = rule.trim_start();
    if let Some(space_idx) = trimmed.find([' ', '\t']) {
        let effect = &trimmed[..space_idx];
        let rest = &trimmed[space_idx..];
        format!("{} agent{}", effect, rest)
    } else {
        rule.to_string()
    }
}

/// Find the position of the `:` constraint separator in a rule string.
///
/// Returns the byte offset of `:` if found, or None if the rule has no constraint.
/// We look for `:` that is NOT part of an entity type (like `agent:claude`).
/// The constraint separator `:` must have a space before it.
fn find_constraint_separator(input: &str) -> Option<usize> {
    // Walk backwards from the end, looking for ' :' pattern.
    // The entity colon (agent:claude) never has a space before the colon.
    let bytes = input.as_bytes();
    (1..bytes.len())
        .rev()
        .find(|&i| bytes[i] == b':' && bytes[i - 1] == b' ')
}

// Expression parsing delegated to expr module.
pub use super::expr::{parse_filter_expr, parse_profile_expr};

/// Serialize a `PolicyDocument` back to YAML.
#[instrument(level = Level::TRACE)]
pub fn to_yaml(doc: &PolicyDocument) -> Result<String, serde_yaml::Error> {
    let raw = RawPolicyYaml {
        default: doc.policy.default.to_string(),
        constraints: doc.constraints.clone(),
        profiles: doc.profiles.clone(),
        rules: doc.statements.iter().map(format_rule).collect(),
        permissions: doc.permissions.clone(),
    };
    serde_yaml::to_string(&raw)
}

/// Format a `Statement` as a compact rule string.
///
/// When the entity is the default (any agent), it is omitted from the output.
#[instrument(level = Level::TRACE)]
pub fn format_rule(stmt: &Statement) -> String {
    let effect = stmt.effect.to_string();
    let tool = match &stmt.verb {
        VerbPattern::Any => "*".to_string(),
        VerbPattern::Exact(v) => v.rule_name().to_string(),
        VerbPattern::Named(s) => s.clone(),
    };
    let noun = super::ast::format_pattern_str(&stmt.noun);

    let base = if is_default_entity(&stmt.entity) {
        format!("{} {} {}", effect, tool, noun)
    } else {
        let entity = super::ast::format_pattern_str(&stmt.entity);
        format!("{} {} {} {}", effect, entity, tool, noun)
    };

    if let Some(ref profile) = stmt.profile {
        format!("{} : {}", base, profile)
    } else {
        base
    }
}

/// Check if an entity pattern is the default (matches any agent).
///
/// The default entity is either:
/// - `agent` (typed, no name) — matches agent and agent:*
/// - `*` (wildcard) — matches everything
///
/// Both are implicit when entity is omitted from a rule.
fn is_default_entity(entity: &Pattern) -> bool {
    match entity {
        Pattern::Match(MatchExpr::Typed {
            entity_type,
            name: None,
        }) => entity_type == "agent",
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Kept for backward compatibility — parse TOML policy documents.
// ---------------------------------------------------------------------------

/// Parse a policy document from a TOML string.
#[instrument(level = Level::TRACE)]
pub fn parse_toml(input: &str) -> Result<PolicyDocument, toml::de::Error> {
    toml::from_str(input)
}

// ---------------------------------------------------------------------------
// Pattern / verb parsing (shared between rule parser and serde)
// ---------------------------------------------------------------------------

/// Parse a pattern string (used for entity and noun slots).
///
/// Syntax:
/// - `*` → `Pattern::Match(MatchExpr::Any)`
/// - `!*` → `Pattern::Not(MatchExpr::Any)`
/// - `!pattern` → `Pattern::Not(parse_match_expr(pattern))`
/// - `pattern` → `Pattern::Match(parse_match_expr(pattern))`
#[instrument(level = Level::TRACE)]
pub fn parse_pattern(s: &str) -> Pattern {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('!') {
        Pattern::Not(parse_match_expr(inner.trim()))
    } else {
        Pattern::Match(parse_match_expr(s))
    }
}

/// Parse a match expression (without negation).
///
/// Syntax:
/// - `*` → `MatchExpr::Any`
/// - `type:name` → `MatchExpr::Typed { entity_type, name }`
/// - `type:*` → `MatchExpr::Typed { entity_type, name: None }`
/// - contains `*` or `**` or `?` → `MatchExpr::Glob`
/// - otherwise → `MatchExpr::Exact`
#[instrument(level = Level::TRACE)]
pub fn parse_match_expr(s: &str) -> MatchExpr {
    let s = s.trim();
    if s == "*" {
        return MatchExpr::Any;
    }

    // Check for typed entity pattern (e.g., "agent:claude", "service:*")
    if let Some((entity_type, name)) = s.split_once(':') {
        let entity_type = entity_type.trim();
        let name = name.trim();
        if !entity_type.is_empty()
            && !entity_type.contains('/')
            && !entity_type.contains('.')
            && !entity_type.contains('~')
        {
            if name == "*" {
                return MatchExpr::Typed {
                    entity_type: entity_type.to_string(),
                    name: None,
                };
            } else {
                return MatchExpr::Typed {
                    entity_type: entity_type.to_string(),
                    name: Some(name.to_string()),
                };
            }
        }
    }

    // Check for glob patterns
    if s.contains('*') || s.contains("**") || s.contains('?') {
        MatchExpr::Glob(s.to_string())
    } else {
        MatchExpr::Exact(s.to_string())
    }
}

/// Parse a verb pattern string.
///
/// Syntax:
/// - `*` → `VerbPattern::Any`
/// - `read` / `write` / `edit` / `execute` → `VerbPattern::Exact(Verb)`
#[instrument(level = Level::TRACE)]
pub fn parse_verb_pattern(s: &str) -> Result<VerbPattern, String> {
    let s = s.trim();
    if s == "*" {
        return Ok(VerbPattern::Any);
    }
    match s {
        "read" => Ok(VerbPattern::Exact(Verb::Read)),
        "write" => Ok(VerbPattern::Exact(Verb::Write)),
        "edit" => Ok(VerbPattern::Exact(Verb::Edit)),
        "execute" => Ok(VerbPattern::Exact(Verb::Execute)),
        other => Ok(VerbPattern::Named(other.to_string())),
    }
}

// Re-export legacy desugaring for backward compatibility.
pub use super::legacy::desugar_legacy;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn parse_effect_str(s: &str) -> Result<Effect, PolicyParseError> {
    match s {
        "allow" => Ok(Effect::Allow),
        "deny" => Ok(Effect::Deny),
        "ask" => Ok(Effect::Ask),
        other => Err(PolicyParseError::InvalidEffect(other.into())),
    }
}

fn parse_tool_str(s: &str) -> Result<VerbPattern, PolicyParseError> {
    match s {
        "*" => Ok(VerbPattern::Any),
        "bash" => Ok(VerbPattern::Exact(Verb::Execute)),
        "read" => Ok(VerbPattern::Exact(Verb::Read)),
        "write" => Ok(VerbPattern::Exact(Verb::Write)),
        "edit" => Ok(VerbPattern::Exact(Verb::Edit)),
        other => Ok(VerbPattern::Named(other.to_string())),
    }
}

/// Build a `Pattern` from a pest entity pair.
fn parse_entity_pair(pair: pest::iterators::Pair<Rule>) -> Pattern {
    let mut negated = false;
    let mut entity_value = None;

    for inner in pair.into_inner() {
        match inner.as_rule() {
            Rule::negation => negated = true,
            Rule::entity_value => {
                entity_value = Some(parse_entity_value(inner));
            }
            _ => {}
        }
    }

    let expr = entity_value.unwrap_or(MatchExpr::Any);
    if negated {
        Pattern::Not(expr)
    } else {
        Pattern::Match(expr)
    }
}

fn parse_entity_value(pair: pest::iterators::Pair<Rule>) -> MatchExpr {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::wildcard => MatchExpr::Any,
        Rule::typed_entity => {
            let mut parts = inner.into_inner();
            let entity_type = parts.next().unwrap().as_str().to_string();
            let name_part = parts.next().unwrap();
            let name = match name_part.as_rule() {
                Rule::wildcard => None,
                _ => Some(name_part.as_str().to_string()),
            };
            MatchExpr::Typed { entity_type, name }
        }
        Rule::identifier => {
            // A bare identifier in entity position is an entity type (e.g., "agent", "user").
            // Treat it as Typed with no name, so "agent" matches "agent" and "agent:*".
            let s = inner.as_str();
            MatchExpr::Typed {
                entity_type: s.to_string(),
                name: None,
            }
        }
        _ => MatchExpr::Any,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Pattern parsing ---

    #[test]
    fn test_parse_pattern_wildcard() {
        assert_eq!(parse_pattern("*"), Pattern::Match(MatchExpr::Any));
    }

    #[test]
    fn test_parse_pattern_negated_wildcard() {
        assert_eq!(parse_pattern("!*"), Pattern::Not(MatchExpr::Any));
    }

    #[test]
    fn test_parse_pattern_exact() {
        assert_eq!(
            parse_pattern(".env"),
            Pattern::Match(MatchExpr::Exact(".env".into()))
        );
    }

    #[test]
    fn test_parse_pattern_negated_exact() {
        assert_eq!(
            parse_pattern("!user"),
            Pattern::Not(MatchExpr::Exact("user".into()))
        );
    }

    #[test]
    fn test_parse_pattern_glob() {
        assert_eq!(
            parse_pattern("~/config/*"),
            Pattern::Match(MatchExpr::Glob("~/config/*".into()))
        );
    }

    #[test]
    fn test_parse_pattern_negated_glob() {
        assert_eq!(
            parse_pattern("!~/code/proj/**"),
            Pattern::Not(MatchExpr::Glob("~/code/proj/**".into()))
        );
    }

    #[test]
    fn test_parse_pattern_typed_entity() {
        assert_eq!(
            parse_pattern("agent:claude"),
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
    }

    #[test]
    fn test_parse_pattern_typed_entity_wildcard() {
        assert_eq!(
            parse_pattern("agent:*"),
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
    }

    #[test]
    fn test_parse_pattern_bare_type() {
        assert_eq!(
            parse_pattern("agent"),
            Pattern::Match(MatchExpr::Exact("agent".into()))
        );
    }

    #[test]
    fn test_parse_verb_pattern() {
        assert_eq!(parse_verb_pattern("*").unwrap(), VerbPattern::Any);
        assert_eq!(
            parse_verb_pattern("read").unwrap(),
            VerbPattern::Exact(Verb::Read)
        );
        assert_eq!(
            parse_verb_pattern("execute").unwrap(),
            VerbPattern::Exact(Verb::Execute)
        );
        assert_eq!(
            parse_verb_pattern("task").unwrap(),
            VerbPattern::Named("task".into())
        );
    }

    // --- Rule parsing (pest) ---

    #[test]
    fn test_parse_rule_simple_allow() {
        let stmt = parse_rule("allow * bash cargo build *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.entity, Pattern::Match(MatchExpr::Any));
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Execute));
        assert!(stmt.matches("agent", &Verb::Execute, "cargo build --release"));
    }

    #[test]
    fn test_parse_rule_typed_entity() {
        let stmt = parse_rule("allow agent:claude bash git *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(!stmt.matches("agent:codex", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_rule_negated_entity() {
        let stmt = parse_rule("deny !user read ~/config/*").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert!(stmt.matches("agent:claude", &Verb::Read, "~/config/test.json"));
        assert!(!stmt.matches("user", &Verb::Read, "~/config/test.json"));
    }

    #[test]
    fn test_parse_rule_wildcard_tool() {
        let stmt = parse_rule("deny agent:untrusted * ~/sensitive/**").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Any);
        assert!(stmt.matches("agent:untrusted", &Verb::Read, "~/sensitive/secrets.json"));
        assert!(stmt.matches("agent:untrusted", &Verb::Write, "~/sensitive/secrets.json"));
    }

    #[test]
    fn test_parse_rule_all_wildcards() {
        let stmt = parse_rule("ask * * *").unwrap();
        assert_eq!(stmt.effect, Effect::Ask);
        assert_eq!(stmt.entity, Pattern::Match(MatchExpr::Any));
        assert_eq!(stmt.verb, VerbPattern::Any);
        assert!(stmt.matches("anyone", &Verb::Execute, "anything"));
    }

    #[test]
    fn test_parse_rule_read_tool() {
        let stmt = parse_rule("allow * read *.rs").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Read));
        assert!(stmt.matches("agent", &Verb::Read, "main.rs"));
    }

    #[test]
    fn test_parse_rule_write_tool() {
        let stmt = parse_rule("deny * write /etc/*").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Write));
        assert!(stmt.matches("agent", &Verb::Write, "/etc/passwd"));
    }

    #[test]
    fn test_parse_rule_edit_tool() {
        let stmt = parse_rule("allow * edit src/**").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Edit));
    }

    #[test]
    fn test_parse_rule_entity_wildcard_type() {
        let stmt = parse_rule("allow agent:* bash git *").unwrap();
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:codex", &Verb::Execute, "git status"));
        assert!(!stmt.matches("user", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_rule_invalid() {
        assert!(parse_rule("").is_err());
        assert!(parse_rule("allow").is_err());
        assert!(parse_rule("allow *").is_err());
        assert!(parse_rule("allow * bash").is_err());
        assert!(parse_rule("invalid * bash *").is_err());
    }

    // --- YAML document parsing ---

    #[test]
    fn test_parse_yaml_simple() {
        let yaml = r#"
default: ask

rules:
  - allow agent:claude bash git *
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask);
        assert_eq!(doc.statements.len(), 1);

        let stmt = &doc.statements[0];
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(!stmt.matches("agent:codex", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_yaml_multiple_rules() {
        let yaml = r#"
default: ask

rules:
  - allow * bash cargo build *
  - allow * bash cargo test *
  - deny * bash rm -rf /
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 3);
        assert_eq!(doc.statements[0].effect, Effect::Allow);
        assert_eq!(doc.statements[1].effect, Effect::Allow);
        assert_eq!(doc.statements[2].effect, Effect::Deny);
    }

    #[test]
    fn test_parse_yaml_with_negation() {
        let yaml = r#"
rules:
  - deny !user read ~/config/*
"#;
        let doc = parse_yaml(yaml).unwrap();
        let stmt = &doc.statements[0];

        assert_eq!(stmt.effect, Effect::Deny);
        assert!(stmt.matches("agent:claude", &Verb::Read, "~/config/test.json"));
        assert!(!stmt.matches("user", &Verb::Read, "~/config/test.json"));
    }

    #[test]
    fn test_parse_yaml_default_values() {
        let yaml = "rules:\n  - allow * * *.rs\n";
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask); // default
        let stmt = &doc.statements[0];
        assert!(stmt.entity.matches_entity("agent:claude"));
        assert!(stmt.entity.matches_entity("user"));
        assert!(stmt.verb.matches(&Verb::Read));
        assert!(stmt.verb.matches(&Verb::Execute));
    }

    #[test]
    fn test_parse_yaml_with_legacy_permissions() {
        let yaml = r#"
default: ask

permissions:
  allow:
    - "Bash(git:*)"
    - "Read(**/*.rs)"
  deny:
    - "Read(.env)"
  ask:
    - "Write"
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert!(doc.permissions.is_some());
        let perms = doc.permissions.as_ref().unwrap();
        assert_eq!(perms.allow.len(), 2);
        assert_eq!(perms.deny.len(), 1);
        assert_eq!(perms.ask.len(), 1);
    }

    // --- Legacy desugaring ---

    #[test]
    fn test_desugar_legacy_bash() {
        let perms = LegacyPermissions {
            allow: vec!["Bash(git:*)".into()],
            deny: vec![],
            ask: vec![],
        };
        let stmts = desugar_legacy(&perms);
        assert_eq!(stmts.len(), 1);
        let stmt = &stmts[0];
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git commit -m 'test'"));
        assert!(!stmt.matches("agent:claude", &Verb::Execute, "npm install"));
    }

    #[test]
    fn test_desugar_legacy_read() {
        let perms = LegacyPermissions {
            allow: vec!["Read".into()],
            deny: vec!["Read(.env)".into()],
            ask: vec![],
        };
        let stmts = desugar_legacy(&perms);
        assert_eq!(stmts.len(), 2);

        let allow_stmt = &stmts[0];
        assert_eq!(allow_stmt.effect, Effect::Allow);
        assert!(allow_stmt.matches("agent:claude", &Verb::Read, "anything.txt"));

        let deny_stmt = &stmts[1];
        assert_eq!(deny_stmt.effect, Effect::Deny);
        assert!(deny_stmt.matches("agent:claude", &Verb::Read, ".env"));
        assert!(!deny_stmt.matches("agent:claude", &Verb::Read, ".env.local"));
    }

    #[test]
    fn test_desugar_legacy_glob() {
        let perms = LegacyPermissions {
            allow: vec!["Read(**/*.rs)".into()],
            deny: vec![],
            ask: vec![],
        };
        let stmts = desugar_legacy(&perms);
        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].matches("agent:claude", &Verb::Read, "src/main.rs"));
        assert!(!stmts[0].matches("agent:claude", &Verb::Read, "src/main.py"));
    }

    // --- Serde roundtrips ---

    #[test]
    fn test_pattern_serde_roundtrip() {
        let patterns = vec![
            Pattern::Match(MatchExpr::Any),
            Pattern::Not(MatchExpr::Any),
            Pattern::Match(MatchExpr::Exact(".env".into())),
            Pattern::Match(MatchExpr::Glob("~/config/*".into())),
            Pattern::Not(MatchExpr::Glob("~/code/**".into())),
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            }),
        ];

        for pattern in &patterns {
            let json = serde_json::to_string(pattern).unwrap();
            let parsed: Pattern = serde_json::from_str(&json).unwrap();
            assert_eq!(pattern, &parsed, "roundtrip failed for {:?}", pattern);
        }
    }

    #[test]
    fn test_verb_pattern_serde_roundtrip() {
        let patterns = vec![
            VerbPattern::Any,
            VerbPattern::Exact(Verb::Read),
            VerbPattern::Exact(Verb::Execute),
        ];

        for pattern in &patterns {
            let json = serde_json::to_string(pattern).unwrap();
            let parsed: VerbPattern = serde_json::from_str(&json).unwrap();
            assert_eq!(pattern, &parsed, "roundtrip failed for {:?}", pattern);
        }
    }

    // --- Rule formatting roundtrip ---

    #[test]
    fn test_format_rule_roundtrip() {
        let rules = vec![
            "allow * bash cargo build *",
            "deny !user read ~/config/*",
            "ask agent:claude * *",
            "allow agent:* bash git *",
        ];
        for rule in rules {
            let stmt = parse_rule(rule).unwrap();
            let formatted = format_rule(&stmt);
            let reparsed = parse_rule(&formatted).unwrap();
            // Effects must match
            assert_eq!(
                stmt.effect, reparsed.effect,
                "effect mismatch for: {}",
                rule
            );
            // Verify the reparsed statement matches the same inputs
            assert_eq!(
                stmt.matches("agent:claude", &Verb::Execute, "cargo build --release"),
                reparsed.matches("agent:claude", &Verb::Execute, "cargo build --release"),
                "behavior mismatch for: {}",
                rule
            );
        }
    }

    // --- Implicit entity ---

    #[test]
    fn test_parse_rule_implicit_entity() {
        // When entity is omitted, "agent" is inserted as default.
        let stmt = parse_rule("allow bash git *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Execute));
        assert!(stmt.matches("agent", &Verb::Execute, "git status"));
        assert!(stmt.matches("agent:claude", &Verb::Execute, "git status"));
    }

    #[test]
    fn test_parse_rule_implicit_entity_deny() {
        let stmt = parse_rule("deny bash rm *").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert!(stmt.matches("agent", &Verb::Execute, "rm -rf /"));
    }

    #[test]
    fn test_parse_rule_implicit_entity_read() {
        let stmt = parse_rule("allow read *.rs").unwrap();
        assert_eq!(stmt.verb, VerbPattern::Exact(Verb::Read));
        assert!(stmt.matches("agent", &Verb::Read, "main.rs"));
    }

    #[test]
    fn test_parse_rule_implicit_entity_with_constraint() {
        let stmt = parse_rule("allow bash git * : strict-git").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert!(stmt.profile.is_some());
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: None,
            })
        );
    }

    #[test]
    fn test_format_rule_omits_default_entity() {
        // Explicit "agent" or "agent:*" entity should be omitted in formatted output.
        let stmt = parse_rule("allow agent bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow bash git *");

        let stmt = parse_rule("allow agent:* bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow bash git *");
    }

    #[test]
    fn test_format_rule_keeps_explicit_entity() {
        // Non-default entities should be kept.
        let stmt = parse_rule("allow agent:claude bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow agent:claude bash git *");

        let stmt = parse_rule("allow * bash git *").unwrap();
        assert_eq!(format_rule(&stmt), "allow * bash git *");
    }

    #[test]
    fn test_implicit_entity_roundtrip() {
        // Rules with implicit entity should roundtrip correctly.
        let rules = vec![
            "allow bash cargo build *",
            "deny bash rm *",
            "allow read *.rs",
            "allow edit src/**",
        ];
        for rule in rules {
            let stmt = parse_rule(rule).unwrap();
            let formatted = format_rule(&stmt);
            let reparsed = parse_rule(&formatted).unwrap();
            assert_eq!(
                stmt.effect, reparsed.effect,
                "effect mismatch for: {}",
                rule
            );
            assert_eq!(
                stmt.entity, reparsed.entity,
                "entity mismatch for: {}",
                rule
            );
            assert_eq!(stmt.verb, reparsed.verb, "verb mismatch for: {}", rule);
        }
    }

    // --- TOML backward compat ---

    #[test]
    fn test_parse_toml_still_works() {
        let toml_str = r#"
[policy]
default = "ask"

[[statements]]
effect = "allow"
entity = "agent:claude"
verb = "execute"
noun = "git *"
"#;
        let doc = parse_toml(toml_str).unwrap();
        assert_eq!(doc.policy.default, Effect::Ask);
        assert_eq!(doc.statements.len(), 1);
        assert!(doc.statements[0].matches("agent:claude", &Verb::Execute, "git status"));
    }

    // --- Filter expression parsing ---

    #[test]
    fn test_parse_filter_expr_subpath() {
        let expr = parse_filter_expr("subpath(.)").unwrap();
        assert_eq!(expr, FilterExpr::Subpath(".".into()));
    }

    #[test]
    fn test_parse_filter_expr_literal() {
        let expr = parse_filter_expr("literal(.env)").unwrap();
        assert_eq!(expr, FilterExpr::Literal(".env".into()));
    }

    #[test]
    fn test_parse_filter_expr_regex() {
        let expr = parse_filter_expr("regex(.*\\.rs$)").unwrap();
        assert_eq!(expr, FilterExpr::Regex(".*\\.rs$".into()));
    }

    #[test]
    fn test_parse_filter_expr_not() {
        let expr = parse_filter_expr("!literal(.env)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::Not(Box::new(FilterExpr::Literal(".env".into())))
        );
    }

    #[test]
    fn test_parse_filter_expr_and() {
        let expr = parse_filter_expr("subpath(.) & !literal(.env)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::And(
                Box::new(FilterExpr::Subpath(".".into())),
                Box::new(FilterExpr::Not(Box::new(FilterExpr::Literal(
                    ".env".into()
                ))))
            )
        );
    }

    #[test]
    fn test_parse_filter_expr_or() {
        let expr = parse_filter_expr("subpath(./src) | subpath(./test)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::Or(
                Box::new(FilterExpr::Subpath("./src".into())),
                Box::new(FilterExpr::Subpath("./test".into()))
            )
        );
    }

    #[test]
    fn test_parse_filter_expr_precedence() {
        // & binds tighter than |
        let expr = parse_filter_expr("subpath(./a) | subpath(./b) & !literal(.env)").unwrap();
        // Should parse as: a | (b & !.env)
        assert_eq!(
            expr,
            FilterExpr::Or(
                Box::new(FilterExpr::Subpath("./a".into())),
                Box::new(FilterExpr::And(
                    Box::new(FilterExpr::Subpath("./b".into())),
                    Box::new(FilterExpr::Not(Box::new(FilterExpr::Literal(
                        ".env".into()
                    ))))
                ))
            )
        );
    }

    #[test]
    fn test_parse_filter_expr_parens() {
        let expr = parse_filter_expr("(subpath(./a) | subpath(./b)) & !literal(.env)").unwrap();
        assert_eq!(
            expr,
            FilterExpr::And(
                Box::new(FilterExpr::Or(
                    Box::new(FilterExpr::Subpath("./a".into())),
                    Box::new(FilterExpr::Subpath("./b".into()))
                )),
                Box::new(FilterExpr::Not(Box::new(FilterExpr::Literal(
                    ".env".into()
                ))))
            )
        );
    }

    // --- Profile expression parsing ---

    #[test]
    fn test_parse_profile_expr_ref() {
        let expr = parse_profile_expr("sandboxed").unwrap();
        assert_eq!(expr, ProfileExpr::Ref("sandboxed".into()));
    }

    #[test]
    fn test_parse_profile_expr_and() {
        let expr = parse_profile_expr("local & safe-io").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::And(
                Box::new(ProfileExpr::Ref("local".into())),
                Box::new(ProfileExpr::Ref("safe-io".into()))
            )
        );
    }

    #[test]
    fn test_parse_profile_expr_or() {
        let expr = parse_profile_expr("a | b").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::Or(
                Box::new(ProfileExpr::Ref("a".into())),
                Box::new(ProfileExpr::Ref("b".into()))
            )
        );
    }

    #[test]
    fn test_parse_profile_expr_not() {
        let expr = parse_profile_expr("!unsafe").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::Not(Box::new(ProfileExpr::Ref("unsafe".into())))
        );
    }

    #[test]
    fn test_parse_profile_expr_complex() {
        let expr = parse_profile_expr("sandboxed & git-safe-args").unwrap();
        assert_eq!(
            expr,
            ProfileExpr::And(
                Box::new(ProfileExpr::Ref("sandboxed".into())),
                Box::new(ProfileExpr::Ref("git-safe-args".into()))
            )
        );
    }

    // --- Rule parsing with constraint suffix ---

    #[test]
    fn test_parse_rule_with_constraint() {
        let stmt = parse_rule("allow agent bash git * : strict-git").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.profile, Some(ProfileExpr::Ref("strict-git".into())));
    }

    #[test]
    fn test_parse_rule_with_inline_constraint() {
        let stmt = parse_rule("allow agent read * : local & no-secrets").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(
            stmt.profile,
            Some(ProfileExpr::And(
                Box::new(ProfileExpr::Ref("local".into())),
                Box::new(ProfileExpr::Ref("no-secrets".into()))
            ))
        );
    }

    #[test]
    fn test_parse_rule_without_constraint() {
        let stmt = parse_rule("deny agent bash rm *").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert_eq!(stmt.profile, None);
    }

    // --- YAML with constraints and profiles ---

    #[test]
    fn test_parse_yaml_with_constraints() {
        let yaml = r#"
default: deny

constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false

profiles:
  sandboxed: local & safe-io

rules:
  - "allow agent bash git * : sandboxed"
  - deny agent bash rm *
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Deny);
        assert_eq!(doc.constraints.len(), 2);
        assert!(doc.constraints.contains_key("local"));
        assert!(doc.constraints.contains_key("safe-io"));
        assert_eq!(doc.profiles.len(), 1);
        assert!(doc.profiles.contains_key("sandboxed"));
        assert_eq!(doc.statements.len(), 2);

        // First statement has a constraint
        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::Ref("sandboxed".into()))
        );
        // Second statement has no constraint
        assert_eq!(doc.statements[1].profile, None);
    }

    // --- Mapping-format rules ---

    #[test]
    fn test_parse_yaml_mapping_format() {
        let yaml = r#"
default: ask

rules:
  allow bash git * : strict-git
  allow bash cargo * : sandboxed
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 3);

        assert_eq!(doc.statements[0].effect, Effect::Allow);
        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::Ref("strict-git".into()))
        );
        assert!(doc.statements[0].matches("agent", &Verb::Execute, "git status"));

        assert_eq!(doc.statements[1].effect, Effect::Allow);
        assert_eq!(
            doc.statements[1].profile,
            Some(ProfileExpr::Ref("sandboxed".into()))
        );

        assert_eq!(doc.statements[2].effect, Effect::Deny);
        assert_eq!(doc.statements[2].profile, None);
        assert!(doc.statements[2].matches("agent", &Verb::Execute, "rm -rf /"));
    }

    #[test]
    fn test_parse_yaml_mapping_format_no_constraint() {
        let yaml = r#"
rules:
  allow bash git * : []
  allow read * :
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 3);

        // All should have no profile/constraint
        for stmt in &doc.statements {
            assert_eq!(stmt.profile, None, "expected no constraint for: {:?}", stmt);
        }
    }

    #[test]
    fn test_parse_yaml_mapping_format_with_constraints() {
        let yaml = r#"
default: deny

constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false

profiles:
  sandboxed: local & safe-io

rules:
  allow bash git * : sandboxed
  allow read * : local
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.policy.default, Effect::Deny);
        assert_eq!(doc.constraints.len(), 2);
        assert_eq!(doc.profiles.len(), 1);
        assert_eq!(doc.statements.len(), 3);

        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::Ref("sandboxed".into()))
        );
        assert_eq!(
            doc.statements[1].profile,
            Some(ProfileExpr::Ref("local".into()))
        );
        assert_eq!(doc.statements[2].profile, None);
    }

    #[test]
    fn test_parse_yaml_mapping_format_inline_constraint() {
        let yaml = r#"
rules:
  allow edit * : local & no-secrets
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 1);
        assert_eq!(
            doc.statements[0].profile,
            Some(ProfileExpr::And(
                Box::new(ProfileExpr::Ref("local".into())),
                Box::new(ProfileExpr::Ref("no-secrets".into()))
            ))
        );
    }

    #[test]
    fn test_parse_yaml_mapping_format_with_explicit_entity() {
        let yaml = r#"
rules:
  allow agent:claude bash git * : strict-git
  deny * bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 2);

        assert_eq!(
            doc.statements[0].entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
        assert_eq!(doc.statements[1].entity, Pattern::Match(MatchExpr::Any));
    }

    #[test]
    fn test_yaml_mapping_serialization_roundtrip() {
        let yaml = r#"
default: ask

constraints:
  safe-io:
    pipe: false

rules:
  allow bash git * : safe-io
  deny bash rm * : []
"#;
        let doc = parse_yaml(yaml).unwrap();
        let serialized = to_yaml(&doc).unwrap();
        let reparsed = parse_yaml(&serialized).unwrap();

        assert_eq!(doc.policy.default, reparsed.policy.default);
        assert_eq!(doc.statements.len(), reparsed.statements.len());
        for (a, b) in doc.statements.iter().zip(reparsed.statements.iter()) {
            assert_eq!(a.effect, b.effect);
            assert_eq!(a.profile, b.profile);
        }
    }

    // -----------------------------------------------------------------------
    // New-format parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_new_format_basic() {
        let yaml = r#"
default:
  permission: ask
  profile: basic

profiles:
  basic:
    rules:
      allow bash *:
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert!(doc.default_config.is_some());
        let dc = doc.default_config.as_ref().unwrap();
        assert_eq!(dc.permission, Effect::Ask);
        assert_eq!(dc.profile, "basic");
        assert_eq!(doc.profile_defs.len(), 1);
        let basic = &doc.profile_defs["basic"];
        assert_eq!(basic.rules.len(), 1);
        assert_eq!(basic.rules[0].effect, Effect::Allow);
        assert_eq!(basic.rules[0].verb, "bash");
    }

    #[test]
    fn test_parse_new_format_default_struct() {
        let yaml = r#"
default:
  permission: deny
  profile: locked

profiles:
  locked:
    rules:
      deny * *:
"#;
        let doc = parse_yaml(yaml).unwrap();
        let dc = doc.default_config.as_ref().unwrap();
        assert_eq!(dc.permission, Effect::Deny);
        assert_eq!(dc.profile, "locked");
    }

    #[test]
    fn test_parse_new_format_cap_scoped_fs() {
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      deny * *:
        fs:
          read + write: "subpath(~/.ssh)"
"#;
        let doc = parse_yaml(yaml).unwrap();
        let rule = &doc.profile_defs["test"].rules[0];
        let constraints = rule.constraints.as_ref().unwrap();
        let fs = constraints.fs.as_ref().unwrap();
        assert_eq!(fs.len(), 1);
        let (caps, filter) = &fs[0];
        assert_eq!(*caps, Cap::READ | Cap::WRITE);
        assert_eq!(*filter, FilterExpr::Subpath("~/.ssh".into()));
    }

    #[test]
    fn test_parse_new_format_args() {
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      allow bash *:
        args: ["!-delete", "--dry-run"]
"#;
        let doc = parse_yaml(yaml).unwrap();
        let rule = &doc.profile_defs["test"].rules[0];
        let constraints = rule.constraints.as_ref().unwrap();
        let args = constraints.args.as_ref().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], ArgSpec::Forbid("-delete".into()));
        assert_eq!(args[1], ArgSpec::Require("--dry-run".into()));
    }

    #[test]
    fn test_parse_new_format_include() {
        let yaml = r#"
default:
  permission: ask
  profile: child

profiles:
  parent:
    rules:
      deny bash rm *:
  child:
    include: parent
    rules:
      allow bash git *:
"#;
        let doc = parse_yaml(yaml).unwrap();
        let child = &doc.profile_defs["child"];
        assert_eq!(
            child.include.as_deref(),
            Some(["parent".to_string()].as_slice())
        );
        assert_eq!(child.rules.len(), 1);

        // Flatten should include parent rules first
        let flat = flatten_profile("child", &doc.profile_defs).unwrap();
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].effect, Effect::Deny); // parent rule
        assert_eq!(flat[0].verb, "bash");
        assert_eq!(flat[1].effect, Effect::Allow); // child rule
        assert_eq!(flat[1].verb, "bash");
    }

    #[test]
    fn test_parse_new_format_circular_include_error() {
        let yaml = r#"
default:
  permission: ask
  profile: a

profiles:
  a:
    include: b
    rules:
      allow bash *:
  b:
    include: a
    rules:
      allow read *:
"#;
        let result = parse_yaml(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("circular"),
            "expected circular error, got: {}",
            err
        );
    }

    #[test]
    fn test_parse_new_format_arbitrary_verb() {
        let yaml = r#"
default:
  permission: ask
  profile: test

profiles:
  test:
    rules:
      allow safe-read *:
        args: []
"#;
        let doc = parse_yaml(yaml).unwrap();
        let rule = &doc.profile_defs["test"].rules[0];
        assert_eq!(rule.effect, Effect::Allow);
        assert_eq!(rule.verb, "safe-read");
    }

    #[test]
    fn test_parse_old_format_still_works() {
        // Ensure old format still parses correctly when new format is added
        let yaml = r#"
default: ask

constraints:
  local:
    fs: subpath(.)

rules:
  - "allow * bash git * : local"
  - deny * bash rm *
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert!(doc.default_config.is_none());
        assert!(doc.profile_defs.is_empty());
        assert_eq!(doc.policy.default, Effect::Ask);
        assert_eq!(doc.statements.len(), 2);
    }

    // --- Custom tool name tests ---

    #[test]
    fn test_parse_rule_custom_tool() {
        // Custom tool with explicit entity
        let stmt = parse_rule("allow * task *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.verb, VerbPattern::Named("task".into()));
        assert_eq!(stmt.entity, Pattern::Match(MatchExpr::Any));
    }

    #[test]
    fn test_parse_rule_custom_tool_with_noun() {
        let stmt = parse_rule("deny * glob *.rs").unwrap();
        assert_eq!(stmt.effect, Effect::Deny);
        assert_eq!(stmt.verb, VerbPattern::Named("glob".into()));
    }

    #[test]
    fn test_parse_rule_custom_tool_with_entity() {
        let stmt = parse_rule("allow agent:claude websearch *").unwrap();
        assert_eq!(stmt.effect, Effect::Allow);
        assert_eq!(stmt.verb, VerbPattern::Named("websearch".into()));
        assert_eq!(
            stmt.entity,
            Pattern::Match(MatchExpr::Typed {
                entity_type: "agent".into(),
                name: Some("claude".into()),
            })
        );
    }

    #[test]
    fn test_format_rule_custom_tool_roundtrip() {
        let rules = vec![
            "allow * task *",
            "deny * glob *.rs",
            "allow agent:claude websearch *",
        ];
        for rule in rules {
            let stmt = parse_rule(rule).unwrap();
            let formatted = format_rule(&stmt);
            let reparsed = parse_rule(&formatted).unwrap();
            assert_eq!(
                stmt.effect, reparsed.effect,
                "effect mismatch for: {}",
                rule
            );
            assert_eq!(stmt.verb, reparsed.verb, "verb mismatch for: {}", rule);
        }
    }

    #[test]
    fn test_parse_yaml_custom_tool() {
        let yaml = r#"
default: ask

rules:
  - allow * task *
  - deny * websearch *
"#;
        let doc = parse_yaml(yaml).unwrap();
        assert_eq!(doc.statements.len(), 2);
        assert_eq!(doc.statements[0].verb, VerbPattern::Named("task".into()));
        assert_eq!(
            doc.statements[1].verb,
            VerbPattern::Named("websearch".into())
        );
    }

    #[test]
    fn test_verb_pattern_named_serde_roundtrip() {
        let pattern = VerbPattern::Named("task".into());
        let json = serde_json::to_string(&pattern).unwrap();
        let parsed: VerbPattern = serde_json::from_str(&json).unwrap();
        assert_eq!(pattern, parsed);
    }
}
