//! Rust-native implementation of the `policy()` Starlark function.
//!
//! Processes dict-form policy definitions, building match tree nodes from
//! nested key-value structures in typed Rust code for better error handling and safety.

use anyhow::{Context, bail};
use serde_json::{Value as JsonValue, json};
use starlark::values::dict::DictRef;
use starlark::values::list::ListRef;
use starlark::values::tuple::TupleRef;
use starlark::values::{Heap, Value};

use crate::builders::match_tree::{self as mt, MatchTreeNode, pattern_to_json};

/// Sandbox collection state threaded through tree building.
struct SandboxCollector {
    sandboxes: Vec<JsonValue>,
    seen: std::collections::HashSet<String>,
}

impl SandboxCollector {
    fn new() -> Self {
        Self {
            sandboxes: Vec::new(),
            seen: std::collections::HashSet::new(),
        }
    }

    fn collect_from_effect<'v>(&mut self, effect: Value<'v>, heap: &'v Heap) -> anyhow::Result<()> {
        let sandbox = effect
            .get_attr("_sandbox", heap)
            .ok()
            .flatten()
            .filter(|v| !v.is_none());

        if let Some(sb) = sandbox {
            if sb.get_type() == "struct" {
                if let Ok(Some(name_val)) = sb.get_attr("_name", heap) {
                    if let Some(name) = name_val.unpack_str() {
                        if self.seen.insert(name.to_string()) {
                            let sb_json = sandbox_to_json(sb, heap)?;
                            self.sandboxes.push(sb_json);
                        }
                    }
                }
            }
            // String sandbox names are resolved at document assembly time
        }
        Ok(())
    }
}

/// Convert an effect struct to a decision `MatchTreeNode`.
fn effect_to_decision<'v>(effect: Value<'v>, heap: &'v Heap) -> anyhow::Result<MatchTreeNode> {
    let kind = effect
        .get_attr("_effect", heap)
        .ok()
        .flatten()
        .and_then(|v| v.unpack_str().map(|s| s.to_string()))
        .context("effect struct missing _effect field")?;

    let sandbox_name = effect
        .get_attr("_sandbox", heap)
        .ok()
        .flatten()
        .filter(|v| !v.is_none())
        .map(|sb| {
            // If sandbox struct, get name; if string, use directly
            if sb.get_type() == "struct" {
                sb.get_attr("_name", heap)
                    .ok()
                    .flatten()
                    .and_then(|v| v.unpack_str().map(|s| s.to_string()))
            } else {
                sb.unpack_str().map(|s| s.to_string())
            }
        })
        .flatten();

    let decision = match kind.as_str() {
        "allow" => json!({"decision": {"allow": sandbox_name}}),
        "deny" => json!({"decision": "deny"}),
        "ask" => json!({"decision": {"ask": sandbox_name}}),
        other => bail!("unknown effect: {other}"),
    };
    Ok(MatchTreeNode { json: decision })
}

/// Check if a Starlark value is an effect struct (has `_is_effect = True`).
fn is_effect<'v>(value: Value<'v>, heap: &'v Heap) -> bool {
    value.get_type() == "struct"
        && value
            .get_attr("_is_effect", heap)
            .ok()
            .flatten()
            .and_then(|v| v.unpack_bool())
            .unwrap_or(false)
}

/// Expand a value into a list of individual keys (handling tuples).
fn expand_keys<'v>(key: Value<'v>) -> Vec<Value<'v>> {
    if let Some(tuple) = TupleRef::from_value(key) {
        tuple.iter().collect()
    } else {
        vec![key]
    }
}

/// Classify what kind of match key a Starlark value represents.
#[allow(dead_code)]
enum MatchKeyKind {
    Default {
        doc: Option<String>,
    },
    Mode {
        pattern: JsonValue,
        doc: Option<String>,
    },
    Tool {
        pattern: JsonValue,
        doc: Option<String>,
    },
    Path {
        value: JsonValue,
        doc: Option<String>,
    },
    Glob {
        value: JsonValue,
        doc: Option<String>,
    },
    Domain {
        value: JsonValue,
        doc: Option<String>,
    },
    Localhost {
        ports: JsonValue,
        doc: Option<String>,
    },
}

/// Classify a **root-level** key in a policy/sandbox tree. Requires a typed
/// constructor (struct with `_match_key`). Bare strings are rejected.
fn classify_root_key<'v>(key: Value<'v>, heap: &'v Heap) -> anyhow::Result<MatchKeyKind> {
    if key.get_type() == "struct"
        && let Ok(Some(mk_val)) = key.get_attr("_match_key", heap)
        && let Some(mk) = mk_val.unpack_str()
    {
        let doc = key
            .get_attr("_doc", heap)
            .ok()
            .flatten()
            .filter(|v| !v.is_none())
            .and_then(|v| v.unpack_str().map(|s| s.to_string()));

        // `default()` has no _match_value.
        if mk == "default" {
            return Ok(MatchKeyKind::Default { doc });
        }

        let mv = key
            .get_attr("_match_value", heap)
            .ok()
            .flatten()
            .context("match key struct missing _match_value")?;

        return match mk {
            "mode" => Ok(MatchKeyKind::Mode {
                pattern: pattern_to_json(mv, heap)?,
                doc,
            }),
            "tool" => Ok(MatchKeyKind::Tool {
                pattern: pattern_to_json(mv, heap)?,
                doc,
            }),
            "path" => Ok(MatchKeyKind::Path {
                value: pattern_to_json(mv, heap)?,
                doc,
            }),
            "glob" => Ok(MatchKeyKind::Glob {
                value: pattern_to_json(mv, heap)?,
                doc,
            }),
            "domain" => Ok(MatchKeyKind::Domain {
                value: pattern_to_json(mv, heap)?,
                doc,
            }),
            "localhost" => Ok(MatchKeyKind::Localhost {
                ports: pattern_to_json(mv, heap)?,
                doc,
            }),
            other => bail!("unknown match key type: {other}"),
        };
    }
    bail!(
        "Root keys in a policy or sandbox tree must use a typed constructor \
         (default(), mode(), tool(), path(), glob(), domain(), localhost()). \
         Got a bare {} key. If you meant a filesystem path, use path(\"...\"). \
         If you meant a tool name, use tool(\"...\").",
        key.get_type()
    )
}

#[allow(dead_code)]
fn classify_nested_key<'v>(key: Value<'v>, heap: &'v Heap) -> anyhow::Result<MatchKeyKind> {
    // Check for typed match key struct (Mode() / Tool() / mode())
    if key.get_type() == "struct" {
        if let Ok(Some(mk_val)) = key.get_attr("_match_key", heap) {
            if let Some(mk) = mk_val.unpack_str() {
                let match_value = key
                    .get_attr("_match_value", heap)
                    .ok()
                    .flatten()
                    .context("match key struct missing _match_value")?;
                let pattern = pattern_to_json(match_value, heap)?;
                let doc = key
                    .get_attr("_doc", heap)
                    .ok()
                    .flatten()
                    .filter(|v| !v.is_none())
                    .and_then(|v| v.unpack_str().map(|s| s.to_string()));
                return match mk {
                    "mode" => Ok(MatchKeyKind::Mode { pattern, doc }),
                    "tool" => Ok(MatchKeyKind::Tool { pattern, doc }),
                    other => bail!("unknown match key type: {other}"),
                };
            }
        }
    }

    // Raw string or None = tool name
    let pattern = pattern_to_json(key, heap)?;
    Ok(MatchKeyKind::Tool { pattern, doc: None })
}

/// Build condition node for a tool-level key.
fn build_tool_condition(
    pattern: JsonValue,
    doc: Option<String>,
    source: Option<String>,
) -> MatchTreeNode {
    mt::mt_condition_with_doc(json!("tool_name"), pattern, doc, source)
}

/// Build condition node for a mode-level key.
fn build_mode_condition(
    pattern: JsonValue,
    doc: Option<String>,
    source: Option<String>,
) -> MatchTreeNode {
    mt::mt_condition_with_doc(json!("mode"), pattern, doc, source)
}

/// Recursively build positional-arg tree from nested dicts.
fn build_arg_tree<'v>(
    dict: &DictRef<'v>,
    arg_index: usize,
    heap: &'v Heap,
    collector: &mut SandboxCollector,
) -> anyhow::Result<Vec<MatchTreeNode>> {
    let mut nodes = Vec::new();
    for (key, value) in dict.iter() {
        for k in expand_keys(key) {
            let pattern = pattern_to_json(k, heap)?;
            let cond = mt::mt_condition_with_doc(
                json!({"positional_arg": arg_index}),
                pattern,
                None,
                None,
            );

            let node = if let Some(inner_dict) = DictRef::from_value(value) {
                let children = build_arg_tree(&inner_dict, arg_index + 1, heap, collector)?;
                set_children_on_node(&cond, children)?
            } else if is_effect(value, heap) {
                let decision = effect_to_decision(value, heap)?;
                collector.collect_from_effect(value, heap)?;
                set_children_on_node(&cond, vec![decision])?
            } else {
                bail!(
                    "policy dict values must be effect descriptors (allow/deny/ask) or dicts, got {}",
                    value.get_type()
                )
            };
            nodes.push(node);
        }
    }
    Ok(nodes)
}

/// Build tool-level children from a dict (used inside Mode keys).
fn build_tool_level<'v>(
    dict: &DictRef<'v>,
    heap: &'v Heap,
    source: &Option<String>,
    collector: &mut SandboxCollector,
) -> anyhow::Result<Vec<MatchTreeNode>> {
    let mut nodes = Vec::new();
    for (key, value) in dict.iter() {
        for k in expand_keys(key) {
            // Inside a mode, keys are tool names (string, Tool(), or glob/struct)
            let (name, doc) = if k.get_type() == "struct" {
                if let Ok(Some(mk_val)) = k.get_attr("_match_key", heap) {
                    if mk_val.unpack_str() == Some("tool") {
                        let mv = k
                            .get_attr("_match_value", heap)
                            .ok()
                            .flatten()
                            .context("Tool() missing _match_value")?;
                        (mv, None)
                    } else {
                        (k, None)
                    }
                } else {
                    // Could be a glob or other struct — pass through to pattern_to_json
                    (k, None)
                }
            } else {
                (k, None)
            };

            let pattern = pattern_to_json(name, heap)?;
            let tool_cond = build_tool_condition(pattern, doc, source.clone());
            let node = build_value_children(tool_cond, value, heap, source, collector)?;
            nodes.push(node);
        }
    }
    Ok(nodes)
}

/// Build children for a condition from a value (effect or nested dict).
fn build_value_children<'v>(
    cond: MatchTreeNode,
    value: Value<'v>,
    heap: &'v Heap,
    _source: &Option<String>,
    collector: &mut SandboxCollector,
) -> anyhow::Result<MatchTreeNode> {
    if let Some(inner_dict) = DictRef::from_value(value) {
        let children = build_arg_tree(&inner_dict, 0, heap, collector)?;
        set_children_on_node(&cond, children)
    } else if is_effect(value, heap) {
        let decision = effect_to_decision(value, heap)?;
        collector.collect_from_effect(value, heap)?;
        set_children_on_node(&cond, vec![decision])
    } else {
        bail!(
            "policy dict values must be effect descriptors (allow/deny/ask) or dicts, got {}",
            value.get_type()
        )
    }
}

/// Set children on a `MatchTreeNode` condition.
fn set_children_on_node(
    cond: &MatchTreeNode,
    children: Vec<MatchTreeNode>,
) -> anyhow::Result<MatchTreeNode> {
    let child_json: Vec<JsonValue> = children.into_iter().map(|n| n.json).collect();
    let mut json = cond.json.clone();
    mt::set_children_on_deepest_leaf_pub(&mut json, child_json);
    Ok(MatchTreeNode { json })
}

// ---------------------------------------------------------------------------
// Public API: policy()
// ---------------------------------------------------------------------------

/// Rust-native implementation of `policy()`.
///
/// Handles dict form only, collects sandboxes,
/// and registers the policy into EvalContext.
pub fn policy_impl<'v>(
    _name: &str,
    rules_or_dict: Value<'v>,
    default_sandbox: Value<'v>,
    heap: &'v Heap,
    source: Option<String>,
) -> anyhow::Result<(Vec<JsonValue>, Vec<JsonValue>)> {
    let mut flat_nodes: Vec<JsonValue> = Vec::new();
    let mut collector = SandboxCollector::new();

    // Dict form
    if !rules_or_dict.is_none() {
        if let Some(dict) = DictRef::from_value(rules_or_dict) {
            process_policy_dict(&dict, heap, &source, &mut flat_nodes, &mut collector)?;
        }
    }

    // default_sandbox
    if !default_sandbox.is_none() {
        if default_sandbox.get_type() == "struct" {
            if let Ok(Some(name_val)) = default_sandbox.get_attr("_name", heap) {
                if let Some(sb_name) = name_val.unpack_str() {
                    if collector.seen.insert(sb_name.to_string()) {
                        let sb_json = sandbox_to_json(default_sandbox, heap)?;
                        collector.sandboxes.push(sb_json);
                    }
                }
            }
        }
    }

    Ok((flat_nodes, collector.sandboxes))
}

/// Process the dict form of policy().
fn process_policy_dict<'v>(
    dict: &DictRef<'v>,
    heap: &'v Heap,
    source: &Option<String>,
    flat_nodes: &mut Vec<JsonValue>,
    collector: &mut SandboxCollector,
) -> anyhow::Result<()> {
    for (key, value) in dict.iter() {
        for k in expand_keys(key) {
            match classify_root_key(k, heap)? {
                MatchKeyKind::Default { .. } => {
                    bail!("sandbox-only key default used in policy root");
                }
                MatchKeyKind::Path { .. } => {
                    bail!("sandbox-only key path used in policy root");
                }
                MatchKeyKind::Glob { .. } => {
                    bail!("sandbox-only key glob used in policy root");
                }
                MatchKeyKind::Domain { .. } => {
                    bail!("sandbox-only key domain used in policy root");
                }
                MatchKeyKind::Localhost { .. } => {
                    bail!("sandbox-only key localhost used in policy root");
                }
                MatchKeyKind::Mode { pattern, doc } => {
                    let cond = build_mode_condition(pattern, doc, source.clone());
                    let node = if let Some(inner_dict) = DictRef::from_value(value) {
                        let children = build_tool_level(&inner_dict, heap, source, collector)?;
                        set_children_on_node(&cond, children)?
                    } else if is_effect(value, heap) {
                        let decision = effect_to_decision(value, heap)?;
                        collector.collect_from_effect(value, heap)?;
                        set_children_on_node(&cond, vec![decision])?
                    } else {
                        bail!("policy dict values must be effects (allow/deny/ask) or dicts")
                    };
                    flat_nodes.push(node.json);
                }
                MatchKeyKind::Tool { pattern, doc } => {
                    let cond = build_tool_condition(pattern, doc, source.clone());
                    let node = build_value_children(cond, value, heap, source, collector)?;
                    flat_nodes.push(node.json);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sandbox conversion (replaces _sandbox_to_json / _resolve_path_value)
// ---------------------------------------------------------------------------

/// Shared assembly: build the sandbox JSON from already-converted parts.
/// Both the legacy struct path (`sandbox_to_json`) and the new tree path
/// (`sandbox_tree_impl`) feed this function so the wire format stays in sync.
fn build_sandbox_json(
    name: &str,
    default_effect: &str,
    rules: Vec<JsonValue>,
    network: JsonValue,
    doc: Option<String>,
) -> JsonValue {
    let default_caps = if default_effect == "deny" {
        json!(["execute"])
    } else {
        json!(["read", "write", "create", "delete", "execute"])
    };
    let mut result = json!({
        "name": name,
        "default": default_caps,
        "rules": rules,
        "network": network,
    });
    if let Some(d) = doc {
        result
            .as_object_mut()
            .unwrap()
            .insert("doc".to_string(), json!(d));
    }
    result
}

/// Extract the effect string ("allow"/"deny"/"ask") from an effect struct.
fn effect_to_string<'v>(value: Value<'v>, heap: &'v Heap) -> anyhow::Result<String> {
    if let Some(s) = value.unpack_str() {
        return Ok(s.to_string());
    }
    if !is_effect(value, heap) {
        bail!(
            "expected an effect (allow()/deny()/ask()), got {}",
            value.get_type()
        );
    }
    let kind = value
        .get_attr("_effect", heap)
        .ok()
        .flatten()
        .and_then(|v| v.unpack_str().map(|s| s.to_string()))
        .context("effect struct missing _effect")?;
    Ok(kind)
}

/// Compute capability list from an effect struct's `_read`/`_write`/...
/// flags. Mirrors the logic of stdlib `_caps_from_effect`.
fn caps_from_effect<'v>(eff: Value<'v>, heap: &'v Heap) -> anyhow::Result<Vec<String>> {
    let get_bool = |name: &str| -> Option<bool> {
        eff.get_attr(name, heap)
            .ok()
            .flatten()
            .and_then(|v| v.unpack_bool())
    };
    let r = get_bool("_read");
    let w = get_bool("_write");
    let c = get_bool("_create");
    let d = get_bool("_delete");
    let x = get_bool("_execute");
    if r.is_none() && w.is_none() && c.is_none() && d.is_none() && x.is_none() {
        return Ok(vec![
            "read".into(),
            "write".into(),
            "create".into(),
            "delete".into(),
            "execute".into(),
        ]);
    }
    let mut caps = Vec::new();
    if r == Some(true) {
        caps.push("read".to_string());
    }
    if w == Some(true) {
        caps.push("write".to_string());
    }
    if c == Some(true) {
        caps.push("create".to_string());
    }
    if d == Some(true) {
        caps.push("delete".to_string());
    }
    if x == Some(true) {
        caps.push("execute".to_string());
    }
    Ok(caps)
}

/// Build an fs rule JSON from an effect value at a typed path/glob key.
fn fs_rule_from<'v>(
    effect: Value<'v>,
    path_str: String,
    doc: Option<String>,
    match_type: &str,
    heap: &'v Heap,
) -> anyhow::Result<JsonValue> {
    if !is_effect(effect, heap) {
        bail!(
            "sandbox tree fs values must be effects (allow/deny/ask), got {}",
            effect.get_type()
        );
    }
    let eff_str = effect_to_string(effect, heap)?;
    let caps = caps_from_effect(effect, heap)?;
    let mut rule = json!({
        "effect": eff_str,
        "caps": caps,
        "path": path_str,
        "path_match": match_type,
    });
    if let Some(d) = doc {
        rule.as_object_mut()
            .unwrap()
            .insert("doc".to_string(), json!(d));
    }
    Ok(rule)
}

/// Inject the system rules that the legacy `sandbox()` builder used to add:
/// allow `read` on `/` (subpath), deny everything on the user-home root.
fn append_system_rules(rules: &mut Vec<JsonValue>) {
    let user_homes = if std::env::consts::OS == "macos" {
        "/Users"
    } else {
        "/home"
    };
    rules.push(json!({
        "effect": "allow",
        "caps": ["read"],
        "path": "/",
        "path_match": "subpath",
    }));
    rules.push(json!({
        "effect": "deny",
        "caps": ["read", "write", "create", "delete", "execute"],
        "path": user_homes,
        "path_match": "subpath",
    }));
}

/// Build the JSON `network` field from collected sandbox-tree net pieces.
fn build_network_json(
    domains: Vec<String>,
    localhost: Option<bool>,
    localhost_ports: Vec<i64>,
) -> JsonValue {
    let has_localhost = localhost == Some(true) || !localhost_ports.is_empty();
    let has_domains = !domains.is_empty();
    if !has_localhost && !has_domains {
        return json!("deny");
    }
    if has_domains && !has_localhost {
        return json!({ "allow_domains": domains });
    }
    if has_localhost && !has_domains {
        if localhost_ports.is_empty() {
            return json!("localhost");
        }
        return json!({ "localhost": localhost_ports });
    }
    // Both — emit allow_domains plus localhost.
    let mut obj = serde_json::Map::new();
    obj.insert("allow_domains".to_string(), json!(domains));
    if localhost_ports.is_empty() {
        obj.insert("localhost".to_string(), json!(true));
    } else {
        obj.insert("localhost".to_string(), json!(localhost_ports));
    }
    JsonValue::Object(obj)
}

/// Process a unified sandbox-tree dict into a complete sandbox JSON value.
pub fn sandbox_tree_impl<'v>(
    name: &str,
    tree: Value<'v>,
    default_effect_kwarg: &str,
    doc: Option<String>,
    heap: &'v Heap,
    _source: Option<String>,
) -> anyhow::Result<JsonValue> {
    let dict = DictRef::from_value(tree)
        .ok_or_else(|| anyhow::anyhow!("sandbox() tree must be a dict"))?;

    let mut default_effect = default_effect_kwarg.to_string();
    let mut fs_rules: Vec<JsonValue> = Vec::new();
    let mut net_domains: Vec<String> = Vec::new();
    let mut net_localhost_allow: Option<bool> = None;
    let mut net_localhost_ports: Vec<i64> = Vec::new();

    for (key, value) in dict.iter() {
        let raw_mv = key
            .get_attr("_match_value", heap)
            .ok()
            .flatten()
            .and_then(|v| v.unpack_str().map(|s| s.to_string()));
        let raw_ports: Vec<i64> = key
            .get_attr("_match_value", heap)
            .ok()
            .flatten()
            .and_then(|v| {
                ListRef::from_value(v).map(|list| {
                    list.iter()
                        .filter_map(|item| item.unpack_i32().map(|n| n as i64))
                        .collect()
                })
            })
            .unwrap_or_default();
        let key_doc = key
            .get_attr("_doc", heap)
            .ok()
            .flatten()
            .filter(|v| !v.is_none())
            .and_then(|v| v.unpack_str().map(|s| s.to_string()));

        match classify_root_key(key, heap)? {
            MatchKeyKind::Default { .. } => {
                default_effect = effect_to_string(value, heap)?;
            }
            MatchKeyKind::Path { .. } => {
                let pv = raw_mv
                    .ok_or_else(|| anyhow::anyhow!("path() key missing string value"))?;
                fs_rules.push(fs_rule_from(value, pv, key_doc, "literal", heap)?);
            }
            MatchKeyKind::Glob { .. } => {
                let pv = raw_mv
                    .ok_or_else(|| anyhow::anyhow!("glob() key missing string value"))?;
                fs_rules.push(fs_rule_from(value, pv, key_doc, "glob", heap)?);
            }
            MatchKeyKind::Domain { .. } => {
                let dn = raw_mv
                    .ok_or_else(|| anyhow::anyhow!("domain() key must be a string"))?;
                let _eff = effect_to_string(value, heap)?;
                net_domains.push(dn);
            }
            MatchKeyKind::Localhost { .. } => {
                let eff = effect_to_string(value, heap)?;
                if eff == "allow" {
                    net_localhost_allow = Some(true);
                }
                net_localhost_ports.extend(raw_ports);
            }
            MatchKeyKind::Mode { .. } | MatchKeyKind::Tool { .. } => {
                bail!("mode()/tool() are policy-only keys; not allowed in a sandbox tree");
            }
        }
    }

    append_system_rules(&mut fs_rules);

    let network = build_network_json(net_domains, net_localhost_allow, net_localhost_ports);
    Ok(build_sandbox_json(name, &default_effect, fs_rules, network, doc))
}

/// Convert a sandbox Starlark struct to JSON.
pub fn sandbox_to_json<'v>(sb: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    let name = sb
        .get_attr("_name", heap)
        .ok()
        .flatten()
        .and_then(|v| v.unpack_str().map(|s| s.to_string()))
        .context("sandbox missing _name")?;

    let default_effect = sb
        .get_attr("_default", heap)
        .ok()
        .flatten()
        .and_then(|v| v.unpack_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "deny".to_string());

    // FS rules
    let mut rules = Vec::new();
    if let Ok(Some(fs_rules_val)) = sb.get_attr("_fs_rules", heap) {
        if let Some(fs_list) = ListRef::from_value(fs_rules_val) {
            for rule_item in fs_list.iter() {
                let rule_json = convert_fs_rule(rule_item, heap)?;
                rules.push(rule_json);
            }
        }
    }

    // Network policy
    let net = convert_net_policy(sb, heap)?;

    let doc = sb
        .get_attr("_doc", heap)
        .ok()
        .flatten()
        .and_then(|v| v.unpack_str().map(|s| s.to_string()));

    Ok(build_sandbox_json(&name, &default_effect, rules, net, doc))
}

fn convert_fs_rule<'v>(rule: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    // rule is a Starlark dict with keys: path_value, caps, effect, match_type, follow_worktrees, doc
    let rule_dict =
        DictRef::from_value(rule).ok_or_else(|| anyhow::anyhow!("fs rule must be a dict"))?;

    let dict_get = |key: &str| -> Option<Value<'v>> {
        let key_val = heap.alloc_str(key);
        rule_dict.get(key_val.to_value()).ok().flatten()
    };

    let get_str = |key: &str| -> Option<String> {
        dict_get(key).and_then(|v| v.unpack_str().map(|s| s.to_string()))
    };

    let path_value =
        dict_get("path_value").ok_or_else(|| anyhow::anyhow!("fs rule missing path_value"))?;
    let path_str = resolve_path_value(path_value, heap)?;
    let effect = get_str("effect").unwrap_or_else(|| "allow".to_string());
    let match_type = get_str("match_type").unwrap_or_else(|| "literal".to_string());

    // Get caps list
    let caps = dict_get("caps")
        .and_then(|v| {
            ListRef::from_value(v).map(|list| {
                list.iter()
                    .filter_map(|item| item.unpack_str().map(|s| json!(s)))
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_else(|| vec![json!("read"), json!("write"), json!("create")]);

    let mut rule_json = json!({
        "effect": effect,
        "caps": caps,
        "path": path_str,
        "path_match": match_type,
    });

    // Optional follow_worktrees
    if let Some(fw) = dict_get("follow_worktrees") {
        if fw.unpack_bool() == Some(true) {
            rule_json
                .as_object_mut()
                .unwrap()
                .insert("follow_worktrees".to_string(), json!(true));
        }
    }

    // Optional doc
    if let Some(doc) = dict_get("doc") {
        if let Some(s) = doc.unpack_str() {
            rule_json
                .as_object_mut()
                .unwrap()
                .insert("doc".to_string(), json!(s));
        }
    }

    Ok(rule_json)
}

fn convert_net_policy<'v>(sb: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    let net_policy = sb.get_attr("_net_policy", heap).ok().flatten();

    match net_policy {
        None => Ok(json!("deny")),
        Some(v) if v.is_none() => Ok(json!("deny")),
        Some(v) if v.unpack_str().is_some() => Ok(json!(v.unpack_str().unwrap())),
        Some(v) if DictRef::from_value(v).is_some() => {
            // Dict — check for _localhost_ports key
            let dict = DictRef::from_value(v).unwrap();
            let key = heap.alloc_str("_localhost_ports");
            if let Ok(Some(ports_val)) = dict.get(key.to_value()) {
                if let Some(ports_list) = ListRef::from_value(ports_val) {
                    let ports: Vec<u16> = ports_list
                        .iter()
                        .filter_map(|item| item.unpack_i32().map(|n| n as u16))
                        .collect();
                    if ports.is_empty() {
                        return Ok(json!("localhost"));
                    }
                    return Ok(json!({"localhost": ports}));
                }
            }
            Ok(json!("deny"))
        }
        Some(v) if ListRef::from_value(v).is_some() => {
            // List of domain rules — check for stored domain names
            let domain_names = sb
                .get_attr("_net_domain_names", heap)
                .ok()
                .flatten()
                .and_then(|v| {
                    ListRef::from_value(v).map(|list| {
                        list.iter()
                            .filter_map(|item| item.unpack_str().map(|s| s.to_string()))
                            .collect::<Vec<String>>()
                    })
                })
                .unwrap_or_default();

            if domain_names.is_empty() {
                Ok(json!("localhost"))
            } else {
                Ok(json!({"allow_domains": domain_names}))
            }
        }
        _ => Ok(json!("deny")),
    }
}

/// Convert a Starlark path value to a `$ENV`-style string.
fn resolve_path_value<'v>(pv: Value<'v>, heap: &'v Heap) -> anyhow::Result<String> {
    if let Some(s) = pv.unpack_str() {
        return Ok(s.to_string());
    }
    if pv.get_type() == "struct" {
        if let Ok(Some(env_val)) = pv.get_attr("_env", heap) {
            if let Some(env_name) = env_val.unpack_str() {
                return Ok(format!("${env_name}"));
            }
        }
        if let Ok(Some(join_val)) = pv.get_attr("_join", heap) {
            if let Some(list) = ListRef::from_value(join_val) {
                let parts: Result<Vec<_>, _> =
                    list.iter().map(|v| resolve_path_value(v, heap)).collect();
                return Ok(parts?.join("/"));
            }
        }
    }
    Ok(pv.to_str())
}
