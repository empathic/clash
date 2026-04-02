//! Rust-native implementation of the `when()` and `policy()` Starlark functions.
//!
//! These replace the complex dict-processing logic that was previously in std.star,
//! moving tree building into typed Rust code for better error handling and safety.

use anyhow::{bail, Context};
use serde_json::{json, Value as JsonValue};
use starlark::values::dict::DictRef;
use starlark::values::list::ListRef;
use starlark::values::tuple::TupleRef;
use starlark::values::{Heap, Value, ValueLike};

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
enum MatchKeyKind {
    Mode {
        pattern: JsonValue,
        doc: Option<String>,
    },
    Tool {
        pattern: JsonValue,
        doc: Option<String>,
    },
}

fn classify_key<'v>(key: Value<'v>, heap: &'v Heap) -> anyhow::Result<MatchKeyKind> {
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
                    "when() values must be effect descriptors (allow/deny/ask) or dicts, got {}",
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
            "when() values must be effect descriptors (allow/deny/ask) or dicts, got {}",
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
// Public API: when()
// ---------------------------------------------------------------------------

/// Rust-native implementation of `when(tree)`.
///
/// Walks the dict tree, dispatching on key types (Mode/Tool/string/tuple),
/// and produces a list of `MatchTreeNode` values with collected sandboxes.
pub fn when_impl<'v>(
    tree: Value<'v>,
    heap: &'v Heap,
    source: Option<String>,
) -> anyhow::Result<(Vec<MatchTreeNode>, Vec<JsonValue>)> {
    let dict = DictRef::from_value(tree)
        .ok_or_else(|| anyhow::anyhow!("when() requires a dict argument, got {}", tree.get_type()))?;

    let mut collector = SandboxCollector::new();
    let mut result = Vec::new();

    for (key, value) in dict.iter() {
        for k in expand_keys(key) {
            match classify_key(k, heap)? {
                MatchKeyKind::Mode { pattern, doc } => {
                    let cond = build_mode_condition(pattern, doc, source.clone());
                    let node = if let Some(inner_dict) = DictRef::from_value(value) {
                        let children =
                            build_tool_level(&inner_dict, heap, &source, &mut collector)?;
                        set_children_on_node(&cond, children)?
                    } else if is_effect(value, heap) {
                        let decision = effect_to_decision(value, heap)?;
                        collector.collect_from_effect(value, heap)?;
                        set_children_on_node(&cond, vec![decision])?
                    } else {
                        bail!("Mode() value must be a dict of tools or an effect")
                    };
                    result.push(node);
                }
                MatchKeyKind::Tool { pattern, doc } => {
                    let cond = build_tool_condition(pattern, doc, source.clone());
                    let node =
                        build_value_children(cond, value, heap, &source, &mut collector)?;
                    result.push(node);
                }
            }
        }
    }

    Ok((result, collector.sandboxes))
}

// ---------------------------------------------------------------------------
// Public API: policy()
// ---------------------------------------------------------------------------

/// Rust-native implementation of `policy()`.
///
/// Handles both dict form and rules/list form, collects sandboxes,
/// and registers the policy into EvalContext.
pub fn policy_impl<'v>(
    _name: &str,
    rules_or_dict: Value<'v>,
    rules: Option<Value<'v>>,
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
        } else if let Some(list) = ListRef::from_value(rules_or_dict) {
            // List passed as positional arg
            process_rules_list(&list, heap, &mut flat_nodes, &mut collector)?;
        }
    }

    // Named rules= kwarg
    if let Some(rules_val) = rules {
        if let Some(list) = ListRef::from_value(rules_val) {
            process_rules_list(&list, heap, &mut flat_nodes, &mut collector)?;
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
            match classify_key(k, heap)? {
                MatchKeyKind::Mode { pattern, doc } => {
                    let cond = build_mode_condition(pattern, doc, source.clone());
                    let node = if let Some(inner_dict) = DictRef::from_value(value) {
                        let children =
                            build_tool_level(&inner_dict, heap, source, collector)?;
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

/// Process the rules/list form of policy().
fn process_rules_list<'v>(
    list: &ListRef<'v>,
    heap: &'v Heap,
    flat_nodes: &mut Vec<JsonValue>,
    collector: &mut SandboxCollector,
) -> anyhow::Result<()> {
    for item in list.iter() {
        // Path builder result (e.g., cwd().allow())
        if item.get_type() == "struct" {
            if let Ok(Some(is_path)) = item.get_attr("_is_path", heap) {
                if is_path.unpack_bool() == Some(true) {
                    if let Ok(Some(nodes_val)) = item.get_attr("_nodes", heap) {
                        if let Some(node_list) = ListRef::from_value(nodes_val) {
                            for node_item in node_list.iter() {
                                if let Some(node) = node_item.downcast_ref::<MatchTreeNode>() {
                                    flat_nodes.push(node.json.clone());
                                }
                            }
                        }
                    }
                    continue;
                }
            }
        }

        // List from when() — each item is a MatchTreeNode
        if let Some(sub_list) = ListRef::from_value(item) {
            for sub in sub_list.iter() {
                extract_node(sub, heap, flat_nodes, collector)?;
            }
            continue;
        }

        // Direct MatchTreeNode
        if let Some(node) = item.downcast_ref::<MatchTreeNode>() {
            flat_nodes.push(node.json.clone());
            continue;
        }

        // Struct with _node field (legacy when() return format)
        extract_node(item, heap, flat_nodes, collector)?;
    }
    Ok(())
}

/// Extract a node from a struct wrapper or direct MatchTreeNode.
fn extract_node<'v>(
    item: Value<'v>,
    heap: &'v Heap,
    flat_nodes: &mut Vec<JsonValue>,
    collector: &mut SandboxCollector,
) -> anyhow::Result<()> {
    if let Some(node) = item.downcast_ref::<MatchTreeNode>() {
        flat_nodes.push(node.json.clone());
        return Ok(());
    }

    if item.get_type() == "struct" {
        // Extract _node
        if let Ok(Some(node_val)) = item.get_attr("_node", heap) {
            if let Some(node) = node_val.downcast_ref::<MatchTreeNode>() {
                flat_nodes.push(node.json.clone());
            }
        }

        // Extract _sandbox
        if let Ok(Some(sb_val)) = item.get_attr("_sandbox", heap) {
            if !sb_val.is_none() && sb_val.get_type() == "struct" {
                if let Ok(Some(name_val)) = sb_val.get_attr("_name", heap) {
                    if let Some(name) = name_val.unpack_str() {
                        if collector.seen.insert(name.to_string()) {
                            let sb_json = sandbox_to_json(sb_val, heap)?;
                            collector.sandboxes.push(sb_json);
                        }
                    }
                }
            }
        }

        // Extract _cmd_sandboxes (from when() results)
        if let Ok(Some(cmd_sb)) = item.get_attr("_cmd_sandboxes", heap) {
            if let Some(sb_list) = ListRef::from_value(cmd_sb) {
                for sb_item in sb_list.iter() {
                    let sb_json = crate::globals::starlark_to_json(sb_item)?;
                    if let Some(name) = sb_json.get("name").and_then(|n| n.as_str()) {
                        if collector.seen.insert(name.to_string()) {
                            collector.sandboxes.push(sb_json);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sandbox conversion (replaces _sandbox_to_json / _resolve_path_value)
// ---------------------------------------------------------------------------

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

    // Default caps
    let default_caps = if default_effect == "deny" {
        json!(["execute"])
    } else {
        json!(["read", "write", "create", "delete", "execute"])
    };

    let mut result = json!({
        "name": name,
        "default": default_caps,
        "rules": rules,
        "network": net,
    });

    // Optional doc
    if let Ok(Some(doc_val)) = sb.get_attr("_doc", heap) {
        if let Some(doc) = doc_val.unpack_str() {
            result
                .as_object_mut()
                .unwrap()
                .insert("doc".to_string(), json!(doc));
        }
    }

    Ok(result)
}

fn convert_fs_rule<'v>(rule: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    // rule is a Starlark dict with keys: path_value, caps, effect, match_type, follow_worktrees, doc
    let rule_dict = DictRef::from_value(rule)
        .ok_or_else(|| anyhow::anyhow!("fs rule must be a dict"))?;

    let dict_get = |key: &str| -> Option<Value<'v>> {
        let key_val = heap.alloc_str(key);
        rule_dict.get(key_val.to_value()).ok().flatten()
    };

    let get_str = |key: &str| -> Option<String> {
        dict_get(key).and_then(|v| v.unpack_str().map(|s| s.to_string()))
    };

    let path_value = dict_get("path_value")
        .ok_or_else(|| anyhow::anyhow!("fs rule missing path_value"))?;
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
