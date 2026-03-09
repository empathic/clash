//! Starlark builders for match tree IR.
//!
//! These produce JSON that deserializes to `clash::policy::match_tree::CompiledPolicy`.
//! The builders emit tree-shaped policies where capability domains are compile-time
//! sugar, not IR concepts.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::{Value as JsonValue, json};
use starlark::starlark_simple_value;
use starlark::values::list::ListRef;
use starlark::values::{
    Heap, ProvidesStaticType, StarlarkValue, Trace, Value, ValueLike, starlark_value,
};

// ---------------------------------------------------------------------------
// MatchTreeNode — Starlark wrapper for match tree nodes
// ---------------------------------------------------------------------------

/// A match tree node value in Starlark — represents a Condition or Decision node.
#[derive(Debug, Clone, ProvidesStaticType, Allocative)]
pub struct MatchTreeNode {
    #[allocative(skip)]
    pub json: JsonValue,
}

impl serde::Serialize for MatchTreeNode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.json.serialize(serializer)
    }
}

unsafe impl Trace<'_> for MatchTreeNode {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

impl Display for MatchTreeNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MatchTreeNode({})", self.json)
    }
}

starlark_simple_value!(MatchTreeNode);

#[starlark_value(type = "MatchTreeNode")]
impl<'v> StarlarkValue<'v> for MatchTreeNode {
    fn get_methods() -> Option<&'static starlark::environment::Methods> {
        static RES: starlark::environment::MethodsStatic =
            starlark::environment::MethodsStatic::new();
        RES.methods(match_tree_node_methods)
    }
}

#[starlark::starlark_module]
fn match_tree_node_methods(builder: &mut starlark::environment::MethodsBuilder) {
    /// Set children on a condition node.
    fn on<'v>(
        this: &MatchTreeNode,
        #[starlark(require = pos)] children: Value<'v>,
    ) -> anyhow::Result<MatchTreeNode> {
        let list = ListRef::from_value(children)
            .ok_or_else(|| anyhow::anyhow!(".on() requires a list of nodes"))?;

        let mut child_nodes = Vec::new();
        for item in list.iter() {
            if let Some(node) = item.downcast_ref::<MatchTreeNode>() {
                child_nodes.push(node.json.clone());
            } else {
                anyhow::bail!(
                    ".on() children must be MatchTreeNode values, got {}",
                    item.get_type()
                );
            }
        }

        // Clone this node and set children on the deepest leaf
        let mut json = this.json.clone();
        set_children_on_deepest_leaf(&mut json, child_nodes);

        Ok(MatchTreeNode { json })
    }

    /// Sugar for `.on([allow_node])`.
    fn allow(
        this: &MatchTreeNode,
        #[starlark(require = named)] sandbox: Option<&str>,
    ) -> anyhow::Result<MatchTreeNode> {
        let decision = if let Some(sb) = sandbox {
            json!({"decision": {"allow": sb}})
        } else {
            json!({"decision": {"allow": null}})
        };
        set_children(this, vec![decision])
    }

    /// Sugar for `.on([deny_node])`.
    fn deny(this: &MatchTreeNode) -> anyhow::Result<MatchTreeNode> {
        let decision = json!({"decision": "deny"});
        set_children(this, vec![decision])
    }

    /// Sugar for `.on([ask_node])`.
    fn ask(
        this: &MatchTreeNode,
        #[starlark(require = named)] sandbox: Option<&str>,
    ) -> anyhow::Result<MatchTreeNode> {
        let decision = if let Some(sb) = sandbox {
            json!({"decision": {"ask": sb}})
        } else {
            json!({"decision": {"ask": null}})
        };
        set_children(this, vec![decision])
    }
}

fn set_children(node: &MatchTreeNode, children: Vec<JsonValue>) -> anyhow::Result<MatchTreeNode> {
    let mut json = node.json.clone();
    set_children_on_deepest_leaf(&mut json, children);
    Ok(MatchTreeNode { json })
}

/// Recursively find the deepest condition node with empty children and set its children.
fn set_children_on_deepest_leaf(json: &mut JsonValue, children: Vec<JsonValue>) {
    if let Some(obj) = json.as_object_mut() {
        if let Some(cond) = obj.get_mut("condition").and_then(|c| c.as_object_mut()) {
            if let Some(existing) = cond.get_mut("children").and_then(|c| c.as_array_mut()) {
                if existing.is_empty() {
                    // This is the leaf — set children here
                    *existing = children;
                    return;
                }
                // If there's exactly one child that is a condition, recurse into it
                if existing.len() == 1 && existing[0].get("condition").is_some() {
                    set_children_on_deepest_leaf(&mut existing[0], children);
                    return;
                }
            }
            // Fallback: set children directly
            cond.insert("children".into(), serde_json::json!(children));
        }
    }
}

// ---------------------------------------------------------------------------
// Builder functions (registered as Starlark globals)
// ---------------------------------------------------------------------------

/// Create a condition node. `observe` is JSON (string or structured).
pub fn mt_condition(observe: JsonValue, pattern: JsonValue) -> MatchTreeNode {
    MatchTreeNode {
        json: json!({
            "condition": {
                "observe": observe,
                "pattern": pattern,
                "children": []
            }
        }),
    }
}

/// Convert a Starlark pattern value to JSON.
/// - None → wildcard
/// - "foo" → literal
/// - regex("...") struct → regex
/// - ["a", "b"] → any_of
pub fn pattern_to_json<'v>(value: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    if value.is_none() {
        return Ok(json!("wildcard"));
    }
    if let Some(s) = value.unpack_str() {
        return Ok(json!({"literal": {"literal": s}}));
    }
    if let Some(list) = ListRef::from_value(value) {
        let items: Result<Vec<_>, _> = list.iter().map(|v| pattern_to_json(v, heap)).collect();
        return Ok(json!({"any_of": items?}));
    }
    // Check for regex struct
    if value.get_type() == "struct" {
        if let Ok(Some(regex_val)) = value.get_attr("_regex", heap) {
            if let Some(s) = regex_val.unpack_str() {
                return Ok(json!({"regex": s}));
            }
        }
    }
    anyhow::bail!(
        "cannot convert {} to a match tree pattern",
        value.get_type()
    )
}

/// Convert a Starlark path value (string, struct with _env, struct with _join) to a Value JSON.
pub fn path_value_to_json<'v>(value: Value<'v>, heap: &'v Heap) -> anyhow::Result<JsonValue> {
    if let Some(s) = value.unpack_str() {
        return Ok(json!({"literal": s}));
    }
    if value.get_type() == "struct" {
        if let Ok(Some(env_val)) = value.get_attr("_env", heap) {
            if let Some(env_name) = env_val.unpack_str() {
                return Ok(json!({"env": env_name}));
            }
        }
        if let Ok(Some(join_val)) = value.get_attr("_join", heap) {
            if let Some(list) = ListRef::from_value(join_val) {
                let parts: Result<Vec<_>, _> =
                    list.iter().map(|v| path_value_to_json(v, heap)).collect();
                return Ok(json!({"path": parts?}));
            }
        }
    }
    anyhow::bail!("cannot convert {} to a path value", value.get_type())
}
