//! Match tree IR builders.
//!
//! These produce JSON that deserializes to `clash::policy::match_tree::CompiledPolicy`.
//! The builders emit tree-shaped policies where capability domains are compile-time
//! sugar, not IR concepts.
//!
//! `MatchTreeNode` is a thin JSON wrapper used internally by `when.rs` and
//! `settings_compat.rs` — it is **not** exposed to Starlark.

use serde_json::{Value as JsonValue, json};
use starlark::values::list::ListRef;
use starlark::values::{Heap, Value};

// ---------------------------------------------------------------------------
// MatchTreeNode — internal JSON wrapper (not a Starlark value)
// ---------------------------------------------------------------------------

/// A match tree node — represents a Condition or Decision node as JSON.
#[derive(Debug, Clone)]
pub struct MatchTreeNode {
    pub json: JsonValue,
}

impl serde::Serialize for MatchTreeNode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.json.serialize(serializer)
    }
}

/// Recursively find the deepest condition node with empty children and set its children.
fn set_children_on_deepest_leaf(json: &mut JsonValue, children: Vec<JsonValue>) {
    if let Some(obj) = json.as_object_mut()
        && let Some(cond) = obj.get_mut("condition").and_then(|c| c.as_object_mut())
    {
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

/// Public wrapper for `set_children_on_deepest_leaf`.
pub fn set_children_on_deepest_leaf_pub(json: &mut JsonValue, children: Vec<JsonValue>) {
    set_children_on_deepest_leaf(json, children);
}

// ---------------------------------------------------------------------------
// Builder helpers (used by when.rs dict processing)
// ---------------------------------------------------------------------------

/// Create a condition node with an optional docstring and source location.
pub fn mt_condition_with_doc(
    observe: JsonValue,
    pattern: JsonValue,
    doc: Option<String>,
    source: Option<String>,
) -> MatchTreeNode {
    let mut condition = json!({
        "observe": observe,
        "pattern": pattern,
        "children": []
    });
    if let Some(d) = doc {
        condition
            .as_object_mut()
            .unwrap()
            .insert("doc".to_string(), json!(d));
    }
    if let Some(s) = source {
        condition
            .as_object_mut()
            .unwrap()
            .insert("source".to_string(), json!(s));
    }
    MatchTreeNode {
        json: json!({"condition": condition}),
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
    if let Some(tuple) = starlark::values::tuple::TupleRef::from_value(value) {
        let items: Result<Vec<_>, _> = tuple.iter().map(|v| pattern_to_json(v, heap)).collect();
        return Ok(json!({"any_of": items?}));
    }
    // Check for regex struct
    if value.get_type() == "struct"
        && let Ok(Some(regex_val)) = value.get_attr("_regex", heap)
        && let Some(s) = regex_val.unpack_str()
    {
        return Ok(json!({"regex": s}));
    }
    // Check for glob struct
    if value.get_type() == "struct"
        && let Ok(Some(glob_val)) = value.get_attr("_glob", heap)
        && let Some(s) = glob_val.unpack_str()
    {
        let glob_type = value
            .get_attr("_glob_type", heap)
            .ok()
            .flatten()
            .and_then(|v| v.unpack_str())
            .unwrap_or("recursive");
        return match glob_type {
            "wildcard" => Ok(json!("wildcard")),
            "children" => Ok(json!({"child_of": {"literal": s}})),
            _ => Ok(json!({"prefix": {"literal": s}})),
        };
    }
    anyhow::bail!(
        "cannot convert {} to a match tree pattern: {}",
        value.get_type(),
        value.to_repr()
    )
}
