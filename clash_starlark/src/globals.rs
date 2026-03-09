//! Pre-loaded Starlark globals: minimal Rust primitives.
//!
//! Most DSL functions live in `@clash//std.star`. Only things that require
//! Rust (typed wrappers, JSON bridge, eval context) stay here.

use starlark::environment::{GlobalsBuilder, LibraryExtension};
use starlark::starlark_module;
use starlark::values::{Value, ValueLike};

use crate::builders::base::BasePolicyValue;
use crate::builders::match_tree::{self as mt, MatchTreeNode, path_value_to_json, pattern_to_json};

/// Build the globals environment with all Clash DSL functions and constants.
pub fn clash_globals() -> starlark::environment::Globals {
    let mut builder = GlobalsBuilder::standard();
    LibraryExtension::StructType.add(&mut builder);
    register_globals(&mut builder);
    builder.build()
}

fn starlark_to_json(value: Value) -> anyhow::Result<serde_json::Value> {
    let json_str = value.to_json()?;
    serde_json::from_str(&json_str).map_err(Into::into)
}

#[starlark_module]
fn register_globals(builder: &mut GlobalsBuilder) {
    // Effect constants
    const allow: &str = "allow";
    const deny: &str = "deny";
    const ask: &str = "ask";

    // -- Minimal Rust primitives (everything else is in @clash//std.star) --

    /// Wrap an arbitrary dict/value as a MatchTreeNode.
    /// This is the escape hatch that lets Starlark code build any node shape.
    fn _mt_node<'v>(#[starlark(require = pos)] value: Value<'v>) -> anyhow::Result<MatchTreeNode> {
        let json = starlark_to_json(value)?;
        Ok(MatchTreeNode { json })
    }

    /// Generic condition builder. `observe` can be a string ("tool_name")
    /// or a dict ({"positional_arg": 0}). `pattern` is a MatchTreeNode from _mt_pattern().
    fn _mt_condition<'v>(
        #[starlark(require = pos)] observe: Value<'v>,
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        let observe_json = starlark_to_json(observe)?;
        Ok(mt::mt_condition(observe_json, pattern.json.clone()))
    }

    /// Convert a value to a matcher pattern (type dispatch in Rust).
    /// - None          → wildcard
    /// - "foo"         → literal
    /// - ["a", "b"]    → any_of
    /// - regex("...")  → regex
    fn _mt_pattern<'v>(
        #[starlark(require = pos)] value: Value<'v>,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<MatchTreeNode> {
        let pat = pattern_to_json(value, heap)?;
        Ok(MatchTreeNode { json: pat })
    }

    /// Convert a path value to a prefix pattern (needs Rust for env/join dispatch).
    fn _mt_prefix<'v>(
        #[starlark(require = pos)] value: Value<'v>,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<MatchTreeNode> {
        let val_json = path_value_to_json(value, heap)?;
        Ok(MatchTreeNode {
            json: serde_json::json!({"prefix": val_json}),
        })
    }

    /// Internal match tree policy constructor.
    fn _mt_policy<'v>(
        #[starlark(require = named)] default: Option<&str>,
        #[starlark(require = named)] sandboxes: Option<Value<'v>>,
        #[starlark(require = named)] rules: Option<Value<'v>>,
    ) -> anyhow::Result<BasePolicyValue> {
        use serde_json::json;

        let default_effect = default.unwrap_or("deny").to_string();

        // Collect sandbox definitions
        let mut sandbox_map = serde_json::Map::new();
        if let Some(sb_val) = sandboxes {
            if let Some(list) = starlark::values::list::ListRef::from_value(sb_val) {
                for item in list.iter() {
                    let sb_json = starlark_to_json(item)?;
                    if let Some(name) = sb_json.get("name").and_then(|n| n.as_str()) {
                        sandbox_map.insert(name.to_string(), sb_json);
                    }
                }
            }
        }

        // Collect rule nodes
        let mut tree_nodes = Vec::new();
        if let Some(rules_val) = rules {
            if let Some(list) = starlark::values::list::ListRef::from_value(rules_val) {
                for item in list.iter() {
                    if let Some(node) = item.downcast_ref::<MatchTreeNode>() {
                        tree_nodes.push(node.json.clone());
                    } else {
                        anyhow::bail!(
                            "match tree policy rules must be MatchTreeNode values, got {}",
                            item.get_type()
                        );
                    }
                }
            }
        }

        // Build the v5 policy document
        let doc = json!({
            "schema_version": 5,
            "default_effect": default_effect,
            "sandboxes": sandbox_map,
            "tree": tree_nodes,
        });

        Ok(BasePolicyValue {
            base_doc: Some(doc),
            default_effect,
        })
    }
}
