//! Pre-loaded Starlark globals: minimal Rust primitives.
//!
//! Most DSL functions live in `@clash//std.star`. Only things that require
//! Rust (typed wrappers, JSON bridge, eval context) stay here.

use starlark::environment::{GlobalsBuilder, LibraryExtension};
use starlark::starlark_module;
use starlark::values::{Value, ValueLike};

use crate::builders::base::BasePolicyValue;
use crate::builders::match_tree::{
    self as mt, MatchTreeNode, not_pattern_to_json, or_pattern_to_json, path_value_to_json,
    pattern_to_json,
};

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

    // -- Match tree primitives (used by @clash//std.star and @clash//match_tree.star) --

    fn _mt_pattern<'v>(
        #[starlark(require = pos)] value: Value<'v>,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<MatchTreeNode> {
        let pat = pattern_to_json(value, heap)?;
        Ok(MatchTreeNode { json: pat })
    }

    fn _mt_exe<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_exe(pattern.json.clone()))
    }

    fn _mt_tool<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_tool(pattern.json.clone()))
    }

    fn _mt_hook<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_hook(pattern.json.clone()))
    }

    fn _mt_agent<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_agent(pattern.json.clone()))
    }

    fn _mt_arg(
        #[starlark(require = pos)] n: i32,
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_arg(n, pattern.json.clone()))
    }

    fn _mt_has_arg<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_has_arg(pattern.json.clone()))
    }

    fn _mt_named<'v>(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_named(name, pattern.json.clone()))
    }

    fn _mt_fs_op<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_condition("fs_op", pattern.json.clone()))
    }

    fn _mt_fs_path<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_condition("fs_path", pattern.json.clone()))
    }

    fn _mt_net_domain<'v>(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_condition("net_domain", pattern.json.clone()))
    }

    fn _mt_prefix<'v>(
        #[starlark(require = pos)] value: Value<'v>,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<MatchTreeNode> {
        let val_json = path_value_to_json(value, heap)?;
        Ok(MatchTreeNode {
            json: serde_json::json!({"prefix": val_json}),
        })
    }

    fn _mt_field<'v>(
        #[starlark(require = pos)] path: Value<'v>,
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        let list = starlark::values::list::ListRef::from_value(path)
            .ok_or_else(|| anyhow::anyhow!("field() path must be a list of strings"))?;
        let segments: Result<Vec<String>, _> = list
            .iter()
            .map(|v| {
                v.unpack_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| anyhow::anyhow!("field() path segments must be strings"))
            })
            .collect();
        Ok(mt::mt_field(segments?, pattern.json.clone()))
    }

    fn _mt_allow(#[starlark(require = pos)] sandbox: Value) -> anyhow::Result<MatchTreeNode> {
        let sb = if sandbox.is_none() {
            None
        } else {
            sandbox.unpack_str()
        };
        Ok(mt::mt_decision_allow(sb))
    }

    fn _mt_deny() -> anyhow::Result<MatchTreeNode> {
        Ok(mt::mt_decision_deny())
    }

    fn _mt_ask(#[starlark(require = pos)] sandbox: Value) -> anyhow::Result<MatchTreeNode> {
        let sb = if sandbox.is_none() {
            None
        } else {
            sandbox.unpack_str()
        };
        Ok(mt::mt_decision_ask(sb))
    }

    fn _mt_not(
        #[starlark(require = pos)] pattern: &MatchTreeNode,
    ) -> anyhow::Result<MatchTreeNode> {
        Ok(MatchTreeNode {
            json: not_pattern_to_json(pattern.json.clone()),
        })
    }

    fn _mt_or<'v>(#[starlark(require = pos)] patterns: Value<'v>) -> anyhow::Result<MatchTreeNode> {
        let list = starlark::values::list::ListRef::from_value(patterns)
            .ok_or_else(|| anyhow::anyhow!("_mt_or requires a list"))?;
        let items: Result<Vec<_>, _> = list
            .iter()
            .map(|v| {
                v.downcast_ref::<MatchTreeNode>()
                    .map(|n| n.json.clone())
                    .ok_or_else(|| anyhow::anyhow!("_mt_or items must be pattern nodes"))
            })
            .collect();
        Ok(MatchTreeNode {
            json: or_pattern_to_json(items?),
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
