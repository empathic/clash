//! Pre-loaded Starlark globals: minimal Rust primitives.
//!
//! Most DSL functions live in `@clash//std.star`. Only things that require
//! Rust (typed wrappers, JSON bridge, eval context) stay here.

use starlark::environment::{GlobalsBuilder, LibraryExtension};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::values::none::NoneType;
use starlark::values::{Value, ValueLike};

use crate::builders::base::BasePolicyValue;
use crate::builders::match_tree::{self as mt, MatchTreeNode, path_value_to_json, pattern_to_json};
use crate::eval_context::{EvalContext, PolicyRegistration, SettingsValue};

/// Build the globals environment with all Clash DSL functions and constants.
pub fn clash_globals() -> starlark::environment::Globals {
    let mut builder = GlobalsBuilder::standard();
    LibraryExtension::StructType.add(&mut builder);
    register_globals(&mut builder);
    builder.build()
}

/// Walk the Starlark call stack and return the source location of the first
/// frame that isn't from the stdlib (`@clash//` prefix). This gives us the
/// user's policy file and line number, e.g. `policy.star:3:1`.
fn caller_source_location(eval: &Evaluator) -> Option<String> {
    let stack = eval.call_stack();
    for frame in &stack.frames {
        if let Some(loc) = &frame.location {
            let filename = loc.file.filename();
            if !filename.starts_with("@clash//") {
                return Some(loc.to_string());
            }
        }
    }
    None
}

pub(crate) fn starlark_to_json(value: Value) -> anyhow::Result<serde_json::Value> {
    let json_str = value.to_json()?;
    serde_json::from_str(&json_str).map_err(Into::into)
}

#[starlark_module]
fn register_globals(builder: &mut GlobalsBuilder) {
    // Effect constants (internal — callable versions are in std.star)
    const _ALLOW: &str = "allow";
    const _DENY: &str = "deny";
    const _ASK: &str = "ask";

    // Platform constants — let Starlark policies branch on OS/architecture
    const _OS: &str = std::env::consts::OS;
    const _ARCH: &str = std::env::consts::ARCH;

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
        #[starlark(require = named)] doc: Option<&str>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<MatchTreeNode> {
        let observe_json = starlark_to_json(observe)?;
        // Walk the call stack to find the first non-stdlib frame (the user's policy file).
        let source = caller_source_location(eval);
        Ok(mt::mt_condition_with_doc(
            observe_json,
            pattern.json.clone(),
            doc.map(|s| s.to_string()),
            source,
        ))
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

    /// Convert a path value to a child-of pattern (direct children only).
    fn _mt_child_of<'v>(
        #[starlark(require = pos)] value: Value<'v>,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<MatchTreeNode> {
        let val_json = path_value_to_json(value, heap)?;
        Ok(MatchTreeNode {
            json: serde_json::json!({"child_of": val_json}),
        })
    }

    /// Convert a path value to a literal (exact) pattern (needs Rust for env/join dispatch).
    fn _mt_literal<'v>(
        #[starlark(require = pos)] value: Value<'v>,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<MatchTreeNode> {
        let val_json = path_value_to_json(value, heap)?;
        Ok(MatchTreeNode {
            json: serde_json::json!({"literal": val_json}),
        })
    }

    /// Internal match tree policy constructor (legacy — used by match_tree.star).
    fn _mt_policy<'v>(
        #[starlark(require = named)] default: Option<&str>,
        #[starlark(require = named)] sandboxes: Option<Value<'v>>,
        #[starlark(require = named)] rules: Option<Value<'v>>,
        #[starlark(require = named)] default_sandbox: Option<Value<'v>>,
    ) -> anyhow::Result<BasePolicyValue> {
        use serde_json::json;

        let default_effect = default.unwrap_or("deny").to_string();

        // Collect sandbox definitions
        let mut sandbox_map = serde_json::Map::new();
        if let Some(sb_val) = sandboxes
            && let Some(list) = starlark::values::list::ListRef::from_value(sb_val)
        {
            for item in list.iter() {
                let sb_json = starlark_to_json(item)?;
                if let Some(name) = sb_json.get("name").and_then(|n| n.as_str()) {
                    sandbox_map.insert(name.to_string(), sb_json);
                }
            }
        }

        // Collect rule nodes
        let mut tree_nodes = Vec::new();
        if let Some(rules_val) = rules
            && let Some(list) = starlark::values::list::ListRef::from_value(rules_val)
        {
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

        // Convert default_sandbox from Starlark dict to JSON
        let default_sandbox_json = match default_sandbox {
            Some(val) if !val.is_none() => {
                let sb_json = starlark_to_json(val)?;
                // Extract the sandbox name to reference it
                sb_json
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|name| json!(name))
            }
            _ => None,
        };

        // Build the v5 policy document
        let mut doc = json!({
            "schema_version": 5,
            "default_effect": default_effect,
            "sandboxes": sandbox_map,
            "tree": tree_nodes,
        });

        if let Some(ds) = default_sandbox_json {
            doc.as_object_mut()
                .unwrap()
                .insert("default_sandbox".to_string(), ds);
        }

        Ok(BasePolicyValue {
            base_doc: Some(doc),
            default_effect,
        })
    }

    // -- Registration functions (side-effecting, write into EvalContext) --

    /// Register settings into the evaluation context.
    fn _register_settings<'v>(
        #[starlark(require = named)] default: &str,
        #[starlark(require = named, default = starlark::values::none::NoneType)]
        default_sandbox: Value<'v>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let ctx = eval
            .extra
            .and_then(|e| e.downcast_ref::<EvalContext>())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "settings() can only be called in a policy file, not in loaded modules"
                )
            })?;
        let ds = if default_sandbox.is_none() {
            None
        } else {
            Some(
                default_sandbox
                    .unpack_str()
                    .ok_or_else(|| anyhow::anyhow!("default_sandbox must be a string"))?
                    .to_string(),
            )
        };
        ctx.register_settings(SettingsValue {
            default_effect: default.to_string(),
            default_sandbox: ds,
        })?;
        Ok(NoneType)
    }

    /// Register a policy into the evaluation context (legacy — used by match_tree.star).
    fn _register_policy<'v>(
        #[starlark(require = named)] name: &str,
        #[starlark(require = named)] rules: Option<Value<'v>>,
        #[starlark(require = named)] sandboxes: Option<Value<'v>>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let ctx = eval
            .extra
            .and_then(|e| e.downcast_ref::<EvalContext>())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "policy() can only be called in a policy file, not in loaded modules"
                )
            })?;

        let mut tree_nodes = Vec::new();
        if let Some(rules_val) = rules
            && let Some(list) = starlark::values::list::ListRef::from_value(rules_val)
        {
            for item in list.iter() {
                if let Some(node) = item.downcast_ref::<MatchTreeNode>() {
                    tree_nodes.push(node.json.clone());
                } else {
                    anyhow::bail!(
                        "policy rules must be MatchTreeNode values, got {}",
                        item.get_type()
                    );
                }
            }
        }

        let mut sandbox_list = Vec::new();
        if let Some(sb_val) = sandboxes
            && let Some(list) = starlark::values::list::ListRef::from_value(sb_val)
        {
            for item in list.iter() {
                let sb_json = starlark_to_json(item)?;
                sandbox_list.push(sb_json);
            }
        }

        ctx.register_policy(PolicyRegistration {
            name: name.to_string(),
            tree_nodes,
            sandboxes: sandbox_list,
        })?;
        Ok(NoneType)
    }

    // -- Rust-native when() and policy() --

    /// Build rules from a nested dict tree.
    ///
    /// Keys can be raw strings (tool names), Tool("Bash"), Mode("plan"),
    /// or tuples of the above. Values are effects (allow/deny/ask) or nested dicts.
    fn _when_impl<'v>(
        #[starlark(require = pos)] tree: Value<'v>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<Value<'v>> {
        let source = caller_source_location(eval);
        let heap = eval.heap();
        let (nodes, sandboxes) = crate::when::when_impl(tree, heap, source)?;

        // Stash collected sandboxes in EvalContext for policy() to drain.
        if !sandboxes.is_empty() {
            if let Some(ctx) = eval
                .extra
                .and_then(|e| e.downcast_ref::<EvalContext>())
            {
                ctx.pending_sandboxes.borrow_mut().extend(sandboxes);
            }
        }

        // Return plain list of MatchTreeNode values.
        let result: Vec<Value<'v>> = nodes
            .into_iter()
            .map(|node| heap.alloc(node))
            .collect();
        Ok(heap.alloc(starlark::values::list::AllocList(result)))
    }

    /// Register a named policy.
    ///
    /// Accepts dict form: `policy("name", {mode("plan"): allow(), ...})`
    /// or rules form: `policy("name", rules=[when({...}), ...])`
    fn _policy_impl<'v>(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = pos, default = starlark::values::none::NoneType)]
        rules_or_dict: Value<'v>,
        #[starlark(require = named, default = starlark::values::none::NoneType)]
        default: Value<'v>,
        #[starlark(require = named)] rules: Option<Value<'v>>,
        #[starlark(require = named, default = starlark::values::none::NoneType)]
        default_sandbox: Value<'v>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<NoneType> {
        let heap = eval.heap();
        let ctx = eval
            .extra
            .and_then(|e| e.downcast_ref::<EvalContext>())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "policy() can only be called in a policy file, not in loaded modules"
                )
            })?;

        // Unwrap default effect
        let default_effect = if default.is_none() {
            "deny".to_string()
        } else if let Some(s) = default.unpack_str() {
            s.to_string()
        } else if default.get_type() == "struct" {
            // Effect struct — extract _effect
            default
                .get_attr("_effect", heap)
                .ok()
                .flatten()
                .and_then(|v| v.unpack_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "deny".to_string())
        } else {
            "deny".to_string()
        };

        let source = caller_source_location(eval);
        let (flat_nodes, mut sandboxes) =
            crate::when::policy_impl(name, rules_or_dict, rules, default_sandbox, heap, source)?;

        // Drain pending sandboxes from when() calls
        sandboxes.extend(ctx.pending_sandboxes.borrow_mut().drain(..));

        ctx.register_policy(PolicyRegistration {
            name: name.to_string(),
            tree_nodes: flat_nodes,
            sandboxes,
        })?;
        Ok(NoneType)
    }
}
