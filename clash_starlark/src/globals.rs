//! Pre-loaded Starlark globals: minimal Rust primitives.
//!
//! Most DSL functions live in `@clash//std.star`. Only things that require
//! Rust (typed wrappers, JSON bridge, eval context) stay here.

use starlark::environment::{GlobalsBuilder, LibraryExtension};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::values::Value;
use starlark::values::dict::{AllocDict, DictRef};
use starlark::values::none::NoneType;

use crate::builders::match_tree::{self as mt, MatchTreeNode, path_value_to_json, pattern_to_json};
use crate::eval_context::{EvalContext, PolicyRegistration, SettingsValue, ShadowedRule};

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

/// Deep-merge two Starlark dicts. When both sides have the same key and both
/// values are dicts, recurse. Otherwise the right (later) value wins and the
/// left value is recorded as a shadow.
fn deep_merge<'v>(
    left: Value<'v>,
    right: Value<'v>,
    path: &[String],
    ctx: Option<&EvalContext>,
    heap: &'v starlark::values::Heap,
) -> anyhow::Result<Value<'v>> {
    let left_dict = DictRef::from_value(left)
        .ok_or_else(|| anyhow::anyhow!("merge: expected dict, got {}", left.get_type()))?;
    let right_dict = DictRef::from_value(right)
        .ok_or_else(|| anyhow::anyhow!("merge: expected dict, got {}", right.get_type()))?;

    // Start with all entries from left.
    let mut entries: Vec<(Value<'v>, Value<'v>)> = left_dict.iter().collect();

    // Merge in entries from right.
    for (rk, rv) in right_dict.iter() {
        // Check if left already has this key.
        let existing_idx = entries
            .iter()
            // unwrap_or(false): if equals() fails (shouldn't for policy keys — strings/structs),
            // treat as not-equal so the key gets added as a new entry rather than merged.
            .position(|(lk, _)| lk.equals(rk).unwrap_or(false));

        match existing_idx {
            Some(idx) => {
                let (_lk, lv) = entries[idx];
                let both_dicts =
                    DictRef::from_value(lv).is_some() && DictRef::from_value(rv).is_some();
                if both_dicts {
                    // Recurse into nested dicts.
                    let key_str = rk.to_repr();
                    let mut child_path = path.to_vec();
                    child_path.push(key_str);
                    let merged = deep_merge(lv, rv, &child_path, ctx, heap)?;
                    entries[idx].1 = merged;
                } else {
                    // Leaf conflict — rightmost wins.
                    if let Some(ctx) = ctx {
                        let key_str = rk.to_repr();
                        let mut full_path = path.to_vec();
                        full_path.push(key_str);
                        ctx.shadows.borrow_mut().push(ShadowedRule {
                            path: full_path,
                            winner: rv.to_repr(),
                            shadowed: lv.to_repr(),
                        });
                    }
                    entries[idx].1 = rv;
                }
            }
            None => {
                entries.push((rk, rv));
            }
        }
    }

    Ok(heap.alloc(AllocDict(entries)))
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

    // -- Claude settings import --

    /// Import Claude Code permission settings as a policy dict at eval time.
    ///
    /// Returns a Starlark dict suitable for passing to `merge()` and then
    /// to `policy()`. Keys are tool name strings, values are effect structs
    /// or nested dicts for argument-level rules.
    ///
    /// Parameters:
    ///   user (bool): include user-level (~/.claude/settings.json) permissions
    ///   project (bool): include project-level (.claude/settings.json) permissions
    fn _from_claude_settings<'v>(
        #[starlark(require = named, default = true)] user: bool,
        #[starlark(require = named, default = true)] project: bool,
        heap: &'v starlark::values::Heap,
    ) -> anyhow::Result<Value<'v>> {
        Ok(crate::settings_compat::from_claude_settings_as_dict(user, project, heap))
    }

    // -- Deep merge primitive --

    /// Deep-merge two or more dicts. Rightmost wins at leaf conflicts.
    /// Records shadowed (overwritten) leaf values in the EvalContext.
    fn _merge<'v>(
        #[starlark(args)] args: &starlark::values::tuple::TupleRef<'v>,
        eval: &mut Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<Value<'v>> {
        let heap = eval.heap();
        let items = args.content();
        if items.len() < 2 {
            anyhow::bail!("merge() requires at least 2 dict arguments, got {}", items.len());
        }
        for (i, arg) in items.iter().enumerate() {
            if DictRef::from_value(*arg).is_none() {
                anyhow::bail!("merge() argument {} is not a dict", i + 1);
            }
        }

        let ctx = eval.extra.and_then(|e| e.downcast_ref::<EvalContext>());

        let mut result = items[0];
        for arg in &items[1..] {
            result = deep_merge(result, *arg, &[], ctx, heap)?;
        }
        Ok(result)
    }

    // -- Registration functions (side-effecting, write into EvalContext) --

    /// Register settings into the evaluation context.
    fn _register_settings<'v>(
        #[starlark(require = named)] default: &str,
        #[starlark(require = named, default = starlark::values::none::NoneType)]
        default_sandbox: Value<'v>,
        #[starlark(require = named, default = starlark::values::none::NoneType)]
        on_sandbox_violation: Value<'v>,
        #[starlark(require = named, default = starlark::values::none::NoneType)]
        harness_defaults: Value<'v>,
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
        let osv = if on_sandbox_violation.is_none() {
            None
        } else {
            let s = on_sandbox_violation
                .unpack_str()
                .ok_or_else(|| anyhow::anyhow!("on_sandbox_violation must be a string"))?
                .to_string();
            match s.as_str() {
                "stop" | "workaround" | "smart" => {}
                _ => anyhow::bail!(
                    "on_sandbox_violation must be \"stop\", \"workaround\", or \"smart\", got \"{s}\""
                ),
            }
            Some(s)
        };
        let hd = if harness_defaults.is_none() {
            None
        } else {
            Some(
                harness_defaults
                    .unpack_bool()
                    .ok_or_else(|| anyhow::anyhow!("harness_defaults must be True or False"))?,
            )
        };
        ctx.register_settings(SettingsValue {
            default_effect: default.to_string(),
            default_sandbox: ds,
            on_sandbox_violation: osv,
            harness_defaults: hd,
        })?;
        Ok(NoneType)
    }

    // -- Rust-native policy() --

    /// Register a named policy.
    ///
    /// Accepts dict form only: `policy("name", {mode("plan"): allow(), ...})`
    fn _policy_impl<'v>(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = pos, default = starlark::values::none::NoneType)] rules_or_dict: Value<
            'v,
        >,
        #[starlark(require = named, default = starlark::values::none::NoneType)] default: Value<'v>,
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

        // Reject non-dict, non-None values with a helpful error
        if !rules_or_dict.is_none() && DictRef::from_value(rules_or_dict).is_none() {
            anyhow::bail!(
                "policy() requires a dict argument, got {}. The when()/rules= syntax has been removed — use dict syntax instead. Run 'clash policy migrate' to convert.",
                rules_or_dict.get_type()
            );
        }

        // Unwrap default effect (reserved for future use in policy registration)
        let _default_effect = if default.is_none() {
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
        let (flat_nodes, sandboxes) =
            crate::when::policy_impl(name, rules_or_dict, default_sandbox, heap, source)?;

        ctx.register_policy(PolicyRegistration {
            name: name.to_string(),
            tree_nodes: flat_nodes,
            sandboxes,
        })?;
        Ok(NoneType)
    }
}
