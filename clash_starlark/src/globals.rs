//! Pre-loaded Starlark globals: minimal Rust primitives.
//!
//! Most DSL functions live in `@clash//std.star`. Only things that require
//! Rust (typed wrappers, JSON bridge, eval context) stay here.

use starlark::environment::{GlobalsBuilder, LibraryExtension};
use starlark::starlark_module;
use starlark::values::Value;

use crate::builders::base::BasePolicyValue;
use crate::builders::rule::{RuleValue, starlark_to_json};

/// Build the globals environment with all Clash DSL functions and constants.
pub fn clash_globals() -> starlark::environment::Globals {
    let mut builder = GlobalsBuilder::standard();
    LibraryExtension::StructType.add(&mut builder);
    register_globals(&mut builder);
    builder.build()
}

#[starlark_module]
fn register_globals(builder: &mut GlobalsBuilder) {
    // Effect constants
    const allow: &str = "allow";
    const deny: &str = "deny";
    const ask: &str = "ask";

    // -- Rule builder (the single bridge from Starlark dicts to typed rules) --

    fn rule<'v>(#[starlark(require = pos)] value: Value<'v>) -> anyhow::Result<RuleValue> {
        let json = starlark_to_json(value)?;
        Ok(RuleValue {
            json,
            sandbox: None,
        })
    }

    // -- Base policy (must stay in Rust — return type for compile_to_json) --

    fn import_json<'v>(
        #[starlark(require = pos)] filename: &str,
        eval: &mut starlark::eval::Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<BasePolicyValue> {
        crate::import_json::import_json_impl(filename, eval)
    }

    /// Internal policy constructor. Starlark `policy()` in std.star wraps this
    /// to flatten path entries and nested lists before passing rules through.
    fn _policy<'v>(
        #[starlark(require = named)] default: Option<&str>,
        #[starlark(require = named)] rules: Option<Value<'v>>,
    ) -> anyhow::Result<BasePolicyValue> {
        BasePolicyValue::from_scratch(default, rules)
    }
}
