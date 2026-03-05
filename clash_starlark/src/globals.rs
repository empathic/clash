//! Pre-loaded Starlark globals: effect constants and DSL builder functions.

use starlark::environment::GlobalsBuilder;
use starlark::starlark_module;
use starlark::values::{Heap, Value};

use crate::builders::base::BasePolicyValue;
use crate::builders::exec::{ExecBindingValue, ToolBindingValue};
use crate::builders::net::NetValue;
use crate::builders::path::PathValue;
use crate::builders::sandbox::SandboxValue;

/// Build the globals environment with all Clash DSL functions and constants.
pub fn clash_globals() -> starlark::environment::Globals {
    let mut builder = GlobalsBuilder::standard();
    register_globals(&mut builder);
    builder.build()
}

#[starlark_module]
fn register_globals(builder: &mut GlobalsBuilder) {
    // Effect constants
    const allow: &str = "allow";
    const deny: &str = "deny";
    const ask: &str = "ask";

    // -- Sandbox builder --

    fn sandbox<'v>(
        #[starlark(require = named)] default: Option<&str>,
        #[starlark(require = named)] fs: Option<Value<'v>>,
        #[starlark(require = named)] net: Option<Value<'v>>,
        heap: &'v Heap,
    ) -> anyhow::Result<SandboxValue> {
        SandboxValue::new(default, fs, net, heap)
    }

    // -- Path builders --

    fn cwd(
        #[starlark(require = named, default = false)] follow_worktrees: bool,
        #[starlark(require = named)] read: Option<&str>,
        #[starlark(require = named)] write: Option<&str>,
        #[starlark(require = named)] execute: Option<&str>,
        #[starlark(require = named, default = false)] allow_all: bool,
    ) -> anyhow::Result<PathValue> {
        PathValue::cwd(follow_worktrees, read, write, execute, allow_all)
    }

    fn home() -> anyhow::Result<PathValue> {
        Ok(PathValue::home())
    }

    fn tempdir(
        #[starlark(require = named, default = false)] allow_all: bool,
        #[starlark(require = named)] read: Option<&str>,
        #[starlark(require = named)] write: Option<&str>,
        #[starlark(require = named)] execute: Option<&str>,
    ) -> anyhow::Result<PathValue> {
        PathValue::tempdir(allow_all, read, write, execute)
    }

    fn path(
        #[starlark(require = pos)] path_str: Option<&str>,
        #[starlark(require = named)] env: Option<&str>,
        #[starlark(require = named)] read: Option<&str>,
        #[starlark(require = named)] write: Option<&str>,
        #[starlark(require = named)] execute: Option<&str>,
        #[starlark(require = named, default = false)] allow_all: bool,
    ) -> anyhow::Result<PathValue> {
        PathValue::arbitrary(path_str, env, read, write, execute, allow_all)
    }

    // -- Network builders --

    fn domains<'v>(#[starlark(require = pos)] mapping: Value<'v>) -> anyhow::Result<NetValue> {
        NetValue::from_domains_dict(mapping)
    }

    fn domain(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = pos)] effect: &str,
    ) -> anyhow::Result<NetValue> {
        NetValue::single_domain(name, effect)
    }

    // -- Exec/tool builders --

    fn exe(
        #[starlark(require = pos)] name: &str,
        #[starlark(require = named)] sandbox: Option<&SandboxValue>,
    ) -> anyhow::Result<ExecBindingValue> {
        ExecBindingValue::new_single(name, sandbox)
    }

    fn r#match<'v>(
        #[starlark(require = named)] exe: Option<Value<'v>>,
        #[starlark(require = named)] sandbox: Option<&SandboxValue>,
    ) -> anyhow::Result<ExecBindingValue> {
        ExecBindingValue::new_multi(exe, sandbox)
    }

    fn allow_tool(
        #[starlark(require = pos)] name: Option<&str>,
    ) -> anyhow::Result<ToolBindingValue> {
        Ok(ToolBindingValue::allow(name))
    }

    fn deny_tool(
        #[starlark(require = pos)] name: Option<&str>,
    ) -> anyhow::Result<ToolBindingValue> {
        Ok(ToolBindingValue::deny(name))
    }

    // -- Base policy --

    fn import_json<'v>(
        #[starlark(require = pos)] filename: &str,
        eval: &mut starlark::eval::Evaluator<'v, '_, '_>,
    ) -> anyhow::Result<BasePolicyValue> {
        crate::import_json::import_json_impl(filename, eval)
    }

    fn policy<'v>(
        #[starlark(require = named)] default: Option<&str>,
        #[starlark(require = named)] rules: Option<Value<'v>>,
    ) -> anyhow::Result<BasePolicyValue> {
        BasePolicyValue::from_scratch(default, rules)
    }
}
