//! Test helpers for evaluating Starlark sources outside the full
//! `policy()`/`sandbox()` registration pipeline.
//!
//! Used by integration tests under `clash_starlark/tests/` to verify
//! stdlib constructors and individual evaluator pieces.

use std::collections::HashMap;

use anyhow::{Result, anyhow};
use starlark::environment::Module;
use starlark::eval::Evaluator;
use starlark::syntax::{AstModule, Dialect};
use starlark::values::list::ListRef;

use crate::eval_context::EvalContext;
use crate::globals::clash_globals;
use crate::loader::ClashLoader;

/// Handle returned from [`load_starlark_source_for_test`].
///
/// Holds snapshots of named globals captured immediately after evaluation,
/// so the underlying Starlark heap does not have to outlive the call.
pub struct TestModule {
    string_lists: HashMap<String, Vec<String>>,
}

impl TestModule {
    /// Read a previously snapshot-captured global as a list of strings.
    pub fn get_global_strings(&self, name: &str) -> Result<Vec<String>> {
        self.string_lists
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("global `{name}` was not captured as a string list"))
    }
}

/// Evaluate a Starlark source string against `clash_globals()` with the
/// stdlib pre-injected, and return a handle to read named globals.
///
/// The source must be self-contained — it should not call `policy()` or
/// `sandbox()`. Use this to unit-test stdlib constructors.
///
/// This eagerly snapshots every top-level binding whose value is a list of
/// strings, so callers can read them after the underlying Starlark module
/// has been dropped.
pub fn load_starlark_source_for_test(source: &str) -> Result<TestModule> {
    let ast = AstModule::parse("test.star", source.to_owned(), &Dialect::Standard)
        .map_err(|e| anyhow!("{e}"))?;

    let loader = ClashLoader::new(std::path::PathBuf::from("."));
    let globals = clash_globals();
    let ctx = EvalContext::new();
    let module = Module::new();
    loader
        .inject_std(&module)
        .map_err(|e| anyhow!("failed to load stdlib: {e}"))?;

    let mut string_lists: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut eval = Evaluator::new(&module);
        eval.set_loader(&loader);
        eval.extra = Some(&ctx);
        eval.eval_module(ast, &globals).map_err(|e| anyhow!("{e}"))?;
    }
    for name in module.names() {
        let n = name.as_str();
        if let Some(value) = module.get(n) {
            if let Some(list) = ListRef::from_value(value) {
                let mut out = Vec::with_capacity(list.len());
                let mut all_strings = true;
                for v in list.iter() {
                    if let Some(s) = v.unpack_str() {
                        out.push(s.to_string());
                    } else {
                        all_strings = false;
                        break;
                    }
                }
                if all_strings {
                    string_lists.insert(n.to_string(), out);
                }
            }
        }
    }
    Ok(TestModule { string_lists })
}

/// Evaluate a Starlark source string as a policy file with a fresh
/// `EvalContext`. Top-level `policy()` / `sandbox()` / `settings()` calls
/// register into the returned context.
///
/// Used by integration tests that need to verify that the evaluator
/// accepts/rejects particular root-level constructs.
pub fn eval_policy_source_for_test(source: &str) -> Result<EvalContext> {
    let ast = AstModule::parse("test.star", source.to_owned(), &Dialect::Standard)
        .map_err(|e| anyhow!("{e}"))?;

    let loader = ClashLoader::new(std::path::PathBuf::from("."));
    let globals = clash_globals();
    let ctx = EvalContext::new();
    let module = Module::new();
    loader
        .inject_std(&module)
        .map_err(|e| anyhow!("failed to load stdlib: {e}"))?;

    {
        let mut eval = Evaluator::new(&module);
        eval.set_loader(&loader);
        eval.extra = Some(&ctx);
        eval.eval_module(ast, &globals).map_err(|e| anyhow!("{e}"))?;
    }
    Ok(ctx)
}
