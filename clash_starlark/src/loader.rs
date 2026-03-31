//! FileLoader implementation for Starlark's `load()` statement.
//!
//! - `@clash//foo.star` → embedded stdlib
//! - `./relative.star` → resolve from base directory

use std::path::PathBuf;
use std::sync::Mutex;

use starlark::environment::{FrozenModule, Module};
use starlark::eval::Evaluator;
use starlark::syntax::{AstModule, Dialect};

use crate::globals::clash_globals;
use crate::stdlib;

/// Clash file loader — resolves `load()` paths.
///
/// Pre-injects `@clash//std.star` exports into every loaded module so that
/// stdlib DSL functions (`allow`, `deny`, `sandbox`, etc.) are always available.
pub struct ClashLoader {
    base_dir: PathBuf,
    loaded: Mutex<Vec<String>>,
    /// Cached frozen std.star module for pre-injection.
    std_module: std::sync::OnceLock<FrozenModule>,
}

impl ClashLoader {
    pub fn new(base_dir: PathBuf) -> Self {
        ClashLoader {
            base_dir,
            loaded: Mutex::new(Vec::new()),
            std_module: std::sync::OnceLock::new(),
        }
    }

    pub fn loaded_files(&self) -> Vec<String> {
        self.loaded.lock().unwrap().clone()
    }

    /// Get or lazily load the frozen std.star module.
    fn std_module(&self) -> starlark::Result<&FrozenModule> {
        if let Some(m) = self.std_module.get() {
            return Ok(m);
        }
        let m = self.load_raw("@clash//std.star")?;
        // Another thread may have raced us — that's fine, use whichever won.
        let _ = self.std_module.set(m);
        Ok(self.std_module.get().unwrap())
    }

    /// Load a module without std pre-injection (used for std.star itself).
    fn load_raw(&self, path: &str) -> starlark::Result<FrozenModule> {
        let source = if let Some(stdlib_path) = path.strip_prefix("@clash//") {
            stdlib::get(stdlib_path)
                .ok_or_else(|| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "unknown stdlib module: @clash//{stdlib_path}"
                    ))
                })?
                .to_string()
        } else {
            let full_path = self.base_dir.join(path);
            self.loaded
                .lock()
                .unwrap()
                .push(full_path.display().to_string());
            std::fs::read_to_string(&full_path).map_err(|e| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "failed to load {}: {e}",
                    full_path.display()
                ))
            })?
        };
        let mut dialect = Dialect::Standard;
        dialect.enable_types = starlark::syntax::DialectTypes::Enable;

        let ast = AstModule::parse(path, source, &dialect)
            .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e}")))?;

        let globals = clash_globals();
        let module = Module::new();
        {
            let mut eval = Evaluator::new(&module);
            eval.set_loader(self);
            eval.eval_module(ast, &globals)
                .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e}")))?;
        }

        module
            .freeze()
            .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e:?}")))
    }

    /// Pre-inject std.star exports into a module.
    pub fn inject_std(&self, module: &Module) -> starlark::Result<()> {
        let std = self.std_module()?;
        for name in std.names() {
            if let Ok(value) = std.get(name.as_str()) {
                module.set(name.as_str(), value.value());
            }
        }
        Ok(())
    }
}

impl starlark::eval::FileLoader for ClashLoader {
    fn load(&self, path: &str) -> starlark::Result<FrozenModule> {
        // std.star itself loads without pre-injection (avoid circularity)
        if path == "@clash//std.star" {
            return self.load_raw(path);
        }

        let source = if let Some(stdlib_path) = path.strip_prefix("@clash//") {
            stdlib::get(stdlib_path)
                .ok_or_else(|| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "unknown stdlib module: @clash//{stdlib_path}"
                    ))
                })?
                .to_string()
        } else {
            let full_path = self.base_dir.join(path);
            self.loaded
                .lock()
                .unwrap()
                .push(full_path.display().to_string());
            std::fs::read_to_string(&full_path).map_err(|e| {
                starlark::Error::new_other(anyhow::anyhow!(
                    "failed to load {}: {e}",
                    full_path.display()
                ))
            })?
        };
        let mut dialect = Dialect::Standard;
        dialect.enable_types = starlark::syntax::DialectTypes::Enable;

        let ast = AstModule::parse(path, source, &dialect)
            .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e}")))?;

        let globals = clash_globals();
        let module = Module::new();
        // Pre-inject std.star so loaded modules can use sandbox(), allow(), etc.
        self.inject_std(&module)?;
        {
            let mut eval = Evaluator::new(&module);
            eval.set_loader(self);
            eval.eval_module(ast, &globals)
                .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e}")))?;
        }

        module
            .freeze()
            .map_err(|e| starlark::Error::new_other(anyhow::anyhow!("{e:?}")))
    }
}
