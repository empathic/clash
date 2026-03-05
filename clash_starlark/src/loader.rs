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
pub struct ClashLoader {
    base_dir: PathBuf,
    loaded: Mutex<Vec<String>>,
}

impl ClashLoader {
    pub fn new(base_dir: PathBuf) -> Self {
        ClashLoader {
            base_dir,
            loaded: Mutex::new(Vec::new()),
        }
    }

    pub fn loaded_files(&self) -> Vec<String> {
        self.loaded.lock().unwrap().clone()
    }
}

impl starlark::eval::FileLoader for ClashLoader {
    fn load(&self, path: &str) -> starlark::Result<FrozenModule> {
        let source = if let Some(stdlib_path) = path.strip_prefix("@clash//") {
            // Embedded stdlib
            stdlib::get(stdlib_path)
                .ok_or_else(|| {
                    starlark::Error::new_other(anyhow::anyhow!(
                        "unknown stdlib module: @clash//{stdlib_path}"
                    ))
                })?
                .to_string()
        } else {
            // Relative path
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

        let ast = AstModule::parse(path, source, &Dialect::Standard)
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
}
