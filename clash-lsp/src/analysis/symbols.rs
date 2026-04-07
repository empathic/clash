//! Top-level symbol index: maps identifier names to their definition [`Range`].

use std::collections::HashMap;

use tower_lsp::lsp_types::Range;

/// Maps top-level identifier names (assignments and `def`s) to their definition location.
#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    defs: HashMap<String, Range>,
}

impl SymbolIndex {
    pub fn insert(&mut self, name: impl Into<String>, range: Range) {
        self.defs.insert(name.into(), range);
    }

    pub fn get(&self, name: &str) -> Option<Range> {
        self.defs.get(name).copied()
    }
}
