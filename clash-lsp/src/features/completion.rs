//! Completion provider for clash policy files.
//!
//! v1: returns every top-level builtin from the schema, ignoring cursor
//! position. Context-aware filtering is reserved for a future iteration.

use tower_lsp::lsp_types::{CompletionItem, CompletionItemKind, Documentation, Position};

use crate::schema::Schema;

/// Produce completion items for a position in the source.
///
/// v1: returns every top-level builtin from the schema, ignoring position.
pub fn complete(schema: &Schema, _source: &str, _pos: Position) -> Vec<CompletionItem> {
    schema
        .builtins
        .iter()
        .map(|b| CompletionItem {
            label: b.name.to_string(),
            kind: Some(CompletionItemKind::FUNCTION),
            detail: Some(b.signature.to_string()),
            documentation: Some(Documentation::String(b.doc.to_string())),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::load_builtin;

    #[test]
    fn completes_builtins() {
        let items = complete(&load_builtin(), "", Position::default());
        let labels: Vec<_> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"policy"));
        assert!(labels.contains(&"sandbox"));
        assert!(labels.contains(&"settings"));
        assert!(labels.contains(&"allow"));
        assert!(labels.contains(&"deny"));
        assert!(labels.contains(&"ask"));
    }
}
