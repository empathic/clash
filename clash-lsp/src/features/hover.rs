//! Hover documentation for clash builtins.

use tower_lsp::lsp_types::{Hover, HoverContents, MarkupContent, MarkupKind, Position};

use crate::schema::Schema;

/// Look up the identifier at `pos` in `source` and return its hover doc.
pub fn hover(schema: &Schema, source: &str, pos: Position) -> Option<Hover> {
    let word = word_at(source, pos)?;
    let builtin = schema.lookup(&word)?;
    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: format!("```\n{}\n```\n\n{}", builtin.signature, builtin.doc),
        }),
        range: None,
    })
}

pub(crate) fn word_at(source: &str, pos: Position) -> Option<String> {
    let line = source.lines().nth(pos.line as usize)?;
    let col = pos.character as usize;
    if col > line.len() { return None; }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let start = line[..col].rfind(|c: char| !is_word(c)).map(|i| i + 1).unwrap_or(0);
    let end = line[col..].find(|c: char| !is_word(c)).map(|i| col + i).unwrap_or(line.len());
    if start == end { None } else { Some(line[start..end].to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::load_builtin;

    #[test]
    fn hovers_on_policy_builtin() {
        let src = "policy({})\n";
        let h = hover(&load_builtin(), src, Position { line: 0, character: 2 }).unwrap();
        if let HoverContents::Markup(m) = h.contents {
            assert!(m.value.contains("policy"));
        } else { panic!("expected markup"); }
    }

    #[test]
    fn no_hover_on_unknown_word() {
        let src = "frobnicate()\n";
        assert!(hover(&load_builtin(), src, Position { line: 0, character: 2 }).is_none());
    }
}
