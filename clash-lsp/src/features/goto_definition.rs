//! Go-to-definition for top-level clash policy symbols.

use tower_lsp::lsp_types::{GotoDefinitionResponse, Location, Position, Url};

use crate::analysis::ParsedPolicy;
use crate::features::hover::word_at;

/// Look up the word under `pos` in the symbol index and return its definition location.
pub fn goto(
    parsed: &ParsedPolicy,
    source: &str,
    uri: &Url,
    pos: Position,
) -> Option<GotoDefinitionResponse> {
    let word = word_at(source, pos)?;
    let range = parsed.symbols.get(&word)?;
    Some(GotoDefinitionResponse::Scalar(Location { uri: uri.clone(), range }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::parse;

    #[test]
    fn goto_finds_local_definition() {
        let src = "my_rule = {}\npolicy(\"x\", my_rule)\n";
        let parsed = parse("x.star", src);
        let uri: Url = "file:///x.star".parse().unwrap();
        // Line 1: `policy("x", my_rule)` — col 13 is 'y' (inside "my_rule" which starts at col 12).
        let resp = goto(&parsed, src, &uri, Position { line: 1, character: 13 });
        assert!(resp.is_some(), "expected definition, got None");
    }
}
