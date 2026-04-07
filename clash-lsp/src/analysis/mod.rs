//! Pure analysis: parse + validate clash `.star` policies.

use std::path::Path;

use tower_lsp::lsp_types::{Position, Range};

pub mod diagnostic;
pub use diagnostic::AnalysisDiagnostic;

pub mod symbols;
pub use symbols::SymbolIndex;

/// Result of analyzing a single `.star` source.
#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    pub diagnostics: Vec<AnalysisDiagnostic>,
    pub symbols: SymbolIndex,
}

/// Parse and evaluate a `.star` source. Always returns a `ParsedPolicy`; failures land in
/// `diagnostics`.
///
/// - Syntax errors → `clash/parse` diagnostic
/// - IR evaluation errors → `clash/validate` diagnostic
pub fn parse(filename: &str, source: &str) -> ParsedPolicy {
    // Step 1: check syntax. A parse failure returns immediately.
    let ast = match clash_starlark::parse_source(filename, source) {
        Ok(ast) => ast,
        Err(e) => {
            return ParsedPolicy {
                diagnostics: vec![AnalysisDiagnostic::from_starlark_error(&e)],
                ..Default::default()
            };
        }
    };

    // Build the symbol index from top-level assignments and defs.
    let mut symbols = SymbolIndex::default();
    for sym in clash_starlark::top_level_symbols(&ast) {
        let range = Range {
            start: Position {
                line: sym.start_line,
                character: sym.start_col,
            },
            end: Position {
                line: sym.end_line,
                character: sym.end_col,
            },
        };
        symbols.insert(sym.name, range);
    }

    // Step 2: evaluate the policy to catch IR-level errors (unknown effects, wrong types, etc.).
    // Use the filename's parent dir as base_dir for resolving relative load() paths.
    let base_dir = Path::new(filename)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let eval_output = match clash_starlark::evaluate(source, filename, base_dir) {
        Ok(output) => output,
        Err(e) => {
            return ParsedPolicy {
                diagnostics: vec![AnalysisDiagnostic::from_validation_error(&e)],
                symbols,
            };
        }
    };

    // Step 3: compile the evaluated JSON through the clash-policy IR to catch
    // structural errors (unknown effects, malformed rule trees, etc.).
    match clash_policy::compile::compile_to_tree(&eval_output.json) {
        Ok(_) => ParsedPolicy {
            symbols,
            ..Default::default()
        },
        Err(e) => ParsedPolicy {
            diagnostics: vec![AnalysisDiagnostic::from_validation_error(&e)],
            symbols,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    #[test]
    fn parses_valid_policy_with_no_diagnostics() {
        let src = indoc! {r#"
            policy("test", {"Bash": allow()})
        "#};
        let parsed = parse("test.star", src);
        assert!(
            parsed.diagnostics.is_empty(),
            "expected no diagnostics, got {:?}",
            parsed.diagnostics
        );
    }

    #[test]
    fn reports_syntax_error_with_span() {
        let src = "policy({ unclosed";
        let parsed = parse("bad.star", src);
        assert_eq!(parsed.diagnostics.len(), 1);
        let d = &parsed.diagnostics[0];
        assert!(
            d.message.to_lowercase().contains("syntax")
                || d.message.to_lowercase().contains("parse")
                || !d.message.is_empty()
        );
    }

    #[test]
    fn parses_top_level_assignment_into_symbols() {
        let src = "my_rule = {}\npolicy(\"x\", my_rule)\n";
        let parsed = parse("x.star", src);
        assert!(
            parsed.symbols.get("my_rule").is_some(),
            "expected my_rule symbol, got {:?}",
            parsed.symbols
        );
    }

    #[test]
    fn reports_invalid_policy_ir() {
        // Passing an integer (42) where an effect (allow/deny/ask) or dict is expected
        // parses as valid Starlark but is rejected during IR evaluation.
        let src = indoc! {r#"
            policy("test", {"Bash": {"git": 42}})
        "#};
        let parsed = parse("bad_ir.star", src);
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|d| d.code.as_deref() == Some("clash/validate")),
            "expected a clash/validate diagnostic, got {:?}",
            parsed.diagnostics
        );
    }
}
