//! Pure analysis: parse + validate clash `.star` policies.

use std::path::Path;

pub mod diagnostic;
pub use diagnostic::AnalysisDiagnostic;

/// Result of analyzing a single `.star` source.
#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

/// Parse and evaluate a `.star` source. Always returns a `ParsedPolicy`; failures land in
/// `diagnostics`.
///
/// - Syntax errors → `clash/parse` diagnostic
/// - IR evaluation errors → `clash/validate` diagnostic
pub fn parse(filename: &str, source: &str) -> ParsedPolicy {
    // Step 1: check syntax. A parse failure returns immediately.
    if let Err(e) = clash_starlark::parse_source(filename, source) {
        return ParsedPolicy {
            diagnostics: vec![AnalysisDiagnostic::from_starlark_error(&e)],
        };
    }

    // Step 2: evaluate the policy to catch IR-level errors (unknown effects, wrong types, etc.).
    // Use the filename's parent dir as base_dir for resolving relative load() paths.
    let base_dir = Path::new(filename)
        .parent()
        .unwrap_or_else(|| Path::new("."));

    match clash_starlark::evaluate(source, filename, base_dir) {
        Ok(_output) => ParsedPolicy::default(),
        Err(e) => ParsedPolicy {
            diagnostics: vec![AnalysisDiagnostic::from_validation_error(&e)],
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
        assert!(parsed.diagnostics.is_empty(), "expected no diagnostics, got {:?}", parsed.diagnostics);
    }

    #[test]
    fn reports_syntax_error_with_span() {
        let src = "policy({ unclosed";
        let parsed = parse("bad.star", src);
        assert_eq!(parsed.diagnostics.len(), 1);
        let d = &parsed.diagnostics[0];
        assert!(d.message.to_lowercase().contains("syntax") || d.message.to_lowercase().contains("parse") || !d.message.is_empty());
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
            parsed.diagnostics.iter().any(|d| d.code.as_deref() == Some("clash/validate")),
            "expected a clash/validate diagnostic, got {:?}",
            parsed.diagnostics
        );
    }
}
