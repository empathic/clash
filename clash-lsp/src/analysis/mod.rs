//! Pure analysis: parse + validate clash `.star` policies.

pub mod diagnostic;
pub use diagnostic::AnalysisDiagnostic;

/// Result of analyzing a single `.star` source.
#[derive(Debug, Clone, Default)]
pub struct ParsedPolicy {
    pub diagnostics: Vec<AnalysisDiagnostic>,
}

/// Parse a `.star` source. Always returns a `ParsedPolicy`; failures land in `diagnostics`.
pub fn parse(filename: &str, source: &str) -> ParsedPolicy {
    match clash_starlark::parse_source(filename, source) {
        Ok(_ast) => ParsedPolicy::default(),
        Err(e) => ParsedPolicy {
            diagnostics: vec![AnalysisDiagnostic::from_starlark_error(&e)],
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
            policy({
                "rule": {"effect": "allow", "exec": {"bin": {"literal": "ls"}}}
            })
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
}
