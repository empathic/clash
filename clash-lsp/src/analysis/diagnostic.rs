use lsp_types::{Diagnostic, DiagnosticSeverity, Range};

#[derive(Debug, Clone)]
pub struct AnalysisDiagnostic {
    pub message: String,
    pub severity: DiagnosticSeverity,
    pub range: Range,
    pub code: Option<String>,
}

impl AnalysisDiagnostic {
    pub fn from_starlark_error(err: &starlark::Error) -> Self {
        let range = err
            .span()
            .map(|file_span: &starlark::codemap::FileSpan| {
                let s = file_span.resolve_span();
                Range {
                    start: lsp_types::Position {
                        line: s.begin.line as u32,
                        character: s.begin.column as u32,
                    },
                    end: lsp_types::Position {
                        line: s.end.line as u32,
                        character: s.end.column as u32,
                    },
                }
            })
            .unwrap_or_default();
        Self {
            message: err.to_string(),
            severity: DiagnosticSeverity::ERROR,
            range,
            code: Some("clash/parse".into()),
        }
    }

    /// Create a diagnostic from a policy evaluation or IR validation error.
    ///
    /// IR errors don't carry source spans (they occur post-parse), so the range
    /// defaults to the beginning of the file.
    pub fn from_validation_error(err: &dyn std::fmt::Display) -> Self {
        Self {
            message: err.to_string(),
            severity: DiagnosticSeverity::ERROR,
            range: Range::default(),
            code: Some("clash/validate".into()),
        }
    }

    pub fn to_lsp(&self) -> Diagnostic {
        Diagnostic {
            range: self.range,
            severity: Some(self.severity),
            code: self.code.clone().map(lsp_types::NumberOrString::String),
            source: Some("clash".into()),
            message: self.message.clone(),
            ..Default::default()
        }
    }
}
