//! `tower_lsp::LanguageServer` implementation.

use tower_lsp::{Client, LanguageServer, jsonrpc};
use tower_lsp::lsp_types::{
    self as tl, Diagnostic, DiagnosticSeverity, InitializeParams, InitializeResult,
    InitializedParams, MessageType, NumberOrString, Position, Range, ServerCapabilities,
    ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, Url,
    DidOpenTextDocumentParams, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
};
use lsp_types::DiagnosticSeverity as Sev95;

use crate::analysis::{AnalysisDiagnostic, ParsedPolicy};
use crate::documents::DocumentStore;

pub struct Backend {
    client: Client,
    docs: DocumentStore,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self { client, docs: DocumentStore::new() }
    }

    async fn publish(&self, uri: Url, parsed: ParsedPolicy) {
        let diags: Vec<Diagnostic> = parsed
            .diagnostics
            .iter()
            .map(diag_to_tl)
            .collect();
        self.client.publish_diagnostics(uri, diags, None).await;
    }
}

/// Convert an [`AnalysisDiagnostic`] (which uses lsp-types 0.95) into a
/// [`tower_lsp::lsp_types::Diagnostic`] (which uses lsp-types 0.94).
///
/// Both crates use the same wire format; we re-map the fields by value.
fn diag_to_tl(d: &AnalysisDiagnostic) -> Diagnostic {
    let r = &d.range;
    Diagnostic {
        range: Range {
            start: Position { line: r.start.line, character: r.start.character },
            end:   Position { line: r.end.line,   character: r.end.character   },
        },
        severity: Some(match d.severity {
            Sev95::ERROR       => DiagnosticSeverity::ERROR,
            Sev95::WARNING     => DiagnosticSeverity::WARNING,
            Sev95::INFORMATION => DiagnosticSeverity::INFORMATION,
            _                  => DiagnosticSeverity::HINT,
        }),
        code: d.code.as_deref().map(|s| NumberOrString::String(s.to_owned())),
        source: Some("clash".into()),
        message: d.message.clone(),
        ..Default::default()
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> jsonrpc::Result<tl::InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "clash-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client.log_message(MessageType::INFO, "clash-lsp ready").await;
    }

    async fn shutdown(&self) -> jsonrpc::Result<()> { Ok(()) }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let parsed = self.docs.open(uri.clone(), params.text_document.text);
        self.publish(uri, parsed).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let Some(change) = params.content_changes.into_iter().next() else { return };
        let parsed = self.docs.change(uri.clone(), change.text);
        self.publish(uri, parsed).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        self.docs.close(&params.text_document.uri);
    }
}
