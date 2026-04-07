//! `tower_lsp::LanguageServer` implementation.

use lsp_types::DiagnosticSeverity as Sev95;
use tower_lsp::lsp_types::{
    self as tl, CompletionOptions, CompletionParams, CompletionResponse, Diagnostic,
    DiagnosticSeverity, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
    DidOpenTextDocumentParams, DocumentFormattingParams, GotoDefinitionParams,
    GotoDefinitionResponse, Hover, HoverParams, HoverProviderCapability, InitializeParams,
    InitializeResult, InitializedParams, MessageType, NumberOrString, OneOf, Position, Range,
    ServerCapabilities, ServerInfo, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit,
    Url,
};
use tower_lsp::{Client, LanguageServer, jsonrpc};

use crate::analysis::{AnalysisDiagnostic, ParsedPolicy};
use crate::documents::DocumentStore;

pub struct Backend {
    client: Client,
    docs: DocumentStore,
    schema: crate::schema::Schema,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            docs: DocumentStore::new(),
            schema: crate::schema::load_builtin(),
        }
    }

    async fn publish(&self, uri: Url, parsed: ParsedPolicy) {
        let diags: Vec<Diagnostic> = parsed.diagnostics.iter().map(diag_to_tl).collect();
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
            start: Position {
                line: r.start.line,
                character: r.start.character,
            },
            end: Position {
                line: r.end.line,
                character: r.end.character,
            },
        },
        severity: Some(match d.severity {
            Sev95::ERROR => DiagnosticSeverity::ERROR,
            Sev95::WARNING => DiagnosticSeverity::WARNING,
            Sev95::INFORMATION => DiagnosticSeverity::INFORMATION,
            _ => DiagnosticSeverity::HINT,
        }),
        code: d
            .code
            .as_deref()
            .map(|s| NumberOrString::String(s.to_owned())),
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
                completion_provider: Some(CompletionOptions::default()),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                document_formatting_provider: Some(OneOf::Left(true)),
                ..Default::default()
            },
            server_info: Some(ServerInfo {
                name: "clash-lsp".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        tracing::info!("client initialized — clash-lsp ready");
        self.client
            .log_message(MessageType::INFO, "clash-lsp ready")
            .await;
    }

    async fn shutdown(&self) -> jsonrpc::Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        tracing::info!(%uri, lang = %params.text_document.language_id, "did_open");
        let parsed = self.docs.open(uri.clone(), params.text_document.text);
        tracing::debug!(diagnostics = parsed.diagnostics.len(), "parsed on open");
        self.publish(uri, parsed).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let Some(change) = params.content_changes.into_iter().next() else {
            return;
        };
        tracing::debug!(%uri, len = change.text.len(), "did_change");
        let parsed = self.docs.change(uri.clone(), change.text);
        self.publish(uri, parsed).await;
    }

    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        tracing::info!(uri = %params.text_document.uri, "did_close");
        self.docs.close(&params.text_document.uri);
    }

    async fn hover(&self, params: HoverParams) -> jsonrpc::Result<Option<Hover>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let Some(source) = self.docs.get_text(uri) else {
            return Ok(None);
        };
        Ok(crate::features::hover::hover(
            &self.schema,
            &source,
            params.text_document_position_params.position,
        ))
    }

    async fn completion(
        &self,
        params: CompletionParams,
    ) -> jsonrpc::Result<Option<CompletionResponse>> {
        let items = crate::features::completion::complete(
            &self.schema,
            "",
            params.text_document_position.position,
        );
        Ok(Some(CompletionResponse::Array(items)))
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> jsonrpc::Result<Option<GotoDefinitionResponse>> {
        let uri = params
            .text_document_position_params
            .text_document
            .uri
            .clone();
        let Some(source) = self.docs.get_text(&uri) else {
            return Ok(None);
        };
        let Some(parsed) = self.docs.get(&uri) else {
            return Ok(None);
        };
        Ok(crate::features::goto_definition::goto(
            &parsed,
            &source,
            &uri,
            params.text_document_position_params.position,
        ))
    }

    async fn formatting(
        &self,
        params: DocumentFormattingParams,
    ) -> jsonrpc::Result<Option<Vec<TextEdit>>> {
        let uri = &params.text_document.uri;
        tracing::info!(%uri, "formatting");
        let Some(source) = self.docs.get_text(uri) else {
            tracing::warn!(%uri, "formatting: document not in store");
            return Ok(None);
        };
        let Some(formatted) = crate::features::formatting::format(&source) else {
            tracing::warn!(%uri, "formatting: parse failed, leaving buffer untouched");
            return Ok(None);
        };
        if formatted == source {
            return Ok(Some(vec![]));
        }
        // Replace the entire document. The end position uses u32::MAX to cover
        // any line/column the editor's view of the buffer might have.
        Ok(Some(vec![TextEdit {
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: u32::MAX,
                    character: u32::MAX,
                },
            },
            new_text: formatted,
        }]))
    }
}
