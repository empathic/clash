//! `tower_lsp::LanguageServer` implementation.

use tower_lsp::{Client, LanguageServer, jsonrpc};
use tower_lsp::lsp_types::*;

pub struct Backend {
    #[allow(dead_code)]
    client: Client,
}

impl Backend {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> jsonrpc::Result<InitializeResult> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities::default(),
            ..Default::default()
        })
    }

    async fn initialized(&self, _: InitializedParams) {}

    async fn shutdown(&self) -> jsonrpc::Result<()> { Ok(()) }
}
