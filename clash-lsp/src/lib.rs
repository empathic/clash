//! Language Server Protocol implementation for clash policy files.

pub mod analysis;
pub mod documents;
pub mod features;
pub mod install;
pub mod schema;
pub mod server;

/// Run the language server over stdio. Blocks until the client disconnects.
pub async fn run_stdio() -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = tower_lsp::LspService::new(server::Backend::new);
    tower_lsp::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;
    Ok(())
}
