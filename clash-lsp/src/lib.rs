//! Language Server Protocol implementation for clash policy files.

pub mod analysis;
pub mod documents;
pub mod features;
pub mod install;
pub mod schema;
pub mod server;

use std::fs::OpenOptions;
use tracing_subscriber::{EnvFilter, fmt};

/// Initialize a tracing subscriber for the language server.
///
/// Logs go to **stderr** by default (Zed/VS Code surface server stderr in their
/// LSP log panels). If `CLASH_LSP_LOG` is set to a path, logs are *also*
/// appended to that file — useful when you want a stable log to tail from
/// another terminal.
///
/// The verbosity is controlled by `CLASH_LSP_LOG_LEVEL` (defaulting to `info`),
/// or by the standard `RUST_LOG` env var which takes precedence if set.
fn init_tracing() {
    let filter = EnvFilter::try_from_env("RUST_LOG")
        .or_else(|_| {
            let level = std::env::var("CLASH_LSP_LOG_LEVEL").unwrap_or_else(|_| "info".into());
            EnvFilter::try_new(format!(
                "clash_lsp={level},clash_starlark=warn,clash_policy=warn"
            ))
        })
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let stderr_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(true);

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer);

    if let Ok(path) = std::env::var("CLASH_LSP_LOG") {
        if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
            let file_layer = fmt::layer()
                .with_writer(file)
                .with_ansi(false)
                .with_target(true);
            let _ = registry.with(file_layer).try_init();
            return;
        }
    }

    let _ = registry.try_init();
}

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Run the language server over stdio. Blocks until the client disconnects.
pub async fn run_stdio() -> anyhow::Result<()> {
    init_tracing();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "clash-lsp starting");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = tower_lsp::LspService::new(server::Backend::new);
    tower_lsp::Server::new(stdin, stdout, socket)
        .serve(service)
        .await;

    tracing::info!("clash-lsp shutting down");
    Ok(())
}
