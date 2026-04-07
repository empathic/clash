//! Drives `clash-lsp` over an in-memory duplex pipe and asserts that
//! a `didOpen` for an invalid policy produces a `publishDiagnostics`.

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_policy_emits_diagnostic() {
    let (client_to_server, server_from_client) = tokio::io::duplex(8192);
    let (server_to_client, mut client_from_server) = tokio::io::duplex(8192);

    let server = tokio::spawn(async move {
        let (service, socket) = tower_lsp::LspService::new(clash_lsp::server::Backend::new);
        tower_lsp::Server::new(server_from_client, server_to_client, socket)
            .serve(service)
            .await;
    });

    let mut client = client_to_server;

    // initialize
    send(&mut client, &json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"capabilities": {}}
    })).await;
    let _init_resp = read_message(&mut client_from_server).await;

    send(&mut client, &json!({
        "jsonrpc": "2.0", "method": "initialized", "params": {}
    })).await;

    // didOpen with garbage
    send(&mut client, &json!({
        "jsonrpc": "2.0", "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file:///bad.star",
                "languageId": "starlark",
                "version": 1,
                "text": "policy({ unclosed"
            }
        }
    })).await;

    // Drain messages until we see publishDiagnostics (with timeout to fail fast)
    let diag = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let msg = read_message(&mut client_from_server).await;
            if msg["method"] == "textDocument/publishDiagnostics" {
                return msg;
            }
        }
    })
    .await
    .expect("timed out waiting for publishDiagnostics");

    let diags = &diag["params"]["diagnostics"];
    assert!(diags.is_array() && !diags.as_array().unwrap().is_empty(),
        "expected at least one diagnostic, got {diag}");

    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completion_returns_clash_builtins() {
    let (client_to_server, server_from_client) = tokio::io::duplex(8192);
    let (server_to_client, mut client_from_server) = tokio::io::duplex(8192);

    let server = tokio::spawn(async move {
        let (service, socket) = tower_lsp::LspService::new(clash_lsp::server::Backend::new);
        tower_lsp::Server::new(server_from_client, server_to_client, socket)
            .serve(service)
            .await;
    });

    let mut client = client_to_server;

    // initialize
    send(&mut client, &json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"capabilities": {}}
    })).await;
    let _init_resp = read_message(&mut client_from_server).await;

    send(&mut client, &json!({
        "jsonrpc": "2.0", "method": "initialized", "params": {}
    })).await;

    // didOpen with a valid policy
    send(&mut client, &json!({
        "jsonrpc": "2.0", "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file:///x.star",
                "languageId": "starlark",
                "version": 1,
                "text": "policy(\"test\", {\"Bash\": allow()})"
            }
        }
    })).await;

    send(&mut client, &json!({
        "jsonrpc": "2.0", "id": 2, "method": "textDocument/completion",
        "params": {
            "textDocument": {"uri": "file:///x.star"},
            "position": {"line": 0, "character": 0}
        }
    })).await;

    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let msg = read_message(&mut client_from_server).await;
            if msg.get("id") == Some(&json!(2)) { break msg; }
        }
    }).await.expect("timed out waiting for completion response");

    // The result is either an array of CompletionItem or a CompletionList. Handle both.
    let items = if resp["result"].is_array() {
        resp["result"].as_array().unwrap().clone()
    } else {
        resp["result"]["items"].as_array().expect("completion result missing items").clone()
    };
    let labels: std::collections::HashSet<String> = items.iter()
        .filter_map(|i| i.get("label").and_then(|l| l.as_str()).map(String::from))
        .collect();
    assert!(labels.contains("policy"), "missing 'policy' in {labels:?}");
    assert!(labels.contains("sandbox"), "missing 'sandbox' in {labels:?}");
    assert!(labels.contains("settings"), "missing 'settings' in {labels:?}");

    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
}

async fn send(w: &mut tokio::io::DuplexStream, v: &Value) {
    let body = serde_json::to_vec(v).unwrap();
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    w.write_all(header.as_bytes()).await.unwrap();
    w.write_all(&body).await.unwrap();
    w.flush().await.unwrap();
}

async fn read_message(r: &mut tokio::io::DuplexStream) -> Value {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        r.read_exact(&mut byte).await.unwrap();
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") { break; }
    }
    let headers = std::str::from_utf8(&buf).unwrap();
    let len: usize = headers
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}
