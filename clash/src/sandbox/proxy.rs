//! HTTP forward proxy for domain-level network filtering.
//!
//! Provides a lightweight HTTP proxy that enforces domain allowlists at the
//! sandbox boundary.  Supports both CONNECT tunneling (for HTTPS) and plain
//! HTTP forwarding.  Built on tokio + hyper for correct HTTP framing and
//! connection lifecycle management.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tracing::{debug, trace, warn};

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn empty_body() -> BoxBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body(msg: impl Into<Bytes>) -> BoxBody {
    Full::new(msg.into())
        .map_err(|never| match never {})
        .boxed()
}

fn error_response(status: u16, reason: &str) -> Response<BoxBody> {
    let body_text = format!("{status} {reason}\r\n");
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header("Connection", "close")
        .body(full_body(body_text))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration for the filtering proxy.
pub struct ProxyConfig {
    /// Domains that are permitted through the proxy.  An entry of
    /// `"github.com"` allows both `github.com` itself **and** any subdomain
    /// such as `api.github.com`.
    pub allowed_domains: Vec<String>,
}

/// Handle to a running proxy.  Dropping the handle initiates a clean shutdown.
pub struct ProxyHandle {
    /// The `127.0.0.1:<port>` address the proxy is listening on.
    pub addr: SocketAddr,
    /// Dropping the sender signals the accept loop to stop.
    shutdown: Option<oneshot::Sender<()>>,
    /// The std::thread running the tokio runtime.
    runtime_thread: Option<thread::JoinHandle<()>>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        // Signal shutdown by dropping the sender.
        drop(self.shutdown.take());
        if let Some(handle) = self.runtime_thread.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Domain matching
// ---------------------------------------------------------------------------

/// Returns `true` if `host` is permitted by the allowlist.
///
/// Matching rules:
/// - Exact match: `"github.com"` matches host `"github.com"`.
/// - Subdomain match: `"github.com"` matches host `"api.github.com"`.
/// - No false positives: `"github.com"` does **not** match `"notgithub.com"`.
pub fn is_domain_allowed(host: &str, allowed: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    for domain in allowed {
        let domain = domain.to_ascii_lowercase();
        if host == domain {
            return true;
        }
        // Subdomain match: host must end with `.<domain>`.
        if host.ends_with(&format!(".{domain}")) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Proxy entry point
// ---------------------------------------------------------------------------

/// Start the filtering proxy.
///
/// Binds to `127.0.0.1:0` (OS-assigned ephemeral port), spawns a background
/// tokio runtime that accepts connections, and returns a [`ProxyHandle`] whose
/// lifetime controls the proxy.
pub fn start_proxy(config: ProxyConfig) -> io::Result<ProxyHandle> {
    // Bind with std so the address is available synchronously.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = std_listener.local_addr()?;
    debug!(addr = %addr, "proxy listening");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let config = Arc::new(config);

    let runtime_thread = thread::Builder::new()
        .name("proxy-runtime".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for proxy");

            rt.block_on(accept_loop(std_listener, shutdown_rx, config));
        })?;

    Ok(ProxyHandle {
        addr,
        shutdown: Some(shutdown_tx),
        runtime_thread: Some(runtime_thread),
    })
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

async fn accept_loop(
    std_listener: std::net::TcpListener,
    shutdown_rx: oneshot::Receiver<()>,
    config: Arc<ProxyConfig>,
) {
    std_listener
        .set_nonblocking(true)
        .expect("failed to set listener non-blocking");
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .expect("failed to create tokio TcpListener");

    tokio::pin!(shutdown_rx);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        trace!(peer = %peer, "accepted connection");
                        let cfg = Arc::clone(&config);
                        tokio::task::spawn(async move {
                            if let Err(e) = serve_connection(stream, cfg).await {
                                debug!(peer = %peer, error = %e, "connection finished with error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "accept error");
                    }
                }
            }
            _ = &mut shutdown_rx => {
                debug!("proxy accept loop shutting down");
                break;
            }
        }
    }
    debug!("proxy accept loop exiting");
}

// ---------------------------------------------------------------------------
// Per-connection handler (hyper service)
// ---------------------------------------------------------------------------

async fn serve_connection(
    stream: TcpStream,
    config: Arc<ProxyConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let io = TokioIo::new(stream);

    server_http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let cfg = Arc::clone(&config);
                async move { proxy_handler(req, cfg).await }
            }),
        )
        .with_upgrades()
        .await?;

    Ok(())
}

async fn proxy_handler(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
) -> Result<Response<BoxBody>, Infallible> {
    if req.method() == Method::CONNECT {
        handle_connect(req, &config).await
    } else {
        handle_http(req, &config).await
    }
}

// ---------------------------------------------------------------------------
// CONNECT (HTTPS tunneling)
// ---------------------------------------------------------------------------

async fn handle_connect(
    req: Request<Incoming>,
    config: &ProxyConfig,
) -> Result<Response<BoxBody>, Infallible> {
    let authority = match req.uri().authority() {
        Some(auth) => auth.to_string(),
        None => {
            warn!("CONNECT request missing authority");
            return Ok(error_response(400, "Bad Request"));
        }
    };

    let host = extract_host_from_authority(&authority);

    if !is_domain_allowed(host, &config.allowed_domains) {
        warn!(host = %host, "CONNECT blocked by allowlist");
        return Ok(error_response(403, "Forbidden"));
    }

    debug!(authority = %authority, "CONNECT allowed");

    // Verify upstream is reachable before sending 200.
    let upstream = match TcpStream::connect(&authority).await {
        Ok(s) => s,
        Err(e) => {
            warn!(authority = %authority, error = %e, "failed to connect upstream");
            return Ok(error_response(502, "Bad Gateway"));
        }
    };

    // Spawn the tunnel task.  It awaits the upgrade, then relays bytes.
    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                let mut server = upstream;
                if let Err(e) = copy_bidirectional(&mut client, &mut server).await {
                    debug!(error = %e, "tunnel relay finished with error");
                }
            }
            Err(e) => {
                warn!(error = %e, "CONNECT upgrade failed");
            }
        }
    });

    // Return 200 to trigger the upgrade.
    Ok(Response::new(empty_body()))
}

// ---------------------------------------------------------------------------
// Plain HTTP forwarding
// ---------------------------------------------------------------------------

async fn handle_http(
    req: Request<Incoming>,
    config: &ProxyConfig,
) -> Result<Response<BoxBody>, Infallible> {
    let host = match extract_target_host(&req) {
        Some(h) => h,
        None => {
            warn!("could not determine target host");
            return Ok(error_response(400, "Bad Request"));
        }
    };

    if !is_domain_allowed(&host, &config.allowed_domains) {
        warn!(host = %host, "HTTP request blocked by allowlist");
        return Ok(error_response(403, "Forbidden"));
    }

    debug!(host = %host, method = %req.method(), "HTTP request allowed");

    // Determine upstream address.  Default to port 80.
    let addr = if let Some(authority) = req.uri().authority() {
        let auth_str = authority.to_string();
        if auth_str.contains(':') {
            auth_str
        } else {
            format!("{auth_str}:80")
        }
    } else {
        format!("{host}:80")
    };

    // Connect to upstream.
    let upstream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(addr = %addr, error = %e, "failed to connect upstream");
            return Ok(error_response(502, "Bad Gateway"));
        }
    };

    let io = TokioIo::new(upstream);

    // HTTP/1.1 handshake with upstream.
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(parts) => parts,
        Err(e) => {
            warn!(error = %e, "upstream handshake failed");
            return Ok(error_response(502, "Bad Gateway"));
        }
    };

    // Drive the upstream connection in the background.
    tokio::task::spawn(async move {
        if let Err(e) = conn.await {
            debug!(error = %e, "upstream connection error");
        }
    });

    // Transform URI from absolute-form to origin-form for the upstream.
    let (mut parts, body) = req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    parts.uri = path_and_query.parse().unwrap_or_default();
    let upstream_req = Request::from_parts(parts, body);

    // Forward the request and collect the response.
    match sender.send_request(upstream_req).await {
        Ok(resp) => {
            let (resp_parts, incoming) = resp.into_parts();
            match incoming.collect().await {
                Ok(collected) => {
                    let body = full_body(collected.to_bytes());
                    Ok(Response::from_parts(resp_parts, body))
                }
                Err(e) => {
                    warn!(error = %e, "failed to read upstream response");
                    Ok(error_response(502, "Bad Gateway"))
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "failed to forward request");
            Ok(error_response(502, "Bad Gateway"))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the hostname portion from an `authority` string (`host:port`).
fn extract_host_from_authority(authority: &str) -> &str {
    // Handle IPv6 bracket notation: [::1]:443
    if authority.starts_with('[')
        && let Some(bracket_end) = authority.find(']')
    {
        return &authority[1..bracket_end];
    }
    authority
        .rsplit_once(':')
        .map(|(host, _port)| host)
        .unwrap_or(authority)
}

/// Extract the target hostname from a plain HTTP request.
///
/// Checks the absolute-form URI first, then falls back to the Host header.
fn extract_target_host(req: &Request<Incoming>) -> Option<String> {
    // Absolute-form URI: http://host[:port]/path
    if let Some(authority) = req.uri().authority() {
        let host = authority.host();
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }

    // Host header fallback.
    if let Some(host_value) = req.headers().get(hyper::header::HOST)
        && let Ok(host_str) = host_value.to_str()
    {
        let host = host_str.split(':').next().unwrap_or(host_str);
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::time::Duration;

    // -- Domain matching ---------------------------------------------------

    #[test]
    fn test_is_domain_allowed_exact() {
        let allowed = vec!["github.com".to_string()];
        assert!(is_domain_allowed("github.com", &allowed));
    }

    #[test]
    fn test_is_domain_allowed_subdomain() {
        let allowed = vec!["github.com".to_string()];
        assert!(is_domain_allowed("api.github.com", &allowed));
    }

    #[test]
    fn test_is_domain_allowed_no_false_positive() {
        let allowed = vec!["github.com".to_string()];
        assert!(!is_domain_allowed("notgithub.com", &allowed));
    }

    #[test]
    fn test_is_domain_allowed_denied() {
        let allowed = vec!["github.com".to_string()];
        assert!(!is_domain_allowed("evil.com", &allowed));
    }

    // -- Proxy lifecycle ---------------------------------------------------

    #[test]
    fn test_proxy_lifecycle() {
        let handle = start_proxy(ProxyConfig {
            allowed_domains: vec!["example.com".into()],
        })
        .unwrap();
        let addr = handle.addr;

        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);

        // Should be able to connect.
        let stream = std::net::TcpStream::connect(addr).unwrap();
        drop(stream);

        // Drop the handle -- proxy should shut down deterministically.
        drop(handle);

        // After drop returns, the listener is closed.
        assert!(
            std::net::TcpStream::connect_timeout(&addr.into(), Duration::from_millis(200)).is_err(),
            "proxy should have stopped accepting connections"
        );
    }

    // -- Proxy blocks unlisted domains -------------------------------------

    #[test]
    fn test_proxy_denies_unlisted_domain() {
        let handle = start_proxy(ProxyConfig {
            allowed_domains: vec!["github.com".into()],
        })
        .unwrap();

        let mut stream = std::net::TcpStream::connect(handle.addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n"
        )
        .unwrap();

        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let code: u16 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert_eq!(code, 403, "expected 403 Forbidden, got: {line}");
    }

    // -- Proxy allows listed domain via CONNECT ----------------------------

    #[test]
    fn test_proxy_allows_listed_domain_connect() {
        // Mock upstream server: accepts one connection, writes a greeting,
        // shuts down its write half, then drains reads.
        let upstream_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind upstream");
        let upstream_port = upstream_listener.local_addr().unwrap().port();

        let upstream_thread = std::thread::spawn(move || {
            let (mut conn, _) = upstream_listener.accept().expect("upstream accept");
            conn.write_all(b"HELLO FROM UPSTREAM\n")
                .expect("upstream write");
            conn.flush().unwrap();
            let _ = conn.shutdown(std::net::Shutdown::Write);
            let mut buf = [0u8; 1024];
            while let Ok(n) = conn.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });

        let handle = start_proxy(ProxyConfig {
            allowed_domains: vec!["localhost".into()],
        })
        .unwrap();

        let mut stream = std::net::TcpStream::connect(handle.addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            stream,
            "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .unwrap();

        let reader_stream = stream.try_clone().unwrap();
        let mut reader = BufReader::new(reader_stream);

        // Read status line.
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        let code: u16 = status.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert_eq!(code, 200, "expected 200, got: {status}");

        // Consume headers until blank line (hyper may add headers).
        loop {
            let mut hdr = String::new();
            reader.read_line(&mut hdr).unwrap();
            if hdr.trim().is_empty() {
                break;
            }
        }

        // Read the upstream greeting through the tunnel.
        let mut greeting = String::new();
        reader.read_line(&mut greeting).unwrap();
        assert_eq!(greeting, "HELLO FROM UPSTREAM\n");

        // Clean shutdown.
        let _ = stream.shutdown(std::net::Shutdown::Write);
        drop(stream);
        drop(reader);
        upstream_thread.join().expect("upstream thread panicked");
    }
}
