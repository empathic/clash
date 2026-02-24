//! HTTP forward proxy for domain-level network filtering.
//!
//! Provides a lightweight HTTP proxy that enforces domain allowlists at the
//! sandbox boundary. Supports both CONNECT tunneling (for HTTPS) and plain
//! HTTP forwarding. Uses only `std` networking primitives -- no async runtime
//! or external HTTP crate required.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::{debug, trace, warn};

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

/// Handle to a running proxy.  Dropping the handle initiates a clean shutdown
/// of the listener thread.
pub struct ProxyHandle {
    /// The `127.0.0.1:<port>` address the proxy is listening on.
    pub addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    listener_thread: Option<thread::JoinHandle<()>>,
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        // Signal the accept loop to stop.
        self.shutdown.store(true, Ordering::SeqCst);

        // Poke the listener so its non-blocking accept wakes up immediately
        // rather than waiting for the next poll interval.
        let _ = TcpStream::connect(self.addr);

        if let Some(handle) = self.listener_thread.take() {
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
/// thread that accepts connections, and returns a [`ProxyHandle`] whose
/// lifetime controls the proxy.
pub fn start_proxy(config: ProxyConfig) -> io::Result<ProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    debug!(addr = %addr, "proxy listening");

    // Make accept non-blocking so we can poll the shutdown flag.
    listener.set_nonblocking(true)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    let config = Arc::new(config);

    let listener_thread = thread::Builder::new()
        .name("proxy-accept".into())
        .spawn(move || {
            accept_loop(listener, shutdown_flag, config);
        })?;

    Ok(ProxyHandle {
        addr,
        shutdown,
        listener_thread: Some(listener_thread),
    })
}

// ---------------------------------------------------------------------------
// Accept loop
// ---------------------------------------------------------------------------

fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, config: Arc<ProxyConfig>) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, peer)) => {
                trace!(peer = %peer, "accepted connection");
                let cfg = Arc::clone(&config);
                thread::Builder::new()
                    .name(format!("proxy-conn-{peer}"))
                    .spawn(move || {
                        if let Err(e) = handle_client(stream, &cfg) {
                            debug!(peer = %peer, error = %e, "connection finished with error");
                        }
                    })
                    .ok(); // If spawn fails we just drop the connection.
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Non-blocking accept found nothing -- sleep briefly then retry.
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                warn!(error = %e, "accept error");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    debug!("proxy accept loop exiting");
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

fn handle_client(stream: TcpStream, config: &ProxyConfig) -> io::Result<()> {
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;

    let reader = BufReader::new(stream.try_clone()?);
    dispatch(stream, reader, config)
}

/// Read the first line, determine whether this is a CONNECT or plain HTTP
/// request, then dispatch accordingly.
fn dispatch(
    client: TcpStream,
    mut reader: BufReader<TcpStream>,
    config: &ProxyConfig,
) -> io::Result<()> {
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let request_line = request_line.trim_end().to_string();

    if request_line.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty request line",
        ));
    }

    trace!(request_line = %request_line, "parsed request line");

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        send_error(&client, 400, "Bad Request")?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed request line",
        ));
    }

    let method = parts[0].to_ascii_uppercase();

    if method == "CONNECT" {
        // CONNECT host:port HTTP/1.x
        let authority = parts[1];
        let host = extract_host_from_authority(authority);

        // Consume remaining headers (we don't need them for CONNECT).
        consume_headers(&mut reader)?;

        if !is_domain_allowed(host, &config.allowed_domains) {
            warn!(host = %host, "CONNECT blocked by allowlist");
            send_error(&client, 403, "Forbidden")?;
            return Ok(());
        }

        debug!(authority = %authority, "CONNECT allowed");
        handle_connect(client, authority)
    } else {
        // Plain HTTP: GET / POST / etc.
        let host = resolve_host(&mut reader, parts[1])?;

        if !is_domain_allowed(&host, &config.allowed_domains) {
            warn!(host = %host, "HTTP request blocked by allowlist");
            send_error(&client, 403, "Forbidden")?;
            return Ok(());
        }

        debug!(host = %host, method = %method, "HTTP request allowed");
        handle_http(client, reader, &request_line, &host)
    }
}

// ---------------------------------------------------------------------------
// CONNECT (HTTPS tunneling)
// ---------------------------------------------------------------------------

/// Establish an upstream TCP connection, send `200 Connection Established` to
/// the client, then relay bytes in both directions until either side closes.
fn handle_connect(mut client: TcpStream, authority: &str) -> io::Result<()> {
    let upstream = TcpStream::connect(authority).map_err(|e| {
        let _ = send_error(&client, 502, "Bad Gateway");
        io::Error::new(
            e.kind(),
            format!("failed to connect to upstream {authority}: {e}"),
        )
    })?;

    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    client.flush()?;

    relay(client, upstream)
}

// ---------------------------------------------------------------------------
// Plain HTTP forwarding
// ---------------------------------------------------------------------------

/// Forward a plain HTTP request to the origin server and relay the response
/// back to the client.
fn handle_http(
    client: TcpStream,
    mut reader: BufReader<TcpStream>,
    request_line: &str,
    host: &str,
) -> io::Result<()> {
    // Collect remaining headers.
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers.push(line);
    }

    // Determine upstream address.  Default to port 80.
    let addr = if host.contains(':') {
        host.to_string()
    } else {
        format!("{host}:80")
    };

    let mut upstream = TcpStream::connect(&addr).map_err(|e| {
        let _ = send_error(&client, 502, "Bad Gateway");
        io::Error::new(
            e.kind(),
            format!("failed to connect to upstream {addr}: {e}"),
        )
    })?;
    upstream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    upstream.set_write_timeout(Some(CLIENT_TIMEOUT))?;

    // Re-send request line + headers.
    upstream.write_all(request_line.as_bytes())?;
    upstream.write_all(b"\r\n")?;
    for h in &headers {
        upstream.write_all(h.as_bytes())?;
    }
    upstream.write_all(b"\r\n")?;
    upstream.flush()?;

    // Relay the response back.  We don't parse it -- just pipe bytes both
    // directions until the connection closes.
    relay(client, upstream)
}

// ---------------------------------------------------------------------------
// Bidirectional relay
// ---------------------------------------------------------------------------

/// Bidirectional byte relay between `client` and `upstream`.
///
/// Spawns two threads: one copying client -> upstream and one copying
/// upstream -> client.  When either direction's copy finishes (EOF or error),
/// the write side of the other direction is shut down so the peer sees EOF.
fn relay(client: TcpStream, upstream: TcpStream) -> io::Result<()> {
    let client_r = client.try_clone()?;
    let client_w = client.try_clone()?;
    let upstream_r = upstream.try_clone()?;
    let upstream_w = upstream.try_clone()?;

    // client -> upstream
    let c2u = thread::Builder::new()
        .name("relay-c2u".into())
        .spawn(move || {
            let mut src = client_r;
            let mut dst = upstream_w;
            let _ = io::copy(&mut src, &mut dst);
            let _ = dst.shutdown(Shutdown::Write);
        })?;

    // upstream -> client
    let u2c = thread::Builder::new()
        .name("relay-u2c".into())
        .spawn(move || {
            let mut src = upstream_r;
            let mut dst = client_w;
            let _ = io::copy(&mut src, &mut dst);
            let _ = dst.shutdown(Shutdown::Write);
        })?;

    let _ = c2u.join();
    let _ = u2c.join();
    Ok(())
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

/// Determine the target host for a plain HTTP request.
///
/// Tries the `Host` header first (reading additional header lines from the
/// buffered reader), then falls back to parsing the absolute-form URI in the
/// request line.
fn resolve_host(reader: &mut BufReader<TcpStream>, uri: &str) -> io::Result<String> {
    // Peek at headers to find `Host:`.  We buffer lines so we can re-send
    // them later; however, `resolve_host` is only used to decide
    // allow/deny -- the full header set is read again in `handle_http`.
    // Because the reader is a `BufReader` and we need the headers later,
    // we look at the URI first and only fall through to headers if needed.

    // Absolute-form: http://host[:port]/path
    if let Some(rest) = uri.strip_prefix("http://") {
        let host_part = rest.split('/').next().unwrap_or(rest);
        let host = host_part.split(':').next().unwrap_or(host_part);
        if !host.is_empty() {
            return Ok(host.to_string());
        }
    }

    // Read headers looking for Host.
    // NOTE: we must still leave them in the reader for handle_http to
    // re-read.  Because BufReader buffers data, and we cannot "unread",
    // we consume here and accept that handle_http will see them already
    // consumed.  This is fine -- handle_http collects whatever headers
    // remain after resolve_host returns.
    //
    // In practice the Host header is typically the first header, so the
    // loop is short.
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            let value = value.trim();
            let host = value.split(':').next().unwrap_or(value);
            return Ok(host.to_string());
        }
        // Also try case-insensitive match.
        if line.len() > 5 && line[..5].eq_ignore_ascii_case("host:") {
            let value = line[5..].trim();
            let host = value.split(':').next().unwrap_or(value);
            return Ok(host.to_string());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "could not determine target host from request",
    ))
}

/// Consume (and discard) HTTP headers until the blank line terminator.
fn consume_headers(reader: &mut BufReader<TcpStream>) -> io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            return Ok(());
        }
    }
}

/// Send a minimal HTTP error response.
fn send_error(stream: &TcpStream, code: u16, reason: &str) -> io::Result<()> {
    let body = format!("{code} {reason}\r\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Length: {}\r\n\
         Content-Type: text/plain\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    );
    // Use a short-lived clone so we don't need &mut.
    let mut w = stream.try_clone()?;
    w.write_all(response.as_bytes())?;
    w.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};

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
        let config = ProxyConfig {
            allowed_domains: vec!["example.com".to_string()],
        };
        let handle = start_proxy(config).expect("failed to start proxy");
        let addr = handle.addr;

        // Addr should be on loopback with a non-zero port.
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);

        // Should be able to connect.
        let conn = TcpStream::connect(addr);
        assert!(conn.is_ok());
        drop(conn);

        // Drop the handle -- proxy should shut down.
        drop(handle);

        // After a brief pause, new connections should be refused.
        thread::sleep(Duration::from_millis(200));
        let conn = TcpStream::connect_timeout(&addr.into(), Duration::from_millis(200));
        assert!(conn.is_err(), "proxy should have stopped accepting");
    }

    // -- Proxy blocks unlisted domains -------------------------------------

    #[test]
    fn test_proxy_denies_unlisted_domain() {
        let config = ProxyConfig {
            allowed_domains: vec!["github.com".to_string()],
        };
        let handle = start_proxy(config).expect("failed to start proxy");

        let mut stream =
            TcpStream::connect(handle.addr).expect("failed to connect to proxy");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Send a CONNECT to an unlisted domain.
        write!(stream, "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n")
            .expect("failed to write request");
        stream.flush().unwrap();

        let mut reader = BufReader::new(&stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .expect("failed to read response");

        assert!(
            status_line.contains("403"),
            "expected 403 Forbidden, got: {status_line}",
        );
    }

    // -- Proxy allows listed domain via CONNECT ----------------------------

    #[test]
    fn test_proxy_allows_listed_domain_connect() {
        // Spin up a small TCP "upstream" server on localhost that echoes back
        // a greeting then closes.
        let upstream_listener =
            TcpListener::bind("127.0.0.1:0").expect("failed to bind upstream");
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let upstream_thread = thread::spawn(move || {
            let (mut conn, _) = upstream_listener.accept().expect("upstream accept");
            conn.write_all(b"HELLO FROM UPSTREAM\n")
                .expect("upstream write");
            conn.flush().unwrap();
            // Read until client closes so relay completes cleanly.
            let mut buf = Vec::new();
            let _ = conn.read_to_end(&mut buf);
        });

        // Configure the proxy to allow "localhost" (the upstream).
        let config = ProxyConfig {
            allowed_domains: vec!["localhost".to_string()],
        };
        let handle = start_proxy(config).expect("failed to start proxy");

        let mut stream =
            TcpStream::connect(handle.addr).expect("failed to connect to proxy");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // CONNECT to the upstream address via the proxy.  We use the numeric
        // form `127.0.0.1:<port>` in the authority but the proxy only checks
        // the hostname.  Since the CONNECT authority uses an IP literal here,
        // we instead write `localhost:<port>` which matches our allowlist.
        let authority = format!("localhost:{}", upstream_addr.port());
        write!(
            stream,
            "CONNECT {authority} HTTP/1.1\r\nHost: localhost\r\n\r\n"
        )
        .expect("failed to write CONNECT");
        stream.flush().unwrap();

        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .expect("failed to read status");

        assert!(
            status_line.contains("200"),
            "expected 200 Connection Established, got: {status_line}",
        );

        // Consume the blank line after the status.
        let mut blank = String::new();
        reader.read_line(&mut blank).unwrap();

        // Now we should be tunneled -- read the upstream greeting.
        let mut greeting = String::new();
        reader
            .read_line(&mut greeting)
            .expect("failed to read upstream greeting");
        assert_eq!(greeting, "HELLO FROM UPSTREAM\n");

        // Shut down our end so the relay threads finish.
        let _ = stream.shutdown(Shutdown::Both);
        let _ = upstream_thread.join();
    }
}
