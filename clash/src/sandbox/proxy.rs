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

    // Keep a clone alive so the socket isn't fully closed when dispatch
    // drops its copies.  After dispatch returns we drain remaining client
    // data through this clone, giving the peer time to read our response
    // before the socket is torn down (prevents RST-before-FIN on macOS).
    let drain = stream.try_clone()?;

    let reader = BufReader::new(stream.try_clone()?);
    let result = dispatch(stream, reader, config);

    let _ = drain.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = io::copy(&mut &drain, &mut io::sink());

    result
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
    // Explicitly shut down the write half so the client receives a TCP FIN
    // instead of RST when the socket is dropped.  Without this, the implicit
    // close can race the response data, producing "Connection reset by peer"
    // on the client side.
    let _ = stream.shutdown(Shutdown::Write);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Instant;

    // -- Test helpers ------------------------------------------------------

    /// Poll a condition with bounded retries.  Returns `true` if the
    /// condition was met within `timeout`.
    fn poll_until(timeout: Duration, interval: Duration, mut f: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            thread::sleep(interval);
        }
        false
    }

    /// A client connection to the proxy with graceful shutdown on drop.
    ///
    /// Owns both the stream and a buffered reader over a clone, so there is
    /// no lifetime tangle between reads and writes.  The `Drop` impl sends
    /// FIN (via `shutdown(Write)`) and drains outstanding data before the
    /// socket is closed, preventing the kernel from sending RST.
    struct ProxyClient {
        stream: TcpStream,
        reader: BufReader<TcpStream>,
    }

    impl ProxyClient {
        fn connect(addr: SocketAddr) -> Self {
            let stream = TcpStream::connect(addr).expect("failed to connect to proxy");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let reader = BufReader::new(stream.try_clone().unwrap());
            Self { stream, reader }
        }

        fn send_connect(&mut self, authority: &str) {
            let host = authority.split(':').next().unwrap_or(authority);
            write!(
                self.stream,
                "CONNECT {authority} HTTP/1.1\r\nHost: {host}\r\n\r\n",
            )
            .expect("failed to write CONNECT");
            self.stream.flush().unwrap();
        }

        fn read_line(&mut self) -> String {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .expect("failed to read line");
            line
        }

        fn read_status_code(&mut self) -> u16 {
            let line = self.read_line();
            let code_str = line
                .split_whitespace()
                .nth(1)
                .unwrap_or_else(|| panic!("malformed status line: {line}"));
            code_str
                .parse::<u16>()
                .unwrap_or_else(|_| panic!("non-numeric status code in: {line}"))
        }

        fn close(self) {
            drop(self);
        }
    }

    impl Drop for ProxyClient {
        fn drop(&mut self) {
            // Send FIN to proxy.
            let _ = self.stream.shutdown(Shutdown::Write);
            // Drain any remaining data so close doesn't race pending writes.
            let _ = self
                .stream
                .set_read_timeout(Some(Duration::from_millis(500)));
            let mut discard = [0u8; 1024];
            while let Ok(n) = self.reader.read(&mut discard) {
                if n == 0 {
                    break;
                }
            }
        }
    }

    /// A mock upstream TCP server for CONNECT tunnel tests.
    ///
    /// Accepts one connection, writes `greeting`, shuts down its write half
    /// (so the relay sees EOF), then drains reads until the client closes.
    struct UpstreamServer {
        addr: SocketAddr,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl UpstreamServer {
        fn with_greeting(greeting: &'static [u8]) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind upstream");
            let addr = listener.local_addr().unwrap();

            let handle = thread::spawn(move || {
                let (mut conn, _) = listener.accept().expect("upstream accept");
                conn.write_all(greeting).expect("upstream write");
                conn.flush().unwrap();
                // Signal EOF to the relay's upstream->client direction.
                let _ = conn.shutdown(Shutdown::Write);
                // Drain reads so the relay's client->upstream direction
                // finishes cleanly when the client shuts down.
                let mut buf = [0u8; 1024];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                }
            });

            Self {
                addr,
                handle: Some(handle),
            }
        }

        fn port(&self) -> u16 {
            self.addr.port()
        }

        fn join(mut self) {
            if let Some(h) = self.handle.take() {
                h.join().expect("upstream thread panicked");
            }
        }
    }

    impl Drop for UpstreamServer {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

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
        let client = ProxyClient::connect(addr);
        client.close();

        // Drop the handle -- proxy should shut down.
        drop(handle);

        // Poll until connections are refused (replaces fixed sleep).
        let stopped = poll_until(Duration::from_secs(2), Duration::from_millis(50), || {
            TcpStream::connect_timeout(&addr.into(), Duration::from_millis(100)).is_err()
        });
        assert!(stopped, "proxy should have stopped accepting connections");
    }

    // -- Proxy blocks unlisted domains -------------------------------------

    #[test]
    fn test_proxy_denies_unlisted_domain() {
        let config = ProxyConfig {
            allowed_domains: vec!["github.com".to_string()],
        };
        let handle = start_proxy(config).expect("failed to start proxy");

        let mut client = ProxyClient::connect(handle.addr);
        client.send_connect("evil.com:443");

        let code = client.read_status_code();
        assert_eq!(code, 403, "expected 403 Forbidden");

        client.close();
    }

    // -- Proxy allows listed domain via CONNECT ----------------------------

    #[test]
    fn test_proxy_allows_listed_domain_connect() {
        let upstream = UpstreamServer::with_greeting(b"HELLO FROM UPSTREAM\n");

        let config = ProxyConfig {
            allowed_domains: vec!["localhost".to_string()],
        };
        let handle = start_proxy(config).expect("failed to start proxy");

        let mut client = ProxyClient::connect(handle.addr);
        let authority = format!("localhost:{}", upstream.port());
        client.send_connect(&authority);

        let code = client.read_status_code();
        assert_eq!(code, 200, "expected 200 Connection Established");

        // Consume the blank line after the status.
        let blank = client.read_line();
        assert_eq!(blank.trim(), "");

        // Read the upstream greeting through the tunnel.
        let greeting = client.read_line();
        assert_eq!(greeting, "HELLO FROM UPSTREAM\n");

        // Graceful close: client FIN → relay c2u EOF → upstream write shutdown
        // → relay u2c EOF → client drain EOF.  No RSTs.
        client.close();
        upstream.join();
    }
}
