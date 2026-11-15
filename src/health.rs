//! A tiny HTTP health endpoint for orchestrators (readiness/liveness probes
//! and load balancer health checks): `GET /healthz`. Nothing else is served.
//! Meant for the internal network only.
//!
//! `/healthz` proves the relay path, not just that this task runs: each
//! request sends a STUN Binding request to uTURN's own UDP port and answers
//! `200 ok` only if the Binding success response comes back within
//! [`PROBE_TIMEOUT`], otherwise `503`. A Binding request from an address
//! without an allocation is answered directly by the receive loop, does not
//! count against the allocation rate limit, and creates no state, so probes
//! leave nothing behind.
//!
//! Each connection is bounded in time and at most [`MAX_CONNS`] are served at
//! once, so a slow or idle client cannot hold up a probe.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::{timeout, timeout_at, Instant};
use tracing::{debug, warn};

use crate::demux::stun::STUN_MAGIC_COOKIE;

/// Connections handled at once; more are closed right away.
const MAX_CONNS: usize = 32;
/// Time a client gets to send its request head.
const READ_DEADLINE: Duration = Duration::from_secs(1);
/// Time a client gets to read the answer.
const WRITE_DEADLINE: Duration = Duration::from_secs(1);
/// The request line and headers may not be longer than this.
const MAX_HEAD: usize = 8192;
/// Pause after a failed accept (e.g. out of file descriptors).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long the relay gets to answer the self-check. Below the 1 s default
/// timeout of a Kubernetes probe, so a hung relay gets a 503 rather than a
/// probe timeout.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(800);
/// The self-check request is sent again after this long without an answer,
/// in case a busy receive buffer dropped it.
const PROBE_RETRANSMIT: Duration = Duration::from_millis(250);

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

/// The address the self-check sends to, given the relay socket's local
/// address: loopback of the same family when the socket is bound to the
/// wildcard address, otherwise the bound address itself.
pub fn probe_target(udp_local: SocketAddr) -> SocketAddr {
    let ip = match udp_local.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, udp_local.port())
}

/// Binds `listen` and serves the health endpoint on a background task. Each
/// `/healthz` request checks the relay at `udp_target` (see
/// [`probe_target`]). Returns the bound address.
pub async fn spawn(listen: SocketAddr, udp_target: SocketAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(serve(listener, udp_target));
    Ok(addr)
}

async fn serve(listener: TcpListener, udp_target: SocketAddr) {
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    let mut failing = false;
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => {
                failing = false;
                s
            }
            Err(e) => {
                if !failing {
                    warn!("Health endpoint accept failed: {}", e);
                    failing = true;
                }
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        // Full: the stream is dropped, which closes it.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(stream, udp_target).await {
                debug!("Health connection ended: {}", e);
            }
        });
    }
}

async fn handle(mut stream: TcpStream, udp_target: SocketAddr) -> io::Result<()> {
    let (status, body) = match read_head(&mut stream).await? {
        Some(head) => match route(&head) {
            Route::Healthz => match self_check(udp_target).await {
                Ok(()) => ("200 OK", "ok\n"),
                Err(e) => {
                    warn!("Health check failed: relay at {} {}", udp_target, e);
                    ("503 Service Unavailable", "relay not responding\n")
                }
            },
            Route::Respond(status, body) => (status, body),
        },
        None => bad_request(),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    timeout(WRITE_DEADLINE, async {
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Sends a STUN Binding request to the relay and waits for the matching
/// success response. The error describes what went wrong, phrased to follow
/// "relay at <addr>".
pub async fn self_check(udp_target: SocketAddr) -> Result<(), String> {
    let bind: SocketAddr = match udp_target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("could not be probed: {e}"))?;
    let tid: [u8; 12] = rand::random();
    let request = binding_request(&tid);
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let mut buf = [0u8; 1500];

    while Instant::now() < deadline {
        // A send error (e.g. ICMP port unreachable reported on a previous
        // round) is not final: the relay may still answer the next one.
        if let Err(e) = socket.send_to(&request, udp_target).await {
            debug!("Health probe send to {} failed: {}", udp_target, e);
        }
        let round_end = (Instant::now() + PROBE_RETRANSMIT).min(deadline);
        loop {
            match timeout_at(round_end, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if is_binding_success(&buf[..len], &tid) => return Ok(()),
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    debug!("Health probe recv from {} failed: {}", udp_target, e);
                    // Avoid a busy loop on a socket that errors immediately.
                    tokio::time::sleep_until(round_end).await;
                    break;
                }
                Err(_) => break, // round timed out, retransmit
            }
        }
    }
    Err(format!(
        "did not answer a STUN Binding request within {PROBE_TIMEOUT:?}"
    ))
}

/// A bare STUN Binding request (RFC 5389, no attributes).
fn binding_request(tid: &[u8; 12]) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(tid);
    msg
}

fn is_binding_success(data: &[u8], tid: &[u8; 12]) -> bool {
    data.len() >= 20
        && u16::from_be_bytes([data[0], data[1]]) == BINDING_SUCCESS
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == STUN_MAGIC_COOKIE
        && &data[8..20] == tid
}

/// Reads the request head up to and including the blank line, so that
/// closing the connection after the answer does not reset it away. Returns
/// `None` if the head is longer than `MAX_HEAD`. A client that closes its side
/// early gets an answer to what it sent.
async fn read_head(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    // One deadline for the whole request, not per read.
    let deadline = Instant::now() + READ_DEADLINE;
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while head_end(&head).is_none() {
        if head.len() >= MAX_HEAD {
            return Ok(None);
        }
        let want = buf.len().min(MAX_HEAD - head.len());
        match timeout_at(deadline, stream.read(&mut buf[..want])).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => head.extend_from_slice(&buf[..n]),
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::ErrorKind::TimedOut.into()),
        }
    }
    Ok(Some(head))
}

/// Where the head ends (after the blank line), if it is complete.
fn head_end(b: &[u8]) -> Option<usize> {
    (0..b.len()).find_map(|i| {
        if b[i..].starts_with(b"\r\n\r\n") {
            Some(i + 4)
        } else if b[i..].starts_with(b"\n\n") {
            Some(i + 2)
        } else {
            None
        }
    })
}

#[derive(Debug, PartialEq)]
enum Route {
    /// Run the self-check and answer with its result.
    Healthz,
    /// Answer right away: (status, plain-text body).
    Respond(&'static str, &'static str),
}

fn bad_request() -> (&'static str, &'static str) {
    ("400 Bad Request", "bad request\n")
}

fn route(head: &[u8]) -> Route {
    let bad = || {
        let (s, b) = bad_request();
        Route::Respond(s, b)
    };
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else {
        return bad();
    };
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return bad();
    };
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return bad();
    }
    let path = target.split('?').next().unwrap_or_default();
    match (method, path) {
        ("GET", "/healthz") => Route::Healthz,
        ("GET", _) => Route::Respond("404 Not Found", "not found\n"),
        _ => Route::Respond("405 Method Not Allowed", "method not allowed\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let status = |head: &[u8]| match route(head) {
            Route::Healthz => "healthz",
            Route::Respond(s, _) => s,
        };
        assert_eq!(
            status(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"),
            "healthz"
        );
        assert_eq!(status(b"GET /healthz?x=1 HTTP/1.0\n\n"), "healthz");
        assert_eq!(status(b"GET /nope HTTP/1.1\r\n\r\n"), "404 Not Found");
        assert_eq!(
            status(b"POST /healthz HTTP/1.1\r\n\r\n"),
            "405 Method Not Allowed"
        );
        assert_eq!(status(b"GET /healthz\r\n\r\n"), "400 Bad Request");
        assert_eq!(status(b"GET \xff HTTP/1.1\r\n\r\n"), "400 Bad Request");
        assert_eq!(status(b"\r\n\r\n"), "400 Bad Request");
        assert_eq!(status(b"hello world foo\r\n\r\n"), "400 Bad Request");
    }

    #[test]
    fn head_end_finds_the_blank_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\n\n"), Some(16));
    }

    #[test]
    fn probe_target_uses_loopback_for_wildcard() {
        let sa = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(probe_target(sa("0.0.0.0:3478")), sa("127.0.0.1:3478"));
        assert_eq!(probe_target(sa("[::]:3478")), sa("[::1]:3478"));
        assert_eq!(probe_target(sa("192.0.2.5:3478")), sa("192.0.2.5:3478"));
    }

    #[test]
    fn binding_success_must_match_transaction() {
        let tid = [7u8; 12];
        let mut msg = binding_request(&tid).to_vec();
        assert!(!is_binding_success(&msg, &tid)); // a request, not a response
        msg[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        assert!(is_binding_success(&msg, &tid));
        assert!(!is_binding_success(&msg, &[8u8; 12]));
        assert!(!is_binding_success(&msg[..19], &tid));
    }
}
