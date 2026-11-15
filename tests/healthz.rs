//! The HTTP health endpoint against a real relay, and against a UDP port that
//! never answers.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use uturn::{health, Config, Server};

async fn get(addr: SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(3), s.read_to_string(&mut out))
        .await
        .expect("health endpoint did not answer")
        .unwrap();
    out
}

#[tokio::test]
async fn healthz_is_ok_when_the_relay_answers() {
    let config = Config::new("203.0.113.10".parse().unwrap())
        .with_port(0)
        .with_credential("alice", "secretpass");
    let server = Server::new(config).await.unwrap();
    // The relay binds the wildcard address; the probe must reach it on loopback.
    let udp = server.local_addr().unwrap();
    assert!(udp.ip().is_unspecified());
    let target = health::probe_target(udp);
    tokio::spawn(async move { server.run().await });

    let addr = health::spawn("127.0.0.1:0".parse().unwrap(), target)
        .await
        .unwrap();

    // Idle clients and a half-sent request must not hold up a probe.
    let _idle: Vec<_> = idle_connections(addr, 4).await;
    let mut half = TcpStream::connect(addr).await.unwrap();
    half.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();

    // Repeated probes from one IP must keep passing (no rate limit trips).
    for _ in 0..50 {
        let r = get(addr, "/healthz").await;
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"), "{r}");
        assert!(r.ends_with("\r\n\r\nok\n"), "{r}");
    }

    let r = get(addr, "/nope").await;
    assert!(r.starts_with("HTTP/1.1 404 "), "{r}");
}

#[tokio::test]
async fn healthz_is_503_when_the_relay_does_not_answer() {
    // A bound UDP socket that never replies stands in for a hung relay.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = silent.local_addr().unwrap();
    let addr = health::spawn("127.0.0.1:0".parse().unwrap(), target)
        .await
        .unwrap();

    let t = Instant::now();
    let r = get(addr, "/healthz").await;
    assert!(r.starts_with("HTTP/1.1 503 Service Unavailable\r\n"), "{r}");
    // Bounded by the probe timeout, well inside a 1 s Kubernetes probe.
    assert!(t.elapsed() >= health::PROBE_TIMEOUT, "{:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());

    // The silent socket did receive the probe (and its retransmits).
    let mut buf = [0u8; 64];
    let (len, _) = silent.recv_from(&mut buf).await.unwrap();
    assert_eq!(len, 20);
    assert_eq!(&buf[0..2], &[0x00, 0x01]);
}

async fn idle_connections(addr: SocketAddr, n: usize) -> Vec<TcpStream> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(TcpStream::connect(addr).await.unwrap());
    }
    v
}
