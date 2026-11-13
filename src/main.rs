//! uTURN - Single-port TURN relay for WebRTC
//!
//! Client-to-client traffic through the shared relay address is routed by ICE
//! ufrag, so both sides must be ICE agents. See ARCHITECTURE.md for scope.

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::signal;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use uturn::{Config, Server};

#[derive(Parser, Debug)]
#[command(name = "uturn")]
#[command(about = "Single-port TURN relay for WebRTC")]
#[command(
    long_about = "Single-port TURN relay for WebRTC. Internal (client-to-client) \
and external (client-to-peer) traffic are routed over this one UDP port, so \
there is a single port to expose rather than a relay port range.\n\n\
Client-to-client relaying through the shared single-port relay address is \
routed by ICE ufrag, so both sides must be ICE agents. Plain client-to-\
external-peer relaying follows RFC 5766 and works with any TURN client. \
This is not a drop-in general-purpose TURN server: no TCP, no TURNS, and \
all clients share one relay address."
)]
#[command(version)]
struct Args {
    /// UDP port to listen on
    #[arg(short, long, env = "UTURN_PORT", default_value = "3478")]
    port: u16,

    /// External/public IP address for relay addresses. If omitted, it is
    /// auto-detected at startup with a STUN Binding request to the
    /// `--stun-server` list (IPv4 only; set it explicitly for IPv6).
    #[arg(short, long, env = "UTURN_EXTERNAL_IP")]
    external_ip: Option<std::net::IpAddr>,

    /// STUN servers (host:port) used to auto-detect the external IP when
    /// `--external-ip` is not set. Queried in parallel; the first answer wins.
    #[arg(
        long,
        env = "UTURN_STUN_SERVERS",
        value_delimiter = ',',
        default_values_t = uturn::discover::DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string())
    )]
    stun_server: Vec<String>,

    /// TURN realm
    #[arg(short, long, env = "UTURN_REALM", default_value = "uturn")]
    realm: String,

    /// Static credentials in format user:password (can be repeated)
    #[arg(
        short,
        long,
        env = "UTURN_USERS",
        value_delimiter = ',',
        hide_env_values = true
    )]
    user: Vec<String>,

    /// Shared secret for time-limited TURN REST API credentials (coturn's
    /// `static-auth-secret`). Username `<expiry-unix-secs>:<id>`, password
    /// base64(HMAC-SHA1(secret, username)). Repeat the flag, or separate with
    /// whitespace in the env var, to accept several secrets while rotating.
    /// Each secret must be at least 16 bytes.
    #[arg(long, env = "UTURN_AUTH_SECRET", hide_env_values = true)]
    static_auth_secret: Vec<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "UTURN_LOG_LEVEL", default_value = "info")]
    log_level: Level,

    /// Maximum allocations per IP address (0 = unlimited)
    #[arg(long, env = "UTURN_MAX_ALLOC_PER_IP", default_value = "200")]
    max_allocations_per_ip: u32,

    /// Rate limit: max allocation requests per IP per minute (0 = unlimited)
    #[arg(long, env = "UTURN_RATE_LIMIT", default_value = "30")]
    rate_limit_per_minute: u32,

    /// Nonce validity period in seconds
    #[arg(long, env = "UTURN_NONCE_LIFETIME", default_value = "3600")]
    nonce_lifetime_secs: u64,

    /// Run as an open relay with no authentication. Without this flag the
    /// server refuses to start when neither `--user` nor
    /// `--static-auth-secret` is configured. Exposing an
    /// anonymous relay on the public internet will be abused.
    #[arg(long, env = "UTURN_ALLOW_ANONYMOUS", default_value = "false")]
    allow_anonymous: bool,

    /// Maximum number of peer IP permissions per allocation
    #[arg(long, env = "UTURN_MAX_PERMISSIONS", default_value = "64")]
    max_permissions_per_alloc: usize,

    /// Maximum number of bound channels per allocation
    #[arg(long, env = "UTURN_MAX_CHANNELS", default_value = "128")]
    max_channels_per_alloc: usize,

    /// Peer addresses (ip:port) on the relay's own external IP that clients
    /// may still relay to, e.g. an SFU sharing the public IP on another port.
    /// By default every port on the external IP except the relay port is
    /// refused. Comma-separated; exact matches only.
    #[arg(long, env = "UTURN_ALLOWED_PEERS", value_delimiter = ',', value_parser = parse_peer_addr)]
    allowed_peer: Vec<std::net::SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    FmtSubscriber::builder()
        .with_max_level(args.log_level)
        .with_target(false)
        .init();

    // Parse credentials
    let credentials: Vec<(String, String)> = args
        .user
        .iter()
        .filter_map(|s| {
            let parts: Vec<&str> = s.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                tracing::warn!("Invalid credential format: {}", s);
                None
            }
        })
        .collect();

    let auth_secrets = parse_auth_secrets(&args.static_auth_secret)?;

    if credentials.is_empty() && auth_secrets.is_empty() && !args.allow_anonymous {
        error!("No credentials configured. Refusing to start an unauthenticated TURN relay.");
        error!(
            "Pass --user USER:PASS (or UTURN_USERS=...) and/or \
             --static-auth-secret SECRET (or UTURN_AUTH_SECRET=...) to configure auth, \
             or --allow-anonymous to intentionally run as an open relay."
        );
        bail!("missing credentials");
    }

    let external_ip = match args.external_ip {
        Some(ip) => ip,
        None => {
            info!("No external IP configured, detecting via STUN");
            uturn::discover::discover_public_ip(&args.stun_server, STUN_DISCOVERY_TIMEOUT)
                .await
                .context(
                    "could not auto-detect the external IP; \
                     set --external-ip (or UTURN_EXTERNAL_IP)",
                )?
        }
    };

    // Generate random nonce secret at startup
    let nonce_secret: [u8; 16] = rand::random();

    let config = Config {
        port: args.port,
        external_ip,
        realm: args.realm,
        credentials,
        auth_secrets,
        max_allocations_per_ip: args.max_allocations_per_ip,
        rate_limit_per_minute: args.rate_limit_per_minute,
        nonce_lifetime_secs: args.nonce_lifetime_secs,
        nonce_secret,
        allow_anonymous: args.allow_anonymous,
        max_permissions_per_alloc: args.max_permissions_per_alloc,
        max_channels_per_alloc: args.max_channels_per_alloc,
        allowed_peers: args.allowed_peer,
    };

    info!(
        "Starting uTURN server v{} on :{} (external: {})",
        env!("CARGO_PKG_VERSION"),
        config.port,
        config.external_ip
    );

    if !config.auth_secrets.is_empty() {
        info!(
            "TURN REST API credentials enabled ({} shared secret(s))",
            config.auth_secrets.len()
        );
    }

    if !config.allowed_peers.is_empty() {
        info!(
            "Allowed peers on the external IP: {:?}",
            config.allowed_peers
        );
        for peer in &config.allowed_peers {
            if peer.ip() != config.external_ip {
                warn!(
                    "Allowed peer {} has no effect: its IP is not the external IP {}. \
                     Only targets on the external IP need listing; loopback and other \
                     forbidden addresses cannot be allowed.",
                    peer, config.external_ip
                );
            }
        }
    }

    if !config.auth_enabled() {
        warn!(
            "ANONYMOUS MODE: server is running as an open relay with no authentication. \
             This will be abused on the public internet (amplification, free transit, \
             SSRF pivots). Use only on trusted networks."
        );
    }

    let server = Server::new(config).await?;

    // Run server with graceful shutdown on SIGTERM/SIGINT
    tokio::select! {
        result = server.run() => {
            result
        }
        _ = shutdown_signal() => {
            info!("Received shutdown signal, exiting gracefully");
            Ok(())
        }
    }
}

/// How long to wait for any STUN server to answer during IP auto-detection.
const STUN_DISCOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Minimum length of a TURN REST API shared secret, in bytes.
const MIN_AUTH_SECRET_LEN: usize = 16;

/// Parse one `--allowed-peer` entry, ignoring surrounding whitespace so
/// `UTURN_ALLOWED_PEERS="a:1, b:2"` works.
fn parse_peer_addr(s: &str) -> std::result::Result<std::net::SocketAddr, String> {
    s.trim()
        .parse()
        .map_err(|e| format!("invalid ip:port {:?}: {}", s.trim(), e))
}

/// Split `--static-auth-secret` values into secrets.
///
/// Whitespace separates secrets (so one env var can carry several during
/// rotation, and a trailing newline from a mounted secret file is dropped).
/// Commas are deliberately *not* separators: a generated secret may contain
/// one, and splitting it would silently turn it into weaker keys. A short
/// secret is refused for the same reason - it is brute-forceable offline from
/// a single observed credential.
fn parse_auth_secrets(values: &[String]) -> Result<Vec<String>> {
    let secrets: Vec<String> = values
        .iter()
        .flat_map(|v| v.split_whitespace())
        .map(str::to_string)
        .collect();
    if let Some(short) = secrets.iter().find(|s| s.len() < MIN_AUTH_SECRET_LEN) {
        bail!(
            "--static-auth-secret: a {}-byte secret is too short (minimum {} bytes)",
            short.len(),
            MIN_AUTH_SECRET_LEN
        );
    }
    Ok(secrets)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    const A: &str = "aaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbb";

    #[test]
    fn auth_secrets_split_on_whitespace_only() {
        assert_eq!(parse_auth_secrets(&strings(&[A])).unwrap(), strings(&[A]));
        assert_eq!(
            parse_auth_secrets(&strings(&[&format!("{A} {B}\n")])).unwrap(),
            strings(&[A, B])
        );
        assert_eq!(
            parse_auth_secrets(&strings(&[A, B])).unwrap(),
            strings(&[A, B])
        );
        // A comma is part of the secret, not a separator.
        let with_comma = format!("{A},{B}");
        assert_eq!(
            parse_auth_secrets(&strings(&[&with_comma])).unwrap(),
            strings(&[&with_comma])
        );
    }

    #[test]
    fn auth_secrets_empty_values_yield_none() {
        assert!(parse_auth_secrets(&strings(&[])).unwrap().is_empty());
        assert!(parse_auth_secrets(&strings(&["", " \n"]))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn short_auth_secret_is_refused() {
        assert!(parse_auth_secrets(&strings(&["short"])).is_err());
        // "new, old"-style input must fail loudly, not run with fragments.
        assert!(parse_auth_secrets(&strings(&[&format!("{A}, x")])).is_err());
    }

    #[test]
    fn secret_alone_satisfies_startup_gate() {
        let args = Args::try_parse_from([
            "uturn",
            "--external-ip",
            "203.0.113.10",
            "--static-auth-secret",
            A,
        ])
        .unwrap();
        assert!(args.user.is_empty());
        assert!(!args.allow_anonymous);
        assert_eq!(
            parse_auth_secrets(&args.static_auth_secret).unwrap(),
            strings(&[A])
        );
    }

    #[test]
    fn allowed_peers_parse_comma_separated_with_spaces() {
        // Same delimiter and parser as UTURN_ALLOWED_PEERS.
        let args = Args::try_parse_from([
            "uturn",
            "--user",
            "u:p",
            "--allowed-peer",
            "203.0.113.10:30029, 203.0.113.10:30031",
        ])
        .unwrap();
        let sa = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        assert_eq!(
            args.allowed_peer,
            vec![sa("203.0.113.10:30029"), sa("203.0.113.10:30031")]
        );
        assert!(Args::try_parse_from(["uturn", "--allowed-peer", "bogus"]).is_err());
        assert!(Args::try_parse_from(["uturn", "--allowed-peer", "203.0.113.10"]).is_err());
    }

    #[test]
    fn external_ip_is_optional_with_default_stun_servers() {
        let args = Args::try_parse_from(["uturn", "--user", "u:p"]).unwrap();
        assert!(args.external_ip.is_none());
        assert_eq!(
            args.stun_server,
            strings(uturn::discover::DEFAULT_STUN_SERVERS)
        );
    }
}
