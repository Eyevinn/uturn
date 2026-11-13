//! Server configuration

use std::net::{IpAddr, SocketAddr};

use crate::turn::TurnAuth;

/// Server configuration
#[derive(Clone)]
pub struct Config {
    /// UDP port to listen on
    pub port: u16,

    /// External/public IP address
    ///
    /// This is the IP address that will be returned in TURN allocation responses
    /// as the relay address. Must be reachable by peers.
    pub external_ip: IpAddr,

    /// TURN realm for authentication
    pub realm: String,

    /// Static credentials (username, password)
    pub credentials: Vec<(String, String)>,

    /// Shared secrets for TURN REST API (time-limited) credentials.
    ///
    /// A username `<expiry>:<id>` is accepted with password
    /// base64(HMAC-SHA1(secret, username)) until `expiry` (unix seconds).
    /// Every secret is tried, so a new one can be added before the old one is
    /// retired.
    pub auth_secrets: Vec<String>,

    /// Maximum allocations per IP address (0 = unlimited)
    pub max_allocations_per_ip: u32,

    /// Rate limit: max allocation requests per IP per minute (0 = unlimited)
    pub rate_limit_per_minute: u32,

    /// Nonce validity period in seconds
    pub nonce_lifetime_secs: u64,

    /// Secret key for nonce generation (randomly generated at startup)
    pub nonce_secret: [u8; 16],

    /// Opt-in for running without any credentials configured (open relay).
    /// The binary refuses to start when `credentials` is empty unless this is true.
    pub allow_anonymous: bool,

    /// Maximum number of permission entries (peer IPs) per allocation.
    /// Exceeding this returns 508 Insufficient Capacity. (RFC 5766 §9.2)
    pub max_permissions_per_alloc: usize,

    /// Maximum number of bound channels per allocation.
    /// Exceeding this returns 508 Insufficient Capacity. (RFC 5766 §11.2)
    pub max_channels_per_alloc: usize,

    /// Peer transport addresses exempt from the "own external IP on a
    /// non-relay port" rule. For a service that shares the relay's public IP
    /// on another port (e.g. an SFU behind the same NAT). Exact `ip:port`
    /// matches only; loopback, multicast and the other IP-level rules still
    /// apply.
    pub allowed_peers: Vec<SocketAddr>,
}

/// Redacts passwords and secrets, so logging a `Config` cannot leak them.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let users: Vec<&str> = self.credentials.iter().map(|(u, _)| u.as_str()).collect();
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("external_ip", &self.external_ip)
            .field("realm", &self.realm)
            .field("credentials", &users)
            .field(
                "auth_secrets",
                &format_args!("[{} redacted]", self.auth_secrets.len()),
            )
            .field("max_allocations_per_ip", &self.max_allocations_per_ip)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("nonce_lifetime_secs", &self.nonce_lifetime_secs)
            .field("nonce_secret", &"[redacted]")
            .field("allow_anonymous", &self.allow_anonymous)
            .field("max_permissions_per_alloc", &self.max_permissions_per_alloc)
            .field("max_channels_per_alloc", &self.max_channels_per_alloc)
            .field("allowed_peers", &self.allowed_peers)
            .finish()
    }
}

impl Config {
    /// Create a new config with minimal settings
    pub fn new(external_ip: IpAddr) -> Self {
        let nonce_secret: [u8; 16] = rand::random();

        Self {
            port: 3478,
            external_ip,
            realm: "uturn".to_string(),
            credentials: Vec::new(),
            auth_secrets: Vec::new(),
            max_allocations_per_ip: 200,
            rate_limit_per_minute: 30,
            nonce_lifetime_secs: 3600,
            nonce_secret,
            allow_anonymous: false,
            max_permissions_per_alloc: 64,
            max_channels_per_alloc: 128,
            allowed_peers: Vec::new(),
        }
    }

    /// Set the listen port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Exempt a peer address from the own-external-IP rule
    pub fn with_allowed_peer(mut self, addr: SocketAddr) -> Self {
        self.allowed_peers.push(addr);
        self
    }

    /// Set the realm
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Add a credential
    pub fn with_credential(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.credentials.push((username.into(), password.into()));
        self
    }

    /// Add a shared secret for TURN REST API credentials
    pub fn with_auth_secret(mut self, secret: impl Into<String>) -> Self {
        self.auth_secrets.push(secret.into());
        self
    }

    /// Whether requests must authenticate. False only in anonymous mode.
    pub fn auth_enabled(&self) -> bool {
        !self.credentials.is_empty() || !self.auth_secrets.is_empty()
    }

    /// Passwords a request with this username may be signed with.
    ///
    /// A static credential wins outright. Otherwise a TURN REST API username
    /// that has not expired at `now` (unix seconds) yields one password per
    /// shared secret. Empty means the username is unknown or expired.
    pub fn candidate_passwords(&self, username: &str, now: u64) -> Vec<String> {
        if let Some((_, p)) = self.credentials.iter().find(|(u, _)| u == username) {
            return vec![p.clone()];
        }
        match TurnAuth::ephemeral_expiry(username) {
            Some(expiry) if expiry > now => self
                .auth_secrets
                .iter()
                .map(|secret| TurnAuth::ephemeral_password(secret, username))
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_761_000_000;

    fn config() -> Config {
        Config::new("203.0.113.10".parse().unwrap())
    }

    #[test]
    fn auth_enabled_by_users_or_secret() {
        assert!(!config().auth_enabled());
        assert!(config().with_credential("u", "p").auth_enabled());
        // A secret alone must not leave the relay open.
        assert!(config().with_auth_secret("s").auth_enabled());
    }

    #[test]
    fn ephemeral_username_valid_until_expiry() {
        let cfg = config().with_auth_secret("s");
        let user = format!("{}:alice", NOW + 60);
        assert_eq!(
            cfg.candidate_passwords(&user, NOW),
            vec![TurnAuth::ephemeral_password("s", &user)]
        );
        assert!(cfg.candidate_passwords(&user, NOW + 60).is_empty());
        assert!(cfg.candidate_passwords(&user, NOW + 61).is_empty());
    }

    #[test]
    fn ephemeral_username_rejected_without_secret() {
        let cfg = config().with_credential("u", "p");
        assert!(cfg
            .candidate_passwords(&format!("{}:alice", NOW + 60), NOW)
            .is_empty());
    }

    #[test]
    fn every_secret_is_a_candidate() {
        let cfg = config().with_auth_secret("old").with_auth_secret("new");
        let user = format!("{}:alice", NOW + 60);
        assert_eq!(
            cfg.candidate_passwords(&user, NOW),
            vec![
                TurnAuth::ephemeral_password("old", &user),
                TurnAuth::ephemeral_password("new", &user),
            ]
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let out = format!(
            "{:?}",
            config()
                .with_credential("alice", "hunter2-static")
                .with_auth_secret("example-secret-value")
        );
        assert!(out.contains("alice"));
        assert!(!out.contains("hunter2-static"));
        assert!(!out.contains("example-secret-value"));
    }

    #[test]
    fn static_credential_wins_over_ephemeral_format() {
        let user = format!("{}:alice", NOW + 60);
        let cfg = config()
            .with_credential(user.clone(), "static")
            .with_auth_secret("s");
        assert_eq!(cfg.candidate_passwords(&user, NOW), vec!["static"]);
        assert!(cfg.candidate_passwords("unknown", NOW).is_empty());
    }
}
