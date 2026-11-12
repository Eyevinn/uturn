//! uTURN - Single-port TURN relay for WebRTC
//!
//! This library provides a TURN server implementation that multiplexes all traffic
//! through a single UDP port using packet-level demultiplexing.
//!
//! # Scope
//!
//! Both internal (client-to-client) and external (client-to-peer) traffic is
//! routed over the single UDP port uTURN listens on, so there is one port to
//! expose rather than a relay port range — useful behind a Kubernetes Service, a
//! restrictive firewall, or a single NAT port forward.
//!
//! It is built for WebRTC/ICE traffic. Because every client shares one relay
//! address, client-to-client relaying cannot be resolved from the destination
//! address alone; it is routed by the ICE ufrag carried in the STUN USERNAME, so
//! both sides must be ICE agents. Plain client-to-external-peer relaying follows
//! RFC 5766 and works with any TURN client. This is not a drop-in general-purpose
//! TURN server: there is no TCP transport, no TURNS (TLS/DTLS), and no
//! per-allocation relay address.

pub mod coarse_time;
pub mod config;
pub mod demux;
pub mod discover;
pub mod lookup;
pub mod relay;
pub mod server;
pub mod turn;

pub use config::Config;
pub use server::Server;
