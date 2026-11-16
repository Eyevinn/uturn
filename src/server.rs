//! Main server implementation
//!
//! Performance-optimized: processes packets inline without task-per-packet overhead.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

use crate::coarse_time;
use crate::config::Config;
use crate::demux::{Demuxer, PacketType};
use crate::lookup::{AllocationId, AllocationTable, RateLimiter};
use crate::relay::RelayEngine;
use crate::turn::TurnHandler;

/// Interval for cleaning up expired allocations
const CLEANUP_INTERVAL_SECS: u64 = 2;

/// Inactivity timeout - remove allocation if no traffic FROM client for this long
const INACTIVITY_TIMEOUT_SECS: u64 = 45;

/// Receive buffer size.
///
/// Sized for the largest possible UDP payload (65 507 bytes over IPv4). A
/// datagram larger than the buffer is silently truncated by recv_from, which
/// would corrupt a relayed payload or make a STUN message unparseable without
/// any error. Allocated once for the lifetime of the receive loop, so the
/// generous size costs nothing per packet.
const RECV_BUFFER_SIZE: usize = 65_535;

/// uTURN server
pub struct Server {
    config: Arc<Config>,
    socket: Arc<UdpSocket>,
    allocations: Arc<AllocationTable>,
    turn_handler: Arc<TurnHandler>,
    relay_engine: Arc<RelayEngine>,
    rate_limiter: Arc<RateLimiter>,
}

impl Server {
    /// Create a new server with the given configuration
    pub async fn new(config: Config) -> Result<Self> {
        // Initialize coarse time system
        coarse_time::init();

        // Bind to wildcard address matching the external IP's address family
        let bind_addr = match config.external_ip {
            std::net::IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], config.port)),
            std::net::IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], config.port)),
        };
        // Raise kernel socket buffers before converting to tokio::UdpSocket.
        // Best-effort: failure to set is non-fatal (some environments cap SO_*).
        let socket = {
            let domain = match config.external_ip {
                std::net::IpAddr::V4(_) => socket2::Domain::IPV4,
                std::net::IpAddr::V6(_) => socket2::Domain::IPV6,
            };
            let sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
            sock.set_nonblocking(true)?;
            sock.bind(&bind_addr.into())?;
            UdpSocket::from_std(sock.into())?
        };

        info!("Bound to {}", bind_addr);

        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_per_minute,
            config.max_allocations_per_ip,
        ));

        let config = Arc::new(config);
        let socket = Arc::new(socket);
        let allocations = Arc::new(AllocationTable::new());

        let turn_handler = Arc::new(TurnHandler::new(
            config.clone(),
            allocations.clone(),
            rate_limiter.clone(),
        ));

        let relay_engine = Arc::new(RelayEngine::new(
            config.clone(),
            socket.clone(),
            allocations.clone(),
        ));

        Ok(Self {
            config,
            socket,
            allocations,
            turn_handler,
            relay_engine,
            rate_limiter,
        })
    }

    /// Run the server main loop
    pub async fn run(&self) -> Result<()> {
        info!(
            "uTURN server running - relay address: {}:{}",
            self.config.external_ip, self.config.port
        );

        // Spawn coarse time updater (updates timestamp every 10ms)
        coarse_time::spawn_updater().await;

        // Spawn cleanup task for expired, inactive, and orphaned allocations
        let cleanup_allocations = self.allocations.clone();
        let cleanup_rate_limiter = self.rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            // If a cleanup ever takes longer than the interval, don't spin
            // through queued catch-up ticks; resume on the next aligned tick.
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;

                // Cleanup expired allocations and update quota
                let expired_ips = cleanup_allocations.cleanup_expired();
                if !expired_ips.is_empty() {
                    info!("Cleaned up {} expired allocation(s)", expired_ips.len());
                    for ip in expired_ips {
                        cleanup_rate_limiter.record_deallocation(ip);
                    }
                }

                // Cleanup inactive allocations and update quota
                let inactive_ips = cleanup_allocations.cleanup_inactive(INACTIVITY_TIMEOUT_SECS);
                if !inactive_ips.is_empty() {
                    info!("Cleaned up {} inactive allocation(s)", inactive_ips.len());
                    for ip in inactive_ips {
                        cleanup_rate_limiter.record_deallocation(ip);
                    }
                }

                // Cleanup orphaned senders and update quota
                let orphaned_ips =
                    cleanup_allocations.cleanup_orphaned_senders(INACTIVITY_TIMEOUT_SECS);
                if !orphaned_ips.is_empty() {
                    info!(
                        "Cleaned up {} orphaned sender allocation(s)",
                        orphaned_ips.len()
                    );
                    for ip in orphaned_ips {
                        cleanup_rate_limiter.record_deallocation(ip);
                    }
                }

                // Reap channel bindings past their 10-minute lifetime, so the
                // channel number and the peer are free to be bound again.
                cleanup_allocations.cleanup_channel_bindings();

                // Reap permissions past their 5-minute lifetime (RFC 5766 §9).
                cleanup_allocations.cleanup_permissions();

                // Drop STUN requests to external peers that were never answered.
                cleanup_allocations.cleanup_peer_txns();

                // Cleanup stale rate limiter entries
                cleanup_rate_limiter.cleanup();
            }
        });

        // Main receive loop - process packets inline for maximum performance
        // No task spawning, no buffer pool mutex, no Arc clones per packet
        let mut recv_buf = vec![0u8; RECV_BUFFER_SIZE];

        loop {
            let (len, src_addr) = match self.socket.recv_from(&mut recv_buf).await {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to receive packet: {}", e);
                    continue;
                }
            };

            trace!("Received {} bytes from {}", len, src_addr);

            // Process packet inline - no spawn overhead
            if let Err(e) = self.handle_packet(&recv_buf[..len], src_addr).await {
                warn!("Error handling packet from {}: {}", src_addr, e);
            }
        }
    }

    /// Handle a single incoming packet
    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        // Check if this is from a client (has an allocation at this address)
        // Important: is_client checks by_client only, NOT by_peer_tuple
        // This prevents learned peer tuples from being treated as clients
        let is_client = self.allocations.is_client(src_addr);
        if is_client {
            trace!("Fast path: found allocation for client {}", src_addr);
        }

        // Classify packet FIRST - this is important!
        // We must classify before checking peer permissions, because a new client
        // from the same IP (different port) could be sending a STUN Allocate request.
        let packet_type = Demuxer::classify(data);

        match packet_type {
            PacketType::Stun(msg) => {
                // STUN from an external peer (an ICE check or a response to a
                // client's check) is relayed to the client it is for.
                if !is_client && self.relay_engine.relay_peer_stun(&msg, src_addr).await? {
                    return Ok(());
                }
                // Everything else goes to the TURN handler, including new
                // Allocate requests from any source.
                debug!("STUN message from {}", src_addr);
                self.turn_handler
                    .handle_stun(msg, src_addr, &self.socket)
                    .await?;
            }

            PacketType::TurnChannelData {
                channel,
                data: payload,
            } if is_client => {
                debug!("ChannelData (channel={}) from {}", channel, src_addr);
                self.relay_engine
                    .handle_channel_data(channel, &payload, src_addr)
                    .await?;
            }

            // Only clients send ChannelData. From anyone else, a first byte
            // in 0x40-0x7F is just the start of the peer's payload: relay it
            // whole like any other peer data.
            PacketType::TurnChannelData { .. } => {
                self.relay_engine.handle_peer_data(data, src_addr).await?;
            }

            PacketType::Rtp { ssrc, data } => {
                if is_client {
                    // Client sending RTP - relay to other clients (single-port TURN)
                    debug!("RTP from client {} - relaying to other clients", src_addr);
                    self.relay_client_data(&data, src_addr).await?;
                } else {
                    // Check if this is from a permitted peer (prefer tuple, fallback to IP)
                    let (candidates, _) = self.allocations.lookup_by_peer_addr(src_addr);
                    if !candidates.is_empty() {
                        debug!("RTP from peer {} (SSRC={:08x}) - relaying", src_addr, ssrc);
                        self.relay_engine.handle_rtp(ssrc, &data, src_addr).await?;
                    } else {
                        trace!("RTP (SSRC={:08x}) from unknown {}", ssrc, src_addr);
                    }
                }
            }

            PacketType::Rtcp(data) => {
                if is_client {
                    debug!("RTCP from client {} - relaying to other clients", src_addr);
                    self.relay_client_data(&data, src_addr).await?;
                } else {
                    let (candidates, _) = self.allocations.lookup_by_peer_addr(src_addr);
                    if !candidates.is_empty() {
                        debug!("RTCP from peer {} - relaying", src_addr);
                        self.relay_engine.handle_rtcp(&data, src_addr).await?;
                    } else {
                        trace!("RTCP from unknown {}", src_addr);
                    }
                }
            }

            PacketType::Dtls(data) => {
                if is_client {
                    // Client sending DTLS (handshake) - relay to other clients
                    debug!("DTLS from client {} - relaying to other clients", src_addr);
                    self.relay_client_data(&data, src_addr).await?;
                } else {
                    let (candidates, _) = self.allocations.lookup_by_peer_addr(src_addr);
                    if !candidates.is_empty() {
                        debug!("DTLS from peer {} - relaying via Data Indication", src_addr);
                        // Use handle_dtls which always uses Data Indication (not ChannelData)
                        // DTLS handshake packets must not be sent via ChannelData
                        self.relay_engine.handle_dtls(&data, src_addr).await?;
                    } else {
                        trace!("DTLS from unknown {}", src_addr);
                    }
                }
            }

            PacketType::Unknown => {
                if is_client {
                    debug!(
                        "Unknown data from client {} - relaying to other clients",
                        src_addr
                    );
                    self.relay_client_data(data, src_addr).await?;
                } else {
                    let (candidates, _) = self.allocations.lookup_by_peer_addr(src_addr);
                    if !candidates.is_empty() {
                        debug!(
                            "Unknown data from peer {} - relaying via Data Indication",
                            src_addr
                        );
                        self.relay_engine.handle_peer_data(data, src_addr).await?;
                    } else {
                        trace!(
                            "Unknown packet type from {} ({} bytes)",
                            src_addr,
                            data.len()
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Relay data from one client to other clients (single-port TURN)
    ///
    /// In single-port TURN, all clients share the same relay address. When client A
    /// sends data to the server, we relay it to other clients that have permission
    /// for the relay IP. Uses ICE ufrag matching to route to the correct peer,
    /// falling back to broadcast only when pairing is not yet established.
    async fn relay_client_data(&self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

        // Snapshot the sender's id, relay-IP permission and ICE ufrags, then
        // release the guard: everything below awaits socket sends, and an
        // allocation guard must never be held across I/O (cleanup takes shard
        // write locks and would stall or deadlock behind a parked guard).
        let (sender_id, sender_local, sender_remote) =
            match self.allocations.get_by_client(src_addr) {
                Some(alloc) => {
                    // Check that SENDER has permission for the relay IP (RFC 5766 requirement)
                    if !alloc.is_permitted(self.config.external_ip) {
                        trace!(
                            "Client {} tried to relay data without permission for relay IP",
                            src_addr
                        );
                        return Ok(());
                    }
                    (
                        alloc.id,
                        alloc.get_ice_ufrag(),
                        alloc.get_ice_remote_ufrag(),
                    )
                }
                None => {
                    trace!("relay_client_data from unknown client: {}", src_addr);
                    return Ok(());
                }
            };

        // Try ufrag-based routing first to avoid bandwidth multiplication
        let peers = match (&sender_local, &sender_remote) {
            (Some(local), Some(remote)) => self.allocations.find_ice_peers(local, remote),
            _ => Vec::new(),
        };

        if peers.is_empty() {
            // No ICE pairing yet - drop (no broadcast fallback)
            trace!(
                "Data from {} dropped: no ICE ufrag match (local={:?}, remote={:?})",
                src_addr,
                sender_local,
                sender_remote,
            );
            self.touch_relay(sender_id, false);
            return Ok(());
        }

        // Snapshot the ICE peers' client addresses, then send to the snapshot.
        let targets: Vec<(AllocationId, SocketAddr)> = peers
            .iter()
            .filter_map(|&peer_id| {
                let target = self.allocations.get(peer_id)?;
                if target.client_addr == src_addr || !target.is_permitted(self.config.external_ip) {
                    None
                } else {
                    Some((peer_id, target.client_addr))
                }
            })
            .collect();

        let indication = self.build_data_indication(relay_addr, data);
        let mut relayed = false;
        for (peer_id, target_addr) in targets {
            debug!(
                "Relaying {} bytes from client {} to ICE peer {} (via relay {})",
                data.len(),
                src_addr,
                target_addr,
                relay_addr
            );
            self.socket.send_to(&indication, target_addr).await?;
            if let Some(target) = self.allocations.get(peer_id) {
                target.touch();
            }
            relayed = true;
        }

        self.touch_relay(sender_id, relayed);
        Ok(())
    }

    /// Re-acquire briefly to record the outcome of a relay attempt.
    fn touch_relay(&self, id: AllocationId, relayed: bool) {
        if let Some(a) = self.allocations.get(id) {
            if relayed {
                a.touch_relay_success();
            } else {
                a.touch_relay_attempt();
            }
        }
    }

    /// Build a TURN Data Indication message
    #[inline]
    fn build_data_indication(&self, peer_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(48 + data.len());

        // Data Indication: 0x0017
        packet.extend_from_slice(&[0x00, 0x17]);

        // Length placeholder
        packet.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        packet.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);

        // Transaction ID (random for indication per RFC 5389)
        let txn_id: [u8; 12] = rand::random();
        packet.extend_from_slice(&txn_id);

        // XOR-PEER-ADDRESS attribute (0x0012)
        self.append_xor_peer_address(&mut packet, peer_addr, &txn_id);

        // DATA attribute (0x0013)
        packet.extend_from_slice(&[0x00, 0x13]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        // Pad DATA attribute to 4-byte boundary (more efficient than byte-by-byte)
        let padding = (4 - ((packet.len() - 20) % 4)) % 4;
        packet.resize(packet.len() + padding, 0);

        // Update length field
        let msg_len = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&msg_len.to_be_bytes());

        packet
    }

    /// Append XOR-PEER-ADDRESS attribute to buffer
    #[inline]
    fn append_xor_peer_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        buf.extend_from_slice(&[0x00, 0x12]); // Type

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]); // Length
                buf.push(0x00); // Reserved
                buf.push(0x01); // IPv4

                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                let addr_bytes = v4.ip().octets();
                let magic = [0x21, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
            }
            SocketAddr::V6(v6) => {
                buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
                buf.push(0x00); // Reserved
                buf.push(0x02); // IPv6 family

                let xor_port = v6.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie (4 bytes) + transaction ID (12 bytes)
                let addr_bytes = v6.ip().octets();
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                for i in 0..4 {
                    buf.push(addr_bytes[i] ^ magic[i]);
                }
                for i in 0..12 {
                    buf.push(addr_bytes[4 + i] ^ transaction_id[i]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Relaying STUN between a TURN client and an external peer, i.e. a peer
    //! that is not itself a client of this server (an SFU, or a browser
    //! without TURN). ICE needs both directions: the peer's Binding requests
    //! must reach the client, and the peer's responses to the client's
    //! requests must come back.

    use super::*;
    use crate::demux::{StunClass, StunInfo, StunMethod};
    use std::net::IpAddr;

    const PEER: &str = "198.51.100.7:5000";
    const CLIENT_UFRAG: &str = "cliU";
    const PEER_UFRAG: &str = "peerU";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// A STUN message: header, then attributes, each padded to 4 bytes.
    fn stun(msg_type: u16, txn: [u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            body.resize(body.len() + (4 - v.len() % 4) % 4, 0);
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&msg_type.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        msg.extend_from_slice(&txn);
        msg.extend_from_slice(&body);
        msg
    }

    fn binding_request(txn: [u8; 12], username: &str) -> Vec<u8> {
        stun(0x0001, txn, &[(0x0006, username.as_bytes().to_vec())])
    }

    fn binding_success(txn: [u8; 12]) -> Vec<u8> {
        stun(0x0101, txn, &[])
    }

    fn xor_v4(addr: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(v4) = addr else {
            panic!("IPv4 only")
        };
        let mut v = vec![0x00, 0x01];
        v.extend_from_slice(&(v4.port() ^ 0x2112).to_be_bytes());
        let magic = [0x21, 0x12, 0xa4, 0x42];
        v.extend(v4.ip().octets().iter().zip(magic).map(|(a, m)| a ^ m));
        v
    }

    /// Send indication carrying `data` to `peer`.
    fn send_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
        stun(
            0x0016,
            rand::random(),
            &[(0x0012, xor_v4(peer)), (0x0013, data.to_vec())],
        )
    }

    /// A server with one allocation for a real client socket, permitted to
    /// talk to `PEER`. Allocation and permission are installed directly; the
    /// auth path is covered elsewhere.
    async fn setup() -> (Server, tokio::net::UdpSocket, SocketAddr) {
        let config = Config::new(IpAddr::from([127, 0, 0, 1]))
            .with_port(0)
            .with_credential("u", "p");
        let server = Server::new(config).await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let id = server.allocations.create(client_addr, "u".into(), 600);
        server.allocations.add_permission(id, sa(PEER).ip());
        (server, client, client_addr)
    }

    /// The next datagram the client receives, or None within 200 ms.
    async fn recv(client: &tokio::net::UdpSocket) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(200), client.recv(&mut buf)).await {
            Ok(Ok(n)) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    /// Assert `packet` is a Data indication from `peer` carrying `data`.
    fn assert_data_indication(packet: &[u8], peer: SocketAddr, data: &[u8]) {
        let msg = StunInfo::parse(packet).expect("STUN");
        assert_eq!(msg.class, StunClass::Indication);
        assert_eq!(msg.method, StunMethod::Data);
        assert_eq!(msg.xor_peer_addresses, vec![peer]);
        assert_eq!(msg.data.as_deref(), Some(data));
    }

    /// The client sends its ICE check to the peer, so uTURN learns the
    /// client's ufrag and the check's transaction id.
    async fn client_checks_peer(server: &Server, client_addr: SocketAddr, txn: [u8; 12]) {
        let check = binding_request(txn, &format!("{PEER_UFRAG}:{CLIENT_UFRAG}"));
        server
            .handle_packet(&send_indication(sa(PEER), &check), client_addr)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn peer_response_to_client_check_reaches_the_client() {
        let (server, client, client_addr) = setup().await;
        let txn: [u8; 12] = rand::random();
        client_checks_peer(&server, client_addr, txn).await;

        let response = binding_success(txn);
        server.handle_packet(&response, sa(PEER)).await.unwrap();

        let got = recv(&client).await.expect("response relayed to client");
        assert_data_indication(&got, sa(PEER), &response);
    }

    #[tokio::test]
    async fn peer_check_addressed_to_client_reaches_the_client() {
        let (server, client, client_addr) = setup().await;
        client_checks_peer(&server, client_addr, rand::random()).await;

        let check = binding_request(rand::random(), &format!("{CLIENT_UFRAG}:{PEER_UFRAG}"));
        server.handle_packet(&check, sa(PEER)).await.unwrap();

        let got = recv(&client).await.expect("check relayed to client");
        assert_data_indication(&got, sa(PEER), &check);
    }

    #[tokio::test]
    async fn checks_over_a_bound_channel_round_trip_as_channel_data() {
        let (server, client, client_addr) = setup().await;
        const CHANNEL: u16 = 0x4000;
        server
            .allocations
            .get_by_client(client_addr)
            .unwrap()
            .bind_channel(CHANNEL, sa(PEER));

        let txn: [u8; 12] = rand::random();
        let check = binding_request(txn, &format!("{PEER_UFRAG}:{CLIENT_UFRAG}"));
        let mut framed = CHANNEL.to_be_bytes().to_vec();
        framed.extend_from_slice(&(check.len() as u16).to_be_bytes());
        framed.extend_from_slice(&check);
        server.handle_packet(&framed, client_addr).await.unwrap();

        let response = binding_success(txn);
        server.handle_packet(&response, sa(PEER)).await.unwrap();

        let got = recv(&client).await.expect("response relayed to client");
        assert_eq!(&got[..2], &CHANNEL.to_be_bytes());
        assert_eq!(&got[4..4 + response.len()], &response[..]);
    }

    /// A second client on the same server, also permitted for `PEER`.
    async fn second_client(server: &Server) -> (tokio::net::UdpSocket, SocketAddr) {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = client.local_addr().unwrap();
        let id = server.allocations.create(addr, "u".into(), 600);
        server.allocations.add_permission(id, sa(PEER).ip());
        (client, addr)
    }

    #[tokio::test]
    async fn peer_response_reaches_only_the_client_that_asked() {
        // Two clients talk to the same peer (e.g. one SFU); a response must
        // not cross over to the other one.
        let (server, client, client_addr) = setup().await;
        let (other, _) = second_client(&server).await;
        let txn: [u8; 12] = rand::random();
        client_checks_peer(&server, client_addr, txn).await;

        server
            .handle_packet(&binding_success(txn), sa(PEER))
            .await
            .unwrap();
        assert!(recv(&client).await.is_some());
        assert!(recv(&other).await.is_none());
    }

    #[tokio::test]
    async fn peer_check_reaches_only_its_ice_session() {
        let (server, client, client_addr) = setup().await;
        let (other, other_addr) = second_client(&server).await;
        client_checks_peer(&server, client_addr, rand::random()).await;
        let other_check = binding_request(rand::random(), "peerU:otherU");
        server
            .handle_packet(&send_indication(sa(PEER), &other_check), other_addr)
            .await
            .unwrap();

        let check = binding_request(rand::random(), &format!("{CLIENT_UFRAG}:{PEER_UFRAG}"));
        server.handle_packet(&check, sa(PEER)).await.unwrap();
        assert!(recv(&client).await.is_some());
        assert!(recv(&other).await.is_none());
    }

    #[tokio::test]
    async fn peer_check_before_the_clients_own_check_is_not_relayed() {
        // Nothing yet ties the ufrag to an allocation; the peer retransmits.
        let (server, client, _) = setup().await;
        let check = binding_request(rand::random(), &format!("{CLIENT_UFRAG}:{PEER_UFRAG}"));
        server.handle_packet(&check, sa(PEER)).await.unwrap();
        assert!(recv(&client).await.is_none());
    }

    #[tokio::test]
    async fn peer_check_uses_the_bound_channel() {
        let (server, client, client_addr) = setup().await;
        const CHANNEL: u16 = 0x4001;
        server
            .allocations
            .get_by_client(client_addr)
            .unwrap()
            .bind_channel(CHANNEL, sa(PEER));
        client_checks_peer(&server, client_addr, rand::random()).await;

        let check = binding_request(rand::random(), &format!("{CLIENT_UFRAG}:{PEER_UFRAG}"));
        server.handle_packet(&check, sa(PEER)).await.unwrap();

        let got = recv(&client).await.expect("check relayed to client");
        assert_eq!(&got[..2], &CHANNEL.to_be_bytes());
        assert_eq!(&got[4..4 + check.len()], &check[..]);
    }

    #[tokio::test]
    async fn peer_response_with_unknown_transaction_is_not_relayed() {
        let (server, client, client_addr) = setup().await;
        client_checks_peer(&server, client_addr, rand::random()).await;

        server
            .handle_packet(&binding_success(rand::random()), sa(PEER))
            .await
            .unwrap();
        assert!(recv(&client).await.is_none());
    }

    #[tokio::test]
    async fn response_from_another_address_is_not_relayed() {
        let (server, client, client_addr) = setup().await;
        let txn: [u8; 12] = rand::random();
        client_checks_peer(&server, client_addr, txn).await;

        // Same IP, other port: the client asked 198.51.100.7:5000, not :5001.
        server
            .handle_packet(&binding_success(txn), sa("198.51.100.7:5001"))
            .await
            .unwrap();
        assert!(recv(&client).await.is_none());
    }

    #[tokio::test]
    async fn check_from_unpermitted_peer_is_not_relayed() {
        let (server, client, client_addr) = setup().await;
        client_checks_peer(&server, client_addr, rand::random()).await;

        let check = binding_request(rand::random(), &format!("{CLIENT_UFRAG}:{PEER_UFRAG}"));
        server
            .handle_packet(&check, sa("198.51.100.99:5000"))
            .await
            .unwrap();
        assert!(recv(&client).await.is_none());
    }

    #[tokio::test]
    async fn check_naming_another_remote_ufrag_is_not_relayed() {
        let (server, client, client_addr) = setup().await;
        client_checks_peer(&server, client_addr, rand::random()).await;

        let check = binding_request(rand::random(), &format!("{CLIENT_UFRAG}:other"));
        server.handle_packet(&check, sa(PEER)).await.unwrap();
        assert!(recv(&client).await.is_none());
    }

    #[tokio::test]
    async fn plain_binding_request_from_peer_is_still_answered_not_relayed() {
        // A Binding request without USERNAME is STUN, not ICE: srflx discovery
        // against this server. It keeps getting a Binding response.
        let (server, client, client_addr) = setup().await;
        client_checks_peer(&server, client_addr, rand::random()).await;

        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe_addr = probe.local_addr().unwrap();
        let id = server.allocations.get_by_client(client_addr).unwrap().id;
        server.allocations.add_permission(id, probe_addr.ip());

        let txn: [u8; 12] = rand::random();
        server
            .handle_packet(&stun(0x0001, txn, &[]), probe_addr)
            .await
            .unwrap();

        assert!(recv(&client).await.is_none());
        let answer = StunInfo::parse(&recv(&probe).await.expect("answered")).unwrap();
        assert_eq!(answer.class, StunClass::SuccessResponse);
        assert_eq!(answer.transaction_id, txn);
    }
}

#[cfg(test)]
mod peer_data_tests {
    use super::*;
    use crate::demux::StunInfo;
    use std::net::IpAddr;

    #[tokio::test]
    async fn peer_data_starting_like_channel_data_reaches_the_client() {
        let config = Config::new(IpAddr::from([127, 0, 0, 1]))
            .with_port(0)
            .with_credential("u", "p");
        let server = Server::new(config).await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let peer: SocketAddr = "198.51.100.7:5000".parse().unwrap();
        let id = server.allocations.create(client_addr, "u".into(), 600);
        server.allocations.add_permission(id, peer.ip());

        // turnutils_uclient payload: little-endian msgnum first, so message
        // 64 starts 0x40 0x00 0x00 0x00 - a valid empty ChannelData header.
        let mut payload = vec![0x40, 0, 0, 0, 0, 0, 0, 0];
        payload.resize(100, 7);
        server.handle_packet(&payload, peer).await.unwrap();

        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_millis(200), client.recv(&mut buf))
            .await
            .expect("peer data relayed to client")
            .unwrap();
        let msg = StunInfo::parse(&buf[..n]).unwrap();
        assert_eq!(msg.data.as_deref(), Some(&payload[..]));

        // From an address with no permission it is dropped, as before.
        server
            .handle_packet(&payload, "198.51.100.99:5000".parse().unwrap())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), client.recv(&mut buf))
                .await
                .is_err()
        );
    }
}
