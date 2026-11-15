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

    /// The local address of the relay's UDP socket (useful with port 0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
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
                // STUN messages are ALWAYS processed by the TURN handler.
                // This includes new Allocate requests from any source.
                debug!("STUN message from {}", src_addr);
                self.turn_handler
                    .handle_stun(msg, src_addr, &self.socket)
                    .await?;
            }

            PacketType::TurnChannelData { channel, data } => {
                debug!("ChannelData (channel={}) from {}", channel, src_addr);
                self.relay_engine
                    .handle_channel_data(channel, &data, src_addr)
                    .await?;
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
