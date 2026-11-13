//! TURN message handler

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::{debug, info, trace, warn};

use crate::config::Config;
use crate::demux::{StunClass, StunInfo, StunMethod};
use crate::lookup::{AllocationId, AllocationTable, RateLimitError, RateLimiter};

use super::auth::TurnAuth;
use super::message::TurnErrorCode;

/// TURN protocol handler
pub struct TurnHandler {
    config: Arc<Config>,
    allocations: Arc<AllocationTable>,
    rate_limiter: Arc<RateLimiter>,
}

/// Peer addresses we refuse to relay to, regardless of permission.
///
/// Loopback, multicast, broadcast and unspecified addresses either enable
/// reflection to services on the relay host or fan out amplification to the
/// local network. IPv4 link-local (169.254.0.0/16) covers AWS/GCE instance
/// metadata services.
pub(crate) fn is_forbidden_peer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) reaches the IPv4 host on
            // a dual-stack socket, so it must be judged by the IPv4 rules:
            // ::ffff:127.0.0.1 is loopback even though Ipv6Addr::is_loopback
            // says otherwise.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_forbidden_peer_ip(IpAddr::V4(v4));
            }
            // fe80::/10 unicast link-local (no stable std predicate yet).
            let unicast_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() || unicast_link_local
        }
    }
}

/// Peer *transport addresses* we refuse to relay to.
///
/// Extends [`is_forbidden_peer_ip`] with the relay host's own external IP on
/// any port other than the relay port: `external_ip:relay_port` is the
/// legitimate single-port internal-routing target, everything else on that IP
/// would let a client reach other UDP services on the relay host. Applied to
/// Send indications, ChannelBind and the ChannelData egress alike so the two
/// data paths cannot be played against each other.
///
/// `config.allowed_peers` exempts exact `ip:port` targets from the external-IP
/// rule (a service sharing the relay's public IP), never from the IP-level
/// rules.
pub(crate) fn is_forbidden_peer_addr(config: &Config, addr: SocketAddr) -> bool {
    is_forbidden_peer_ip(addr.ip())
        || (addr.ip() == config.external_ip
            && addr.port() != config.port
            && !config.allowed_peers.contains(&addr))
}

/// Where a Send indication's payload should go once the sender's own
/// permission has been verified.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendTarget {
    /// Another TURN client of this server, plus the channel it has bound back
    /// to the sender (if any). The payload is wrapped rather than forwarded
    /// raw: a raw datagram from our relay address would be discarded by the
    /// target's TURN stack.
    Local {
        id: AllocationId,
        reverse_channel: Option<u16>,
    },
    /// Not one of our clients - forward the raw payload.
    External,
    /// Drop the payload.
    Drop,
}

impl TurnHandler {
    /// Create a new handler
    pub fn new(
        config: Arc<Config>,
        allocations: Arc<AllocationTable>,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        Self {
            config,
            allocations,
            rate_limiter,
        }
    }

    /// Decide where a Send indication's payload should go.
    ///
    /// The caller has already checked that the *sender* holds a permission for
    /// `peer_addr`. That only authorises the sender's half: when the peer turns
    /// out to be another client of this server, the payload is delivered into
    /// that client's allocation as a Data Indication / ChannelData, so its
    /// permissions apply as well (RFC 5766 §10.3). Without that second check
    /// any client could hand any other client arbitrary application data - and
    /// keep its allocation alive indefinitely with the accompanying touch - by
    /// creating a permission for the victim's IP, which nothing restricts.
    ///
    /// The relay-IP convention matches every other client-to-client path here:
    /// a WebRTC client permits the relay address, which is where peer traffic
    /// appears to come from on this single-port server.
    fn classify_send_target(&self, src_addr: SocketAddr, peer_addr: SocketAddr) -> SendTarget {
        // Never bounce a well-formed indication back at the sender.
        if peer_addr == src_addr {
            return SendTarget::Drop;
        }
        match self.allocations.get_by_client(peer_addr) {
            Some(target) => {
                if target.is_permitted(self.config.external_ip) {
                    SendTarget::Local {
                        id: target.id,
                        reverse_channel: target.channel_for_peer(src_addr),
                    }
                } else {
                    // A client of ours with no permission for the relay IP.
                    // Drop rather than falling back to the raw send, which
                    // would put the same bytes on the same socket unwrapped.
                    SendTarget::Drop
                }
            }
            None => SendTarget::External,
        }
    }

    /// Verify RFC 5389 long-term credentials on a request.
    ///
    /// Returns the authenticated username and its key on success, or the error
    /// response to send (401 with fresh REALM/NONCE, 438 Stale Nonce, or 400).
    /// Callers must have checked that authentication is enabled at all.
    fn verify_long_term_credentials(&self, msg: &StunInfo) -> Result<(String, [u8; 16]), Vec<u8>> {
        // MESSAGE-INTEGRITY must be present: first contact gets a 401 challenge.
        if msg.message_integrity.is_none() {
            debug!("Request missing MESSAGE-INTEGRITY, sending 401 challenge");
            return Err(self.build_unauthorized_response(msg));
        }

        let username = match &msg.username {
            Some(u) => u,
            None => {
                warn!("Request has MESSAGE-INTEGRITY but no USERNAME");
                return Err(self.build_error_response(msg, TurnErrorCode::BadRequest));
            }
        };

        // Validate nonce freshness
        match &msg.nonce {
            Some(nonce) => {
                if !TurnAuth::validate_nonce(
                    nonce,
                    self.config.nonce_lifetime_secs,
                    &self.config.nonce_secret,
                ) {
                    // 438 Stale Nonce must include REALM and fresh NONCE per RFC 5389
                    return Err(self.build_stale_nonce_response(msg));
                }
            }
            None => {
                warn!("Missing NONCE in authenticated request");
                return Err(self.build_error_response(msg, TurnErrorCode::BadRequest));
            }
        }

        // Validate REALM - required for long-term credentials per RFC 5389
        match msg.realm.as_deref() {
            Some(realm) if realm != self.config.realm => {
                warn!(
                    "Realm mismatch: client sent {:?}, expected {:?}",
                    realm, self.config.realm
                );
                return Err(self.build_unauthorized_response(msg));
            }
            None => {
                warn!("Missing REALM attribute in authenticated request");
                return Err(self.build_unauthorized_response(msg));
            }
            _ => {} // Realm matches
        }

        // Derive candidate passwords only now: with REST API secrets this costs
        // one HMAC per secret, which a request with a stale nonce or wrong
        // realm must not be able to force.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let passwords = self.config.candidate_passwords(username, now);
        if passwords.is_empty() {
            // debug, not warn: any unauthenticated sender reaches this, so a
            // warn would let it flood the log.
            debug!(
                "Unknown or expired username in authenticated request: {:?}",
                username
            );
            return Err(self.build_unauthorized_response(msg));
        }

        let (integrity, offset) = match (&msg.message_integrity, msg.message_integrity_offset) {
            (Some(i), Some(o)) => (i, o),
            _ => {
                warn!("MESSAGE-INTEGRITY parsing error");
                return Err(self.build_error_response(msg, TurnErrorCode::BadRequest));
            }
        };

        // Build message up to MESSAGE-INTEGRITY for validation. The header
        // length must be adjusted to end right after the MESSAGE-INTEGRITY
        // attribute: offset - 20 (header) + 24 (MESSAGE-INTEGRITY attr size).
        let mut msg_for_hmac = msg.raw[..offset].to_vec();
        let new_len = (offset - 20 + 24) as u16;
        msg_for_hmac[2..4].copy_from_slice(&new_len.to_be_bytes());

        // Always use server's realm for key computation. More than one
        // candidate only when several REST API secrets are configured.
        let key = passwords
            .iter()
            .map(|password| TurnAuth::compute_key(username, &self.config.realm, password))
            .find(|key| TurnAuth::verify_message_integrity(&msg_for_hmac, integrity, key));
        let Some(key) = key else {
            warn!("Invalid MESSAGE-INTEGRITY for user {:?}", username);
            return Err(self.build_unauthorized_response(msg));
        };

        debug!("MESSAGE-INTEGRITY validated for user {:?}", username);
        Ok((username.clone(), key))
    }

    /// Authenticate a request that operates on an existing allocation
    /// (Refresh, CreatePermission, ChannelBind) and resolve that allocation.
    ///
    /// RFC 5766 §10.1: every request after the initial Allocate carries the same
    /// credentials as the Allocate did, so the username must match the one on
    /// the allocation.
    ///
    /// Authentication deliberately runs *before* the allocation lookup. The
    /// lookup's own failure is a 437, and RFC 5389 §10.2.3 has an authenticated
    /// client discard an error response that carries no MESSAGE-INTEGRITY - so a
    /// 437 built without a key is invisible: the client retransmits through its
    /// whole RTO schedule (~39.5s) and reports a timeout instead of reallocating.
    /// Allocations here live at most 60s, so a client that loses one Refresh hits
    /// this on its next one.
    ///
    /// Returns the allocation id and the key every response on this request must
    /// be signed with (`None` in anonymous mode), or the error response to send.
    fn authenticate_for_allocation(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
    ) -> Result<(AllocationId, Option<[u8; 16]>), Vec<u8>> {
        let auth = if !self.config.auth_enabled() {
            None
        } else {
            Some(self.verify_long_term_credentials(msg)?)
        };
        let key = auth.as_ref().map(|(_, k)| *k);

        // Snapshot id + username, then drop the guard: the caller awaits a send
        // on every path out of here and must not hold an allocation guard.
        let found = self
            .allocations
            .get_by_client(src_addr)
            .map(|a| (a.id, a.username.clone()));

        match (found, &auth) {
            (None, _) => {
                debug!("Request from {} has no allocation - 437", src_addr);
                Err(self.build_signed_error_response(
                    msg,
                    TurnErrorCode::AllocationMismatch,
                    key.as_ref(),
                ))
            }
            (Some((_, allocated_to)), Some((username, _))) if allocated_to != *username => {
                warn!(
                    "Username mismatch: allocation for {} belongs to {:?}, request says {:?}",
                    src_addr, allocated_to, username
                );
                Err(self.build_unauthorized_response(msg))
            }
            (Some((id, _)), _) => Ok((id, key)),
        }
    }

    /// Handle incoming STUN/TURN message
    pub async fn handle_stun(
        &self,
        msg: StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        use crate::demux::stun::{StunClass, StunMethod};

        match (&msg.class, &msg.method) {
            // STUN Binding Request (ICE connectivity check)
            (StunClass::Request, StunMethod::Binding) => {
                self.handle_binding_request(&msg, src_addr, socket).await
            }

            // TURN Allocate
            (StunClass::Request, StunMethod::Allocate) => {
                self.handle_allocate(&msg, src_addr, socket).await
            }

            // TURN Refresh
            (StunClass::Request, StunMethod::Refresh) => {
                self.handle_refresh(&msg, src_addr, socket).await
            }

            // TURN CreatePermission
            (StunClass::Request, StunMethod::CreatePermission) => {
                self.handle_create_permission(&msg, src_addr, socket).await
            }

            // TURN ChannelBind
            (StunClass::Request, StunMethod::ChannelBind) => {
                self.handle_channel_bind(&msg, src_addr, socket).await
            }

            // TURN Send (client -> peer via indication)
            (StunClass::Indication, StunMethod::Send) => {
                self.handle_send(&msg, src_addr, socket).await
            }

            // Handle STUN responses from clients - relay them to peers
            (StunClass::SuccessResponse, _) | (StunClass::ErrorResponse, _) => {
                // If this is from a client with an allocation, relay to peers
                if self.allocations.lookup_by_source(src_addr).is_some() {
                    self.handle_client_response(&msg, src_addr, socket).await
                } else {
                    debug!(
                        "Unhandled STUN response: {:?} {:?} from {}",
                        msg.class, msg.method, src_addr
                    );
                    Ok(())
                }
            }

            _ => {
                debug!(
                    "Unhandled STUN message: {:?} {:?} from {}",
                    msg.class, msg.method, src_addr
                );
                Ok(())
            }
        }
    }

    /// Handle STUN Binding Request
    ///
    /// In single-port TURN, ICE connectivity checks may arrive as direct Binding Requests
    /// (not via Send Indication) because the remote relay address equals the TURN server address.
    /// We detect this case and relay the Binding Request to other clients.
    async fn handle_binding_request(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Binding request from {}", src_addr);

        // Non-TURN client (no allocation): respond with a normal Binding Response
        // (server reflexive). Membership is checked without holding a guard.
        if !self.allocations.is_client(src_addr) {
            let response = self.build_binding_response(msg, src_addr);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Sender is a TURN client doing ICE checks. Snapshot its id and current
        // relay permission, releasing the guard immediately: the relay paths below
        // await socket sends, and a guard must never be held across I/O.
        let (alloc_id, already_permitted) = match self.allocations.get_by_client(src_addr) {
            Some(a) => (a.id, a.is_permitted(self.config.external_ip)),
            None => {
                let response = self.build_binding_response(msg, src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Register ICE ufrags from USERNAME attribute (format: "remoteUfrag:localUfrag").
        // This is critical for single-port TURN to route DTLS/media correctly.
        // The parsed pair is kept: `remote_ufrag` also names the one allocation
        // this check is addressed to, which is what the relay below routes on.
        let ice_ufrags = msg.parse_ice_username();
        if let Some((remote_ufrag, local_ufrag)) = &ice_ufrags {
            let registered = self.allocations.register_ice_ufrags(
                alloc_id,
                local_ufrag.clone(),
                remote_ufrag.clone(),
            );
            if registered {
                debug!(
                    "Registered ICE ufrags for {}: local={}, remote={}",
                    src_addr, local_ufrag, remote_ufrag
                );
            }
        }

        // Auto-grant permission for relay IP if not already granted. This handles
        // the case where Chrome doesn't send CreatePermission when remote relay ==
        // local relay (single-port TURN).
        if !already_permitted {
            self.allocations
                .add_permission(alloc_id, self.config.external_ip);
            debug!(
                "Auto-granted permission for relay IP to allocation {}",
                alloc_id
            );
        }

        // Update the sender's activity timer and snapshot whether it is permitted
        // for the relay IP, then release the guard before any await.
        let sender_permitted = match self.allocations.get_by_client(src_addr) {
            Some(a) => {
                // Client is actively sending ICE checks
                a.touch_received();
                a.is_permitted(self.config.external_ip)
            }
            None => {
                let response = self.build_binding_response(msg, src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Relay the check to the one allocation it is addressed to.
        //
        // An ICE connectivity check names its destination: USERNAME carries
        // "remoteUfrag:localUfrag", so `remote_ufrag` identifies the peer this
        // packet is for. Delivering it anywhere else is not just wasted fan-out,
        // it is a disclosure - the USERNAME would hand every other client on this
        // server the ufrag pair of a call it has nothing to do with. That pair is
        // all an attacker needs, because `AllocationTable::register_ice_ufrags` is
        // first-come-first-served: claim the peer's ufrag before it does and the
        // reverse-pair lookup in `find_ice_peers` routes that call's media to the
        // claimant while the real peer, whose own registration now loses the race,
        // goes dark.
        //
        // If the addressed peer has not allocated yet there is nothing to deliver
        // to. Dropping is correct and free: STUN retransmits the check over its
        // RTO schedule (RFC 5389 section 7.2.1, ~39.5s), by which time the peer has
        // registered. No buffering, and no fan-out for an attacker to farm.
        if sender_permitted {
            let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);

            // Snapshot the target's client address without holding an allocation
            // guard across the await below.
            let target_addr = ice_ufrags.as_ref().and_then(|(remote_ufrag, _)| {
                let target_id = self.allocations.lookup_by_ice_ufrag(remote_ufrag)?;
                let target = self.allocations.get(target_id)?;
                if target.client_addr == src_addr || !target.is_permitted(self.config.external_ip) {
                    return None;
                }
                Some(target.client_addr)
            });

            match target_addr {
                Some(target_addr) => {
                    debug!(
                        "Relaying Binding Request from {} to {} via Data Indication",
                        src_addr, target_addr
                    );
                    // XOR-PEER-ADDRESS = relay address (from receiver's perspective).
                    let indication = self.build_data_indication(relay_addr, &msg.raw);
                    socket.send_to(&indication, target_addr).await?;
                }
                None => {
                    trace!(
                        "Binding Request from {} dropped: no allocation holds target ufrag {:?}",
                        src_addr,
                        ice_ufrags.as_ref().map(|(remote, _)| remote),
                    );
                }
            }
        }

        // For TURN clients: don't respond ourselves - let the peer respond. This
        // allows consent freshness to work correctly (timeout if peer is gone).
        Ok(())
    }

    /// Handle STUN response from a client - relay to ICE-paired peers.
    ///
    /// STUN responses carry no USERNAME, so they cannot disclose a ufrag pair.
    /// We therefore route using the *sender's* already-registered ICE pair
    /// (`find_ice_peers`). Permission-IP fanout is intentionally not used: in
    /// single-port mode many allocations share permissions for the same IPs,
    /// and fanout would cross-talk between unrelated calls. If the sender has
    /// not yet registered ICE credentials, the response is dropped.
    async fn handle_client_response(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Client response from {} - relaying to ICE peers", src_addr);

        let (local, remote) = match self.allocations.get_by_client(src_addr) {
            Some(alloc) => (alloc.get_ice_ufrag(), alloc.get_ice_remote_ufrag()),
            None => {
                trace!("Client response from unknown client {}", src_addr);
                return Ok(());
            }
        };

        let peers = match (local.as_deref(), remote.as_deref()) {
            (Some(l), Some(r)) => self.allocations.find_ice_peers(l, r),
            _ => {
                trace!(
                    "Client response from {} dropped: no ICE ufrag pair registered yet",
                    src_addr
                );
                return Ok(());
            }
        };

        let targets: Vec<SocketAddr> = peers
            .into_iter()
            .filter_map(|alloc_id| {
                let target = self.allocations.get(alloc_id)?;
                if target.client_addr == src_addr {
                    None
                } else {
                    Some(target.client_addr)
                }
            })
            .collect();

        if targets.is_empty() {
            return Ok(());
        }

        let indication = self.build_data_indication(src_addr, &msg.raw);
        for target_addr in targets {
            debug!(
                "Relaying response from {} to {} via Data Indication",
                src_addr, target_addr
            );
            socket.send_to(&indication, target_addr).await?;
        }

        Ok(())
    }

    /// Handle TURN Allocate Request
    ///
    /// Order follows RFC 5766 §6.2: authenticate first, then check the 5-tuple
    /// for an existing allocation, then validate the request, then admission
    /// control, then create.
    async fn handle_allocate(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        info!("Allocate request from {}", src_addr);

        // 1. Authenticate. Nothing below - including the retransmission shortcut -
        //    may act on a request whose MESSAGE-INTEGRITY has not been verified.
        let auth: Option<(String, [u8; 16])> = if !self.config.auth_enabled() {
            None
        } else {
            match self.verify_long_term_credentials(msg) {
                Ok(v) => Some(v),
                Err(response) => {
                    debug!("Allocate auth failed from {}", src_addr);
                    socket.send_to(&response, src_addr).await?;
                    return Ok(());
                }
            }
        };
        let key = auth.as_ref().map(|(_, k)| k);
        let username: String = match &auth {
            Some((u, _)) => u.clone(),
            // Anonymous mode: the (unauthenticated) USERNAME is informational only.
            None => msg.username.as_deref().unwrap_or("anonymous").to_string(),
        };

        // 2. Existing *live* allocation on this 5-tuple. A retransmission carries
        //    the same transaction id and gets the success response again; a *new*
        //    Allocate over a live allocation is a 437 Allocation Mismatch.
        //
        //    An allocation whose lifetime has run out but which cleanup_expired
        //    (2s interval) has not reaped yet is not live.
        let existing = self.allocations.get_by_client(src_addr).map(|a| {
            (
                a.id,
                a.is_expired(),
                a.allocate_txn_id == msg.transaction_id,
                a.remaining_lifetime(),
            )
        });

        // Reap a lapsed allocation rather than answer it: 437 would leave a
        // client that lets its allocation expire and reconnects unable to
        // allocate until the reaper catches up, and the success-with-lifetime-0
        // it used to get is just as dead. Releasing the quota slot here mirrors
        // what cleanup_expired would have done.
        if let Some((id, true, _, _)) = existing {
            if self.allocations.remove(id) {
                self.rate_limiter.record_deallocation(src_addr.ip());
                debug!(
                    "Reaped expired allocation {} for {} before re-Allocate",
                    id, src_addr
                );
            }
        } else if let Some((_, false, is_retransmission, lifetime)) = existing {
            if is_retransmission {
                debug!(
                    "Allocate retransmission from {} - resending success",
                    src_addr
                );
                let response = self.build_allocate_response(msg, src_addr, lifetime, key);
                socket.send_to(&response, src_addr).await?;
            } else {
                warn!(
                    "Allocate from {} with a new transaction id over an existing allocation - 437",
                    src_addr
                );
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::AllocationMismatch, key);
                socket.send_to(&response, src_addr).await?;
            }
            return Ok(());
        }

        // 3. Validate REQUESTED-TRANSPORT (RFC 5766 requires UDP = 17)
        match msg.requested_transport {
            Some(17) => {
                // UDP is supported
            }
            Some(other) => {
                warn!("Unsupported transport protocol {} from {}", other, src_addr);
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::UnsupportedTransport, key);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            None => {
                // Per RFC 5766, REQUESTED-TRANSPORT is required. However, some clients
                // may omit it for UDP-only servers. We'll be lenient and assume UDP.
                debug!("Allocate request missing REQUESTED-TRANSPORT, assuming UDP");
            }
        }

        // 4. Admission control. Runs after auth so that auth failures return 401,
        //    not 508/486, and only valid attempts count against the limits.
        if let Err(e) = self.rate_limiter.check_allocation_request(src_addr.ip()) {
            warn!("Allocate request rejected for {}: {}", src_addr, e);
            let error_code = match e {
                RateLimitError::TooManyRequests => TurnErrorCode::InsufficientCapacity,
                RateLimitError::QuotaExceeded => TurnErrorCode::AllocationQuotaReached,
            };
            let response = self.build_signed_error_response(msg, error_code, key);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // 5. Create the allocation atomically, remembering the transaction id so
        //    retransmissions can be recognised in step 2.
        let lifetime = 60;
        let (alloc_id, created) = self.allocations.create_or_get(
            src_addr,
            username.clone(),
            lifetime,
            msg.transaction_id,
        );

        if !created {
            // Concurrent request won the race - treat as retransmission and
            // cancel our rate limiter reservation since nothing new was created.
            debug!(
                "Concurrent allocation created for {} - treating as retransmission",
                src_addr
            );
            self.rate_limiter.cancel_reservation(src_addr.ip());
        } else {
            info!(
                "Created allocation {} for {} (user: {})",
                alloc_id, src_addr, username
            );
        }

        // Get actual lifetime from allocation (may be different if existing)
        let actual_lifetime = self
            .allocations
            .get(alloc_id)
            .map(|a| a.remaining_lifetime())
            .unwrap_or(lifetime);

        let response = self.build_allocate_response(msg, src_addr, actual_lifetime, key);
        debug!(
            "Sending Allocate response ({} bytes) to {}: {:02x?}",
            response.len(),
            src_addr,
            &response[..std::cmp::min(response.len(), 64)]
        );
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN Refresh Request
    async fn handle_refresh(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Refresh request from {}", src_addr);

        // Authenticate, then resolve the allocation (RFC 5766 §10.1). No
        // allocation guard is held across the awaits below.
        let (alloc_id, key) = match self.authenticate_for_allocation(msg, src_addr) {
            Ok(v) => v,
            Err(response) => {
                debug!("Refresh from {} rejected", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Parse requested lifetime (0 means delete allocation)
        let requested_lifetime = msg.lifetime.unwrap_or(60);

        if requested_lifetime == 0 {
            // Client wants to delete the allocation. Only release the quota
            // slot if *we* removed it: if cleanup reaped it concurrently, the
            // cleanup task already released the slot and a second decrement
            // would let this IP exceed its allocation quota.
            if self.allocations.remove(alloc_id) {
                self.rate_limiter.record_deallocation(src_addr.ip());
                info!(
                    "Deleted allocation {} for {} (lifetime=0)",
                    alloc_id, src_addr
                );
            } else {
                debug!(
                    "Allocation {} for {} already removed before lifetime=0 refresh",
                    alloc_id, src_addr
                );
            }

            let response = self.build_refresh_response(msg, 0, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Cap lifetime at 60 seconds max, minimum 10 seconds
        let lifetime = requested_lifetime.clamp(10, 60);
        // Re-acquire briefly to extend the lifetime and activity timer; if the
        // allocation was reaped concurrently we simply skip the update.
        if let Some(alloc) = self.allocations.get_by_client(src_addr) {
            alloc.refresh(lifetime);
            alloc.touch_received();
        }

        debug!(
            "Refreshed allocation for {} (lifetime={}s)",
            src_addr, lifetime
        );

        let response = self.build_refresh_response(msg, lifetime, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN CreatePermission Request
    async fn handle_create_permission(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("CreatePermission request from {}", src_addr);

        // Parse XOR-PEER-ADDRESS attributes first (can have multiple)
        if msg.xor_peer_addresses.is_empty() {
            warn!(
                "CreatePermission missing XOR-PEER-ADDRESS from {}",
                src_addr
            );
            let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Authenticate, then resolve the allocation (RFC 5766 §10.1). No
        // allocation guard is held across the awaits below.
        let (alloc_id, key) = match self.authenticate_for_allocation(msg, src_addr) {
            Ok(v) => v,
            Err(response) => {
                debug!("CreatePermission from {} rejected", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Reject forbidden peer IPs. RFC 5766 §9.2 permits the server to reject
        // any peer address it does not wish to relay to; 403 covers
        // loopback/multicast/etc. Runs after authentication so the response can
        // be signed - an unsigned 403 is discarded by an authenticated client.
        for peer_addr in &msg.xor_peer_addresses {
            if is_forbidden_peer_ip(peer_addr.ip()) {
                warn!(
                    "CreatePermission with forbidden peer {} from {}",
                    peer_addr.ip(),
                    src_addr
                );
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::Forbidden, key.as_ref());
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        }

        if let Some(alloc) = self.allocations.get(alloc_id) {
            alloc.touch_received();
        }

        // Atomically enforce the per-allocation permission cap and insert the
        // new peer IPs. Re-adds of existing permissions are always allowed
        // (refresh semantics). Holding the write lock across the count check
        // and insert avoids TOCTOU against concurrent CreatePermission requests.
        let peer_ips: Vec<IpAddr> = msg.xor_peer_addresses.iter().map(|a| a.ip()).collect();
        if !self.allocations.try_add_permissions_capped(
            alloc_id,
            &peer_ips,
            self.config.max_permissions_per_alloc,
        ) {
            warn!(
                "CreatePermission cap exceeded for {} (alloc {}, max {})",
                src_addr, alloc_id, self.config.max_permissions_per_alloc
            );
            let response = self.build_signed_error_response(
                msg,
                TurnErrorCode::InsufficientCapacity,
                key.as_ref(),
            );
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        info!(
            "CreatePermission: added/refreshed {} peer(s) for {} (alloc {})",
            peer_ips.len(),
            src_addr,
            alloc_id
        );

        let response = self.build_success_response(msg, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN ChannelBind Request
    async fn handle_channel_bind(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("ChannelBind request from {}", src_addr);

        // Parse CHANNEL-NUMBER
        let channel = match msg.channel_number {
            Some(ch) => ch,
            None => {
                warn!("ChannelBind missing CHANNEL-NUMBER from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Parse XOR-PEER-ADDRESS (ChannelBind uses only one peer address)
        let peer_addr = match msg.xor_peer_addresses.first() {
            Some(addr) => *addr,
            None => {
                warn!("ChannelBind missing XOR-PEER-ADDRESS from {}", src_addr);
                let response = self.build_error_response(msg, TurnErrorCode::BadRequest);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Authenticate, then resolve the allocation (RFC 5766 §10.1). No
        // allocation guard is held across the awaits below.
        let (alloc_id, key) = match self.authenticate_for_allocation(msg, src_addr) {
            Ok(v) => v,
            Err(response) => {
                debug!("ChannelBind from {} rejected", src_addr);
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // Runs after authentication so the 403 can be signed - an unsigned error
        // response is discarded by an authenticated client (RFC 5389 §10.2.3).
        if is_forbidden_peer_addr(&self.config, peer_addr) {
            warn!(
                "ChannelBind with forbidden peer {} from {}",
                peer_addr, src_addr
            );
            let response =
                self.build_signed_error_response(msg, TurnErrorCode::Forbidden, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        /// Outcome of the bind check, decided under one short-lived guard.
        enum Bind {
            /// Admissible. `needs_bind` is false for a refresh of the same pair.
            Ok {
                needs_bind: bool,
            },
            /// Channel bound to another peer, or peer bound to another channel.
            Conflict,
            CapExceeded(usize),
            Gone,
        }

        // Decide the outcome before mutating anything. RFC 5766 §11.2 requires an
        // error response to leave the allocation untouched; installing the implied
        // permission up front let a client fill its permission table with IPs
        // through ChannelBinds the server goes on to reject.
        let outcome = match self.allocations.get(alloc_id) {
            Some(alloc) => {
                let bound_peer = alloc.peer_for_channel(channel);
                let bound_channel = alloc.channel_for_peer(peer_addr);
                match (bound_peer, bound_channel) {
                    // RFC 5766 §11.2: a channel may not be rebound to a different
                    // peer, nor a peer to a different channel, while bound. Both
                    // accessors report only *live* bindings, so a pair whose
                    // 10-minute lifetime (§11) has lapsed is free to be rebound
                    // rather than conflicting for the life of the allocation.
                    (Some(p), _) if p != peer_addr => Bind::Conflict,
                    (_, Some(c)) if c != channel => Bind::Conflict,
                    // Identical binding: still needs bind_channel() so the
                    // 10-minute lifetime is refreshed (RFC 5766 §11).
                    (Some(_), Some(_)) => Bind::Ok { needs_bind: true },
                    _ if alloc.channels_count() >= self.config.max_channels_per_alloc => {
                        Bind::CapExceeded(alloc.channels_count())
                    }
                    _ => Bind::Ok { needs_bind: true },
                }
            }
            None => Bind::Gone,
        };

        let needs_bind = match outcome {
            Bind::Ok { needs_bind } => needs_bind,
            Bind::Conflict => {
                warn!(
                    "ChannelBind conflict from {}: channel 0x{:04x} / peer {} already bound elsewhere",
                    src_addr, channel, peer_addr
                );
                let response =
                    self.build_signed_error_response(msg, TurnErrorCode::BadRequest, key.as_ref());
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            Bind::CapExceeded(count) => {
                warn!(
                    "ChannelBind cap exceeded for {}: {} >= {}",
                    src_addr, count, self.config.max_channels_per_alloc
                );
                let response = self.build_signed_error_response(
                    msg,
                    TurnErrorCode::InsufficientCapacity,
                    key.as_ref(),
                );
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
            Bind::Gone => {
                let response = self.build_signed_error_response(
                    msg,
                    TurnErrorCode::AllocationMismatch,
                    key.as_ref(),
                );
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        };

        // ChannelBind also installs (or refreshes) a permission for the peer IP
        // (RFC 5766 §11.2). Go through the capped path so ChannelBind cannot be
        // used to bypass the per-allocation permission cap.
        if !self.allocations.try_add_permissions_capped(
            alloc_id,
            &[peer_addr.ip()],
            self.config.max_permissions_per_alloc,
        ) {
            let (code, what) = if self.allocations.get(alloc_id).is_none() {
                (TurnErrorCode::AllocationMismatch, "allocation gone")
            } else {
                (
                    TurnErrorCode::InsufficientCapacity,
                    "permission cap exceeded",
                )
            };
            warn!("ChannelBind from {} rejected: {}", src_addr, what);
            let response = self.build_signed_error_response(msg, code, key.as_ref());
            socket.send_to(&response, src_addr).await?;
            return Ok(());
        }

        // Commit the binding. The permission is in place, so a client that gets
        // a success response can use the channel immediately.
        match self.allocations.get(alloc_id) {
            Some(alloc) => {
                if needs_bind {
                    alloc.bind_channel(channel, peer_addr);
                }
                alloc.touch_received();
            }
            None => {
                let response = self.build_signed_error_response(
                    msg,
                    TurnErrorCode::AllocationMismatch,
                    key.as_ref(),
                );
                socket.send_to(&response, src_addr).await?;
                return Ok(());
            }
        }

        info!(
            "ChannelBind: channel 0x{:04x} -> {} for {} (alloc {})",
            channel, peer_addr, src_addr, alloc_id
        );

        let response = self.build_success_response(msg, key.as_ref());
        socket.send_to(&response, src_addr).await?;

        Ok(())
    }

    /// Handle TURN Send Indication
    async fn handle_send(
        &self,
        msg: &StunInfo,
        src_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<()> {
        debug!("Send indication from {}", src_addr);

        // This client must have an allocation. We deliberately do NOT hold the
        // allocation guard across this function: the relay paths below await
        // socket sends, and an allocation guard must never be held across I/O.
        // Each branch re-acquires the allocation briefly as needed.
        if !self.allocations.is_client(src_addr) {
            trace!("Send indication from unknown client: {}", src_addr);
            return Ok(());
        }

        // Get peer address
        let peer_addr = match msg.xor_peer_addresses.first() {
            Some(addr) => *addr,
            None => {
                warn!("Send indication missing XOR-PEER-ADDRESS from {}", src_addr);
                return Ok(());
            }
        };

        // Reject forbidden peer targets: loopback, multicast, broadcast, link-
        // local, and our own external IP on a non-relay port. Same IP + relay
        // port is the legitimate single-port internal-routing case handled below.
        if is_forbidden_peer_addr(&self.config, peer_addr) {
            warn!(
                "Send indication to forbidden peer {} from {}",
                peer_addr, src_addr
            );
            return Ok(());
        }

        // Prevent sending to ourselves (would create a loop)
        let our_addr = SocketAddr::new(self.config.external_ip, self.config.port);
        if peer_addr == our_addr {
            // This is valid in single-port TURN - both clients may have the same relay address
            // In this case, we need to find OTHER allocations that have permission for our relay
            // and send the data to them
            debug!("Send to our own relay address - routing internally");

            // Snapshot the sender's permission + id, then release the guard before
            // any await below (never hold an allocation guard across socket I/O).
            let (sender_permitted, alloc_id) = match self.allocations.get_by_client(src_addr) {
                Some(a) => (a.is_permitted(self.config.external_ip), a.id),
                None => return Ok(()),
            };

            // Check that the SENDER has permission for the relay IP (RFC 5766 requirement)
            if !sender_permitted {
                warn!(
                    "Send indication to relay address from {} without permission",
                    src_addr
                );
                return Ok(());
            }

            let data = match &msg.data {
                Some(d) => d,
                None => return Ok(()),
            };

            // Route via ICE ufrags to avoid cross-talk between unrelated calls.
            // If no ufrag matches (the target has not registered yet), the
            // payload is dropped, not broadcast: STUN retransmits the check and
            // a later copy routes once the peer is up.
            let mut sent = false;

            // For STUN Binding Requests: register sender ufrags and route by target ufrag
            if let Some(stun_info) = StunInfo::parse(data) {
                if stun_info.method == StunMethod::Binding && stun_info.class == StunClass::Request
                {
                    if let Some((remote_ufrag, local_ufrag)) = stun_info.parse_ice_username() {
                        let registered = self.allocations.register_ice_ufrags(
                            alloc_id,
                            local_ufrag.clone(),
                            remote_ufrag.clone(),
                        );
                        if registered {
                            debug!(
                                "ICE registration (Send indication): {} local={}, remote={}",
                                src_addr, local_ufrag, remote_ufrag
                            );
                        }

                        // Route to target by their ICE ufrag: snapshot its address,
                        // release the guard, then await.
                        let target_addr = self
                            .allocations
                            .lookup_by_ice_ufrag(&remote_ufrag)
                            .and_then(|target_id| {
                                let target = self.allocations.get(target_id)?;
                                if target.client_addr != src_addr
                                    && target.is_permitted(self.config.external_ip)
                                {
                                    Some(target.client_addr)
                                } else {
                                    None
                                }
                            });
                        if let Some(target_addr) = target_addr {
                            let indication = self.build_data_indication(our_addr, data);
                            socket.send_to(&indication, target_addr).await?;
                            sent = true;
                        }
                    }
                }
            }

            // For non-STUN or STUN responses: use ICE peer matching. Read the
            // sender's ufrags fresh (the block above may have just registered
            // them), then snapshot peer addresses before awaiting.
            if !sent {
                let (sender_local, sender_remote) = match self.allocations.get_by_client(src_addr) {
                    Some(a) => (a.get_ice_ufrag(), a.get_ice_remote_ufrag()),
                    None => (None, None),
                };
                if let (Some(local), Some(remote)) = (&sender_local, &sender_remote) {
                    let targets: Vec<SocketAddr> = self
                        .allocations
                        .find_ice_peers(local, remote)
                        .into_iter()
                        .filter_map(|peer_id| {
                            let target = self.allocations.get(peer_id)?;
                            if target.client_addr != src_addr
                                && target.is_permitted(self.config.external_ip)
                            {
                                Some(target.client_addr)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !targets.is_empty() {
                        let indication = self.build_data_indication(our_addr, data);
                        for target_addr in targets {
                            socket.send_to(&indication, target_addr).await?;
                            sent = true;
                        }
                    }
                }
            }

            // Nothing matched, so there is nobody to deliver to: drop.
            //
            // This used to fall back to a broadcast, restricted to allocations
            // that had not registered an ICE ufrag yet, on the theory that those
            // are calls still setting up rather than established ones. That
            // restriction does not hold. "Unpaired" is not a transient startup
            // state a client passes through - it is a state a client can simply
            // choose and stay in, for free and indefinitely: allocate, permit the
            // relay IP, never send a check carrying a USERNAME, and Refresh every
            // 30s. `is_inactive` is fed by Refresh (`Allocation::touch_received`)
            // so the allocation never ages out, and `is_orphaned_sender` returns
            // false while `has_relay_attempt` is unset, so a purely passive
            // allocation is never reaped either. Anyone parked like that received
            // the first connectivity check of every new call on this server -
            // which is exactly the packet whose USERNAME carries both ufrags of
            // that call, and that pair is enough to hijack it (see the routing
            // comment in `handle_binding_request`).
            //
            // Dropping costs nothing: STUN retransmits the check over its RTO
            // schedule (RFC 5389 section 7.2.1), so once the real peer registers, a
            // retransmit routes to it by ufrag on one of the paths above.
            if !sent {
                trace!(
                    "Internal routing from {} dropped: no ufrag match for target",
                    src_addr
                );
            }

            // Touch sender's allocation - they're actively sending data. A
            // successful internal route also feeds the orphan-sender timer, but a
            // failed one deliberately does not: the payload here is usually an ICE
            // connectivity check, sent before any peer exists, so arming the timer
            // would have cleanup_orphaned_senders reap the allocation of whoever
            // joins first (ringing, waiting room, slow signalling) 45s later,
            // while it is actively sending and refreshing. The ChannelData and raw
            // media paths do arm it on a failed relay, but STUN never reaches
            // them - engine.rs routes ICE in its own branch and server.rs only
            // sees RTP/RTCP/DTLS - so by then the client is past ICE.
            if let Some(a) = self.allocations.get_by_client(src_addr) {
                a.touch_received();
                if sent {
                    a.touch_relay_success();
                }
            }
            return Ok(());
        }

        // Get data
        let data = match &msg.data {
            Some(d) => d,
            None => {
                trace!("Send indication missing DATA from {}", src_addr);
                return Ok(());
            }
        };

        // Check permission (snapshot, then release the guard before the await).
        let permitted = match self.allocations.get_by_client(src_addr) {
            Some(a) => a.is_permitted(peer_addr.ip()),
            None => return Ok(()),
        };
        if !permitted {
            warn!(
                "Send indication to unpermitted peer {} from {}",
                peer_addr, src_addr
            );
            return Ok(());
        }

        // Decide where the payload goes under a short guard, release it, then
        // send: the arms below await, and an allocation guard must never be
        // held across I/O.
        match self.classify_send_target(src_addr, peer_addr) {
            SendTarget::Drop => {
                trace!("Send indication from {} to {} dropped", src_addr, peer_addr);
                return Ok(());
            }
            SendTarget::Local {
                id: target_id,
                reverse_channel,
            } => {
                debug!(
                    "Relaying {} bytes from {} to TURN client {} via {}",
                    data.len(),
                    src_addr,
                    peer_addr,
                    match reverse_channel {
                        Some(c) => format!("reverse channel 0x{:04x}", c),
                        None => "Data Indication".to_string(),
                    }
                );
                let packet = match reverse_channel {
                    Some(c) => self.build_channel_data(c, data),
                    None => self.build_data_indication(src_addr, data),
                };
                socket.send_to(&packet, peer_addr).await?;
                if let Some(t) = self.allocations.get(target_id) {
                    t.touch();
                }
            }
            SendTarget::External => {
                debug!(
                    "Relaying {} bytes from {} to peer {}",
                    data.len(),
                    src_addr,
                    peer_addr
                );
                socket.send_to(data, peer_addr).await?;
            }
        }

        // Touch sender's allocation - they're actively sending data
        if let Some(a) = self.allocations.get_by_client(src_addr) {
            a.touch_received();
        }

        Ok(())
    }

    /// Build a STUN Binding Response
    fn build_binding_response(&self, request: &StunInfo, client_addr: SocketAddr) -> Vec<u8> {
        let mut response = Vec::with_capacity(32);

        // Message type: Binding Success Response (0x0101)
        response.extend_from_slice(&[0x01, 0x01]);

        // Placeholder for length (will be filled later)
        response.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);

        // Transaction ID
        response.extend_from_slice(&request.transaction_id);

        // XOR-MAPPED-ADDRESS attribute
        self.append_xor_mapped_address(&mut response, client_addr, &request.transaction_id);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a TURN Allocate Success Response
    fn build_allocate_response(
        &self,
        request: &StunInfo,
        client_addr: SocketAddr,
        lifetime: u32,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(96);

        // Message type: Allocate Success Response (0x0103)
        response.extend_from_slice(&[0x01, 0x03]);
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]); // Magic cookie
        response.extend_from_slice(&request.transaction_id);

        // XOR-RELAYED-ADDRESS (our single port!)
        let relay_addr = SocketAddr::new(self.config.external_ip, self.config.port);
        self.append_xor_relayed_address(&mut response, relay_addr, &request.transaction_id);

        // XOR-MAPPED-ADDRESS
        self.append_xor_mapped_address(&mut response, client_addr, &request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build a TURN Refresh Success Response
    fn build_refresh_response(
        &self,
        request: &StunInfo,
        lifetime: u32,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

        // Message type: Refresh Success Response (0x0104)
        response.extend_from_slice(&[0x01, 0x04]);
        response.extend_from_slice(&[0x00, 0x00]);
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // LIFETIME
        self.append_lifetime(&mut response, lifetime);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build a generic success response
    fn build_success_response(&self, request: &StunInfo, key: Option<&[u8; 16]>) -> Vec<u8> {
        let mut response = Vec::with_capacity(64);

        // Success response: set bit 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let success_type = msg_type | 0x0100;

        response.extend_from_slice(&success_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Build an error response without MESSAGE-INTEGRITY.
    ///
    /// Only for errors raised before the credentials were verified, where no
    /// key is available. Anything answered after authentication goes through
    /// [`Self::build_signed_error_response`].
    fn build_error_response(&self, request: &StunInfo, error: TurnErrorCode) -> Vec<u8> {
        self.build_signed_error_response(request, error, None)
    }

    /// Build an error response, signed when the request was authenticated.
    ///
    /// RFC 5389 Section 10.2.3: a client using long-term credentials discards an
    /// error response that carries no MESSAGE-INTEGRITY, except for 400, 401 and
    /// 438. An unsigned 437 or 508 is therefore invisible to the client - it keeps
    /// retransmitting until its RTO schedule runs out (~39.5s) and then reports a
    /// plain timeout instead of the error we sent.
    fn build_signed_error_response(
        &self,
        request: &StunInfo,
        error: TurnErrorCode,
        key: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(48);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009)
        let reason = error.reason();
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes()); // Length
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push((error as u16 / 100) as u8); // Class
        response.push((error as u16 % 100) as u8); // Number
        response.extend_from_slice(reason.as_bytes());

        // Padding (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // MESSAGE-INTEGRITY (if authenticated)
        if let Some(key) = key {
            self.append_message_integrity(&mut response, key);
        } else {
            // Update length (no MESSAGE-INTEGRITY)
            let attr_len = (response.len() - 20) as u16;
            response[2..4].copy_from_slice(&attr_len.to_be_bytes());
        }

        response
    }

    /// Append XOR-MAPPED-ADDRESS attribute
    fn append_xor_mapped_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        // Attribute type: 0x0020
        buf.extend_from_slice(&[0x00, 0x20]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]); // Length = 8
                buf.push(0x00); // Reserved
                buf.push(0x01); // IPv4 family

                // XOR port with magic cookie upper 16 bits
                let xor_port = v4.port() ^ 0x2112;
                buf.extend_from_slice(&xor_port.to_be_bytes());

                // XOR address with magic cookie
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

                // XOR port with magic cookie upper 16 bits
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

    /// Append XOR-RELAYED-ADDRESS attribute
    fn append_xor_relayed_address(
        &self,
        buf: &mut Vec<u8>,
        addr: SocketAddr,
        transaction_id: &[u8; 12],
    ) {
        // Attribute type: 0x0016
        buf.extend_from_slice(&[0x00, 0x16]);

        match addr {
            SocketAddr::V4(v4) => {
                buf.extend_from_slice(&[0x00, 0x08]);
                buf.push(0x00);
                buf.push(0x01);

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

    /// Append LIFETIME attribute
    fn append_lifetime(&self, buf: &mut Vec<u8>, lifetime: u32) {
        buf.extend_from_slice(&[0x00, 0x0d]); // Type
        buf.extend_from_slice(&[0x00, 0x04]); // Length
        buf.extend_from_slice(&lifetime.to_be_bytes());
    }

    /// Build a 401 Unauthorized response with REALM and NONCE
    fn build_unauthorized_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(128);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009) - 401 Unauthorized
        let reason = "Unauthorized";
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push(4); // Class (401 / 100)
        response.push(1); // Number (401 % 100)
        response.extend_from_slice(reason.as_bytes());

        // Padding for ERROR-CODE (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // REALM attribute
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute
        let nonce = TurnAuth::generate_nonce(&self.config.nonce_secret);
        self.append_nonce(&mut response, &nonce);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Build a 438 Stale Nonce response with REALM and fresh NONCE
    ///
    /// Per RFC 5389, 438 responses must include REALM and NONCE so clients
    /// can retry with the new nonce.
    fn build_stale_nonce_response(&self, request: &StunInfo) -> Vec<u8> {
        let mut response = Vec::with_capacity(128);

        // Error response: set bits 4 and 8 of method
        let msg_type = u16::from_be_bytes([request.raw[0], request.raw[1]]);
        let error_type = msg_type | 0x0110;

        response.extend_from_slice(&error_type.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Length placeholder
        response.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request.transaction_id);

        // ERROR-CODE attribute (0x0009) - 438 Stale Nonce
        let reason = "Stale Nonce";
        let attr_len = 4 + reason.len();
        let padded_len = (attr_len + 3) & !3;

        response.extend_from_slice(&[0x00, 0x09]); // Type
        response.extend_from_slice(&(attr_len as u16).to_be_bytes());
        response.extend_from_slice(&[0x00, 0x00]); // Reserved
        response.push(4); // Class (438 / 100)
        response.push(38); // Number (438 % 100)
        response.extend_from_slice(reason.as_bytes());

        // Padding for ERROR-CODE (20 byte header + 4 byte attr header + padded value)
        while response.len() < 20 + 4 + padded_len {
            response.push(0);
        }

        // REALM attribute - required for client to retry
        self.append_realm(&mut response, &self.config.realm);

        // NONCE attribute - fresh nonce for client to use
        let nonce = TurnAuth::generate_nonce(&self.config.nonce_secret);
        self.append_nonce(&mut response, &nonce);

        // Update length
        let attr_len = (response.len() - 20) as u16;
        response[2..4].copy_from_slice(&attr_len.to_be_bytes());

        response
    }

    /// Append REALM attribute (0x0014)
    fn append_realm(&self, buf: &mut Vec<u8>, realm: &str) {
        let realm_bytes = realm.as_bytes();
        let padded_len = (realm_bytes.len() + 3) & !3;

        buf.extend_from_slice(&[0x00, 0x14]); // Type
        buf.extend_from_slice(&(realm_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(realm_bytes);

        // Padding
        for _ in realm_bytes.len()..padded_len {
            buf.push(0);
        }
    }

    /// Append NONCE attribute (0x0015)
    fn append_nonce(&self, buf: &mut Vec<u8>, nonce: &str) {
        let nonce_bytes = nonce.as_bytes();
        let padded_len = (nonce_bytes.len() + 3) & !3;

        buf.extend_from_slice(&[0x00, 0x15]); // Type
        buf.extend_from_slice(&(nonce_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(nonce_bytes);

        // Padding
        for _ in nonce_bytes.len()..padded_len {
            buf.push(0);
        }
    }

    /// Append MESSAGE-INTEGRITY attribute (0x0008)
    fn append_message_integrity(&self, buf: &mut Vec<u8>, key: &[u8; 16]) {
        // First, update the length to include MESSAGE-INTEGRITY (24 bytes: 4 header + 20 HMAC)
        let new_len = (buf.len() - 20 + 24) as u16;
        buf[2..4].copy_from_slice(&new_len.to_be_bytes());

        // Compute HMAC-SHA1 over message up to this point
        let integrity = TurnAuth::compute_message_integrity(buf, key);

        // Append MESSAGE-INTEGRITY attribute
        buf.extend_from_slice(&[0x00, 0x08]); // Type
        buf.extend_from_slice(&[0x00, 0x14]); // Length = 20
        buf.extend_from_slice(&integrity);
    }

    /// Build a TURN ChannelData message (RFC 5766 §11.4)
    fn build_channel_data(&self, channel: u16, data: &[u8]) -> Vec<u8> {
        let padding = (4 - ((4 + data.len()) % 4)) % 4;
        let mut packet = Vec::with_capacity(4 + data.len() + padding);
        packet.extend_from_slice(&channel.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
        packet.resize(packet.len() + padding, 0);
        packet
    }

    /// Build a TURN Data Indication
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

        // Pad DATA attribute
        while (packet.len() - 20) % 4 != 0 {
            packet.push(0);
        }

        // Update length
        let msg_len = (packet.len() - 20) as u16;
        packet[2..4].copy_from_slice(&msg_len.to_be_bytes());

        packet
    }

    /// Append XOR-PEER-ADDRESS attribute (0x0012)
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
    use super::is_forbidden_peer_ip;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn forbidden_ipv4_loopback() {
        assert!(is_forbidden_peer_ip(ip("127.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("127.0.0.2")));
        assert!(is_forbidden_peer_ip(ip("127.255.255.254")));
    }

    #[test]
    fn forbidden_ipv4_multicast_and_broadcast() {
        assert!(is_forbidden_peer_ip(ip("224.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("239.255.255.255")));
        assert!(is_forbidden_peer_ip(ip("255.255.255.255")));
    }

    #[test]
    fn forbidden_ipv4_unspecified() {
        assert!(is_forbidden_peer_ip(ip("0.0.0.0")));
    }

    #[test]
    fn forbidden_ipv4_link_local_covers_cloud_metadata() {
        // AWS/GCE/Azure instance metadata: 169.254.169.254
        assert!(is_forbidden_peer_ip(ip("169.254.169.254")));
        assert!(is_forbidden_peer_ip(ip("169.254.0.1")));
    }

    #[test]
    fn forbidden_ipv6_loopback_and_multicast_and_unspecified() {
        assert!(is_forbidden_peer_ip(ip("::1")));
        assert!(is_forbidden_peer_ip(ip("ff02::1")));
        assert!(is_forbidden_peer_ip(ip("::")));
    }

    #[test]
    fn forbidden_ipv4_mapped_ipv6_judged_by_ipv4_rules() {
        assert!(is_forbidden_peer_ip(ip("::ffff:127.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("::ffff:169.254.169.254")));
        assert!(is_forbidden_peer_ip(ip("::ffff:224.0.0.1")));
        assert!(is_forbidden_peer_ip(ip("::ffff:0.0.0.0")));
        // Mapped global unicast stays allowed.
        assert!(!is_forbidden_peer_ip(ip("::ffff:203.0.113.5")));
    }

    #[test]
    fn forbidden_ipv6_unicast_link_local() {
        assert!(is_forbidden_peer_ip(ip("fe80::1")));
        assert!(is_forbidden_peer_ip(ip("febf::1")));
        // fec0::/10 (deprecated site-local) is not link-local.
        assert!(!is_forbidden_peer_ip(ip("fec0::1")));
    }

    #[test]
    fn forbidden_peer_addr_blocks_own_external_ip_on_other_ports() {
        use super::is_forbidden_peer_addr;
        use crate::config::Config;
        let cfg = Config::new(ip("203.0.113.10")).with_port(3478);
        let sa = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        // Relay address itself is the legitimate single-port target.
        assert!(!is_forbidden_peer_addr(&cfg, sa("203.0.113.10:3478")));
        // Any other port on the relay host is refused.
        assert!(is_forbidden_peer_addr(&cfg, sa("203.0.113.10:53")));
        assert!(is_forbidden_peer_addr(&cfg, sa("203.0.113.10:3479")));
        // IP-level rules still apply.
        assert!(is_forbidden_peer_addr(&cfg, sa("127.0.0.1:3478")));
        // Unrelated hosts are fine on any port.
        assert!(!is_forbidden_peer_addr(&cfg, sa("203.0.113.11:53")));
    }

    #[test]
    fn forbidden_peer_addr_respects_allowed_peers() {
        use super::is_forbidden_peer_addr;
        use crate::config::Config;
        let sa = |s: &str| s.parse::<std::net::SocketAddr>().unwrap();
        let cfg = Config::new(ip("203.0.113.10"))
            .with_port(3478)
            .with_allowed_peer(sa("203.0.113.10:30029"))
            .with_allowed_peer(sa("127.0.0.1:30029"));
        // The listed port on our own external IP is allowed...
        assert!(!is_forbidden_peer_addr(&cfg, sa("203.0.113.10:30029")));
        // ...but only that exact port.
        assert!(is_forbidden_peer_addr(&cfg, sa("203.0.113.10:30030")));
        assert!(is_forbidden_peer_addr(&cfg, sa("203.0.113.10:53")));
        // The relay address itself is still fine.
        assert!(!is_forbidden_peer_addr(&cfg, sa("203.0.113.10:3478")));
        // The allow-list never overrides the IP-level rules.
        assert!(is_forbidden_peer_addr(&cfg, sa("127.0.0.1:30029")));
    }

    #[test]
    fn allowed_global_unicast_not_forbidden() {
        assert!(!is_forbidden_peer_ip(ip("8.8.8.8")));
        assert!(!is_forbidden_peer_ip(ip("203.0.113.5"))); // TEST-NET-3
        assert!(!is_forbidden_peer_ip(ip("2001:db8::1")));
    }

    // ---- helpers for the handler-level tests below -------------------------

    use super::{
        AllocationTable, Config, RateLimiter, SendTarget, StunClass, StunInfo, StunMethod,
        TurnAuth, TurnErrorCode, TurnHandler,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;

    const RELAY_IP: &str = "203.0.113.10";
    const RELAY_PORT: u16 = 3478;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Handler over an anonymous (no credentials) config, so the tests exercise
    /// the request logic rather than the authentication path.
    fn handler() -> (TurnHandler, Arc<AllocationTable>) {
        let config = Arc::new(Config::new(ip(RELAY_IP)).with_port(RELAY_PORT));
        let allocations = Arc::new(AllocationTable::new());
        let rate_limiter = Arc::new(RateLimiter::new(120, 100));
        (
            TurnHandler::new(config, Arc::clone(&allocations), rate_limiter),
            allocations,
        )
    }

    /// Minimal parsed request. Attributes are set by the caller; only `raw`'s
    /// message type and transaction id matter for building a response.
    fn request(method: StunMethod, msg_type: u16) -> StunInfo {
        let transaction_id = [7u8; 12];
        let mut raw = Vec::with_capacity(20);
        raw.extend_from_slice(&msg_type.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x00]);
        raw.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        raw.extend_from_slice(&transaction_id);
        StunInfo {
            class: StunClass::Request,
            method,
            transaction_id,
            username: None,
            xor_peer_addresses: Vec::new(),
            channel_number: None,
            lifetime: None,
            data: None,
            realm: None,
            nonce: None,
            message_integrity: None,
            message_integrity_offset: None,
            requested_transport: None,
            raw: raw.into(),
        }
    }

    // ---- error responses ----------------------------------------------------

    #[test]
    fn signed_error_response_carries_verifiable_message_integrity() {
        // RFC 5389 §10.2.3: a client that authenticated discards an error
        // response without MESSAGE-INTEGRITY (except 400/401/438), so a 437 has
        // to be signed or the client just retransmits until it times out.
        let (h, _) = handler();
        let msg = request(StunMethod::Allocate, 0x0003);
        let key = TurnAuth::compute_key("user", "uturn", "pass");

        let resp =
            h.build_signed_error_response(&msg, TurnErrorCode::AllocationMismatch, Some(&key));

        // Header length covers everything after the 20-byte header.
        let declared = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(declared, resp.len() - 20);

        // MESSAGE-INTEGRITY is the trailing 24-byte attribute (4 + 20).
        let mi_start = resp.len() - 24;
        assert_eq!(&resp[mi_start..mi_start + 2], &[0x00, 0x08]);
        assert_eq!(&resp[mi_start + 2..mi_start + 4], &[0x00, 0x14]);
        assert!(TurnAuth::verify_message_integrity(
            &resp[..mi_start],
            &resp[mi_start + 4..],
            &key
        ));

        // ERROR-CODE still says 437.
        assert_eq!(&resp[20..22], &[0x00, 0x09]);
        assert_eq!(resp[24 + 2], 4);
        assert_eq!(resp[24 + 3], 37);
    }

    #[test]
    fn unsigned_error_response_has_no_message_integrity() {
        let (h, _) = handler();
        let msg = request(StunMethod::Allocate, 0x0003);
        let resp = h.build_error_response(&msg, TurnErrorCode::AllocationMismatch);
        let declared = u16::from_be_bytes([resp[2], resp[3]]) as usize;
        assert_eq!(declared, resp.len() - 20);

        // Same message, 24 bytes shorter than the signed one, and its trailing
        // attribute is the ERROR-CODE rather than a MESSAGE-INTEGRITY.
        let key = TurnAuth::compute_key("user", "uturn", "pass");
        let signed =
            h.build_signed_error_response(&msg, TurnErrorCode::AllocationMismatch, Some(&key));
        assert_eq!(signed.len(), resp.len() + 24);
        assert_eq!(&resp[20..22], &[0x00, 0x09]);
        let attr_len = u16::from_be_bytes([resp[22], resp[23]]) as usize;
        assert_eq!(resp.len(), 20 + 4 + attr_len.div_ceil(4) * 4);
    }

    // ---- ChannelBind --------------------------------------------------------

    #[tokio::test]
    async fn channel_bind_conflict_installs_no_permission() {
        // RFC 5766 §11.2: an error response must leave the allocation unchanged.
        // The permission implied by ChannelBind used to be installed before the
        // binding was validated, so a client could fill its permission table
        // with IPs through requests the server went on to reject with 400.
        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40001");
        let id = table.create(client, "u".to_string(), 600);

        let peer_a = sa("203.0.113.20:5000");
        let peer_b = sa("203.0.113.21:5000");

        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![peer_a];
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer_a));
        assert_eq!(alloc.permissions_count(), 1);
        drop(alloc);

        // Same channel, different peer -> 400, and no trace of peer_b.
        bind.xor_peer_addresses = vec![peer_b];
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer_a));
        assert_eq!(alloc.channel_for_peer(peer_b), None);
        assert!(!alloc.is_permitted(peer_b.ip()));
        assert_eq!(alloc.permissions_count(), 1);
    }

    #[tokio::test]
    async fn channel_bind_refresh_of_same_pair_is_idempotent() {
        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40002");
        let id = table.create(client, "u".to_string(), 600);

        let peer = sa("203.0.113.20:5000");
        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![peer];

        h.handle_channel_bind(&bind, client, &socket).await.unwrap();
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer));
        assert_eq!(alloc.channels_count(), 1);
        assert_eq!(alloc.permissions_count(), 1);
    }

    #[tokio::test]
    async fn channel_bind_refresh_extends_lifetime() {
        // RFC 5766 §11: a ChannelBind for an existing same channel/peer pair
        // must refresh the ~10 min lifetime. Regression: the handler used to
        // set needs_bind=false and skip bind_channel(), so expires_ms never
        // moved and a lapsed-then-refreshed binding stayed dead.
        use crate::coarse_time::coarse_now_ms;
        use std::sync::atomic::Ordering;

        crate::coarse_time::init();

        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40003");
        let id = table.create(client, "u".to_string(), 600);

        let peer = sa("203.0.113.21:5000");
        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![peer];

        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        // Near the end of its lifetime, as when a client refreshes it, without
        // waiting 10 minutes. Still live.
        {
            let alloc = table.get(id).unwrap();
            alloc
                .channels
                .get(&0x4000)
                .expect("channel bound")
                .expires_ms
                .store(coarse_now_ms() + 1_000, Ordering::Relaxed);
            assert_eq!(
                alloc.peer_for_channel(0x4000),
                Some(peer),
                "binding must still be live before the refresh"
            );
        }

        // Refresh via the handler path (same pair).
        h.handle_channel_bind(&bind, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        assert_eq!(
            alloc.peer_for_channel(0x4000),
            Some(peer),
            "binding must stay bound after the refresh"
        );
        let expires = alloc
            .channels
            .get(&0x4000)
            .expect("channel still bound")
            .expires_ms
            .load(Ordering::Relaxed);
        let now = coarse_now_ms();
        assert!(
            expires > now,
            "refreshed binding must be in the future (expires={expires}, now={now})"
        );
        // Full 10-minute grant, allow a few seconds of skew for the coarse clock.
        assert!(
            expires >= now + 600_000 - 5_000,
            "lifetime not extended toward 10 min: expires={expires}, now={now}"
        );
        assert_eq!(alloc.channels_count(), 1);
    }

    // ---- authenticated requests --------------------------------------------

    const USER: &str = "user";
    const PASS: &str = "pass";

    /// Handler with one static credential configured, plus the key that user
    /// signs with. Responses to its requests must carry MESSAGE-INTEGRITY.
    fn auth_handler() -> (TurnHandler, Arc<AllocationTable>, Arc<Config>, [u8; 16]) {
        let config = Arc::new(
            Config::new(ip(RELAY_IP))
                .with_port(RELAY_PORT)
                .with_credential(USER, PASS),
        );
        let allocations = Arc::new(AllocationTable::new());
        let rate_limiter = Arc::new(RateLimiter::new(120, 100));
        let key = TurnAuth::compute_key(USER, &config.realm, PASS);
        (
            TurnHandler::new(Arc::clone(&config), Arc::clone(&allocations), rate_limiter),
            allocations,
            config,
            key,
        )
    }

    /// Add the credential attributes and a MESSAGE-INTEGRITY over `raw`, the way
    /// a client would. `raw` holds only the header, which is all the server
    /// hashes here; the parsed attributes are set as fields.
    fn sign(msg: StunInfo, config: &Config, key: &[u8; 16]) -> StunInfo {
        sign_as(msg, USER, config, key)
    }

    /// `sign` for an arbitrary username.
    fn sign_as(mut msg: StunInfo, user: &str, config: &Config, key: &[u8; 16]) -> StunInfo {
        msg.username = Some(user.to_string());
        msg.realm = Some(config.realm.clone());
        msg.nonce = Some(TurnAuth::generate_nonce(&config.nonce_secret));

        let offset = msg.raw.len();
        let hashed_len = (offset - 20 + 24) as u16;
        let mut raw = msg.raw.to_vec();
        raw[2..4].copy_from_slice(&hashed_len.to_be_bytes());
        let mi = TurnAuth::compute_message_integrity(&raw, key);
        raw.extend_from_slice(&[0x00, 0x08, 0x00, 0x14]);
        raw.extend_from_slice(&mi);
        msg.raw = raw.into();
        msg.message_integrity = Some(mi.to_vec());
        msg.message_integrity_offset = Some(offset);
        msg
    }

    /// Bind a socket for the server and one standing in for the client, and
    /// return the client's address so responses can be read back.
    async fn socket_pair() -> (tokio::net::UdpSocket, tokio::net::UdpSocket, SocketAddr) {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        (server, client, client_addr)
    }

    /// Read one response, asserting it arrives.
    async fn recv(client: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("no response sent")
        .unwrap()
        .0;
        buf.truncate(n);
        buf
    }

    fn error_code(resp: &[u8]) -> (u8, u8) {
        assert_eq!(
            &resp[20..22],
            &[0x00, 0x09],
            "first attribute is ERROR-CODE"
        );
        (resp[26], resp[27])
    }

    fn assert_signed_with(resp: &[u8], key: &[u8; 16]) {
        let mi_start = resp.len() - 24;
        assert_eq!(
            &resp[mi_start..mi_start + 4],
            &[0x00, 0x08, 0x00, 0x14],
            "response ends in a MESSAGE-INTEGRITY attribute"
        );
        assert!(
            TurnAuth::verify_message_integrity(&resp[..mi_start], &resp[mi_start + 4..], key),
            "MESSAGE-INTEGRITY verifies"
        );
    }

    #[tokio::test]
    async fn refresh_without_allocation_returns_signed_437() {
        // Allocations live at most 60s, so a client that loses one Refresh gets
        // this 437 on its next one. Unsigned, an authenticated client discards
        // it (RFC 5389 §10.2.3) and retransmits for ~39.5s instead of
        // reallocating - which is why authentication runs before the lookup.
        let (h, _table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;

        let msg = sign(request(StunMethod::Refresh, 0x0004), &config, &key);
        h.handle_refresh(&msg, client_addr, &server).await.unwrap();

        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x14], "Refresh error response");
        assert_eq!(error_code(&resp), (4, 37));
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn channel_bind_forbidden_peer_returns_signed_403() {
        let (h, table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create(client_addr, USER.to_string(), 600);

        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![sa("127.0.0.1:1234")];
        let bind = sign(bind, &config, &key);
        h.handle_channel_bind(&bind, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 3));
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn create_permission_forbidden_peer_returns_signed_403() {
        let (h, table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create(client_addr, USER.to_string(), 600);

        let mut perm = request(StunMethod::CreatePermission, 0x0008);
        perm.xor_peer_addresses = vec![sa("169.254.169.254:80")];
        let perm = sign(perm, &config, &key);
        h.handle_create_permission(&perm, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 3));
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn request_for_another_users_allocation_is_rejected() {
        // RFC 5766 §10.1: post-Allocate requests carry the same credentials as
        // the Allocate did. Moving auth ahead of the lookup must not lose that.
        let (h, table, config, key) = auth_handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create(client_addr, "someone-else".to_string(), 600);

        let msg = sign(request(StunMethod::Refresh, 0x0004), &config, &key);
        h.handle_refresh(&msg, client_addr, &server).await.unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 1), "401 Unauthorized");
    }

    // ---- TURN REST API (shared secret) credentials ---------------------------

    const SECRET: &str = "example-secret";

    /// Handler configured with REST API secrets only - no static `--user`.
    fn secret_handler(secrets: &[&str]) -> (TurnHandler, Arc<AllocationTable>, Arc<Config>) {
        let mut cfg = Config::new(ip(RELAY_IP)).with_port(RELAY_PORT);
        for secret in secrets {
            cfg = cfg.with_auth_secret(*secret);
        }
        let config = Arc::new(cfg);
        let allocations = Arc::new(AllocationTable::new());
        let rate_limiter = Arc::new(RateLimiter::new(120, 100));
        (
            TurnHandler::new(Arc::clone(&config), Arc::clone(&allocations), rate_limiter),
            allocations,
            config,
        )
    }

    /// REST API username expiring `offset_secs` from now, and its key under `secret`.
    fn ephemeral(config: &Config, secret: &str, offset_secs: i64) -> (String, [u8; 16]) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let user = format!("{}:alice", now + offset_secs);
        let password = TurnAuth::ephemeral_password(secret, &user);
        let key = TurnAuth::compute_key(&user, &config.realm, &password);
        (user, key)
    }

    fn allocate_request() -> StunInfo {
        let mut alloc = request(StunMethod::Allocate, 0x0003);
        alloc.requested_transport = Some(17);
        alloc
    }

    #[tokio::test]
    async fn allocate_with_ephemeral_credentials_succeeds() {
        let (h, table, config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;
        let (user, key) = ephemeral(&config, SECRET, 3600);

        let msg = sign_as(allocate_request(), &user, &config, &key);
        h.handle_allocate(&msg, client_addr, &server).await.unwrap();

        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x03], "Allocate success response");
        assert_signed_with(&resp, &key);
        assert_eq!(table.get_by_client(client_addr).unwrap().username, user);
    }

    #[tokio::test]
    async fn allocate_with_expired_ephemeral_credentials_is_401() {
        let (h, table, config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;
        let (user, key) = ephemeral(&config, SECRET, -1);

        let msg = sign_as(allocate_request(), &user, &config, &key);
        h.handle_allocate(&msg, client_addr, &server).await.unwrap();

        assert_eq!(error_code(&recv(&client).await), (4, 1));
        assert!(table.get_by_client(client_addr).is_none());
    }

    #[tokio::test]
    async fn allocate_signed_with_wrong_secret_is_401() {
        let (h, table, config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;
        let (user, key) = ephemeral(&config, "not-the-secret", 3600);

        let msg = sign_as(allocate_request(), &user, &config, &key);
        h.handle_allocate(&msg, client_addr, &server).await.unwrap();

        assert_eq!(error_code(&recv(&client).await), (4, 1));
        assert!(table.get_by_client(client_addr).is_none());
    }

    #[tokio::test]
    async fn secret_only_config_is_not_anonymous() {
        // With no static users the relay must still challenge: a secret alone
        // must not fall through to anonymous mode.
        let (h, table, _config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;

        h.handle_allocate(&allocate_request(), client_addr, &server)
            .await
            .unwrap();

        assert_eq!(error_code(&recv(&client).await), (4, 1));
        assert!(table.get_by_client(client_addr).is_none());
    }

    #[tokio::test]
    async fn rotated_secrets_are_both_accepted() {
        let (h, _table, config) = secret_handler(&["old-secret", "new-secret"]);
        for (n, secret) in ["old-secret", "new-secret"].into_iter().enumerate() {
            let (server, client, client_addr) = socket_pair().await;
            let (user, key) = ephemeral(&config, secret, 3600 + n as i64);

            let msg = sign_as(allocate_request(), &user, &config, &key);
            h.handle_allocate(&msg, client_addr, &server).await.unwrap();

            let resp = recv(&client).await;
            assert_eq!(&resp[0..2], &[0x01, 0x03], "{secret} accepted");
            assert_signed_with(&resp, &key);
        }
    }

    #[tokio::test]
    async fn refresh_after_ephemeral_expiry_is_401() {
        // Credentials are checked on every request, so an allocation cannot be
        // kept alive past the credential's expiry.
        let (h, table, config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;
        let (user, key) = ephemeral(&config, SECRET, -1);
        table.create(client_addr, user.clone(), 600);

        let msg = sign_as(request(StunMethod::Refresh, 0x0004), &user, &config, &key);
        h.handle_refresh(&msg, client_addr, &server).await.unwrap();

        assert_eq!(error_code(&recv(&client).await), (4, 1));
        assert!(
            table.get_by_client(client_addr).is_some(),
            "the allocation runs to its own lifetime"
        );
    }

    #[tokio::test]
    async fn refresh_and_channel_bind_with_valid_ephemeral_credentials() {
        let (h, table, config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;
        let (user, key) = ephemeral(&config, SECRET, 3600);
        table.create(client_addr, user.clone(), 600);

        let msg = sign_as(request(StunMethod::Refresh, 0x0004), &user, &config, &key);
        h.handle_refresh(&msg, client_addr, &server).await.unwrap();
        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x04], "Refresh success response");
        assert_signed_with(&resp, &key);

        let mut bind = request(StunMethod::ChannelBind, 0x0009);
        bind.channel_number = Some(0x4000);
        bind.xor_peer_addresses = vec![sa("198.51.100.7:5000")];
        let bind = sign_as(bind, &user, &config, &key);
        h.handle_channel_bind(&bind, client_addr, &server)
            .await
            .unwrap();
        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x09], "ChannelBind success response");
        assert_signed_with(&resp, &key);
    }

    #[tokio::test]
    async fn static_and_ephemeral_users_both_allocate() {
        let config = Arc::new(
            Config::new(ip(RELAY_IP))
                .with_port(RELAY_PORT)
                .with_credential(USER, PASS)
                .with_auth_secret(SECRET),
        );
        let table = Arc::new(AllocationTable::new());
        let h = TurnHandler::new(
            Arc::clone(&config),
            Arc::clone(&table),
            Arc::new(RateLimiter::new(120, 100)),
        );
        let static_key = TurnAuth::compute_key(USER, &config.realm, PASS);
        let (user, ephemeral_key) = ephemeral(&config, SECRET, 3600);

        for (user, key) in [(USER, static_key), (user.as_str(), ephemeral_key)] {
            let (server, client, client_addr) = socket_pair().await;
            let msg = sign_as(allocate_request(), user, &config, &key);
            h.handle_allocate(&msg, client_addr, &server).await.unwrap();

            let resp = recv(&client).await;
            assert_eq!(&resp[0..2], &[0x01, 0x03], "{user} allocates");
            assert_signed_with(&resp, &key);
            assert_eq!(table.get_by_client(client_addr).unwrap().username, user);
        }
    }

    #[tokio::test]
    async fn stale_nonce_is_438_before_any_password_derivation() {
        // Ordering guard: an expired REST username yields no candidate
        // passwords, so if derivation ran before the nonce check this would be
        // a 401. 438 shows the bogus nonce is rejected first, without any HMAC.
        let (h, _table, config) = secret_handler(&[SECRET]);
        let (server, client, client_addr) = socket_pair().await;
        let (user, key) = ephemeral(&config, SECRET, -1);

        let mut msg = sign_as(allocate_request(), &user, &config, &key);
        msg.nonce = Some("0000000000000001:0000000000000000".to_string());
        h.handle_allocate(&msg, client_addr, &server).await.unwrap();

        assert_eq!(error_code(&recv(&client).await), (4, 38));
    }

    // ---- Allocate over a lapsed allocation ----------------------------------

    #[tokio::test]
    async fn allocate_over_expired_allocation_starts_fresh() {
        // cleanup_expired runs every 2s, so a client that lets its allocation
        // lapse and reconnects usually finds the dead entry still in the table.
        // 437 there would lock it out of the port until the reaper catches up.
        let (h, table) = handler();
        let (server, client, client_addr) = socket_pair().await;

        // The coarse clock only moves when the server ticks it, so drive it by
        // hand: allocate with a zero lifetime, then step past the expiry.
        crate::coarse_time::init();
        let dead = table.create(client_addr, "u".to_string(), 0);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        crate::coarse_time::update_coarse_time();
        assert!(table.get(dead).unwrap().is_expired());

        let mut alloc = request(StunMethod::Allocate, 0x0003);
        alloc.requested_transport = Some(17);
        h.handle_allocate(&alloc, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(&resp[0..2], &[0x01, 0x03], "Allocate success response");
        assert!(table.get(dead).is_none(), "the lapsed allocation is gone");
        let fresh = table.get_by_client(client_addr).expect("a new allocation");
        assert!(!fresh.is_expired());
    }

    #[tokio::test]
    async fn allocate_with_new_transaction_id_over_live_allocation_is_437() {
        let (h, table) = handler();
        let (server, client, client_addr) = socket_pair().await;
        table.create_or_get(client_addr, "u".to_string(), 600, [1u8; 12]);

        let mut alloc = request(StunMethod::Allocate, 0x0003);
        alloc.requested_transport = Some(17);
        h.handle_allocate(&alloc, client_addr, &server)
            .await
            .unwrap();

        let resp = recv(&client).await;
        assert_eq!(error_code(&resp), (4, 37));
    }

    // ---- Send indication ----------------------------------------------------

    #[test]
    fn send_to_turn_client_without_relay_permission_is_dropped() {
        // RFC 5766 §10.3: peer data must not be relayed to a client that has no
        // matching permission. A Send indication aimed at another client of this
        // server is delivered *into* that client's allocation as a Data
        // Indication, so the target's permissions apply too - the sender's
        // permission for the target's IP (which nothing restricts a client from
        // creating) only covers the sender's half. Without this, any client
        // could inject application data into any other client's allocation and
        // keep it alive indefinitely with the accompanying touch.
        let (h, table) = handler();
        let attacker = sa("198.51.100.5:50000");
        let victim = sa("198.51.100.9:50001");
        table.create(attacker, "attacker".to_string(), 600);
        let victim_id = table.create(victim, "victim".to_string(), 600);

        // The victim never permitted the relay IP.
        assert_eq!(
            h.classify_send_target(attacker, victim),
            SendTarget::Drop,
            "unpermitted TURN client must not be handed peer data"
        );

        // Once it does, the normal client-to-client path is available again.
        table.get(victim_id).unwrap().add_permission(ip(RELAY_IP));
        assert_eq!(
            h.classify_send_target(attacker, victim),
            SendTarget::Local {
                id: victim_id,
                reverse_channel: None,
            }
        );
    }

    #[test]
    fn send_to_self_is_dropped() {
        let (h, table) = handler();
        let client = sa("198.51.100.5:50000");
        let id = table.create(client, "u".to_string(), 600);
        table.get(id).unwrap().add_permission(ip(RELAY_IP));

        // Even a fully permitted client must not get its own payload bounced
        // back to it as a well-formed Data Indication.
        assert_eq!(h.classify_send_target(client, client), SendTarget::Drop);
    }

    #[test]
    fn send_to_non_client_peer_is_forwarded_raw() {
        // The external-peer path is unaffected by the permission gate above.
        let (h, table) = handler();
        let client = sa("198.51.100.5:50000");
        table.create(client, "u".to_string(), 600);

        assert_eq!(
            h.classify_send_target(client, sa("203.0.113.77:9000")),
            SendTarget::External
        );
    }

    #[test]
    fn send_to_turn_client_uses_its_reverse_channel() {
        let (h, table) = handler();
        let a = sa("198.51.100.5:50000");
        let b = sa("198.51.100.9:50001");
        table.create(a, "a".to_string(), 600);
        let b_id = table.create(b, "b".to_string(), 600);
        {
            let b_alloc = table.get(b_id).unwrap();
            b_alloc.add_permission(ip(RELAY_IP));
            b_alloc.bind_channel(0x4004, a);
        }

        assert_eq!(
            h.classify_send_target(a, b),
            SendTarget::Local {
                id: b_id,
                reverse_channel: Some(0x4004),
            }
        );
    }

    /// Assert nothing is delivered to `sock` within a short window.
    async fn assert_silent(sock: &tokio::net::UdpSocket, who: &str) {
        let mut buf = vec![0u8; 1500];
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            sock.recv_from(&mut buf),
        )
        .await;
        assert!(
            got.is_err(),
            "{} received {} bytes it was not addressed in",
            who,
            got.map(|r| r.unwrap().0).unwrap_or(0)
        );
    }

    /// An allocation permitted for the relay IP that never registers an ICE
    /// ufrag. Nothing ages it out (Refresh feeds `is_inactive`, and
    /// `is_orphaned_sender` stays false while it sends nothing), so this is a
    /// posture an attacker can hold indefinitely. It must never be delivered
    /// traffic addressed to somebody else.
    async fn bystander(table: &AllocationTable) -> tokio::net::UdpSocket {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let id = table.create(sock.local_addr().unwrap(), "u".to_string(), 600);
        table.add_permission(id, ip(RELAY_IP));
        sock
    }

    #[tokio::test]
    async fn binding_request_reaches_only_the_addressed_peer() {
        let (h, table) = handler();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let onlooker = bystander(&table).await;

        let sender = sa("127.0.0.1:40010");
        let sender_id = table.create(sender, "u".to_string(), 600);
        table.add_permission(sender_id, ip(RELAY_IP));
        table.register_ice_ufrags(sender_id, "AAAA".to_string(), "BBBB".to_string());

        let peer_id = table.create(peer_sock.local_addr().unwrap(), "u".to_string(), 600);
        table.add_permission(peer_id, ip(RELAY_IP));
        table.register_ice_ufrags(peer_id, "BBBB".to_string(), "AAAA".to_string());

        // USERNAME is "remoteUfrag:localUfrag" - addressed to BBBB.
        let mut req = request(StunMethod::Binding, 0x0001);
        req.username = Some("BBBB:AAAA".to_string());

        h.handle_binding_request(&req, sender, &server)
            .await
            .unwrap();

        // The addressed peer gets it...
        let delivered = recv(&peer_sock).await;
        assert!(!delivered.is_empty());
        // ...and nobody else does. A leaked USERNAME hands over both ufrags of
        // this call, which is enough to claim BBBB and hijack the routing.
        assert_silent(&onlooker, "unpaired onlooker").await;
    }

    #[tokio::test]
    async fn binding_request_for_an_unregistered_ufrag_is_dropped() {
        let (h, table) = handler();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let onlooker = bystander(&table).await;

        let sender = sa("127.0.0.1:40011");
        let sender_id = table.create(sender, "u".to_string(), 600);
        table.add_permission(sender_id, ip(RELAY_IP));

        // The peer has not allocated yet - the common case for the first check
        // of a call. STUN retransmits, so dropping loses nothing.
        let mut req = request(StunMethod::Binding, 0x0001);
        req.username = Some("NOTHERE:AAAA".to_string());

        h.handle_binding_request(&req, sender, &server)
            .await
            .unwrap();

        assert_silent(&onlooker, "unpaired onlooker").await;
    }

    #[tokio::test]
    async fn send_indication_without_a_ufrag_match_is_dropped_not_broadcast() {
        let (h, table) = handler();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let onlooker = bystander(&table).await;

        let sender = sa("127.0.0.1:40012");
        let sender_id = table.create(sender, "u".to_string(), 600);
        table.add_permission(sender_id, ip(RELAY_IP));

        let mut send = request(StunMethod::Send, 0x0006);
        send.class = StunClass::Indication;
        send.xor_peer_addresses = vec![sa(&format!("{}:{}", RELAY_IP, RELAY_PORT))];
        // Not STUN, and the sender has no ufrags registered: nothing matches.
        send.data = Some(vec![0xde, 0xad, 0xbe, 0xef]);

        h.handle_send(&send, sender, &server).await.unwrap();

        assert_silent(&onlooker, "unpaired onlooker").await;
    }

    #[tokio::test]
    async fn send_indication_without_target_does_not_arm_orphan_timer() {
        // Internal routing runs during ICE, before a peer exists. Arming the
        // orphan-sender timer here would have cleanup_orphaned_senders reap the
        // allocation of whoever joins the call first, 45s later, while it is
        // still actively sending and refreshing.
        let (h, table) = handler();
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = sa("127.0.0.1:40003");
        let id = table.create(client, "u".to_string(), 600);
        table.add_permission(id, ip(RELAY_IP));

        let mut send = request(StunMethod::Send, 0x0006);
        send.class = StunClass::Indication;
        send.xor_peer_addresses = vec![sa(&format!("{}:{}", RELAY_IP, RELAY_PORT))];
        // Not a STUN message, so the ICE-ufrag routing branch is skipped and
        // nothing matches: the payload is dropped.
        send.data = Some(vec![0xde, 0xad, 0xbe, 0xef]);

        h.handle_send(&send, client, &socket).await.unwrap();

        let alloc = table.get(id).unwrap();
        // A zero timeout would report any armed timer as orphaned.
        assert!(!alloc.is_orphaned_sender(0));
    }

    #[test]
    fn private_networks_not_forbidden_by_default() {
        // Policy call: private ranges are common in legit on-prem/lab
        // deployments. is_forbidden_peer_ip intentionally allows them.
        assert!(!is_forbidden_peer_ip(ip("10.0.0.1")));
        assert!(!is_forbidden_peer_ip(ip("192.168.1.1")));
        assert!(!is_forbidden_peer_ip(ip("172.16.0.1")));
        // CGNAT and IPv6 ULA are likewise allowed by default.
        assert!(!is_forbidden_peer_ip(ip("100.64.0.1")));
        assert!(!is_forbidden_peer_ip(ip("fc00::1")));
    }
}
