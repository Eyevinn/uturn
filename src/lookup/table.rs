//! Allocation lookup tables
//!
//! Multiple lookup paths for efficient packet routing:
//! - Source address (fast path for established flows)
//! - ICE username fragment (bi-directional matching)
//! - Peer tuple (IP:port)
//! - TURN channel ID

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::coarse_time::{coarse_now_ms, is_expired_secs};

/// Lifetime of a channel binding (RFC 5766 §11): 10 minutes, refreshed by a
/// ChannelBind for the same channel/peer pair.
pub const CHANNEL_LIFETIME_MS: u64 = 600_000;

/// Lifetime of a permission (RFC 5766 §9): 5 minutes, refreshed by a
/// CreatePermission (or ChannelBind, which also installs a permission) for the
/// same peer IP.
pub const PERMISSION_LIFETIME_MS: u64 = 300_000;

/// How long a STUN request a client sent to an external peer waits for the
/// peer's response. A retransmit of the request (same transaction id)
/// restarts it. Responses arrive within a round trip; this only has to
/// outlast one retransmit interval.
pub const PEER_TXN_LIFETIME_MS: u64 = 10_000;

/// Outstanding STUN requests to external peers per allocation. ICE paces
/// new checks at ~20/s and unanswered ones linger for the lifetime above
/// (reaped every cleanup tick), so this leaves headroom; it exists to stop
/// one client growing the table.
pub const MAX_PEER_TXNS_PER_ALLOC: usize = 256;

/// Unique allocation identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationId(u64);

impl AllocationId {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl std::fmt::Display for AllocationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "alloc-{}", self.0)
    }
}

/// TURN allocation state
#[derive(Debug)]
pub struct Allocation {
    pub id: AllocationId,

    /// Client's address (TURN control connection)
    pub client_addr: SocketAddr,

    /// Permitted peer IP addresses -> expiry (coarse ms). RFC 5766 §9.
    pub permissions: RwLock<HashMap<IpAddr, u64>>,

    /// Channel bindings: channel_id -> binding (peer address + expiry)
    pub channels: DashMap<u16, ChannelBinding>,

    /// Reverse channel lookup: peer_addr -> channel_id. Liveness is decided by
    /// the forward entry in `channels`; this map may briefly hold a lapsed
    /// channel number until `cleanup_expired_channels` reaps it.
    pub channels_reverse: DashMap<SocketAddr, u16>,

    /// Known peer addresses (learned from traffic)
    pub known_peers: DashMap<SocketAddr, PeerInfo>,

    /// Allocation expiry time (milliseconds since coarse_time init)
    expires_at_ms: AtomicU64,

    /// Allocation lifetime in seconds (for refresh calculations)
    lifetime_secs: AtomicU64,

    /// Last activity time (coarse timestamp, milliseconds since init)
    last_activity_ms: AtomicU64,

    /// Last time we received traffic FROM the client (coarse timestamp)
    /// Used for inactivity detection (client gone but sender still active)
    last_received_ms: AtomicU64,

    /// Last time we successfully relayed data (coarse timestamp)
    /// Used to detect senders with no recipients. 0 = never tried.
    last_successful_relay_ms: AtomicU64,

    /// Whether we've ever attempted a relay (for orphan detection)
    has_relay_attempt: std::sync::atomic::AtomicBool,

    /// Username for authentication
    pub username: String,

    /// Transaction id of the Allocate request that created this allocation.
    /// Used to tell a retransmitted Allocate (same id: resend success) from a
    /// new Allocate over an existing 5-tuple (437 Allocation Mismatch).
    pub allocate_txn_id: [u8; 12],

    /// This allocation's ICE ufrag (learned from STUN USERNAME attribute).
    /// Stored as Arc<str> so hot-path reads are a cheap refcount bump.
    pub ice_ufrag: RwLock<Option<Arc<str>>>,

    /// Remote ICE ufrag this allocation communicates with (from STUN USERNAME)
    pub ice_remote_ufrag: RwLock<Option<Arc<str>>>,

    /// Entries this allocation holds in `AllocationTable::peer_txns`, for
    /// the per-allocation cap.
    pending_peer_txns: AtomicUsize,

    /// (local, remote) ICE ufrags from this client's checks to external
    /// peers. Kept apart from `ice_ufrag`/`ice_remote_ufrag`, which route
    /// client-to-client traffic first-come-first-served.
    peer_ice_ufrags: RwLock<Option<(Arc<str>, Arc<str>)>>,
}

/// A STUN request a client sent to an external peer, awaiting its response.
#[derive(Debug)]
struct PendingPeerTxn {
    /// The sending allocation.
    id: AllocationId,
    /// Where the request went; only a response from this address matches.
    peer_addr: SocketAddr,
    /// Coarse-clock deadline after which the entry is dropped.
    expires_ms: u64,
}

/// A channel binding: the bound peer plus the deadline at which it lapses.
///
/// RFC 5766 §11 gives channel bindings a 10-minute lifetime, refreshed by a
/// ChannelBind for the same pair. Without expiry the §11.2 conflict rules
/// ("channel not bound to a different peer, peer not bound to a different
/// channel") would hold for the whole life of the allocation, and a client
/// that legitimately rebinds a peer to a new channel number - libwebrtc does
/// exactly this when a `TurnEntry` is torn down and recreated for the same
/// address after an ICE restart, having advanced its channel counter - would
/// get a permanent 400 for the rest of the call.
#[derive(Debug)]
pub struct ChannelBinding {
    /// Peer this channel is bound to.
    pub peer_addr: SocketAddr,
    /// Coarse-clock deadline; the binding is lapsed once `now >= expires_ms`.
    pub expires_ms: AtomicU64,
}

impl ChannelBinding {
    #[inline]
    fn is_live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_ms.load(Ordering::Relaxed)
    }
}

/// Information about a known peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// When we last saw traffic from this peer (coarse timestamp in ms)
    pub last_seen_ms: u64,
}

impl Allocation {
    /// Create a new allocation
    pub fn new(
        client_addr: SocketAddr,
        username: String,
        lifetime_secs: u32,
        allocate_txn_id: [u8; 12],
    ) -> Self {
        let now_ms = coarse_now_ms();
        let expires_ms = now_ms + (lifetime_secs as u64 * 1000);
        Self {
            id: AllocationId::new(),
            client_addr,
            permissions: RwLock::new(HashMap::new()),
            channels: DashMap::new(),
            channels_reverse: DashMap::new(),
            known_peers: DashMap::new(),
            expires_at_ms: AtomicU64::new(expires_ms),
            lifetime_secs: AtomicU64::new(lifetime_secs as u64),
            last_activity_ms: AtomicU64::new(now_ms),
            last_received_ms: AtomicU64::new(now_ms),
            last_successful_relay_ms: AtomicU64::new(0),
            has_relay_attempt: std::sync::atomic::AtomicBool::new(false),
            username,
            allocate_txn_id,
            ice_ufrag: RwLock::new(None),
            ice_remote_ufrag: RwLock::new(None),
            pending_peer_txns: AtomicUsize::new(0),
            peer_ice_ufrags: RwLock::new(None),
        }
    }

    /// Set this allocation's ICE ufrag (from STUN USERNAME local part)
    /// Returns true if this is a new value
    pub fn set_ice_ufrag(&self, ufrag: impl Into<Arc<str>>) -> bool {
        let ufrag = ufrag.into();
        let mut guard = self.ice_ufrag.write();
        if guard.as_ref() == Some(&ufrag) {
            return false;
        }
        *guard = Some(ufrag);
        true
    }

    /// Get this allocation's ICE ufrag (cheap Arc clone)
    pub fn get_ice_ufrag(&self) -> Option<Arc<str>> {
        self.ice_ufrag.read().clone()
    }

    /// Set the remote ICE ufrag (peer this allocation communicates with)
    pub fn set_ice_remote_ufrag(&self, ufrag: impl Into<Arc<str>>) -> bool {
        let ufrag = ufrag.into();
        let mut guard = self.ice_remote_ufrag.write();
        if guard.as_ref() == Some(&ufrag) {
            return false;
        }
        *guard = Some(ufrag);
        true
    }

    /// Get the remote ICE ufrag (cheap Arc clone)
    pub fn get_ice_remote_ufrag(&self) -> Option<Arc<str>> {
        self.ice_remote_ufrag.read().clone()
    }

    /// Check if a peer IP has a *live* permission (RFC 5766 §9)
    #[inline]
    pub fn is_permitted(&self, peer_ip: IpAddr) -> bool {
        let now = coarse_now_ms();
        match self.permissions.read().get(&peer_ip) {
            Some(&expires_ms) => now < expires_ms,
            None => false,
        }
    }

    /// Add or refresh a permission for a peer IP (5-minute lifetime)
    #[inline]
    pub fn add_permission(&self, peer_ip: IpAddr) {
        let expires = coarse_now_ms() + PERMISSION_LIFETIME_MS;
        self.permissions.write().insert(peer_ip, expires);
    }

    /// Number of *live* permission entries currently held.
    #[inline]
    pub fn permissions_count(&self) -> usize {
        let now = coarse_now_ms();
        self.permissions
            .read()
            .values()
            .filter(|&&expires| now < expires)
            .count()
    }

    /// Drop permissions whose 5-minute lifetime has elapsed.
    /// Returns the peer IPs that were removed (for reverse-index cleanup).
    pub fn cleanup_expired_permissions(&self) -> Vec<IpAddr> {
        let now = coarse_now_ms();
        let mut perms = self.permissions.write();
        let expired: Vec<IpAddr> = perms
            .iter()
            .filter(|(_, &expires)| now >= expires)
            .map(|(&ip, _)| ip)
            .collect();
        for ip in &expired {
            perms.remove(ip);
        }
        expired
    }

    /// Bind a channel to a peer address, or refresh an existing binding.
    ///
    /// Keeps `channels` and `channels_reverse` consistent: if the channel was
    /// previously bound to another peer, or the peer to another channel, the
    /// stale entries are removed. Otherwise traffic from the old peer would
    /// still be framed with a channel number the client now associates with
    /// the new peer. (The handler rejects conflicting binds with 400 per RFC
    /// 5766 §11.2 while the old binding is live; this also covers the rebind
    /// that becomes legal once it has lapsed.)
    pub fn bind_channel(&self, channel: u16, peer_addr: SocketAddr) {
        let expires_ms = coarse_now_ms() + CHANNEL_LIFETIME_MS;

        match self.channels.entry(channel) {
            dashmap::mapref::entry::Entry::Occupied(e) => {
                let old_peer = e.get().peer_addr;
                if old_peer == peer_addr {
                    // Refresh in place.
                    e.get().expires_ms.store(expires_ms, Ordering::Relaxed);
                } else {
                    e.replace_entry(ChannelBinding {
                        peer_addr,
                        expires_ms: AtomicU64::new(expires_ms),
                    });
                    self.channels_reverse.remove(&old_peer);
                }
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(ChannelBinding {
                    peer_addr,
                    expires_ms: AtomicU64::new(expires_ms),
                });
            }
        }

        if let Some(old_channel) = self.channels_reverse.insert(peer_addr, channel) {
            if old_channel != channel {
                self.channels.remove(&old_channel);
            }
        }
    }

    /// Number of channels currently bound and not yet lapsed.
    #[inline]
    pub fn channels_count(&self) -> usize {
        let now_ms = coarse_now_ms();
        self.channels
            .iter()
            .filter(|e| e.value().is_live(now_ms))
            .count()
    }

    /// Get the live channel bound to a peer address.
    ///
    /// The forward entry is authoritative: `channels_reverse` can outlive it
    /// between cleanup passes.
    #[inline]
    pub fn channel_for_peer(&self, peer_addr: SocketAddr) -> Option<u16> {
        let channel = *self.channels_reverse.get(&peer_addr)?;
        let binding = self.channels.get(&channel)?;
        if binding.peer_addr == peer_addr && binding.is_live(coarse_now_ms()) {
            Some(channel)
        } else {
            None
        }
    }

    /// Get the peer address bound to a channel, if the binding is still live.
    #[inline]
    pub fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        let binding = self.channels.get(&channel)?;
        if binding.is_live(coarse_now_ms()) {
            Some(binding.peer_addr)
        } else {
            None
        }
    }

    /// Drop channel bindings whose 10-minute lifetime has elapsed, freeing the
    /// channel number and the peer for a fresh bind.
    pub fn cleanup_expired_channels(&self) {
        let now_ms = coarse_now_ms();
        let mut lapsed: Vec<(u16, SocketAddr)> = Vec::new();
        for entry in self.channels.iter() {
            if !entry.value().is_live(now_ms) {
                lapsed.push((*entry.key(), entry.value().peer_addr));
            }
        }
        for (channel, peer_addr) in lapsed {
            self.channels.remove(&channel);
            // Only clear the reverse entry if it still points at this channel;
            // a concurrent rebind may already have claimed the peer.
            self.channels_reverse
                .remove_if(&peer_addr, |_, &ch| ch == channel);
        }
    }

    /// Update last activity time (lock-free, uses coarse timestamp)
    #[inline]
    pub fn touch(&self) {
        self.last_activity_ms
            .store(coarse_now_ms(), Ordering::Relaxed);
    }

    /// Update last received time (traffic FROM client)
    /// Call this only when receiving traffic FROM the client, not when sending TO them
    #[inline]
    pub fn touch_received(&self) {
        let now = coarse_now_ms();
        self.last_received_ms.store(now, Ordering::Relaxed);
        self.last_activity_ms.store(now, Ordering::Relaxed);
    }

    /// Check if client is inactive (no traffic FROM client for given duration)
    #[inline]
    pub fn is_inactive(&self, timeout_secs: u64) -> bool {
        is_expired_secs(self.last_received_ms.load(Ordering::Relaxed), timeout_secs)
    }

    /// Record a successful relay (data was sent to at least one target)
    #[inline]
    pub fn touch_relay_success(&self) {
        self.last_successful_relay_ms
            .store(coarse_now_ms(), Ordering::Relaxed);
        self.has_relay_attempt.store(true, Ordering::Relaxed);
    }

    /// Record a relay attempt - starts the orphan timer if not already started
    #[inline]
    pub fn touch_relay_attempt(&self) {
        // Only set if we haven't recorded any relay yet
        if !self.has_relay_attempt.swap(true, Ordering::Relaxed) {
            self.last_successful_relay_ms
                .store(coarse_now_ms(), Ordering::Relaxed);
        }
    }

    /// Check if sender is orphaned (sending but no targets for given duration)
    #[inline]
    pub fn is_orphaned_sender(&self, timeout_secs: u64) -> bool {
        if !self.has_relay_attempt.load(Ordering::Relaxed) {
            // Never tried to relay - not orphaned
            return false;
        }
        is_expired_secs(
            self.last_successful_relay_ms.load(Ordering::Relaxed),
            timeout_secs,
        )
    }

    /// Check if allocation has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        coarse_now_ms() > self.expires_at_ms.load(Ordering::Relaxed)
    }

    /// Refresh the allocation lifetime
    pub fn refresh(&self, lifetime_secs: u32) {
        let now_ms = coarse_now_ms();
        let expires_ms = now_ms + (lifetime_secs as u64 * 1000);
        self.expires_at_ms.store(expires_ms, Ordering::Relaxed);
        self.lifetime_secs
            .store(lifetime_secs as u64, Ordering::Relaxed);
    }

    /// Get remaining lifetime in seconds
    pub fn remaining_lifetime(&self) -> u32 {
        let expires_ms = self.expires_at_ms.load(Ordering::Relaxed);
        let now_ms = coarse_now_ms();
        if expires_ms > now_ms {
            ((expires_ms - now_ms) / 1000) as u32
        } else {
            0
        }
    }
}

/// Multi-index lookup table for allocations
///
/// LOCK ORDER (must hold globally to avoid ABBA deadlocks):
/// `allocations` is the primary map; every other field is a secondary index.
/// Any code that needs guards on both the primary map and a secondary index
/// MUST acquire the `allocations` guard FIRST. The `cleanup_*` paths rely on
/// this: they hold an `allocations` shard write lock (via `retain`) and then
/// mutate the secondary indices. A path that locked a secondary index first
/// and then `allocations` would deadlock against a concurrent cleanup on the
/// multi-thread runtime.
pub struct AllocationTable {
    /// All allocations by ID
    allocations: DashMap<AllocationId, Allocation>,

    /// Lookup by client address (primary key)
    by_client: DashMap<SocketAddr, AllocationId>,

    /// Lookup by permitted peer IP -> list of allocations
    /// (multiple clients may permit the same peer)
    by_permission: DashMap<IpAddr, Vec<AllocationId>>,

    /// Lookup by (peer_ip, peer_port) for fast path
    by_peer_tuple: DashMap<SocketAddr, AllocationId>,

    /// Lookup by ICE ufrag (learned from STUN USERNAME attribute)
    by_ice_ufrag: DashMap<String, AllocationId>,

    /// STUN requests clients sent to external peers, by transaction id, so
    /// the peer's response (which carries no USERNAME) can be routed back.
    peer_txns: DashMap<[u8; 12], PendingPeerTxn>,

    /// Local ICE ufrag from clients' checks to external peers -> allocations.
    /// Several may claim one ufrag; a peer's check goes to every claimant
    /// that also matches, so claiming a ufrag first cannot cut the real
    /// client off.
    by_peer_ice_ufrag: DashMap<Arc<str>, Vec<AllocationId>>,
}

impl AllocationTable {
    /// Create a new empty table
    pub fn new() -> Self {
        Self {
            allocations: DashMap::new(),
            by_client: DashMap::new(),
            by_permission: DashMap::new(),
            by_peer_tuple: DashMap::new(),
            by_ice_ufrag: DashMap::new(),
            peer_txns: DashMap::new(),
            by_peer_ice_ufrag: DashMap::new(),
        }
    }

    /// Create a new allocation atomically, or return existing allocation ID
    ///
    /// This prevents race conditions where concurrent Allocate requests from
    /// the same client could create multiple allocations.
    ///
    /// Returns (allocation_id, created) where created is true if new, false if existing.
    pub fn create_or_get(
        &self,
        client_addr: SocketAddr,
        username: String,
        lifetime_secs: u32,
        allocate_txn_id: [u8; 12],
    ) -> (AllocationId, bool) {
        use dashmap::mapref::entry::Entry;

        // Fast path: an allocation already exists. The guard is dropped at the
        // end of this statement, before any other map is touched.
        if let Some(id) = self.by_client.get(&client_addr).map(|r| *r) {
            return (id, false);
        }

        // Lock-order invariant: `allocations` before any secondary index, and
        // never hold guards on both at once. Insert into the primary map first
        // (guard released immediately), then claim the by_client slot. If we
        // lose the race for the slot, roll back our primary insert.
        let alloc = Allocation::new(client_addr, username, lifetime_secs, allocate_txn_id);
        let id = alloc.id;
        self.allocations.insert(id, alloc);

        let claimed = match self.by_client.entry(client_addr) {
            Entry::Occupied(entry) => Err(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(id);
                Ok(())
            }
        };

        match claimed {
            Ok(()) => (id, true),
            Err(existing) => {
                // Concurrent request won the race - discard ours.
                self.allocations.remove(&id);
                (existing, false)
            }
        }
    }

    /// Create a new allocation (non-atomic, for backward compatibility)
    ///
    /// Prefer `create_or_get` for new code to avoid race conditions.
    pub fn create(
        &self,
        client_addr: SocketAddr,
        username: String,
        lifetime_secs: u32,
    ) -> AllocationId {
        let (id, _created) = self.create_or_get(client_addr, username, lifetime_secs, [0u8; 12]);
        id
    }

    /// Get allocation by ID
    #[inline]
    pub fn get(
        &self,
        id: AllocationId,
    ) -> Option<dashmap::mapref::one::Ref<'_, AllocationId, Allocation>> {
        self.allocations.get(&id)
    }

    /// Get allocation by client address
    #[inline]
    pub fn get_by_client(
        &self,
        addr: SocketAddr,
    ) -> Option<dashmap::mapref::one::Ref<'_, AllocationId, Allocation>> {
        // Copy the id out so the by_client guard is released before we take
        // an `allocations` guard. Holding both inverts the documented lock
        // order (cleanup holds `allocations` then removes from `by_client`)
        // and can deadlock against a concurrent cleanup.
        let id = *self.by_client.get(&addr)?;
        self.allocations.get(&id)
    }

    /// Check if address is a known client (has an allocation)
    /// Use this to determine if traffic is from a client vs a peer
    #[inline]
    pub fn is_client(&self, addr: SocketAddr) -> bool {
        self.by_client.contains_key(&addr)
    }

    /// Lookup allocation ID by peer tuple (for relay traffic from peers)
    /// Returns the allocation that should receive traffic from this peer
    #[inline]
    pub fn lookup_by_peer_tuple(&self, addr: SocketAddr) -> Option<AllocationId> {
        self.by_peer_tuple.get(&addr).map(|r| *r)
    }

    /// Lookup allocation ID by source address (fast path for any traffic)
    /// Note: This returns an allocation ID but does NOT indicate if it's a client or peer.
    /// Use is_client() to determine traffic direction.
    pub fn lookup_by_source(&self, addr: SocketAddr) -> Option<AllocationId> {
        // First try client address (for TURN control traffic)
        if let Some(id) = self.by_client.get(&addr) {
            return Some(*id);
        }

        // Then try peer tuple (for relay traffic from peers)
        self.by_peer_tuple.get(&addr).map(|r| *r)
    }

    /// Register ICE ufrag pair for an allocation (learned from STUN USERNAME).
    /// `local_ufrag` is this client's ufrag; `remote_ufrag` is who they want to talk to.
    ///
    /// First-come ownership of a given `local_ufrag` is preserved across
    /// *different* allocations (hijack protection). The *same* allocation may
    /// update its credentials (ICE restart): old index entries are removed and
    /// the new pair is installed.
    pub fn register_ice_ufrags(
        &self,
        id: AllocationId,
        local_ufrag: String,
        remote_ufrag: String,
    ) -> bool {
        use dashmap::mapref::entry::Entry;

        // Lock-order invariant: `allocations` MUST be locked before any secondary
        // index, never the reverse. Acquire the allocation ref first and hold it
        // across the by_ice_ufrag claim.
        let alloc = match self.allocations.get(&id) {
            Some(a) => a,
            None => return false,
        };

        // If this local_ufrag is already claimed, only the owning allocation may
        // refresh/update its remote side.
        if let Some(owner) = self.by_ice_ufrag.get(&local_ufrag).map(|r| *r) {
            if owner != id {
                return false;
            }
            alloc.set_ice_ufrag(local_ufrag);
            alloc.set_ice_remote_ufrag(remote_ufrag);
            return true;
        }

        // New local_ufrag claim. Drop any previous local ufrag this allocation
        // held (ICE restart with a fresh local credential).
        if let Some(old_local) = alloc.get_ice_ufrag() {
            if old_local.as_ref() != local_ufrag.as_str() {
                self.by_ice_ufrag.remove(old_local.as_ref());
            }
        }

        match self.by_ice_ufrag.entry(local_ufrag.clone()) {
            Entry::Occupied(entry) => {
                // Lost a race: another allocation claimed it first.
                if *entry.get() != id {
                    return false;
                }
                alloc.set_ice_ufrag(local_ufrag);
                alloc.set_ice_remote_ufrag(remote_ufrag);
                true
            }
            Entry::Vacant(entry) => {
                alloc.set_ice_ufrag(local_ufrag);
                alloc.set_ice_remote_ufrag(remote_ufrag);
                entry.insert(id);
                true
            }
        }
    }

    /// Lookup by ICE ufrag (client's actual ICE ufrag from STUN)
    pub fn lookup_by_ice_ufrag(&self, ice_ufrag: &str) -> Option<AllocationId> {
        self.by_ice_ufrag.get(ice_ufrag).map(|r| *r)
    }

    /// Find allocations that are ICE peers of the sender.
    /// Bi-directional: sender (local=X, remote=Y) matches peer (local=Y, remote=X).
    ///
    /// Avoids allocating Strings: look up the peer by its local ufrag (our
    /// remote) via `by_ice_ufrag`, then verify its remote matches our local.
    pub fn find_ice_peers(&self, sender_local: &str, sender_remote: &str) -> Vec<AllocationId> {
        match self.find_ice_peer(sender_local, sender_remote) {
            Some(id) => vec![id],
            None => Vec::new(),
        }
    }

    /// Single-peer variant of [`find_ice_peers`] — hot path prefers this.
    pub fn find_ice_peer(&self, sender_local: &str, sender_remote: &str) -> Option<AllocationId> {
        let id = *self.by_ice_ufrag.get(sender_remote)?;
        let alloc = self.allocations.get(&id)?;
        let remote = alloc.ice_remote_ufrag.read();
        match remote.as_deref() {
            Some(r) if r == sender_local => Some(id),
            _ => None,
        }
    }

    /// Lookup by peer IP (may return multiple allocations)
    #[inline]
    pub fn lookup_by_peer_ip(&self, ip: IpAddr) -> Vec<AllocationId> {
        self.by_permission
            .get(&ip)
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Lookup by peer address - prefer tuple, fallback to IP
    ///
    /// Returns (candidates, is_unique) where:
    /// - candidates: list of allocation IDs that may receive this traffic
    /// - is_unique: true if exactly one candidate (safe to register tuple)
    ///
    /// This function enables fast-path routing: on first packet from a peer,
    /// if is_unique is true, the caller should register the tuple for future
    /// direct lookups. This avoids bandwidth multiplication when multiple
    /// allocations share the same peer IP permission.
    #[inline]
    pub fn lookup_by_peer_addr(&self, addr: SocketAddr) -> (Vec<AllocationId>, bool) {
        // Fast path: direct tuple lookup (already registered)
        if let Some(id) = self.by_peer_tuple.get(&addr) {
            return (vec![*id], true);
        }

        // Slow path: IP-based lookup (first packet from this peer)
        let candidates = self.lookup_by_peer_ip(addr.ip());
        let is_unique = candidates.len() == 1;
        (candidates, is_unique)
    }

    /// Remove `id` from `by_permission` for `peer_ip`, dropping the map entry
    /// when the Vec becomes empty so the DashMap does not accumulate empties.
    fn remove_from_permission_index(&self, peer_ip: IpAddr, id: AllocationId) {
        let empty = if let Some(mut ids) = self.by_permission.get_mut(&peer_ip) {
            ids.retain(|&i| i != id);
            ids.is_empty()
        } else {
            false
        };
        if empty {
            // Re-check emptiness under the entry API to avoid removing a Vec
            // that another thread just re-populated.
            self.by_permission.remove_if(&peer_ip, |_, v| v.is_empty());
        }
    }

    /// Add permission and update index (also refreshes lifetime).
    pub fn add_permission(&self, id: AllocationId, peer_ip: IpAddr) {
        if let Some(alloc) = self.allocations.get(&id) {
            alloc.add_permission(peer_ip);
        }

        let mut entry = self.by_permission.entry(peer_ip).or_default();
        if !entry.contains(&id) {
            entry.push(id);
        }
    }

    /// Atomically check the permission cap, insert *or refresh* peer IPs.
    ///
    /// Holds the allocation's permissions write lock across the count check
    /// and insert, preventing TOCTOU races between concurrent CreatePermission
    /// requests. Existing permissions are refreshed to a new 5-minute lifetime
    /// (RFC 5766 §9) even when already present. Returns `false` if the
    /// allocation does not exist or if adding the new IPs would exceed `cap`;
    /// in both cases no state is modified.
    pub fn try_add_permissions_capped(
        &self,
        id: AllocationId,
        peer_ips: &[IpAddr],
        cap: usize,
    ) -> bool {
        let alloc = match self.allocations.get(&id) {
            Some(a) => a,
            None => return false,
        };

        let now = coarse_now_ms();
        let expires = now + PERMISSION_LIFETIME_MS;

        let to_index: Vec<IpAddr> = {
            let mut perms = alloc.permissions.write();
            // Count only live permissions toward the cap.
            let live: usize = perms.values().filter(|&&e| now < e).count();
            let new_ips: Vec<IpAddr> = peer_ips
                .iter()
                .filter(|ip| match perms.get(ip) {
                    Some(&e) if now < e => false, // already live
                    _ => true,
                })
                .copied()
                .collect();
            if live + new_ips.len() > cap {
                return false;
            }
            // Refresh every requested IP (new or existing).
            for ip in peer_ips {
                perms.insert(*ip, expires);
            }
            peer_ips.to_vec()
        };

        for ip in to_index {
            let mut entry = self.by_permission.entry(ip).or_default();
            if !entry.contains(&id) {
                entry.push(id);
            }
        }

        true
    }

    /// Register peer tuple for fast path lookup
    /// Also records in known_peers so it gets cleaned up with the allocation
    pub fn register_peer_tuple(&self, id: AllocationId, peer_addr: SocketAddr) {
        self.by_peer_tuple.insert(peer_addr, id);

        // Also record in known_peers so cleanup removes the by_peer_tuple entry
        if let Some(alloc) = self.allocations.get(&id) {
            alloc
                .known_peers
                .entry(peer_addr)
                .or_insert_with(|| PeerInfo {
                    last_seen_ms: coarse_now_ms(),
                });
        }
    }

    /// Remove an allocation.
    ///
    /// Returns `true` if the allocation existed and was removed by this call,
    /// `false` if it was already gone (e.g. reaped concurrently by cleanup).
    /// Callers that account for the removal elsewhere (rate limiter quota)
    /// must only do so when this returns `true`.
    pub fn remove(&self, id: AllocationId) -> bool {
        if let Some((_, alloc)) = self.allocations.remove(&id) {
            self.by_client.remove(&alloc.client_addr);
            if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                self.by_ice_ufrag.remove(ice_ufrag.as_ref());
            }
            self.unindex_peer_ice(id, &alloc);

            for &peer_ip in alloc.permissions.read().keys() {
                self.remove_from_permission_index(peer_ip, id);
            }

            for entry in alloc.known_peers.iter() {
                self.by_peer_tuple.remove(entry.key());
            }
            true
        } else {
            false
        }
    }

    /// Drop lapsed channel bindings across every allocation (RFC 5766 §11).
    ///
    /// Touches only each allocation's own channel maps, never a secondary
    /// index, so it does not participate in the `allocations`-before-index
    /// lock order documented above.
    pub fn cleanup_channel_bindings(&self) {
        for entry in self.allocations.iter() {
            entry.value().cleanup_expired_channels();
        }
    }

    /// Remember STUN request `txn` that allocation `id` sent to external
    /// `peer_addr`, or refresh it on retransmit. Returns false when the
    /// allocation is at its cap or another allocation already holds `txn`.
    pub fn record_peer_txn(&self, id: AllocationId, txn: [u8; 12], peer_addr: SocketAddr) -> bool {
        use dashmap::mapref::entry::Entry;

        // Lock order: `allocations` before the index.
        let Some(alloc) = self.allocations.get(&id) else {
            return false;
        };
        let expires_ms = coarse_now_ms() + PEER_TXN_LIFETIME_MS;
        match self.peer_txns.entry(txn) {
            Entry::Occupied(mut e) => {
                if e.get().id != id {
                    return false;
                }
                e.insert(PendingPeerTxn {
                    id,
                    peer_addr,
                    expires_ms,
                });
                true
            }
            Entry::Vacant(e) => {
                if alloc.pending_peer_txns.load(Ordering::Relaxed) >= MAX_PEER_TXNS_PER_ALLOC {
                    return false;
                }
                alloc.pending_peer_txns.fetch_add(1, Ordering::Relaxed);
                e.insert(PendingPeerTxn {
                    id,
                    peer_addr,
                    expires_ms,
                });
                true
            }
        }
    }

    /// The allocation whose client sent STUN request `txn` to `peer_addr`,
    /// consuming the pending entry. The allocation must still be permitted
    /// for the peer's IP (RFC 5766 §10.3).
    pub fn take_peer_txn_owner(
        &self,
        peer_addr: SocketAddr,
        txn: &[u8; 12],
    ) -> Option<AllocationId> {
        let now = coarse_now_ms();
        // Index guard released at the end of this statement.
        let (_, pending) = self
            .peer_txns
            .remove_if(txn, |_, p| p.peer_addr == peer_addr && now < p.expires_ms)?;
        let alloc = self.allocations.get(&pending.id)?;
        Self::release_peer_txn_slot(&alloc);
        alloc.is_permitted(peer_addr.ip()).then_some(pending.id)
    }

    fn release_peer_txn_slot(alloc: &Allocation) {
        // Packets are handled on one task, so check-then-sub cannot race
        // another release for the same allocation.
        if alloc.pending_peer_txns.load(Ordering::Relaxed) > 0 {
            alloc.pending_peer_txns.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Drop STUN requests to external peers that were never answered.
    pub fn cleanup_peer_txns(&self) {
        let now = coarse_now_ms();
        let mut owners = Vec::new();
        self.peer_txns.retain(|_, p| {
            let live = now < p.expires_ms;
            if !live {
                owners.push(p.id);
            }
            live
        });
        // Index guards are released; now touch the allocations.
        for id in owners {
            if let Some(alloc) = self.allocations.get(&id) {
                Self::release_peer_txn_slot(&alloc);
            }
        }
    }

    /// Record the (local, remote) ICE ufrags of a check allocation `id` sent
    /// to an external peer, so the peer's own checks can find it.
    pub fn register_peer_ice_ufrags(&self, id: AllocationId, local: &str, remote: &str) {
        // Lock order: `allocations` before the index.
        let Some(alloc) = self.allocations.get(&id) else {
            return;
        };
        let mut current = alloc.peer_ice_ufrags.write();
        if let Some((l, r)) = current.as_ref() {
            if l.as_ref() == local && r.as_ref() == remote {
                return;
            }
        }
        let old_local = current.as_ref().map(|(l, _)| l.clone());
        let local: Arc<str> = local.into();
        *current = Some((local.clone(), remote.into()));
        drop(current);

        if old_local.as_deref() == Some(local.as_ref()) {
            return;
        }
        if let Some(old) = old_local {
            self.unindex_peer_ice_ufrag(&old, id);
        }
        let mut ids = self.by_peer_ice_ufrag.entry(local).or_default();
        if !ids.contains(&id) {
            ids.push(id);
        }
    }

    fn unindex_peer_ice_ufrag(&self, local: &Arc<str>, id: AllocationId) {
        let empty = match self.by_peer_ice_ufrag.get_mut(local) {
            Some(mut ids) => {
                ids.retain(|&i| i != id);
                ids.is_empty()
            }
            None => false,
        };
        if empty {
            self.by_peer_ice_ufrag.remove_if(local, |_, v| v.is_empty());
        }
    }

    /// Drop `alloc` from the external-peer ufrag index (allocation removal).
    fn unindex_peer_ice(&self, id: AllocationId, alloc: &Allocation) {
        if let Some((local, _)) = alloc.peer_ice_ufrags.read().as_ref() {
            self.unindex_peer_ice_ufrag(local, id);
        }
    }

    /// Allocations a peer's ICE check (USERNAME "client_ufrag:peer_ufrag")
    /// is for: those that sent checks as `client_ufrag` to `peer_ufrag` and
    /// are permitted for the peer's IP.
    pub fn peer_ice_targets(
        &self,
        peer_addr: SocketAddr,
        client_ufrag: &str,
        peer_ufrag: &str,
    ) -> Vec<AllocationId> {
        let Some(ids) = self.by_peer_ice_ufrag.get(client_ufrag).map(|r| r.clone()) else {
            return Vec::new();
        };
        ids.into_iter()
            .filter(|&id| {
                self.allocations.get(&id).is_some_and(|a| {
                    a.is_permitted(peer_addr.ip())
                        && a.peer_ice_ufrags
                            .read()
                            .as_ref()
                            .is_some_and(|(_, r)| r.as_ref() == peer_ufrag)
                })
            })
            .collect()
    }

    /// Drop lapsed permissions (RFC 5766 §9) and prune empty `by_permission` entries.
    pub fn cleanup_permissions(&self) {
        for entry in self.allocations.iter() {
            let id = *entry.key();
            let expired = entry.value().cleanup_expired_permissions();
            for peer_ip in expired {
                self.remove_from_permission_index(peer_ip, id);
            }
        }
    }

    /// Remove expired allocations (atomic per-entry removal)
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_expired(&self) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_expired() {
                tracing::info!(
                    "Removing expired allocation {} for {} (lifetime ended)",
                    id,
                    alloc.client_addr
                );
                // Clean up indices before removal
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                    self.by_ice_ufrag.remove(ice_ufrag.as_ref());
                }
                self.unindex_peer_ice(*id, alloc);
                for &peer_ip in alloc.permissions.read().keys() {
                    self.remove_from_permission_index(peer_ip, *id);
                }
                for entry in alloc.known_peers.iter() {
                    self.by_peer_tuple.remove(entry.key());
                }
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });
        removed_ips
    }

    /// Remove inactive allocations (no traffic FROM client for timeout_secs)
    /// Uses atomic per-entry removal to avoid race conditions
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_inactive(&self, timeout_secs: u64) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_inactive(timeout_secs) {
                tracing::info!(
                    "Removing inactive allocation {} for {} (no traffic for {}s)",
                    id,
                    alloc.client_addr,
                    timeout_secs
                );
                // Clean up indices
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                    self.by_ice_ufrag.remove(ice_ufrag.as_ref());
                }
                self.unindex_peer_ice(*id, alloc);
                for &peer_ip in alloc.permissions.read().keys() {
                    self.remove_from_permission_index(peer_ip, *id);
                }
                for entry in alloc.known_peers.iter() {
                    self.by_peer_tuple.remove(entry.key());
                }
                false
            } else {
                true
            }
        });
        removed_ips
    }

    /// Remove orphaned sender allocations (sending but no targets for timeout_secs)
    /// Uses atomic per-entry removal to avoid race conditions
    /// Returns the list of client IPs whose allocations were removed
    pub fn cleanup_orphaned_senders(&self, timeout_secs: u64) -> Vec<IpAddr> {
        let mut removed_ips = Vec::new();
        self.allocations.retain(|id, alloc| {
            if alloc.is_orphaned_sender(timeout_secs) {
                tracing::info!(
                    "Removing orphaned sender {} for {} (no relay targets for {}s)",
                    id,
                    alloc.client_addr,
                    timeout_secs
                );
                // Clean up indices
                removed_ips.push(alloc.client_addr.ip());
                self.by_client.remove(&alloc.client_addr);
                if let Some(ice_ufrag) = alloc.get_ice_ufrag() {
                    self.by_ice_ufrag.remove(ice_ufrag.as_ref());
                }
                self.unindex_peer_ice(*id, alloc);
                for &peer_ip in alloc.permissions.read().keys() {
                    self.remove_from_permission_index(peer_ip, *id);
                }
                for entry in alloc.known_peers.iter() {
                    self.by_peer_tuple.remove(entry.key());
                }
                false
            } else {
                true
            }
        });
        removed_ips
    }
}

impl Default for AllocationTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ---- STUN requests to external peers ----------------------------------

    fn peer_table() -> (AllocationTable, AllocationId, AllocationId) {
        let t = AllocationTable::new();
        let a = t.create("192.0.2.1:5000".parse().unwrap(), "a".into(), 600);
        let b = t.create("192.0.2.2:5000".parse().unwrap(), "b".into(), 600);
        for id in [a, b] {
            t.add_permission(id, "198.51.100.7".parse().unwrap());
        }
        (t, a, b)
    }

    const PEER: &str = "198.51.100.7:5000";

    fn txn(i: usize) -> [u8; 12] {
        let mut t = [0u8; 12];
        t[..8].copy_from_slice(&(i as u64).to_be_bytes());
        t
    }

    #[test]
    fn peer_txn_goes_to_its_sender_only_once_and_only_from_its_peer() {
        let (t, a, b) = peer_table();
        let peer: SocketAddr = PEER.parse().unwrap();
        assert!(t.record_peer_txn(a, txn(1), peer));
        assert!(!t.record_peer_txn(b, txn(1), peer), "first sender keeps it");

        assert_eq!(
            t.take_peer_txn_owner("198.51.100.7:5001".parse().unwrap(), &txn(1)),
            None
        );
        assert_eq!(t.take_peer_txn_owner(peer, &txn(2)), None);
        assert_eq!(t.take_peer_txn_owner(peer, &txn(1)), Some(a));
        assert_eq!(t.take_peer_txn_owner(peer, &txn(1)), None, "consumed");
    }

    #[test]
    fn peer_txn_needs_a_live_permission() {
        let (t, a, _) = peer_table();
        let peer: SocketAddr = PEER.parse().unwrap();
        t.record_peer_txn(a, txn(1), peer);
        t.get(a).unwrap().permissions.write().clear();
        assert_eq!(t.take_peer_txn_owner(peer, &txn(1)), None);
    }

    #[test]
    fn lapsed_peer_txn_is_reaped_and_frees_its_slot() {
        let (t, a, _) = peer_table();
        let peer: SocketAddr = PEER.parse().unwrap();
        t.record_peer_txn(a, txn(1), peer);
        t.peer_txns.get_mut(&txn(1)).unwrap().expires_ms = 0;

        assert_eq!(t.take_peer_txn_owner(peer, &txn(1)), None);
        t.cleanup_peer_txns();
        assert!(t.peer_txns.is_empty());
        assert_eq!(
            t.get(a).unwrap().pending_peer_txns.load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn peer_txn_cap_refuses_new_but_refreshes_retransmits() {
        let (t, a, b) = peer_table();
        let peer: SocketAddr = PEER.parse().unwrap();
        for i in 0..MAX_PEER_TXNS_PER_ALLOC {
            assert!(t.record_peer_txn(a, txn(i), peer));
        }
        assert!(!t.record_peer_txn(a, txn(usize::MAX), peer), "cap");
        assert!(t.record_peer_txn(a, txn(0), peer), "retransmit refreshes");
        assert!(
            t.record_peer_txn(b, txn(usize::MAX), peer),
            "cap is per allocation"
        );

        assert_eq!(t.take_peer_txn_owner(peer, &txn(0)), Some(a));
        assert!(
            t.record_peer_txn(a, txn(usize::MAX - 1), peer),
            "slot freed"
        );
    }

    #[test]
    fn peer_ice_check_reaches_every_matching_claimant() {
        // An allocation that claims a victim's ufrag first must not cut the
        // victim off: both get the check (and the claimant learns nothing it
        // did not already put in its own USERNAME).
        let (t, a, b) = peer_table();
        let peer: SocketAddr = PEER.parse().unwrap();
        t.register_peer_ice_ufrags(b, "cli", "peer");
        t.register_peer_ice_ufrags(a, "cli", "peer");
        let mut got = t.peer_ice_targets(peer, "cli", "peer");
        got.sort_by_key(|id| id.0);
        assert_eq!(got, vec![a, b]);

        assert!(t.peer_ice_targets(peer, "cli", "other").is_empty());
        assert!(t
            .peer_ice_targets("198.51.100.99:5000".parse().unwrap(), "cli", "peer")
            .is_empty());
    }

    #[test]
    fn peer_ice_ufrags_follow_restart_and_removal() {
        let (t, a, _) = peer_table();
        let peer: SocketAddr = PEER.parse().unwrap();
        t.register_peer_ice_ufrags(a, "old", "peer");
        t.register_peer_ice_ufrags(a, "new", "peer2");
        assert!(t.peer_ice_targets(peer, "old", "peer").is_empty());
        assert_eq!(t.peer_ice_targets(peer, "new", "peer2"), vec![a]);

        t.remove(a);
        assert!(t.peer_ice_targets(peer, "new", "peer2").is_empty());
        assert!(t.by_peer_ice_ufrag.is_empty());
    }

    #[test]
    fn peer_ice_ufrags_leave_the_client_to_client_index_alone() {
        let (t, a, _) = peer_table();
        t.register_peer_ice_ufrags(a, "cli", "peer");
        assert_eq!(t.lookup_by_ice_ufrag("cli"), None);
        assert!(t.get(a).unwrap().get_ice_ufrag().is_none());
    }

    // ---- channel binding lifetime (RFC 5766 §11) ----------------------------

    /// Force a binding past its deadline without waiting out the real lifetime.
    fn lapse(alloc: &Allocation, channel: u16) {
        alloc
            .channels
            .get(&channel)
            .expect("channel bound")
            .expires_ms
            .store(0, Ordering::Relaxed);
    }

    #[test]
    fn lapsed_channel_binding_frees_the_peer_for_a_new_channel() {
        // RFC 5766 §11.2 forbids rebinding a peer to a different channel only
        // while the binding is live; §11 caps that at 10 minutes. libwebrtc
        // rebinds the same peer to a higher channel number after a TurnEntry is
        // destroyed and recreated (ICE restart), so a conflict that never
        // lapsed would 400 for the rest of the allocation.
        let alloc = Allocation::new(
            "198.51.100.5:50000".parse().unwrap(),
            "u".to_string(),
            600,
            [0u8; 12],
        );
        let peer: SocketAddr = "203.0.113.20:5000".parse().unwrap();

        alloc.bind_channel(0x4000, peer);
        assert_eq!(alloc.channel_for_peer(peer), Some(0x4000));
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer));
        assert_eq!(alloc.channels_count(), 1);

        lapse(&alloc, 0x4000);

        // The lapsed binding is invisible, so the handler sees no conflict.
        assert_eq!(alloc.channel_for_peer(peer), None);
        assert_eq!(alloc.peer_for_channel(0x4000), None);
        assert_eq!(alloc.channels_count(), 0);

        // ... and the peer may be bound to a fresh channel number.
        alloc.bind_channel(0x4001, peer);
        assert_eq!(alloc.channel_for_peer(peer), Some(0x4001));
        assert_eq!(alloc.peer_for_channel(0x4001), Some(peer));
        assert_eq!(alloc.channels_count(), 1);
    }

    #[test]
    fn rebinding_same_pair_refreshes_the_lifetime() {
        let alloc = Allocation::new(
            "198.51.100.5:50000".parse().unwrap(),
            "u".to_string(),
            600,
            [0u8; 12],
        );
        let peer: SocketAddr = "203.0.113.20:5000".parse().unwrap();

        alloc.bind_channel(0x4000, peer);
        lapse(&alloc, 0x4000);
        assert_eq!(alloc.peer_for_channel(0x4000), None);

        // A ChannelBind for the same pair revives it rather than allocating a
        // second slot.
        alloc.bind_channel(0x4000, peer);
        assert_eq!(alloc.peer_for_channel(0x4000), Some(peer));
        assert_eq!(alloc.channels_count(), 1);
    }

    #[test]
    fn cleanup_expired_channels_reaps_both_maps() {
        let table = AllocationTable::new();
        let client: SocketAddr = "198.51.100.5:50000".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);
        let peer: SocketAddr = "203.0.113.20:5000".parse().unwrap();
        let live_peer: SocketAddr = "203.0.113.21:5000".parse().unwrap();

        {
            let alloc = table.get(id).unwrap();
            alloc.bind_channel(0x4000, peer);
            alloc.bind_channel(0x4001, live_peer);
            lapse(&alloc, 0x4000);
        }

        table.cleanup_channel_bindings();

        let alloc = table.get(id).unwrap();
        assert!(alloc.channels.get(&0x4000).is_none());
        assert!(
            alloc.channels_reverse.get(&peer).is_none(),
            "reverse entry must not outlive the binding"
        );
        // The still-live binding is untouched.
        assert_eq!(alloc.peer_for_channel(0x4001), Some(live_peer));
        assert_eq!(alloc.channel_for_peer(live_peer), Some(0x4001));
    }

    #[test]
    fn rebinding_a_channel_to_a_new_peer_clears_the_old_reverse_entry() {
        let alloc = Allocation::new(
            "198.51.100.5:50000".parse().unwrap(),
            "u".to_string(),
            600,
            [0u8; 12],
        );
        let old: SocketAddr = "203.0.113.20:5000".parse().unwrap();
        let new: SocketAddr = "203.0.113.21:5000".parse().unwrap();

        alloc.bind_channel(0x4000, old);
        alloc.bind_channel(0x4000, new);

        assert_eq!(alloc.peer_for_channel(0x4000), Some(new));
        assert_eq!(alloc.channel_for_peer(new), Some(0x4000));
        assert_eq!(
            alloc.channel_for_peer(old),
            None,
            "old peer must not keep a channel the client reassigned"
        );
        assert_eq!(alloc.channels_count(), 1);
    }

    #[test]
    fn test_create_allocation() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();

        let id = table.create(client, "testuser".to_string(), 600);

        assert!(table.get(id).is_some());
        assert!(table.get_by_client(client).is_some());
    }

    #[test]
    fn test_permission_lookup() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let id = table.create(client, "testuser".to_string(), 600);
        table.add_permission(id, peer_ip);

        let found = table.lookup_by_peer_ip(peer_ip);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], id);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn try_add_permissions_capped_rejects_when_over_cap() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        let peers = [ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")];
        // Cap of 2 with 3 new IPs -> reject, no state modification.
        assert!(!table.try_add_permissions_capped(id, &peers, 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 0);
        for p in &peers {
            assert!(table.lookup_by_peer_ip(*p).is_empty());
        }
    }

    #[test]
    fn try_add_permissions_capped_allows_refresh_at_cap() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        let peers = [ip("10.0.0.1"), ip("10.0.0.2")];
        assert!(table.try_add_permissions_capped(id, &peers, 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);

        // Refresh the same IPs -- must not count as new additions.
        assert!(table.try_add_permissions_capped(id, &peers, 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);
    }

    #[test]
    fn try_add_permissions_capped_mixed_new_and_existing() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        assert!(table.try_add_permissions_capped(id, &[ip("10.0.0.1")], 2));
        // Existing 10.0.0.1 plus new 10.0.0.2 -> total 2, within cap of 2.
        assert!(table.try_add_permissions_capped(id, &[ip("10.0.0.1"), ip("10.0.0.2")], 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);
        // Adding a third distinct IP now exceeds cap.
        assert!(!table.try_add_permissions_capped(id, &[ip("10.0.0.3")], 2));
        assert_eq!(table.get(id).unwrap().permissions_count(), 2);
    }

    #[test]
    fn try_add_permissions_capped_is_atomic_under_concurrent_callers() {
        use std::sync::Arc;
        use std::thread;

        let table = Arc::new(AllocationTable::new());
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        const CAP: usize = 64;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 16;

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let table = table.clone();
                thread::spawn(move || {
                    let peers: Vec<IpAddr> = (0..PER_THREAD)
                        .map(|i| ip(&format!("10.{}.{}.1", t, i)))
                        .collect();
                    // Each thread tries to add 16 unique IPs. 8*16 = 128 > cap 64,
                    // so some must fail. The cap must never be exceeded regardless.
                    let _ = table.try_add_permissions_capped(id, &peers, CAP);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let total = table.get(id).unwrap().permissions_count();
        assert!(
            total <= CAP,
            "permissions_count {} exceeded cap {}",
            total,
            CAP
        );
    }

    /// Regression guard for the ABBA deadlock between `get_by_client` /
    /// `create_or_get` (previously: `by_client` guard held while locking
    /// `allocations`) and the `cleanup_*` paths (`allocations` retain lock held
    /// while removing from `by_client`). Same watchdog shape as the test below.
    #[test]
    fn client_lookup_and_cleanup_do_not_deadlock_under_contention() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let table = Arc::new(AllocationTable::new());
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        const WRITERS: usize = 8;
        for t in 0..WRITERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            let progress = Arc::clone(&progress);
            handles.push(thread::spawn(move || {
                let mut n: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    // Tiny port space so both maps collide on shards constantly.
                    let port = 30000 + ((t as u64 * 131 + n) % 64) as u16;
                    let client: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
                    let (id, _) = table.create_or_get(client, "u".to_string(), 600, [0u8; 12]);
                    if let Some(a) = table.get_by_client(client) {
                        assert_eq!(a.client_addr, client);
                    }
                    let _ = table.is_client(client);
                    let _ = table.get(id);
                    n += 1;
                }
                progress.fetch_add(n, Ordering::Relaxed);
            }));
        }

        const CLEANERS: usize = 2;
        for _ in 0..CLEANERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    table.cleanup_inactive(0);
                }
            }));
        }

        thread::sleep(Duration::from_millis(1500));
        stop.store(true, Ordering::Relaxed);

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for h in handles {
                let _ = h.join();
            }
            let _ = tx.send(());
        });

        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(()) => assert!(
                progress.load(Ordering::Relaxed) > 0,
                "writers made no progress"
            ),
            Err(_) => panic!(
                "deadlock: get_by_client/create_or_get and cleanup_* threads did not \
                 finish after stop -- a by_client guard is being held while locking \
                 allocations (see AllocationTable lock-order doc)"
            ),
        }
    }

    #[test]
    fn bind_channel_removes_stale_reverse_and_forward_entries() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);
        let a: SocketAddr = "203.0.113.1:5000".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:5000".parse().unwrap();
        let alloc = table.get(id).unwrap();

        // Rebind the channel to another peer: the old peer must no longer map
        // to the channel.
        alloc.bind_channel(0x4000, a);
        alloc.bind_channel(0x4000, b);
        assert_eq!(alloc.peer_for_channel(0x4000), Some(b));
        assert_eq!(alloc.channel_for_peer(a), None);
        assert_eq!(alloc.channel_for_peer(b), Some(0x4000));
        assert_eq!(alloc.channels_count(), 1);

        // Rebind the peer to another channel: the old channel must be freed.
        alloc.bind_channel(0x4001, b);
        assert_eq!(alloc.peer_for_channel(0x4000), None);
        assert_eq!(alloc.peer_for_channel(0x4001), Some(b));
        assert_eq!(alloc.channel_for_peer(b), Some(0x4001));
        assert_eq!(alloc.channels_count(), 1);

        // Refreshing an identical binding is a no-op.
        alloc.bind_channel(0x4001, b);
        assert_eq!(alloc.channels_count(), 1);
    }

    #[test]
    fn remove_reports_whether_it_removed() {
        let table = AllocationTable::new();
        let client = "192.168.1.100:54321".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);
        assert!(table.remove(id));
        assert!(!table.remove(id));
        assert!(table.get_by_client(client).is_none());
    }

    /// Regression guard for the ABBA deadlock between `register_ice_ufrags`
    /// (locks `by_ice_ufrag` then `allocations`) and the `cleanup_*` paths
    /// (lock `allocations` via `retain`, then `by_ice_ufrag`). The lock-order
    /// invariant requires `allocations` to be acquired first everywhere. If a
    /// future change reintroduces the inverse order, the writer and cleanup
    /// threads deadlock and never observe `stop`, so the watchdog fails the test
    /// instead of hanging the whole suite.
    #[test]
    fn register_and_cleanup_do_not_deadlock_under_contention() {
        use std::sync::atomic::AtomicBool;
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let table = Arc::new(AllocationTable::new());
        let stop = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        // Writers: create an allocation and register a fresh ICE ufrag. The
        // fresh ufrag forces the `Vacant` arm of `register_ice_ufrags`, which is
        // where it holds a `by_ice_ufrag` write lock while touching `allocations`.
        const WRITERS: usize = 8;
        for t in 0..WRITERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            let progress = Arc::clone(&progress);
            handles.push(thread::spawn(move || {
                let mut n: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    // Small, recycled client-port space so shards collide often.
                    let port = 20000 + ((t as u64 * 251 + n) % 512) as u16;
                    let client: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
                    let id = table.create(client, "strom".to_string(), 600);
                    table.register_ice_ufrags(id, format!("L{}-{}", t, n), format!("R{}-{}", t, n));
                    n += 1;
                }
                progress.fetch_add(n, Ordering::Relaxed);
            }));
        }

        // Cleaners: `cleanup_inactive(0)` removes every allocation unconditionally
        // (now - last_received >= 0 always holds), exercising the removal branch
        // that locks `by_ice_ufrag` while holding the `allocations` retain lock.
        const CLEANERS: usize = 2;
        for _ in 0..CLEANERS {
            let table = Arc::clone(&table);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    table.cleanup_inactive(0);
                }
            }));
        }

        thread::sleep(Duration::from_millis(1500));
        stop.store(true, Ordering::Relaxed);

        // Watchdog: a separate thread joins the workers. If they deadlocked they
        // never exit, the join blocks, and `recv_timeout` fails the test loudly.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for h in handles {
                let _ = h.join();
            }
            let _ = tx.send(());
        });

        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(()) => assert!(
                progress.load(Ordering::Relaxed) > 0,
                "writers made no progress"
            ),
            Err(_) => panic!(
                "deadlock: register_ice_ufrags and cleanup_* threads did not finish \
                 after stop -- lock-order inversion reintroduced (allocations must be \
                 locked before any secondary index; see AllocationTable lock-order doc)"
            ),
        }
    }

    #[test]
    fn same_allocation_can_update_ice_ufrags_on_restart() {
        let table = AllocationTable::new();
        let client = "198.51.100.5:50000".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        assert!(table.register_ice_ufrags(id, "OLDLOC".into(), "OLDREM".into()));
        assert_eq!(table.lookup_by_ice_ufrag("OLDLOC"), Some(id));

        // ICE restart: new local + remote on the same allocation.
        assert!(table.register_ice_ufrags(id, "NEWLOC".into(), "NEWREM".into()));
        assert_eq!(table.lookup_by_ice_ufrag("NEWLOC"), Some(id));
        assert!(
            table.lookup_by_ice_ufrag("OLDLOC").is_none(),
            "old local ufrag must be released"
        );
        let alloc = table.get(id).unwrap();
        assert_eq!(alloc.get_ice_ufrag().as_deref(), Some("NEWLOC"));
        assert_eq!(alloc.get_ice_remote_ufrag().as_deref(), Some("NEWREM"));
    }

    #[test]
    fn same_allocation_can_refresh_remote_ufrag_with_same_local() {
        let table = AllocationTable::new();
        let client = "198.51.100.5:50001".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);

        assert!(table.register_ice_ufrags(id, "LOC".into(), "REM1".into()));
        assert!(table.register_ice_ufrags(id, "LOC".into(), "REM2".into()));
        assert_eq!(
            table.get(id).unwrap().get_ice_remote_ufrag().as_deref(),
            Some("REM2")
        );
        assert_eq!(table.lookup_by_ice_ufrag("LOC"), Some(id));
    }

    #[test]
    fn different_allocation_cannot_hijack_ice_ufrag() {
        let table = AllocationTable::new();
        let a = table.create("198.51.100.5:50002".parse().unwrap(), "a".into(), 600);
        let b = table.create("198.51.100.5:50003".parse().unwrap(), "b".into(), 600);

        assert!(table.register_ice_ufrags(a, "SHARED".into(), "PEER".into()));
        assert!(
            !table.register_ice_ufrags(b, "SHARED".into(), "OTHER".into()),
            "second allocation must not steal the ufrag"
        );
        assert_eq!(table.lookup_by_ice_ufrag("SHARED"), Some(a));
        assert_eq!(
            table.get(a).unwrap().get_ice_remote_ufrag().as_deref(),
            Some("PEER")
        );
        assert!(table.get(b).unwrap().get_ice_ufrag().is_none());
    }

    #[test]
    fn permission_expires_after_lifetime_and_create_permission_refreshes() {
        crate::coarse_time::init();
        let table = AllocationTable::new();
        let client = "198.51.100.5:50004".parse().unwrap();
        let id = table.create(client, "u".to_string(), 600);
        let peer = ip("203.0.113.50");

        assert!(table.try_add_permissions_capped(id, &[peer], 8));
        assert!(table.get(id).unwrap().is_permitted(peer));

        // Force expiry.
        {
            let alloc = table.get(id).unwrap();
            alloc.permissions.write().insert(peer, 0);
            assert!(!alloc.is_permitted(peer));
        }

        // CreatePermission-equivalent refresh via capped path.
        assert!(table.try_add_permissions_capped(id, &[peer], 8));
        assert!(table.get(id).unwrap().is_permitted(peer));
    }

    #[test]
    fn by_permission_drops_empty_vec_on_remove() {
        let table = AllocationTable::new();
        let id = table.create("198.51.100.5:50005".parse().unwrap(), "u".into(), 600);
        let peer = ip("203.0.113.60");
        table.add_permission(id, peer);
        assert!(table.by_permission.contains_key(&peer));
        table.remove(id);
        assert!(
            !table.by_permission.contains_key(&peer),
            "empty Vec must not linger in by_permission"
        );
    }

    #[test]
    fn cleanup_permissions_reaps_expired_and_index() {
        crate::coarse_time::init();
        let table = AllocationTable::new();
        let id = table.create("198.51.100.5:50006".parse().unwrap(), "u".into(), 600);
        let peer = ip("203.0.113.70");
        table.add_permission(id, peer);
        table.get(id).unwrap().permissions.write().insert(peer, 0);
        table.cleanup_permissions();
        assert!(!table.get(id).unwrap().is_permitted(peer));
        assert!(!table.by_permission.contains_key(&peer));
    }
}
