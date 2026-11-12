# uTURN Architecture

## Overview

uTURN is a WebRTC-focused TURN server that operates on a single UDP port. Unlike traditional TURN servers that allocate separate ports for each relay, uTURN multiplexes all traffic through one port using packet-level demultiplexing.

### Scope

uTURN carries both internal (client-to-client) and external (client-to-peer) traffic over the one UDP port it listens on, so there is a single port to expose rather than a relay port range. That matters anywhere a port range is awkward — Kubernetes Services, restrictive firewalls, a single NAT port forward. (For the Kubernetes case specifically, see the STUNner comparison in the README: STUNner terminates TURN at the cluster edge and relies on pod networking for the media path, where uTURN keeps that path on its single port.)

That single shared relay address is what makes the design WebRTC-specific. With one address for every client, a client-to-client packet's destination says nothing about which peer it is for, so the pairing has to be inferred from the payload: uTURN routes by the **ICE ufrag** in the STUN USERNAME (see [Relay Engine](#5-relay-engine)). Both sides must therefore be ICE agents. Client-to-external-peer relaying takes the ordinary RFC 5766 path and is not ufrag-dependent, so a generic TURN client works there.

### Deviation from the TURN spec

The shared relay address is not an unimplemented feature, it is a deliberate deviation. RFC 5766 Section 5 requires:

> Both the relayed transport address and the 5-tuple MUST be unique across all allocations, so either one can be used to uniquely identify the allocation.

RFC 8656 Section 6 carries the same requirement forward for the relayed transport address. uTURN honours the 5-tuple half — a client is still identified by its source address — and gives up the other half. Everything else in this document follows from that: with one relayed transport address shared by every allocation, a packet arriving for that address cannot be attributed to an allocation by its destination, so the pairing has to come from the payload, which is what the ICE ufrag provides and why both parties must be ICE agents.

This is the objection raised against single-port TURN in [pion/turn#284](https://github.com/pion/turn/issues/284), where the same thread also sketches the way out that uTURN takes: track the ICE connectivity checks and derive the pairing from them.

### Scaling

All allocation state lives in this process (`AllocationTable`'s `DashMap`s; there is no shared store), and client-to-client relaying resolves both parties inside one instance. So an instance is the unit of consistency: every participant of a call must reach the same one.

This rules out putting several replicas behind one load-balanced address. Kubernetes Services in particular pick "a backend Pod at random" by default; `sessionAffinity: ClientIP` pins each client to a pod, but two clients have two source IPs and may still be pinned to different pods, and neither would see the other's ufrag registration. Scale out by adding instances with their own addresses and directing a whole call to one of them.

Deliberately out of scope: TCP transport, TURNS (TLS/DTLS), per-allocation relay addresses, and any form of clustering.

## System Architecture

```
                                    ┌─────────────────────────────────────┐
                                    │            uTURN Server             │
                                    │                                     │
 ┌──────────┐                       │  ┌───────────────────────────────┐  │
 │  Client  │◄──────────────────────┼─►│         UDP Socket            │  │
 │    A     │    TURN control +     │  │          :3478                │  │
 └──────────┘    relayed media      │  └──────────────┬────────────────┘  │
                                    │                 │                   │
 ┌──────────┐                       │                 ▼                   │
 │  Client  │◄──────────────────────┼─►│  ┌───────────────────────────┐  │
 │    B     │                       │  │  │       Demultiplexer       │  │
 └──────────┘                       │  │  │                           │  │
                                    │  │  │  ┌─────┐ ┌─────┐ ┌─────┐  │  │
 ┌──────────┐                       │  │  │  │STUN │ │DTLS │ │ RTP │  │  │
 │  Peer    │───────────────────────┼─►│  │  └──┬──┘ └──┬──┘ └──┬──┘  │  │
 │  (media) │   media to relay      │  │  │     │       │       │     │  │
 └──────────┘                       │  │  └─────┴───────┴───────┴─────┘  │
                                    │                 │                   │
                                    │                 ▼                   │
                                    │  ┌───────────────────────────────┐  │
                                    │  │     Allocation Manager        │  │
                                    │  │                               │  │
                                    │  │  ┌─────────────────────────┐  │  │
                                    │  │  │ Allocation 1 (Client A) │  │  │
                                    │  │  │ - permissions           │  │  │
                                    │  │  │ - channels              │  │  │
                                    │  │  │ - ice_ufrag             │  │  │
                                    │  │  │ - ice_remote_ufrag      │  │  │
                                    │  │  └─────────────────────────┘  │  │
                                    │  │  ┌─────────────────────────┐  │  │
                                    │  │  │ Allocation 2 (Client B) │  │  │
                                    │  │  │ - ...                   │  │  │
                                    │  │  └─────────────────────────┘  │  │
                                    │  └───────────────────────────────┘  │
                                    └─────────────────────────────────────┘
```

## Core Components

### 1. UDP Socket Layer

Single socket bound to the configured port (default 3478).

The server binds a single `tokio::net::UdpSocket` (via `socket2` so receive/send
buffers can be raised). All packets (STUN, TURN, RTP, DTLS) arrive here and are
dispatched to the demultiplexer.

The relay address advertised to clients is `external_ip:port`. If no external
IP is configured, `discover.rs` detects it once at startup, before the socket
is bound: it sends a STUN Binding request from a separate ephemeral IPv4 socket
to every configured STUN server in parallel (default: Google and Cloudflare)
and takes the first valid XOR-MAPPED-ADDRESS. DNS resolution and retransmits
share a single 5 s deadline; if no server answers, startup fails rather than
advertising a wrong address. The result is the *egress* IP, so deployments
where ingress differs (cloud LoadBalancer, separate NAT gateway) must set it
explicitly.

### 2. Demultiplexer

Identifies packet type and routes to appropriate handler.

```rust
pub enum PacketType {
    Stun(StunMessage),
    Dtls(Vec<u8>),
    Rtp(RtpHeader, Vec<u8>),
    Rtcp(Vec<u8>),
    TurnChannelData(u16, Vec<u8>),  // channel_id, data
    Unknown,
}

impl Demuxer {
    pub fn classify(data: &[u8]) -> PacketType {
        match data.first() {
            Some(0..=3) => Self::parse_stun(data),
            Some(20..=63) => PacketType::Dtls(data.to_vec()),
            Some(64..=127) => Self::parse_channel_data(data),
            Some(128..=191) => Self::parse_rtp_rtcp(data),
            _ => PacketType::Unknown,
        }
    }
}
```

#### Protocol Detection (RFC 7983)

| First Byte | Protocol |
|------------|----------|
| 0-3 | STUN |
| 20-63 | DTLS |
| 64-127 | TURN ChannelData (TURN channel numbers 0x4000-0x7FFF) |
| 128-191 | RTP or RTCP |

#### STUN Session Identification (ICE Ufrag Pairing)

STUN Binding Requests contain USERNAME attribute: `remoteUfrag:localUfrag`

Each allocation learns its ICE credentials from STUN messages and uses **bi-directional matching** to find its peer:

```rust
// Extract ufrags from STUN USERNAME attribute
fn extract_stun_ufrags(data: &[u8]) -> Option<(String, String)> {
    // Parse USERNAME attribute (type 0x0006)
    // Format: "remoteUfrag:localUfrag"
    // Returns (remote_ufrag, local_ufrag)
}

// Bi-directional matching: find allocations where their
// (local, remote) matches our (remote, local)
fn find_ice_peers(sender_local: &str, sender_remote: &str) -> Vec<AllocationId> {
    // If sender has local=X, remote=Y
    // Find peers with local=Y, remote=X
}
```

The ICE ufrag pairing is learned atomically on the first STUN Binding Request using DashMap's entry API. The claim is first-come-first-served across *different* allocations: the first allocation to register a given ICE ufrag owns it, and a later registration of the same ufrag by another allocation is refused. The *same* allocation may update its ufrags (ICE restart). This makes the pairing stable, but it is **not** bound to the authenticated TURN username — see the Security Considerations section for what that means for trust.

### 3. Allocation Manager

Tracks all active TURN allocations and their state.

```rust
pub struct AllocationTable {
    // Primary lookup: client address → allocation
    by_client: DashMap<SocketAddr, AllocationId>,

    // Reverse lookups for demuxing
    by_ice_ufrag: DashMap<String, AllocationId>,     // ICE local ufrag
    by_permission: DashMap<IpAddr, Vec<AllocationId>>,  // Permission-based
    by_peer_tuple: DashMap<SocketAddr, AllocationId>, // Direct peer lookup

    allocations: DashMap<AllocationId, Allocation>,
}

pub struct Allocation {
    id: AllocationId,
    client_addr: SocketAddr,
    relay_addr: SocketAddr,  // Always external_ip:listen_port

    // TURN credentials
    ufrag: String,

    // ICE credentials (learned from STUN Binding Requests)
    ice_ufrag: RwLock<Option<String>>,         // This allocation's ICE ufrag
    ice_remote_ufrag: RwLock<Option<String>>,  // Remote peer's ICE ufrag

    // TURN state
    permissions: RwLock<HashMap<IpAddr, u64>>,  // peer IP → expires_ms (RFC 5766 §9, 5 min)
    channels: DashMap<u16, ChannelBinding>,     // channel_id → peer + expires_ms (§11, 10 min)

    // Lifetime management
    expires_at: RwLock<Instant>,
    last_activity: AtomicU64,
}
```

### 4. STUN/TURN Message Handler

Processes TURN protocol messages.

```rust
pub enum TurnRequest {
    Allocate,
    Refresh { lifetime: u32 },
    CreatePermission { peers: Vec<IpAddr> },
    ChannelBind { channel: u16, peer: SocketAddr },
    Send { peer: SocketAddr, data: Vec<u8> },
}

impl TurnHandler {
    pub async fn handle(&self,
        req: TurnRequest,
        client: SocketAddr,
        alloc_mgr: &mut AllocationManager
    ) -> TurnResponse;
}
```

### 5. Relay Engine

Forwards media between peers and clients using targeted ICE ufrag-based routing.
Media, DTLS and ICE connectivity checks are routed to the specific ufrag-matched
peer, or dropped if no match exists — no broadcast — which prevents cross-talk
between unrelated calls.

STUN *responses* from a client (`handle_client_response`) carry no USERNAME, so
routing uses the sender's already-registered ICE ufrag pair (`find_ice_peers`).
If the sender has not registered ICE credentials yet, the response is dropped
rather than permission-IP fanout (which would cross-talk between calls that share
peer IPs in single-port mode).

**ChannelData routing (STUN)** — 3-tier targeted routing:

```rust
// Tier 1: Targeted send via USERNAME attribute (STUN Binding Requests)
if let Some((remote_ufrag, local_ufrag)) = extract_stun_ufrags(data) {
    register_ice_ufrags(alloc.id, local_ufrag, remote_ufrag);
    if let Some(target) = lookup_by_ice_ufrag(&remote_ufrag) {
        send_to(target);  // Targeted delivery
    }
}
// Tier 2: ICE peer matching (STUN responses without USERNAME)
if !sent {
    let peers = find_ice_peers(sender_local, sender_remote);
    send_to(peers);  // Targeted delivery
}
// Tier 3: Drop (ufrags registered via Send Indication before channel binding)
```

**ChannelData routing (RTP/DTLS)** — ufrag match or drop:

```rust
let peers = find_ice_peers(sender_local, sender_remote);
if !peers.is_empty() {
    relay_to_listeners(data, peers);  // Targeted delivery
} else {
    drop;  // No broadcast fallback
}
```

**Send Indication routing** — targeted, or drop:

```rust
// ICE checks arrive here before channel binding. Register ufrags and
// route to the one target named by the check's USERNAME. If that target
// has not registered yet, drop: STUN retransmits the check (RFC 5389
// §7.2.1) and a later copy routes once the peer is up. No broadcast.
if is_stun_binding_request(data) {
    register_ice_ufrags(alloc.id, local_ufrag, remote_ufrag);
    if let Some(target) = lookup_by_ice_ufrag(&remote_ufrag) {
        send_to(target);  // Targeted delivery
    }
}
if !sent { find_ice_peers() → send_to(peers); }
if !sent { drop; }
```

The same holds for the ICE check that arrives as a direct STUN Binding
Request (`handle_binding_request`): it is delivered only to the allocation
whose ICE ufrag the USERNAME names, or dropped. A check's USERNAME carries
both ufrags of the call, so delivering it to any other client would disclose
that pair — and because ufrag registration is first-come-first-served, a
disclosed pair is enough to hijack the call's routing. See the Security
Considerations section.

**Peer → Client relay:**

```rust
// Check for channel binding (more efficient) or use Data Indication
if let Some(channel) = allocation.channel_for_peer(peer_addr) {
    send_channel_data(channel, data, allocation.client_addr);
} else {
    send_data_indication(peer_addr, data, allocation.client_addr);
}
```

## Packet Flow

### Client Allocation

```
Client                              uTURN
   │                                  │
   │──── Allocate Request ───────────►│
   │                                  │ Create allocation
   │                                  │ Generate ufrag
   │◄─── Allocate Response ───────────│ (relay = external:3478)
   │     (XOR-RELAYED-ADDRESS)        │
   │                                  │
   │──── CreatePermission ───────────►│
   │     (peer IPs)                   │ Store permissions
   │◄─── Success ─────────────────────│
   │                                  │
```

### Media Relay (Peer → Client)

```
Peer                    uTURN                         Client
  │                       │                              │
  │─── RTP packet ───────►│                              │
  │    (to :3478)         │                              │
  │                       │ Demux:                       │
  │                       │ 1. First byte → RTP          │
  │                       │ 2. Lookup by peer tuple      │
  │                       │ 3. Or lookup by ICE pairing  │
  │                       │ 4. Check permission          │
  │                       │                              │
  │                       │─── Data Indication ─────────►│
  │                       │    (or ChannelData)          │
  │                       │                              │
```

### Demux Decision Tree

```
Packet arrives from (ip, port)
           │
           ▼
    ┌──────────────┐
    │ Parse first  │
    │    byte      │
    └──────┬───────┘
           │
     ┌─────┴─────┬─────────────┬────────────┐
     ▼           ▼             ▼            ▼
   STUN       DTLS           RTP      ChannelData
     │           │             │            │
     ▼           │             │            ▼
 ┌────────┐      │             │       ┌─────────┐
 │ Parse  │      │             │       │ Channel │
 │ ufrag  │      │             │       │   ID    │
 └───┬────┘      │             │       └────┬────┘
     │           │             │            │
     ▼           │             │            │
 ┌────────────┐  │             │            │
 │ Learn ICE  │  │             │            │
 │ pair for   │  │             │            │
 │ allocation │  │             │            │
 └───┬────────┘  │             │            │
     │           │             │            │
     └───────────┴─────────────┴────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Lookup by:      │
              │ 1. src (ip,port)│ ◄── fast path
              │ 2. ICE ufrag    │ ◄── bi-directional
              │    pairing      │     matching
              │ 3. channel ID   │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Allocation    │
              │     found?      │
              └────────┬────────┘
                    Y/ \N
                    /   \
                   ▼     ▼
              Process   Drop
```

## Single-Port Routing with ICE Ufrag Pairing

### The Problem

In single-port TURN, all clients share the same relay address (`external_ip:port`). When a peer sends media to this address, we must determine which client should receive it.

**Without proper routing:** If multiple clients have `CreatePermission` for the same peer IP, data gets duplicated to all of them, causing bandwidth multiplication.

### The Solution: ICE Ufrag Bi-Directional Matching

WebRTC ICE connectivity checks use STUN Binding Requests with a USERNAME attribute formatted as `remoteUfrag:localUfrag`. Each side of a connection uses complementary credentials:

```
Client A (sender):   local=X, remote=Y  →  USERNAME="Y:X"
Client B (receiver): local=Y, remote=X  →  USERNAME="X:Y"
```

When Client A sends a STUN Binding Request, we:
1. Extract `(remote_ufrag=Y, local_ufrag=X)` from USERNAME
2. Register `ice_ufrag=X` and `ice_remote_ufrag=Y` on Client A's allocation
3. Look for allocations where `ice_ufrag=Y` and `ice_remote_ufrag=X` (the inverse)
4. Found match = Client B is Client A's peer

### Registration Timing

ICE connectivity checks arrive via **Send Indication** (before channel binding is established).
The Send Indication handler parses STUN Binding Requests from the relayed data and registers
ICE ufrags. This ensures ufrags are available by the time media flows via ChannelData.

### Atomic Registration

Registration uses DashMap's entry API to ensure each ICE ufrag is claimed exactly once:

```rust
match self.by_ice_ufrag.entry(local_ufrag) {
    Entry::Occupied(_) => false,  // Already claimed by another allocation
    Entry::Vacant(entry) => {
        // First one wins - register atomically
        entry.insert(id);
        // Also register in pair index for O(1) bidirectional lookup
        self.by_ice_ufrag_pair.insert((local, remote), id);
        true
    }
}
```

### No Broadcast Routing

All client-to-client packet types (STUN connectivity checks, DTLS, RTP) are routed
exclusively to the ufrag-matched peer. When no peer matches — including the very
first check of a call, before the addressed peer has registered its ufrag — the
packet is dropped, not broadcast; STUN retransmission (RFC 5389 §7.2.1) recovers
the setup case. This eliminates cross-talk between concurrent unrelated calls and,
because a check's USERNAME carries the call's ufrag pair, avoids disclosing it to
unrelated clients.

(The one exception is the relayed STUN *response* path noted under the Relay
Engine, which still fans out by source-IP permission and carries no ufrag pair.)

## State Machine

### Allocation Lifecycle

```
                    ┌──────────────┐
                    │   Initial    │
                    └──────┬───────┘
                           │ Allocate Request
                           ▼
                    ┌──────────────┐
                    │  Allocated   │◄─────────────┐
                    └──────┬───────┘              │
                           │                      │
           ┌───────────────┼───────────────┐      │
           │               │               │      │
           ▼               ▼               ▼      │
    ┌────────────┐  ┌────────────┐  ┌──────────┐  │
    │ Permission │  │  Channel   │  │ Refresh  │──┘
    │   Added    │  │   Bound    │  │          │
    └────────────┘  └────────────┘  └──────────┘
                           │
                           │ Timeout / Refresh(0)
                           ▼
                    ┌──────────────┐
                    │   Expired    │
                    └──────────────┘
```

## Module Structure

```
uturn/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point, CLI
│   ├── lib.rs               # Library root
│   ├── config.rs            # Configuration
│   ├── server.rs            # Main server loop, packet dispatch
│   ├── coarse_time.rs       # Low-overhead monotonic timestamps
│   ├── discover.rs          # External IP auto-detection via STUN
│   │
│   ├── transport/
│   │   ├── mod.rs
│   │   └── udp.rs           # UDP socket handling
│   │
│   ├── demux/
│   │   ├── mod.rs           # Demultiplexer
│   │   ├── protocol.rs      # Protocol detection (RFC 7983)
│   │   ├── stun.rs          # STUN message parsing
│   │   └── rtp.rs           # RTP/RTCP header parsing
│   │
│   ├── turn/
│   │   ├── mod.rs
│   │   ├── message.rs       # TURN message types
│   │   ├── handler.rs       # Request/response handling + Send Indication routing
│   │   └── auth.rs          # Long-term credentials
│   │
│   ├── relay/
│   │   ├── mod.rs
│   │   └── engine.rs        # Media relay logic (ufrag-based routing)
│   │
│   └── lookup/
│       ├── mod.rs
│       ├── table.rs         # Allocation table & ICE ufrag indexes
│       └── rate_limit.rs    # Per-client rate limiting
│
└── test-webrtc/
    └── webrtc-test.html     # Browser-based WebRTC test page
```

## Performance Considerations

### Fast Path

For established flows, use source tuple `(ip, port)` for O(1) lookup:

```rust
// Hot path: check source tuple first
if let Some(alloc_id) = self.by_source.get(&src_addr) {
    return self.allocations.get(alloc_id);
}

// Cold path: parse packet, extract identifiers
let packet_type = Demuxer::classify(data);
// ...
```

### Lock-Free Where Possible

Use concurrent data structures for lookup tables:

```rust
use dashmap::DashMap;

struct AllocationManager {
    by_source: DashMap<SocketAddr, AllocationId>,
    by_ufrag: DashMap<String, AllocationId>,
    // ...
}
```

## Security Considerations

1. **Authentication**: Long-term credentials (RFC 5389), verified by
   MESSAGE-INTEGRITY on every request. Passwords come either from static
   `--user` entries, which are shared across clients unless the deployment
   issues per-user ones, or are derived from a shared secret for time-limited
   TURN REST API usernames (`<expiry>:<id>`, see README). An expired REST
   username is rejected on every request, Refresh included, so an allocation
   outlives its credentials by at most one allocation lifetime (60s).
2. **Permissions**: Peer permissions are enforced with a 5-minute lifetime
   refreshed by CreatePermission/ChannelBind (RFC 5766 §9), but note they
   provide **little isolation between calls in single-port mode**: every client
   shares one relay address and auto-grants a permission for it, so all clients
   permit the same target. Separation between concurrent calls rests on ICE
   ufrag routing, not on permissions.
3. **Rate limiting**: Per-IP allocation quota and request rate. There is no
   global allocation cap, and quotas key on the full IP, so an actor with an
   IPv6 prefix has many independent quotas.
4. **Amplification / SSRF**: Loopback, multicast, broadcast, link-local (incl.
   cloud metadata) and the relay host's other ports are refused as peers.
   Private ranges (RFC 1918, ULA, CGNAT) are **allowed by default** — intended
   for on-prem/lab use, but it means a client can reach private networks the
   relay host can see.

### Trust model and known limitation

The single-port design routes client-to-client traffic by **ICE ufrag**, a
label the client asserts in the STUN USERNAME. That claim is **not
authenticated**: `register_ice_ufrags` is first-come-first-served and is not
bound to the authenticated TURN username. The MESSAGE-INTEGRITY on the inner ICE
check is keyed with the ICE password, which this server does not hold, so it
cannot verify the claim.

Consequence: a party that knows a call's ufrag — a leaked/observed SDP, an
on-path observer, or the call's own counterparty — can claim it before the real
peer and take over that call's routing (the real peer's own registration then
loses the race and its media is dropped). Media stays confidential regardless,
because DTLS-SRTP is end-to-end and its certificate is pinned by the SDP
fingerprint; the exposure is hijack, denial of service, and metadata, not
plaintext. ICE ufrags are regenerated per call, so a stolen ufrag is a
single-call, single-use capability, not a durable key.

Not fixed by ufrag routing alone. Closing it requires verifying the claim —
e.g. call-scoped ephemeral credentials carrying a call id, giving the server the
ICE password, or handing each allocation its own relay address (removing the
need to infer pairing at all). Until then, deployments should treat ufrag
secrecy as best-effort and rely on DTLS-SRTP for confidentiality.

Not yet implemented: TURNS (TLS/DTLS), so on-path observers can read STUN
USERNAMEs and see who talks to whom.

## Future Extensions

- **TCP TURN**: Tunnel over TCP for restrictive firewalls
- **TURNS**: TLS encryption
- **Metrics**: Prometheus endpoint
- **Clustering**: Distributed allocation state
