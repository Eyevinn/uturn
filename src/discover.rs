//! Public IP auto-detection via STUN Binding requests.
//!
//! Used at startup when no external IP is configured. A Binding request is sent
//! to every configured STUN server at once (from one ephemeral IPv4 socket), and
//! the XOR-MAPPED-ADDRESS of the first valid response is taken as our public IP.
//! Querying independent operators in parallel means one of them being down or
//! slow does not delay startup.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::net::UdpSocket;
use tokio::time::{timeout_at, Instant};
use tracing::{debug, info, warn};

use crate::demux::stun::{StunInfo, STUN_MAGIC_COOKIE};

/// Default STUN servers, run by two independent operators.
pub const DEFAULT_STUN_SERVERS: &[&str] = &["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// Binding request message type (method 0x001, class request).
const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response message type.
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Interval between retransmissions of the Binding requests.
const RETRANSMIT_INTERVAL: Duration = Duration::from_millis(500);

/// Discover our public IPv4 address by asking the given STUN servers.
///
/// Returns the mapped address of the first server to answer. Fails if none
/// answers within `total_timeout`.
pub async fn discover_public_ip(servers: &[String], total_timeout: Duration) -> Result<IpAddr> {
    // The deadline covers DNS resolution too, so a hung resolver cannot stall
    // startup past `total_timeout`.
    let deadline = Instant::now() + total_timeout;
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await?;

    // Resolve all servers concurrently.
    let mut lookups = tokio::task::JoinSet::new();
    for server in servers {
        let server = server.trim().to_string();
        lookups.spawn(async move {
            let res = tokio::net::lookup_host(server.as_str())
                .await
                .map(|addrs| addrs.collect::<Vec<_>>());
            (server, res)
        });
    }
    let mut targets: Vec<(String, SocketAddr, [u8; 12])> = Vec::new();
    while let Ok(Some(joined)) = timeout_at(deadline, lookups.join_next()).await {
        let Ok((server, res)) = joined else { continue };
        match res {
            Ok(addrs) => match addrs.into_iter().find(SocketAddr::is_ipv4) {
                Some(addr) => targets.push((server, addr, rand::random())),
                None => warn!("STUN server {} has no IPv4 address", server),
            },
            Err(e) => warn!("Could not resolve STUN server {}: {}", server, e),
        }
    }
    lookups.abort_all();
    if targets.is_empty() {
        bail!("none of the STUN servers could be resolved");
    }

    let mut buf = [0u8; 1500];

    while Instant::now() < deadline {
        for (name, addr, tid) in &targets {
            if let Err(e) = socket.send_to(&binding_request(tid), addr).await {
                debug!("STUN request to {} ({}) failed: {}", name, addr, e);
            }
        }

        let round_end = (Instant::now() + RETRANSMIT_INTERVAL).min(deadline);
        loop {
            let len = match timeout_at(round_end, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) => len,
                Ok(Err(e)) => {
                    debug!("STUN recv error: {}", e);
                    continue;
                }
                Err(_) => break, // round timed out, retransmit
            };
            // Match on transaction ID rather than source address: a server may
            // answer from a different address than the one we resolved.
            let found = targets.iter().find_map(|(name, _, tid)| {
                parse_binding_response(&buf[..len], tid).map(|mapped| (name, mapped))
            });
            if let Some((name, mapped)) = found {
                let ip = mapped.ip();
                if !ip.is_ipv4() || ip.is_unspecified() {
                    debug!("Ignoring unusable mapped address {} from {}", ip, name);
                    continue;
                }
                info!("Detected public IP {} via STUN server {}", ip, name);
                return Ok(ip);
            }
        }
    }

    bail!(
        "no STUN server answered within {:?} ({})",
        total_timeout,
        servers.join(", ")
    )
}

/// Build a bare STUN Binding request (RFC 5389, no attributes).
fn binding_request(tid: &[u8; 12]) -> [u8; 20] {
    let mut msg = [0u8; 20];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Length stays 0.
    msg[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(tid);
    msg
}

/// Extract XOR-MAPPED-ADDRESS from a Binding success response with the given
/// transaction ID.
fn parse_binding_response(data: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 20
        || u16::from_be_bytes([data[0], data[1]]) != BINDING_SUCCESS
        || u32::from_be_bytes([data[4], data[5], data[6], data[7]]) != STUN_MAGIC_COOKIE
        || &data[8..20] != tid
    {
        return None;
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let attrs = data.get(20..20 + len)?;

    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        let value = attrs.get(offset + 4..offset + 4 + attr_len)?;
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return StunInfo::decode_xor_address(value, tid);
        }
        offset += 4 + ((attr_len + 3) & !3);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn response(tid: &[u8; 12], ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes()); // fixed up below
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(tid);
        // An unrelated attribute first, to exercise the attribute walk.
        msg.extend_from_slice(&[0x80, 0x22, 0x00, 0x00]); // SOFTWARE, empty
        msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        msg.extend_from_slice(&8u16.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        msg.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        for (b, c) in ip.octets().iter().zip(cookie) {
            msg.push(b ^ c);
        }
        let attr_len = (msg.len() - 20) as u16;
        msg[2..4].copy_from_slice(&attr_len.to_be_bytes());
        msg
    }

    #[test]
    fn parses_xor_mapped_address() {
        let tid = [7u8; 12];
        let ip = Ipv4Addr::new(203, 0, 113, 10);
        let msg = response(&tid, ip, 54321);
        assert_eq!(
            parse_binding_response(&msg, &tid),
            Some(SocketAddr::new(IpAddr::V4(ip), 54321))
        );
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let msg = response(&[7u8; 12], Ipv4Addr::new(203, 0, 113, 10), 1);
        assert_eq!(parse_binding_response(&msg, &[8u8; 12]), None);
    }

    #[test]
    fn rejects_truncated_and_non_success() {
        let tid = [1u8; 12];
        let mut msg = response(&tid, Ipv4Addr::new(192, 0, 2, 1), 1);
        assert_eq!(parse_binding_response(&msg[..msg.len() - 2], &tid), None);
        msg[0..2].copy_from_slice(&0x0111u16.to_be_bytes()); // error response
        assert_eq!(parse_binding_response(&msg, &tid), None);
    }

    #[test]
    fn request_is_well_formed() {
        let tid = [3u8; 12];
        let req = binding_request(&tid);
        let info = StunInfo::parse(&req).unwrap();
        assert_eq!(info.transaction_id, tid);
        assert_eq!(info.method, crate::demux::stun::StunMethod::Binding);
        assert_eq!(info.class, crate::demux::stun::StunClass::Request);
    }
}
