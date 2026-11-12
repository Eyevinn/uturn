//! STUN message parsing for demultiplexing
//!
//! Extracts ICE username fragment (ufrag) for session identification.

use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// STUN magic cookie
pub const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN attribute types
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
const ATTR_LIFETIME: u16 = 0x000D;
const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_REALM: u16 = 0x0014;
const ATTR_NONCE: u16 = 0x0015;
const ATTR_REQUESTED_TRANSPORT: u16 = 0x0019;

/// Maximum attribute lengths per RFC 5389
const MAX_USERNAME_LEN: usize = 513;
const MAX_REALM_LEN: usize = 763;
const MAX_NONCE_LEN: usize = 763;

/// STUN message type classes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

/// STUN message type methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    Binding,
    Allocate,
    Refresh,
    Send,
    Data,
    CreatePermission,
    ChannelBind,
    Unknown(u16),
}

/// Parsed STUN information for demultiplexing
#[derive(Debug, Clone)]
pub struct StunInfo {
    /// Message class
    pub class: StunClass,

    /// Message method
    pub method: StunMethod,

    /// Transaction ID (96 bits)
    pub transaction_id: [u8; 12],

    /// USERNAME attribute (if present)
    /// Format: "serverUfrag:clientUfrag" for ICE
    pub username: Option<String>,

    /// XOR-PEER-ADDRESS attributes (for CreatePermission, ChannelBind, Send)
    pub xor_peer_addresses: Vec<SocketAddr>,

    /// CHANNEL-NUMBER attribute (for ChannelBind)
    pub channel_number: Option<u16>,

    /// LIFETIME attribute (for Allocate, Refresh)
    pub lifetime: Option<u32>,

    /// DATA attribute (for Send indication)
    pub data: Option<Vec<u8>>,

    /// REALM attribute (for authentication)
    pub realm: Option<String>,

    /// NONCE attribute (for authentication)
    pub nonce: Option<String>,

    /// MESSAGE-INTEGRITY attribute (HMAC-SHA1, 20 bytes)
    pub message_integrity: Option<Vec<u8>>,

    /// Offset where MESSAGE-INTEGRITY starts (for validation)
    pub message_integrity_offset: Option<usize>,

    /// REQUESTED-TRANSPORT attribute (protocol number, e.g., 17 for UDP)
    pub requested_transport: Option<u8>,

    /// Raw message bytes (shared; cheap to clone)
    pub raw: Bytes,
}

/// Intermediate structure for parsed attributes
struct ParsedAttrs {
    username: Option<String>,
    xor_peer_addresses: Vec<SocketAddr>,
    channel_number: Option<u16>,
    lifetime: Option<u32>,
    data: Option<Vec<u8>>,
    realm: Option<String>,
    nonce: Option<String>,
    message_integrity: Option<Vec<u8>>,
    message_integrity_offset: Option<usize>,
    requested_transport: Option<u8>,
}

impl StunInfo {
    /// Parse STUN message header and attributes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        // Check magic cookie
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if magic != STUN_MAGIC_COOKIE {
            return None;
        }

        // Parse message type (first 2 bytes)
        let msg_type = u16::from_be_bytes([data[0], data[1]]);

        // Extract class (bits 4, 8)
        let class_bits = ((msg_type >> 4) & 0x01) | ((msg_type >> 7) & 0x02);
        let class = match class_bits {
            0b00 => StunClass::Request,
            0b01 => StunClass::Indication,
            0b10 => StunClass::SuccessResponse,
            0b11 => StunClass::ErrorResponse,
            _ => return None,
        };

        // Extract method (bits 0-3, 5-7, 9-11)
        let method_bits =
            (msg_type & 0x000F) | ((msg_type >> 1) & 0x0070) | ((msg_type >> 2) & 0x0F80);
        let method = match method_bits {
            0x001 => StunMethod::Binding,
            0x003 => StunMethod::Allocate,
            0x004 => StunMethod::Refresh,
            0x006 => StunMethod::Send,
            0x007 => StunMethod::Data,
            0x008 => StunMethod::CreatePermission,
            0x009 => StunMethod::ChannelBind,
            other => StunMethod::Unknown(other),
        };

        // Message length
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 20 + msg_len {
            return None;
        }

        // Transaction ID (bytes 8-19)
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Parse all attributes
        let attrs = Self::parse_attributes(&data[20..20 + msg_len], &transaction_id);

        Some(Self {
            class,
            method,
            transaction_id,
            username: attrs.username,
            xor_peer_addresses: attrs.xor_peer_addresses,
            channel_number: attrs.channel_number,
            lifetime: attrs.lifetime,
            data: attrs.data,
            realm: attrs.realm,
            nonce: attrs.nonce,
            message_integrity: attrs.message_integrity,
            message_integrity_offset: attrs.message_integrity_offset,
            requested_transport: attrs.requested_transport,
            raw: Bytes::copy_from_slice(data),
        })
    }

    /// Parse all relevant attributes from STUN message
    fn parse_attributes(attrs: &[u8], transaction_id: &[u8; 12]) -> ParsedAttrs {
        let mut result = ParsedAttrs {
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
        };

        let mut offset = 0;

        while offset + 4 <= attrs.len() {
            let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
            let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;

            if offset + 4 + attr_len > attrs.len() {
                break;
            }

            let value = &attrs[offset + 4..offset + 4 + attr_len];

            match attr_type {
                ATTR_USERNAME
                    // RFC 5389: USERNAME must be less than 513 bytes
                    if value.len() <= MAX_USERNAME_LEN => {
                        result.username = String::from_utf8(value.to_vec()).ok();
                    }
                ATTR_XOR_PEER_ADDRESS => {
                    if let Some(addr) = Self::decode_xor_address(value, transaction_id) {
                        result.xor_peer_addresses.push(addr);
                    }
                }
                ATTR_CHANNEL_NUMBER
                    if value.len() >= 2 => {
                        let channel = u16::from_be_bytes([value[0], value[1]]);
                        // Valid channel range: 0x4000-0x7FFF
                        if (0x4000..=0x7FFF).contains(&channel) {
                            result.channel_number = Some(channel);
                        }
                    }
                ATTR_LIFETIME
                    if value.len() >= 4 => {
                        result.lifetime =
                            Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                    }
                ATTR_DATA => {
                    result.data = Some(value.to_vec());
                }
                ATTR_REALM
                    // RFC 5389: REALM must be less than 763 bytes
                    if value.len() <= MAX_REALM_LEN => {
                        result.realm = String::from_utf8(value.to_vec()).ok();
                    }
                ATTR_NONCE
                    // RFC 5389: NONCE must be less than 763 bytes
                    if value.len() <= MAX_NONCE_LEN => {
                        result.nonce = String::from_utf8(value.to_vec()).ok();
                    }
                ATTR_MESSAGE_INTEGRITY
                    if value.len() == 20 => {
                        result.message_integrity = Some(value.to_vec());
                        // Offset from start of attributes section + 20 bytes header
                        result.message_integrity_offset = Some(20 + offset);
                        // RFC 5389 §15.4: MESSAGE-INTEGRITY covers everything before
                        // it; any attribute after it (other than FINGERPRINT, which
                        // we do not use) MUST be ignored. Stop here so that nothing
                        // outside the HMAC-protected region can influence auth,
                        // permissions, channel bindings or lifetimes.
                        break;
                    }
                ATTR_REQUESTED_TRANSPORT
                    // REQUESTED-TRANSPORT is 4 bytes: protocol (1 byte) + RFFU (3 bytes)
                    if !value.is_empty() => {
                        result.requested_transport = Some(value[0]);
                    }
                _ => {}
            }

            // Move to next attribute (4-byte aligned)
            let padded_len = (attr_len + 3) & !3;
            offset += 4 + padded_len;
        }

        result
    }

    /// Decode XOR-PEER-ADDRESS or XOR-MAPPED-ADDRESS
    pub(crate) fn decode_xor_address(
        value: &[u8],
        transaction_id: &[u8; 12],
    ) -> Option<SocketAddr> {
        if value.len() < 8 {
            return None;
        }

        let family = value[1];

        // XOR port with upper 16 bits of magic cookie
        let xor_port = u16::from_be_bytes([value[2], value[3]]);
        let port = xor_port ^ 0x2112;

        match family {
            0x01 => {
                // IPv4
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                let ip = Ipv4Addr::new(
                    value[4] ^ magic[0],
                    value[5] ^ magic[1],
                    value[6] ^ magic[2],
                    value[7] ^ magic[3],
                );
                Some(SocketAddr::new(IpAddr::V4(ip), port))
            }
            0x02 => {
                // IPv6 - XOR with magic cookie + transaction ID
                if value.len() < 20 {
                    return None;
                }
                let magic = [0x21u8, 0x12, 0xa4, 0x42];
                let mut ip_bytes = [0u8; 16];
                for i in 0..4 {
                    ip_bytes[i] = value[4 + i] ^ magic[i];
                }
                for i in 0..12 {
                    ip_bytes[4 + i] = value[8 + i] ^ transaction_id[i];
                }
                let ip = std::net::Ipv6Addr::from(ip_bytes);
                Some(SocketAddr::new(IpAddr::V6(ip), port))
            }
            _ => None,
        }
    }

    /// Extract ufrag pair from USERNAME attribute
    ///
    /// ICE USERNAME format: "serverUfrag:clientUfrag"
    pub fn parse_ice_username(&self) -> Option<(String, String)> {
        let username = self.username.as_ref()?;
        let parts: Vec<&str> = username.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }

    /// Check if this is a TURN message (not just STUN binding)
    pub fn is_turn(&self) -> bool {
        matches!(
            self.method,
            StunMethod::Allocate
                | StunMethod::Refresh
                | StunMethod::Send
                | StunMethod::Data
                | StunMethod::CreatePermission
                | StunMethod::ChannelBind
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_binding_request() {
        let data = [
            0x00, 0x01, // Binding Request
            0x00, 0x00, // Length = 0
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0x01, 0x02, 0x03, 0x04, // Transaction ID
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];

        let info = StunInfo::parse(&data).unwrap();
        assert_eq!(info.class, StunClass::Request);
        assert_eq!(info.method, StunMethod::Binding);
    }

    #[test]
    fn test_parse_allocate_request() {
        let data = [
            0x00, 0x03, // Allocate Request
            0x00, 0x00, // Length = 0
            0x21, 0x12, 0xa4, 0x42, // Magic cookie
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];

        let info = StunInfo::parse(&data).unwrap();
        assert_eq!(info.method, StunMethod::Allocate);
        assert!(info.is_turn());
    }

    /// Build a minimal STUN message with the given attribute list.
    fn build_stun(msg_type: u16, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&msg_type.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        msg.extend_from_slice(&[0u8; 12]);
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn attributes_after_message_integrity_are_ignored() {
        // XOR-PEER-ADDRESS for 192.0.2.1:1234 (IPv4, XORed with magic cookie).
        let peer_before: Vec<u8> = {
            let mut v = vec![0x00, 0x01];
            v.extend_from_slice(&(1234u16 ^ 0x2112).to_be_bytes());
            for (b, m) in [192u8, 0, 2, 1].iter().zip([0x21u8, 0x12, 0xa4, 0x42]) {
                v.push(b ^ m);
            }
            v
        };
        // A second XOR-PEER-ADDRESS (192.0.2.2), a LIFETIME and a USERNAME appended
        // *after* MESSAGE-INTEGRITY, i.e. outside the HMAC-protected region.
        let peer_after: Vec<u8> = {
            let mut v = vec![0x00, 0x01];
            v.extend_from_slice(&(4321u16 ^ 0x2112).to_be_bytes());
            for (b, m) in [192u8, 0, 2, 2].iter().zip([0x21u8, 0x12, 0xa4, 0x42]) {
                v.push(b ^ m);
            }
            v
        };
        let hmac = [0xAAu8; 20];
        let msg = build_stun(
            0x0008, // CreatePermission request
            &[
                (0x0006, b"alice"),
                (0x0012, &peer_before),
                (0x0008, &hmac),
                (0x0012, &peer_after),
                (0x000D, &0u32.to_be_bytes()),
                (0x0006, b"mallory"),
            ],
        );

        let info = StunInfo::parse(&msg).unwrap();
        assert_eq!(info.message_integrity.as_deref(), Some(&hmac[..]));
        // Only the attributes covered by MESSAGE-INTEGRITY are visible.
        assert_eq!(info.username.as_deref(), Some("alice"));
        assert_eq!(info.xor_peer_addresses.len(), 1);
        assert_eq!(
            info.xor_peer_addresses[0],
            "192.0.2.1:1234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(info.lifetime, None);
    }

    #[test]
    fn test_parse_with_username() {
        let username = b"serverufrag:clientufrag";
        let padded_len = (username.len() + 3) & !3;

        let mut data = vec![
            0x00,
            0x01, // Binding Request
            0x00,
            (4 + padded_len) as u8, // Length
            0x21,
            0x12,
            0xa4,
            0x42, // Magic cookie
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            // USERNAME attribute
            0x00,
            0x06, // Type
            0x00,
            username.len() as u8, // Length
        ];
        data.extend_from_slice(username);
        // Add padding
        while data.len() < 20 + 4 + padded_len {
            data.push(0);
        }

        let info = StunInfo::parse(&data).unwrap();
        assert_eq!(info.username, Some("serverufrag:clientufrag".to_string()));

        let (server, client) = info.parse_ice_username().unwrap();
        assert_eq!(server, "serverufrag");
        assert_eq!(client, "clientufrag");
    }
}
