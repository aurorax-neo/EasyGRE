use std::net::Ipv4Addr;

use crate::packet::{internet_checksum, parse_outer_ipv4, write_ipv4_header};

pub const IPPROTO_GRE: u8 = 47;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const GRE_PT_KEEPALIVE: u16 = 0x0000;

const GRE_FLAG_CSUM: u16 = 0x8000;
const GRE_FLAG_ROUTING: u16 = 0x4000;
const GRE_FLAG_KEY: u16 = 0x2000;
const GRE_FLAG_SEQ: u16 = 0x1000;
const GRE_RESERVED_MASK: u16 = 0x0ff8;
const GRE_VERSION_MASK: u16 = 0x0007;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GreDecoded<'a> {
    /// Normal encapsulated IPv4/IPv6 data packet.
    Data { protocol: u16, payload: &'a [u8] },
    /// Incoming keepalive echo request (GRE-in-GRE with inner PT=0x0000).
    /// `learned_public_ip` is extracted from inner IPv4 source address (what remote considers our public IP).
    KeepaliveRequest {
        learned_public_ip: Ipv4Addr,
        echo_token: Option<[u8; 4]>,
        inner_packet: &'a [u8],
    },
    /// Incoming keepalive echo reply (outer GRE PT=0x0000).
    KeepaliveReply {
        echo_token: Option<[u8; 4]>,
        body_len: usize,
    },
    /// Unsupported or ignored protocol type (e.g. non-IP ethertype).
    Unsupported(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GreHeader {
    pub flags_ver: u16,
    pub protocol: u16,
    pub header_len: usize,
}

/// Parse RFC 2784 / 2890 GRE header, validating optional checksum if C=1.
pub fn parse_gre_header(buf: &[u8]) -> Option<GreHeader> {
    if buf.len() < 4 {
        return None;
    }
    let flags_ver = u16::from_be_bytes([buf[0], buf[1]]);
    if (flags_ver & GRE_VERSION_MASK) != 0 {
        // Only standard GRE version 0 (not PPTP GREv1)
        return None;
    }
    // Reject obsolete Routing (R=1), unconfigured Keyed GRE (K=1), and non-zero RFC 2784 Reserved0 bits
    if (flags_ver & (GRE_FLAG_ROUTING | GRE_FLAG_KEY | GRE_RESERVED_MASK)) != 0 {
        return None;
    }
    let protocol = u16::from_be_bytes([buf[2], buf[3]]);
    let mut offset = 4usize;
    let has_csum = (flags_ver & GRE_FLAG_CSUM) != 0;
    if has_csum {
        if buf.len() < offset + 4 {
            return None;
        }
        if internet_checksum(buf) != 0 {
            return None;
        }
        offset += 4;
    }
    if (flags_ver & GRE_FLAG_SEQ) != 0 {
        offset += 4;
    }
    if buf.len() < offset {
        return None;
    }
    Some(GreHeader {
        flags_ver,
        protocol,
        header_len: offset,
    })
}

/// Decode an inbound GRE payload (after outer IPv4 header has been stripped).
pub fn decode_gre_payload(gre_buf: &[u8]) -> Option<GreDecoded<'_>> {
    let hdr = parse_gre_header(gre_buf)?;
    let body = &gre_buf[hdr.header_len..];
    match hdr.protocol {
        GRE_PT_KEEPALIVE => {
            let echo_token = if body.len() >= 4 {
                Some([body[0], body[1], body[2], body[3]])
            } else {
                None
            };
            Some(GreDecoded::KeepaliveReply {
                echo_token,
                body_len: body.len(),
            })
        }
        ETHERTYPE_IPV4 => {
            // Check if this is a GRE-in-GRE keepalive probe:
            // Inner IPv4 (proto=47) + Inner GRE (PT=0x0000)
            if let Some(inner_ip) = parse_outer_ipv4(body) {
                if inner_ip.proto == IPPROTO_GRE {
                    if let Some(inner_gre) = parse_gre_header(inner_ip.payload) {
                        if inner_gre.protocol == GRE_PT_KEEPALIVE {
                            let inner_body = &inner_ip.payload[inner_gre.header_len..];
                            let echo_token = if inner_body.len() >= 4 {
                                Some([
                                    inner_body[0],
                                    inner_body[1],
                                    inner_body[2],
                                    inner_body[3],
                                ])
                            } else {
                                None
                            };
                            return Some(GreDecoded::KeepaliveRequest {
                                learned_public_ip: inner_ip.src,
                                echo_token,
                                inner_packet: body,
                            });
                        }
                    }
                }
            }
            Some(GreDecoded::Data {
                protocol: ETHERTYPE_IPV4,
                payload: body,
            })
        }
        ETHERTYPE_IPV6 => Some(GreDecoded::Data {
            protocol: ETHERTYPE_IPV6,
            payload: body,
        }),
        other => Some(GreDecoded::Unsupported(other)),
    }
}

/// Write standard 4-byte RFC 2784 GRE header (`flags=0`, `protocol=0x0800|0x86DD`) followed by `inner`
/// into `out` buffer and return total written bytes.
#[cfg(test)]
pub fn encode_gre_packet(protocol: u16, inner: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 4 + inner.len();
    if out.len() < total {
        return None;
    }
    out[0] = 0x00;
    out[1] = 0x00;
    out[2..4].copy_from_slice(&protocol.to_be_bytes());
    out[4..total].copy_from_slice(inner);
    Some(total)
}

/// Build a 32-byte GRE-in-GRE keepalive request payload (to send over IPPROTO_GRE raw socket):
/// [Outer GRE: flags=0, PT=0x0800] + [Inner IPv4: src=remote_ip, dst=local_reply_ip, proto=47] + [Inner GRE: flags=0, PT=0x0000 + 4B zero pad]
///
/// Note: The 4-byte zero padding after Inner GRE ensures the resulting IPv4 keepalive reply
/// packet is 28 bytes (>= 20 + 8 bytes), avoiding silent drops by Linux `nf_nat` (`gre_manip_pkt`).
pub fn build_keepalive_request_with_token(
    remote_ip: Ipv4Addr,
    local_reply_ip: Ipv4Addr,
    seq_id: u16,
    token: u32,
) -> [u8; 32] {
    let mut buf = [0u8; 32];
    // Outer GRE header: PT = 0x0800
    buf[0] = 0x00;
    buf[1] = 0x00;
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    // Inner IPv4 header: 20 bytes + 8 bytes inner GRE (with 4B probe token) = 28 bytes total
    write_ipv4_header(
        &mut buf[4..24],
        remote_ip,
        local_reply_ip,
        IPPROTO_GRE,
        seq_id,
        255,
        28,
    );
    // Inner GRE header (bytes 24..28 zero, PT=0x0000) + 4B correlation token (bytes 28..32)
    buf[28..32].copy_from_slice(&token.to_be_bytes());
    buf
}

/// Build 8-byte GRE keepalive reply payload (4B GRE PT=0x0000 + 4B echoed token/pad
/// to satisfy Linux `nf_nat` 8-byte minimum writable GRE check).
#[inline]
pub fn build_keepalive_reply(echo_token: Option<[u8; 4]>) -> [u8; 8] {
    let mut out = [0u8; 8];
    if let Some(tok) = echo_token {
        out[4..8].copy_from_slice(&tok);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_roundtrip() {
        let remote = Ipv4Addr::new(198, 51, 100, 2);
        let public_local = Ipv4Addr::new(203, 0, 113, 10);
        let req = build_keepalive_request_with_token(public_local, remote, 42, 0xdead_beef);
        // Simulate remote side receiving our probe: inner IPv4 src is public_local
        let echoed = match decode_gre_payload(&req).unwrap() {
            GreDecoded::KeepaliveRequest {
                learned_public_ip,
                echo_token,
                inner_packet,
            } => {
                assert_eq!(learned_public_ip, public_local);
                assert_eq!(echo_token, Some([0xde, 0xad, 0xbe, 0xef]));
                assert_eq!(inner_packet.len(), 28);
                echo_token
            }
            other => panic!("unexpected decode: {other:?}"),
        };

        let rep_pkt = build_keepalive_reply(echoed);
        match decode_gre_payload(&rep_pkt).unwrap() {
            GreDecoded::KeepaliveReply {
                echo_token,
                body_len,
            } => {
                assert_eq!(echo_token, Some([0xde, 0xad, 0xbe, 0xef]));
                assert_eq!(body_len, 4);
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn test_keyed_and_reserved_gre_flags_rejected() {
        let inner = [0x45u8, 0, 0, 20, 0, 1, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let mut keyed = vec![0u8; 8 + inner.len()];
        keyed[0..2].copy_from_slice(&GRE_FLAG_KEY.to_be_bytes());
        keyed[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        keyed[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        keyed[8..].copy_from_slice(&inner);
        assert!(decode_gre_payload(&keyed).is_none());

        let mut rsv = vec![0u8; 4 + inner.len()];
        rsv[0..2].copy_from_slice(&0x0010u16.to_be_bytes()); // Reserved0 bit set
        rsv[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        rsv[4..].copy_from_slice(&inner);
        assert!(decode_gre_payload(&rsv).is_none());
    }

    #[test]
    fn test_gre_with_checksum() {
        let inner = [0x45u8, 0, 0, 20, 0, 1, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        let mut pkt = vec![0u8; 8 + inner.len()];
        pkt[0..2].copy_from_slice(&GRE_FLAG_CSUM.to_be_bytes());
        pkt[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        pkt[8..].copy_from_slice(&inner);
        let csum = internet_checksum(&pkt);
        pkt[4..6].copy_from_slice(&csum.to_be_bytes());

        match decode_gre_payload(&pkt).unwrap() {
            GreDecoded::Data { protocol, payload } => {
                assert_eq!(protocol, ETHERTYPE_IPV4);
                assert_eq!(payload, &inner);
            }
            other => panic!("unexpected decode: {other:?}"),
        }

        // Corrupt checksum
        pkt[4] ^= 0xff;
        assert!(decode_gre_payload(&pkt).is_none());
    }

    #[test]
    fn test_ipv6_data_encode_decode() {
        let inner_v6 = [0x60u8; 40];
        let mut out = [0u8; 128];
        let n = encode_gre_packet(ETHERTYPE_IPV6, &inner_v6, &mut out).unwrap();
        assert_eq!(n, 44);
        match decode_gre_payload(&out[..n]).unwrap() {
            GreDecoded::Data { protocol, payload } => {
                assert_eq!(protocol, ETHERTYPE_IPV6);
                assert_eq!(payload, &inner_v6);
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    fn next_rng(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[test]
    fn test_fuzz_gre_parsers_no_panic_and_invariants() {
        let mut rng = 0x4561_7379_4752_4531u64;
        let mut buf = [0u8; 320];

        for iter in 0..50_000usize {
            let len = (next_rng(&mut rng) as usize) % (buf.len() + 1);
            for chunk in buf[..len].chunks_mut(8) {
                let r = next_rng(&mut rng).to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }

            // Mix pure random inputs with structured mutations of valid GRE / Keepalive frames
            if iter % 3 == 1 && len >= 32 {
                let ka = build_keepalive_request_with_token(
                    Ipv4Addr::from(next_rng(&mut rng) as u32),
                    Ipv4Addr::from(next_rng(&mut rng) as u32),
                    next_rng(&mut rng) as u16,
                    next_rng(&mut rng) as u32,
                );
                buf[..32].copy_from_slice(&ka);
                let flip_idx = (next_rng(&mut rng) as usize) % len;
                buf[flip_idx] ^= (next_rng(&mut rng) as u8) | 1;
            } else if iter % 3 == 2 && len >= 8 {
                // Valid C=1 or C=1|S=1 header with optional bit flip
                buf[0] = if (iter & 1) == 0 { 0x80 } else { 0x90 };
                buf[1] = 0x00;
                let proto = [0x0000u16, ETHERTYPE_IPV4, ETHERTYPE_IPV6, 0x8847][iter & 3];
                buf[2..4].copy_from_slice(&proto.to_be_bytes());
                buf[4..8].fill(0);
                let csum = internet_checksum(&buf[..len]);
                buf[4..6].copy_from_slice(&csum.to_be_bytes());
                if (iter & 4) != 0 {
                    let flip_idx = (next_rng(&mut rng) as usize) % len;
                    buf[flip_idx] ^= 1 << ((next_rng(&mut rng) as usize) & 7);
                }
            }

            let slice = &buf[..len];
            if let Some(hdr) = parse_gre_header(slice) {
                assert!(hdr.header_len >= 4 && hdr.header_len <= slice.len());
                assert_eq!(hdr.flags_ver & GRE_VERSION_MASK, 0);
                assert_eq!(
                    hdr.flags_ver & (GRE_FLAG_ROUTING | GRE_FLAG_KEY | GRE_RESERVED_MASK),
                    0
                );
                if (hdr.flags_ver & GRE_FLAG_CSUM) != 0 {
                    assert_eq!(internet_checksum(slice), 0);
                }
                let decoded = decode_gre_payload(slice).unwrap();
                if let GreDecoded::Data { payload, .. } = decoded {
                    assert_eq!(payload.len(), slice.len() - hdr.header_len);
                }
            } else {
                assert!(decode_gre_payload(slice).is_none());
            }
        }
    }
}
