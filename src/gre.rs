use std::net::{Ipv4Addr, Ipv6Addr};

use crate::packet::{
    checksum_accumulate, checksum_finish, internet_checksum, parse_outer_ipv4, write_ipv4_header,
};

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_GRE: u8 = 47;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const GRE_PT_KEEPALIVE: u16 = 0x0000;

/// 4-byte signature prefix distinguishing EasyGRE keepalive probes from user ICMP/UDP traffic.
pub const KA_SIG_MAGIC: [u8; 4] = *b"EGRK";
pub const KA_ICMP_ID: u16 = 0x4547;
pub const KA_TRACEROUTE_PORT: u16 = 33434;

const GRE_FLAG_CSUM: u16 = 0x8000;
const GRE_FLAG_ROUTING: u16 = 0x4000;
const GRE_FLAG_KEY: u16 = 0x2000;
const GRE_FLAG_SEQ: u16 = 0x1000;
const GRE_RESERVED_MASK: u16 = 0x0ff8;
const GRE_VERSION_MASK: u16 = 0x0007;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveReplyKind {
    GrePt0 = 1,
    InTunnelEcho = 2,
    InTunnelTtl1 = 3,
    UdpBounce = 4,
}

impl KeepaliveReplyKind {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::GrePt0),
            2 => Some(Self::InTunnelEcho),
            3 => Some(Self::InTunnelTtl1),
            4 => Some(Self::UdpBounce),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTunnelIp {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

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
    /// Incoming in-tunnel ICMPv4/ICMPv6 Echo Request carrying `KA_SIG_MAGIC`.
    InTunnelKeepaliveRequest { protocol: u16, payload: &'a [u8] },
    /// Incoming keepalive echo reply (outer GRE PT=0x0000, or in-tunnel ICMP Echo Reply / Time Exceeded).
    KeepaliveReply {
        kind: KeepaliveReplyKind,
        daemon_tag: Option<u32>,
        echo_token: Option<[u8; 4]>,
        body_len: usize,
        peer_tunnel_ip: Option<PeerTunnelIp>,
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
                kind: KeepaliveReplyKind::GrePt0,
                daemon_tag: None,
                echo_token,
                body_len: body.len(),
                peer_tunnel_ip: None,
            })
        }
        ETHERTYPE_IPV4 => {
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
                } else if inner_ip.proto == IPPROTO_ICMP {
                    let icmp = inner_ip.payload;
                    // In-tunnel ICMPv4 Echo Reply (0) or Echo Request (8) carrying KA_SIG_MAGIC
                    if icmp.len() == 20
                        && (icmp[0] == 0 || icmp[0] == 8)
                        && icmp[1] == 0
                        && u16::from_be_bytes([icmp[4], icmp[5]]) == KA_ICMP_ID
                        && icmp[8..12] == KA_SIG_MAGIC
                        && internet_checksum(icmp) == 0
                    {
                        if icmp[0] == 0 {
                            let tag = u32::from_be_bytes([icmp[12], icmp[13], icmp[14], icmp[15]]);
                            let tok = [icmp[16], icmp[17], icmp[18], icmp[19]];
                            return Some(GreDecoded::KeepaliveReply {
                                kind: KeepaliveReplyKind::InTunnelEcho,
                                daemon_tag: Some(tag),
                                echo_token: Some(tok),
                                body_len: 4,
                                peer_tunnel_ip: Some(PeerTunnelIp::V4(inner_ip.src)),
                            });
                        }
                        return Some(GreDecoded::InTunnelKeepaliveRequest {
                            protocol: ETHERTYPE_IPV4,
                            payload: body,
                        });
                    }
                    // In-tunnel ICMPv4 Time Exceeded (11, code 0) quoting our TTL=1 UDP probe
                    if icmp.len() >= 48 && icmp[0] == 11 && icmp[1] == 0 {
                        let q = &icmp[8..];
                        if (q[0] >> 4) == 4 && ((q[0] & 0x0f) as usize) * 4 == 20 && q[9] == IPPROTO_UDP {
                            let q_dport = u16::from_be_bytes([q[22], q[23]]);
                            if q_dport == KA_TRACEROUTE_PORT
                                && q[28..32] == KA_SIG_MAGIC
                                && internet_checksum(icmp) == 0
                            {
                                let tag = u32::from_be_bytes([q[32], q[33], q[34], q[35]]);
                                let tok = [q[36], q[37], q[38], q[39]];
                                return Some(GreDecoded::KeepaliveReply {
                                    kind: KeepaliveReplyKind::InTunnelTtl1,
                                    daemon_tag: Some(tag),
                                    echo_token: Some(tok),
                                    body_len: 4,
                                    peer_tunnel_ip: Some(PeerTunnelIp::V4(inner_ip.src)),
                                });
                            }
                        }
                    }
                }
            }
            Some(GreDecoded::Data {
                protocol: ETHERTYPE_IPV4,
                payload: body,
            })
        }
        ETHERTYPE_IPV6 => {
            if body.len() >= 60 && (body[0] >> 4) == 6 && body[6] == IPPROTO_ICMPV6 {
                let payload_len = u16::from_be_bytes([body[4], body[5]]) as usize;
                let ip6_end = 40usize.saturating_add(payload_len);
                if ip6_end <= body.len() {
                    let ip6 = &body[..ip6_end];
                    let icmp6 = &ip6[40..];
                    let mut src_oct = [0u8; 16];
                    src_oct.copy_from_slice(&ip6[8..24]);
                    let src_v6 = Ipv6Addr::from(src_oct);

                    if icmp6.len() == 20
                        && (icmp6[0] == 129 || icmp6[0] == 128)
                        && icmp6[1] == 0
                        && u16::from_be_bytes([icmp6[4], icmp6[5]]) == KA_ICMP_ID
                        && icmp6[8..12] == KA_SIG_MAGIC
                        && verify_icmpv6_checksum(ip6)
                    {
                        if icmp6[0] == 129 {
                            let tag =
                                u32::from_be_bytes([icmp6[12], icmp6[13], icmp6[14], icmp6[15]]);
                            let tok = [icmp6[16], icmp6[17], icmp6[18], icmp6[19]];
                            return Some(GreDecoded::KeepaliveReply {
                                kind: KeepaliveReplyKind::InTunnelEcho,
                                daemon_tag: Some(tag),
                                echo_token: Some(tok),
                                body_len: 4,
                                peer_tunnel_ip: Some(PeerTunnelIp::V6(src_v6)),
                            });
                        }
                        return Some(GreDecoded::InTunnelKeepaliveRequest {
                            protocol: ETHERTYPE_IPV6,
                            payload: body,
                        });
                    }

                    if icmp6.len() >= 68 && icmp6[0] == 3 && icmp6[1] == 0 {
                        let q6 = &icmp6[8..];
                        if (q6[0] >> 4) == 6
                            && q6[6] == IPPROTO_UDP
                            && u16::from_be_bytes([q6[42], q6[43]]) == KA_TRACEROUTE_PORT
                            && q6[48..52] == KA_SIG_MAGIC
                            && verify_icmpv6_checksum(ip6)
                        {
                            let tag = u32::from_be_bytes([q6[52], q6[53], q6[54], q6[55]]);
                            let tok = [q6[56], q6[57], q6[58], q6[59]];
                            return Some(GreDecoded::KeepaliveReply {
                                kind: KeepaliveReplyKind::InTunnelTtl1,
                                daemon_tag: Some(tag),
                                echo_token: Some(tok),
                                body_len: 4,
                                peer_tunnel_ip: Some(PeerTunnelIp::V6(src_v6)),
                            });
                        }
                    }
                }
            }
            Some(GreDecoded::Data {
                protocol: ETHERTYPE_IPV6,
                payload: body,
            })
        }
        other => Some(GreDecoded::Unsupported(other)),
    }
}

/// Inspect a strict RFC 792 truncated (28-byte quote) ICMPv4 Time Exceeded packet when awaiting a
/// TTL=1 keepalive reply. Returns `(icmp_outer_src, quoted_ip_id, quoted_udp_sport)` if headers match.
pub fn parse_truncated_ttl1_icmpv4(
    inner_pkt: &[u8],
    expected_local_tun: Ipv4Addr,
) -> Option<(Ipv4Addr, u16, u16)> {
    let outer = parse_outer_ipv4(inner_pkt)?;
    if outer.proto != IPPROTO_ICMP || outer.payload.len() < 36 || outer.payload.len() >= 48 {
        return None;
    }
    let icmp = outer.payload;
    if icmp[0] != 11 || icmp[1] != 0 {
        return None;
    }
    let q = &icmp[8..];
    if (q[0] >> 4) != 4 || ((q[0] & 0x0f) as usize) * 4 != 20 || q[9] != IPPROTO_UDP {
        return None;
    }
    let q_src = Ipv4Addr::new(q[12], q[13], q[14], q[15]);
    let q_dport = u16::from_be_bytes([q[22], q[23]]);
    if q_src != expected_local_tun || q_dport != KA_TRACEROUTE_PORT || internet_checksum(icmp) != 0 {
        return None;
    }
    let q_id = u16::from_be_bytes([q[4], q[5]]);
    let q_sport = u16::from_be_bytes([q[20], q[21]]);
    Some((outer.src, q_id, q_sport))
}

#[inline]
pub fn ttl1_probe_fields_from_token(token: u32) -> (u16, u16) {
    let ip_id = (token >> 16) as u16;
    let sport = (token as u16) | 0x8000;
    (ip_id, sport)
}

#[inline]
fn write_ipv6_header(
    buf: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_hdr: u8,
    hop_limit: u8,
    payload_len: u16,
) {
    buf[0] = 0x60;
    buf[1] = 0x00;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4..6].copy_from_slice(&payload_len.to_be_bytes());
    buf[6] = next_hdr;
    buf[7] = hop_limit;
    buf[8..24].copy_from_slice(&src.octets());
    buf[24..40].copy_from_slice(&dst.octets());
}

#[inline]
fn compute_udp_v4_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_pkt: &[u8]) -> u16 {
    let udp_len = udp_pkt.len() as u32;
    let mut sum = checksum_accumulate(0, &src.octets());
    sum = checksum_accumulate(sum, &dst.octets());
    sum += IPPROTO_UDP as u32;
    sum += udp_len;
    sum = checksum_accumulate(sum, &udp_pkt[..6]);
    sum = checksum_accumulate(sum, &udp_pkt[8..]);
    let csum = checksum_finish(sum);
    if csum == 0 {
        0xffff
    } else {
        csum
    }
}

#[inline]
fn compute_udp_v6_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_pkt: &[u8]) -> u16 {
    let udp_len = udp_pkt.len() as u32;
    let mut sum = checksum_accumulate(0, &src.octets());
    sum = checksum_accumulate(sum, &dst.octets());
    sum = checksum_accumulate(sum, &udp_len.to_be_bytes());
    sum += IPPROTO_UDP as u32;
    sum = checksum_accumulate(sum, &udp_pkt[..6]);
    sum = checksum_accumulate(sum, &udp_pkt[8..]);
    let csum = checksum_finish(sum);
    if csum == 0 {
        0xffff
    } else {
        csum
    }
}

#[inline]
fn compute_icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp6: &[u8]) -> u16 {
    let len = icmp6.len() as u32;
    let mut sum = checksum_accumulate(0, &src.octets());
    sum = checksum_accumulate(sum, &dst.octets());
    sum = checksum_accumulate(sum, &len.to_be_bytes());
    sum += IPPROTO_ICMPV6 as u32;
    sum = checksum_accumulate(sum, &icmp6[..2]);
    sum = checksum_accumulate(sum, &icmp6[4..]);
    checksum_finish(sum)
}

#[inline]
fn verify_icmpv6_checksum(ip6: &[u8]) -> bool {
    if ip6.len() < 48 || (ip6[0] >> 4) != 6 || ip6[6] != IPPROTO_ICMPV6 {
        return false;
    }
    let icmp_len = (ip6.len() - 40) as u32;
    let mut sum = checksum_accumulate(0, &ip6[8..40]);
    sum = checksum_accumulate(sum, &icmp_len.to_be_bytes());
    sum += IPPROTO_ICMPV6 as u32;
    sum = checksum_accumulate(sum, &ip6[40..]);
    checksum_finish(sum) == 0
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
/// [Outer GRE: flags=0, PT=0x0800] + [Inner IPv4: src=remote_ip, dst=local_reply_ip, proto=47] + [Inner GRE: flags=0, PT=0x0000 + 4B token]
///
/// Note: The 4-byte token after Inner GRE ensures the resulting IPv4 keepalive reply
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

/// Build a 44-byte GRE-encapsulated in-tunnel ICMPv4 Echo Request or Reply (`PT=0x0800`).
/// Travels strictly inside the outer GRE tunnel, avoiding peer WAN SNAT/masquerade conntrack collisions.
pub fn build_in_tunnel_icmpv4_echo(
    src_tun: Ipv4Addr,
    dst_tun: Ipv4Addr,
    is_reply: bool,
    seq_id: u16,
    daemon_tag: u32,
    token: u32,
) -> [u8; 44] {
    let mut buf = [0u8; 44];
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    write_ipv4_header(
        &mut buf[4..24],
        src_tun,
        dst_tun,
        IPPROTO_ICMP,
        seq_id,
        64,
        40,
    );
    let icmp = &mut buf[24..44];
    icmp[0] = if is_reply { 0 } else { 8 };
    icmp[1] = 0;
    icmp[4..6].copy_from_slice(&KA_ICMP_ID.to_be_bytes());
    icmp[6..8].copy_from_slice(&seq_id.to_be_bytes());
    icmp[8..12].copy_from_slice(&KA_SIG_MAGIC);
    icmp[12..16].copy_from_slice(&daemon_tag.to_be_bytes());
    icmp[16..20].copy_from_slice(&token.to_be_bytes());
    let csum = internet_checksum(icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    buf
}

/// Build a 44-byte GRE-encapsulated in-tunnel `TTL=1` UDP probe (`PT=0x0800`).
/// Expires in peer `ip_forward()` before `POSTROUTING` SNAT/masquerade, eliciting an in-tunnel
/// ICMPv4 Time Exceeded reply even when peer tunnel IP is unknown (e.g. `/24` subnet).
pub fn build_in_tunnel_ttl1_v4_probe(
    src_tun: Ipv4Addr,
    dst_routable: Ipv4Addr,
    daemon_tag: u32,
    token: u32,
) -> [u8; 44] {
    let mut buf = [0u8; 44];
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    let (ip_id, sport) = ttl1_probe_fields_from_token(token);
    write_ipv4_header(
        &mut buf[4..24],
        src_tun,
        dst_routable,
        IPPROTO_UDP,
        ip_id,
        1,
        40,
    );
    let udp = &mut buf[24..44];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&KA_TRACEROUTE_PORT.to_be_bytes());
    udp[4..6].copy_from_slice(&20u16.to_be_bytes());
    udp[8..12].copy_from_slice(&KA_SIG_MAGIC);
    udp[12..16].copy_from_slice(&daemon_tag.to_be_bytes());
    udp[16..20].copy_from_slice(&token.to_be_bytes());
    let csum = compute_udp_v4_checksum(src_tun, dst_routable, udp);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    buf
}

/// Build a 64-byte GRE-encapsulated in-tunnel ICMPv6 Echo Request or Reply (`PT=0x86DD`).
pub fn build_in_tunnel_icmpv6_echo(
    src_tun: Ipv6Addr,
    dst_tun: Ipv6Addr,
    is_reply: bool,
    seq_id: u16,
    daemon_tag: u32,
    token: u32,
) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    write_ipv6_header(&mut buf[4..44], src_tun, dst_tun, IPPROTO_ICMPV6, 64, 20);
    let icmp6 = &mut buf[44..64];
    icmp6[0] = if is_reply { 129 } else { 128 };
    icmp6[1] = 0;
    icmp6[4..6].copy_from_slice(&KA_ICMP_ID.to_be_bytes());
    icmp6[6..8].copy_from_slice(&seq_id.to_be_bytes());
    icmp6[8..12].copy_from_slice(&KA_SIG_MAGIC);
    icmp6[12..16].copy_from_slice(&daemon_tag.to_be_bytes());
    icmp6[16..20].copy_from_slice(&token.to_be_bytes());
    let csum = compute_icmpv6_checksum(src_tun, dst_tun, icmp6);
    icmp6[2..4].copy_from_slice(&csum.to_be_bytes());
    buf
}

/// Build a 64-byte GRE-encapsulated in-tunnel `HopLimit=1` IPv6 UDP probe (`PT=0x86DD`).
pub fn build_in_tunnel_hoplimit1_v6_probe(
    src_tun: Ipv6Addr,
    dst_routable: Ipv6Addr,
    daemon_tag: u32,
    token: u32,
) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    write_ipv6_header(&mut buf[4..44], src_tun, dst_routable, IPPROTO_UDP, 1, 20);
    let (_, sport) = ttl1_probe_fields_from_token(token);
    let udp = &mut buf[44..64];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&KA_TRACEROUTE_PORT.to_be_bytes());
    udp[4..6].copy_from_slice(&20u16.to_be_bytes());
    udp[8..12].copy_from_slice(&KA_SIG_MAGIC);
    udp[12..16].copy_from_slice(&daemon_tag.to_be_bytes());
    udp[16..20].copy_from_slice(&token.to_be_bytes());
    let csum = compute_udp_v6_checksum(src_tun, dst_routable, udp);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    buf
}

/// Construct a GRE-encapsulated ICMPv4/ICMPv6 Echo Reply for an `InTunnelKeepaliveRequest`
/// when `dst` belongs to one of our local tunnel interface addresses.
pub fn build_in_tunnel_keepalive_reply(
    protocol: u16,
    inner_req: &[u8],
    out: &mut [u8; 64],
) -> Option<usize> {
    match protocol {
        ETHERTYPE_IPV4 => {
            let ip = parse_outer_ipv4(inner_req)?;
            let icmp = ip.payload;
            if ip.proto != IPPROTO_ICMP || icmp.len() != 20 || icmp[0] != 8 {
                return None;
            }
            let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
            let tag = u32::from_be_bytes([icmp[12], icmp[13], icmp[14], icmp[15]]);
            let tok = u32::from_be_bytes([icmp[16], icmp[17], icmp[18], icmp[19]]);
            let pkt = build_in_tunnel_icmpv4_echo(ip.dst, ip.src, true, seq, tag, tok);
            out[..44].copy_from_slice(&pkt);
            Some(44)
        }
        ETHERTYPE_IPV6 => {
            if inner_req.len() < 60 || (inner_req[0] >> 4) != 6 || inner_req[6] != IPPROTO_ICMPV6 {
                return None;
            }
            let icmp6 = &inner_req[40..60];
            if icmp6[0] != 128 {
                return None;
            }
            let mut src_oct = [0u8; 16];
            let mut dst_oct = [0u8; 16];
            src_oct.copy_from_slice(&inner_req[8..24]);
            dst_oct.copy_from_slice(&inner_req[24..40]);
            let seq = u16::from_be_bytes([icmp6[6], icmp6[7]]);
            let tag = u32::from_be_bytes([icmp6[12], icmp6[13], icmp6[14], icmp6[15]]);
            let tok = u32::from_be_bytes([icmp6[16], icmp6[17], icmp6[18], icmp6[19]]);
            let pkt = build_in_tunnel_icmpv6_echo(
                Ipv6Addr::from(dst_oct),
                Ipv6Addr::from(src_oct),
                true,
                seq,
                tag,
                tok,
            );
            *out = pkt;
            Some(64)
        }
        _ => None,
    }
}

/// Build a 44-byte `UDP-in-GRE` bounce keepalive probe for unnumbered tunnels behind NAT+masquerade.
/// Inner UDP (`proto=17`) avoids colliding with the outer GRE (`proto=47`) conntrack tuple on the peer.
pub fn build_udp_in_gre_keepalive(
    remote_ip: Ipv4Addr,
    local_reply_ip: Ipv4Addr,
    udp_port: u16,
    seq_id: u16,
    daemon_tag: u32,
    token: u32,
) -> [u8; 44] {
    let mut buf = [0u8; 44];
    buf[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    write_ipv4_header(
        &mut buf[4..24],
        remote_ip,
        local_reply_ip,
        IPPROTO_UDP,
        seq_id,
        255,
        40,
    );
    let udp = &mut buf[24..44];
    udp[0..2].copy_from_slice(&udp_port.to_be_bytes());
    udp[2..4].copy_from_slice(&udp_port.to_be_bytes());
    udp[4..6].copy_from_slice(&20u16.to_be_bytes());
    udp[8..12].copy_from_slice(&KA_SIG_MAGIC);
    udp[12..16].copy_from_slice(&daemon_tag.to_be_bytes());
    udp[16..20].copy_from_slice(&token.to_be_bytes());
    let csum = compute_udp_v4_checksum(remote_ip, local_reply_ip, udp);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    buf
}

/// Parse an inbound 12-byte UDP keepalive bounce payload (`[KA_SIG_MAGIC, daemon_tag, token]`).
#[inline]
pub fn parse_udp_keepalive_payload(buf: &[u8]) -> Option<(u32, [u8; 4])> {
    if buf.len() != 12 || buf[0..4] != KA_SIG_MAGIC {
        return None;
    }
    let tag = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let tok = [buf[8], buf[9], buf[10], buf[11]];
    Some((tag, tok))
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
                kind,
                daemon_tag,
                echo_token,
                body_len,
                peer_tunnel_ip,
            } => {
                assert_eq!(kind, KeepaliveReplyKind::GrePt0);
                assert_eq!(daemon_tag, None);
                assert_eq!(echo_token, Some([0xde, 0xad, 0xbe, 0xef]));
                assert_eq!(body_len, 4);
                assert_eq!(peer_tunnel_ip, None);
            }
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn test_in_tunnel_icmpv4_and_icmpv6_echo_roundtrip() {
        let local_v4 = Ipv4Addr::new(172, 16, 1, 2);
        let peer_v4 = Ipv4Addr::new(172, 16, 1, 1);
        let req4 = build_in_tunnel_icmpv4_echo(local_v4, peer_v4, false, 9, 0x1122_3344, 0xcafe_babe);
        assert_eq!(internet_checksum(&req4[4..24]), 0);
        assert_eq!(internet_checksum(&req4[24..44]), 0);

        let mut rep_buf = [0u8; 64];
        let rep4_len = match decode_gre_payload(&req4).unwrap() {
            GreDecoded::InTunnelKeepaliveRequest { protocol, payload } => {
                assert_eq!(protocol, ETHERTYPE_IPV4);
                build_in_tunnel_keepalive_reply(protocol, payload, &mut rep_buf).unwrap()
            }
            other => panic!("unexpected v4 echo req decode: {other:?}"),
        };
        match decode_gre_payload(&rep_buf[..rep4_len]).unwrap() {
            GreDecoded::KeepaliveReply {
                kind,
                daemon_tag,
                echo_token,
                peer_tunnel_ip,
                ..
            } => {
                assert_eq!(kind, KeepaliveReplyKind::InTunnelEcho);
                assert_eq!(daemon_tag, Some(0x1122_3344));
                assert_eq!(echo_token, Some([0xca, 0xfe, 0xba, 0xbe]));
                assert_eq!(peer_tunnel_ip, Some(PeerTunnelIp::V4(peer_v4)));
            }
            other => panic!("unexpected v4 echo rep decode: {other:?}"),
        }

        // Normal user ping must NOT be intercepted as keepalive
        let mut user_ping = req4;
        user_ping[32..36].copy_from_slice(b"PING");
        user_ping[26..28].fill(0);
        let csum = internet_checksum(&user_ping[24..44]);
        user_ping[26..28].copy_from_slice(&csum.to_be_bytes());
        assert!(matches!(
            decode_gre_payload(&user_ping).unwrap(),
            GreDecoded::Data {
                protocol: ETHERTYPE_IPV4,
                ..
            }
        ));

        // IPv6 in-tunnel Echo roundtrip
        let local_v6 = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 2);
        let peer_v6 = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 1);
        let req6 = build_in_tunnel_icmpv6_echo(local_v6, peer_v6, false, 11, 0x5566_7788, 0x1357_2468);
        let rep6_len = match decode_gre_payload(&req6).unwrap() {
            GreDecoded::InTunnelKeepaliveRequest { protocol, payload } => {
                assert_eq!(protocol, ETHERTYPE_IPV6);
                build_in_tunnel_keepalive_reply(protocol, payload, &mut rep_buf).unwrap()
            }
            other => panic!("unexpected v6 echo req decode: {other:?}"),
        };
        match decode_gre_payload(&rep_buf[..rep6_len]).unwrap() {
            GreDecoded::KeepaliveReply {
                kind,
                daemon_tag,
                echo_token,
                peer_tunnel_ip,
                ..
            } => {
                assert_eq!(kind, KeepaliveReplyKind::InTunnelEcho);
                assert_eq!(daemon_tag, Some(0x5566_7788));
                assert_eq!(echo_token, Some([0x13, 0x57, 0x24, 0x68]));
                assert_eq!(peer_tunnel_ip, Some(PeerTunnelIp::V6(peer_v6)));
            }
            other => panic!("unexpected v6 echo rep decode: {other:?}"),
        }
    }

    #[test]
    fn test_ttl1_time_exceeded_full_and_rfc792_truncated_quotes() {
        let local_tun = Ipv4Addr::new(172, 16, 9, 2);
        let peer_tun = Ipv4Addr::new(172, 16, 9, 1);
        let pub_dst = Ipv4Addr::new(23, 94, 104, 214);
        let tok = 0xaabb_ccdd_u32;
        let tag = 0x9988_7766_u32;

        let probe = build_in_tunnel_ttl1_v4_probe(local_tun, pub_dst, tag, tok);
        let inner_probe = &probe[4..44];
        assert_eq!(inner_probe[8], 1); // TTL=1

        // 1. Full RFC 1812 Time Exceeded quote (40B inner quote)
        let mut te_gre = [0u8; 4 + 20 + 8 + 40];
        te_gre[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        write_ipv4_header(&mut te_gre[4..24], peer_tun, local_tun, IPPROTO_ICMP, 1, 64, 68);
        te_gre[24] = 11;
        te_gre[25] = 0;
        te_gre[32..72].copy_from_slice(inner_probe);
        let csum = internet_checksum(&te_gre[24..72]);
        te_gre[26..28].copy_from_slice(&csum.to_be_bytes());

        match decode_gre_payload(&te_gre).unwrap() {
            GreDecoded::KeepaliveReply {
                kind,
                daemon_tag,
                echo_token,
                peer_tunnel_ip,
                ..
            } => {
                assert_eq!(kind, KeepaliveReplyKind::InTunnelTtl1);
                assert_eq!(daemon_tag, Some(tag));
                assert_eq!(echo_token, Some(tok.to_be_bytes()));
                assert_eq!(peer_tunnel_ip, Some(PeerTunnelIp::V4(peer_tun)));
            }
            other => panic!("unexpected TTL=1 reply decode: {other:?}"),
        }

        // 2. Strict RFC 792 28-byte truncated quote falls through to Data unless matched by token fields
        let mut trunc_ip = [0u8; 20 + 8 + 28];
        write_ipv4_header(&mut trunc_ip[..20], peer_tun, local_tun, IPPROTO_ICMP, 2, 64, 56);
        trunc_ip[20] = 11;
        trunc_ip[21] = 0;
        trunc_ip[28..56].copy_from_slice(&inner_probe[..28]);
        let tcsum = internet_checksum(&trunc_ip[20..56]);
        trunc_ip[22..24].copy_from_slice(&tcsum.to_be_bytes());
        let (src, q_id, q_sport) = parse_truncated_ttl1_icmpv4(&trunc_ip, local_tun).unwrap();
        assert_eq!(src, peer_tun);
        assert_eq!((q_id, q_sport), ttl1_probe_fields_from_token(tok));
    }

    #[test]
    fn test_udp_in_gre_keepalive_layout() {
        let remote = Ipv4Addr::new(106, 74, 21, 21);
        let local = Ipv4Addr::new(23, 94, 104, 214);
        let pkt = build_udp_in_gre_keepalive(remote, local, 49152, 7, 0x1234_5678, 0xfeed_face);
        assert_eq!(internet_checksum(&pkt[4..24]), 0);
        // Verify valid RFC 768 UDP checksum
        let mut sum = checksum_accumulate(0, &remote.octets());
        sum = checksum_accumulate(sum, &local.octets());
        sum += IPPROTO_UDP as u32;
        sum += 20u32;
        sum = checksum_accumulate(sum, &pkt[24..44]);
        assert_eq!(checksum_finish(sum), 0);

        let (tag, tok) = parse_udp_keepalive_payload(&pkt[32..44]).unwrap();
        assert_eq!(tag, 0x1234_5678);
        assert_eq!(tok, [0xfe, 0xed, 0xfa, 0xce]);
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
            if iter % 5 == 1 && len >= 32 {
                let ka = build_keepalive_request_with_token(
                    Ipv4Addr::from(next_rng(&mut rng) as u32),
                    Ipv4Addr::from(next_rng(&mut rng) as u32),
                    next_rng(&mut rng) as u16,
                    next_rng(&mut rng) as u32,
                );
                buf[..32].copy_from_slice(&ka);
                let flip_idx = (next_rng(&mut rng) as usize) % len;
                buf[flip_idx] ^= (next_rng(&mut rng) as u8) | 1;
            } else if iter % 5 == 2 && len >= 44 {
                let echo = build_in_tunnel_icmpv4_echo(
                    Ipv4Addr::from(next_rng(&mut rng) as u32),
                    Ipv4Addr::from(next_rng(&mut rng) as u32),
                    (iter & 1) == 0,
                    next_rng(&mut rng) as u16,
                    next_rng(&mut rng) as u32,
                    next_rng(&mut rng) as u32,
                );
                buf[..44].copy_from_slice(&echo);
                let flip_idx = (next_rng(&mut rng) as usize) % len;
                buf[flip_idx] ^= (next_rng(&mut rng) as u8) | 1;
            } else if iter % 5 == 3 && len >= 64 {
                let echo6 = build_in_tunnel_icmpv6_echo(
                    Ipv6Addr::from(next_rng(&mut rng) as u128),
                    Ipv6Addr::from(next_rng(&mut rng) as u128),
                    (iter & 1) == 0,
                    next_rng(&mut rng) as u16,
                    next_rng(&mut rng) as u32,
                    next_rng(&mut rng) as u32,
                );
                buf[..64].copy_from_slice(&echo6);
                let flip_idx = (next_rng(&mut rng) as usize) % len;
                buf[flip_idx] ^= (next_rng(&mut rng) as u8) | 1;
            } else if iter % 5 == 4 && len >= 8 {
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
            let _ = parse_truncated_ttl1_icmpv4(slice, Ipv4Addr::new(172, 16, 0, 2));
            let _ = parse_udp_keepalive_payload(slice);
        }
    }
}
