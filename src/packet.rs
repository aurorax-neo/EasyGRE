use std::net::{Ipv4Addr, Ipv6Addr};

/// Compute symmetric L3/L4 5-tuple hash for selecting TUN multiqueue index on RX write,
/// keeping `tun_flow_update` consistent for bidirectional flows and evenly distributed.
#[inline]
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn packet_flow_hash(pkt: &[u8]) -> usize {
    let Some(&first) = pkt.first() else {
        return 0;
    };
    let mut h: u32 = 0x811c_9dc5;
    match first >> 4 {
        4 if pkt.len() >= 20 => {
            let src = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
            let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
            let (ip_lo, ip_hi) = if src <= dst { (src, dst) } else { (dst, src) };
            let ihl = ((first & 0x0f) as usize) * 4;
            let proto = pkt[9];
            h ^= ip_lo;
            h = h.wrapping_mul(0x0100_0193) ^ ip_hi;
            h = h.wrapping_mul(0x0100_0193) ^ (proto as u32);
            if matches!(proto, 6 | 17) && pkt.len() >= ihl + 4 {
                let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                let (p_lo, p_hi) = if sp <= dp { (sp, dp) } else { (dp, sp) };
                let ports = ((p_lo as u32) << 16) | (p_hi as u32);
                h = h.wrapping_mul(0x0100_0193) ^ ports;
            }
        }
        6 if pkt.len() >= 40 => {
            let (a, b) = if pkt[8..24] <= pkt[24..40] {
                (&pkt[8..24], &pkt[24..40])
            } else {
                (&pkt[24..40], &pkt[8..24])
            };
            for chunk in a.chunks_exact(4).chain(b.chunks_exact(4)) {
                let v = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                h = (h ^ v).wrapping_mul(0x0100_0193);
            }
            let nh = pkt[6];
            h ^= nh as u32;
            if matches!(nh, 6 | 17) && pkt.len() >= 44 {
                let sp = u16::from_be_bytes([pkt[40], pkt[41]]);
                let dp = u16::from_be_bytes([pkt[42], pkt[43]]);
                let (p_lo, p_hi) = if sp <= dp { (sp, dp) } else { (dp, sp) };
                let ports = ((p_lo as u32) << 16) | (p_hi as u32);
                h = h.wrapping_mul(0x0100_0193) ^ ports;
            }
        }
        _ => return 0,
    }
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h as usize
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InnerIpMeta {
    pub version: IpVersion,
    pub dscp: u8,
    pub df: bool,
}

/// Check whether an IPv4 address is a valid routable unicast address
/// (excludes 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, multicast 224.0.0.0/4, and reserved/broadcast 240.0.0.0/4).
#[inline]
pub fn is_valid_unicast_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    if o[0] == 0 || o[0] == 127 || o[0] >= 224 {
        return false;
    }
    if o[0] == 169 && o[1] == 254 {
        return false;
    }
    true
}

/// Inspect inner IP packet (IPv4 or IPv6) to extract protocol version, DSCP, and DF bit.
pub fn inspect_inner_ip(pkt: &[u8]) -> Option<InnerIpMeta> {
    let first = *pkt.first()?;
    match first >> 4 {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = ((first & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return None;
            }
            let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_len < ihl || pkt.len() < total_len {
                return None;
            }
            let dscp = pkt[1] >> 2;
            let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            let df = (flags_frag & 0x4000) != 0;
            Some(InnerIpMeta {
                version: IpVersion::V4,
                dscp,
                df,
            })
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            if pkt.len() < 40 + payload_len {
                return None;
            }
            let tc = ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4);
            let dscp = tc >> 2;
            Some(InnerIpMeta {
                version: IpVersion::V6,
                dscp,
                df: false,
            })
        }
        _ => None,
    }
}

/// Compute RFC 1071 Internet Checksum over a byte slice.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let sum = checksum_accumulate(0, data);
    checksum_finish(sum)
}

/// Fast unrolled 20-byte IPv4 header checksum.
#[inline]
pub fn ipv4_header_checksum_fast(hdr: &[u8]) -> u16 {
    let mut sum: u32 = u16::from_be_bytes([hdr[0], hdr[1]]) as u32
        + u16::from_be_bytes([hdr[2], hdr[3]]) as u32
        + u16::from_be_bytes([hdr[4], hdr[5]]) as u32
        + u16::from_be_bytes([hdr[6], hdr[7]]) as u32
        + u16::from_be_bytes([hdr[8], hdr[9]]) as u32
        + u16::from_be_bytes([hdr[12], hdr[13]]) as u32
        + u16::from_be_bytes([hdr[14], hdr[15]]) as u32
        + u16::from_be_bytes([hdr[16], hdr[17]]) as u32
        + u16::from_be_bytes([hdr[18], hdr[19]]) as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline]
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn checksum_accumulate(sum: u32, data: &[u8]) -> u32 {
    let mut acc0: u64 = 0;
    let mut acc1: u64 = 0;
    let mut acc2: u64 = 0;
    let mut acc3: u64 = 0;

    let mut chunks32 = data.chunks_exact(32);
    for c in chunks32.by_ref() {
        let v0 = u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        let v1 = u64::from_ne_bytes([c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]]);
        let v2 = u64::from_ne_bytes([c[16], c[17], c[18], c[19], c[20], c[21], c[22], c[23]]);
        let v3 = u64::from_ne_bytes([c[24], c[25], c[26], c[27], c[28], c[29], c[30], c[31]]);
        let (s0, c0) = acc0.overflowing_add(v0);
        let (s1, c1) = acc1.overflowing_add(v1);
        let (s2, c2) = acc2.overflowing_add(v2);
        let (s3, c3) = acc3.overflowing_add(v3);
        acc0 = s0 + (c0 as u64);
        acc1 = s1 + (c1 as u64);
        acc2 = s2 + (c2 as u64);
        acc3 = s3 + (c3 as u64);
    }

    let mut chunks8 = chunks32.remainder().chunks_exact(8);
    for c in chunks8.by_ref() {
        let v = u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
        let (s, carry) = acc0.overflowing_add(v);
        acc0 = s + (carry as u64);
    }

    let rem = chunks8.remainder();
    let mut i = 0;
    while i + 1 < rem.len() {
        let word = u16::from_ne_bytes([rem[i], rem[i + 1]]) as u64;
        let (s, carry) = acc1.overflowing_add(word);
        acc1 = s + (carry as u64);
        i += 2;
    }
    if i < rem.len() {
        #[cfg(target_endian = "little")]
        let tail = rem[i] as u64;
        #[cfg(target_endian = "big")]
        let tail = (rem[i] as u64) << 8;
        let (s, carry) = acc2.overflowing_add(tail);
        acc2 = s + (carry as u64);
    }

    let (s01, c01) = acc0.overflowing_add(acc1);
    let mut total = s01 + (c01 as u64);
    let (s23, c23) = acc2.overflowing_add(acc3);
    let total2 = s23 + (c23 as u64);
    let (st, ct) = total.overflowing_add(total2);
    total = st + (ct as u64);

    let mut folded: u32 = ((total as u32) & 0xffff)
        + (((total >> 16) as u32) & 0xffff)
        + (((total >> 32) as u32) & 0xffff)
        + ((total >> 48) as u32);
    while (folded >> 16) != 0 {
        folded = (folded & 0xffff) + (folded >> 16);
    }
    #[cfg(target_endian = "little")]
    let data_sum = (folded as u16).swap_bytes() as u32;
    #[cfg(target_endian = "big")]
    let data_sum = folded;

    let (s, c) = sum.overflowing_add(data_sum);
    s + (c as u32)
}

#[inline]
pub fn checksum_finish(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute full TCP checksum for IPv4 packet (starting at IP header).
#[cfg(test)]
pub fn compute_tcp_v4_checksum(ip_pkt: &[u8]) -> Option<u16> {
    if ip_pkt.len() < 20 || (ip_pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([ip_pkt[2], ip_pkt[3]]) as usize;
    if ihl < 20 || total_len < ihl + 20 || ip_pkt.len() < total_len || ip_pkt[9] != 6 {
        return None;
    }
    let tcp_len = (total_len - ihl) as u16;
    let mut sum: u32 = 0;
    sum = checksum_accumulate(sum, &ip_pkt[12..20]);
    sum += 6u32;
    sum += tcp_len as u32;

    let tcp = &ip_pkt[ihl..total_len];
    sum = checksum_accumulate(sum, &tcp[..16]);
    sum = checksum_accumulate(sum, &tcp[18..]);
    Some(checksum_finish(sum))
}

/// Compute full TCP checksum for IPv6 packet (starting at IPv6 header).
#[cfg(test)]
pub fn compute_tcp_v6_checksum(ip_pkt: &[u8], tcp_offset: usize, tcp_end: usize) -> Option<u16> {
    if ip_pkt.len() < 40 || (ip_pkt[0] >> 4) != 6 || tcp_end <= tcp_offset + 20 || tcp_end > ip_pkt.len() {
        return None;
    }
    let tcp_len = (tcp_end - tcp_offset) as u32;
    let mut sum: u32 = 0;
    sum = checksum_accumulate(sum, &ip_pkt[8..40]);
    sum = checksum_accumulate(sum, &tcp_len.to_be_bytes());
    sum += 6u32;

    let tcp = &ip_pkt[tcp_offset..tcp_end];
    sum = checksum_accumulate(sum, &tcp[..16]);
    sum = checksum_accumulate(sum, &tcp[18..]);
    Some(checksum_finish(sum))
}

/// RFC 1624 incremental checksum update for a 16-bit aligned word change.
#[inline]
fn csum_update_u16(csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum = (!csum) as u32;
    sum += (!old_val) as u32;
    sum += new_val as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Clamp TCP MSS option inside an IPv4 or IPv6 packet when SYN flag is set.
/// - IPv4 max MSS = tunnel_mtu - 40
/// - IPv6 max MSS = tunnel_mtu - 60
pub fn clamp_tcp_mss(pkt: &mut [u8], tunnel_mtu: u16) -> bool {
    let Some(first) = pkt.first().copied() else {
        return false;
    };
    match first >> 4 {
        4 => {
            if pkt.len() < 20 {
                return false;
            }
            let ihl = ((first & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return false;
            }
            let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_len < ihl || pkt.len() < total_len {
                return false;
            }
            if pkt[9] != 6 {
                return false;
            }
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if (frag & 0x1fff) != 0 {
                return false;
            }
            let max_mss = tunnel_mtu.saturating_sub(40);
            if max_mss < 64 {
                return false;
            }
            clamp_tcp_segment_mss(&mut pkt[ihl..total_len], max_mss)
        }
        6 => {
            if pkt.len() < 40 {
                return false;
            }
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let end = 40 + payload_len;
            if pkt.len() < end {
                return false;
            }
            let Some(tcp_offset) = find_ipv6_tcp_offset(&pkt[..end]) else {
                return false;
            };
            let max_mss = tunnel_mtu.saturating_sub(60);
            if max_mss < 64 {
                return false;
            }
            clamp_tcp_segment_mss(&mut pkt[tcp_offset..end], max_mss)
        }
        _ => false,
    }
}

fn find_ipv6_l4_offset(pkt: &[u8], target_proto: u8) -> Option<usize> {
    let mut next_hdr = pkt[6];
    let mut offset = 40usize;
    for _ in 0..8 {
        match next_hdr {
            p if p == target_proto => return Some(offset),
            0 | 43 | 60 => {
                if offset + 2 > pkt.len() {
                    return None;
                }
                let ext_next = pkt[offset];
                let hdr_len = (pkt[offset + 1] as usize + 1) * 8;
                offset = offset.checked_add(hdr_len)?;
                if offset > pkt.len() {
                    return None;
                }
                next_hdr = ext_next;
            }
            44 => {
                if offset + 8 > pkt.len() {
                    return None;
                }
                let frag_off = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]) & 0xfff8;
                if frag_off != 0 {
                    return None;
                }
                next_hdr = pkt[offset];
                offset += 8;
            }
            _ => return None,
        }
    }
    None
}

#[inline]
fn find_ipv6_tcp_offset(pkt: &[u8]) -> Option<usize> {
    find_ipv6_l4_offset(pkt, 6)
}

fn clamp_tcp_segment_mss(tcp: &mut [u8], max_mss: u16) -> bool {
    if tcp.len() < 20 {
        return false;
    }
    let flags = tcp[13];
    if (flags & 0x02) == 0 {
        return false;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || data_offset > tcp.len() {
        return false;
    }
    let mut i = 20usize;
    let mut modified = false;
    while i < data_offset {
        let kind = tcp[i];
        match kind {
            0 => break,
            1 => {
                i += 1;
            }
            _ => {
                if i + 1 >= data_offset {
                    break;
                }
                let len = tcp[i + 1] as usize;
                if len < 2 || i + len > data_offset {
                    break;
                }
                if kind == 2 && len == 4 {
                    let old_mss = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
                    if old_mss > max_mss {
                        let val_offset = i + 2;
                        let aligned_start = val_offset & !1;
                        let aligned_end = if (val_offset & 1) == 0 {
                            val_offset + 2
                        } else {
                            (val_offset + 3).min(data_offset)
                        };
                        let mut before = [0u8; 4];
                        let span = aligned_end - aligned_start;
                        before[..span].copy_from_slice(&tcp[aligned_start..aligned_end]);

                        tcp[val_offset..val_offset + 2].copy_from_slice(&max_mss.to_be_bytes());

                        let mut after = [0u8; 4];
                        after[..span].copy_from_slice(&tcp[aligned_start..aligned_end]);

                        let mut csum = u16::from_be_bytes([tcp[16], tcp[17]]);
                        let mut w = 0;
                        while w < span {
                            let old_w = u16::from_be_bytes([before[w], before[w + 1]]);
                            let new_w = u16::from_be_bytes([after[w], after[w + 1]]);
                            if old_w != new_w {
                                csum = csum_update_u16(csum, old_w, new_w);
                            }
                            w += 2;
                        }
                        tcp[16..18].copy_from_slice(&csum.to_be_bytes());
                        modified = true;
                    }
                    break;
                }
                i += len;
            }
        }
    }
    modified
}

/// Parse an IPv4 packet's outer header (used when receiving from AF_INET SOCK_RAW).
pub struct OuterIpv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub id: u16,
    pub proto: u8,
    pub payload: &'a [u8],
}

pub fn parse_outer_ipv4(raw_pkt: &[u8]) -> Option<OuterIpv4<'_>> {
    if raw_pkt.len() < 20 || (raw_pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((raw_pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || raw_pkt.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([raw_pkt[2], raw_pkt[3]]) as usize;
    let effective_end = if total_len >= ihl && total_len <= raw_pkt.len() {
        total_len
    } else if total_len == 0 {
        raw_pkt.len()
    } else {
        return None;
    };
    let src = Ipv4Addr::new(raw_pkt[12], raw_pkt[13], raw_pkt[14], raw_pkt[15]);
    let dst = Ipv4Addr::new(raw_pkt[16], raw_pkt[17], raw_pkt[18], raw_pkt[19]);
    let id = u16::from_be_bytes([raw_pkt[4], raw_pkt[5]]);
    Some(OuterIpv4 {
        src,
        dst,
        id,
        proto: raw_pkt[9],
        payload: &raw_pkt[ihl..effective_end],
    })
}

/// Build a 20-byte IPv4 header without options and compute its header checksum.
pub fn write_ipv4_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    id: u16,
    ttl: u8,
    total_len: u16,
) {
    buf[0] = 0x45;
    buf[1] = 0x00;
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&[0x00, 0x00]);
    buf[8] = ttl;
    buf[9] = proto;
    buf[10..12].copy_from_slice(&[0x00, 0x00]);
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());
    let csum = ipv4_header_checksum_fast(&buf[..20]);
    buf[10..12].copy_from_slice(&csum.to_be_bytes());
}

/// Write a 20-byte outer IPv4 header for GRE (proto=47) with explicit DSCP and DF bit.
#[inline]
pub fn write_outer_ipv4_gre_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    dscp: u8,
    df: bool,
    id: u16,
    total_len: u16,
) {
    buf[0] = 0x45;
    buf[1] = (dscp & 0x3f) << 2;
    buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6] = if df { 0x40 } else { 0x00 };
    buf[7] = 0x00;
    buf[8] = 64;
    buf[9] = 47;
    buf[10] = 0;
    buf[11] = 0;
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());
    let csum = ipv4_header_checksum_fast(&buf[..20]);
    buf[10..12].copy_from_slice(&csum.to_be_bytes());
}

/// Build an RFC 792 / RFC 1191 ICMPv4 Fragmentation Needed (Type 3, Code 4) or
/// RFC 4443 ICMPv6 Packet Too Big (Type 2, Code 0) error packet ready to write back into TUN.
/// Enforces RFC 1812 / RFC 4443 anti-loop checks (never responds to ICMP errors, non-initial
/// fragments, or multicast/broadcast traffic).
/// Build an RFC 792 / RFC 1191 ICMPv4 Fragmentation Needed (Type 3, Code 4) or
/// RFC 4443 ICMPv6 Packet Too Big (Type 2, Code 0) error packet ready to write back into TUN.
/// Uses the inner destination address (or `icmp_src_override` if non-local) as outer ICMP source
/// so Linux `fib_validate_source` (`rp_filter=1` and `accept_local=0`) always accepts it on TUN.
pub fn build_icmp_pkt_too_big(
    failed_inner: &[u8],
    next_hop_mtu: u16,
    icmp_src_v4: Option<Ipv4Addr>,
    icmp_src_v6: Option<Ipv6Addr>,
    with_vnet_hdr: bool,
    out: &mut [u8],
) -> Option<usize> {
    let vnet_off = if with_vnet_hdr { VNET_HDR_LEN } else { 0 };
    let ver = *failed_inner.first()? >> 4;
    match ver {
        4 => {
            if failed_inner.len() < 28 {
                return None;
            }
            let ihl = ((failed_inner[0] & 0x0f) as usize) * 4;
            if ihl < 20 || failed_inner.len() < ihl + 8 {
                return None;
            }
            let frag = u16::from_be_bytes([failed_inner[6], failed_inner[7]]);
            if (frag & 0x1fff) != 0 {
                return None;
            }
            let orig_src = Ipv4Addr::new(
                failed_inner[12],
                failed_inner[13],
                failed_inner[14],
                failed_inner[15],
            );
            let orig_dst = Ipv4Addr::new(
                failed_inner[16],
                failed_inner[17],
                failed_inner[18],
                failed_inner[19],
            );
            if !is_valid_unicast_ipv4(orig_src)
                || orig_dst.octets()[0] >= 224
                || orig_dst == Ipv4Addr::BROADCAST
            {
                return None;
            }
            // RFC 1812: Do not generate ICMPv4 error in response to ICMPv4 error messages
            if failed_inner[9] == 1 {
                let icmp_type = failed_inner[ihl];
                if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
                    return None;
                }
            }
            let quote_len = failed_inner.len().min(ihl + 64).min(576 - 28);
            let ip_total_len = 20 + 8 + quote_len;
            let total_out = vnet_off + ip_total_len;
            if out.len() < total_out {
                return None;
            }
            if with_vnet_hdr {
                out[..VNET_HDR_LEN].fill(0);
            }
            let pkt = &mut out[vnet_off..total_out];
            let src = match icmp_src_v4 {
                Some(ip) if is_valid_unicast_ipv4(ip) && ip != orig_src => ip,
                _ => orig_dst,
            };
            write_ipv4_header(pkt, src, orig_src, 1, 0, 64, ip_total_len as u16);
            pkt[6] = 0x40; // DF=1 on synthetic ICMP
            pkt[10] = 0;
            pkt[11] = 0;
            let ip_csum = ipv4_header_checksum_fast(&pkt[..20]);
            pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            let icmp = &mut pkt[20..];
            icmp[0] = 3; // Destination Unreachable
            icmp[1] = 4; // Fragmentation Needed and DF Set
            icmp[2] = 0;
            icmp[3] = 0;
            icmp[4] = 0;
            icmp[5] = 0;
            icmp[6..8].copy_from_slice(&next_hop_mtu.max(68).to_be_bytes());
            icmp[8..8 + quote_len].copy_from_slice(&failed_inner[..quote_len]);
            let csum = internet_checksum(icmp);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());
            Some(total_out)
        }
        6 => {
            if failed_inner.len() < 48 {
                return None;
            }
            // Reject unspecified (::) or multicast (ff00::/8) source/destination
            if failed_inner[8..24].iter().all(|&b| b == 0)
                || failed_inner[8] == 0xff
                || failed_inner[24] == 0xff
            {
                return None;
            }
            // RFC 4443 Section 2.4: Never send ICMPv6 error in response to an ICMPv6 error (type < 128)
            if let Some(icmp6_off) = find_ipv6_l4_offset(failed_inner, 58) {
                if icmp6_off < failed_inner.len() && failed_inner[icmp6_off] < 128 {
                    return None;
                }
            }
            let quote_len = failed_inner.len().min(1280 - 48);
            let icmp_len = 8 + quote_len;
            let ip_total_len = 40 + icmp_len;
            let total_out = vnet_off + ip_total_len;
            if out.len() < total_out {
                return None;
            }
            if with_vnet_hdr {
                out[..VNET_HDR_LEN].fill(0);
            }
            let pkt = &mut out[vnet_off..total_out];
            pkt[0] = 0x60;
            pkt[1] = 0;
            pkt[2] = 0;
            pkt[3] = 0;
            pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
            pkt[6] = 58; // ICMPv6
            pkt[7] = 64;
            if let Some(sv6) = icmp_src_v6 {
                pkt[8..24].copy_from_slice(&sv6.octets());
            } else {
                pkt[8..24].copy_from_slice(&failed_inner[24..40]);
            }
            pkt[24..40].copy_from_slice(&failed_inner[8..24]);

            let (ip6_hdr, icmp) = pkt.split_at_mut(40);
            icmp[0] = 2; // Packet Too Big
            icmp[1] = 0;
            icmp[2] = 0;
            icmp[3] = 0;
            let mtu_field = (next_hop_mtu.max(68) as u32).to_be_bytes();
            icmp[4..8].copy_from_slice(&mtu_field);
            icmp[8..8 + quote_len].copy_from_slice(&failed_inner[..quote_len]);

            let mut sum = checksum_accumulate(0, &ip6_hdr[8..40]);
            sum = checksum_accumulate(sum, &(icmp_len as u32).to_be_bytes());
            sum += 58u32;
            sum = checksum_accumulate(sum, icmp);
            let csum = checksum_finish(sum);
            icmp[2..4].copy_from_slice(&csum.to_be_bytes());
            Some(total_out)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCidr {
    V4 { addr: Ipv4Addr, prefix_len: u8 },
    V6 { addr: Ipv6Addr, prefix_len: u8 },
}

impl IpCidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        let (ip_str, prefix_str) = trimmed
            .split_once('/')
            .ok_or_else(|| format!("CIDR '{trimmed}' missing '/' prefix length"))?;
        let prefix_len: u8 = prefix_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid CIDR prefix length in '{trimmed}'"))?;
        if let Ok(v4) = ip_str.trim().parse::<Ipv4Addr>() {
            if prefix_len > 32 {
                return Err(format!("IPv4 prefix length {prefix_len} > 32 in '{trimmed}'"));
            }
            return Ok(IpCidr::V4 {
                addr: v4,
                prefix_len,
            });
        }
        if let Ok(v6) = ip_str.trim().parse::<Ipv6Addr>() {
            if prefix_len > 128 {
                return Err(format!("IPv6 prefix length {prefix_len} > 128 in '{trimmed}'"));
            }
            return Ok(IpCidr::V6 {
                addr: v6,
                prefix_len,
            });
        }
        Err(format!("invalid IP address in CIDR '{trimmed}'"))
    }

    pub fn masked_v4(&self) -> Option<(Ipv4Addr, u8)> {
        match *self {
            IpCidr::V4 { addr, prefix_len } => {
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                Some((Ipv4Addr::from(u32::from(addr) & mask), prefix_len))
            }
            IpCidr::V6 { .. } => None,
        }
    }

    #[allow(dead_code)]
    pub fn masked_v6(&self) -> Option<(Ipv6Addr, u8)> {
        match *self {
            IpCidr::V6 { addr, prefix_len } => {
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                Some((Ipv6Addr::from(u128::from(addr) & mask), prefix_len))
            }
            IpCidr::V4 { .. } => None,
        }
    }

    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        if let Some((net, pfx)) = self.masked_v4() {
            let mask = if pfx == 0 { 0u32 } else { u32::MAX << (32 - pfx) };
            (u32::from(ip) & mask) == u32::from(net)
        } else {
            false
        }
    }
}

pub const VNET_HDR_LEN: usize = 10;
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

#[inline]
pub fn write_vnet_hdr(
    out: &mut [u8],
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
) {
    out[0] = flags;
    out[1] = gso_type;
    out[2..4].copy_from_slice(&hdr_len.to_ne_bytes());
    out[4..6].copy_from_slice(&gso_size.to_ne_bytes());
    out[6..8].copy_from_slice(&csum_start.to_ne_bytes());
    out[8..10].copy_from_slice(&csum_offset.to_ne_bytes());
}

#[inline]
pub fn verify_tcp_checksum(ip_pkt: &[u8]) -> bool {
    if ip_pkt.is_empty() {
        return false;
    }
    match ip_pkt[0] >> 4 {
        4 => {
            if ip_pkt.len() < 20 || ip_pkt[9] != 6 {
                return false;
            }
            let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
            let total_len = u16::from_be_bytes([ip_pkt[2], ip_pkt[3]]) as usize;
            if ihl < 20 || total_len < ihl + 20 || ip_pkt.len() < total_len {
                return false;
            }
            let tcp_len = (total_len - ihl) as u32;
            let mut sum = checksum_accumulate(0, &ip_pkt[12..20]);
            sum += 6u32 + tcp_len;
            sum = checksum_accumulate(sum, &ip_pkt[ihl..total_len]);
            checksum_finish(sum) == 0
        }
        6 => {
            if ip_pkt.len() < 60 || ip_pkt[6] != 6 {
                return false;
            }
            let payload_len = u16::from_be_bytes([ip_pkt[4], ip_pkt[5]]) as usize;
            let end = 40 + payload_len;
            if payload_len < 20 || ip_pkt.len() < end {
                return false;
            }
            let mut sum = checksum_accumulate(0, &ip_pkt[8..40]);
            sum = checksum_accumulate(sum, &(payload_len as u32).to_be_bytes());
            sum += 6u32;
            sum = checksum_accumulate(sum, &ip_pkt[40..end]);
            checksum_finish(sum) == 0
        }
        _ => false,
    }
}

/// Compute un-inverted 16-bit one's complement TCP pseudo-header checksum
/// required in `tcp->check` when setting `VIRTIO_NET_HDR_F_NEEDS_CSUM`.
#[inline]
pub fn verify_udp_checksum(ip_pkt: &[u8]) -> bool {
    if ip_pkt.is_empty() {
        return false;
    }
    match ip_pkt[0] >> 4 {
        4 => {
            if ip_pkt.len() < 28 || ip_pkt[9] != 17 {
                return false;
            }
            let ihl = ((ip_pkt[0] & 0x0f) as usize) * 4;
            let total_len = u16::from_be_bytes([ip_pkt[2], ip_pkt[3]]) as usize;
            if ihl != 20 || total_len <= 28 || ip_pkt.len() < total_len {
                return false;
            }
            let udp_len = u16::from_be_bytes([ip_pkt[24], ip_pkt[25]]) as usize;
            if udp_len != total_len - 20 {
                return false;
            }
            let udp_csum = u16::from_be_bytes([ip_pkt[26], ip_pkt[27]]);
            if udp_csum == 0 {
                return true;
            }
            let mut sum = checksum_accumulate(0, &ip_pkt[12..20]);
            sum += 17u32 + (udp_len as u32);
            sum = checksum_accumulate(sum, &ip_pkt[20..total_len]);
            checksum_finish(sum) == 0
        }
        6 => {
            if ip_pkt.len() < 48 || ip_pkt[6] != 17 {
                return false;
            }
            let payload_len = u16::from_be_bytes([ip_pkt[4], ip_pkt[5]]) as usize;
            let end = 40 + payload_len;
            if payload_len <= 8 || ip_pkt.len() < end {
                return false;
            }
            let udp_len = u16::from_be_bytes([ip_pkt[44], ip_pkt[45]]) as usize;
            if udp_len != payload_len {
                return false;
            }
            let udp_csum = u16::from_be_bytes([ip_pkt[46], ip_pkt[47]]);
            if udp_csum == 0 {
                return false;
            }
            let mut sum = checksum_accumulate(0, &ip_pkt[8..40]);
            sum = checksum_accumulate(sum, &(payload_len as u32).to_be_bytes());
            sum += 17u32;
            sum = checksum_accumulate(sum, &ip_pkt[40..end]);
            checksum_finish(sum) == 0
        }
        _ => false,
    }
}

#[inline]
fn l4_pseudo_sum_be(ip_pkt: &[u8], is_v6: bool, proto: u8, l4_len: u32) -> [u8; 2] {
    let mut sum: u32 = if is_v6 {
        let mut s = checksum_accumulate(0, &ip_pkt[8..40]);
        s = checksum_accumulate(s, &l4_len.to_be_bytes());
        s + (proto as u32)
    } else {
        checksum_accumulate(0, &ip_pkt[12..20]) + (proto as u32) + l4_len
    };
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (sum as u16).to_be_bytes()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct GroFlowKey {
    is_v6: bool,
    is_udp: bool,
    src: [u8; 16],
    dst: [u8; 16],
    sport_dport: [u8; 4],
    ack: [u8; 4],
    window: [u8; 2],
    tos_or_tc: u8,
    ttl_or_hl: u8,
    ip_hdr_len: u8,
    l4_hdr_len: u8,
}

struct GroCandidate<'a> {
    key: GroFlowKey,
    seq: u32,
    flags: u8,
    tcp_opts: &'a [u8],
    payload: &'a [u8],
}

fn parse_gro_candidate(pkt: &[u8], allow_udp: bool) -> Option<GroCandidate<'_>> {
    let ver = *pkt.first()? >> 4;
    match ver {
        4 => {
            if pkt.len() < 28 {
                return None;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl != 20 {
                return None;
            }
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if (frag & 0x3fff) != 0 {
                return None;
            }
            let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if pkt.len() < total_len {
                return None;
            }
            if pkt[9] == 17 {
                if !allow_udp || total_len <= 28 || !verify_udp_checksum(&pkt[..total_len]) {
                    return None;
                }
                let mut src = [0u8; 16];
                let mut dst = [0u8; 16];
                src[..4].copy_from_slice(&pkt[12..16]);
                dst[..4].copy_from_slice(&pkt[16..20]);
                let udp = &pkt[20..total_len];
                return Some(GroCandidate {
                    key: GroFlowKey {
                        is_v6: false,
                        is_udp: true,
                        src,
                        dst,
                        sport_dport: [udp[0], udp[1], udp[2], udp[3]],
                        ack: [0; 4],
                        window: [0; 2],
                        tos_or_tc: pkt[1],
                        ttl_or_hl: pkt[8],
                        ip_hdr_len: 20,
                        l4_hdr_len: 8,
                    },
                    seq: 0,
                    flags: 0,
                    tcp_opts: &[],
                    payload: &udp[8..],
                });
            }
            if total_len < 40 || pkt[9] != 6 {
                return None;
            }
            let tcp = &pkt[20..total_len];
            let tcp_doff = ((tcp[12] >> 4) as usize) * 4;
            if tcp_doff < 20 || tcp.len() <= tcp_doff {
                return None; // Must carry >0 payload bytes
            }
            let flags = tcp[13];
            // Reject SYN(0x02), RST(0x04), URG(0x20), CWR(0x80)
            if (flags & 0xa6) != 0 {
                return None;
            }
            if !verify_tcp_checksum(&pkt[..total_len]) {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src[..4].copy_from_slice(&pkt[12..16]);
            dst[..4].copy_from_slice(&pkt[16..20]);
            Some(GroCandidate {
                key: GroFlowKey {
                    is_v6: false,
                    is_udp: false,
                    src,
                    dst,
                    sport_dport: [tcp[0], tcp[1], tcp[2], tcp[3]],
                    ack: [tcp[8], tcp[9], tcp[10], tcp[11]],
                    window: [tcp[14], tcp[15]],
                    tos_or_tc: pkt[1],
                    ttl_or_hl: pkt[8],
                    ip_hdr_len: 20,
                    l4_hdr_len: tcp_doff as u8,
                },
                seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
                flags,
                tcp_opts: &tcp[20..tcp_doff],
                payload: &tcp[tcp_doff..],
            })
        }
        6 => {
            if pkt.len() < 48 {
                return None;
            }
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let end = 40 + payload_len;
            if pkt.len() < end {
                return None;
            }
            if pkt[6] == 17 {
                if !allow_udp || payload_len <= 8 || !verify_udp_checksum(&pkt[..end]) {
                    return None;
                }
                let mut src = [0u8; 16];
                let mut dst = [0u8; 16];
                src.copy_from_slice(&pkt[8..24]);
                dst.copy_from_slice(&pkt[24..40]);
                let tc = ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4);
                let udp = &pkt[40..end];
                return Some(GroCandidate {
                    key: GroFlowKey {
                        is_v6: true,
                        is_udp: true,
                        src,
                        dst,
                        sport_dport: [udp[0], udp[1], udp[2], udp[3]],
                        ack: [0; 4],
                        window: [0; 2],
                        tos_or_tc: tc,
                        ttl_or_hl: pkt[7],
                        ip_hdr_len: 40,
                        l4_hdr_len: 8,
                    },
                    seq: 0,
                    flags: 0,
                    tcp_opts: &[],
                    payload: &udp[8..],
                });
            }
            if pkt.len() < 60 || pkt[6] != 6 || payload_len < 20 {
                return None;
            }
            let tcp = &pkt[40..end];
            let tcp_doff = ((tcp[12] >> 4) as usize) * 4;
            if tcp_doff < 20 || tcp.len() <= tcp_doff {
                return None;
            }
            let flags = tcp[13];
            if (flags & 0xa6) != 0 {
                return None;
            }
            if !verify_tcp_checksum(&pkt[..end]) {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&pkt[8..24]);
            dst.copy_from_slice(&pkt[24..40]);
            let tc = ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4);
            Some(GroCandidate {
                key: GroFlowKey {
                    is_v6: true,
                    is_udp: false,
                    src,
                    dst,
                    sport_dport: [tcp[0], tcp[1], tcp[2], tcp[3]],
                    ack: [tcp[8], tcp[9], tcp[10], tcp[11]],
                    window: [tcp[14], tcp[15]],
                    tos_or_tc: tc,
                    ttl_or_hl: pkt[7],
                    ip_hdr_len: 40,
                    l4_hdr_len: tcp_doff as u8,
                },
                seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
                flags,
                tcp_opts: &tcp[20..tcp_doff],
                payload: &tcp[tcp_doff..],
            })
        }
        _ => None,
    }
}

const RX_GRO_SLOTS: usize = 16;

struct RxGroSlot {
    buf: Vec<u8>,
    active: bool,
    tunnel_idx: usize,
    key: GroFlowKey,
    next_seq: u32,
    seg_size: usize,
    seg_count: usize,
    total_pkt_len: usize,
    last_flags: u8,
    last_tick: u64,
}

impl RxGroSlot {
    fn new() -> Self {
        Self {
            buf: vec![0u8; VNET_HDR_LEN + 65536],
            active: false,
            tunnel_idx: 0,
            key: GroFlowKey {
                is_v6: false,
                is_udp: false,
                src: [0; 16],
                dst: [0; 16],
                sport_dport: [0; 4],
                ack: [0; 4],
                window: [0; 2],
                tos_or_tc: 0,
                ttl_or_hl: 0,
                ip_hdr_len: 0,
                l4_hdr_len: 0,
            },
            next_seq: 0,
            seg_size: 0,
            seg_count: 0,
            total_pkt_len: 0,
            last_flags: 0,
            last_tick: 0,
        }
    }

    #[inline]
    fn same_4tuple(&self, other: &GroFlowKey) -> bool {
        self.key.is_v6 == other.is_v6
            && self.key.is_udp == other.is_udp
            && self.key.sport_dport == other.sport_dport
            && self.key.src == other.src
            && self.key.dst == other.dst
    }

    fn flush_slot<F>(&mut self, mut emit: F)
    where
        F: FnMut(usize, &[u8]),
    {
        if !self.active {
            return;
        }
        self.active = false;
        let pkt_end = VNET_HDR_LEN + self.total_pkt_len;
        if self.seg_count == 1 {
            self.buf[..VNET_HDR_LEN].fill(0);
            emit(self.tunnel_idx, &self.buf[..pkt_end]);
            return;
        }

        let ip_hlen = self.key.ip_hdr_len as usize;
        let l4_hlen = self.key.l4_hdr_len as usize;
        let hdr_len = (ip_hlen + l4_hlen) as u16;
        let ip_slice = &mut self.buf[VNET_HDR_LEN..pkt_end];

        if self.key.is_v6 {
            let v6_plen = (self.total_pkt_len - 40) as u16;
            ip_slice[4..6].copy_from_slice(&v6_plen.to_be_bytes());
        } else {
            ip_slice[2..4].copy_from_slice(&(self.total_pkt_len as u16).to_be_bytes());
            ip_slice[10] = 0;
            ip_slice[11] = 0;
            let ip_csum = ipv4_header_checksum_fast(&ip_slice[..20]);
            ip_slice[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        }

        if self.key.is_udp {
            let udp_len = (self.total_pkt_len - ip_hlen) as u16;
            ip_slice[ip_hlen + 4..ip_hlen + 6].copy_from_slice(&udp_len.to_be_bytes());
            let psum = l4_pseudo_sum_be(ip_slice, self.key.is_v6, 17, udp_len as u32);
            ip_slice[ip_hlen + 6..ip_hlen + 8].copy_from_slice(&psum);
            write_vnet_hdr(
                &mut self.buf[..VNET_HDR_LEN],
                VIRTIO_NET_HDR_F_NEEDS_CSUM,
                VIRTIO_NET_HDR_GSO_UDP_L4,
                hdr_len,
                self.seg_size as u16,
                ip_hlen as u16,
                6,
            );
            emit(self.tunnel_idx, &self.buf[..pkt_end]);
            return;
        }

        ip_slice[ip_hlen + 13] = self.last_flags;
        let tcp_len = (self.total_pkt_len - ip_hlen) as u32;
        let psum = l4_pseudo_sum_be(ip_slice, self.key.is_v6, 6, tcp_len);
        ip_slice[ip_hlen + 16..ip_hlen + 18].copy_from_slice(&psum);

        let gso_type = if self.key.is_v6 {
            VIRTIO_NET_HDR_GSO_TCPV6
        } else {
            VIRTIO_NET_HDR_GSO_TCPV4
        };
        write_vnet_hdr(
            &mut self.buf[..VNET_HDR_LEN],
            VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type,
            hdr_len,
            self.seg_size as u16,
            ip_hlen as u16,
            16,
        );
        emit(self.tunnel_idx, &self.buf[..pkt_end]);
    }
}

type L4FourTuple = (bool, bool, [u8; 16], [u8; 16], [u8; 4]);

#[inline]
fn extract_l4_4tuple(pkt: &[u8]) -> Option<L4FourTuple> {
    let ver = *pkt.first()? >> 4;
    match ver {
        4 if pkt.len() >= 28 && matches!(pkt[9], 6 | 17) && ((pkt[0] & 0x0f) == 5) => {
            if pkt[9] == 6 && pkt.len() < 40 {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src[..4].copy_from_slice(&pkt[12..16]);
            dst[..4].copy_from_slice(&pkt[16..20]);
            Some((false, pkt[9] == 17, src, dst, [pkt[20], pkt[21], pkt[22], pkt[23]]))
        }
        6 if pkt.len() >= 48 && matches!(pkt[6], 6 | 17) => {
            if pkt[6] == 6 && pkt.len() < 60 {
                return None;
            }
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src.copy_from_slice(&pkt[8..24]);
            dst.copy_from_slice(&pkt[24..40]);
            Some((true, pkt[6] == 17, src, dst, [pkt[40], pkt[41], pkt[42], pkt[43]]))
        }
        _ => None,
    }
}

/// In-batch multi-flow zero-delay RX TCP GRO coalescer (8 pre-allocated flow slots)
/// whose buffers hold `virtio_net_hdr` (10 bytes) ahead of the coalesced IP packet.
pub struct RxGroMerger {
    slots: Vec<RxGroSlot>,
    tick: u64,
}

impl RxGroMerger {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(RX_GRO_SLOTS);
        for _ in 0..RX_GRO_SLOTS {
            slots.push(RxGroSlot::new());
        }
        Self { slots, tick: 0 }
    }

    #[inline]
    pub fn has_active(&self) -> bool {
        self.slots.iter().any(|s| s.active)
    }

    /// Flush all pending coalesced packets in FIFO order via `emit(tunnel_idx, complete_vnet_slice)`.
    pub fn flush<F>(&mut self, mut emit: F)
    where
        F: FnMut(usize, &[u8]),
    {
        loop {
            let mut best_idx: Option<usize> = None;
            let mut best_tick = u64::MAX;
            for (idx, slot) in self.slots.iter().enumerate() {
                if slot.active && slot.last_tick < best_tick {
                    best_tick = slot.last_tick;
                    best_idx = Some(idx);
                }
            }
            let Some(idx) = best_idx else {
                break;
            };
            self.slots[idx].flush_slot(&mut emit);
        }
    }

    /// Feed an inbound IP packet. Returns `true` if absorbed into a GRO slot
    /// (caller should not write it directly), or `false` if caller can write it directly.
    #[cfg(test)]
    pub fn feed<F>(&mut self, tunnel_idx: usize, pkt: &[u8], emit: F) -> bool
    where
        F: FnMut(usize, &[u8]),
    {
        self.feed_with_udp(tunnel_idx, pkt, false, emit)
    }

    pub fn feed_with_udp<F>(
        &mut self,
        tunnel_idx: usize,
        pkt: &[u8],
        allow_udp_gro: bool,
        mut emit: F,
    ) -> bool
    where
        F: FnMut(usize, &[u8]),
    {
        let Some(cand) = parse_gro_candidate(pkt, allow_udp_gro) else {
            if let Some((is_v6, is_udp, src, dst, ports)) = extract_l4_4tuple(pkt) {
                for slot in &mut self.slots {
                    if slot.active
                        && slot.tunnel_idx == tunnel_idx
                        && slot.key.is_v6 == is_v6
                        && slot.key.is_udp == is_udp
                        && slot.key.sport_dport == ports
                        && slot.key.src == src
                        && slot.key.dst == dst
                    {
                        slot.flush_slot(&mut emit);
                        break;
                    }
                }
            }
            return false;
        };

        let hdr_len = cand.key.ip_hdr_len as usize + cand.key.l4_hdr_len as usize;
        let pkt_len = hdr_len + cand.payload.len();
        let min_payload = if cand.key.is_udp { 1usize } else { 64usize };

        let existing_idx = self.slots.iter().position(|slot| {
            slot.active && slot.tunnel_idx == tunnel_idx && slot.same_4tuple(&cand.key)
        });

        if let Some(idx) = existing_idx {
            let slot = &mut self.slots[idx];
            let can_append = if cand.key.is_udp {
                slot.key == cand.key
                    && cand.payload.len() <= slot.seg_size
                    && slot.total_pkt_len + cand.payload.len() <= 64500
            } else {
                let start = VNET_HDR_LEN + slot.key.ip_hdr_len as usize + 20;
                let end = VNET_HDR_LEN + slot.key.ip_hdr_len as usize + slot.key.l4_hdr_len as usize;
                let opts_match = &slot.buf[start..end] == cand.tcp_opts;
                slot.key == cand.key
                    && cand.seq == slot.next_seq
                    && (slot.last_flags & 0x09) == 0
                    && opts_match
                    && cand.payload.len() <= slot.seg_size
                    && slot.total_pkt_len + cand.payload.len() <= 64500
            };

            if can_append {
                self.tick = self.tick.wrapping_add(1);
                let dst_start = VNET_HDR_LEN + slot.total_pkt_len;
                slot.buf[dst_start..dst_start + cand.payload.len()].copy_from_slice(cand.payload);
                slot.total_pkt_len += cand.payload.len();
                slot.next_seq = slot.next_seq.wrapping_add(cand.payload.len() as u32);
                slot.seg_count += 1;
                slot.last_flags = cand.flags;
                slot.last_tick = self.tick;
                if cand.payload.len() < slot.seg_size
                    || (cand.flags & 0x09) != 0
                    || slot.total_pkt_len + slot.seg_size > 64500
                {
                    slot.flush_slot(emit);
                }
                return true;
            }

            slot.flush_slot(&mut emit);
            if (!cand.key.is_udp && (cand.flags & 0x09) != 0)
                || cand.payload.len() < min_payload
                || pkt_len > 64500
            {
                return false;
            }
            self.tick = self.tick.wrapping_add(1);
            slot.active = true;
            slot.tunnel_idx = tunnel_idx;
            slot.key = cand.key;
            slot.next_seq = cand.seq.wrapping_add(cand.payload.len() as u32);
            slot.seg_size = cand.payload.len();
            slot.seg_count = 1;
            slot.total_pkt_len = pkt_len;
            slot.last_flags = cand.flags;
            slot.last_tick = self.tick;
            slot.buf[VNET_HDR_LEN..VNET_HDR_LEN + pkt_len].copy_from_slice(&pkt[..pkt_len]);
            return true;
        }

        if (!cand.key.is_udp && (cand.flags & 0x09) != 0)
            || cand.payload.len() < min_payload
            || pkt_len > 64500
        {
            return false;
        }

        let target_idx = if let Some(free_idx) = self.slots.iter().position(|s| !s.active) {
            free_idx
        } else {
            let mut oldest_idx = 0usize;
            let mut oldest_tick = u64::MAX;
            for (idx, s) in self.slots.iter().enumerate() {
                if s.last_tick < oldest_tick {
                    oldest_tick = s.last_tick;
                    oldest_idx = idx;
                }
            }
            self.slots[oldest_idx].flush_slot(&mut emit);
            oldest_idx
        };

        self.tick = self.tick.wrapping_add(1);
        let slot = &mut self.slots[target_idx];
        slot.active = true;
        slot.tunnel_idx = tunnel_idx;
        slot.key = cand.key;
        slot.next_seq = cand.seq.wrapping_add(cand.payload.len() as u32);
        slot.seg_size = cand.payload.len();
        slot.seg_count = 1;
        slot.total_pkt_len = pkt_len;
        slot.last_flags = cand.flags;
        slot.last_tick = self.tick;
        slot.buf[VNET_HDR_LEN..VNET_HDR_LEN + pkt_len].copy_from_slice(&pkt[..pkt_len]);
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    #[allow(dead_code)]
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VnetHdr {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < VNET_HDR_LEN {
            return None;
        }
        Some(Self {
            flags: buf[0],
            gso_type: buf[1],
            hdr_len: u16::from_ne_bytes([buf[2], buf[3]]),
            gso_size: u16::from_ne_bytes([buf[4], buf[5]]),
            csum_start: u16::from_ne_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_ne_bytes([buf[8], buf[9]]),
        })
    }
}

/// Complete partial L4 checksum left by Linux `VIRTIO_NET_HDR_F_NEEDS_CSUM`.
pub fn finish_partial_checksum(pkt: &mut [u8], hdr: VnetHdr) -> bool {
    if (hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) == 0 {
        return true;
    }
    let start = hdr.csum_start as usize;
    let offset = hdr.csum_offset as usize;
    if start >= pkt.len() || start + offset + 2 > pkt.len() {
        return false;
    }
    let mut csum = internet_checksum(&pkt[start..]);
    // UDP uses 0xffff instead of 0x0000 for zero checksum
    if csum == 0 && offset == 6 {
        csum = 0xffff;
    }
    pkt[start + offset..start + offset + 2].copy_from_slice(&csum.to_be_bytes());
    true
}

/// Zero-copy sink trait allowing `segment_tso_into` to write directly into target mmap or batch slots.
pub trait TxSlotSink {
    fn alloc_slot(&mut self, gre_pkt_len: usize) -> Option<&mut [u8]>;
    fn commit_slot(&mut self, gre_pkt_len: usize);
}

/// Zero-copy TSO segmentation writing `[4B GRE + InnerIP + TCP + Payload]` directly into `sink`.
pub fn segment_tso_into<S: TxSlotSink>(
    pkt: &[u8],
    hdr: VnetHdr,
    tunnel_mtu: u16,
    sink: &mut S,
) -> bool {
    let base_gso = hdr.gso_type & !VIRTIO_NET_HDR_GSO_ECN;
    match base_gso {
        VIRTIO_NET_HDR_GSO_TCPV4 => {
            if pkt.len() < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6 {
                return false;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl + 20 {
                return false;
            }
            let tcp_doff = ((pkt[ihl + 12] >> 4) as usize) * 4;
            if tcp_doff < 20 || pkt.len() < ihl + tcp_doff {
                return false;
            }
            let l4_hdr_len = ihl + tcp_doff;
            let mtu_cap = (tunnel_mtu as usize).saturating_sub(l4_hdr_len);
            let seg_mss = if hdr.gso_size > 0 {
                (hdr.gso_size as usize).min(mtu_cap)
            } else {
                mtu_cap
            };
            if seg_mss == 0 {
                return false;
            }

            let base_id = u16::from_be_bytes([pkt[4], pkt[5]]);
            let base_seq = u32::from_be_bytes([
                pkt[ihl + 4],
                pkt[ihl + 5],
                pkt[ihl + 6],
                pkt[ihl + 7],
            ]);
            let orig_flags = pkt[ihl + 13];
            let pseudo_base = checksum_accumulate(0, &pkt[12..20]) + 6u32;

            let total_payload = pkt.len() - l4_hdr_len;
            let mut offset = 0usize;
            let mut seg_idx = 0usize;

            while offset < total_payload || seg_idx == 0 {
                let chunk_len = (total_payload - offset).min(seg_mss);
                let pkt_len = l4_hdr_len + chunk_len;
                let gre_len = 4 + pkt_len;
                let is_last = offset + chunk_len >= total_payload;

                let Some(seg_buf) = sink.alloc_slot(gre_len) else {
                    return false;
                };
                if seg_buf.len() < gre_len {
                    return false;
                }
                let out_ip = &mut seg_buf[4..gre_len];
                out_ip[..l4_hdr_len].copy_from_slice(&pkt[..l4_hdr_len]);
                if chunk_len > 0 {
                    out_ip[l4_hdr_len..].copy_from_slice(
                        &pkt[l4_hdr_len + offset..l4_hdr_len + offset + chunk_len],
                    );
                }

                out_ip[2..4].copy_from_slice(&(pkt_len as u16).to_be_bytes());
                out_ip[4..6].copy_from_slice(&(base_id.wrapping_add(seg_idx as u16)).to_be_bytes());
                out_ip[10] = 0;
                out_ip[11] = 0;
                let ip_csum = if ihl == 20 {
                    ipv4_header_checksum_fast(&out_ip[..20])
                } else {
                    internet_checksum(&out_ip[..ihl])
                };
                out_ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                let tcp = &mut out_ip[ihl..];
                tcp[4..8].copy_from_slice(&(base_seq.wrapping_add(offset as u32)).to_be_bytes());
                let mut flags = orig_flags;
                if seg_idx > 0 {
                    flags &= !0x80;
                }
                if !is_last {
                    flags &= !(0x01 | 0x08);
                }
                tcp[13] = flags;
                tcp[16] = 0;
                tcp[17] = 0;
                let tcp_len = tcp.len() as u32;
                let sum = checksum_accumulate(pseudo_base + tcp_len, tcp);
                let tcp_csum = checksum_finish(sum);
                tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

                seg_buf[0] = 0;
                seg_buf[1] = 0;
                seg_buf[2] = 0x08;
                seg_buf[3] = 0x00;
                sink.commit_slot(gre_len);

                if is_last {
                    break;
                }
                offset += chunk_len;
                seg_idx += 1;
            }
            true
        }
        VIRTIO_NET_HDR_GSO_TCPV6 => {
            if pkt.len() < 60 || (pkt[0] >> 4) != 6 {
                return false;
            }
            let Some(tcp_off) = find_ipv6_tcp_offset(pkt) else {
                return false;
            };
            if pkt.len() < tcp_off + 20 {
                return false;
            }
            let tcp_doff = ((pkt[tcp_off + 12] >> 4) as usize) * 4;
            if tcp_doff < 20 || pkt.len() < tcp_off + tcp_doff {
                return false;
            }
            let l4_hdr_len = tcp_off + tcp_doff;
            let mtu_cap = (tunnel_mtu as usize).saturating_sub(l4_hdr_len);
            let seg_mss = if hdr.gso_size > 0 {
                (hdr.gso_size as usize).min(mtu_cap)
            } else {
                mtu_cap
            };
            if seg_mss == 0 {
                return false;
            }

            let base_seq = u32::from_be_bytes([
                pkt[tcp_off + 4],
                pkt[tcp_off + 5],
                pkt[tcp_off + 6],
                pkt[tcp_off + 7],
            ]);
            let orig_flags = pkt[tcp_off + 13];
            let pseudo_base = checksum_accumulate(0, &pkt[8..40]) + 6u32;

            let total_payload = pkt.len() - l4_hdr_len;
            let mut offset = 0usize;
            let mut seg_idx = 0usize;

            while offset < total_payload || seg_idx == 0 {
                let chunk_len = (total_payload - offset).min(seg_mss);
                let pkt_len = l4_hdr_len + chunk_len;
                let gre_len = 4 + pkt_len;
                let is_last = offset + chunk_len >= total_payload;

                let Some(seg_buf) = sink.alloc_slot(gre_len) else {
                    return false;
                };
                if seg_buf.len() < gre_len {
                    return false;
                }
                let out_ip = &mut seg_buf[4..gre_len];
                out_ip[..l4_hdr_len].copy_from_slice(&pkt[..l4_hdr_len]);
                if chunk_len > 0 {
                    out_ip[l4_hdr_len..].copy_from_slice(
                        &pkt[l4_hdr_len + offset..l4_hdr_len + offset + chunk_len],
                    );
                }
                let v6_payload_len = (pkt_len - 40) as u16;
                out_ip[4..6].copy_from_slice(&v6_payload_len.to_be_bytes());

                let tcp = &mut out_ip[tcp_off..];
                tcp[4..8].copy_from_slice(&(base_seq.wrapping_add(offset as u32)).to_be_bytes());
                let mut flags = orig_flags;
                if seg_idx > 0 {
                    flags &= !0x80;
                }
                if !is_last {
                    flags &= !(0x01 | 0x08);
                }
                tcp[13] = flags;
                tcp[16] = 0;
                tcp[17] = 0;
                let tcp_len = tcp.len() as u32;
                let sum = checksum_accumulate(pseudo_base + tcp_len, tcp);
                let tcp_csum = checksum_finish(sum);
                tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

                seg_buf[0] = 0;
                seg_buf[1] = 0;
                seg_buf[2] = 0x86;
                seg_buf[3] = 0xDD;
                sink.commit_slot(gre_len);

                if is_last {
                    break;
                }
                offset += chunk_len;
                seg_idx += 1;
            }
            true
        }
        VIRTIO_NET_HDR_GSO_UDP_L4 => {
            if (hdr.gso_type & VIRTIO_NET_HDR_GSO_ECN) != 0 || hdr.gso_size == 0 {
                return false;
            }
            let seg_size = hdr.gso_size as usize;
            match pkt.first().map(|b| b >> 4) {
                Some(4) => {
                    if pkt.len() < 28 || pkt[9] != 17 {
                        return false;
                    }
                    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
                    if ihl < 20 || pkt.len() < ihl + 8 {
                        return false;
                    }
                    let l4_hdr_len = ihl + 8;
                    let base_id = u16::from_be_bytes([pkt[4], pkt[5]]);
                    let pseudo_base = checksum_accumulate(0, &pkt[12..20]) + 17u32;
                    let total_payload = pkt.len() - l4_hdr_len;
                    let mut offset = 0usize;
                    let mut seg_idx = 0usize;

                    while offset < total_payload || seg_idx == 0 {
                        let chunk_len = (total_payload - offset).min(seg_size);
                        let pkt_len = l4_hdr_len + chunk_len;
                        if pkt_len > u16::MAX as usize {
                            return false;
                        }
                        let gre_len = 4 + pkt_len;
                        let is_last = offset + chunk_len >= total_payload;

                        let Some(seg_buf) = sink.alloc_slot(gre_len) else {
                            return false;
                        };
                        if seg_buf.len() < gre_len {
                            return false;
                        }
                        let out_ip = &mut seg_buf[4..gre_len];
                        out_ip[..l4_hdr_len].copy_from_slice(&pkt[..l4_hdr_len]);
                        if chunk_len > 0 {
                            out_ip[l4_hdr_len..].copy_from_slice(
                                &pkt[l4_hdr_len + offset..l4_hdr_len + offset + chunk_len],
                            );
                        }

                        out_ip[2..4].copy_from_slice(&(pkt_len as u16).to_be_bytes());
                        out_ip[4..6]
                            .copy_from_slice(&(base_id.wrapping_add(seg_idx as u16)).to_be_bytes());
                        out_ip[10] = 0;
                        out_ip[11] = 0;
                        let ip_csum = if ihl == 20 {
                            ipv4_header_checksum_fast(&out_ip[..20])
                        } else {
                            internet_checksum(&out_ip[..ihl])
                        };
                        out_ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                        let udp = &mut out_ip[ihl..];
                        let udp_len = (8 + chunk_len) as u16;
                        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
                        udp[6] = 0;
                        udp[7] = 0;
                        let sum = checksum_accumulate(pseudo_base + (udp_len as u32), udp);
                        let mut udp_csum = checksum_finish(sum);
                        if udp_csum == 0 {
                            udp_csum = 0xffff;
                        }
                        udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());

                        seg_buf[0] = 0;
                        seg_buf[1] = 0;
                        seg_buf[2] = 0x08;
                        seg_buf[3] = 0x00;
                        sink.commit_slot(gre_len);

                        if is_last {
                            break;
                        }
                        offset += chunk_len;
                        seg_idx += 1;
                    }
                    true
                }
                Some(6) => {
                    if pkt.len() < 48 {
                        return false;
                    }
                    let Some(udp_off) = find_ipv6_l4_offset(pkt, 17) else {
                        return false;
                    };
                    if pkt.len() < udp_off + 8 {
                        return false;
                    }
                    let l4_hdr_len = udp_off + 8;
                    let pseudo_base = checksum_accumulate(0, &pkt[8..40]) + 17u32;
                    let total_payload = pkt.len() - l4_hdr_len;
                    let mut offset = 0usize;
                    let mut seg_idx = 0usize;

                    while offset < total_payload || seg_idx == 0 {
                        let chunk_len = (total_payload - offset).min(seg_size);
                        let pkt_len = l4_hdr_len + chunk_len;
                        if pkt_len - 40 > u16::MAX as usize {
                            return false;
                        }
                        let gre_len = 4 + pkt_len;
                        let is_last = offset + chunk_len >= total_payload;

                        let Some(seg_buf) = sink.alloc_slot(gre_len) else {
                            return false;
                        };
                        if seg_buf.len() < gre_len {
                            return false;
                        }
                        let out_ip = &mut seg_buf[4..gre_len];
                        out_ip[..l4_hdr_len].copy_from_slice(&pkt[..l4_hdr_len]);
                        if chunk_len > 0 {
                            out_ip[l4_hdr_len..].copy_from_slice(
                                &pkt[l4_hdr_len + offset..l4_hdr_len + offset + chunk_len],
                            );
                        }
                        let v6_plen = (pkt_len - 40) as u16;
                        out_ip[4..6].copy_from_slice(&v6_plen.to_be_bytes());

                        let udp = &mut out_ip[udp_off..];
                        let udp_len = (8 + chunk_len) as u16;
                        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
                        udp[6] = 0;
                        udp[7] = 0;
                        let mut sum = checksum_accumulate(
                            pseudo_base,
                            &(udp_len as u32).to_be_bytes(),
                        );
                        sum = checksum_accumulate(sum, udp);
                        let mut udp_csum = checksum_finish(sum);
                        if udp_csum == 0 {
                            udp_csum = 0xffff;
                        }
                        udp[6..8].copy_from_slice(&udp_csum.to_be_bytes());

                        seg_buf[0] = 0;
                        seg_buf[1] = 0;
                        seg_buf[2] = 0x86;
                        seg_buf[3] = 0xDD;
                        sink.commit_slot(gre_len);

                        if is_last {
                            break;
                        }
                        offset += chunk_len;
                        seg_idx += 1;
                    }
                    true
                }
                _ => false,
            }
        }
        _ => false,
    }
}

/// Segment a TSO IPv4 or IPv6 TCP packet into standard MTU-sized GRE packets placed into
/// `emit(gre_proto, out_slice_with_4b_gre_headroom_ready)`.
/// Each emitted slice starts at offset 0 with 4 bytes reserved for GRE header `[0..4]`.
#[cfg(test)]
pub fn segment_tso_packet<F>(
    pkt: &[u8],
    hdr: VnetHdr,
    tunnel_mtu: u16,
    mut emit: F,
) -> bool
where
    F: FnMut(u16, &[u8], usize),
{
    let base_gso = hdr.gso_type & !VIRTIO_NET_HDR_GSO_ECN;
    match base_gso {
        VIRTIO_NET_HDR_GSO_TCPV4 => {
            if pkt.len() < 40 || (pkt[0] >> 4) != 4 || pkt[9] != 6 {
                return false;
            }
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl + 20 {
                return false;
            }
            let tcp_doff = ((pkt[ihl + 12] >> 4) as usize) * 4;
            if tcp_doff < 20 || pkt.len() < ihl + tcp_doff {
                return false;
            }
            let l4_hdr_len = ihl + tcp_doff;
            let mtu_cap = (tunnel_mtu as usize).saturating_sub(l4_hdr_len);
            let seg_mss = if hdr.gso_size > 0 {
                (hdr.gso_size as usize).min(mtu_cap)
            } else {
                mtu_cap
            };
            if seg_mss == 0 {
                return false;
            }

            let base_id = u16::from_be_bytes([pkt[4], pkt[5]]);
            let base_seq = u32::from_be_bytes([
                pkt[ihl + 4],
                pkt[ihl + 5],
                pkt[ihl + 6],
                pkt[ihl + 7],
            ]);
            let orig_flags = pkt[ihl + 13];
            let pseudo_base = checksum_accumulate(0, &pkt[12..20]) + 6u32;

            let mut seg_buf = [0u8; 2048];
            let total_payload = pkt.len() - l4_hdr_len;
            let mut offset = 0usize;
            let mut seg_idx = 0usize;

            while offset < total_payload || seg_idx == 0 {
                let chunk_len = (total_payload - offset).min(seg_mss);
                let pkt_len = l4_hdr_len + chunk_len;
                let is_last = offset + chunk_len >= total_payload;

                if 4 + pkt_len > seg_buf.len() {
                    return false;
                }
                let out_ip = &mut seg_buf[4..4 + pkt_len];
                out_ip[..l4_hdr_len].copy_from_slice(&pkt[..l4_hdr_len]);
                if chunk_len > 0 {
                    out_ip[l4_hdr_len..].copy_from_slice(&pkt[l4_hdr_len + offset..l4_hdr_len + offset + chunk_len]);
                }

                // Update IPv4 total_len, id, and IP header checksum
                out_ip[2..4].copy_from_slice(&(pkt_len as u16).to_be_bytes());
                out_ip[4..6].copy_from_slice(&(base_id.wrapping_add(seg_idx as u16)).to_be_bytes());
                out_ip[10] = 0;
                out_ip[11] = 0;
                let ip_csum = internet_checksum(&out_ip[..ihl]);
                out_ip[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                // Update TCP seq, flags, and checksum
                let tcp = &mut out_ip[ihl..];
                tcp[4..8].copy_from_slice(&(base_seq.wrapping_add(offset as u32)).to_be_bytes());
                let mut flags = orig_flags;
                if seg_idx > 0 {
                    flags &= !0x80; // Clear CWR after first segment
                }
                if !is_last {
                    flags &= !(0x01 | 0x08); // Clear FIN and PSH on non-final segments
                }
                tcp[13] = flags;
                tcp[16] = 0;
                tcp[17] = 0;
                let tcp_len = tcp.len() as u32;
                let sum = checksum_accumulate(pseudo_base + tcp_len, tcp);
                let tcp_csum = checksum_finish(sum);
                tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

                // Write GRE header in [0..4]
                seg_buf[0] = 0;
                seg_buf[1] = 0;
                seg_buf[2] = 0x08;
                seg_buf[3] = 0x00;
                emit(0x0800, &seg_buf[..4 + pkt_len], 4 + pkt_len);

                if is_last {
                    break;
                }
                offset += chunk_len;
                seg_idx += 1;
            }
            true
        }
        VIRTIO_NET_HDR_GSO_TCPV6 => {
            if pkt.len() < 60 || (pkt[0] >> 4) != 6 {
                return false;
            }
            let Some(tcp_off) = find_ipv6_tcp_offset(pkt) else {
                return false;
            };
            if pkt.len() < tcp_off + 20 {
                return false;
            }
            let tcp_doff = ((pkt[tcp_off + 12] >> 4) as usize) * 4;
            if tcp_doff < 20 || pkt.len() < tcp_off + tcp_doff {
                return false;
            }
            let l4_hdr_len = tcp_off + tcp_doff;
            let mtu_cap = (tunnel_mtu as usize).saturating_sub(l4_hdr_len);
            let seg_mss = if hdr.gso_size > 0 {
                (hdr.gso_size as usize).min(mtu_cap)
            } else {
                mtu_cap
            };
            if seg_mss == 0 {
                return false;
            }

            let base_seq = u32::from_be_bytes([
                pkt[tcp_off + 4],
                pkt[tcp_off + 5],
                pkt[tcp_off + 6],
                pkt[tcp_off + 7],
            ]);
            let orig_flags = pkt[tcp_off + 13];
            let pseudo_base = checksum_accumulate(0, &pkt[8..40]) + 6u32;

            let mut seg_buf = [0u8; 2048];
            let total_payload = pkt.len() - l4_hdr_len;
            let mut offset = 0usize;
            let mut seg_idx = 0usize;

            while offset < total_payload || seg_idx == 0 {
                let chunk_len = (total_payload - offset).min(seg_mss);
                let pkt_len = l4_hdr_len + chunk_len;
                let is_last = offset + chunk_len >= total_payload;

                if 4 + pkt_len > seg_buf.len() {
                    return false;
                }
                let out_ip = &mut seg_buf[4..4 + pkt_len];
                out_ip[..l4_hdr_len].copy_from_slice(&pkt[..l4_hdr_len]);
                if chunk_len > 0 {
                    out_ip[l4_hdr_len..].copy_from_slice(&pkt[l4_hdr_len + offset..l4_hdr_len + offset + chunk_len]);
                }
                let v6_payload_len = (pkt_len - 40) as u16;
                out_ip[4..6].copy_from_slice(&v6_payload_len.to_be_bytes());

                let tcp = &mut out_ip[tcp_off..];
                tcp[4..8].copy_from_slice(&(base_seq.wrapping_add(offset as u32)).to_be_bytes());
                let mut flags = orig_flags;
                if seg_idx > 0 {
                    flags &= !0x80;
                }
                if !is_last {
                    flags &= !(0x01 | 0x08);
                }
                tcp[13] = flags;
                tcp[16] = 0;
                tcp[17] = 0;
                let tcp_len = tcp.len() as u32;
                let sum = checksum_accumulate(pseudo_base + tcp_len, tcp);
                let tcp_csum = checksum_finish(sum);
                tcp[16..18].copy_from_slice(&tcp_csum.to_be_bytes());

                seg_buf[0] = 0;
                seg_buf[1] = 0;
                seg_buf[2] = 0x86;
                seg_buf[3] = 0xDD;
                emit(0x86DD, &seg_buf[..4 + pkt_len], 4 + pkt_len);

                if is_last {
                    break;
                }
                offset += chunk_len;
                seg_idx += 1;
            }
            true
        }
        _ => false,
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpCidr::V4 { addr, prefix_len } => write!(f, "{addr}/{prefix_len}"),
            IpCidr::V6 { addr, prefix_len } => write!(f, "{addr}/{prefix_len}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_tcp_syn(mss: u16, leading_nop: bool) -> Vec<u8> {
        let mut opts = Vec::new();
        if leading_nop {
            opts.push(1);
        }
        opts.extend_from_slice(&[2, 4]);
        opts.extend_from_slice(&mss.to_be_bytes());
        while opts.len() % 4 != 0 {
            opts.push(1);
        }
        let tcp_len = 20 + opts.len();
        let total_len = 20 + tcp_len;
        let mut pkt = vec![0u8; total_len];
        write_ipv4_header(
            &mut pkt,
            Ipv4Addr::new(172, 16, 1, 2),
            Ipv4Addr::new(10, 1, 101, 5),
            6,
            1,
            64,
            total_len as u16,
        );
        let tcp = &mut pkt[20..];
        tcp[0..2].copy_from_slice(&45000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        tcp[12] = ((tcp_len / 4) as u8) << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp[20..].copy_from_slice(&opts);
        let csum = compute_tcp_v4_checksum(&pkt).unwrap();
        pkt[20 + 16..20 + 18].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    fn build_ipv6_tcp_syn(mss: u16, with_dest_opt: bool) -> Vec<u8> {
        let opts = [2u8, 4, (mss >> 8) as u8, mss as u8];
        let ext_len = if with_dest_opt { 8 } else { 0 };
        let tcp_len = 24;
        let payload_len = ext_len + tcp_len;
        let mut pkt = vec![0u8; 40 + payload_len];
        pkt[0] = 0x62;
        pkt[1] = 0x00;
        pkt[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        pkt[6] = if with_dest_opt { 60 } else { 6 };
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        pkt[24..40].copy_from_slice(&Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 5).octets());
        let mut tcp_off = 40;
        if with_dest_opt {
            pkt[40] = 6;
            pkt[41] = 0;
            tcp_off += 8;
        }
        let tcp = &mut pkt[tcp_off..];
        tcp[0..2].copy_from_slice(&51000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = (24 / 4) << 4;
        tcp[13] = 0x12;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..24].copy_from_slice(&opts);
        let csum = compute_tcp_v6_checksum(&pkt, tcp_off, pkt.len()).unwrap();
        pkt[tcp_off + 16..tcp_off + 18].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn test_ipv4_mss_clamp_aligned_and_unaligned() {
        for leading_nop in [false, true] {
            let mut pkt = build_ipv4_tcp_syn(1460, leading_nop);
            assert!(clamp_tcp_mss(&mut pkt, 1476));
            let opt_idx = if leading_nop { 20 + 21 } else { 20 + 20 };
            assert_eq!(pkt[opt_idx], 2);
            let new_mss = u16::from_be_bytes([pkt[opt_idx + 2], pkt[opt_idx + 3]]);
            assert_eq!(new_mss, 1436);
            let expected_csum = compute_tcp_v4_checksum(&pkt).unwrap();
            let actual_csum = u16::from_be_bytes([pkt[20 + 16], pkt[20 + 17]]);
            assert_eq!(actual_csum, expected_csum);

            assert!(!clamp_tcp_mss(&mut pkt, 1476));
        }
    }

    #[test]
    fn test_ipv4_smaller_mss_untouched() {
        let mut pkt = build_ipv4_tcp_syn(1300, false);
        let before = pkt.clone();
        assert!(!clamp_tcp_mss(&mut pkt, 1476));
        assert_eq!(pkt, before);
    }

    #[test]
    fn test_ipv6_mss_clamp_with_ext_header() {
        for with_ext in [false, true] {
            let mut pkt = build_ipv6_tcp_syn(1440, with_ext);
            assert!(clamp_tcp_mss(&mut pkt, 1476));
            let tcp_off = if with_ext { 48 } else { 40 };
            let new_mss = u16::from_be_bytes([pkt[tcp_off + 22], pkt[tcp_off + 23]]);
            assert_eq!(new_mss, 1416);
            let expected_csum = compute_tcp_v6_checksum(&pkt, tcp_off, pkt.len()).unwrap();
            let actual_csum = u16::from_be_bytes([pkt[tcp_off + 16], pkt[tcp_off + 17]]);
            assert_eq!(actual_csum, expected_csum);
        }
    }

    #[test]
    fn test_inspect_inner_ip_dscp_df() {
        let mut v4 = vec![0u8; 20];
        write_ipv4_header(&mut v4, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 1, 1, 64, 20);
        v4[1] = 46 << 2;
        v4[6] = 0x40;
        let meta = inspect_inner_ip(&v4).unwrap();
        assert_eq!(meta.version, IpVersion::V4);
        assert_eq!(meta.dscp, 46);
        assert!(meta.df);

        let v6 = build_ipv6_tcp_syn(1400, false);
        let meta6 = inspect_inner_ip(&v6).unwrap();
        assert_eq!(meta6.version, IpVersion::V6);
        assert_eq!(meta6.dscp, 8);
        assert!(!meta6.df);
    }

    #[test]
    fn test_fast_checksum_matches_reference() {
        for len in [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1476, 1477, 1500] {
            let data: Vec<u8> = (0..len).map(|i| ((i * 131 + 17) & 0xff) as u8).collect();
            let mut ref_sum: u32 = 0;
            let mut i = 0;
            while i + 1 < data.len() {
                ref_sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
                i += 2;
            }
            if i < data.len() {
                ref_sum += (data[i] as u32) << 8;
            }
            assert_eq!(
                checksum_finish(checksum_accumulate(0, &data)),
                checksum_finish(ref_sum),
                "mismatch at len {len}"
            );
            assert_eq!(
                checksum_finish(checksum_accumulate(0x12345, &data)),
                checksum_finish(0x12345 + ref_sum),
                "mismatch with initial sum at len {len}"
            );
        }
    }

    #[test]
    fn test_tso_v4_segmentation_and_checksums() {
        let payload = vec![0x5au8; 3000];
        let mut pkt = vec![0u8; 40 + payload.len()];
        let total_len = pkt.len() as u16;
        write_ipv4_header(
            &mut pkt,
            Ipv4Addr::new(172, 16, 1, 1),
            Ipv4Addr::new(172, 16, 1, 2),
            6,
            100,
            64,
            total_len,
        );
        pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1000u32.to_be_bytes());
        pkt[32] = 5 << 4;
        pkt[33] = 0x98; // CWR | ACK | PSH
        pkt[40..].copy_from_slice(&payload);

        let vnet = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN,
            hdr_len: 40,
            gso_size: 1436,
            csum_start: 20,
            csum_offset: 16,
        };

        let mut segments: Vec<Vec<u8>> = Vec::new();
        assert!(segment_tso_packet(&pkt, vnet, 1476, |proto, slice, len| {
            assert_eq!(proto, 0x0800);
            assert_eq!(slice.len(), len);
            segments.push(slice[4..].to_vec());
        }));
        assert_eq!(segments.len(), 3); // 1436 + 1436 + 128 = 3000
        assert_eq!(segments[0].len(), 1476);
        assert_eq!(segments[1].len(), 1476);
        assert_eq!(segments[2].len(), 40 + 128);
        // Check seq progression and CWR/PSH flags
        assert_eq!(u32::from_be_bytes([segments[0][24], segments[0][25], segments[0][26], segments[0][27]]), 1000);
        assert_eq!(u32::from_be_bytes([segments[1][24], segments[1][25], segments[1][26], segments[1][27]]), 2436);
        assert_eq!(u32::from_be_bytes([segments[2][24], segments[2][25], segments[2][26], segments[2][27]]), 3872);
        assert_eq!(segments[0][33], 0x90); // CWR + ACK (PSH stripped)
        assert_eq!(segments[1][33], 0x10); // ACK only
        assert_eq!(segments[2][33], 0x18); // ACK + PSH kept on final
        for seg in &segments {
            assert_eq!(internet_checksum(&seg[..20]), 0);
            let expected_tcp = compute_tcp_v4_checksum(seg).unwrap();
            assert_eq!(u16::from_be_bytes([seg[36], seg[37]]), expected_tcp);
        }
    }

    #[test]
    fn test_rx_gro_coalescing_roundtrip() {
        // Build 3 sequential TCP segments via segment_tso_packet, then coalesce them back with RxGroMerger
        let payload: Vec<u8> = (0..3000).map(|i| (i & 0xff) as u8).collect();
        let mut pkt = vec![0u8; 40 + payload.len()];
        let total_len = pkt.len() as u16;
        write_ipv4_header(
            &mut pkt,
            Ipv4Addr::new(172, 16, 1, 1),
            Ipv4Addr::new(172, 16, 1, 2),
            6,
            100,
            64,
            total_len,
        );
        pkt[20..22].copy_from_slice(&50000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&1000u32.to_be_bytes());
        pkt[32] = 5 << 4;
        pkt[33] = 0x18; // ACK | PSH
        pkt[40..].copy_from_slice(&payload);

        let vnet = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1436,
            csum_start: 20,
            csum_offset: 16,
        };

        let mut segs: Vec<Vec<u8>> = Vec::new();
        segment_tso_packet(&pkt, vnet, 1476, |_, slice, _| {
            segs.push(slice[4..].to_vec());
        });
        assert_eq!(segs.len(), 3);

        let mut merger = RxGroMerger::new();
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        for s in &segs {
            let absorbed = merger.feed(0, s, |_, out| emitted.push(out.to_vec()));
            assert!(absorbed);
        }
        merger.flush(|_, out| emitted.push(out.to_vec()));
        assert_eq!(emitted.len(), 1);
        let merged = &emitted[0];
        assert_eq!(merged.len(), VNET_HDR_LEN + 40 + 3000);
        let vh = VnetHdr::parse(&merged[..VNET_HDR_LEN]).unwrap();
        assert_eq!(vh.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(vh.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(vh.gso_size, 1436);
        assert_eq!(&merged[VNET_HDR_LEN + 40..], &payload[..]);
    }

    #[test]
    fn test_rx_gro_interleaved_multiflow() {
        let make_flow_segs = |sport: u16, base_seq: u32, fill: u8| -> Vec<Vec<u8>> {
            let payload = vec![fill; 3000];
            let mut pkt = vec![0u8; 40 + payload.len()];
            let total_len = pkt.len() as u16;
            write_ipv4_header(
                &mut pkt,
                Ipv4Addr::new(172, 16, 1, 1),
                Ipv4Addr::new(172, 16, 1, 2),
                6,
                100,
                64,
                total_len,
            );
            pkt[20..22].copy_from_slice(&sport.to_be_bytes());
            pkt[22..24].copy_from_slice(&5201u16.to_be_bytes());
            pkt[24..28].copy_from_slice(&base_seq.to_be_bytes());
            pkt[32] = 5 << 4;
            pkt[33] = 0x18;
            pkt[40..].copy_from_slice(&payload);
            let vnet = VnetHdr {
                flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
                hdr_len: 40,
                gso_size: 1436,
                csum_start: 20,
                csum_offset: 16,
            };
            let mut segs = Vec::new();
            segment_tso_packet(&pkt, vnet, 1476, |_, slice, _| {
                segs.push(slice[4..].to_vec());
            });
            segs
        };

        let segs_a = make_flow_segs(50000, 1000, 0xaa);
        let segs_b = make_flow_segs(50002, 2000, 0xbb);
        assert_eq!(segs_a.len(), 3);
        assert_eq!(segs_b.len(), 3);

        let mut merger = RxGroMerger::new();
        let mut emitted: Vec<Vec<u8>> = Vec::new();
        // Interleave flow A and flow B segments before flushing
        for i in 0..3 {
            assert!(merger.feed(0, &segs_a[i], |_, out| emitted.push(out.to_vec())));
            assert!(merger.feed(0, &segs_b[i], |_, out| emitted.push(out.to_vec())));
        }
        merger.flush(|_, out| emitted.push(out.to_vec()));

        assert_eq!(emitted.len(), 2);
        assert_eq!(emitted[0].len(), VNET_HDR_LEN + 40 + 3000);
        assert_eq!(emitted[1].len(), VNET_HDR_LEN + 40 + 3000);
        assert!(emitted[0][VNET_HDR_LEN + 40..].iter().all(|&b| b == 0xaa));
        assert!(emitted[1][VNET_HDR_LEN + 40..].iter().all(|&b| b == 0xbb));
    }

    #[test]
    fn test_packet_flow_hash_symmetric_and_spread() {
        let mut fwd = vec![0u8; 40];
        write_ipv4_header(
            &mut fwd,
            Ipv4Addr::new(172, 16, 1, 1),
            Ipv4Addr::new(172, 16, 1, 2),
            6,
            1,
            64,
            40,
        );
        fwd[20..22].copy_from_slice(&50000u16.to_be_bytes());
        fwd[22..24].copy_from_slice(&5201u16.to_be_bytes());

        let mut rev = vec![0u8; 40];
        write_ipv4_header(
            &mut rev,
            Ipv4Addr::new(172, 16, 1, 2),
            Ipv4Addr::new(172, 16, 1, 1),
            6,
            1,
            64,
            40,
        );
        rev[20..22].copy_from_slice(&5201u16.to_be_bytes());
        rev[22..24].copy_from_slice(&50000u16.to_be_bytes());

        assert_eq!(packet_flow_hash(&fwd), packet_flow_hash(&rev));

        let mut buckets = std::collections::BTreeSet::new();
        for p in [50000u16, 50002, 50004, 50006, 50008, 50010, 50012, 50014] {
            fwd[20..22].copy_from_slice(&p.to_be_bytes());
            buckets.insert(packet_flow_hash(&fwd) % 4);
        }
        assert!(buckets.len() >= 3);
    }

    struct VecSink(Vec<Vec<u8>>, [u8; 4096]);
    impl TxSlotSink for VecSink {
        fn alloc_slot(&mut self, gre_pkt_len: usize) -> Option<&mut [u8]> {
            if gre_pkt_len > self.1.len() {
                return None;
            }
            Some(&mut self.1[..gre_pkt_len])
        }
        fn commit_slot(&mut self, gre_pkt_len: usize) {
            self.0.push(self.1[..gre_pkt_len].to_vec());
        }
    }

    #[test]
    fn test_uso_v4_v6_segmentation_and_udp_gro_roundtrip() {
        let payload: Vec<u8> = (0..2400).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
        let mut pkt4 = vec![0u8; 28 + payload.len()];
        let total_len4 = pkt4.len() as u16;
        write_ipv4_header(
            &mut pkt4,
            Ipv4Addr::new(172, 16, 1, 1),
            Ipv4Addr::new(172, 16, 1, 2),
            17,
            42,
            64,
            total_len4,
        );
        pkt4[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt4[22..24].copy_from_slice(&5201u16.to_be_bytes());
        pkt4[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        pkt4[28..].copy_from_slice(&payload);

        let vnet4 = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
            hdr_len: 28,
            gso_size: 1000,
            csum_start: 20,
            csum_offset: 6,
        };
        let mut sink4 = VecSink(Vec::new(), [0u8; 4096]);
        assert!(segment_tso_into(&pkt4, vnet4, 1476, &mut sink4));
        assert_eq!(sink4.0.len(), 3);
        for seg in &sink4.0 {
            assert_eq!(&seg[..4], &[0, 0, 0x08, 0x00]);
            assert!(verify_udp_checksum(&seg[4..]));
        }

        let mut merger = RxGroMerger::new();
        let mut out4: Vec<Vec<u8>> = Vec::new();
        for seg in &sink4.0 {
            assert!(merger.feed_with_udp(0, &seg[4..], true, |_, m| out4.push(m.to_vec())));
        }
        merger.flush(|_, m| out4.push(m.to_vec()));
        assert_eq!(out4.len(), 1);
        let vh4 = VnetHdr::parse(&out4[0][..VNET_HDR_LEN]).unwrap();
        assert_eq!(vh4.gso_type, VIRTIO_NET_HDR_GSO_UDP_L4);
        assert_eq!(vh4.gso_size, 1000);
        assert_eq!(vh4.csum_offset, 6);
        assert_eq!(&out4[0][VNET_HDR_LEN + 28..], &payload[..]);

        let mut pkt6 = vec![0u8; 48 + payload.len()];
        pkt6[0] = 0x60;
        let plen6 = (8 + payload.len()) as u16;
        pkt6[4..6].copy_from_slice(&plen6.to_be_bytes());
        pkt6[6] = 17;
        pkt6[7] = 64;
        pkt6[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());
        pkt6[24..40].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        pkt6[40..42].copy_from_slice(&40001u16.to_be_bytes());
        pkt6[42..44].copy_from_slice(&5201u16.to_be_bytes());
        pkt6[44..46].copy_from_slice(&plen6.to_be_bytes());
        pkt6[48..].copy_from_slice(&payload);

        let vnet6 = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
            hdr_len: 48,
            csum_start: 40,
            csum_offset: 6,
            gso_size: 1000,
        };
        let mut sink6 = VecSink(Vec::new(), [0u8; 4096]);
        assert!(segment_tso_into(&pkt6, vnet6, 1476, &mut sink6));
        assert_eq!(sink6.0.len(), 3);
        for seg in &sink6.0 {
            assert_eq!(&seg[..4], &[0, 0, 0x86, 0xDD]);
            assert!(verify_udp_checksum(&seg[4..]));
        }

        let mut out6: Vec<Vec<u8>> = Vec::new();
        for seg in &sink6.0 {
            assert!(merger.feed_with_udp(0, &seg[4..], true, |_, m| out6.push(m.to_vec())));
        }
        merger.flush(|_, m| out6.push(m.to_vec()));
        assert_eq!(out6.len(), 1);
        let vh6 = VnetHdr::parse(&out6[0][..VNET_HDR_LEN]).unwrap();
        assert_eq!(vh6.gso_type, VIRTIO_NET_HDR_GSO_UDP_L4);
        assert_eq!(vh6.gso_size, 1000);
        assert_eq!(&out6[0][VNET_HDR_LEN + 48..], &payload[..]);
    }

    #[test]
    fn test_icmp_pkt_too_big_v4_v6_and_antiloop() {
        let mut v4 = vec![0u8; 1480];
        write_ipv4_header(
            &mut v4,
            Ipv4Addr::new(172, 16, 1, 2),
            Ipv4Addr::new(10, 1, 0, 5),
            17,
            99,
            64,
            1480,
        );
        v4[6] = 0x40;
        v4[20..22].copy_from_slice(&12345u16.to_be_bytes());
        v4[22..24].copy_from_slice(&53u16.to_be_bytes());

        let mut out = [0u8; 1500];
        let n = build_icmp_pkt_too_big(
            &v4,
            1400,
            None,
            None,
            true,
            &mut out,
        )
        .unwrap();
        assert!(n > VNET_HDR_LEN + 28);
        let ip_reply = &out[VNET_HDR_LEN..n];
        assert_eq!(internet_checksum(&ip_reply[..20]), 0);
        assert_eq!(ip_reply[9], 1);
        assert_eq!(ip_reply[20], 3);
        assert_eq!(ip_reply[21], 4);
        assert_eq!(u16::from_be_bytes([ip_reply[26], ip_reply[27]]), 1400);
        assert_eq!(internet_checksum(&ip_reply[20..]), 0);

        // Must not generate an ICMP error in response to that ICMP error
        let mut out2 = [0u8; 1500];
        assert!(build_icmp_pkt_too_big(
            ip_reply,
            1400,
            None,
            None,
            false,
            &mut out2,
        )
        .is_none());

        // IPv6 PTB test
        let v6 = build_ipv6_tcp_syn(1440, false);
        let n6 = build_icmp_pkt_too_big(
            &v6,
            1400,
            None,
            Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            false,
            &mut out,
        )
        .unwrap();
        let ip6_reply = &out[..n6];
        assert_eq!(ip6_reply[6], 58);
        assert_eq!(ip6_reply[40], 2);
        assert_eq!(ip6_reply[41], 0);
        assert_eq!(
            u32::from_be_bytes([ip6_reply[44], ip6_reply[45], ip6_reply[46], ip6_reply[47]]),
            1400
        );
        let icmp6_len = n6 - 40;
        let mut sum = checksum_accumulate(0, &ip6_reply[8..40]);
        sum = checksum_accumulate(sum, &(icmp6_len as u32).to_be_bytes());
        sum += 58u32;
        sum = checksum_accumulate(sum, &ip6_reply[40..]);
        assert_eq!(checksum_finish(sum), 0);
        assert!(build_icmp_pkt_too_big(
            ip6_reply,
            1400,
            None,
            None,
            false,
            &mut out2,
        )
        .is_none());
    }

    fn fuzz_rng(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[test]
    fn test_fuzz_packet_parsers_mss_icmp_tso_and_gro() {
        let mut rng = 0x504b_545f_4655_5a5au64;
        let mut buf = [0u8; 512];
        let mut icmp_out = [0u8; 1500];
        let mut icmp_loop = [0u8; 1500];
        let mut merger = RxGroMerger::new();

        for iter in 0..30_000usize {
            let len = (fuzz_rng(&mut rng) as usize) % (buf.len() + 1);
            for chunk in buf[..len].chunks_mut(8) {
                let r = fuzz_rng(&mut rng).to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }

            let slice = &mut buf[..len];
            let _ = packet_flow_hash(slice);
            let _ = inspect_inner_ip(slice);
            let _ = parse_outer_ipv4(slice);

            // Arbitrary ICMP PTB generation + strict anti-loop invariant
            let out_cap = ((fuzz_rng(&mut rng) as usize) % icmp_out.len()).max(1);
            let with_vnet = (iter & 1) != 0;
            let mtu = (fuzz_rng(&mut rng) as u16) % 2000;
            if let Some(n) = build_icmp_pkt_too_big(
                slice,
                mtu,
                None,
                None,
                with_vnet,
                &mut icmp_out[..out_cap],
            ) {
                let ip_off = if with_vnet { VNET_HDR_LEN } else { 0 };
                assert!(n > ip_off && n <= out_cap);
                let generated_ip = &icmp_out[ip_off..n];
                if (generated_ip[0] >> 4) == 4 {
                    assert_eq!(internet_checksum(&generated_ip[..20]), 0);
                    assert_eq!(internet_checksum(&generated_ip[20..]), 0);
                }
                assert!(
                    build_icmp_pkt_too_big(
                        generated_ip,
                        1400,
                        None,
                        None,
                        false,
                        &mut icmp_loop,
                    )
                    .is_none(),
                    "ICMP PTB generated on top of synthetic ICMP error at iter {iter}"
                );
            }

            // Arbitrary TCP MSS clamp must never panic or corrupt buffer bounds
            let _ = clamp_tcp_mss(slice, mtu);

            // Arbitrary VnetHdr + partial checksum + TSO/USO segmentation + GRO feed
            if slice.len() >= VNET_HDR_LEN {
                if let Some(vh) = VnetHdr::parse(&slice[..VNET_HDR_LEN]) {
                    let body = &mut slice[VNET_HDR_LEN..];
                    let _ = finish_partial_checksum(body, vh);
                    let mut sink = VecSink(Vec::new(), [0u8; 4096]);
                    let _ = segment_tso_into(body, vh, mtu, &mut sink);
                }
            }
            let _ = merger.feed_with_udp(iter & 3, slice, (iter & 2) != 0, |_, emitted| {
                assert!(emitted.len() >= VNET_HDR_LEN);
            });
            if iter % 64 == 63 {
                merger.flush(|_, emitted| {
                    assert!(emitted.len() >= VNET_HDR_LEN);
                });
            }
        }
        merger.flush(|_, _| {});

        // Property test: clamp_tcp_mss preserves valid L4 TCP checksum across random SYN MSS/MTU/alignment
        for _ in 0..5_000 {
            let old_mss = 500 + ((fuzz_rng(&mut rng) as u16) % 8500);
            let tun_mtu = 100 + ((fuzz_rng(&mut rng) as u16) % 2000);
            let nop = (fuzz_rng(&mut rng) & 1) != 0;
            let mut v4_syn = build_ipv4_tcp_syn(old_mss, nop);
            let _ = clamp_tcp_mss(&mut v4_syn, tun_mtu);
            assert!(verify_tcp_checksum(&v4_syn));

            let ext = (fuzz_rng(&mut rng) & 1) != 0;
            let mut v6_syn = build_ipv6_tcp_syn(old_mss, ext);
            let _ = clamp_tcp_mss(&mut v6_syn, tun_mtu);
            if !ext {
                assert!(verify_tcp_checksum(&v6_syn));
            } else {
                let expected = compute_tcp_v6_checksum(&v6_syn, 48, v6_syn.len()).unwrap();
                assert_eq!(u16::from_be_bytes([v6_syn[48 + 16], v6_syn[48 + 17]]), expected);
            }
        }
    }
}
