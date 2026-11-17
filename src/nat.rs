use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::config::{DnatRule, DscpMode, NatMode, RouteSpec};
use crate::gre::{ETHERTYPE_IPV4, ETHERTYPE_IPV6};
use crate::packet::{
    checksum_accumulate, checksum_finish, internet_checksum, ipv4_header_checksum_fast,
    parse_outer_ipv4, write_ipv4_header, IpCidr,
};
use crate::sys::{
    bind_nonblock_tcp_listener, bind_socket_to_device, check_socket_connect_err,
    list_host_local_ips, open_nonblock_tcp_stream, Epoll, EpollReady, RawGreSocket, RawIcmpSocket,
};

const PORT_MIN: u16 = 40000;
const PORT_MAX: u16 = 60999;
const PORTAL_VPORT_MIN: u16 = 10000;
const PORTAL_VPORT_MAX: u16 = 60999;

const MAX_SNAT_SESSIONS: usize = 16384;
const MAX_PORTAL_SESSIONS: usize = 8192;
const MAX_TCP_RELAYS: usize = 4096;
const MAX_EXIT_UDP_SOCKS: usize = 2048;
const MAX_DNAT_UDP_SESSIONS: usize = 2048;
const RELAY_BUF_CAP: usize = 32768;

const TCP_EST_TTL_SECS: u64 = 600;
const TCP_TRANS_TTL_SECS: u64 = 60;
const UDP_TTL_SECS: u64 = 120;
const ICMP_TTL_SECS: u64 = 30;
const HOST_IP_REFRESH_SECS: u64 = 30;

const TOK_PORTAL_V4: u64 = 1;
const TOK_PORTAL_V6: u64 = 2;
const TOK_ICMP_V4: u64 = 3;
const TOK_ICMP_V6: u64 = 4;
const TOK_DNAT_TCP_BASE: u64 = 0x0001_0000_0000;
const TOK_DNAT_UDP_BASE: u64 = 0x0002_0000_0000;
const TOK_TCP_CONN_A: u64 = 0x0010_0000_0000;
const TOK_TCP_CONN_B: u64 = 0x0020_0000_0000;
const TOK_DNAT_UDP_BACK: u64 = 0x0030_0000_0000;
const TOK_EXIT_UDP_SOCK: u64 = 0x0040_0000_0000;
const TOK_KIND_MASK: u64 = 0xffff_0000_0000;
const TOK_ID_MASK: u64 = 0x0000_ffff_ffff;

#[cfg(unix)]
#[inline]
fn raw_sock_fd<T: std::os::fd::AsRawFd>(s: &T) -> i32 {
    s.as_raw_fd()
}

#[cfg(not(unix))]
#[inline]
fn raw_sock_fd<T>(_s: &T) -> i32 {
    -1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundNatOutcome {
    /// Forward packet (possibly rewritten in-place) into `TUN`.
    PassToTun,
    /// Packet was consumed in user space (e.g. Exit UDP/ICMP) or dropped as invalid NAT state.
    Consumed,
}

#[derive(Debug, Clone, Copy)]
pub struct PortalAddrs {
    pub gw_v4: Ipv4Addr,
    pub peer_v4: Ipv4Addr,
    pub gw_v6: Ipv6Addr,
    pub peer_v6: Ipv6Addr,
}

pub fn compute_portal_addrs(slot: u32, tunnel_idx: usize) -> PortalAddrs {
    let s_byte = ((slot.saturating_sub(1)) & 0xff) as u8;
    let base = ((tunnel_idx & 0x3f) as u8) * 4;
    PortalAddrs {
        gw_v4: Ipv4Addr::new(198, 19, s_byte, base + 1),
        peer_v4: Ipv4Addr::new(198, 19, s_byte, base + 2),
        gw_v6: Ipv6Addr::new(
            0xfd45,
            0x4752,
            0x4500,
            slot as u16,
            tunnel_idx as u16,
            0,
            0,
            1,
        ),
        peer_v6: Ipv6Addr::new(
            0xfd45,
            0x4752,
            0x4500,
            slot as u16,
            tunnel_idx as u16,
            0,
            0,
            2,
        ),
    }
}

#[inline]
fn csum_update_u16(csum: u16, old_val: u16, new_val: u16) -> u16 {
    if old_val == new_val {
        return csum;
    }
    let mut sum = (!csum) as u32;
    sum += (!old_val) as u32;
    sum += new_val as u32;
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[inline]
fn csum_update_bytes(mut csum: u16, old_bytes: &[u8], new_bytes: &[u8]) -> u16 {
    let mut i = 0usize;
    while i + 1 < old_bytes.len() && i + 1 < new_bytes.len() {
        let old_w = u16::from_be_bytes([old_bytes[i], old_bytes[i + 1]]);
        let new_w = u16::from_be_bytes([new_bytes[i], new_bytes[i + 1]]);
        csum = csum_update_u16(csum, old_w, new_w);
        i += 2;
    }
    csum
}

/// Rewrite IPv4 `(src, sport, dst, dport_or_icmp_id)` in-place.
/// When `update_csum` is false (e.g. TSO/USO super-packet before `segment_tso_into`),
/// only header fields are modified because segmentation recomputes per-segment checksums.
pub fn rewrite_ipv4_l4(
    pkt: &mut [u8],
    new_src: Option<Ipv4Addr>,
    new_sport: Option<u16>,
    new_dst: Option<Ipv4Addr>,
    new_dport: Option<u16>,
    update_csum: bool,
) -> bool {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return false;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if (frag & 0x1fff) != 0 {
        return false;
    }
    let proto = pkt[9];
    let old_src = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let old_dst = [pkt[16], pkt[17], pkt[18], pkt[19]];
    let cur_src = new_src.map(|ip| ip.octets()).unwrap_or(old_src);
    let cur_dst = new_dst.map(|ip| ip.octets()).unwrap_or(old_dst);

    match proto {
        6 => {
            if pkt.len() < ihl + 20 {
                return false;
            }
            let old_sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let old_dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            let sp = new_sport.unwrap_or(old_sp);
            let dp = new_dport.unwrap_or(old_dp);
            pkt[12..16].copy_from_slice(&cur_src);
            pkt[16..20].copy_from_slice(&cur_dst);
            pkt[ihl..ihl + 2].copy_from_slice(&sp.to_be_bytes());
            pkt[ihl + 2..ihl + 4].copy_from_slice(&dp.to_be_bytes());
            if update_csum {
                pkt[10] = 0;
                pkt[11] = 0;
                let ip_csum = if ihl == 20 {
                    ipv4_header_checksum_fast(&pkt[..20])
                } else {
                    internet_checksum(&pkt[..ihl])
                };
                pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                let mut l4_csum = u16::from_be_bytes([pkt[ihl + 16], pkt[ihl + 17]]);
                l4_csum = csum_update_bytes(l4_csum, &old_src, &cur_src);
                l4_csum = csum_update_bytes(l4_csum, &old_dst, &cur_dst);
                l4_csum = csum_update_u16(l4_csum, old_sp, sp);
                l4_csum = csum_update_u16(l4_csum, old_dp, dp);
                pkt[ihl + 16..ihl + 18].copy_from_slice(&l4_csum.to_be_bytes());
            }
            true
        }
        17 => {
            if pkt.len() < ihl + 8 {
                return false;
            }
            let old_sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let old_dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            let sp = new_sport.unwrap_or(old_sp);
            let dp = new_dport.unwrap_or(old_dp);
            pkt[12..16].copy_from_slice(&cur_src);
            pkt[16..20].copy_from_slice(&cur_dst);
            pkt[ihl..ihl + 2].copy_from_slice(&sp.to_be_bytes());
            pkt[ihl + 2..ihl + 4].copy_from_slice(&dp.to_be_bytes());
            if update_csum {
                pkt[10] = 0;
                pkt[11] = 0;
                let ip_csum = if ihl == 20 {
                    ipv4_header_checksum_fast(&pkt[..20])
                } else {
                    internet_checksum(&pkt[..ihl])
                };
                pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                let orig_u_csum = u16::from_be_bytes([pkt[ihl + 6], pkt[ihl + 7]]);
                if orig_u_csum != 0 {
                    let mut u_csum = if orig_u_csum == 0xffff {
                        0xffff
                    } else {
                        orig_u_csum
                    };
                    u_csum = csum_update_bytes(u_csum, &old_src, &cur_src);
                    u_csum = csum_update_bytes(u_csum, &old_dst, &cur_dst);
                    u_csum = csum_update_u16(u_csum, old_sp, sp);
                    u_csum = csum_update_u16(u_csum, old_dp, dp);
                    if u_csum == 0 {
                        u_csum = 0xffff;
                    }
                    pkt[ihl + 6..ihl + 8].copy_from_slice(&u_csum.to_be_bytes());
                }
            }
            true
        }
        1 => {
            if pkt.len() < ihl + 8 {
                return false;
            }
            let old_id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
            let new_id = new_sport.or(new_dport).unwrap_or(old_id);
            pkt[12..16].copy_from_slice(&cur_src);
            pkt[16..20].copy_from_slice(&cur_dst);
            pkt[ihl + 4..ihl + 6].copy_from_slice(&new_id.to_be_bytes());
            if update_csum {
                pkt[10] = 0;
                pkt[11] = 0;
                let ip_csum = if ihl == 20 {
                    ipv4_header_checksum_fast(&pkt[..20])
                } else {
                    internet_checksum(&pkt[..ihl])
                };
                pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

                let old_ic = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                let new_ic = csum_update_u16(old_ic, old_id, new_id);
                pkt[ihl + 2..ihl + 4].copy_from_slice(&new_ic.to_be_bytes());
            }
            true
        }
        _ => false,
    }
}

pub fn rewrite_ipv6_l4(
    pkt: &mut [u8],
    new_src: Option<Ipv6Addr>,
    new_sport: Option<u16>,
    new_dst: Option<Ipv6Addr>,
    new_dport: Option<u16>,
    update_csum: bool,
) -> bool {
    if pkt.len() < 48 || (pkt[0] >> 4) != 6 {
        return false;
    }
    let nh = pkt[6];
    let mut old_src = [0u8; 16];
    let mut old_dst = [0u8; 16];
    old_src.copy_from_slice(&pkt[8..24]);
    old_dst.copy_from_slice(&pkt[24..40]);
    let cur_src = new_src.map(|ip| ip.octets()).unwrap_or(old_src);
    let cur_dst = new_dst.map(|ip| ip.octets()).unwrap_or(old_dst);

    match nh {
        6 => {
            if pkt.len() < 60 {
                return false;
            }
            let old_sp = u16::from_be_bytes([pkt[40], pkt[41]]);
            let old_dp = u16::from_be_bytes([pkt[42], pkt[43]]);
            let sp = new_sport.unwrap_or(old_sp);
            let dp = new_dport.unwrap_or(old_dp);
            pkt[8..24].copy_from_slice(&cur_src);
            pkt[24..40].copy_from_slice(&cur_dst);
            pkt[40..42].copy_from_slice(&sp.to_be_bytes());
            pkt[42..44].copy_from_slice(&dp.to_be_bytes());
            if update_csum {
                let mut l4_csum = u16::from_be_bytes([pkt[56], pkt[57]]);
                l4_csum = csum_update_bytes(l4_csum, &old_src, &cur_src);
                l4_csum = csum_update_bytes(l4_csum, &old_dst, &cur_dst);
                l4_csum = csum_update_u16(l4_csum, old_sp, sp);
                l4_csum = csum_update_u16(l4_csum, old_dp, dp);
                pkt[56..58].copy_from_slice(&l4_csum.to_be_bytes());
            }
            true
        }
        17 => {
            let old_sp = u16::from_be_bytes([pkt[40], pkt[41]]);
            let old_dp = u16::from_be_bytes([pkt[42], pkt[43]]);
            let sp = new_sport.unwrap_or(old_sp);
            let dp = new_dport.unwrap_or(old_dp);
            pkt[8..24].copy_from_slice(&cur_src);
            pkt[24..40].copy_from_slice(&cur_dst);
            pkt[40..42].copy_from_slice(&sp.to_be_bytes());
            pkt[42..44].copy_from_slice(&dp.to_be_bytes());
            if update_csum {
                let orig_u_csum = u16::from_be_bytes([pkt[46], pkt[47]]);
                if orig_u_csum != 0 {
                    let mut u_csum = orig_u_csum;
                    u_csum = csum_update_bytes(u_csum, &old_src, &cur_src);
                    u_csum = csum_update_bytes(u_csum, &old_dst, &cur_dst);
                    u_csum = csum_update_u16(u_csum, old_sp, sp);
                    u_csum = csum_update_u16(u_csum, old_dp, dp);
                    if u_csum == 0 {
                        u_csum = 0xffff;
                    }
                    pkt[46..48].copy_from_slice(&u_csum.to_be_bytes());
                }
            }
            true
        }
        58 => {
            let old_id = u16::from_be_bytes([pkt[44], pkt[45]]);
            let new_id = new_sport.or(new_dport).unwrap_or(old_id);
            pkt[8..24].copy_from_slice(&cur_src);
            pkt[24..40].copy_from_slice(&cur_dst);
            pkt[44..46].copy_from_slice(&new_id.to_be_bytes());
            if update_csum {
                let mut ic = u16::from_be_bytes([pkt[42], pkt[43]]);
                ic = csum_update_bytes(ic, &old_src, &cur_src);
                ic = csum_update_bytes(ic, &old_dst, &cur_dst);
                ic = csum_update_u16(ic, old_id, new_id);
                pkt[42..44].copy_from_slice(&ic.to_be_bytes());
            }
            true
        }
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SnatFwdKeyV4 {
    proto: u8,
    orig_src: Ipv4Addr,
    orig_port: u16,
    dst: Ipv4Addr,
    dport: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SnatRevKey {
    proto: u8,
    nat_port: u16,
}

struct SnatEntryV4 {
    fwd: SnatFwdKeyV4,
    last_seen: u64,
    closing: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SnatFwdKeyV6 {
    proto: u8,
    orig_src: Ipv6Addr,
    orig_port: u16,
    dst: Ipv6Addr,
    dport: u16,
}

struct SnatEntryV6 {
    fwd: SnatFwdKeyV6,
    last_seen: u64,
    closing: bool,
}

struct OutboundSnatInner {
    tun_v4: Option<Ipv4Addr>,
    tun_v6: Option<Ipv6Addr>,
    next_port: u16,
    fwd_v4: HashMap<SnatFwdKeyV4, u16>,
    rev_v4: HashMap<SnatRevKey, SnatEntryV4>,
    fwd_v6: HashMap<SnatFwdKeyV6, u16>,
    rev_v6: HashMap<SnatRevKey, SnatEntryV6>,
    last_gc: u64,
}

impl OutboundSnatInner {
    fn new(tun_v4: Option<Ipv4Addr>, tun_v6: Option<Ipv6Addr>) -> Self {
        Self {
            tun_v4,
            tun_v6,
            next_port: PORT_MIN,
            fwd_v4: HashMap::new(),
            rev_v4: HashMap::new(),
            fwd_v6: HashMap::new(),
            rev_v6: HashMap::new(),
            last_gc: 0,
        }
    }

    fn entry_ttl(proto: u8, closing: bool) -> u64 {
        match proto {
            6 if closing => TCP_TRANS_TTL_SECS,
            6 => TCP_EST_TTL_SECS,
            17 => UDP_TTL_SECS,
            _ => ICMP_TTL_SECS,
        }
    }

    fn maybe_gc(&mut self, now: u64) {
        if now.saturating_sub(self.last_gc) < 15 {
            return;
        }
        self.last_gc = now;
        let fwd4 = &mut self.fwd_v4;
        self.rev_v4.retain(|_, e| {
            let keep = now.saturating_sub(e.last_seen) <= Self::entry_ttl(e.fwd.proto, e.closing);
            if !keep {
                fwd4.remove(&e.fwd);
            }
            keep
        });
        let fwd6 = &mut self.fwd_v6;
        self.rev_v6.retain(|_, e| {
            let keep = now.saturating_sub(e.last_seen) <= Self::entry_ttl(e.fwd.proto, e.closing);
            if !keep {
                fwd6.remove(&e.fwd);
            }
            keep
        });
    }

    fn alloc_port_v4(&mut self, proto: u8, now: u64) -> Option<u16> {
        if self.rev_v4.len() >= MAX_SNAT_SESSIONS {
            self.last_gc = 0;
            self.maybe_gc(now);
            if self.rev_v4.len() >= MAX_SNAT_SESSIONS {
                return None;
            }
        }
        let span = (PORT_MAX - PORT_MIN + 1) as usize;
        for _ in 0..span {
            let p = self.next_port;
            self.next_port = if p >= PORT_MAX { PORT_MIN } else { p + 1 };
            let rkey = SnatRevKey { proto, nat_port: p };
            if let Some(existing) = self.rev_v4.get(&rkey) {
                if now.saturating_sub(existing.last_seen)
                    > Self::entry_ttl(existing.fwd.proto, existing.closing)
                {
                    let old_fwd = existing.fwd;
                    self.rev_v4.remove(&rkey);
                    self.fwd_v4.remove(&old_fwd);
                    return Some(p);
                }
            } else {
                return Some(p);
            }
        }
        None
    }

    fn alloc_port_v6(&mut self, proto: u8, now: u64) -> Option<u16> {
        if self.rev_v6.len() >= MAX_SNAT_SESSIONS {
            self.last_gc = 0;
            self.maybe_gc(now);
            if self.rev_v6.len() >= MAX_SNAT_SESSIONS {
                return None;
            }
        }
        let span = (PORT_MAX - PORT_MIN + 1) as usize;
        for _ in 0..span {
            let p = self.next_port;
            self.next_port = if p >= PORT_MAX { PORT_MIN } else { p + 1 };
            let rkey = SnatRevKey { proto, nat_port: p };
            if let Some(existing) = self.rev_v6.get(&rkey) {
                if now.saturating_sub(existing.last_seen)
                    > Self::entry_ttl(existing.fwd.proto, existing.closing)
                {
                    let old_fwd = existing.fwd;
                    self.rev_v6.remove(&rkey);
                    self.fwd_v6.remove(&old_fwd);
                    return Some(p);
                }
            } else {
                return Some(p);
            }
        }
        None
    }

    fn rewrite_outbound(&mut self, pkt: &mut [u8], is_gso: bool, now: u64) {
        self.maybe_gc(now);
        let Some(&first) = pkt.first() else {
            return;
        };
        match first >> 4 {
            4 => {
                let Some(tun_ip) = self.tun_v4 else {
                    return;
                };
                if pkt.len() < 28 {
                    return;
                }
                let ihl = ((first & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl + 8 {
                    return;
                }
                let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
                if (frag & 0x1fff) != 0 {
                    return;
                }
                let proto = pkt[9];
                let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                let (orig_port, dport, tcp_new_syn, tcp_closing) = match proto {
                    6 if pkt.len() >= ihl + 20 => {
                        let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                        let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                        let flags = pkt[ihl + 13];
                        let is_syn = (flags & 0x12) == 0x02;
                        let closing = (flags & 0x05) != 0; // FIN or RST
                        (sp, dp, is_syn, closing)
                    }
                    17 => {
                        let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                        // Full-cone UDP mapping keyed by (orig_src, orig_sport)
                        (sp, 0u16, true, false)
                    }
                    1 if pkt[ihl] == 8 && pkt[ihl + 1] == 0 => {
                        let id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
                        (id, 0u16, true, false)
                    }
                    _ => return,
                };
                let fkey = SnatFwdKeyV4 {
                    proto,
                    orig_src: src,
                    orig_port,
                    dst: if proto == 6 { dst } else { Ipv4Addr::UNSPECIFIED },
                    dport,
                };
                let nat_port = if let Some(&p) = self.fwd_v4.get(&fkey) {
                    if let Some(ent) = self.rev_v4.get_mut(&SnatRevKey { proto, nat_port: p }) {
                        ent.last_seen = now;
                        if tcp_closing {
                            ent.closing = true;
                        }
                    }
                    p
                } else {
                    if !tcp_new_syn {
                        return;
                    }
                    if src == tun_ip
                        && !self.rev_v4.contains_key(&SnatRevKey {
                            proto,
                            nat_port: orig_port,
                        })
                    {
                        return;
                    }
                    let Some(p) = self.alloc_port_v4(proto, now) else {
                        return;
                    };
                    self.fwd_v4.insert(fkey, p);
                    self.rev_v4.insert(
                        SnatRevKey { proto, nat_port: p },
                        SnatEntryV4 {
                            fwd: fkey,
                            last_seen: now,
                            closing: tcp_closing,
                        },
                    );
                    p
                };
                let _ = rewrite_ipv4_l4(pkt, Some(tun_ip), Some(nat_port), None, None, !is_gso);
            }
            6 => {
                let Some(tun_ip) = self.tun_v6 else {
                    return;
                };
                if pkt.len() < 48 {
                    return;
                }
                let proto = pkt[6];
                let mut s_oct = [0u8; 16];
                let mut d_oct = [0u8; 16];
                s_oct.copy_from_slice(&pkt[8..24]);
                d_oct.copy_from_slice(&pkt[24..40]);
                let src = Ipv6Addr::from(s_oct);
                let dst = Ipv6Addr::from(d_oct);
                let (orig_port, dport, tcp_new_syn, tcp_closing) = match proto {
                    6 if pkt.len() >= 60 => {
                        let sp = u16::from_be_bytes([pkt[40], pkt[41]]);
                        let dp = u16::from_be_bytes([pkt[42], pkt[43]]);
                        let flags = pkt[53];
                        let is_syn = (flags & 0x12) == 0x02;
                        let closing = (flags & 0x05) != 0;
                        (sp, dp, is_syn, closing)
                    }
                    17 => {
                        let sp = u16::from_be_bytes([pkt[40], pkt[41]]);
                        (sp, 0u16, true, false)
                    }
                    58 if pkt[40] == 128 && pkt[41] == 0 => {
                        let id = u16::from_be_bytes([pkt[44], pkt[45]]);
                        (id, 0u16, true, false)
                    }
                    _ => return,
                };
                let fkey = SnatFwdKeyV6 {
                    proto,
                    orig_src: src,
                    orig_port,
                    dst: if proto == 6 { dst } else { Ipv6Addr::UNSPECIFIED },
                    dport,
                };
                let nat_port = if let Some(&p) = self.fwd_v6.get(&fkey) {
                    if let Some(ent) = self.rev_v6.get_mut(&SnatRevKey { proto, nat_port: p }) {
                        ent.last_seen = now;
                        if tcp_closing {
                            ent.closing = true;
                        }
                    }
                    p
                } else {
                    if !tcp_new_syn {
                        return;
                    }
                    if src == tun_ip
                        && !self.rev_v6.contains_key(&SnatRevKey {
                            proto,
                            nat_port: orig_port,
                        })
                    {
                        return;
                    }
                    let Some(p) = self.alloc_port_v6(proto, now) else {
                        return;
                    };
                    self.fwd_v6.insert(fkey, p);
                    self.rev_v6.insert(
                        SnatRevKey { proto, nat_port: p },
                        SnatEntryV6 {
                            fwd: fkey,
                            last_seen: now,
                            closing: tcp_closing,
                        },
                    );
                    p
                };
                let _ = rewrite_ipv6_l4(pkt, Some(tun_ip), Some(nat_port), None, None, !is_gso);
            }
            _ => {}
        }
    }

    fn rewrite_inbound(&mut self, pkt: &mut [u8], now: u64) -> bool {
        let Some(&first) = pkt.first() else {
            return false;
        };
        match first >> 4 {
            4 => {
                let Some(tun_ip) = self.tun_v4 else {
                    return false;
                };
                if pkt.len() < 28 {
                    return false;
                }
                let ihl = ((first & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl + 8 {
                    return false;
                }
                let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                if dst != tun_ip {
                    return false;
                }
                let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let proto = pkt[9];
                match proto {
                    6 if pkt.len() >= ihl + 20 => {
                        let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                        let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                        let Some(ent) = self.rev_v4.get_mut(&SnatRevKey { proto: 6, nat_port: dp })
                        else {
                            return false;
                        };
                        if ent.fwd.dst != src || ent.fwd.dport != sp {
                            return false;
                        }
                        ent.last_seen = now;
                        if (pkt[ihl + 13] & 0x05) != 0 {
                            ent.closing = true;
                        }
                        let orig_ip = ent.fwd.orig_src;
                        let orig_port = ent.fwd.orig_port;
                        rewrite_ipv4_l4(pkt, None, None, Some(orig_ip), Some(orig_port), true)
                    }
                    17 => {
                        let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                        let Some(ent) = self.rev_v4.get_mut(&SnatRevKey {
                            proto: 17,
                            nat_port: dp,
                        }) else {
                            return false;
                        };
                        ent.last_seen = now;
                        let orig_ip = ent.fwd.orig_src;
                        let orig_port = ent.fwd.orig_port;
                        rewrite_ipv4_l4(pkt, None, None, Some(orig_ip), Some(orig_port), true)
                    }
                    1 => {
                        let icmp_type = pkt[ihl];
                        if icmp_type == 0 && pkt[ihl + 1] == 0 {
                            let id = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]);
                            let Some(ent) = self.rev_v4.get_mut(&SnatRevKey {
                                proto: 1,
                                nat_port: id,
                            }) else {
                                return false;
                            };
                            ent.last_seen = now;
                            let orig_ip = ent.fwd.orig_src;
                            let orig_id = ent.fwd.orig_port;
                            return rewrite_ipv4_l4(
                                pkt,
                                None,
                                None,
                                Some(orig_ip),
                                Some(orig_id),
                                true,
                            );
                        }
                        // ICMPv4 Error quoting an outbound SNAT flow (e.g. Frag Needed / Unreachable)
                        if matches!(icmp_type, 3 | 11 | 12) && pkt.len() >= ihl + 8 + 28 {
                            let q_off = ihl + 8;
                            let q_ihl = ((pkt[q_off] & 0x0f) as usize) * 4;
                            if (pkt[q_off] >> 4) == 4
                                && q_ihl >= 20
                                && pkt.len() >= q_off + q_ihl + 8
                            {
                                let q_src = Ipv4Addr::new(
                                    pkt[q_off + 12],
                                    pkt[q_off + 13],
                                    pkt[q_off + 14],
                                    pkt[q_off + 15],
                                );
                                if q_src == tun_ip {
                                    let q_proto = pkt[q_off + 9];
                                    let q_sp = if q_proto == 1 {
                                        u16::from_be_bytes([
                                            pkt[q_off + q_ihl + 4],
                                            pkt[q_off + q_ihl + 5],
                                        ])
                                    } else {
                                        u16::from_be_bytes([
                                            pkt[q_off + q_ihl],
                                            pkt[q_off + q_ihl + 1],
                                        ])
                                    };
                                    if let Some(ent) = self.rev_v4.get(&SnatRevKey {
                                        proto: q_proto,
                                        nat_port: q_sp,
                                    }) {
                                        let orig_ip = ent.fwd.orig_src;
                                        let orig_port = ent.fwd.orig_port;
                                        let _ = rewrite_ipv4_l4(
                                            &mut pkt[q_off..],
                                            Some(orig_ip),
                                            Some(orig_port),
                                            None,
                                            None,
                                            true,
                                        );
                                        pkt[16..20].copy_from_slice(&orig_ip.octets());
                                        pkt[10] = 0;
                                        pkt[11] = 0;
                                        let ip_csum = ipv4_header_checksum_fast(&pkt[..20]);
                                        pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
                                        pkt[ihl + 2] = 0;
                                        pkt[ihl + 3] = 0;
                                        let ic = internet_checksum(&pkt[ihl..]);
                                        pkt[ihl + 2..ihl + 4].copy_from_slice(&ic.to_be_bytes());
                                        return true;
                                    }
                                }
                            }
                        }
                        false
                    }
                    _ => false,
                }
            }
            6 => {
                let Some(tun_ip) = self.tun_v6 else {
                    return false;
                };
                if pkt.len() < 48 {
                    return false;
                }
                let mut d_oct = [0u8; 16];
                d_oct.copy_from_slice(&pkt[24..40]);
                if Ipv6Addr::from(d_oct) != tun_ip {
                    return false;
                }
                let mut s_oct = [0u8; 16];
                s_oct.copy_from_slice(&pkt[8..24]);
                let src = Ipv6Addr::from(s_oct);
                let proto = pkt[6];
                match proto {
                    6 if pkt.len() >= 60 => {
                        let sp = u16::from_be_bytes([pkt[40], pkt[41]]);
                        let dp = u16::from_be_bytes([pkt[42], pkt[43]]);
                        let Some(ent) = self.rev_v6.get_mut(&SnatRevKey { proto: 6, nat_port: dp })
                        else {
                            return false;
                        };
                        if ent.fwd.dst != src || ent.fwd.dport != sp {
                            return false;
                        }
                        ent.last_seen = now;
                        if (pkt[53] & 0x05) != 0 {
                            ent.closing = true;
                        }
                        let orig_ip = ent.fwd.orig_src;
                        let orig_port = ent.fwd.orig_port;
                        rewrite_ipv6_l4(pkt, None, None, Some(orig_ip), Some(orig_port), true)
                    }
                    17 => {
                        let dp = u16::from_be_bytes([pkt[42], pkt[43]]);
                        let Some(ent) = self.rev_v6.get_mut(&SnatRevKey {
                            proto: 17,
                            nat_port: dp,
                        }) else {
                            return false;
                        };
                        ent.last_seen = now;
                        let orig_ip = ent.fwd.orig_src;
                        let orig_port = ent.fwd.orig_port;
                        rewrite_ipv6_l4(pkt, None, None, Some(orig_ip), Some(orig_port), true)
                    }
                    58 if pkt[40] == 129 && pkt[41] == 0 => {
                        let id = u16::from_be_bytes([pkt[44], pkt[45]]);
                        let Some(ent) = self.rev_v6.get_mut(&SnatRevKey {
                            proto: 58,
                            nat_port: id,
                        }) else {
                            return false;
                        };
                        ent.last_seen = now;
                        let orig_ip = ent.fwd.orig_src;
                        let orig_id = ent.fwd.orig_port;
                        rewrite_ipv6_l4(pkt, None, None, Some(orig_ip), Some(orig_id), true)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PortalFlowV4 {
    client_ip: Ipv4Addr,
    client_port: u16,
    target_ip: Ipv4Addr,
    target_port: u16,
}

struct PortalEntryV4 {
    flow: PortalFlowV4,
    last_seen: u64,
    closing: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PortalFlowV6 {
    client_ip: Ipv6Addr,
    client_port: u16,
    target_ip: Ipv6Addr,
    target_port: u16,
}

struct PortalEntryV6 {
    flow: PortalFlowV6,
    last_seen: u64,
    closing: bool,
}

struct TcpPortalTable {
    addrs: PortalAddrs,
    listen_port_v4: u16,
    listen_port_v6: u16,
    next_vport: u16,
    fwd_v4: HashMap<PortalFlowV4, u16>,
    rev_v4: HashMap<u16, PortalEntryV4>,
    fwd_v6: HashMap<PortalFlowV6, u16>,
    rev_v6: HashMap<u16, PortalEntryV6>,
    last_gc: u64,
}

impl TcpPortalTable {
    fn new(addrs: PortalAddrs, listen_port_v4: u16, listen_port_v6: u16) -> Self {
        Self {
            addrs,
            listen_port_v4,
            listen_port_v6,
            next_vport: PORTAL_VPORT_MIN,
            fwd_v4: HashMap::new(),
            rev_v4: HashMap::new(),
            fwd_v6: HashMap::new(),
            rev_v6: HashMap::new(),
            last_gc: 0,
        }
    }

    fn maybe_gc(&mut self, now: u64) {
        if now.saturating_sub(self.last_gc) < 15 {
            return;
        }
        self.last_gc = now;
        let fwd4 = &mut self.fwd_v4;
        self.rev_v4.retain(|_, e| {
            let ttl = if e.closing {
                TCP_TRANS_TTL_SECS
            } else {
                TCP_EST_TTL_SECS
            };
            let keep = now.saturating_sub(e.last_seen) <= ttl;
            if !keep {
                fwd4.remove(&e.flow);
            }
            keep
        });
        let fwd6 = &mut self.fwd_v6;
        self.rev_v6.retain(|_, e| {
            let ttl = if e.closing {
                TCP_TRANS_TTL_SECS
            } else {
                TCP_EST_TTL_SECS
            };
            let keep = now.saturating_sub(e.last_seen) <= ttl;
            if !keep {
                fwd6.remove(&e.flow);
            }
            keep
        });
    }

    fn alloc_v4(&mut self, now: u64) -> Option<u16> {
        if self.rev_v4.len() >= MAX_PORTAL_SESSIONS {
            self.last_gc = 0;
            self.maybe_gc(now);
            if self.rev_v4.len() >= MAX_PORTAL_SESSIONS {
                return None;
            }
        }
        let span = (PORTAL_VPORT_MAX - PORTAL_VPORT_MIN + 1) as usize;
        for _ in 0..span {
            let p = self.next_vport;
            self.next_vport = if p >= PORTAL_VPORT_MAX {
                PORTAL_VPORT_MIN
            } else {
                p + 1
            };
            if let Some(existing) = self.rev_v4.get(&p) {
                let ttl = if existing.closing {
                    TCP_TRANS_TTL_SECS
                } else {
                    TCP_EST_TTL_SECS
                };
                if now.saturating_sub(existing.last_seen) > ttl {
                    let old_flow = existing.flow;
                    self.rev_v4.remove(&p);
                    self.fwd_v4.remove(&old_flow);
                    return Some(p);
                }
            } else {
                return Some(p);
            }
        }
        None
    }

    fn alloc_v6(&mut self, now: u64) -> Option<u16> {
        if self.rev_v6.len() >= MAX_PORTAL_SESSIONS {
            self.last_gc = 0;
            self.maybe_gc(now);
            if self.rev_v6.len() >= MAX_PORTAL_SESSIONS {
                return None;
            }
        }
        let span = (PORTAL_VPORT_MAX - PORTAL_VPORT_MIN + 1) as usize;
        for _ in 0..span {
            let p = self.next_vport;
            self.next_vport = if p >= PORTAL_VPORT_MAX {
                PORTAL_VPORT_MIN
            } else {
                p + 1
            };
            if let Some(existing) = self.rev_v6.get(&p) {
                let ttl = if existing.closing {
                    TCP_TRANS_TTL_SECS
                } else {
                    TCP_EST_TTL_SECS
                };
                if now.saturating_sub(existing.last_seen) > ttl {
                    let old_flow = existing.flow;
                    self.rev_v6.remove(&p);
                    self.fwd_v6.remove(&old_flow);
                    return Some(p);
                }
            } else {
                return Some(p);
            }
        }
        None
    }

    fn lookup_target(&self, peer: SocketAddr) -> Option<SocketAddr> {
        match peer {
            SocketAddr::V4(v4) if *v4.ip() == self.addrs.peer_v4 => {
                let ent = self.rev_v4.get(&v4.port())?;
                Some(SocketAddr::from((ent.flow.target_ip, ent.flow.target_port)))
            }
            SocketAddr::V6(v6) if *v6.ip() == self.addrs.peer_v6 => {
                let ent = self.rev_v6.get(&v6.port())?;
                Some(SocketAddr::from((ent.flow.target_ip, ent.flow.target_port)))
            }
            _ => None,
        }
    }

    fn rewrite_inbound_to_portal(&mut self, pkt: &mut [u8], now: u64) -> InboundNatOutcome {
        self.maybe_gc(now);
        let Some(&first) = pkt.first() else {
            return InboundNatOutcome::Consumed;
        };
        match first >> 4 {
            4 => {
                if self.listen_port_v4 == 0 || pkt.len() < 40 {
                    return InboundNatOutcome::Consumed;
                }
                let ihl = ((first & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl + 20 || pkt[9] != 6 {
                    return InboundNatOutcome::Consumed;
                }
                let client_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let target_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                let client_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let target_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                let flags = pkt[ihl + 13];
                let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
                let closing = (flags & 0x05) != 0;

                let flow = PortalFlowV4 {
                    client_ip,
                    client_port,
                    target_ip,
                    target_port,
                };
                let vport = if let Some(&vp) = self.fwd_v4.get(&flow) {
                    if let Some(ent) = self.rev_v4.get_mut(&vp) {
                        ent.last_seen = now;
                        if closing {
                            ent.closing = true;
                        }
                    }
                    vp
                } else if is_syn {
                    let Some(vp) = self.alloc_v4(now) else {
                        return InboundNatOutcome::Consumed;
                    };
                    self.fwd_v4.insert(flow, vp);
                    self.rev_v4.insert(
                        vp,
                        PortalEntryV4 {
                            flow,
                            last_seen: now,
                            closing: false,
                        },
                    );
                    vp
                } else {
                    return InboundNatOutcome::Consumed;
                };
                if rewrite_ipv4_l4(
                    pkt,
                    Some(self.addrs.peer_v4),
                    Some(vport),
                    Some(self.addrs.gw_v4),
                    Some(self.listen_port_v4),
                    true,
                ) {
                    InboundNatOutcome::PassToTun
                } else {
                    InboundNatOutcome::Consumed
                }
            }
            6 => {
                if self.listen_port_v6 == 0 || pkt.len() < 60 || pkt[6] != 6 {
                    return InboundNatOutcome::Consumed;
                }
                let mut c_oct = [0u8; 16];
                let mut t_oct = [0u8; 16];
                c_oct.copy_from_slice(&pkt[8..24]);
                t_oct.copy_from_slice(&pkt[24..40]);
                let client_ip = Ipv6Addr::from(c_oct);
                let target_ip = Ipv6Addr::from(t_oct);
                let client_port = u16::from_be_bytes([pkt[40], pkt[41]]);
                let target_port = u16::from_be_bytes([pkt[42], pkt[43]]);
                let flags = pkt[53];
                let is_syn = (flags & 0x02) != 0 && (flags & 0x10) == 0;
                let closing = (flags & 0x05) != 0;

                let flow = PortalFlowV6 {
                    client_ip,
                    client_port,
                    target_ip,
                    target_port,
                };
                let vport = if let Some(&vp) = self.fwd_v6.get(&flow) {
                    if let Some(ent) = self.rev_v6.get_mut(&vp) {
                        ent.last_seen = now;
                        if closing {
                            ent.closing = true;
                        }
                    }
                    vp
                } else if is_syn {
                    let Some(vp) = self.alloc_v6(now) else {
                        return InboundNatOutcome::Consumed;
                    };
                    self.fwd_v6.insert(flow, vp);
                    self.rev_v6.insert(
                        vp,
                        PortalEntryV6 {
                            flow,
                            last_seen: now,
                            closing: false,
                        },
                    );
                    vp
                } else {
                    return InboundNatOutcome::Consumed;
                };
                if rewrite_ipv6_l4(
                    pkt,
                    Some(self.addrs.peer_v6),
                    Some(vport),
                    Some(self.addrs.gw_v6),
                    Some(self.listen_port_v6),
                    true,
                ) {
                    InboundNatOutcome::PassToTun
                } else {
                    InboundNatOutcome::Consumed
                }
            }
            _ => InboundNatOutcome::Consumed,
        }
    }

    /// Returns `Some(true)` if rewritten from portal to external tuple, `Some(false)` if packet
    /// belonged to portal subnet without a live session (caller should drop silently), or `None`
    /// if packet is not a portal packet.
    fn rewrite_outbound_from_portal(&mut self, pkt: &mut [u8], is_gso: bool, now: u64) -> Option<bool> {
        let first = *pkt.first()?;
        match first >> 4 {
            4 => {
                if pkt.len() < 40 {
                    return None;
                }
                let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                if src != self.addrs.gw_v4 && dst != self.addrs.peer_v4 {
                    return None;
                }
                let ihl = ((first & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl + 20 || pkt[9] != 6 {
                    return Some(false);
                }
                let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                let vp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                if src != self.addrs.gw_v4 || dst != self.addrs.peer_v4 || sp != self.listen_port_v4 {
                    return Some(false);
                }
                let Some(ent) = self.rev_v4.get_mut(&vp) else {
                    return Some(false);
                };
                ent.last_seen = now;
                if (pkt[ihl + 13] & 0x05) != 0 {
                    ent.closing = true;
                }
                let flow = ent.flow;
                Some(rewrite_ipv4_l4(
                    pkt,
                    Some(flow.target_ip),
                    Some(flow.target_port),
                    Some(flow.client_ip),
                    Some(flow.client_port),
                    !is_gso,
                ))
            }
            6 => {
                if pkt.len() < 60 {
                    return None;
                }
                let mut s_oct = [0u8; 16];
                let mut d_oct = [0u8; 16];
                s_oct.copy_from_slice(&pkt[8..24]);
                d_oct.copy_from_slice(&pkt[24..40]);
                let src = Ipv6Addr::from(s_oct);
                let dst = Ipv6Addr::from(d_oct);
                if src != self.addrs.gw_v6 && dst != self.addrs.peer_v6 {
                    return None;
                }
                if pkt[6] != 6 {
                    return Some(false);
                }
                let sp = u16::from_be_bytes([pkt[40], pkt[41]]);
                let vp = u16::from_be_bytes([pkt[42], pkt[43]]);
                if src != self.addrs.gw_v6 || dst != self.addrs.peer_v6 || sp != self.listen_port_v6 {
                    return Some(false);
                }
                let Some(ent) = self.rev_v6.get_mut(&vp) else {
                    return Some(false);
                };
                ent.last_seen = now;
                if (pkt[53] & 0x05) != 0 {
                    ent.closing = true;
                }
                let flow = ent.flow;
                Some(rewrite_ipv6_l4(
                    pkt,
                    Some(flow.target_ip),
                    Some(flow.target_port),
                    Some(flow.client_ip),
                    Some(flow.client_port),
                    !is_gso,
                ))
            }
            _ => None,
        }
    }
}

struct ExitUdpEntry {
    client_addr: SocketAddr,
    sock: Arc<UdpSocket>,
    last_seen: u64,
}

struct ExitDgramState {
    next_udp_id: u32,
    udp_by_client: HashMap<SocketAddr, u32>,
    udp_by_id: HashMap<u32, ExitUdpEntry>,
    next_icmp_id: u16,
    icmp_fwd: HashMap<(IpAddr, u16), u16>,
    icmp_rev: HashMap<(bool, u16), (IpAddr, u16, u64)>,
    host_v4: HashSet<Ipv4Addr>,
    host_v6: HashSet<Ipv6Addr>,
    last_host_ip_refresh: u64,
}

impl ExitDgramState {
    fn new(extra_local_v4: &[Ipv4Addr], extra_local_v6: &[Ipv6Addr]) -> Self {
        let (v4s, v6s) = list_host_local_ips();
        let mut host_v4: HashSet<Ipv4Addr> = v4s.into_iter().collect();
        let mut host_v6: HashSet<Ipv6Addr> = v6s.into_iter().collect();
        for &ip in extra_local_v4 {
            host_v4.insert(ip);
        }
        for &ip in extra_local_v6 {
            host_v6.insert(ip);
        }
        Self {
            next_udp_id: 1,
            udp_by_client: HashMap::new(),
            udp_by_id: HashMap::new(),
            next_icmp_id: PORT_MIN,
            icmp_fwd: HashMap::new(),
            icmp_rev: HashMap::new(),
            host_v4,
            host_v6,
            last_host_ip_refresh: 0,
        }
    }

    fn maybe_refresh_host_ips(
        &mut self,
        now: u64,
        extra_v4: &[Ipv4Addr],
        extra_v6: &[Ipv6Addr],
    ) {
        if now.saturating_sub(self.last_host_ip_refresh) < HOST_IP_REFRESH_SECS {
            return;
        }
        self.last_host_ip_refresh = now;
        let (v4s, v6s) = list_host_local_ips();
        self.host_v4.clear();
        self.host_v6.clear();
        for ip in v4s {
            self.host_v4.insert(ip);
        }
        for &ip in extra_v4 {
            self.host_v4.insert(ip);
        }
        for ip in v6s {
            self.host_v6.insert(ip);
        }
        for &ip in extra_v6 {
            self.host_v6.insert(ip);
        }
    }

    fn alloc_icmp_id(&mut self, is_v6: bool, client: IpAddr, orig_id: u16, now: u64) -> Option<u16> {
        if let Some(&id) = self.icmp_fwd.get(&(client, orig_id)) {
            if let Some(ent) = self.icmp_rev.get_mut(&(is_v6, id)) {
                ent.2 = now;
                return Some(id);
            }
        }
        let span = (PORT_MAX - PORT_MIN + 1) as usize;
        for _ in 0..span {
            let id = self.next_icmp_id;
            self.next_icmp_id = if id >= PORT_MAX { PORT_MIN } else { id + 1 };
            let rkey = (is_v6, id);
            let expired = match self.icmp_rev.get(&rkey) {
                None => true,
                Some(old) => now.saturating_sub(old.2) > ICMP_TTL_SECS,
            };
            if expired {
                if let Some(old) = self.icmp_rev.remove(&rkey) {
                    self.icmp_fwd.remove(&(old.0, old.1));
                }
                self.icmp_fwd.insert((client, orig_id), id);
                self.icmp_rev.insert(rkey, (client, orig_id, now));
                return Some(id);
            }
        }
        None
    }

    fn gc(&mut self, now: u64, epoll: &Epoll) {
        let by_client = &mut self.udp_by_client;
        self.udp_by_id.retain(|_, ent| {
            let keep = now.saturating_sub(ent.last_seen) <= UDP_TTL_SECS;
            if !keep {
                epoll.del(raw_sock_fd(&*ent.sock));
                by_client.remove(&ent.client_addr);
            }
            keep
        });
        let fwd = &mut self.icmp_fwd;
        self.icmp_rev.retain(|_, ent| {
            let keep = now.saturating_sub(ent.2) <= ICMP_TTL_SECS;
            if !keep {
                fwd.remove(&(ent.0, ent.1));
            }
            keep
        });
    }
}

pub struct TunnelNatEngine {
    epoch: Instant,
    mode: NatMode,
    portal_addrs: Option<PortalAddrs>,
    extra_local_v4: Vec<Ipv4Addr>,
    extra_local_v6: Vec<Ipv6Addr>,
    tunnel_routes: Vec<IpCidr>,
    out_ifname: Mutex<String>,
    snat: Option<Mutex<OutboundSnatInner>>,
    portal: Option<Mutex<TcpPortalTable>>,
    exit_dgram: Option<Mutex<ExitDgramState>>,
    relay_epoll: Option<Arc<Epoll>>,
    icmp_v4: Option<RawIcmpSocket>,
    icmp_v6: Option<RawIcmpSocket>,
}

pub struct NatRelayListeners {
    pub portal_v4: Option<TcpListener>,
    pub portal_v6: Option<TcpListener>,
    pub dnat_tcp: Vec<(TcpListener, SocketAddr)>,
    pub dnat_udp: Vec<(UdpSocket, SocketAddr)>,
}

impl TunnelNatEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        epoch: Instant,
        slot: u32,
        tunnel_idx: usize,
        tun_ifindex: u32,
        mode: NatMode,
        dnat_rules: &[DnatRule],
        addresses: &[IpCidr],
        routes: &[RouteSpec],
        out_ifname: &str,
        configure_addr_fn: impl Fn(u32, &IpCidr) -> Result<(), String>,
    ) -> Result<(Option<Arc<Self>>, Option<NatRelayListeners>), String> {
        if mode == NatMode::Off && dnat_rules.is_empty() {
            return Ok((None, None));
        }

        let mut local_v4 = None;
        let mut local_v6 = None;
        let mut extra_v4 = Vec::new();
        let mut extra_v6 = Vec::new();
        for cidr in addresses {
            match *cidr {
                IpCidr::V4 { addr, .. } => {
                    if local_v4.is_none() {
                        local_v4 = Some(addr);
                    }
                    extra_v4.push(addr);
                }
                IpCidr::V6 { addr, .. } => {
                    if local_v6.is_none() {
                        local_v6 = Some(addr);
                    }
                    extra_v6.push(addr);
                }
            }
        }

        let snat = if mode.has_out() {
            Some(Mutex::new(OutboundSnatInner::new(local_v4, local_v6)))
        } else {
            None
        };

        let mut tunnel_routes = Vec::new();
        for r in routes {
            match r.dst {
                IpCidr::V4 { prefix_len: 0, .. } => {
                    tunnel_routes.push(IpCidr::V4 {
                        addr: Ipv4Addr::new(0, 0, 0, 0),
                        prefix_len: 1,
                    });
                    tunnel_routes.push(IpCidr::V4 {
                        addr: Ipv4Addr::new(128, 0, 0, 0),
                        prefix_len: 1,
                    });
                }
                IpCidr::V6 { prefix_len: 0, .. } => {
                    tunnel_routes.push(IpCidr::V6 {
                        addr: Ipv6Addr::UNSPECIFIED,
                        prefix_len: 1,
                    });
                    tunnel_routes.push(IpCidr::V6 {
                        addr: Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
                        prefix_len: 1,
                    });
                }
                ref c => tunnel_routes.push(c.clone()),
            }
        }

        let need_relay = mode.has_exit() || !dnat_rules.is_empty();
        if !need_relay {
            return Ok((
                Some(Arc::new(Self {
                    epoch,
                    mode,
                    portal_addrs: None,
                    extra_local_v4: extra_v4,
                    extra_local_v6: extra_v6,
                    tunnel_routes,
                    out_ifname: Mutex::new(out_ifname.to_string()),
                    snat,
                    portal: None,
                    exit_dgram: None,
                    relay_epoll: None,
                    icmp_v4: None,
                    icmp_v6: None,
                })),
                None,
            ));
        }

        let relay_epoll = Arc::new(Epoll::new()?);
        let mut portal_addrs = None;
        let mut portal_table = None;
        let mut portal_v4_listener = None;
        let mut portal_v6_listener = None;
        let mut exit_dgram = None;
        let mut icmp_v4 = None;
        let mut icmp_v6 = None;

        if mode.has_exit() {
            let paddrs = compute_portal_addrs(slot, tunnel_idx);
            configure_addr_fn(
                tun_ifindex,
                &IpCidr::V4 {
                    addr: paddrs.gw_v4,
                    prefix_len: 30,
                },
            )?;
            extra_v4.push(paddrs.gw_v4);

            let l4 = bind_nonblock_tcp_listener(SocketAddr::from((paddrs.gw_v4, 0)), true)
                .map_err(|e| format!("failed to bind NAT TCP portal on {}: {e}", paddrs.gw_v4))?;
            let port4 = l4
                .local_addr()
                .map_err(|e| format!("local_addr on NAT TCP portal failed: {e}"))?
                .port();
            relay_epoll.add(raw_sock_fd(&l4), TOK_PORTAL_V4)?;
            portal_v4_listener = Some(l4);

            let mut port6 = 0u16;
            if configure_addr_fn(
                tun_ifindex,
                &IpCidr::V6 {
                    addr: paddrs.gw_v6,
                    prefix_len: 126,
                },
            )
            .is_ok()
            {
                extra_v6.push(paddrs.gw_v6);
                if let Ok(l6) =
                    bind_nonblock_tcp_listener(SocketAddr::from((paddrs.gw_v6, 0)), true)
                {
                    if let Ok(sa6) = l6.local_addr() {
                        if relay_epoll.add(raw_sock_fd(&l6), TOK_PORTAL_V6).is_ok() {
                            port6 = sa6.port();
                            portal_v6_listener = Some(l6);
                        }
                    }
                }
            }

            let bind_dev = if tunnel_routes.iter().any(|r| matches!(r, IpCidr::V4 { prefix_len, .. } if *prefix_len <= 1)) {
                Some(out_ifname)
            } else {
                None
            };
            if let Ok(ic4) = RawIcmpSocket::open_v4(bind_dev) {
                if relay_epoll.add(ic4.raw_fd(), TOK_ICMP_V4).is_ok() {
                    icmp_v4 = Some(ic4);
                }
            }
            if let Ok(ic6) = RawIcmpSocket::open_v6(bind_dev) {
                if relay_epoll.add(ic6.raw_fd(), TOK_ICMP_V6).is_ok() {
                    icmp_v6 = Some(ic6);
                }
            }

            portal_addrs = Some(paddrs);
            portal_table = Some(Mutex::new(TcpPortalTable::new(paddrs, port4, port6)));
            exit_dgram = Some(Mutex::new(ExitDgramState::new(&extra_v4, &extra_v6)));
        }

        let mut dnat_tcp = Vec::new();
        let mut dnat_udp = Vec::new();
        for rule in dnat_rules {
            let bind_sa = match rule.listen_ip {
                Some(ip) => SocketAddr::new(ip, rule.listen_port),
                None => match rule.target {
                    SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, rule.listen_port)),
                    SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, rule.listen_port)),
                },
            };
            if rule.proto.includes_tcp() {
                let tl = bind_nonblock_tcp_listener(bind_sa, rule.listen_ip.is_some()).map_err(
                    |e| format!("failed to bind TCP DNAT listener on {bind_sa}: {e}"),
                )?;
                let tok = TOK_DNAT_TCP_BASE | (dnat_tcp.len() as u64);
                relay_epoll.add(raw_sock_fd(&tl), tok)?;
                dnat_tcp.push((tl, rule.target));
            }
            if rule.proto.includes_udp() {
                let us = UdpSocket::bind(bind_sa).map_err(|e| {
                    format!("failed to bind UDP DNAT socket on {bind_sa}: {e}")
                })?;
                us.set_nonblocking(true)
                    .map_err(|e| format!("failed to set UDP DNAT socket nonblocking: {e}"))?;
                let tok = TOK_DNAT_UDP_BASE | (dnat_udp.len() as u64);
                relay_epoll.add(raw_sock_fd(&us), tok)?;
                dnat_udp.push((us, rule.target));
            }
        }

        let engine = Arc::new(Self {
            epoch,
            mode,
            portal_addrs,
            extra_local_v4: extra_v4,
            extra_local_v6: extra_v6,
            tunnel_routes,
            out_ifname: Mutex::new(out_ifname.to_string()),
            snat,
            portal: portal_table,
            exit_dgram,
            relay_epoll: Some(relay_epoll),
            icmp_v4,
            icmp_v6,
        });

        Ok((
            Some(engine),
            Some(NatRelayListeners {
                portal_v4: portal_v4_listener,
                portal_v6: portal_v6_listener,
                dnat_tcp,
                dnat_udp,
            }),
        ))
    }

    pub fn update_out_ifname(&self, new_ifname: &str) {
        if let Ok(mut g) = self.out_ifname.lock() {
            *g = new_ifname.to_string();
        }
    }

    #[inline]
    fn now_secs(&self) -> u64 {
        Instant::now()
            .saturating_duration_since(self.epoch)
            .as_secs()
    }

    fn target_needs_phys_bind(&self, dst: IpAddr) -> bool {
        match dst {
            IpAddr::V4(v4) => self.tunnel_routes.iter().any(|c| c.contains_v4(v4)),
            IpAddr::V6(v6) => self.tunnel_routes.iter().any(|c| match *c {
                IpCidr::V6 { addr, prefix_len } => {
                    let mask = if prefix_len == 0 {
                        0u128
                    } else {
                        u128::MAX << (128 - prefix_len)
                    };
                    (u128::from(v6) & mask) == (u128::from(addr) & mask)
                }
                IpCidr::V4 { .. } => false,
            }),
        }
    }

    fn phys_bind_ifname(&self, dst: IpAddr) -> Option<String> {
        if self.target_needs_phys_bind(dst) {
            self.out_ifname.lock().ok().map(|g| g.clone())
        } else {
            None
        }
    }

    /// Outbound (`TUN -> GRE`) NAT processing. Returns `false` if packet is a stale internal
    /// portal packet that must be silently dropped rather than transmitted.
    pub fn process_outbound(&self, pkt: &mut [u8], is_gso: bool) -> bool {
        let now = self.now_secs();
        if let Some(ref portal_mu) = self.portal {
            if let Ok(mut portal) = portal_mu.lock() {
                if let Some(ok) = portal.rewrite_outbound_from_portal(pkt, is_gso, now) {
                    return ok;
                }
            }
        }
        if let Some(ref snat_mu) = self.snat {
            if let Ok(mut snat) = snat_mu.lock() {
                snat.rewrite_outbound(pkt, is_gso, now);
            }
        }
        true
    }

    /// Inbound (`GRE -> TUN`) NAT processing.
    pub fn process_inbound(&self, pkt: &mut [u8]) -> InboundNatOutcome {
        let now = self.now_secs();

        // Block forged peer packets directly targeting the internal TCP portal subnet
        if let Some(paddrs) = self.portal_addrs {
            match pkt.first().map(|b| b >> 4) {
                Some(4) if pkt.len() >= 20 => {
                    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                    if dst == paddrs.gw_v4 || dst == paddrs.peer_v4 {
                        return InboundNatOutcome::Consumed;
                    }
                }
                Some(6) if pkt.len() >= 40 => {
                    let mut oct = [0u8; 16];
                    oct.copy_from_slice(&pkt[24..40]);
                    let dst = Ipv6Addr::from(oct);
                    if dst == paddrs.gw_v6 || dst == paddrs.peer_v6 {
                        return InboundNatOutcome::Consumed;
                    }
                }
                _ => {}
            }
        }

        // 1. Reverse-translate replies belonging to our own outbound SNAT sessions first
        if let Some(ref snat_mu) = self.snat {
            if let Ok(mut snat) = snat_mu.lock() {
                if snat.rewrite_inbound(pkt, now) {
                    return InboundNatOutcome::PassToTun;
                }
            }
        }

        if !self.mode.has_exit() {
            return InboundNatOutcome::PassToTun;
        }

        // 2. Exit WAN Masquerade for non-local destination packets
        let Some(&first) = pkt.first() else {
            return InboundNatOutcome::Consumed;
        };
        match first >> 4 {
            4 => {
                if pkt.len() < 28 {
                    return InboundNatOutcome::PassToTun;
                }
                let ihl = ((first & 0x0f) as usize) * 4;
                if ihl < 20 || pkt.len() < ihl + 8 {
                    return InboundNatOutcome::PassToTun;
                }
                let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                if dst.is_loopback()
                    || dst.is_multicast()
                    || dst.is_broadcast()
                    || dst.is_unspecified()
                {
                    return InboundNatOutcome::PassToTun;
                }
                let is_local = self
                    .exit_dgram
                    .as_ref()
                    .and_then(|m| m.lock().ok())
                    .map(|mut st| {
                        st.maybe_refresh_host_ips(now, &self.extra_local_v4, &self.extra_local_v6);
                        st.host_v4.contains(&dst)
                    })
                    .unwrap_or(false);
                if is_local {
                    return InboundNatOutcome::PassToTun;
                }

                let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
                let proto = pkt[9];
                match proto {
                    6 => {
                        if let Some(ref portal_mu) = self.portal {
                            if let Ok(mut portal) = portal_mu.lock() {
                                return portal.rewrite_inbound_to_portal(pkt, now);
                            }
                        }
                        InboundNatOutcome::PassToTun
                    }
                    17 => {
                        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                        if total_len < ihl + 8 || pkt.len() < total_len {
                            return InboundNatOutcome::Consumed;
                        }
                        let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
                        let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                        let payload = &pkt[ihl + 8..total_len];
                        self.forward_exit_udp(
                            SocketAddr::from((src, sport)),
                            SocketAddr::from((dst, dport)),
                            payload,
                            now,
                        );
                        InboundNatOutcome::Consumed
                    }
                    1 if pkt[ihl] == 8 && pkt[ihl + 1] == 0 => {
                        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
                        if total_len < ihl + 8 || pkt.len() < total_len {
                            return InboundNatOutcome::Consumed;
                        }
                        self.forward_exit_icmpv4(src, dst, &pkt[ihl..total_len], now);
                        InboundNatOutcome::Consumed
                    }
                    _ => InboundNatOutcome::PassToTun,
                }
            }
            6 => {
                if pkt.len() < 48 {
                    return InboundNatOutcome::PassToTun;
                }
                let mut s_oct = [0u8; 16];
                let mut d_oct = [0u8; 16];
                s_oct.copy_from_slice(&pkt[8..24]);
                d_oct.copy_from_slice(&pkt[24..40]);
                let src = Ipv6Addr::from(s_oct);
                let dst = Ipv6Addr::from(d_oct);
                if dst.is_loopback()
                    || dst.is_multicast()
                    || dst.is_unspecified()
                    || (dst.segments()[0] & 0xffc0) == 0xfe80
                {
                    return InboundNatOutcome::PassToTun;
                }
                let is_local = self
                    .exit_dgram
                    .as_ref()
                    .and_then(|m| m.lock().ok())
                    .map(|mut st| {
                        st.maybe_refresh_host_ips(now, &self.extra_local_v4, &self.extra_local_v6);
                        st.host_v6.contains(&dst)
                    })
                    .unwrap_or(false);
                if is_local {
                    return InboundNatOutcome::PassToTun;
                }

                let nh = pkt[6];
                let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
                let end = 40usize.saturating_add(payload_len);
                if pkt.len() < end {
                    return InboundNatOutcome::Consumed;
                }
                match nh {
                    6 => {
                        if let Some(ref portal_mu) = self.portal {
                            if let Ok(mut portal) = portal_mu.lock() {
                                return portal.rewrite_inbound_to_portal(pkt, now);
                            }
                        }
                        InboundNatOutcome::PassToTun
                    }
                    17 if payload_len >= 8 => {
                        let sport = u16::from_be_bytes([pkt[40], pkt[41]]);
                        let dport = u16::from_be_bytes([pkt[42], pkt[43]]);
                        let payload = &pkt[48..end];
                        self.forward_exit_udp(
                            SocketAddr::from((src, sport)),
                            SocketAddr::from((dst, dport)),
                            payload,
                            now,
                        );
                        InboundNatOutcome::Consumed
                    }
                    58 if payload_len >= 8 && pkt[40] == 128 && pkt[41] == 0 => {
                        self.forward_exit_icmpv6(src, dst, &pkt[40..end], now);
                        InboundNatOutcome::Consumed
                    }
                    _ => InboundNatOutcome::PassToTun,
                }
            }
            _ => InboundNatOutcome::PassToTun,
        }
    }

    fn forward_exit_udp(
        &self,
        client_sa: SocketAddr,
        target_sa: SocketAddr,
        payload: &[u8],
        now: u64,
    ) {
        let (Some(ref dgram_mu), Some(ref epoll)) = (&self.exit_dgram, &self.relay_epoll) else {
            return;
        };
        let bind_dev = self.phys_bind_ifname(target_sa.ip());
        let sock = {
            let Ok(mut st) = dgram_mu.lock() else {
                return;
            };
            if let Some(&id) = st.udp_by_client.get(&client_sa) {
                if let Some(ent) = st.udp_by_id.get_mut(&id) {
                    ent.last_seen = now;
                    Some(Arc::clone(&ent.sock))
                } else {
                    None
                }
            } else {
                if st.udp_by_id.len() >= MAX_EXIT_UDP_SOCKS {
                    st.gc(now, epoll);
                    if st.udp_by_id.len() >= MAX_EXIT_UDP_SOCKS {
                        return;
                    }
                }
                let bind_addr = match target_sa {
                    SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                    SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                };
                let Ok(us) = UdpSocket::bind(bind_addr) else {
                    return;
                };
                if us.set_nonblocking(true).is_err() {
                    return;
                }
                if let Some(ref dev) = bind_dev {
                    bind_socket_to_device(raw_sock_fd(&us), dev);
                }
                let id = st.next_udp_id;
                st.next_udp_id = st.next_udp_id.wrapping_add(1).max(1);
                if epoll
                    .add(raw_sock_fd(&us), TOK_EXIT_UDP_SOCK | (id as u64))
                    .is_err()
                {
                    return;
                }
                let arc_sock = Arc::new(us);
                st.udp_by_client.insert(client_sa, id);
                st.udp_by_id.insert(
                    id,
                    ExitUdpEntry {
                        client_addr: client_sa,
                        sock: Arc::clone(&arc_sock),
                        last_seen: now,
                    },
                );
                Some(arc_sock)
            }
        };
        if let Some(s) = sock {
            let _ = s.send_to(payload, target_sa);
        }
    }

    fn forward_exit_icmpv4(&self, client_ip: Ipv4Addr, target_ip: Ipv4Addr, icmp: &[u8], now: u64) {
        let (Some(ref dgram_mu), Some(ref ic4)) = (&self.exit_dgram, &self.icmp_v4) else {
            return;
        };
        if icmp.len() < 8 || icmp.len() > 1480 {
            return;
        }
        let orig_id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let nat_id = {
            let Ok(mut st) = dgram_mu.lock() else {
                return;
            };
            let Some(id) = st.alloc_icmp_id(false, IpAddr::V4(client_ip), orig_id, now) else {
                return;
            };
            id
        };
        let mut out = [0u8; 1500];
        let len = icmp.len();
        out[..len].copy_from_slice(icmp);
        out[4..6].copy_from_slice(&nat_id.to_be_bytes());
        let old_csum = u16::from_be_bytes([out[2], out[3]]);
        let new_csum = csum_update_u16(old_csum, orig_id, nat_id);
        out[2..4].copy_from_slice(&new_csum.to_be_bytes());
        let _ = ic4.send_v4(target_ip, &out[..len]);
    }

    fn forward_exit_icmpv6(
        &self,
        client_ip: Ipv6Addr,
        target_ip: Ipv6Addr,
        icmp6: &[u8],
        now: u64,
    ) {
        let (Some(ref dgram_mu), Some(ref ic6)) = (&self.exit_dgram, &self.icmp_v6) else {
            return;
        };
        if icmp6.len() < 8 || icmp6.len() > 1460 {
            return;
        }
        let orig_id = u16::from_be_bytes([icmp6[4], icmp6[5]]);
        let nat_id = {
            let Ok(mut st) = dgram_mu.lock() else {
                return;
            };
            let Some(id) = st.alloc_icmp_id(true, IpAddr::V6(client_ip), orig_id, now) else {
                return;
            };
            id
        };
        let mut out = [0u8; 1500];
        let len = icmp6.len();
        out[..len].copy_from_slice(icmp6);
        out[2] = 0;
        out[3] = 0;
        out[4..6].copy_from_slice(&nat_id.to_be_bytes());
        // Kernel fills ICMPv6 checksum automatically on AF_INET6/IPPROTO_ICMPV6 raw sockets
        let _ = ic6.send_v6(target_ip, &out[..len]);
    }
}

struct StreamBuf {
    data: Vec<u8>,
    rpos: usize,
    wpos: usize,
}

impl StreamBuf {
    fn new() -> Self {
        Self {
            data: vec![0u8; RELAY_BUF_CAP],
            rpos: 0,
            wpos: 0,
        }
    }

    #[inline]
    fn pending(&self) -> &[u8] {
        &self.data[self.rpos..self.wpos]
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.rpos >= self.wpos
    }

    #[inline]
    fn free_slice_mut(&mut self) -> &mut [u8] {
        if self.rpos >= self.wpos {
            self.rpos = 0;
            self.wpos = 0;
        } else if self.rpos > 0 && self.wpos == self.data.len() {
            self.data.copy_within(self.rpos..self.wpos, 0);
            self.wpos -= self.rpos;
            self.rpos = 0;
        }
        &mut self.data[self.wpos..]
    }

    #[inline]
    fn advance_write(&mut self, n: usize) {
        self.wpos += n;
    }

    #[inline]
    fn advance_read(&mut self, n: usize) {
        self.rpos += n;
        if self.rpos >= self.wpos {
            self.rpos = 0;
            self.wpos = 0;
        }
    }
}

struct TcpRelayConn {
    a: TcpStream,
    b: TcpStream,
    b_connected: bool,
    a_to_b: StreamBuf,
    b_to_a: StreamBuf,
    a_eof: bool,
    b_eof: bool,
    a_shut_wr: bool,
    b_shut_wr: bool,
    a_reg: (bool, bool),
    b_reg: (bool, bool),
    last_active: u64,
}

struct DnatUdpSession {
    rule_idx: usize,
    client_addr: SocketAddr,
    backend: UdpSocket,
    last_active: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn run_nat_relay_worker(
    engine: Arc<TunnelNatEngine>,
    listeners: NatRelayListeners,
    tun_ifname: String,
    mut gre_tx_sock: RawGreSocket,
    dscp_mode: DscpMode,
    remote_ip_fn: impl Fn() -> Ipv4Addr,
    carrier_up_fn: impl Fn() -> bool,
    on_gre_tx_fn: impl Fn(),
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    beat_fn: impl Fn(),
) {
    let Some(ref epoll) = engine.relay_epoll else {
        return;
    };

    let mut tcp_conns: HashMap<u32, TcpRelayConn> = HashMap::new();
    let mut next_tcp_id: u32 = 1;

    let mut dnat_udp_by_client: HashMap<(usize, SocketAddr), u32> = HashMap::new();
    let mut dnat_udp_by_id: HashMap<u32, DnatUdpSession> = HashMap::new();
    let mut next_dnat_udp_id: u32 = 1;

    let mut gre_frame = vec![0u8; 65536];
    let mut recv_buf = vec![0u8; 65500];
    let mut events = [EpollReady::default(); 128];
    let mut last_gc = 0u64;
    let mut ip_id_seq: u16 = 1;

    while !stop_flag.load(Ordering::Relaxed) && !crate::sys::shutdown_requested() {
        beat_fn();
        let n_ev = match epoll.wait_ready(&mut events, 200) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        beat_fn();
        let now = engine.now_secs();

        for ev in &events[..n_ev] {
            let tok = ev.token;
            if tok == TOK_PORTAL_V4 || tok == TOK_PORTAL_V6 {
                let listener = if tok == TOK_PORTAL_V4 {
                    listeners.portal_v4.as_ref()
                } else {
                    listeners.portal_v6.as_ref()
                };
                if let Some(l) = listener {
                    for _ in 0..32 {
                        let Ok((client_stream, peer_sa)) = l.accept() else {
                            break;
                        };
                        if tcp_conns.len() >= MAX_TCP_RELAYS {
                            continue;
                        }
                        let target_sa = engine
                            .portal
                            .as_ref()
                            .and_then(|m| m.lock().ok())
                            .and_then(|p| p.lookup_target(peer_sa));
                        let Some(target) = target_sa else {
                            continue;
                        };
                        let _ = client_stream.set_nonblocking(true);
                        let _ = client_stream.set_nodelay(true);
                        let bind_dev = engine.phys_bind_ifname(target.ip());
                        let Ok(out_stream) = open_nonblock_tcp_stream(target, bind_dev.as_deref())
                        else {
                            continue;
                        };
                        spawn_tcp_relay(
                            epoll,
                            &mut tcp_conns,
                            &mut next_tcp_id,
                            client_stream,
                            out_stream,
                            now,
                        );
                    }
                }
                continue;
            }

            if tok == TOK_ICMP_V4 {
                if let Some(ref ic4) = engine.icmp_v4 {
                    for _ in 0..32 {
                        let Ok((n, srv_ip)) = ic4.recv_v4(&mut recv_buf) else {
                            break;
                        };
                        let Some(outer) = parse_outer_ipv4(&recv_buf[..n]) else {
                            continue;
                        };
                        let icmp = outer.payload;
                        if icmp.len() < 8 || icmp[0] != 0 || icmp[1] != 0 {
                            continue;
                        }
                        let nat_id = u16::from_be_bytes([icmp[4], icmp[5]]);
                        let mapped = engine
                            .exit_dgram
                            .as_ref()
                            .and_then(|m| m.lock().ok())
                            .and_then(|mut st| {
                                let ent = st.icmp_rev.get_mut(&(false, nat_id))?;
                                ent.2 = now;
                                match ent.0 {
                                    IpAddr::V4(cip) => Some((cip, ent.1)),
                                    IpAddr::V6(_) => None,
                                }
                            });
                        let Some((client_ip, orig_id)) = mapped else {
                            continue;
                        };
                        if !carrier_up_fn() {
                            continue;
                        }
                        let ip_len = 20 + icmp.len();
                        let gre_len = 4 + ip_len;
                        if gre_len > gre_frame.len() {
                            continue;
                        }
                        gre_frame[0] = 0;
                        gre_frame[1] = 0;
                        gre_frame[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                        ip_id_seq = ip_id_seq.wrapping_add(1).max(1);
                        let src_ip = if outer.src.is_unspecified() {
                            srv_ip
                        } else {
                            outer.src
                        };
                        write_ipv4_header(
                            &mut gre_frame[4..24],
                            src_ip,
                            client_ip,
                            1,
                            ip_id_seq,
                            64,
                            ip_len as u16,
                        );
                        gre_frame[24..gre_len].copy_from_slice(icmp);
                        gre_frame[28..30].copy_from_slice(&orig_id.to_be_bytes());
                        let old_c = u16::from_be_bytes([gre_frame[26], gre_frame[27]]);
                        let new_c = csum_update_u16(old_c, nat_id, orig_id);
                        gre_frame[26..28].copy_from_slice(&new_c.to_be_bytes());

                        let remote_ip = remote_ip_fn();
                        let dscp = match dscp_mode {
                            DscpMode::Inherit => 0,
                            DscpMode::Fixed(v) => v,
                        };
                        if gre_tx_sock
                            .send_to(remote_ip, dscp, false, &gre_frame[..gre_len])
                            .is_ok()
                        {
                            on_gre_tx_fn();
                        }
                    }
                }
                continue;
            }

            if tok == TOK_ICMP_V6 {
                if let Some(ref ic6) = engine.icmp_v6 {
                    for _ in 0..32 {
                        let Ok((n, srv_v6)) = ic6.recv_v6(&mut recv_buf) else {
                            break;
                        };
                        let icmp6 = &recv_buf[..n];
                        if icmp6.len() < 8 || icmp6[0] != 129 || icmp6[1] != 0 {
                            continue;
                        }
                        let nat_id = u16::from_be_bytes([icmp6[4], icmp6[5]]);
                        let mapped = engine
                            .exit_dgram
                            .as_ref()
                            .and_then(|m| m.lock().ok())
                            .and_then(|mut st| {
                                let ent = st.icmp_rev.get_mut(&(true, nat_id))?;
                                ent.2 = now;
                                match ent.0 {
                                    IpAddr::V6(cip) => Some((cip, ent.1)),
                                    IpAddr::V4(_) => None,
                                }
                            });
                        let Some((client_v6, orig_id)) = mapped else {
                            continue;
                        };
                        if !carrier_up_fn() {
                            continue;
                        }
                        let gre_len = 4 + 40 + icmp6.len();
                        if gre_len > gre_frame.len() {
                            continue;
                        }
                        gre_frame[0] = 0;
                        gre_frame[1] = 0;
                        gre_frame[2..4].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
                        gre_frame[4] = 0x60;
                        gre_frame[5] = 0;
                        gre_frame[6] = 0;
                        gre_frame[7] = 0;
                        gre_frame[8..10].copy_from_slice(&(icmp6.len() as u16).to_be_bytes());
                        gre_frame[10] = 58;
                        gre_frame[11] = 64;
                        gre_frame[12..28].copy_from_slice(&srv_v6.octets());
                        gre_frame[28..44].copy_from_slice(&client_v6.octets());
                        gre_frame[44..gre_len].copy_from_slice(icmp6);
                        gre_frame[46] = 0;
                        gre_frame[47] = 0;
                        gre_frame[48..50].copy_from_slice(&orig_id.to_be_bytes());
                        let mut sum = checksum_accumulate(0, &gre_frame[12..44]);
                        sum = checksum_accumulate(sum, &(icmp6.len() as u32).to_be_bytes());
                        sum += 58u32;
                        sum = checksum_accumulate(sum, &gre_frame[44..gre_len]);
                        let ic6_csum = checksum_finish(sum);
                        gre_frame[46..48].copy_from_slice(&ic6_csum.to_be_bytes());

                        let remote_ip = remote_ip_fn();
                        let dscp = match dscp_mode {
                            DscpMode::Inherit => 0,
                            DscpMode::Fixed(v) => v,
                        };
                        if gre_tx_sock
                            .send_to(remote_ip, dscp, false, &gre_frame[..gre_len])
                            .is_ok()
                        {
                            on_gre_tx_fn();
                        }
                    }
                }
                continue;
            }

            let kind = tok & TOK_KIND_MASK;
            let id = (tok & TOK_ID_MASK) as u32;

            match kind {
                TOK_DNAT_TCP_BASE => {
                    let r_idx = id as usize;
                    if let Some((listener, target)) = listeners.dnat_tcp.get(r_idx) {
                        for _ in 0..32 {
                            let Ok((client_stream, _)) = listener.accept() else {
                                break;
                            };
                            if tcp_conns.len() >= MAX_TCP_RELAYS {
                                continue;
                            }
                            let _ = client_stream.set_nonblocking(true);
                            let _ = client_stream.set_nodelay(true);
                            let Ok(out_stream) =
                                open_nonblock_tcp_stream(*target, Some(tun_ifname.as_str()))
                            else {
                                continue;
                            };
                            spawn_tcp_relay(
                                epoll,
                                &mut tcp_conns,
                                &mut next_tcp_id,
                                client_stream,
                                out_stream,
                                now,
                            );
                        }
                    }
                }
                TOK_DNAT_UDP_BASE => {
                    let r_idx = id as usize;
                    if let Some((listener_udp, target)) = listeners.dnat_udp.get(r_idx) {
                        for _ in 0..32 {
                            let Ok((n, client_sa)) = listener_udp.recv_from(&mut recv_buf) else {
                                break;
                            };
                            if let Some(&sid) = dnat_udp_by_client.get(&(r_idx, client_sa)) {
                                if let Some(sess) = dnat_udp_by_id.get_mut(&sid) {
                                    sess.last_active = now;
                                    let _ = sess.backend.send(&recv_buf[..n]);
                                    continue;
                                }
                            }
                            if dnat_udp_by_id.len() >= MAX_DNAT_UDP_SESSIONS {
                                continue;
                            }
                            let bind_any = match target {
                                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
                            };
                            let Ok(back) = UdpSocket::bind(bind_any) else {
                                continue;
                            };
                            if back.set_nonblocking(true).is_err() {
                                continue;
                            }
                            bind_socket_to_device(raw_sock_fd(&back), &tun_ifname);
                            if back.connect(*target).is_err() {
                                continue;
                            }
                            let sid = next_dnat_udp_id;
                            next_dnat_udp_id = next_dnat_udp_id.wrapping_add(1).max(1);
                            if epoll
                                .add(raw_sock_fd(&back), TOK_DNAT_UDP_BACK | (sid as u64))
                                .is_err()
                            {
                                continue;
                            }
                            let _ = back.send(&recv_buf[..n]);
                            dnat_udp_by_client.insert((r_idx, client_sa), sid);
                            dnat_udp_by_id.insert(
                                sid,
                                DnatUdpSession {
                                    rule_idx: r_idx,
                                    client_addr: client_sa,
                                    backend: back,
                                    last_active: now,
                                },
                            );
                        }
                    }
                }
                TOK_DNAT_UDP_BACK => {
                    if let Some(sess) = dnat_udp_by_id.get_mut(&id) {
                        sess.last_active = now;
                        if let Some((listener_udp, _)) = listeners.dnat_udp.get(sess.rule_idx) {
                            for _ in 0..32 {
                                let Ok(n) = sess.backend.recv(&mut recv_buf) else {
                                    break;
                                };
                                let _ = listener_udp.send_to(&recv_buf[..n], sess.client_addr);
                            }
                        }
                    }
                }
                TOK_EXIT_UDP_SOCK => {
                    let entry_info = engine
                        .exit_dgram
                        .as_ref()
                        .and_then(|m| m.lock().ok())
                        .and_then(|mut st| {
                            let ent = st.udp_by_id.get_mut(&id)?;
                            ent.last_seen = now;
                            Some((ent.client_addr, Arc::clone(&ent.sock)))
                        });
                    if let Some((client_sa, sock)) = entry_info {
                        for _ in 0..32 {
                            let Ok((n, remote_sa)) = sock.recv_from(&mut recv_buf) else {
                                break;
                            };
                            if !carrier_up_fn() {
                                continue;
                            }
                            if let Some(gre_len) = encode_gre_udp_reply(
                                remote_sa,
                                client_sa,
                                &recv_buf[..n],
                                &mut ip_id_seq,
                                &mut gre_frame,
                            ) {
                                let remote_ip = remote_ip_fn();
                                let dscp = match dscp_mode {
                                    DscpMode::Inherit => 0,
                                    DscpMode::Fixed(v) => v,
                                };
                                if gre_tx_sock
                                    .send_to(remote_ip, dscp, false, &gre_frame[..gre_len])
                                    .is_ok()
                                {
                                    on_gre_tx_fn();
                                }
                            }
                        }
                    }
                }
                TOK_TCP_CONN_A | TOK_TCP_CONN_B => {
                    let is_a = kind == TOK_TCP_CONN_A;
                    let drop_conn = if let Some(conn) = tcp_conns.get_mut(&id) {
                        conn.last_active = now;
                        drive_tcp_relay(epoll, id, conn, is_a, *ev)
                    } else {
                        false
                    };
                    if drop_conn {
                        if let Some(conn) = tcp_conns.remove(&id) {
                            epoll.del(raw_sock_fd(&conn.a));
                            epoll.del(raw_sock_fd(&conn.b));
                        }
                    }
                }
                _ => {}
            }
        }

        if now.saturating_sub(last_gc) >= 10 {
            last_gc = now;
            tcp_conns.retain(|_, conn| {
                let ttl = if conn.b_connected && !conn.a_eof && !conn.b_eof {
                    TCP_EST_TTL_SECS
                } else {
                    TCP_TRANS_TTL_SECS
                };
                let keep = now.saturating_sub(conn.last_active) <= ttl;
                if !keep {
                    epoll.del(raw_sock_fd(&conn.a));
                    epoll.del(raw_sock_fd(&conn.b));
                }
                keep
            });
            dnat_udp_by_id.retain(|_, sess| {
                let keep = now.saturating_sub(sess.last_active) <= UDP_TTL_SECS;
                if !keep {
                    epoll.del(raw_sock_fd(&sess.backend));
                    dnat_udp_by_client.remove(&(sess.rule_idx, sess.client_addr));
                }
                keep
            });
            if let Some(ref dgram_mu) = engine.exit_dgram {
                if let Ok(mut st) = dgram_mu.lock() {
                    st.gc(now, epoll);
                }
            }
        }
    }
}

fn spawn_tcp_relay(
    epoll: &Epoll,
    conns: &mut HashMap<u32, TcpRelayConn>,
    next_id: &mut u32,
    a: TcpStream,
    b: TcpStream,
    now: u64,
) {
    for _ in 0..8192 {
        let id = *next_id;
        *next_id = next_id.wrapping_add(1).max(1);
        if let std::collections::hash_map::Entry::Vacant(slot) = conns.entry(id) {
            if epoll
                .add_rw(raw_sock_fd(&a), TOK_TCP_CONN_A | (id as u64), true, false)
                .is_err()
            {
                return;
            }
            if epoll
                .add_rw(raw_sock_fd(&b), TOK_TCP_CONN_B | (id as u64), false, true)
                .is_err()
            {
                epoll.del(raw_sock_fd(&a));
                return;
            }
            slot.insert(TcpRelayConn {
                a,
                b,
                b_connected: false,
                a_to_b: StreamBuf::new(),
                b_to_a: StreamBuf::new(),
                a_eof: false,
                b_eof: false,
                a_shut_wr: false,
                b_shut_wr: false,
                a_reg: (true, false),
                b_reg: (false, true),
                last_active: now,
            });
            return;
        }
    }
}

/// Returns `true` if connection has completed or failed and should be removed.
fn drive_tcp_relay(
    epoll: &Epoll,
    id: u32,
    conn: &mut TcpRelayConn,
    is_a: bool,
    ev: EpollReady,
) -> bool {
    if !is_a && !conn.b_connected {
        if ev.hangup_or_err || ev.writable {
            if check_socket_connect_err(raw_sock_fd(&conn.b)).is_err() {
                return true;
            }
            conn.b_connected = true;
        } else {
            return false;
        }
    }

    // Drain reads on ready side
    if is_a && ev.readable && !conn.a_eof {
        loop {
            let dst = conn.a_to_b.free_slice_mut();
            if dst.is_empty() {
                break;
            }
            match conn.a.read(dst) {
                Ok(0) => {
                    conn.a_eof = true;
                    break;
                }
                Ok(n) => conn.a_to_b.advance_write(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return true,
            }
        }
    }
    if !is_a && conn.b_connected && ev.readable && !conn.b_eof {
        loop {
            let dst = conn.b_to_a.free_slice_mut();
            if dst.is_empty() {
                break;
            }
            match conn.b.read(dst) {
                Ok(0) => {
                    conn.b_eof = true;
                    break;
                }
                Ok(n) => conn.b_to_a.advance_write(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return true,
            }
        }
    }

    // Flush pending writes to B if B is connected
    if conn.b_connected {
        while !conn.a_to_b.is_empty() {
            match conn.b.write(conn.a_to_b.pending()) {
                Ok(0) => return true,
                Ok(n) => conn.a_to_b.advance_read(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return true,
            }
        }
        if conn.a_eof && conn.a_to_b.is_empty() && !conn.b_shut_wr {
            let _ = conn.b.shutdown(Shutdown::Write);
            conn.b_shut_wr = true;
        }
    }

    // Flush pending writes to A
    while !conn.b_to_a.is_empty() {
        match conn.a.write(conn.b_to_a.pending()) {
            Ok(0) => return true,
            Ok(n) => conn.b_to_a.advance_read(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return true,
        }
    }
    if conn.b_eof && conn.b_to_a.is_empty() && !conn.a_shut_wr {
        let _ = conn.a.shutdown(Shutdown::Write);
        conn.a_shut_wr = true;
    }

    if conn.a_eof && conn.b_eof && conn.a_to_b.is_empty() && conn.b_to_a.is_empty() {
        return true;
    }

    // Re-read opportunistic space if write just freed buffer room on the active side
    let want_a_r = !conn.a_eof && !conn.a_to_b.free_slice_mut().is_empty();
    let want_a_w = !conn.b_to_a.is_empty();
    let want_b_r = conn.b_connected && !conn.b_eof && !conn.b_to_a.free_slice_mut().is_empty();
    let want_b_w = !conn.b_connected || !conn.a_to_b.is_empty();

    if conn.a_reg != (want_a_r, want_a_w) {
        if epoll
            .mod_rw(raw_sock_fd(&conn.a), TOK_TCP_CONN_A | (id as u64), want_a_r, want_a_w)
            .is_err()
        {
            return true;
        }
        conn.a_reg = (want_a_r, want_a_w);
    }
    if conn.b_reg != (want_b_r, want_b_w) {
        if epoll
            .mod_rw(raw_sock_fd(&conn.b), TOK_TCP_CONN_B | (id as u64), want_b_r, want_b_w)
            .is_err()
        {
            return true;
        }
        conn.b_reg = (want_b_r, want_b_w);
    }
    false
}

fn encode_gre_udp_reply(
    src_sa: SocketAddr,
    dst_sa: SocketAddr,
    payload: &[u8],
    ip_id_seq: &mut u16,
    out: &mut [u8],
) -> Option<usize> {
    match (src_sa, dst_sa) {
        (SocketAddr::V4(s4), SocketAddr::V4(d4)) => {
            let udp_len = 8usize.checked_add(payload.len())?;
            let ip_len = 20usize.checked_add(udp_len)?;
            let gre_len = 4usize.checked_add(ip_len)?;
            if ip_len > u16::MAX as usize || gre_len > out.len() {
                return None;
            }
            out[0] = 0;
            out[1] = 0;
            out[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
            *ip_id_seq = ip_id_seq.wrapping_add(1).max(1);
            write_ipv4_header(
                &mut out[4..24],
                *s4.ip(),
                *d4.ip(),
                17,
                *ip_id_seq,
                64,
                ip_len as u16,
            );
            let udp = &mut out[24..gre_len];
            udp[0..2].copy_from_slice(&s4.port().to_be_bytes());
            udp[2..4].copy_from_slice(&d4.port().to_be_bytes());
            udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            udp[6] = 0;
            udp[7] = 0;
            udp[8..].copy_from_slice(payload);
            let mut sum = checksum_accumulate(0, &s4.ip().octets());
            sum = checksum_accumulate(sum, &d4.ip().octets());
            sum += 17u32 + (udp_len as u32);
            sum = checksum_accumulate(sum, udp);
            let mut csum = checksum_finish(sum);
            if csum == 0 {
                csum = 0xffff;
            }
            udp[6..8].copy_from_slice(&csum.to_be_bytes());
            Some(gre_len)
        }
        (SocketAddr::V6(s6), SocketAddr::V6(d6)) => {
            let udp_len = 8usize.checked_add(payload.len())?;
            let gre_len = 44usize.checked_add(udp_len)?;
            if udp_len > u16::MAX as usize || gre_len > out.len() {
                return None;
            }
            out[0] = 0;
            out[1] = 0;
            out[2..4].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
            out[4] = 0x60;
            out[5] = 0;
            out[6] = 0;
            out[7] = 0;
            out[8..10].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[10] = 17;
            out[11] = 64;
            out[12..28].copy_from_slice(&s6.ip().octets());
            out[28..44].copy_from_slice(&d6.ip().octets());
            let udp = &mut out[44..gre_len];
            udp[0..2].copy_from_slice(&s6.port().to_be_bytes());
            udp[2..4].copy_from_slice(&d6.port().to_be_bytes());
            udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            udp[6] = 0;
            udp[7] = 0;
            udp[8..].copy_from_slice(payload);
            let mut sum = checksum_accumulate(0, &s6.ip().octets());
            sum = checksum_accumulate(sum, &d6.ip().octets());
            sum = checksum_accumulate(sum, &(udp_len as u32).to_be_bytes());
            sum += 17u32;
            sum = checksum_accumulate(sum, udp);
            let mut csum = checksum_finish(sum);
            if csum == 0 {
                csum = 0xffff;
            }
            udp[6..8].copy_from_slice(&csum.to_be_bytes());
            Some(gre_len)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{
        compute_tcp_v4_checksum, compute_tcp_v6_checksum, verify_tcp_checksum, verify_udp_checksum,
    };

    fn make_tcp_v4(src: Ipv4Addr, sp: u16, dst: Ipv4Addr, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut pkt = vec![0u8; total];
        write_ipv4_header(&mut pkt[..20], src, dst, 6, 100, 64, total as u16);
        pkt[20..22].copy_from_slice(&sp.to_be_bytes());
        pkt[22..24].copy_from_slice(&dp.to_be_bytes());
        pkt[24..28].copy_from_slice(&1u32.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = flags;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        pkt[40..].copy_from_slice(payload);
        let csum = compute_tcp_v4_checksum(&pkt).unwrap();
        pkt[36..38].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    fn make_tcp_v6(src: Ipv6Addr, sp: u16, dst: Ipv6Addr, dp: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let plen = 20 + payload.len();
        let mut pkt = vec![0u8; 40 + plen];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
        pkt[6] = 6;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src.octets());
        pkt[24..40].copy_from_slice(&dst.octets());
        pkt[40..42].copy_from_slice(&sp.to_be_bytes());
        pkt[42..44].copy_from_slice(&dp.to_be_bytes());
        pkt[52] = 0x50;
        pkt[53] = flags;
        pkt[60..].copy_from_slice(payload);
        let csum = compute_tcp_v6_checksum(&pkt, 40, pkt.len()).unwrap();
        pkt[56..58].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn test_outbound_snat_v4_v6_tcp_udp_icmp_and_icmp_error() {
        let tun_v4 = Ipv4Addr::new(172, 16, 1, 2);
        let tun_v6 = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 2);
        let mut snat = OutboundSnatInner::new(Some(tun_v4), Some(tun_v6));

        // 1. IPv4 TCP outbound + inbound reply + ICMP Frag Needed quote translation
        let lan_client = Ipv4Addr::new(192, 168, 50, 9);
        let server = Ipv4Addr::new(10, 200, 1, 80);
        let mut syn = make_tcp_v4(lan_client, 51234, server, 80, 0x02, b"hello");
        snat.rewrite_outbound(&mut syn, false, 10);
        assert!(verify_tcp_checksum(&syn));
        assert_eq!(Ipv4Addr::new(syn[12], syn[13], syn[14], syn[15]), tun_v4);
        let nat_sp = u16::from_be_bytes([syn[20], syn[21]]);
        assert!((PORT_MIN..=PORT_MAX).contains(&nat_sp));

        // ICMPv4 Fragmentation Needed quoting the SNATted packet must restore lan_client:51234
        let mut icmp_err = [0u8; 128];
        let icmp_len = crate::packet::build_icmp_pkt_too_big(
            &syn,
            1380,
            Some(Ipv4Addr::new(10, 200, 0, 1)),
            None,
            false,
            &mut icmp_err,
        )
        .unwrap();
        assert!(snat.rewrite_inbound(&mut icmp_err[..icmp_len], 11));
        assert_eq!(
            Ipv4Addr::new(icmp_err[16], icmp_err[17], icmp_err[18], icmp_err[19]),
            lan_client
        );
        assert_eq!(internet_checksum(&icmp_err[..20]), 0);
        assert_eq!(internet_checksum(&icmp_err[20..icmp_len]), 0);
        assert_eq!(
            Ipv4Addr::new(icmp_err[40], icmp_err[41], icmp_err[42], icmp_err[43]),
            lan_client
        );
        assert_eq!(u16::from_be_bytes([icmp_err[48], icmp_err[49]]), 51234);

        // Server SYN+ACK reply translates back to lan_client:51234
        let mut synack = make_tcp_v4(server, 80, tun_v4, nat_sp, 0x12, b"world");
        assert!(snat.rewrite_inbound(&mut synack, 12));
        assert!(verify_tcp_checksum(&synack));
        assert_eq!(
            Ipv4Addr::new(synack[16], synack[17], synack[18], synack[19]),
            lan_client
        );
        assert_eq!(u16::from_be_bytes([synack[22], synack[23]]), 51234);

        // 2. IPv6 TCP SNAT66 roundtrip
        let lan6 = Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 55);
        let srv6 = Ipv6Addr::new(0xfd00, 2, 0, 0, 0, 0, 0, 80);
        let mut syn6 = make_tcp_v6(lan6, 44444, srv6, 443, 0x02, b"tls");
        snat.rewrite_outbound(&mut syn6, false, 20);
        assert!(verify_tcp_checksum(&syn6));
        let mut s6_oct = [0u8; 16];
        s6_oct.copy_from_slice(&syn6[8..24]);
        assert_eq!(Ipv6Addr::from(s6_oct), tun_v6);
        let nat6_sp = u16::from_be_bytes([syn6[40], syn6[41]]);

        let mut rep6 = make_tcp_v6(srv6, 443, tun_v6, nat6_sp, 0x12, b"ok");
        assert!(snat.rewrite_inbound(&mut rep6, 21));
        assert!(verify_tcp_checksum(&rep6));
        let mut d6_oct = [0u8; 16];
        d6_oct.copy_from_slice(&rep6[24..40]);
        assert_eq!(Ipv6Addr::from(d6_oct), lan6);
        assert_eq!(u16::from_be_bytes([rep6[42], rep6[43]]), 44444);

        // 3. Inbound-initiated TCP server replies (SYN+ACK) from LAN or tun_v4 must NOT be hijacked
        let mut srv_reply = make_tcp_v4(
            Ipv4Addr::new(192, 168, 50, 10),
            8080,
            Ipv4Addr::new(172, 16, 1, 1),
            54321,
            0x12,
            b"ok",
        );
        let orig_copy = srv_reply.clone();
        snat.rewrite_outbound(&mut srv_reply, false, 22);
        assert_eq!(srv_reply, orig_copy);
    }

    #[test]
    fn test_exit_tcp_portal_v4_and_v6_roundtrip() {
        let paddrs = compute_portal_addrs(1, 0);
        let mut portal = TcpPortalTable::new(paddrs, 41980, 41986);

        let client = Ipv4Addr::new(10, 88, 0, 9);
        let target = Ipv4Addr::new(1, 1, 1, 1);
        let mut syn = make_tcp_v4(client, 55000, target, 443, 0x02, &[]);
        assert_eq!(
            portal.rewrite_inbound_to_portal(&mut syn, 5),
            InboundNatOutcome::PassToTun
        );
        assert!(verify_tcp_checksum(&syn));
        assert_eq!(Ipv4Addr::new(syn[12], syn[13], syn[14], syn[15]), paddrs.peer_v4);
        assert_eq!(Ipv4Addr::new(syn[16], syn[17], syn[18], syn[19]), paddrs.gw_v4);
        let vp = u16::from_be_bytes([syn[20], syn[21]]);
        assert_eq!(
            portal.lookup_target(SocketAddr::from((paddrs.peer_v4, vp))),
            Some(SocketAddr::from((target, 443)))
        );

        let mut synack = make_tcp_v4(paddrs.gw_v4, 41980, paddrs.peer_v4, vp, 0x12, b"abc");
        assert_eq!(
            portal.rewrite_outbound_from_portal(&mut synack, false, 6),
            Some(true)
        );
        assert!(verify_tcp_checksum(&synack));
        assert_eq!(Ipv4Addr::new(synack[12], synack[13], synack[14], synack[15]), target);
        assert_eq!(Ipv4Addr::new(synack[16], synack[17], synack[18], synack[19]), client);
        assert_eq!(u16::from_be_bytes([synack[20], synack[21]]), 443);
        assert_eq!(u16::from_be_bytes([synack[22], synack[23]]), 55000);
    }

    #[test]
    fn test_fuzz_nat_rewriters_preserve_checksums_and_never_panic() {
        let mut rng = 0x4e41_545f_4655_5a5au64;
        let mut next = || -> u64 {
            rng = rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };

        let mut snat = OutboundSnatInner::new(
            Some(Ipv4Addr::new(172, 16, 0, 2)),
            Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        );
        let mut portal = TcpPortalTable::new(compute_portal_addrs(2, 3), 40001, 40002);
        let mut raw = [0u8; 256];

        for i in 0..20_000usize {
            let len = (next() as usize) % (raw.len() + 1);
            for b in &mut raw[..len] {
                *b = next() as u8;
            }
            if i % 3 == 0 {
                // Valid UDPv4 packet checksum invariant
                let mut ubuf = [0u8; 128];
                let mut id = 1u16;
                let s = SocketAddr::from((Ipv4Addr::from(next() as u32), (next() as u16) | 1));
                let d = SocketAddr::from((Ipv4Addr::from(next() as u32), (next() as u16) | 1));
                let glen =
                    encode_gre_udp_reply(s, d, &raw[..len.clamp(1, 64)], &mut id, &mut ubuf)
                        .unwrap();
                let ip = &mut ubuf[4..glen];
                assert!(verify_udp_checksum(ip));
                assert!(rewrite_ipv4_l4(
                    ip,
                    Some(Ipv4Addr::from(next() as u32)),
                    Some((next() as u16) | 1),
                    Some(Ipv4Addr::from(next() as u32)),
                    Some((next() as u16) | 1),
                    true,
                ));
                assert!(verify_udp_checksum(ip));
            } else if i % 3 == 1 {
                let mut ubuf = [0u8; 160];
                let mut id = 1u16;
                let s = SocketAddr::from((Ipv6Addr::from(next() as u128), (next() as u16) | 1));
                let d = SocketAddr::from((Ipv6Addr::from(next() as u128), (next() as u16) | 1));
                let glen =
                    encode_gre_udp_reply(s, d, &raw[..len.clamp(1, 64)], &mut id, &mut ubuf)
                        .unwrap();
                let ip6 = &mut ubuf[4..glen];
                assert!(verify_udp_checksum(ip6));
                assert!(rewrite_ipv6_l4(
                    ip6,
                    Some(Ipv6Addr::from(next() as u128)),
                    Some((next() as u16) | 1),
                    Some(Ipv6Addr::from(next() as u128)),
                    Some((next() as u16) | 1),
                    true,
                ));
                assert!(verify_udp_checksum(ip6));
            } else {
                snat.rewrite_outbound(&mut raw[..len], (i & 1) == 0, (i / 100) as u64);
                let _ = snat.rewrite_inbound(&mut raw[..len], (i / 100) as u64);
                let _ = portal.rewrite_inbound_to_portal(&mut raw[..len], (i / 100) as u64);
                let _ = portal.rewrite_outbound_from_portal(
                    &mut raw[..len],
                    (i & 1) == 0,
                    (i / 100) as u64,
                );
            }
        }
    }
}
