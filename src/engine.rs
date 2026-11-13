use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{
    AppConfig, DontFragmentMode, DscpMode, MtuMode, RemoteEndpoint, RouteSpec, TunnelConfig, TxMode,
};
use crate::gre::{
    build_keepalive_reply, build_keepalive_request_with_token, decode_gre_payload, GreDecoded,
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_GRE,
};
use crate::keepalive::{KeepaliveConfig, KeepaliveStateMachine};
use crate::packet::{
    build_icmp_pkt_too_big, clamp_tcp_mss, finish_partial_checksum, inspect_inner_ip,
    is_valid_unicast_ipv4, packet_flow_hash, parse_outer_ipv4, segment_tso_into,
    write_outer_ipv4_gre_header, IpVersion, RxGroMerger, TxSlotSink, VnetHdr,
    VIRTIO_NET_HDR_GSO_NONE, VNET_HDR_LEN,
};
use crate::status::{
    read_status_pid, remove_status_file, write_status_file, TunnelStatusSnapshot,
};
use crate::sys::{
    cleanup_stale_easygre_routes, configure_interface_addr, configure_route,
    detect_system_warnings, get_interface_hwaddr, install_host_bypass_route,
    install_signal_handlers, is_pid_alive, lookup_arp_mac, probe_route_excluding,
    remove_host_bypass_route, remove_installed_route, shutdown_requested, trigger_arp_probe,
    Epoll, EventFd, InstalledRoute, InstanceLease, NeighWatchSocket, PacketTxRing, RawGreSocket,
    RxBatchBuffer, TunDevice,
    TunUringReader, BATCH_CAP, BATCH_SLOT_SIZE, TSO_OVERFLOW_SIZE, URING_BATCH,
};

const TOKEN_EVENT_FD: u64 = 1;
const TOKEN_NETLINK_NEIGH: u64 = 2;
const TOKEN_RAW_RX: u64 = u64::MAX;
const GRE_OVERHEAD_V4: u16 = 24;
const STATUS_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const ARP_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const ARP_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const WORKER_STALL_MS: u64 = 15_000;
const ETH_HDR_LEN: usize = 14;
const OUTER_IP_HDR_LEN: usize = 20;
const GRE_HDR_LEN: usize = 4;
const WIRE_PKT_OFF: usize = ETH_HDR_LEN + OUTER_IP_HDR_LEN + GRE_HDR_LEN; // 38
const VNET_IN_FRAME_OFF: usize = WIRE_PKT_OFF - VNET_HDR_LEN; // 28
const MAC_VALID_BIT: u64 = 1u64 << 48;

#[inline]
fn encode_mac(mac: [u8; 6]) -> u64 {
    MAC_VALID_BIT
        | (mac[0] as u64)
        | ((mac[1] as u64) << 8)
        | ((mac[2] as u64) << 16)
        | ((mac[3] as u64) << 24)
        | ((mac[4] as u64) << 32)
        | ((mac[5] as u64) << 40)
}

#[inline]
fn decode_mac(packed: u64) -> Option<[u8; 6]> {
    if (packed & MAC_VALID_BIT) == 0 {
        return None;
    }
    Some([
        packed as u8,
        (packed >> 8) as u8,
        (packed >> 16) as u8,
        (packed >> 24) as u8,
        (packed >> 32) as u8,
        (packed >> 40) as u8,
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BypassEntry {
    out_ifindex: u32,
    gateway: Option<Ipv4Addr>,
    refcount: usize,
}

/// In-process reference-counted `/32` bypass route table tagged with this daemon's unique
/// `InstanceLease` metric. Keyed strictly by `dst_ip` to match the Linux IPv4 FIB route identity
/// `(dst_ip/32, metric)`: identical `(out_ifindex, gateway)` shares a refcount, while conflicting
/// physical next-hops for the same `dst_ip` within one process fail explicitly instead of clobbering.
struct BypassRegistry {
    metric: u32,
    refs: Mutex<BTreeMap<Ipv4Addr, BypassEntry>>,
}

impl BypassRegistry {
    fn new(metric: u32) -> Arc<Self> {
        Arc::new(Self {
            metric,
            refs: Mutex::new(BTreeMap::new()),
        })
    }

    fn acquire(
        self: &Arc<Self>,
        dst_ip: Ipv4Addr,
        out_ifindex: u32,
        gateway: Option<Ipv4Addr>,
    ) -> Result<Option<BypassRouteGuard>, String> {
        self.acquire_with(dst_ip, out_ifindex, gateway, install_host_bypass_route)
    }

    fn acquire_with<F>(
        self: &Arc<Self>,
        dst_ip: Ipv4Addr,
        out_ifindex: u32,
        gateway: Option<Ipv4Addr>,
        installer: F,
    ) -> Result<Option<BypassRouteGuard>, String>
    where
        F: FnOnce(Ipv4Addr, u32, Option<Ipv4Addr>, u32) -> Result<bool, String>,
    {
        let mut map = self
            .refs
            .lock()
            .map_err(|_| "bypass registry mutex poisoned".to_string())?;
        if let Some(entry) = map.get_mut(&dst_ip) {
            if entry.out_ifindex != out_ifindex || entry.gateway != gateway {
                return Err(format!(
                    "conflicting /32 bypass route for {dst_ip}: already bound to ifindex={} gw={:?}, cannot simultaneously bind to ifindex={out_ifindex} gw={gateway:?}",
                    entry.out_ifindex, entry.gateway
                ));
            }
            entry.refcount += 1;
            return Ok(Some(BypassRouteGuard {
                registry: Arc::clone(self),
                dst_ip,
                suppress_os_delete: false,
            }));
        }
        if installer(dst_ip, out_ifindex, gateway, self.metric)? {
            map.insert(
                dst_ip,
                BypassEntry {
                    out_ifindex,
                    gateway,
                    refcount: 1,
                },
            );
            Ok(Some(BypassRouteGuard {
                registry: Arc::clone(self),
                dst_ip,
                suppress_os_delete: false,
            }))
        } else {
            Ok(None)
        }
    }
}

struct BypassRouteGuard {
    registry: Arc<BypassRegistry>,
    dst_ip: Ipv4Addr,
    suppress_os_delete: bool,
}

impl Drop for BypassRouteGuard {
    fn drop(&mut self) {
        let mut delete_target: Option<(u32, Option<Ipv4Addr>)> = None;
        if let Ok(mut map) = self.registry.refs.lock() {
            if let Some(entry) = map.get_mut(&self.dst_ip) {
                if entry.refcount > 1 {
                    entry.refcount -= 1;
                } else {
                    let target = (entry.out_ifindex, entry.gateway);
                    map.remove(&self.dst_ip);
                    delete_target = Some(target);
                }
            }
        }
        if !self.suppress_os_delete {
            if let Some((out_ifindex, gateway)) = delete_target {
                remove_host_bypass_route(self.dst_ip, out_ifindex, gateway, self.registry.metric);
            }
        }
    }
}

struct InstalledRoutesGuard(Vec<InstalledRoute>);

impl Drop for InstalledRoutesGuard {
    fn drop(&mut self) {
        for r in &self.0 {
            remove_installed_route(r);
        }
    }
}

struct WorkerHealth {
    name: String,
    epoch: Instant,
    last_beat_ms: AtomicU64,
    failed: AtomicBool,
}

impl WorkerHealth {
    fn new(name: String, epoch: Instant) -> Arc<Self> {
        let init_ms = Instant::now().saturating_duration_since(epoch).as_millis() as u64;
        Arc::new(Self {
            name,
            epoch,
            last_beat_ms: AtomicU64::new(init_ms),
            failed: AtomicBool::new(false),
        })
    }

    #[inline]
    fn beat(&self) {
        let ms = Instant::now()
            .saturating_duration_since(self.epoch)
            .as_millis() as u64;
        self.last_beat_ms.store(ms, Ordering::Relaxed);
    }
}

struct WorkerExitGuard {
    health: Arc<WorkerHealth>,
    stop_flag: Arc<AtomicBool>,
    wake_evt: Arc<EventFd>,
}

impl Drop for WorkerExitGuard {
    fn drop(&mut self) {
        if !self.stop_flag.load(Ordering::Acquire) && !shutdown_requested() {
            self.health.failed.store(true, Ordering::Release);
            eprintln!(
                "[error] worker '{}' exited unexpectedly",
                self.health.name
            );
            self.wake_evt.notify();
        }
    }
}

struct TunnelShared {
    name: String,
    epoch: Instant,
    local_bind: Option<Ipv4Addr>,
    public_ip_override: Option<Ipv4Addr>,
    dscp_mode: DscpMode,
    df_mode: DontFragmentMode,
    clamp_tcp_mss: bool,
    allow_fast_path: bool,
    actual_mtu: u16,
    out_mtu: AtomicU32,
    out_ifindex: AtomicU32,
    src_mac: AtomicU64,
    local_ip: AtomicU32,
    remote_ip: AtomicU32,
    learned_public_ip: AtomicU32,
    nat_candidate_ip: AtomicU32,
    nat_candidate_hits: AtomicU32,
    next_hop_mac: AtomicU64,
    next_ip_id: AtomicU32,
    carrier_up: AtomicBool,
    ka_awaiting: AtomicBool,
    ka_ring_cursor: AtomicU32,
    ka_expected_tokens: [AtomicU32; 4],
    ka_expected_seqs: [AtomicU32; 4],
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_drops: AtomicU64,
    rx_drops: AtomicU64,
    rx_trunc: AtomicU64,
    ka_replies_rx: AtomicU64,
    ka_requests_ans: AtomicU64,
    ka_spoof_drops: AtomicU64,
    emsgsize_warned: AtomicBool,
    tun: TunDevice,
}

impl TunnelShared {
    fn record_expected_ka(&self, seq: u16, token: u32) {
        let idx = (self.ka_ring_cursor.fetch_add(1, Ordering::Relaxed) as usize) & 3;
        self.ka_expected_seqs[idx].store(seq as u32, Ordering::Release);
        self.ka_expected_tokens[idx].store(token, Ordering::Release);
        self.ka_awaiting.store(true, Ordering::Release);
    }

    fn verify_ka_reply(
        &self,
        echo_token: Option<[u8; 4]>,
        body_len: usize,
        outer_ip_id: u16,
    ) -> bool {
        if !self.ka_awaiting.load(Ordering::Acquire) {
            return false;
        }
        let matched = if let Some(tb) = echo_token {
            let tok = u32::from_be_bytes(tb);
            tok != 0
                && self
                    .ka_expected_tokens
                    .iter()
                    .any(|slot| slot.load(Ordering::Acquire) == tok)
        } else if body_len == 0 {
            outer_ip_id != 0
                && self
                    .ka_expected_seqs
                    .iter()
                    .any(|slot| slot.load(Ordering::Acquire) == outer_ip_id as u32)
        } else {
            false
        };
        if matched {
            self.ka_awaiting.store(false, Ordering::Release);
        }
        matched
    }

    /// Require 2 consecutive matching valid unicast KeepaliveRequest inner source IPs
    /// before updating `learned_public_ip` to defend against single-packet spoofed poisoning.
    fn observe_peer_reported_ip(&self, candidate: Ipv4Addr) -> bool {
        if self.public_ip_override.is_some() || !is_valid_unicast_ipv4(candidate) {
            return false;
        }
        let cand_u32 = u32::from(candidate);
        if cand_u32 == self.remote_ip.load(Ordering::Relaxed)
            || cand_u32 == self.local_ip.load(Ordering::Relaxed)
        {
            return false;
        }
        if self.learned_public_ip.load(Ordering::Relaxed) == cand_u32 {
            return false;
        }
        let prev_cand = self.nat_candidate_ip.swap(cand_u32, Ordering::Relaxed);
        let hits = if prev_cand == cand_u32 {
            self.nat_candidate_hits.fetch_add(1, Ordering::Relaxed) + 1
        } else {
            self.nat_candidate_hits.store(1, Ordering::Relaxed);
            1
        };
        if hits >= 2 {
            self.learned_public_ip.swap(cand_u32, Ordering::Release) != cand_u32
        } else {
            false
        }
    }
}

#[inline]
fn write_tun_counted(shared: &TunnelShared, q_hash: usize, pkt: &[u8]) -> bool {
    for _ in 0..2 {
        match shared.tun.write_queue_nonblock(q_hash, pkt) {
            Ok(_) => return true,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                shared.rx_drops.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
    }
    shared.rx_drops.fetch_add(1, Ordering::Relaxed);
    false
}

struct ManagedTunnel {
    cfg: TunnelConfig,
    shared: Arc<TunnelShared>,
    ka_tx_sock: RawGreSocket,
    keepalive: KeepaliveStateMachine,
    last_ka_replies_seen: u64,
    last_learned_public: u32,
    out_ifname: String,
    gateway: Option<Ipv4Addr>,
    next_dns_check: Option<Instant>,
    dns_inflight: bool,
    dns_result: Arc<Mutex<Option<Result<Ipv4Addr, String>>>>,
    next_arp_check: Option<Instant>,
    arp_logged_fastpath: bool,
    bypass_route: Option<BypassRouteGuard>,
    _installed_routes: InstalledRoutesGuard,
}

impl ManagedTunnel {
    fn remote_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.shared.remote_ip.load(Ordering::Relaxed))
    }

    fn local_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.shared.local_ip.load(Ordering::Relaxed))
    }

    fn effective_reply_dst_ip(&self) -> Ipv4Addr {
        if let Some(p) = self.cfg.public_ip {
            return p;
        }
        let learned = self.shared.learned_public_ip.load(Ordering::Relaxed);
        if learned != 0 {
            Ipv4Addr::from(learned)
        } else {
            self.local_ip()
        }
    }

    fn snapshot(&self) -> TunnelStatusSnapshot {
        let learned = self.shared.learned_public_ip.load(Ordering::Relaxed);
        let pub_ip = self.cfg.public_ip.or_else(|| {
            if learned != 0 {
                Some(Ipv4Addr::from(learned))
            } else {
                None
            }
        });
        TunnelStatusSnapshot {
            name: self.cfg.name.clone(),
            comment: self.cfg.comment.clone(),
            remote_config: self.cfg.remote.as_display(),
            remote_ip: self.remote_ip(),
            local_ip: self.local_ip(),
            public_ip: pub_ip,
            mtu: self.shared.actual_mtu,
            state: self.keepalive.state().as_str(),
            carrier_up: self.keepalive.is_carrier_up(),
            misses: self.keepalive.misses(),
            tx_packets: self.shared.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.shared.rx_packets.load(Ordering::Relaxed),
            tx_drops: self.shared.tx_drops.load(Ordering::Relaxed),
            rx_drops: self.shared.rx_drops.load(Ordering::Relaxed),
            rx_trunc: self.shared.rx_trunc.load(Ordering::Relaxed),
            ka_probes_sent: self.keepalive.probes_sent,
            ka_replies_rx: self.keepalive.replies_received,
            ka_requests_ans: self.shared.ka_requests_ans.load(Ordering::Relaxed),
            ka_spoof_drops: self.shared.ka_spoof_drops.load(Ordering::Relaxed),
        }
    }
}

pub fn run_daemon(config: AppConfig) -> Result<(), String> {
    install_signal_handlers();
    let daemon_epoch = Instant::now();
    let instance_lease = InstanceLease::acquire()?;

    // Reclaim leftover RTPROT_EASYGRE bypass routes whose abstract netns slot lease is dead
    let cur_pid = std::process::id();
    let legacy_status_orphan = match read_status_pid(&config.status_file) {
        None => true,
        Some(old_pid) => old_pid == cur_pid || !is_pid_alive(old_pid),
    };
    cleanup_stale_easygre_routes(&instance_lease, legacy_status_orphan);
    let bypass_registry = BypassRegistry::new(instance_lease.bypass_metric());

    let has_routes = config.tunnels.iter().any(|t| !t.routes.is_empty());
    let fast_path_any = config.tx_mode != TxMode::Raw
        && config.tunnels.iter().any(|t| t.allow_fast_path);
    for w in detect_system_warnings(has_routes, fast_path_any) {
        eprintln!("[warn] {w}");
    }

    let requested_queues = config.queues.resolve();
    let tx_mode = config.tx_mode;

    let rx_sock = RawGreSocket::open_rx()?;
    let wake_evt = Arc::new(EventFd::new()?);
    let ctrl_epoll = Epoll::new()?;
    ctrl_epoll.add(wake_evt.raw_fd(), TOKEN_EVENT_FD)?;
    let neigh_watch = NeighWatchSocket::open().ok();
    if let Some(ref nw) = neigh_watch {
        let _ = ctrl_epoll.add(nw.raw_fd(), TOKEN_NETLINK_NEIGH);
    }

    let now = daemon_epoch;
    let all_configured_routes: Vec<RouteSpec> = config
        .tunnels
        .iter()
        .flat_map(|t| t.routes.iter().cloned())
        .collect();
    let mut tunnels: Vec<ManagedTunnel> = Vec::with_capacity(config.tunnels.len());
    let mut resolved_pairs: Vec<(Ipv4Addr, Ipv4Addr, String)> = Vec::new();

    for cfg in config.tunnels.into_iter() {
        let existing_tun_ifs: Vec<u32> = tunnels.iter().map(|t| t.shared.tun.ifindex()).collect();
        let tunnel = setup_tunnel(
            cfg,
            requested_queues,
            tx_mode,
            &existing_tun_ifs,
            &all_configured_routes,
            &bypass_registry,
            now,
        )?;
        let r_ip = tunnel.remote_ip();
        let l_ip = tunnel.local_ip();
        if let Some((_, _, prev_name)) = resolved_pairs
            .iter()
            .find(|&&(er, el, _)| er == r_ip && el == l_ip)
        {
            return Err(format!(
                "tunnel '{}' resolves to the same (remote={}, local={}) endpoint as '{}'",
                tunnel.cfg.name, r_ip, l_ip, prev_name
            ));
        }
        resolved_pairs.push((r_ip, l_ip, tunnel.cfg.name.clone()));
        tunnels.push(tunnel);
    }

    let shared_list: Vec<Arc<TunnelShared>> = tunnels.iter().map(|t| Arc::clone(&t.shared)).collect();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let mut worker_healths: Vec<Arc<WorkerHealth>> = Vec::new();

    // Pre-open all worker epoll & TX sockets before spawning threads so any resource error fails fast
    let rx_epoll = Epoll::new()?;
    rx_epoll.add(rx_sock.raw_fd(), TOKEN_RAW_RX)?;
    let mut ka_reply_socks: Vec<RawGreSocket> = Vec::with_capacity(shared_list.len());
    for sh in &shared_list {
        ka_reply_socks.push(RawGreSocket::open_tx(sh.local_bind)?);
    }

    let mut tx_inits: Vec<(Arc<TunnelShared>, usize, Epoll, RawGreSocket)> = Vec::new();
    for shared in &shared_list {
        let q_count = shared.tun.queue_count();
        for q_idx in 0..q_count {
            let ep = Epoll::new()?;
            ep.add(shared.tun.queue_fd(q_idx), 1)?;
            let rs = RawGreSocket::open_tx(shared.local_bind)?;
            tx_inits.push((Arc::clone(shared), q_idx, ep, rs));
        }
    }

    let mut worker_handles: Vec<thread::JoinHandle<()>> = Vec::new();
    for (sh, q_idx, ep, rs) in tx_inits {
        let wname = format!("tx-{}-q{}", sh.name, q_idx);
        let health = WorkerHealth::new(wname.clone(), daemon_epoch);
        worker_healths.push(Arc::clone(&health));
        let stop = Arc::clone(&stop_flag);
        let wake = Arc::clone(&wake_evt);
        let handle = thread::Builder::new()
            .name(wname.clone())
            .spawn(move || {
                let _guard = WorkerExitGuard {
                    health: Arc::clone(&health),
                    stop_flag: Arc::clone(&stop),
                    wake_evt: wake,
                };
                run_tx_worker(sh, q_idx, tx_mode, ep, rs, stop, health);
            })
            .map_err(|e| {
                stop_flag.store(true, Ordering::Release);
                format!("failed to spawn TX worker '{wname}': {e}")
            })?;
        worker_handles.push(handle);
    }

    {
        let rx_shared = shared_list.clone();
        let rx_stop = Arc::clone(&stop_flag);
        let rx_wake = Arc::clone(&wake_evt);
        let rx_health = WorkerHealth::new("gre-rx".into(), daemon_epoch);
        worker_healths.push(Arc::clone(&rx_health));
        let guard_wake = Arc::clone(&wake_evt);
        let handle = thread::Builder::new()
            .name("gre-rx".into())
            .spawn(move || {
                let _guard = WorkerExitGuard {
                    health: Arc::clone(&rx_health),
                    stop_flag: Arc::clone(&rx_stop),
                    wake_evt: guard_wake,
                };
                run_rx_worker(
                    rx_sock,
                    rx_epoll,
                    ka_reply_socks,
                    rx_shared,
                    rx_stop,
                    rx_wake,
                    rx_health,
                );
            })
            .map_err(|e| {
                stop_flag.store(true, Ordering::Release);
                format!("failed to spawn RX worker: {e}")
            })?;
        worker_handles.push(handle);
    }

    let pid = cur_pid;
    flush_status(&config.status_file, pid, true, &tunnels);
    let mut last_status_flush = Instant::now();

    let mut status_dirty =
        process_control_tick(&mut tunnels, tx_mode, &wake_evt, &bypass_registry, false, Instant::now());
    if status_dirty {
        flush_status(&config.status_file, pid, true, &tunnels);
        last_status_flush = Instant::now();
    }

    let mut tokens = [0u64; 16];
    let mut fatal_worker_err: Option<String> = None;
    while !shutdown_requested() {
        let now = Instant::now();
        let timeout_ms = next_timeout_ms(&tunnels, last_status_flush, now);

        let mut neigh_event = false;
        match ctrl_epoll.wait(&mut tokens, timeout_ms) {
            Ok(n) => {
                for &tok in &tokens[..n] {
                    if tok == TOKEN_EVENT_FD {
                        wake_evt.drain();
                    } else if tok == TOKEN_NETLINK_NEIGH {
                        if let Some(ref nw) = neigh_watch {
                            neigh_event |= nw.drain();
                        }
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("[warn] control epoll_wait error: {e}");
                break;
            }
        }

        let now_mono_ms = Instant::now()
            .saturating_duration_since(daemon_epoch)
            .as_millis() as u64;
        if let Some(bad_name) = find_unhealthy_worker(&worker_healths, now_mono_ms) {
            flush_status(&config.status_file, pid, false, &tunnels);
            fatal_worker_err = Some(format!(
                "data-plane worker '{bad_name}' failed or stalled; aborting daemon"
            ));
            break;
        }

        let now = Instant::now();
        status_dirty |=
            process_control_tick(&mut tunnels, tx_mode, &wake_evt, &bypass_registry, neigh_event, now);

        if status_dirty || now.duration_since(last_status_flush) >= STATUS_FLUSH_INTERVAL {
            flush_status(&config.status_file, pid, true, &tunnels);
            last_status_flush = now;
            status_dirty = false;
        }
    }

    if let Some(ref reason) = fatal_worker_err {
        eprintln!("[error] {reason}");
    } else {
        eprintln!(
            "[info] shutdown signal received, stopping workers and cleaning up {} tunnel(s)",
            tunnels.len()
        );
    }
    stop_flag.store(true, Ordering::Release);
    for h in worker_handles {
        let _ = h.join();
    }
    drop(tunnels);
    drop(instance_lease);
    remove_status_file(&config.status_file);
    if let Some(err) = fatal_worker_err {
        return Err(err);
    }
    Ok(())
}

fn find_unhealthy_worker(workers: &[Arc<WorkerHealth>], now_ms: u64) -> Option<String> {
    for w in workers {
        if w.failed.load(Ordering::Acquire) {
            return Some(w.name.clone());
        }
        let last = w.last_beat_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) > WORKER_STALL_MS {
            return Some(w.name.clone());
        }
    }
    None
}

fn setup_tunnel(
    cfg: TunnelConfig,
    requested_queues: usize,
    tx_mode: TxMode,
    existing_tun_ifs: &[u32],
    all_routes: &[RouteSpec],
    bypass_registry: &Arc<BypassRegistry>,
    now: Instant,
) -> Result<ManagedTunnel, String> {
    let remote_ip = cfg.remote.resolve_ipv4()?;
    let probe = probe_route_excluding(remote_ip, cfg.local_address, existing_tun_ifs)?;
    let actual_mtu = match cfg.mtu {
        MtuMode::Auto => probe.out_mtu.saturating_sub(GRE_OVERHEAD_V4).max(576),
        MtuMode::Fixed(m) => m,
    };

    let initial_carrier = matches!(cfg.keepalive, KeepaliveConfig::Disabled);
    let tun = TunDevice::create_multi(&cfg.name, actual_mtu, initial_carrier, requested_queues)?;
    let ka_tx_sock = RawGreSocket::open_tx(cfg.local_address)?;

    for cidr in &cfg.addresses {
        configure_interface_addr(tun.ifindex(), cidr)?;
    }

    let mut bypass_route: Option<BypassRouteGuard> = None;
    let needs_bypass = all_routes.iter().any(|r| r.dst.contains_v4(remote_ip));
    if needs_bypass && probe.out_ifindex > 0 {
        if let Some(guard) =
            bypass_registry.acquire(remote_ip, probe.out_ifindex, probe.gateway)?
        {
            eprintln!(
                "[info] [{}] installed bypass route {}/32 via dev {} (gw {}) to prevent tunnel routing loop",
                cfg.name,
                remote_ip,
                probe.out_ifname,
                probe
                    .gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "direct".into())
            );
            bypass_route = Some(guard);
        } else {
            eprintln!(
                "[info] [{}] preserved pre-existing host /32 route for {}",
                cfg.name, remote_ip
            );
        }
    }

    let mut installed_routes = InstalledRoutesGuard(Vec::new());
    for route in &cfg.routes {
        let mut added = configure_route(tun.ifindex(), route)?;
        installed_routes.0.append(&mut added);
    }

    let use_fast_path = tx_mode != TxMode::Raw && cfg.allow_fast_path;
    let src_mac = if use_fast_path && probe.out_ifindex > 0 {
        get_interface_hwaddr(&probe.out_ifname).ok()
    } else {
        None
    };
    let src_mac_packed = src_mac.map(encode_mac).unwrap_or(0);

    let next_hop_ip = probe.gateway.unwrap_or(remote_ip);
    let mut initial_mac_packed = 0u64;
    let mut next_arp_check = None;
    let mut arp_logged_fastpath = false;
    if use_fast_path && src_mac.is_some() && next_hop_ip != probe.local_ip {
        if let Some(mac) = lookup_arp_mac(next_hop_ip, &probe.out_ifname) {
            initial_mac_packed = encode_mac(mac);
            next_arp_check = now.checked_add(ARP_REFRESH_INTERVAL);
            arp_logged_fastpath = true;
        } else {
            trigger_arp_probe(next_hop_ip);
            next_arp_check = now.checked_add(ARP_RETRY_INTERVAL);
        }
    }

    let next_dns_check = match cfg.remote {
        RemoteEndpoint::Host(_) => now.checked_add(cfg.dns_refresh),
        RemoteEndpoint::Ip(_) => None,
    };

    let keepalive = KeepaliveStateMachine::new(cfg.keepalive, now);
    eprintln!(
        "[info] [{}] initialized: local={} remote={} ({}) mtu={} (out_dev={} out_mtu={}) keepalive={} dscp={:?} df={:?} clamp_mss={} vnet_tso={} udp_gso={} queues={} mq={}",
        cfg.name,
        probe.local_ip,
        cfg.remote.as_display(),
        remote_ip,
        actual_mtu,
        probe.out_ifname,
        probe.out_mtu,
        keepalive.state().as_str(),
        cfg.dscp,
        cfg.dont_fragment,
        cfg.clamp_tcp_mss,
        tun.has_vnet_hdr(),
        tun.has_udp_gso(),
        tun.queue_count(),
        tun.is_multi_queue(),
    );
    if arp_logged_fastpath {
        if let Some(m) = decode_mac(initial_mac_packed) {
            eprintln!(
                "[info] [{}] enabled AF_PACKET PACKET_TX_RING fast-path (dev={}, next_hop={}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                cfg.name, probe.out_ifname, next_hop_ip, m[0], m[1], m[2], m[3], m[4], m[5]
            );
        }
    }

    let shared = Arc::new(TunnelShared {
        name: cfg.name.clone(),
        epoch: now,
        local_bind: cfg.local_address,
        public_ip_override: cfg.public_ip,
        dscp_mode: cfg.dscp,
        df_mode: cfg.dont_fragment,
        clamp_tcp_mss: cfg.clamp_tcp_mss,
        allow_fast_path: cfg.allow_fast_path,
        actual_mtu,
        out_mtu: AtomicU32::new(probe.out_mtu as u32),
        out_ifindex: AtomicU32::new(probe.out_ifindex),
        src_mac: AtomicU64::new(src_mac_packed),
        local_ip: AtomicU32::new(u32::from(probe.local_ip)),
        remote_ip: AtomicU32::new(u32::from(remote_ip)),
        learned_public_ip: AtomicU32::new(0),
        nat_candidate_ip: AtomicU32::new(0),
        nat_candidate_hits: AtomicU32::new(0),
        next_hop_mac: AtomicU64::new(initial_mac_packed),
        next_ip_id: AtomicU32::new(1),
        carrier_up: AtomicBool::new(initial_carrier),
        ka_awaiting: AtomicBool::new(false),
        ka_ring_cursor: AtomicU32::new(0),
        ka_expected_tokens: [
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ],
        ka_expected_seqs: [
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
            AtomicU32::new(0),
        ],
        tx_packets: AtomicU64::new(0),
        rx_packets: AtomicU64::new(0),
        tx_drops: AtomicU64::new(0),
        rx_drops: AtomicU64::new(0),
        rx_trunc: AtomicU64::new(0),
        ka_replies_rx: AtomicU64::new(0),
        ka_requests_ans: AtomicU64::new(0),
        ka_spoof_drops: AtomicU64::new(0),
        emsgsize_warned: AtomicBool::new(false),
        tun,
    });

    Ok(ManagedTunnel {
        cfg,
        shared,
        ka_tx_sock,
        keepalive,
        last_ka_replies_seen: 0,
        last_learned_public: 0,
        out_ifname: probe.out_ifname,
        gateway: probe.gateway,
        next_dns_check,
        dns_inflight: false,
        dns_result: Arc::new(Mutex::new(None)),
        next_arp_check,
        arp_logged_fastpath,
        bypass_route,
        _installed_routes: installed_routes,
    })
}

fn find_tunnel_idx(tunnels: &[Arc<TunnelShared>], outer_src: Ipv4Addr, outer_dst: Ipv4Addr) -> Option<usize> {
    if !is_valid_unicast_ipv4(outer_src) || !is_valid_unicast_ipv4(outer_dst) {
        return None;
    }
    let src_u32 = u32::from(outer_src);
    let dst_u32 = u32::from(outer_dst);
    if let Some(pos) = tunnels.iter().position(|t| {
        t.remote_ip.load(Ordering::Relaxed) == src_u32
            && t.local_bind == Some(outer_dst)
    }) {
        return Some(pos);
    }
    if let Some(pos) = tunnels.iter().position(|t| {
        t.remote_ip.load(Ordering::Relaxed) == src_u32
            && t.local_bind.is_none()
            && t.local_ip.load(Ordering::Relaxed) == dst_u32
    }) {
        return Some(pos);
    }
    tunnels
        .iter()
        .position(|t| t.remote_ip.load(Ordering::Relaxed) == src_u32 && t.local_bind.is_none())
}

fn run_rx_worker(
    rx_sock: RawGreSocket,
    epoll: Epoll,
    mut ka_reply_socks: Vec<RawGreSocket>,
    tunnels: Vec<Arc<TunnelShared>>,
    stop_flag: Arc<AtomicBool>,
    wake_evt: Arc<EventFd>,
    health: Arc<WorkerHealth>,
) {
    let max_mtu = tunnels
        .iter()
        .map(|t| {
            (t.actual_mtu as usize + 64).max(t.out_mtu.load(Ordering::Relaxed) as usize + 32)
        })
        .max()
        .unwrap_or(2048);
    let rx_slot_size = if max_mtu <= 2048 {
        2048
    } else if max_mtu <= 9216 {
        9216
    } else {
        BATCH_SLOT_SIZE
    };
    let mut rx_batch = RxBatchBuffer::new(rx_slot_size);
    let mut gro_merger = RxGroMerger::new();
    let mut tokens = [0u64; 16];

    while !stop_flag.load(Ordering::Relaxed) && !shutdown_requested() {
        health.beat();
        let n_events = match epoll.wait(&mut tokens, 200) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if n_events == 0 {
            continue;
        }
        health.beat();

        let mut retry_used = 0u8;
        let mut need_jumbo_grow = false;
        for batch_iter in 0..64 {
            let pkt_count = match rx_sock.recv_batch(&mut rx_batch) {
                Ok(0) => {
                    if gro_merger.has_active() && retry_used < 2 {
                        retry_used += 1;
                        thread::yield_now();
                        continue;
                    }
                    break;
                }
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if gro_merger.has_active() && retry_used < 2 {
                        retry_used += 1;
                        thread::yield_now();
                        continue;
                    }
                    break;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    eprintln!("[warn] raw GRE recv error: {e}");
                    break;
                }
            };
            retry_used = 0;

            for i in 0..pkt_count {
                let is_trunc = rx_batch.is_truncated(i);
                let pkt_slice = rx_batch.pkt_mut(i);
                if is_trunc {
                    if let Some(outer) = parse_outer_ipv4(pkt_slice) {
                        if let Some(idx) = find_tunnel_idx(&tunnels, outer.src, outer.dst) {
                            tunnels[idx].rx_trunc.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if let Some(first_t) = tunnels.first() {
                        first_t.rx_trunc.fetch_add(1, Ordering::Relaxed);
                    }
                    if rx_batch.slot_cap() < BATCH_SLOT_SIZE {
                        need_jumbo_grow = true;
                    }
                    continue;
                }

                let (
                    outer_src,
                    outer_dst,
                    outer_id,
                    p_start,
                    p_end,
                    protocol,
                    ka_req_tok,
                    is_ka_req,
                    learned_ip,
                    ka_rep_info,
                ) = {
                    let Some(outer) = parse_outer_ipv4(pkt_slice) else {
                        continue;
                    };
                    if outer.proto != IPPROTO_GRE {
                        continue;
                    }
                    let Some(decoded) = decode_gre_payload(outer.payload) else {
                        if let Some(idx) = find_tunnel_idx(&tunnels, outer.src, outer.dst) {
                            tunnels[idx].rx_drops.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    };
                    match decoded {
                        GreDecoded::KeepaliveReply {
                            echo_token,
                            body_len,
                        } => (
                            outer.src,
                            outer.dst,
                            outer.id,
                            0usize,
                            0usize,
                            0u16,
                            None,
                            false,
                            Ipv4Addr::UNSPECIFIED,
                            Some((echo_token, body_len)),
                        ),
                        GreDecoded::KeepaliveRequest {
                            learned_public_ip,
                            echo_token,
                            inner_packet: _,
                        } => (
                            outer.src,
                            outer.dst,
                            outer.id,
                            0usize,
                            0usize,
                            0u16,
                            echo_token,
                            true,
                            learned_public_ip,
                            None,
                        ),
                        GreDecoded::Data { protocol, payload } => {
                            let start = payload.as_ptr() as usize - pkt_slice.as_ptr() as usize;
                            (
                                outer.src,
                                outer.dst,
                                outer.id,
                                start,
                                start + payload.len(),
                                protocol,
                                None,
                                false,
                                Ipv4Addr::UNSPECIFIED,
                                None,
                            )
                        }
                        GreDecoded::Unsupported(_) => continue,
                    }
                };

                let Some(idx) = find_tunnel_idx(&tunnels, outer_src, outer_dst) else {
                    continue;
                };
                let tunnel = &tunnels[idx];

                if let Some((rep_tok, body_len)) = ka_rep_info {
                    if tunnel.verify_ka_reply(rep_tok, body_len, outer_id) {
                        tunnel.ka_replies_rx.fetch_add(1, Ordering::Release);
                        if !tunnel.carrier_up.load(Ordering::Relaxed) {
                            wake_evt.notify();
                        }
                    } else {
                        tunnel.ka_spoof_drops.fetch_add(1, Ordering::Relaxed);
                    }
                    continue;
                }

                if is_ka_req {
                    tunnel.ka_requests_ans.fetch_add(1, Ordering::Relaxed);
                    if tunnel.observe_peer_reported_ip(learned_ip) {
                        wake_evt.notify();
                    }
                    let reply_payload = build_keepalive_reply(ka_req_tok);
                    let _ = ka_reply_socks[idx].send_to(outer_src, 0, false, &reply_payload);
                    continue;
                }

                if p_end <= p_start {
                    tunnel.rx_drops.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(meta) = inspect_inner_ip(&pkt_slice[p_start..p_end]) else {
                    tunnel.rx_drops.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                match (protocol, meta.version) {
                    (ETHERTYPE_IPV4, IpVersion::V4) | (ETHERTYPE_IPV6, IpVersion::V6) => {}
                    _ => {
                        tunnel.rx_drops.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                if tunnel.clamp_tcp_mss {
                    clamp_tcp_mss(&mut pkt_slice[p_start..p_end], tunnel.actual_mtu);
                }
                let has_vnet = tunnel.tun.has_vnet_hdr();
                if has_vnet {
                    let absorbed = gro_merger.feed_with_udp(
                        idx,
                        &pkt_slice[p_start..p_end],
                        tunnel.tun.has_udp_gso(),
                        |t_idx, merged_pkt| {
                            let t = &tunnels[t_idx];
                            let q = packet_flow_hash(&merged_pkt[VNET_HDR_LEN..]);
                            if write_tun_counted(t, q, merged_pkt) {
                                t.rx_packets.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                    );
                    if absorbed {
                        continue;
                    }
                }

                let write_start = if has_vnet && p_start >= VNET_HDR_LEN {
                    let vstart = p_start - VNET_HDR_LEN;
                    pkt_slice[vstart..p_start].fill(0);
                    vstart
                } else {
                    p_start
                };
                let q = packet_flow_hash(&pkt_slice[p_start..p_end]);
                if write_tun_counted(tunnel, q, &pkt_slice[write_start..p_end]) {
                    tunnel.rx_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
            if (batch_iter & 7) == 7 {
                gro_merger.flush(|t_idx, merged_pkt| {
                    let t = &tunnels[t_idx];
                    let q = packet_flow_hash(&merged_pkt[VNET_HDR_LEN..]);
                    if write_tun_counted(t, q, merged_pkt) {
                        t.rx_packets.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            if need_jumbo_grow {
                break;
            }
        }
        gro_merger.flush(|t_idx, merged_pkt| {
            let t = &tunnels[t_idx];
            let q = packet_flow_hash(&merged_pkt[VNET_HDR_LEN..]);
            if write_tun_counted(t, q, merged_pkt) {
                t.rx_packets.fetch_add(1, Ordering::Relaxed);
            }
        });
        if need_jumbo_grow && rx_batch.slot_cap() < BATCH_SLOT_SIZE {
            rx_batch = RxBatchBuffer::new(BATCH_SLOT_SIZE);
        }
    }
}

/// Per-worker RFC 6864 compliant IPv4 Identification allocator:
/// - Returns `0` for atomic `DF=1` packets without consuming ID space.
/// - Reserves disjoint 256-ID blocks from `TunnelShared::next_ip_id` for `DF=0` packets.
struct IpIdAlloc {
    cur: u16,
    rem: u16,
}

impl IpIdAlloc {
    fn new() -> Self {
        Self { cur: 0, rem: 0 }
    }

    #[inline]
    fn next(&mut self, df: bool, shared: &TunnelShared) -> u16 {
        if df {
            return 0;
        }
        if self.rem == 0 {
            let base = shared.next_ip_id.fetch_add(256, Ordering::Relaxed) as u16;
            self.cur = base;
            self.rem = 256;
        }
        self.rem -= 1;
        let mut id = self.cur;
        self.cur = self.cur.wrapping_add(1);
        if id == 0 {
            id = 1;
        }
        id
    }
}

/// Compact L2-resident arena for segmented `RawGreSocket` fallback batches (128 KB for standard MTU).
struct TxBatchArena {
    data: Vec<u8>,
    stride: usize,
}

impl TxBatchArena {
    fn new(slot_cap: usize) -> Self {
        let stride = slot_cap.clamp(2048, BATCH_SLOT_SIZE);
        Self {
            data: vec![0u8; stride * BATCH_CAP],
            stride,
        }
    }

    #[inline]
    fn slot_cap(&self) -> usize {
        self.stride
    }

    #[inline]
    fn slot_mut(&mut self, idx: usize) -> &mut [u8] {
        let s = idx * self.stride;
        &mut self.data[s..s + self.stride]
    }

    #[inline]
    fn slot(&self, idx: usize) -> &[u8] {
        let s = idx * self.stride;
        &self.data[s..s + self.stride]
    }
}

struct WorkerTxSink<'a> {
    shared: &'a TunnelShared,
    q_idx: usize,
    raw_sock: &'a mut RawGreSocket,
    ring: &'a mut Option<PacketTxRing>,
    tx_arena: &'a mut TxBatchArena,
    raw_lens: [usize; BATCH_CAP],
    raw_count: usize,
    raw_dscp: u8,
    raw_df: bool,
    cur_local_ip: Ipv4Addr,
    cur_remote_ip: Ipv4Addr,
    cur_out_mtu: usize,
    cur_src_mac: Option<[u8; 6]>,
    cur_dscp: u8,
    cur_df: bool,
    cur_dst_mac: Option<[u8; 6]>,
    ip_ids: &'a mut IpIdAlloc,
    icmp_budget: &'a mut (u64, u32),
    last_alloc_in_ring: bool,
    ring_sent_count: u64,
}

impl<'a> WorkerTxSink<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        shared: &'a TunnelShared,
        q_idx: usize,
        raw_sock: &'a mut RawGreSocket,
        ring: &'a mut Option<PacketTxRing>,
        tx_arena: &'a mut TxBatchArena,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        out_mtu: usize,
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
        ip_ids: &'a mut IpIdAlloc,
        icmp_budget: &'a mut (u64, u32),
    ) -> Self {
        Self {
            shared,
            q_idx,
            raw_sock,
            ring,
            tx_arena,
            raw_lens: [0usize; BATCH_CAP],
            raw_count: 0,
            raw_dscp: 0,
            raw_df: false,
            cur_local_ip: local_ip,
            cur_remote_ip: remote_ip,
            cur_out_mtu: out_mtu,
            cur_src_mac: src_mac,
            cur_dscp: 0,
            cur_df: false,
            cur_dst_mac: dst_mac,
            ip_ids,
            icmp_budget,
            last_alloc_in_ring: false,
            ring_sent_count: 0,
        }
    }

    #[inline]
    fn can_use_ring(&self, gre_pkt_len: usize) -> bool {
        let Some(ring) = self.ring.as_ref() else {
            return false;
        };
        if self.cur_dst_mac.is_none() || self.cur_src_mac.is_none() {
            return false;
        }
        let outer_ip_len = OUTER_IP_HDR_LEN + gre_pkt_len;
        let wire_frame_len = ETH_HDR_LEN + outer_ip_len;
        outer_ip_len <= self.cur_out_mtu && wire_frame_len <= ring.max_frame_len()
    }

    fn flush_raw(&mut self) {
        if self.raw_count == 0 {
            return;
        }
        let mut ip_slices: [&[u8]; BATCH_CAP] = [&[]; BATCH_CAP];
        let mut gre_slices: [&[u8]; BATCH_CAP] = [&[]; BATCH_CAP];
        for i in 0..self.raw_count {
            let gre_len = self.raw_lens[i];
            let slot = self.tx_arena.slot(i);
            ip_slices[i] = &slot[..OUTER_IP_HDR_LEN + gre_len];
            gre_slices[i] = &slot[OUTER_IP_HDR_LEN..OUTER_IP_HDR_LEN + gre_len];
        }
        let outcome = self.raw_sock.send_batch(
            self.cur_remote_ip,
            self.raw_dscp,
            self.raw_df,
            &ip_slices[..self.raw_count],
            &gre_slices[..self.raw_count],
        );
        if outcome.sent > 0 {
            self.shared
                .tx_packets
                .fetch_add(outcome.sent as u64, Ordering::Relaxed);
        }
        if outcome.dropped > 0 {
            self.shared
                .tx_drops
                .fetch_add(outcome.dropped as u64, Ordering::Relaxed);
        }
        if outcome.emsgsize_mask != 0 {
            if !self.shared.emsgsize_warned.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "[warn] [{}] outer packet exceeded path MTU with dont-fragment=inherit; synthesizing ICMP Packet Too Big",
                    self.shared.name
                );
            }
            let pmtu_inner = self
                .shared
                .actual_mtu
                .min((self.cur_out_mtu as u16).saturating_sub(GRE_OVERHEAD_V4))
                .max(68);
            let now_sec = Instant::now()
                .saturating_duration_since(self.shared.epoch)
                .as_secs();
            if self.icmp_budget.0 != now_sec {
                self.icmp_budget.0 = now_sec;
                self.icmp_budget.1 = 0;
            }
            let mut mask = outcome.emsgsize_mask;
            let mut icmp_buf = [0u8; 1340];
            while mask != 0 && self.icmp_budget.1 < 100 {
                let idx = mask.trailing_zeros() as usize;
                mask &= mask - 1;
                if idx < self.raw_count && self.raw_lens[idx] > GRE_HDR_LEN {
                    let slot = self.tx_arena.slot(idx);
                    let inner = &slot[OUTER_IP_HDR_LEN + GRE_HDR_LEN
                        ..OUTER_IP_HDR_LEN + self.raw_lens[idx]];
                    if let Some(icmp_len) = build_icmp_pkt_too_big(
                        inner,
                        pmtu_inner,
                        None,
                        None,
                        self.shared.tun.has_vnet_hdr(),
                        &mut icmp_buf,
                    ) {
                        self.icmp_budget.1 += 1;
                        let _ = self
                            .shared
                            .tun
                            .write_queue_nonblock(self.q_idx, &icmp_buf[..icmp_len]);
                    }
                }
            }
        }
        self.raw_count = 0;
    }

    fn flush_all(&mut self) {
        if let Some(ring) = self.ring.as_mut() {
            ring.kick();
        }
        if self.ring_sent_count > 0 {
            self.shared
                .tx_packets
                .fetch_add(self.ring_sent_count, Ordering::Relaxed);
            self.ring_sent_count = 0;
        }
        self.flush_raw();
    }

    fn push_ready_slice(&mut self, gre_slice: &[u8]) {
        let len = gre_slice.len();
        if let Some(dst_slot) = self.alloc_slot(len) {
            dst_slot[..len].copy_from_slice(&gre_slice[..len]);
            self.commit_slot(len);
        } else {
            self.shared.tx_drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl<'a> TxSlotSink for WorkerTxSink<'a> {
    fn alloc_slot(&mut self, gre_pkt_len: usize) -> Option<&mut [u8]> {
        if self.can_use_ring(gre_pkt_len) {
            let frame_len = ETH_HDR_LEN + OUTER_IP_HDR_LEN + gre_pkt_len;
            if self
                .ring
                .as_mut()
                .map(|r| r.ensure_slot_ready(frame_len))
                .unwrap_or(false)
            {
                self.last_alloc_in_ring = true;
                return self.ring.as_mut().map(|ring| {
                    let frame = ring.cur_frame_mut(frame_len);
                    &mut frame[ETH_HDR_LEN + OUTER_IP_HDR_LEN..]
                });
            }
        }

        self.last_alloc_in_ring = false;
        if self.raw_count > 0
            && (self.raw_dscp != self.cur_dscp
                || self.raw_df != self.cur_df
                || self.raw_count >= BATCH_CAP)
        {
            self.flush_raw();
        }
        if self.raw_count == 0 {
            self.raw_dscp = self.cur_dscp;
            self.raw_df = self.cur_df;
        }
        if OUTER_IP_HDR_LEN + gre_pkt_len > self.tx_arena.slot_cap() {
            return None;
        }
        let slot = self.tx_arena.slot_mut(self.raw_count);
        Some(&mut slot[OUTER_IP_HDR_LEN..OUTER_IP_HDR_LEN + gre_pkt_len])
    }

    fn commit_slot(&mut self, gre_pkt_len: usize) {
        if self.last_alloc_in_ring {
            let frame_len = ETH_HDR_LEN + OUTER_IP_HDR_LEN + gre_pkt_len;
            let dst_mac = self.cur_dst_mac.unwrap_or([0; 6]);
            let src_mac = self.cur_src_mac.unwrap_or([0; 6]);
            let id = self.ip_ids.next(self.cur_df, self.shared);
            if let Some(ring) = self.ring.as_mut() {
                let frame = ring.cur_frame_mut(frame_len);
                frame[0..6].copy_from_slice(&dst_mac);
                frame[6..12].copy_from_slice(&src_mac);
                frame[12] = 0x08;
                frame[13] = 0x00;
                write_outer_ipv4_gre_header(
                    &mut frame[ETH_HDR_LEN..ETH_HDR_LEN + OUTER_IP_HDR_LEN],
                    self.cur_local_ip,
                    self.cur_remote_ip,
                    self.cur_dscp,
                    self.cur_df,
                    id,
                    (OUTER_IP_HDR_LEN + gre_pkt_len) as u16,
                );
                ring.commit_frame(frame_len);
                self.ring_sent_count += 1;
            }
        } else {
            let id = self.ip_ids.next(self.cur_df, self.shared);
            let outer_total = (OUTER_IP_HDR_LEN + gre_pkt_len).min(u16::MAX as usize) as u16;
            let slot = self.tx_arena.slot_mut(self.raw_count);
            write_outer_ipv4_gre_header(
                &mut slot[..OUTER_IP_HDR_LEN],
                self.cur_local_ip,
                self.cur_remote_ip,
                self.cur_dscp,
                self.cur_df,
                id,
                outer_total,
            );
            self.raw_lens[self.raw_count] = gre_pkt_len;
            self.raw_count += 1;
            if self.raw_count >= BATCH_CAP {
                self.flush_raw();
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FastFrameCtx {
    head_read_cap: usize,
    out_mtu: usize,
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

/// Attempt zero-copy in-place GRE+IPv4+Ethernet encapsulation inside `frame` where `readv`
/// placed `[10B VnetHdr][Inner IP]` starting at `frame[VNET_IN_FRAME_OFF..VNET_IN_FRAME_OFF + n]`.
/// Returns `Some(inner_len)` if committed to `ring` in-place, or `None` if caller must evacuate
/// (e.g. TSO/USO super-packet, oversized outer packet, carrier down, or invalid header).
#[inline]
fn try_commit_vnet_frame_in_place(
    frame: &mut [u8],
    n: usize,
    ctx: FastFrameCtx,
    shared: &TunnelShared,
    ring: &mut PacketTxRing,
    ip_ids: &mut IpIdAlloc,
) -> Option<usize> {
    if n <= VNET_HDR_LEN || n > ctx.head_read_cap || !shared.carrier_up.load(Ordering::Relaxed) {
        return None;
    }
    let vhdr = VnetHdr::parse(&frame[VNET_IN_FRAME_OFF..WIRE_PKT_OFF])?;
    if (vhdr.gso_type & !0x80) != VIRTIO_NET_HDR_GSO_NONE {
        return None;
    }
    let inner_len = n - VNET_HDR_LEN;
    let outer_ip_len = OUTER_IP_HDR_LEN + GRE_HDR_LEN + inner_len;
    let wire_end = WIRE_PKT_OFF + inner_len;
    if outer_ip_len > ctx.out_mtu || wire_end > frame.len() {
        return None;
    }
    let meta = inspect_inner_ip(&frame[WIRE_PKT_OFF..wire_end])?;
    if !finish_partial_checksum(&mut frame[WIRE_PKT_OFF..wire_end], vhdr) {
        return None;
    }
    if shared.clamp_tcp_mss {
        clamp_tcp_mss(&mut frame[WIRE_PKT_OFF..wire_end], shared.actual_mtu);
    }
    let dscp = match shared.dscp_mode {
        DscpMode::Inherit => meta.dscp,
        DscpMode::Fixed(v) => v,
    };
    let df = match shared.df_mode {
        DontFragmentMode::No => false,
        DontFragmentMode::Inherit => meta.df,
    };
    let proto = match meta.version {
        IpVersion::V4 => ETHERTYPE_IPV4,
        IpVersion::V6 => ETHERTYPE_IPV6,
    };
    let id = ip_ids.next(df, shared);

    let gre_off = ETH_HDR_LEN + OUTER_IP_HDR_LEN;
    frame[gre_off] = 0;
    frame[gre_off + 1] = 0;
    frame[gre_off + 2..gre_off + 4].copy_from_slice(&proto.to_be_bytes());
    write_outer_ipv4_gre_header(
        &mut frame[ETH_HDR_LEN..gre_off],
        ctx.local_ip,
        ctx.remote_ip,
        dscp,
        df,
        id,
        outer_ip_len as u16,
    );
    frame[0..6].copy_from_slice(&ctx.dst_mac);
    frame[6..12].copy_from_slice(&ctx.src_mac);
    frame[12] = 0x08;
    frame[13] = 0x00;

    ring.commit_frame(wire_end);
    Some(inner_len)
}

/// Process a `[4B headroom][10B VnetHdr][Inner IP]` buffer (`buf[4..4 + n]`) through `WorkerTxSink`.
fn process_vnet_staged_packet(
    buf: &mut [u8],
    n: usize,
    shared: &TunnelShared,
    sink: &mut WorkerTxSink<'_>,
) -> usize {
    if n <= VNET_HDR_LEN || !shared.carrier_up.load(Ordering::Relaxed) {
        return 0;
    }
    let Some(vhdr) = VnetHdr::parse(&buf[4..4 + VNET_HDR_LEN]) else {
        shared.tx_drops.fetch_add(1, Ordering::Relaxed);
        return 0;
    };
    let pkt_start = 4 + VNET_HDR_LEN;
    let pkt_end = 4 + n;
    let Some(meta) = inspect_inner_ip(&buf[pkt_start..pkt_end]) else {
        shared.tx_drops.fetch_add(1, Ordering::Relaxed);
        return 0;
    };
    sink.cur_dscp = match shared.dscp_mode {
        DscpMode::Inherit => meta.dscp,
        DscpMode::Fixed(v) => v,
    };
    sink.cur_df = match shared.df_mode {
        DontFragmentMode::No => false,
        DontFragmentMode::Inherit => meta.df,
    };
    if (vhdr.gso_type & !0x80) == VIRTIO_NET_HDR_GSO_NONE {
        if !finish_partial_checksum(&mut buf[pkt_start..pkt_end], vhdr) {
            shared.tx_drops.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        if shared.clamp_tcp_mss {
            clamp_tcp_mss(&mut buf[pkt_start..pkt_end], shared.actual_mtu);
        }
        let proto = match meta.version {
            IpVersion::V4 => ETHERTYPE_IPV4,
            IpVersion::V6 => ETHERTYPE_IPV6,
        };
        buf[VNET_HDR_LEN] = 0;
        buf[VNET_HDR_LEN + 1] = 0;
        buf[VNET_HDR_LEN + 2..VNET_HDR_LEN + 4].copy_from_slice(&proto.to_be_bytes());
        sink.push_ready_slice(&buf[VNET_HDR_LEN..pkt_end]);
    } else if !segment_tso_into(&buf[pkt_start..pkt_end], vhdr, shared.actual_mtu, sink) {
        shared.tx_drops.fetch_add(1, Ordering::Relaxed);
    }
    n - VNET_HDR_LEN
}

fn run_tx_worker(
    shared: Arc<TunnelShared>,
    q_idx: usize,
    tx_mode: TxMode,
    epoll: Epoll,
    mut raw_sock: RawGreSocket,
    stop_flag: Arc<AtomicBool>,
    health: Arc<WorkerHealth>,
) {
    let tun_fd = shared.tun.queue_fd(q_idx);

    let use_fast_path = tx_mode != TxMode::Raw && shared.allow_fast_path;
    let init_ifindex = shared.out_ifindex.load(Ordering::Acquire);
    let init_src_mac = decode_mac(shared.src_mac.load(Ordering::Acquire));
    let max_ring_frame = (ETH_HDR_LEN + OUTER_IP_HDR_LEN + 4 + shared.actual_mtu as usize).max(2000);

    let mut ring_ifindex = 0u32;
    let mut ring: Option<PacketTxRing> = if use_fast_path
        && init_src_mac.is_some()
        && init_ifindex > 0
    {
        match PacketTxRing::open(init_ifindex, max_ring_frame) {
            Ok(r) => {
                ring_ifindex = init_ifindex;
                Some(r)
            }
            Err(e) => {
                if tx_mode == TxMode::Mmap {
                    eprintln!("[warn] [{}] PACKET_TX_RING unavailable ({e}); using SOCK_RAW", shared.name);
                }
                None
            }
        }
    } else {
        None
    };

    let has_vnet = shared.tun.has_vnet_hdr();
    let mut uring: Option<TunUringReader> = if has_vnet && ring.is_some() {
        TunUringReader::open(tun_fd).ok()
    } else {
        None
    };

    let arena_slot_cap =
        (OUTER_IP_HDR_LEN + GRE_HDR_LEN + shared.actual_mtu as usize + 128).clamp(2048, BATCH_SLOT_SIZE);
    let mut tx_arena = TxBatchArena::new(arena_slot_cap);
    let mut tun_read_buf = vec![0u8; BATCH_SLOT_SIZE + VNET_HDR_LEN];
    let mut tso_overflow = if has_vnet {
        vec![[0u8; TSO_OVERFLOW_SIZE]; URING_BATCH]
    } else {
        Vec::new()
    };
    let mut evac_queue: Vec<Vec<u8>> = Vec::with_capacity(URING_BATCH);
    let mut tokens = [0u64; 8];
    let mut ip_ids = IpIdAlloc::new();
    let mut icmp_budget = (0u64, 0u32);

    while !stop_flag.load(Ordering::Relaxed) && !shutdown_requested() {
        health.beat();
        let n_events = match epoll.wait(&mut tokens, 200) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if n_events == 0 {
            continue;
        }
        health.beat();

        let local_ip = Ipv4Addr::from(shared.local_ip.load(Ordering::Acquire));
        let remote_ip = Ipv4Addr::from(shared.remote_ip.load(Ordering::Acquire));
        let out_mtu = shared.out_mtu.load(Ordering::Acquire) as usize;
        let cur_ifindex = shared.out_ifindex.load(Ordering::Acquire);
        let src_mac = if use_fast_path {
            decode_mac(shared.src_mac.load(Ordering::Acquire))
        } else {
            None
        };
        if use_fast_path {
            if src_mac.is_some() && cur_ifindex > 0 {
                if cur_ifindex != ring_ifindex {
                    ring = PacketTxRing::open(cur_ifindex, max_ring_frame).ok();
                    ring_ifindex = if ring.is_some() { cur_ifindex } else { 0 };
                }
            } else if ring.is_some() {
                ring = None;
                ring_ifindex = 0;
            }
        }
        let dst_mac = if use_fast_path {
            decode_mac(shared.next_hop_mac.load(Ordering::Acquire))
        } else {
            None
        };

        let head_read_cap = VNET_HDR_LEN + shared.actual_mtu as usize;
        let min_ring_frame = WIRE_PKT_OFF + shared.actual_mtu as usize;
        let zero_copy_macs = match (src_mac, dst_mac) {
            (Some(s), Some(d)) => Some((s, d)),
            _ => None,
        };
        let can_zero_copy_ring = has_vnet
            && zero_copy_macs.is_some()
            && (OUTER_IP_HDR_LEN + GRE_HDR_LEN + shared.actual_mtu as usize) <= out_mtu
            && ring
                .as_ref()
                .map(|r| min_ring_frame <= r.max_frame_len())
                .unwrap_or(false);

        if let (true, Some((s_mac, d_mac))) = (can_zero_copy_ring, zero_copy_macs) {
            const TX_BYTE_BUDGET: usize = 1024 * 1024;
            let fctx = FastFrameCtx {
                head_read_cap,
                out_mtu,
                local_ip,
                remote_ip,
                src_mac: s_mac,
                dst_mac: d_mac,
            };
            let mut bytes_read = 0usize;
            let mut direct_sent = 0u64;

            for _ in 0..4 {
                if bytes_read >= TX_BYTE_BUDGET {
                    break;
                }
                if uring.is_some() {
                    let Some((avail, max_frame_len)) = ring.as_mut().map(|r| {
                        (
                            r.available_run(URING_BATCH, min_ring_frame),
                            r.max_frame_len(),
                        )
                    }) else {
                        break;
                    };
                    if avail == 0 {
                        // Ring temporarily full; drain remaining burst through RawGreSocket fallback
                        let mut sink = WorkerTxSink::new(
                            &shared,
                            q_idx,
                            &mut raw_sock,
                            &mut ring,
                            &mut tx_arena,
                            local_ip,
                            remote_ip,
                            out_mtu,
                            src_mac,
                            dst_mac,
                            &mut ip_ids,
                            &mut icmp_budget,
                        );
                        for _ in 0..BATCH_CAP {
                            let n = match shared.tun.read_queue_nonblock(q_idx, &mut tun_read_buf[4..]) {
                                Ok(n) => n,
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                                Err(_) => break,
                            };
                            let _ = process_vnet_staged_packet(&mut tun_read_buf, n, &shared, &mut sink);
                        }
                        sink.flush_all();
                        break;
                    }

                    let mut frame_ptrs = [std::ptr::null_mut::<u8>(); URING_BATCH];
                    if let Some(r) = ring.as_mut() {
                        for (i, slot_ptr) in frame_ptrs.iter_mut().enumerate().take(avail) {
                            *slot_ptr = r.slot_frame_ptr(i);
                        }
                    } else {
                        break;
                    }
                    let mut cqe_results = [-11i32; URING_BATCH];
                    let mut uring_failed = false;
                    let hit_eagain = if let Some(ur) = uring.as_mut() {
                        unsafe {
                            match ur.readv_into_frames(
                                &frame_ptrs[..avail],
                                VNET_IN_FRAME_OFF,
                                head_read_cap,
                                &mut tso_overflow[..avail],
                                &mut cqe_results,
                            ) {
                                Ok(eag) => eag,
                                Err(_) => {
                                    uring_failed = true;
                                    true
                                }
                            }
                        }
                    } else {
                        true
                    };
                    if uring_failed {
                        uring = None;
                        if cqe_results[..avail].iter().all(|&r| r <= 0) {
                            continue;
                        }
                    }

                    let mut divert_from: Option<usize> = None;
                    for i in 0..avail {
                        let res = cqe_results[i];
                        if res <= 0 {
                            if cqe_results[i + 1..avail].iter().any(|&r| r > 0) {
                                divert_from = Some(i + 1);
                            }
                            break;
                        }
                        let n = res as usize;
                        let frame_slice =
                            unsafe { std::slice::from_raw_parts_mut(frame_ptrs[i], max_frame_len) };
                        let Some(r) = ring.as_mut() else {
                            divert_from = Some(i);
                            break;
                        };
                        if let Some(inner_len) = try_commit_vnet_frame_in_place(
                            frame_slice,
                            n,
                            fctx,
                            &shared,
                            r,
                            &mut ip_ids,
                        ) {
                            bytes_read += inner_len;
                            direct_sent += 1;
                        } else {
                            divert_from = Some(i);
                            break;
                        }
                    }

                    if let Some(start_idx) = divert_from {
                        evac_queue.clear();
                        for j in start_idx..avail {
                            if cqe_results[j] <= 0 {
                                continue;
                            }
                            let n = cqe_results[j] as usize;
                            let head_n = n.min(head_read_cap);
                            let tail_n = n.saturating_sub(head_read_cap).min(TSO_OVERFLOW_SIZE);
                            let mut v = vec![0u8; 4 + head_n + tail_n];
                            let src_head = unsafe {
                                std::slice::from_raw_parts(
                                    frame_ptrs[j].add(VNET_IN_FRAME_OFF),
                                    head_n,
                                )
                            };
                            v[4..4 + head_n].copy_from_slice(src_head);
                            if tail_n > 0 {
                                v[4 + head_n..4 + head_n + tail_n]
                                    .copy_from_slice(&tso_overflow[j][..tail_n]);
                            }
                            evac_queue.push(v);
                        }
                        let mut sink = WorkerTxSink::new(
                            &shared,
                            q_idx,
                            &mut raw_sock,
                            &mut ring,
                            &mut tx_arena,
                            local_ip,
                            remote_ip,
                            out_mtu,
                            src_mac,
                            dst_mac,
                            &mut ip_ids,
                            &mut icmp_budget,
                        );
                        for pkt_buf in &mut evac_queue {
                            let pkt_n = pkt_buf.len() - 4;
                            bytes_read += process_vnet_staged_packet(pkt_buf, pkt_n, &shared, &mut sink);
                        }
                        sink.flush_raw();
                        direct_sent += sink.ring_sent_count;
                    }

                    if hit_eagain {
                        break;
                    }
                } else {
                    // Fallback when io_uring is disabled by container seccomp: zero-copy readv per packet
                    let mut drained_empty = false;
                    for _ in 0..BATCH_CAP {
                        if bytes_read >= TX_BYTE_BUDGET {
                            break;
                        }
                        let Some(avail) = ring
                            .as_mut()
                            .map(|r| r.available_run(1, min_ring_frame))
                        else {
                            break;
                        };
                        if avail == 0 {
                            let n = match shared.tun.read_queue_nonblock(q_idx, &mut tun_read_buf[4..]) {
                                Ok(n) => n,
                                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                    drained_empty = true;
                                    break;
                                }
                                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                                Err(_) => {
                                    drained_empty = true;
                                    break;
                                }
                            };
                            let mut sink = WorkerTxSink::new(
                                &shared,
                                q_idx,
                                &mut raw_sock,
                                &mut ring,
                                &mut tx_arena,
                                local_ip,
                                remote_ip,
                                out_mtu,
                                src_mac,
                                dst_mac,
                                &mut ip_ids,
                                &mut icmp_budget,
                            );
                            bytes_read += process_vnet_staged_packet(&mut tun_read_buf, n, &shared, &mut sink);
                            sink.flush_raw();
                            direct_sent += sink.ring_sent_count;
                            continue;
                        }
                        let Some((max_frame_len, fptr)) = ring
                            .as_mut()
                            .map(|r| (r.max_frame_len(), r.slot_frame_ptr(0)))
                        else {
                            break;
                        };
                        let head_slice = unsafe {
                            std::slice::from_raw_parts_mut(fptr.add(VNET_IN_FRAME_OFF), head_read_cap)
                        };
                        let n = match shared
                            .tun
                            .readv_queue_nonblock(q_idx, head_slice, &mut tso_overflow[0])
                        {
                            Ok(n) => n,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                drained_empty = true;
                                break;
                            }
                            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                            Err(_) => {
                                drained_empty = true;
                                break;
                            }
                        };
                        let frame_slice = unsafe { std::slice::from_raw_parts_mut(fptr, max_frame_len) };
                        let committed = ring.as_mut().and_then(|r| {
                            try_commit_vnet_frame_in_place(
                                frame_slice,
                                n,
                                fctx,
                                &shared,
                                r,
                                &mut ip_ids,
                            )
                        });
                        if let Some(inner_len) = committed {
                            bytes_read += inner_len;
                            direct_sent += 1;
                        } else {
                            let head_n = n.min(head_read_cap);
                            let tail_n = n.saturating_sub(head_read_cap).min(TSO_OVERFLOW_SIZE);
                            let total_n = head_n + tail_n;
                            let src_head = unsafe {
                                std::slice::from_raw_parts(fptr.add(VNET_IN_FRAME_OFF), head_n)
                            };
                            tun_read_buf[4..4 + head_n].copy_from_slice(src_head);
                            if tail_n > 0 {
                                tun_read_buf[4 + head_n..4 + total_n]
                                    .copy_from_slice(&tso_overflow[0][..tail_n]);
                            }
                            let mut sink = WorkerTxSink::new(
                                &shared,
                                q_idx,
                                &mut raw_sock,
                                &mut ring,
                                &mut tx_arena,
                                local_ip,
                                remote_ip,
                                out_mtu,
                                src_mac,
                                dst_mac,
                                &mut ip_ids,
                                &mut icmp_budget,
                            );
                            bytes_read += process_vnet_staged_packet(
                                &mut tun_read_buf,
                                total_n,
                                &shared,
                                &mut sink,
                            );
                            sink.flush_raw();
                            direct_sent += sink.ring_sent_count;
                        }
                    }
                    if drained_empty {
                        break;
                    }
                }
            }

            if let Some(r) = ring.as_mut() {
                r.kick();
            }
            if direct_sent > 0 {
                shared.tx_packets.fetch_add(direct_sent, Ordering::Relaxed);
            }
            continue;
        }

        let mut sink = WorkerTxSink::new(
            &shared,
            q_idx,
            &mut raw_sock,
            &mut ring,
            &mut tx_arena,
            local_ip,
            remote_ip,
            out_mtu,
            src_mac,
            dst_mac,
            &mut ip_ids,
            &mut icmp_budget,
        );

        if has_vnet {
            const TX_BYTE_BUDGET: usize = 1024 * 1024;
            let mut bytes_read = 0usize;
            for _ in 0..(BATCH_CAP * 4) {
                if bytes_read >= TX_BYTE_BUDGET {
                    break;
                }
                let n = match shared.tun.read_queue_nonblock(q_idx, &mut tun_read_buf[4..]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                bytes_read += process_vnet_staged_packet(&mut tun_read_buf, n, &shared, &mut sink);
            }
        } else {
            for _ in 0..(BATCH_CAP * 4) {
                let n = match shared.tun.read_queue_nonblock(q_idx, &mut tun_read_buf[4..]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                };
                if n == 0 || !shared.carrier_up.load(Ordering::Relaxed) {
                    continue;
                }
                let pkt_end = 4 + n;
                let Some(meta) = inspect_inner_ip(&tun_read_buf[4..pkt_end]) else {
                    shared.tx_drops.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if shared.clamp_tcp_mss {
                    clamp_tcp_mss(&mut tun_read_buf[4..pkt_end], shared.actual_mtu);
                }
                sink.cur_dscp = match shared.dscp_mode {
                    DscpMode::Inherit => meta.dscp,
                    DscpMode::Fixed(v) => v,
                };
                sink.cur_df = match shared.df_mode {
                    DontFragmentMode::No => false,
                    DontFragmentMode::Inherit => meta.df,
                };
                let proto = match meta.version {
                    IpVersion::V4 => ETHERTYPE_IPV4,
                    IpVersion::V6 => ETHERTYPE_IPV6,
                };
                tun_read_buf[0] = 0;
                tun_read_buf[1] = 0;
                tun_read_buf[2..4].copy_from_slice(&proto.to_be_bytes());
                sink.push_ready_slice(&tun_read_buf[..pkt_end]);
            }
        }

        sink.flush_all();
    }
}

fn refresh_tunnel_arp(tunnel: &mut ManagedTunnel, now: Instant, immediate_on_neigh_event: bool) {
    if !tunnel.cfg.allow_fast_path || tunnel.shared.src_mac.load(Ordering::Acquire) == 0 {
        tunnel.next_arp_check = None;
        return;
    }
    let next_hop = tunnel.gateway.unwrap_or_else(|| tunnel.remote_ip());
    if next_hop == tunnel.local_ip() {
        tunnel.next_arp_check = None;
        return;
    }
    if let Some(mac) = lookup_arp_mac(next_hop, &tunnel.out_ifname) {
        tunnel
            .shared
            .next_hop_mac
            .store(encode_mac(mac), Ordering::Release);
        tunnel.next_arp_check = now.checked_add(ARP_REFRESH_INTERVAL);
        if !tunnel.arp_logged_fastpath {
            tunnel.arp_logged_fastpath = true;
            eprintln!(
                "[info] [{}] enabled AF_PACKET PACKET_TX_RING fast-path (dev={}, next_hop={}, mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                tunnel.cfg.name, tunnel.out_ifname, next_hop, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );
        }
    } else {
        if immediate_on_neigh_event {
            tunnel.shared.next_hop_mac.store(0, Ordering::Release);
        }
        trigger_arp_probe(next_hop);
        tunnel.next_arp_check = now.checked_add(ARP_RETRY_INTERVAL);
    }
}

fn process_control_tick(
    tunnels: &mut [ManagedTunnel],
    tx_mode: TxMode,
    wake_evt: &Arc<EventFd>,
    bypass_registry: &Arc<BypassRegistry>,
    neigh_event: bool,
    now: Instant,
) -> bool {
    let mut changed = false;
    let all_tun_ifs: Vec<u32> = tunnels.iter().map(|t| t.shared.tun.ifindex()).collect();
    let all_routes: Vec<RouteSpec> = tunnels
        .iter()
        .flat_map(|t| t.cfg.routes.iter().cloned())
        .collect();

    for tunnel in tunnels {
        let cur_replies = tunnel.shared.ka_replies_rx.load(Ordering::Acquire);
        if cur_replies > tunnel.last_ka_replies_seen {
            let delta = cur_replies - tunnel.last_ka_replies_seen;
            tunnel.last_ka_replies_seen = cur_replies;
            for _ in 0..delta.min(4) {
                if let Some(true) = tunnel.keepalive.on_reply() {
                    tunnel.shared.carrier_up.store(true, Ordering::Release);
                    let _ = tunnel.shared.tun.set_carrier(true);
                    changed = true;
                    eprintln!(
                        "[info] [{}] keepalive UP (carrier ON, peer={})",
                        tunnel.cfg.name,
                        tunnel.remote_ip()
                    );
                }
            }
        }

        let cur_learned = tunnel.shared.learned_public_ip.load(Ordering::Relaxed);
        if cur_learned != 0 && cur_learned != tunnel.last_learned_public {
            tunnel.last_learned_public = cur_learned;
            eprintln!(
                "[info] [{}] learned NAT public IP {} from peer keepalive",
                tunnel.cfg.name,
                Ipv4Addr::from(cur_learned)
            );
            if !tunnel.keepalive.is_carrier_up() {
                tunnel.keepalive.schedule_immediate_probe(now);
            }
            changed = true;
        }

        // Harvest completed asynchronous DDNS resolution result (never blocks control loop)
        let resolved_dns = tunnel
            .dns_result
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(res) = resolved_dns {
            tunnel.dns_inflight = false;
            let old_ip = tunnel.remote_ip();
            match res {
                Ok(new_ip) if new_ip != old_ip => {
                    match probe_route_excluding(new_ip, tunnel.cfg.local_address, &all_tun_ifs) {
                        Ok(probe) => {
                            let mut new_bypass: Option<BypassRouteGuard> = None;
                            let needs_bypass =
                                all_routes.iter().any(|r| r.dst.contains_v4(new_ip));
                            let mut bypass_ok = true;
                            if needs_bypass && probe.out_ifindex > 0 {
                                match bypass_registry.acquire(
                                    new_ip,
                                    probe.out_ifindex,
                                    probe.gateway,
                                ) {
                                    Ok(Some(guard)) => {
                                        new_bypass = Some(guard);
                                    }
                                    Ok(None) => {}
                                    Err(e) => {
                                        bypass_ok = false;
                                        eprintln!(
                                            "[warn] [{}] failed to install new bypass route for {}: {e}",
                                            tunnel.cfg.name, new_ip
                                        );
                                    }
                                }
                            }

                            if bypass_ok {
                                let new_src_mac = if tx_mode != TxMode::Raw
                                    && tunnel.cfg.allow_fast_path
                                    && probe.out_ifindex > 0
                                {
                                    get_interface_hwaddr(&probe.out_ifname)
                                        .ok()
                                        .map(encode_mac)
                                        .unwrap_or(0)
                                } else {
                                    0
                                };
                                tunnel
                                    .shared
                                    .remote_ip
                                    .store(u32::from(new_ip), Ordering::Release);
                                tunnel
                                    .shared
                                    .local_ip
                                    .store(u32::from(probe.local_ip), Ordering::Release);
                                tunnel
                                    .shared
                                    .out_ifindex
                                    .store(probe.out_ifindex, Ordering::Release);
                                tunnel
                                    .shared
                                    .out_mtu
                                    .store(probe.out_mtu as u32, Ordering::Release);
                                tunnel
                                    .shared
                                    .src_mac
                                    .store(new_src_mac, Ordering::Release);
                                tunnel.shared.next_hop_mac.store(0, Ordering::Release);
                                tunnel.out_ifname = probe.out_ifname;
                                tunnel.gateway = probe.gateway;
                                // Drop old bypass route only AFTER new bypass route and new peer state are live
                                tunnel.bypass_route = new_bypass;
                                tunnel.next_arp_check = Some(now);
                                tunnel.keepalive.schedule_immediate_probe(now);
                                changed = true;
                                eprintln!(
                                    "[info] [{}] DNS updated remote '{}' {} -> {} (dev={})",
                                    tunnel.cfg.name,
                                    tunnel.cfg.remote.as_display(),
                                    old_ip,
                                    new_ip,
                                    tunnel.out_ifname
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[warn] [{}] DNS resolved '{}' -> {}, but physical route lookup failed: {e}",
                                tunnel.cfg.name,
                                tunnel.cfg.remote.as_display(),
                                new_ip
                            );
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "[warn] [{}] DNS refresh for '{}' failed: {e}",
                        tunnel.cfg.name,
                        tunnel.cfg.remote.as_display()
                    );
                }
            }
        }

        if let Some(due_dns) = tunnel.next_dns_check {
            if now >= due_dns && !tunnel.dns_inflight {
                tunnel.next_dns_check = now.checked_add(tunnel.cfg.dns_refresh);
                tunnel.dns_inflight = true;
                let endpoint = tunnel.cfg.remote.clone();
                let slot = Arc::clone(&tunnel.dns_result);
                let wake = Arc::clone(wake_evt);
                if thread::Builder::new()
                    .name("gre-dns".into())
                    .spawn(move || {
                        let r = endpoint.resolve_ipv4();
                        if let Ok(mut guard) = slot.lock() {
                            *guard = Some(r);
                        }
                        wake.notify();
                    })
                    .is_err()
                {
                    tunnel.dns_inflight = false;
                }
            }
        }

        if tx_mode != TxMode::Raw && tunnel.cfg.allow_fast_path {
            if neigh_event {
                refresh_tunnel_arp(tunnel, now, true);
            } else if let Some(due_arp) = tunnel.next_arp_check {
                if now >= due_arp {
                    refresh_tunnel_arp(tunnel, now, false);
                }
            }
        }

        let ka_poll = tunnel.keepalive.poll(now);
        if ka_poll.state_changed {
            changed = true;
        }
        if let Some(false) = ka_poll.carrier_change {
            tunnel.shared.carrier_up.store(false, Ordering::Release);
            let _ = tunnel.shared.tun.set_carrier(false);
            changed = true;
            eprintln!(
                "[warn] [{}] keepalive DOWN after {} missed probes (carrier OFF, peer={})",
                tunnel.cfg.name,
                tunnel.keepalive.misses(),
                tunnel.remote_ip()
            );
        }
        if ka_poll.should_send {
            let (seq, tok) = tunnel.keepalive.next_probe_ids();
            let remote_ip = tunnel.remote_ip();
            tunnel.shared.record_expected_ka(seq, tok);
            let probe_pkt =
                build_keepalive_request_with_token(remote_ip, tunnel.effective_reply_dst_ip(), seq, tok);
            let _ = tunnel.ka_tx_sock.send_to(remote_ip, 0, false, &probe_pkt);
        }
    }
    changed
}

fn next_timeout_ms(tunnels: &[ManagedTunnel], last_status_flush: Instant, now: Instant) -> i32 {
    let mut earliest = last_status_flush
        .checked_add(STATUS_FLUSH_INTERVAL)
        .unwrap_or(now);
    for t in tunnels {
        if let Some(due) = t.keepalive.next_probe_at() {
            if due < earliest {
                earliest = due;
            }
        }
        if let Some(due) = t.next_dns_check {
            if due < earliest {
                earliest = due;
            }
        }
        if let Some(due) = t.next_arp_check {
            if due < earliest {
                earliest = due;
            }
        }
    }
    let wait_ms = earliest
        .saturating_duration_since(now)
        .as_millis()
        .clamp(10, 500);
    wait_ms as i32
}

fn flush_status(path: &str, pid: u32, workers_ok: bool, tunnels: &[ManagedTunnel]) {
    let snaps: Vec<TunnelStatusSnapshot> = tunnels.iter().map(|t| t.snapshot()).collect();
    if let Err(e) = write_status_file(path, pid, workers_ok, &snaps) {
        eprintln!("[warn] {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_pack_roundtrip() {
        assert_eq!(decode_mac(0), None);
        let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let packed = encode_mac(mac);
        assert_eq!(decode_mac(packed), Some(mac));
    }

    #[test]
    fn test_ka_reply_verification_and_nat_ip_two_hit_guard() {
        let now = Instant::now();
        let shared = TunnelShared {
            name: "gre-test".into(),
            epoch: now,
            local_bind: None,
            public_ip_override: None,
            dscp_mode: DscpMode::Inherit,
            df_mode: DontFragmentMode::No,
            clamp_tcp_mss: true,
            allow_fast_path: true,
            actual_mtu: 1476,
            out_mtu: AtomicU32::new(1500),
            out_ifindex: AtomicU32::new(2),
            src_mac: AtomicU64::new(0),
            local_ip: AtomicU32::new(u32::from(Ipv4Addr::new(10, 0, 0, 2))),
            remote_ip: AtomicU32::new(u32::from(Ipv4Addr::new(203, 0, 113, 1))),
            learned_public_ip: AtomicU32::new(0),
            nat_candidate_ip: AtomicU32::new(0),
            nat_candidate_hits: AtomicU32::new(0),
            next_hop_mac: AtomicU64::new(0),
            next_ip_id: AtomicU32::new(1),
            carrier_up: AtomicBool::new(false),
            ka_awaiting: AtomicBool::new(false),
            ka_ring_cursor: AtomicU32::new(0),
            ka_expected_tokens: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            ka_expected_seqs: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_drops: AtomicU64::new(0),
            rx_drops: AtomicU64::new(0),
            rx_trunc: AtomicU64::new(0),
            ka_replies_rx: AtomicU64::new(0),
            ka_requests_ans: AtomicU64::new(0),
            ka_spoof_drops: AtomicU64::new(0),
            emsgsize_warned: AtomicBool::new(false),
            tun: TunDevice::dummy_for_test(),
        };

        // Unsolicited reply before probe must fail on real TunnelShared::verify_ka_reply
        assert!(!shared.verify_ka_reply(Some([0xa1, 0xb2, 0xc3, 0xd4]), 4, 7));

        shared.record_expected_ka(7, 0xa1b2_c3d4);

        // Forged zero-padded 8B reply or wrong token must be rejected and leave awaiting=true
        assert!(!shared.verify_ka_reply(Some([0, 0, 0, 0]), 4, 7));
        assert!(!shared.verify_ka_reply(Some([1, 2, 3, 4]), 4, 7));
        assert!(shared.ka_awaiting.load(Ordering::Acquire));

        // Valid echoed token succeeds once, and replay is rejected
        assert!(shared.verify_ka_reply(Some([0xa1, 0xb2, 0xc3, 0xd4]), 4, 99));
        assert!(!shared.verify_ka_reply(Some([0xa1, 0xb2, 0xc3, 0xd4]), 4, 99));

        // Real TunnelShared::observe_peer_reported_ip two-hit confirmation & non-unicast filter
        assert!(!shared.observe_peer_reported_ip(Ipv4Addr::UNSPECIFIED));
        assert!(!shared.observe_peer_reported_ip(Ipv4Addr::LOCALHOST));
        assert!(!shared.observe_peer_reported_ip(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!shared.observe_peer_reported_ip(Ipv4Addr::new(10, 0, 0, 2))); // equals local_ip
        assert!(!shared.observe_peer_reported_ip(Ipv4Addr::new(203, 0, 113, 1))); // equals remote_ip

        let nat_a = Ipv4Addr::new(198, 51, 100, 9);
        let nat_b = Ipv4Addr::new(198, 51, 100, 10);
        assert!(!shared.observe_peer_reported_ip(nat_a)); // 1st hit: not yet accepted
        assert_eq!(shared.learned_public_ip.load(Ordering::Acquire), 0);
        assert!(!shared.observe_peer_reported_ip(nat_b)); // different IP resets streak
        assert!(shared.observe_peer_reported_ip(nat_b)); // 2nd consecutive hit: accepted!
        assert_eq!(
            Ipv4Addr::from(shared.learned_public_ip.load(Ordering::Acquire)),
            nat_b
        );
        assert!(!shared.observe_peer_reported_ip(nat_b)); // already learned, no duplicate wake

        // Monotonic WorkerHealth watchdog check
        let wh = WorkerHealth::new("tx-test".into(), now);
        assert!(find_unhealthy_worker(std::slice::from_ref(&wh), 5_000).is_none());
        assert_eq!(
            find_unhealthy_worker(std::slice::from_ref(&wh), 20_000).as_deref(),
            Some("tx-test")
        );
    }

    #[test]
    fn test_bypass_registry_dst_key_refcount_and_conflict_rejection() {
        let reg = BypassRegistry::new(19801);
        let dst = Ipv4Addr::new(203, 0, 113, 50);
        let mut os_install_calls = 0usize;

        let mut g1 = reg
            .acquire_with(dst, 2, Some(Ipv4Addr::new(192, 0, 2, 1)), |_, _, _, m| {
                assert_eq!(m, 19801);
                os_install_calls += 1;
                Ok(true)
            })
            .unwrap()
            .unwrap();
        g1.suppress_os_delete = true;
        assert_eq!(os_install_calls, 1);

        // Identical (dst, ifindex, gateway) increments refcount without reinstalling
        let mut g2 = reg
            .acquire_with(dst, 2, Some(Ipv4Addr::new(192, 0, 2, 1)), |_, _, _, _| {
                panic!("must not reinstall when refcount >= 1");
            })
            .unwrap()
            .unwrap();
        g2.suppress_os_delete = true;

        // Different egress ifindex or gateway for the SAME dst_ip in the same process must fail
        let conflict_if = reg.acquire_with(dst, 3, Some(Ipv4Addr::new(192, 0, 2, 1)), |_, _, _, _| {
            Ok(true)
        });
        assert!(conflict_if.is_err());

        let conflict_gw = reg.acquire_with(dst, 2, Some(Ipv4Addr::new(192, 0, 2, 9)), |_, _, _, _| {
            Ok(true)
        });
        assert!(conflict_gw.is_err());

        // Dropping g2 leaves g1's refcount == 1 intact in registry
        drop(g2);
        assert_eq!(reg.refs.lock().unwrap().get(&dst).unwrap().refcount, 1);

        // Dropping g1 brings refcount to 0 and removes entry
        drop(g1);
        assert!(reg.refs.lock().unwrap().is_empty());
    }
}
