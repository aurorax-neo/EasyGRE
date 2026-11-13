use std::net::Ipv4Addr;

use crate::config::RouteSpec;
use crate::packet::IpCidr;
use crate::sys::RouteProbeResult;

pub struct TunDevice;
pub struct RawGreSocket;
pub struct Epoll;
pub struct EventFd;
pub struct PacketTxRing;
pub struct TunUringReader;
pub struct RxBatchBuffer;
pub struct NeighWatchSocket;
pub struct InstanceLease;

impl InstanceLease {
    pub fn acquire() -> Result<Self, String> {
        Ok(Self)
    }
    pub fn bypass_metric(&self) -> u32 {
        19801
    }
}

impl Drop for InstanceLease {
    fn drop(&mut self) {}
}

#[derive(Debug, Clone, Copy)]
pub struct SendBatchOutcome {
    pub sent: usize,
    pub dropped: usize,
    pub emsgsize_mask: u64,
}

#[derive(Debug, Clone)]
pub struct InstalledRoute;

pub const BATCH_CAP: usize = 64;
pub const BATCH_SLOT_SIZE: usize = 65664;
pub const URING_BATCH: usize = 64;
pub const TSO_OVERFLOW_SIZE: usize = 65600;

impl RxBatchBuffer {
    pub fn new(_min_slot_size: usize) -> Self {
        Self
    }
    pub fn pkt_mut(&mut self, _idx: usize) -> &mut [u8] {
        &mut []
    }
    pub fn is_truncated(&self, _idx: usize) -> bool {
        false
    }
    pub fn slot_cap(&self) -> usize {
        BATCH_SLOT_SIZE
    }
}

impl NeighWatchSocket {
    pub fn open() -> Result<Self, String> {
        Err("unsupported OS".into())
    }
    pub fn raw_fd(&self) -> i32 {
        -1
    }
    pub fn drain(&self) -> bool {
        false
    }
}

impl TunDevice {
    #[cfg(test)]
    pub fn dummy_for_test() -> Self {
        Self
    }

    pub fn create_multi(
        _name: &str,
        _mtu: u16,
        _initial_carrier: bool,
        _requested_queues: usize,
    ) -> Result<Self, String> {
        Err("EasyGRE requires Linux (/dev/net/tun and AF_NETLINK are only supported on Linux)".into())
    }
    pub fn ifindex(&self) -> u32 {
        0
    }
    pub fn queue_count(&self) -> usize {
        0
    }
    pub fn queue_fd(&self, _idx: usize) -> i32 {
        -1
    }
    pub fn has_vnet_hdr(&self) -> bool {
        false
    }
    pub fn has_udp_gso(&self) -> bool {
        false
    }
    pub fn is_multi_queue(&self) -> bool {
        false
    }
    pub fn set_carrier(&self, _up: bool) -> Result<(), String> {
        Err("unsupported OS".into())
    }
    pub fn read_queue_nonblock(&self, _q_idx: usize, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    pub fn readv_queue_nonblock(
        &self,
        _q_idx: usize,
        _head: &mut [u8],
        _tail: &mut [u8],
    ) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    pub fn write_queue_nonblock(&self, _q_idx: usize, _buf: &[u8]) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

impl EventFd {
    pub fn new() -> Result<Self, String> {
        Err("unsupported OS".into())
    }
    pub fn raw_fd(&self) -> i32 {
        -1
    }
    pub fn notify(&self) {}
    pub fn drain(&self) {}
}

impl PacketTxRing {
    pub fn open(_out_ifindex: u32, _max_frame_len: usize) -> Result<Self, String> {
        Err("unsupported OS".into())
    }
    pub fn max_frame_len(&self) -> usize {
        0
    }
    pub fn ensure_slot_ready(&mut self, _frame_len: usize) -> bool {
        false
    }
    pub fn available_run(&mut self, _max_slots: usize, _min_frame_cap: usize) -> usize {
        0
    }
    pub fn slot_frame_ptr(&mut self, _offset_from_cursor: usize) -> *mut u8 {
        std::ptr::null_mut()
    }
    pub fn cur_frame_mut(&mut self, _frame_len: usize) -> &mut [u8] {
        &mut []
    }
    pub fn commit_frame(&mut self, _frame_len: usize) {}
    pub fn kick(&mut self) {}
}

impl TunUringReader {
    pub fn open(_tun_fd: i32) -> Result<Self, String> {
        Err("unsupported OS".into())
    }
    pub unsafe fn readv_into_frames(
        &mut self,
        _frame_ptrs: &[*mut u8],
        _head_off: usize,
        _head_len: usize,
        _overflow_bufs: &mut [[u8; TSO_OVERFLOW_SIZE]],
        _results_out: &mut [i32; URING_BATCH],
    ) -> Result<bool, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

pub fn get_interface_hwaddr(_ifname: &str) -> Result<[u8; 6], String> {
    Err("unsupported OS".into())
}
pub fn lookup_arp_mac(_ip: Ipv4Addr, _ifname: &str) -> Option<[u8; 6]> {
    None
}
pub fn trigger_arp_probe(_ip: Ipv4Addr) {}

impl RawGreSocket {
    pub fn open_rx() -> Result<Self, String> {
        Err("EasyGRE requires Linux (AF_INET/SOCK_RAW IPPROTO_GRE is only supported on Linux)".into())
    }
    pub fn open_tx(_local_bind: Option<Ipv4Addr>) -> Result<Self, String> {
        Err("EasyGRE requires Linux".into())
    }
    pub fn raw_fd(&self) -> i32 {
        -1
    }
    pub fn recv_batch(&self, _batch: &mut RxBatchBuffer) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    pub fn send_to(
        &mut self,
        _dst: Ipv4Addr,
        _dscp: u8,
        _dont_fragment: bool,
        _payload: &[u8],
    ) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    pub fn send_batch(
        &mut self,
        _dst: Ipv4Addr,
        _dscp: u8,
        _dont_fragment: bool,
        _ip_packets_with_hdr: &[&[u8]],
        _packets: &[&[u8]],
    ) -> SendBatchOutcome {
        SendBatchOutcome {
            sent: 0,
            dropped: _packets.len(),
            emsgsize_mask: 0,
        }
    }
}

impl Epoll {
    pub fn new() -> Result<Self, String> {
        Err("unsupported OS".into())
    }
    pub fn add(&self, _fd: i32, _token: u64) -> Result<(), String> {
        Err("unsupported OS".into())
    }
    pub fn wait(&self, _events: &mut [u64], _timeout_ms: i32) -> Result<usize, std::io::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

pub fn install_signal_handlers() {}
pub fn shutdown_requested() -> bool {
    false
}
pub fn is_pid_alive(_pid: u32) -> bool {
    false
}
pub fn monotonic_now_secs() -> Option<u64> {
    None
}
pub fn cleanup_stale_easygre_routes(_lease: &InstanceLease, _legacy_status_orphan: bool) {}
pub fn probe_route_excluding(
    _remote: Ipv4Addr,
    _local_override: Option<Ipv4Addr>,
    _excluded_ifindices: &[u32],
) -> Result<RouteProbeResult, String> {
    Err("unsupported OS".into())
}
pub fn configure_interface_addr(_ifindex: u32, _cidr: &IpCidr) -> Result<(), String> {
    Err("unsupported OS".into())
}
pub fn configure_route(_ifindex: u32, _route: &RouteSpec) -> Result<Vec<InstalledRoute>, String> {
    Err("unsupported OS".into())
}
pub fn remove_installed_route(_route: &InstalledRoute) {}
pub fn install_host_bypass_route(
    _dst_ip: Ipv4Addr,
    _out_ifindex: u32,
    _gateway: Option<Ipv4Addr>,
    _metric: u32,
) -> Result<bool, String> {
    Err("unsupported OS".into())
}
pub fn remove_host_bypass_route(
    _dst_ip: Ipv4Addr,
    _out_ifindex: u32,
    _gateway: Option<Ipv4Addr>,
    _metric: u32,
) {
}
pub fn detect_system_warnings(_routes_configured: bool, _fast_path_enabled: bool) -> Vec<String> {
    Vec::new()
}
