use std::net::Ipv4Addr;

use crate::config::RouteSpec;
use crate::packet::IpCidr;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(not(target_os = "linux"))]
mod stub;
#[cfg(not(target_os = "linux"))]
use stub as imp;

pub use imp::{
    cleanup_stale_easygre_routes, get_interface_hwaddr, install_host_bypass_route, is_pid_alive,
    lookup_arp_mac, monotonic_now_secs, probe_route_excluding, remove_host_bypass_route,
    remove_installed_route, trigger_arp_probe, Epoll, EventFd, InstalledRoute, InstanceLease,
    NeighWatchSocket, PacketTxRing, RawGreSocket, RxBatchBuffer, TunDevice, TunUringReader,
    BATCH_CAP,
    BATCH_SLOT_SIZE, TSO_OVERFLOW_SIZE, URING_BATCH,
};

#[derive(Debug, Clone)]
pub struct RouteProbeResult {
    pub local_ip: Ipv4Addr,
    pub out_ifindex: u32,
    pub out_ifname: String,
    pub out_mtu: u16,
    pub gateway: Option<Ipv4Addr>,
}

pub fn install_signal_handlers() {
    imp::install_signal_handlers();
}

pub fn shutdown_requested() -> bool {
    imp::shutdown_requested()
}

pub fn configure_interface_addr(ifindex: u32, cidr: &IpCidr) -> Result<(), String> {
    imp::configure_interface_addr(ifindex, cidr)
}

pub fn configure_route(ifindex: u32, route: &RouteSpec) -> Result<Vec<InstalledRoute>, String> {
    imp::configure_route(ifindex, route)
}

pub fn detect_system_warnings(routes_configured: bool, fast_path_enabled: bool) -> Vec<String> {
    imp::detect_system_warnings(routes_configured, fast_path_enabled)
}
