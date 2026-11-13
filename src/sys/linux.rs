use std::ffi::{c_char, c_int, c_long, c_uint, c_void};
#[cfg(not(target_env = "musl"))]
use std::ffi::c_ulong;
use std::fs::{self, File, OpenOptions};
use std::io::Error as IoError;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::config::{RouteGateway, RouteSpec};
use crate::packet::IpCidr;
use crate::sys::RouteProbeResult;

const AF_UNIX: c_int = 1;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const AF_NETLINK: c_int = 16;
const AF_PACKET: c_int = 17;

const SOCK_DGRAM: c_int = 2;
const SOCK_RAW: c_int = 3;
const SOCK_NONBLOCK: c_int = 0x800;
const SOCK_CLOEXEC: c_int = 0x80000;

const IPPROTO_GRE: c_int = 47;
const IPPROTO_RAW: c_int = 255;
const NETLINK_ROUTE: c_int = 0;

const SOL_SOCKET: c_int = 1;
const SO_SNDBUF: c_int = 7;
const SO_RCVBUF: c_int = 8;
const SO_RCVTIMEO: c_int = 20;
const SO_BINDTODEVICE: c_int = 25;
const SO_ATTACH_FILTER: c_int = 26;
const SO_SNDBUFFORCE: c_int = 32;
const SO_RCVBUFFORCE: c_int = 33;
const SOL_PACKET: c_int = 263;
const PACKET_VERSION: c_int = 10;
const PACKET_TX_RING: c_int = 13;
const PACKET_LOSS: c_int = 14;
const PACKET_QDISC_BYPASS: c_int = 20;
const TPACKET_V2: c_int = 1;
const TP_STATUS_AVAILABLE: u32 = 0;
const TP_STATUS_SEND_REQUEST: u32 = 1;
const TPACKET2_TX_DATA_OFF: usize = 32;
const ETH_P_IP: u16 = 0x0800;
const ARPHRD_ETHER: i16 = 1;

const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_SHARED: c_int = 0x01;
const EFD_NONBLOCK: c_int = 0x800;
const EFD_CLOEXEC: c_int = 0x80000;

const SOL_IP: c_int = 0;
const IP_TOS: c_int = 1;
const IP_MTU_DISCOVER: c_int = 10;
const IP_PMTUDISC_DONT: c_int = 0;
const IP_PMTUDISC_DO: c_int = 2;

const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0x800;

const IFF_UP: i16 = 0x0001;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_CARRIER: i16 = 0x0040;
const IFF_MULTI_QUEUE: i16 = 0x0100;
const IFF_NO_PI: i16 = 0x1000;
const IFF_VNET_HDR: i16 = 0x4000;

const TUNSETIFF: u32 = 0x4004_54ca;
const TUNSETOFFLOAD: u32 = 0x4004_54d0;
const TUNSETCARRIER: u32 = 0x4004_54e2;

const TUN_F_CSUM: usize = 0x01;
const TUN_F_TSO4: usize = 0x02;
const TUN_F_TSO6: usize = 0x04;
const TUN_F_TSO_ECN: usize = 0x08;
const TUN_F_USO4: usize = 0x20;
const TUN_F_USO6: usize = 0x40;

const SIOCGIFFLAGS: u32 = 0x8913;
const SIOCSIFFLAGS: u32 = 0x8914;
const SIOCGIFMTU: u32 = 0x8921;
const SIOCSIFMTU: u32 = 0x8922;
const SIOCGIFHWADDR: u32 = 0x8927;
const SIOCGIFINDEX: u32 = 0x8933;
const SIOCSIFTXQLEN: u32 = 0x8943;

const MSG_TRUNC: c_int = 0x20;
const MSG_DONTWAIT: c_int = 0x40;

pub const BATCH_CAP: usize = 64;
pub const RX_BATCH_CAP: usize = 128;
pub const BATCH_SLOT_SIZE: usize = 65664;
pub const URING_BATCH: usize = 64;
pub const TSO_OVERFLOW_SIZE: usize = 65600;

#[cfg(target_arch = "x86_64")]
const SYS_SENDMMSG: c_long = 307;
#[cfg(target_arch = "aarch64")]
const SYS_SENDMMSG: c_long = 269;

const SYS_IO_URING_SETUP: c_long = 425;
const SYS_IO_URING_ENTER: c_long = 426;

const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_CQ_RING: i64 = 0x0800_0000;
const IORING_OFF_SQES: i64 = 0x1000_0000;
const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
const IORING_OP_READV: u8 = 1;
const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
const RWF_NOWAIT: u32 = 0x0000_0008;

const EPOLL_CTL_ADD: c_int = 1;
const EPOLLIN: u32 = 0x001;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_REPLACE: u16 = 0x0100;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_DUMP: u16 = 0x0300;
const NLM_F_CREATE: u16 = 0x0400;

const RTMGRP_NEIGH: u32 = 4;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;

const RTNH_F_DEAD: u8 = 1;
const RTNH_F_LINKDOWN: u8 = 16;

const RT_TABLE_MAIN: u8 = 254;
const RTPROT_EASYGRE: u8 = 198;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;
const RTN_UNICAST: u8 = 1;

const CLOCK_MONOTONIC: c_int = 1;
const BYPASS_METRIC_BASE: u32 = 19800;
const MAX_INSTANCE_SLOTS: u32 = 256;

const ESRCH: i32 = 3;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const EMSGSIZE: i32 = 90;
const EOPNOTSUPP: i32 = 95;
const EADDRINUSE: i32 = 98;

#[derive(Debug, Clone, Copy)]
pub struct SendBatchOutcome {
    pub sent: usize,
    pub dropped: usize,
    pub emsgsize_mask: u64,
}

#[derive(Debug, Clone)]
pub struct InstalledRoute {
    pub dst: IpCidr,
    pub gateway: RouteGateway,
    pub ifindex: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    rw_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    pad2: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TpacketReq {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Tpacket2Hdr {
    tp_status: u32,
    tp_len: u32,
    tp_snaplen: u32,
    tp_mac: u16,
    tp_net: u16,
    tp_sec: u32,
    tp_nsec: u32,
    tp_vlan_tci: u16,
    tp_vlan_tpid: u16,
    tp_padding: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IoVec {
    iov_base: *mut c_void,
    iov_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MsgHdr {
    msg_name: *mut c_void,
    msg_namelen: c_uint,
    _pad0: u32,
    msg_iov: *mut IoVec,
    msg_iovlen: usize,
    msg_control: *mut c_void,
    msg_controllen: usize,
    msg_flags: c_int,
    _pad1: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MMsgHdr {
    msg_hdr: MsgHdr,
    msg_len: c_uint,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfReq {
    name: [u8; 16],
    data: [u8; 24],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    _pad: [u8; 6],
    filter: *const SockFilter,
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[cfg(not(target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[cfg(test)]
#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
    msg: NlMsgHdr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtNexthop {
    rtnh_len: u16,
    rtnh_flags: u8,
    rtnh_hops: u8,
    rtnh_ifindex: i32,
}

extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, addr: *const c_void, len: c_uint) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: c_uint) -> c_int;
    fn getsockname(fd: c_int, addr: *mut c_void, len: *mut c_uint) -> c_int;
    fn setsockopt(
        fd: c_int,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: c_uint,
    ) -> c_int;
    fn sendto(
        fd: c_int,
        buf: *const c_void,
        len: usize,
        flags: c_int,
        dest_addr: *const c_void,
        addrlen: c_uint,
    ) -> isize;
    fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
    fn syscall(num: c_long, ...) -> c_long;
    fn recvmmsg(
        fd: c_int,
        msgvec: *mut MMsgHdr,
        vlen: c_uint,
        flags: c_int,
        timeout: *mut c_void,
    ) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn readv(fd: c_int, iov: *const IoVec, iovcnt: c_int) -> isize;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, events: *mut EpollEvent, maxevents: c_int, timeout: c_int) -> c_int;
    fn eventfd(initval: c_uint, flags: c_int) -> c_int;
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, length: usize) -> c_int;
    fn signal(sig: c_int, handler: usize) -> usize;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn clock_gettime(clk_id: c_int, tp: *mut TimeSpec) -> c_int;
    fn if_indextoname(ifindex: c_uint, ifname: *mut c_char) -> *mut c_char;
    #[cfg(target_env = "musl")]
    fn ioctl(fd: c_int, request: c_int, ...) -> c_int;
    #[cfg(not(target_env = "musl"))]
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
}

#[inline]
unsafe fn call_ioctl_ptr(fd: c_int, req: u32, ptr: *mut c_void) -> c_int {
    #[cfg(target_env = "musl")]
    {
        ioctl(fd, req as c_int, ptr)
    }
    #[cfg(not(target_env = "musl"))]
    {
        ioctl(fd, req as c_ulong, ptr)
    }
}

#[inline]
unsafe fn call_ioctl_val(fd: c_int, req: u32, val: usize) -> c_int {
    #[cfg(target_env = "musl")]
    {
        ioctl(fd, req as c_int, val as c_int)
    }
    #[cfg(not(target_env = "musl"))]
    {
        ioctl(fd, req as c_ulong, val as c_ulong)
    }
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
}

pub fn install_signal_handlers() {
    unsafe {
        signal(SIGINT, handle_signal as *const () as usize);
        signal(SIGTERM, handle_signal as *const () as usize);
    }
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

pub fn is_pid_alive(pid: u32) -> bool {
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    let rc = unsafe { kill(pid as c_int, 0) };
    if rc == 0 {
        return true;
    }
    IoError::last_os_error().raw_os_error() != Some(ESRCH)
}

pub fn monotonic_now_secs() -> Option<u64> {
    let mut ts = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
    if rc == 0 && ts.tv_sec >= 0 {
        Some(ts.tv_sec as u64)
    } else {
        None
    }
}

fn bind_abstract_slot(slot: u32) -> Result<OwnedFd, i32> {
    let raw = unsafe { socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(IoError::last_os_error().raw_os_error().unwrap_or(EINVAL));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let label = format!("easygre/slot/v1/{slot}");
    let mut addr = SockAddrUn {
        sun_family: AF_UNIX as u16,
        sun_path: [0u8; 108],
    };
    // Abstract socket namespace: sun_path[0] = 0, scoped to Linux network namespace (`struct net`)
    addr.sun_path[1..1 + label.len()].copy_from_slice(label.as_bytes());
    let addrlen = (2 + 1 + label.len()) as c_uint;
    let rc = unsafe { bind(fd.as_raw_fd(), (&addr as *const SockAddrUn).cast(), addrlen) };
    if rc < 0 {
        return Err(IoError::last_os_error().raw_os_error().unwrap_or(EINVAL));
    }
    Ok(fd)
}

fn is_instance_slot_free(slot: u32) -> bool {
    match bind_abstract_slot(slot) {
        Ok(_probe_fd) => true,
        Err(errno) if errno == EADDRINUSE => false,
        Err(_) => false,
    }
}

/// Netns-scoped live instance lease backed by an abstract `AF_UNIX` socket.
/// Automatically released by the kernel even on `SIGKILL` / OOM kill, and visible across
/// containers sharing `network_mode: host` regardless of filesystem or PID namespace isolation.
pub struct InstanceLease {
    _fd: OwnedFd,
    slot: u32,
}

impl InstanceLease {
    pub fn acquire() -> Result<Self, String> {
        for slot in 1..=MAX_INSTANCE_SLOTS {
            match bind_abstract_slot(slot) {
                Ok(fd) => return Ok(Self { _fd: fd, slot }),
                Err(errno) if errno == EADDRINUSE => continue,
                Err(errno) => {
                    return Err(format!(
                        "failed to bind netns instance slot socket: errno={errno} ({})",
                        IoError::from_raw_os_error(errno)
                    ));
                }
            }
        }
        Err("exceeded 256 concurrent EasyGRE instances in the same network namespace".into())
    }

    pub fn bypass_metric(&self) -> u32 {
        BYPASS_METRIC_BASE + self.slot
    }
}

fn set_nonblocking(fd: RawFd) -> Result<(), String> {
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags < 0 {
            return Err(format!("fcntl(F_GETFL) failed: {}", IoError::last_os_error()));
        }
        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(format!("fcntl(F_SETFL) failed: {}", IoError::last_os_error()));
        }
    }
    Ok(())
}

fn make_ifreq(name: &str) -> Result<IfReq, String> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 15 {
        return Err(format!("invalid interface name '{name}'"));
    }
    let mut ifr = IfReq {
        name: [0u8; 16],
        data: [0u8; 24],
    };
    ifr.name[..bytes.len()].copy_from_slice(bytes);
    Ok(ifr)
}

fn open_ioctl_dgram_sock() -> Result<OwnedFd, String> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!("socket(AF_INET, SOCK_DGRAM) failed: {}", IoError::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn get_interface_mtu(ifname: &str) -> Result<u16, String> {
    let sock = open_ioctl_dgram_sock()?;
    let mut ifr = make_ifreq(ifname)?;
    let rc = unsafe { call_ioctl_ptr(sock.as_raw_fd(), SIOCGIFMTU, (&mut ifr as *mut IfReq).cast()) };
    if rc < 0 {
        return Err(format!("SIOCGIFMTU('{ifname}') failed: {}", IoError::last_os_error()));
    }
    let mtu = i32::from_ne_bytes([ifr.data[0], ifr.data[1], ifr.data[2], ifr.data[3]]);
    if mtu <= 0 || mtu > u16::MAX as i32 {
        return Err(format!("invalid interface MTU {mtu} for '{ifname}'"));
    }
    Ok(mtu as u16)
}

fn get_interface_index(ifname: &str) -> Result<u32, String> {
    let sock = open_ioctl_dgram_sock()?;
    let mut ifr = make_ifreq(ifname)?;
    let rc = unsafe { call_ioctl_ptr(sock.as_raw_fd(), SIOCGIFINDEX, (&mut ifr as *mut IfReq).cast()) };
    if rc < 0 {
        return Err(format!("SIOCGIFINDEX('{ifname}') failed: {}", IoError::last_os_error()));
    }
    let idx = i32::from_ne_bytes([ifr.data[0], ifr.data[1], ifr.data[2], ifr.data[3]]);
    if idx <= 0 {
        return Err(format!("invalid ifindex {idx} for '{ifname}'"));
    }
    Ok(idx as u32)
}

fn set_interface_mtu(ifname: &str, mtu: u16) -> Result<(), String> {
    let sock = open_ioctl_dgram_sock()?;
    let mut ifr = make_ifreq(ifname)?;
    ifr.data[0..4].copy_from_slice(&(mtu as i32).to_ne_bytes());
    let rc = unsafe { call_ioctl_ptr(sock.as_raw_fd(), SIOCSIFMTU, (&mut ifr as *mut IfReq).cast()) };
    if rc < 0 {
        return Err(format!("SIOCSIFMTU('{ifname}', {mtu}) failed: {}", IoError::last_os_error()));
    }
    Ok(())
}

fn set_interface_txqlen(ifname: &str, qlen: i32) {
    if let Ok(sock) = open_ioctl_dgram_sock() {
        if let Ok(mut ifr) = make_ifreq(ifname) {
            ifr.data[0..4].copy_from_slice(&qlen.to_ne_bytes());
            unsafe {
                let _ = call_ioctl_ptr(sock.as_raw_fd(), SIOCSIFTXQLEN, (&mut ifr as *mut IfReq).cast());
            }
        }
    }
}

fn set_interface_up(ifname: &str) -> Result<(), String> {
    let sock = open_ioctl_dgram_sock()?;
    let mut ifr = make_ifreq(ifname)?;
    let rc = unsafe { call_ioctl_ptr(sock.as_raw_fd(), SIOCGIFFLAGS, (&mut ifr as *mut IfReq).cast()) };
    if rc < 0 {
        return Err(format!("SIOCGIFFLAGS('{ifname}') failed: {}", IoError::last_os_error()));
    }
    let mut flags = i16::from_ne_bytes([ifr.data[0], ifr.data[1]]);
    flags |= IFF_UP;
    ifr.data[0..2].copy_from_slice(&flags.to_ne_bytes());
    let rc = unsafe { call_ioctl_ptr(sock.as_raw_fd(), SIOCSIFFLAGS, (&mut ifr as *mut IfReq).cast()) };
    if rc < 0 {
        return Err(format!("SIOCSIFFLAGS('{ifname}', UP) failed: {}", IoError::last_os_error()));
    }
    Ok(())
}

pub struct TunDevice {
    _files: Vec<File>,
    fds: Vec<RawFd>,
    ifindex: u32,
    carrier_supported: bool,
    vnet_hdr: bool,
    udp_gso: bool,
    multi_queue: bool,
}

impl TunDevice {
    #[cfg(test)]
    pub fn dummy_for_test() -> Self {
        Self {
            _files: Vec::new(),
            fds: Vec::new(),
            ifindex: 0,
            carrier_supported: false,
            vnet_hdr: false,
            udp_gso: false,
            multi_queue: false,
        }
    }

    fn open_tun_file() -> Result<File, String> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| format!("failed to open /dev/net/tun: {e} (ensure container has /dev/net/tun and CAP_NET_ADMIN)"))
    }

    pub fn create_multi(
        name: &str,
        mtu: u16,
        initial_carrier: bool,
        requested_queues: usize,
    ) -> Result<Self, String> {
        let file = Self::open_tun_file()?;
        let fd = file.as_raw_fd();

        let want_mq = requested_queues > 1;
        let mut ifr = make_ifreq(name)?;
        let mut vnet_hdr = true;
        let mut multi_queue = want_mq;
        let make_flags = |mq: bool, vnet: bool, carrier: bool| -> i16 {
            let mut f = IFF_TUN | IFF_NO_PI;
            if vnet {
                f |= IFF_VNET_HDR;
            }
            if mq {
                f |= IFF_MULTI_QUEUE;
            }
            if !carrier {
                f |= IFF_NO_CARRIER;
            }
            f
        };

        ifr.data[0..2].copy_from_slice(&make_flags(want_mq, true, initial_carrier).to_ne_bytes());
        let mut rc = unsafe { call_ioctl_ptr(fd, TUNSETIFF, (&mut ifr as *mut IfReq).cast()) };
        if rc < 0 && want_mq {
            multi_queue = false;
            ifr = make_ifreq(name)?;
            ifr.data[0..2].copy_from_slice(&make_flags(false, true, initial_carrier).to_ne_bytes());
            rc = unsafe { call_ioctl_ptr(fd, TUNSETIFF, (&mut ifr as *mut IfReq).cast()) };
        }
        let mut carrier_supported = true;
        if rc < 0 {
            vnet_hdr = false;
            multi_queue = false;
            ifr = make_ifreq(name)?;
            ifr.data[0..2].copy_from_slice(&make_flags(false, false, initial_carrier).to_ne_bytes());
            rc = unsafe { call_ioctl_ptr(fd, TUNSETIFF, (&mut ifr as *mut IfReq).cast()) };
        }
        if rc < 0 && !initial_carrier {
            let err = IoError::last_os_error();
            if err.raw_os_error() == Some(EINVAL) {
                ifr = make_ifreq(name)?;
                ifr.data[0..2].copy_from_slice(&make_flags(false, false, true).to_ne_bytes());
                rc = unsafe { call_ioctl_ptr(fd, TUNSETIFF, (&mut ifr as *mut IfReq).cast()) };
            }
        }
        if rc < 0 {
            return Err(format!("TUNSETIFF('{name}') failed: {}", IoError::last_os_error()));
        }
        let mut udp_gso = false;
        let tcp_offload = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
        let udp_offload = TUN_F_USO4 | TUN_F_USO6;
        if vnet_hdr {
            if unsafe { call_ioctl_val(fd, TUNSETOFFLOAD, tcp_offload | udp_offload) } == 0 {
                udp_gso = true;
            } else if unsafe { call_ioctl_val(fd, TUNSETOFFLOAD, tcp_offload) } < 0 {
                let _ = unsafe { call_ioctl_val(fd, TUNSETOFFLOAD, 0) };
                eprintln!(
                    "[warn] TUNSETOFFLOAD failed for {name}: {}; running without TSO/USO offload",
                    IoError::last_os_error()
                );
            }
        }

        set_nonblocking(fd)?;

        let mut files = vec![file];
        let mut fds = vec![fd];
        if multi_queue && requested_queues > 1 {
            let q_flags = IFF_TUN
                | IFF_NO_PI
                | if vnet_hdr { IFF_VNET_HDR } else { 0 }
                | IFF_MULTI_QUEUE;
            let q_offload = if udp_gso {
                tcp_offload | udp_offload
            } else {
                tcp_offload
            };
            for _ in 1..requested_queues {
                if let Ok(qfile) = Self::open_tun_file() {
                    let qfd = qfile.as_raw_fd();
                    let mut qifr = make_ifreq(name)?;
                    qifr.data[0..2].copy_from_slice(&q_flags.to_ne_bytes());
                    let qrc = unsafe { call_ioctl_ptr(qfd, TUNSETIFF, (&mut qifr as *mut IfReq).cast()) };
                    if qrc == 0 && set_nonblocking(qfd).is_ok() {
                        if vnet_hdr {
                            let _ = unsafe { call_ioctl_val(qfd, TUNSETOFFLOAD, q_offload) };
                        }
                        files.push(qfile);
                        fds.push(qfd);
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        // Configure MTU, txqlen, and bring interface UP after all multiqueue fds are attached
        // so every queue gets the host's default qdisc (e.g. fq_pie/fq_codel) and 16384 ring size.
        set_interface_mtu(name, mtu)?;
        set_interface_txqlen(name, 16384);
        set_interface_up(name)?;
        let ifindex = get_interface_index(name)?;

        let dev = Self {
            _files: files,
            fds,
            ifindex,
            carrier_supported,
            vnet_hdr,
            udp_gso,
            multi_queue,
        };
        if let Err(e) = dev.try_set_carrier_inner(initial_carrier) {
            carrier_supported = false;
            eprintln!("[warn] TUNSETCARRIER unsupported for {name}: {e}");
        }
        let mut dev = dev;
        dev.carrier_supported = carrier_supported;
        Ok(dev)
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn queue_count(&self) -> usize {
        self.fds.len()
    }

    pub fn queue_fd(&self, idx: usize) -> i32 {
        self.fds[idx]
    }

    pub fn has_vnet_hdr(&self) -> bool {
        self.vnet_hdr
    }

    pub fn has_udp_gso(&self) -> bool {
        self.udp_gso
    }

    pub fn is_multi_queue(&self) -> bool {
        self.multi_queue && self.fds.len() > 1
    }

    fn try_set_carrier_inner(&self, up: bool) -> Result<(), String> {
        let mut val: c_int = if up { 1 } else { 0 };
        let rc = unsafe { call_ioctl_ptr(self.fds[0], TUNSETCARRIER, (&mut val as *mut c_int).cast()) };
        if rc < 0 {
            let err = IoError::last_os_error();
            if matches!(err.raw_os_error(), Some(ENOTTY | EINVAL | EOPNOTSUPP)) {
                return Err(format!("{err}"));
            }
            return Err(format!("TUNSETCARRIER({up}) failed: {err}"));
        }
        Ok(())
    }

    pub fn set_carrier(&self, up: bool) -> Result<(), String> {
        if !self.carrier_supported {
            return Ok(());
        }
        self.try_set_carrier_inner(up)
    }

    pub fn read_queue_nonblock(&self, q_idx: usize, buf: &mut [u8]) -> Result<usize, IoError> {
        let fd = self.fds[q_idx];
        let n = unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    pub fn readv_queue_nonblock(
        &self,
        q_idx: usize,
        head: &mut [u8],
        tail: &mut [u8],
    ) -> Result<usize, IoError> {
        let fd = self.fds[q_idx];
        let iovs = [
            IoVec {
                iov_base: head.as_mut_ptr().cast(),
                iov_len: head.len(),
            },
            IoVec {
                iov_base: tail.as_mut_ptr().cast(),
                iov_len: tail.len(),
            },
        ];
        let n = unsafe { readv(fd, iovs.as_ptr(), 2) };
        if n < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    pub fn write_queue_nonblock(&self, q_idx: usize, buf: &[u8]) -> Result<usize, IoError> {
        let fd = self.fds[q_idx % self.fds.len()];
        let n = unsafe { write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

pub struct EventFd {
    fd: OwnedFd,
}

impl EventFd {
    pub fn new() -> Result<Self, String> {
        let raw = unsafe { eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC) };
        if raw < 0 {
            return Err(format!("eventfd failed: {}", IoError::last_os_error()));
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
        })
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn notify(&self) {
        let val: u64 = 1;
        unsafe {
            let _ = write(
                self.fd.as_raw_fd(),
                (&val as *const u64).cast(),
                size_of::<u64>(),
            );
        }
    }

    pub fn drain(&self) {
        let mut val: u64 = 0;
        unsafe {
            let _ = read(
                self.fd.as_raw_fd(),
                (&mut val as *mut u64).cast(),
                size_of::<u64>(),
            );
        }
    }
}

pub struct TunUringReader {
    ring_fd: OwnedFd,
    tun_fd: RawFd,
    sq_ptr: *mut u8,
    sq_mmap_len: usize,
    cq_ptr: *mut u8,
    cq_mmap_len: usize,
    single_mmap: bool,
    sqes_ptr: *mut IoUringSqe,
    sqes_mmap_len: usize,
    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_entries: u32,
    sq_ring_mask: u32,
    sq_array: *mut u32,
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_ring_mask: u32,
    cqes_ptr: *const IoUringCqe,
    iovs: Box<[[IoVec; 2]; URING_BATCH]>,
}

unsafe impl Send for TunUringReader {}

impl TunUringReader {
    pub fn open(tun_fd: RawFd) -> Result<Self, String> {
        let mut params: IoUringParams = unsafe { zeroed() };
        let fd = unsafe {
            syscall(
                SYS_IO_URING_SETUP,
                URING_BATCH as c_long,
                (&mut params as *mut IoUringParams).cast::<c_void>(),
            )
        };
        if fd < 0 {
            return Err(format!("io_uring_setup failed: {}", IoError::last_os_error()));
        }
        let ring_fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        if (params.sq_entries as usize) < URING_BATCH || (params.cq_entries as usize) < URING_BATCH {
            return Err("io_uring ring entries smaller than requested batch".into());
        }

        let single_mmap = (params.features & IORING_FEAT_SINGLE_MMAP) != 0;
        let sq_sz = (params.sq_off.array as usize) + (params.sq_entries as usize) * size_of::<u32>();
        let cq_sz =
            (params.cq_off.cqes as usize) + (params.cq_entries as usize) * size_of::<IoUringCqe>();
        let sq_mmap_len = if single_mmap { sq_sz.max(cq_sz) } else { sq_sz };

        let sq_map = unsafe {
            mmap(
                std::ptr::null_mut(),
                sq_mmap_len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                ring_fd.as_raw_fd(),
                IORING_OFF_SQ_RING,
            )
        };
        if sq_map == (-1isize as *mut c_void) {
            return Err(format!("mmap io_uring SQ failed: {}", IoError::last_os_error()));
        }
        let sq_ptr = sq_map.cast::<u8>();

        let (cq_ptr, cq_mmap_len) = if single_mmap {
            (sq_ptr, 0usize)
        } else {
            let cq_map = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    cq_sz,
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED,
                    ring_fd.as_raw_fd(),
                    IORING_OFF_CQ_RING,
                )
            };
            if cq_map == (-1isize as *mut c_void) {
                unsafe {
                    let _ = munmap(sq_ptr.cast(), sq_mmap_len);
                }
                return Err(format!("mmap io_uring CQ failed: {}", IoError::last_os_error()));
            }
            (cq_map.cast::<u8>(), cq_sz)
        };

        let sqes_mmap_len = (params.sq_entries as usize) * size_of::<IoUringSqe>();
        let sqes_map = unsafe {
            mmap(
                std::ptr::null_mut(),
                sqes_mmap_len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                ring_fd.as_raw_fd(),
                IORING_OFF_SQES,
            )
        };
        if sqes_map == (-1isize as *mut c_void) {
            unsafe {
                if !single_mmap {
                    let _ = munmap(cq_ptr.cast(), cq_mmap_len);
                }
                let _ = munmap(sq_ptr.cast(), sq_mmap_len);
            }
            return Err(format!("mmap io_uring SQEs failed: {}", IoError::last_os_error()));
        }
        let sqes_ptr = sqes_map.cast::<IoUringSqe>();

        unsafe {
            let sq_ring_mask = *sq_ptr.add(params.sq_off.ring_mask as usize).cast::<u32>();
            let cq_ring_mask = *cq_ptr.add(params.cq_off.ring_mask as usize).cast::<u32>();
            let sq_head = sq_ptr.add(params.sq_off.head as usize).cast::<AtomicU32>();
            let sq_tail = sq_ptr.add(params.sq_off.tail as usize).cast::<AtomicU32>();
            let sq_array = sq_ptr.add(params.sq_off.array as usize).cast::<u32>();
            let cq_head = cq_ptr.add(params.cq_off.head as usize).cast::<AtomicU32>();
            let cq_tail = cq_ptr.add(params.cq_off.tail as usize).cast::<AtomicU32>();
            let cqes_ptr = cq_ptr.add(params.cq_off.cqes as usize).cast::<IoUringCqe>();

            Ok(Self {
                ring_fd,
                tun_fd,
                sq_ptr,
                sq_mmap_len,
                cq_ptr,
                cq_mmap_len,
                single_mmap,
                sqes_ptr,
                sqes_mmap_len,
                sq_head,
                sq_tail,
                sq_entries: params.sq_entries,
                sq_ring_mask,
                sq_array,
                cq_head,
                cq_tail,
                cq_ring_mask,
                cqes_ptr,
                iovs: Box::new(
                    [[IoVec {
                        iov_base: std::ptr::null_mut(),
                        iov_len: 0,
                    }; 2]; URING_BATCH],
                ),
            })
        }
    }

    /// Submit up to `frame_ptrs.len()` non-blocking (`RWF_NOWAIT`) scatter-gather TUN reads
    /// directly into `PacketTxRing` frame pointers (starting at `head_off` for `head_len` bytes,
    /// spilling oversized TSO super-packets into `overflow_bufs`), and synchronously reap all CQEs.
    /// Writes per-slot `cqe.res` into `results_out[..count]` and returns `hit_eagain`.
    pub unsafe fn readv_into_frames(
        &mut self,
        frame_ptrs: &[*mut u8],
        head_off: usize,
        head_len: usize,
        overflow_bufs: &mut [[u8; TSO_OVERFLOW_SIZE]],
        results_out: &mut [i32; URING_BATCH],
    ) -> Result<bool, IoError> {
        let req_count = frame_ptrs
            .len()
            .min(URING_BATCH)
            .min(overflow_bufs.len());
        let sq_head_ref = &*self.sq_head;
        let tail_ref = &*self.sq_tail;
        let sq_h0 = sq_head_ref.load(Ordering::Acquire);
        let sq_t0 = tail_ref.load(Ordering::Relaxed);
        let in_sq = sq_t0.wrapping_sub(sq_h0) as usize;
        let free_sq = (self.sq_entries as usize).saturating_sub(in_sq);
        let count = req_count.min(free_sq);
        if count == 0 {
            return Ok(false);
        }

        let mut sq_t = sq_t0;
        let mask = self.sq_ring_mask;

        for i in 0..count {
            results_out[i] = -EAGAIN;
            self.iovs[i][0].iov_base = frame_ptrs[i].add(head_off).cast();
            self.iovs[i][0].iov_len = head_len;
            self.iovs[i][1].iov_base = overflow_bufs[i].as_mut_ptr().cast();
            self.iovs[i][1].iov_len = TSO_OVERFLOW_SIZE;

            let sqe = self.sqes_ptr.add(i);
            *sqe = IoUringSqe {
                opcode: IORING_OP_READV,
                flags: 0,
                ioprio: 0,
                fd: self.tun_fd,
                off: 0,
                addr: self.iovs[i].as_ptr() as u64,
                len: 2,
                rw_flags: RWF_NOWAIT,
                user_data: i as u64,
                buf_index: 0,
                personality: 0,
                splice_fd_in: 0,
                pad2: [0; 2],
            };
            *self.sq_array.add((sq_t & mask) as usize) = i as u32;
            sq_t = sq_t.wrapping_add(1);
        }
        tail_ref.store(sq_t, Ordering::Release);

        let rc = syscall(
            SYS_IO_URING_ENTER,
            self.ring_fd.as_raw_fd() as c_long,
            count as c_long,
            count as c_long,
            IORING_ENTER_GETEVENTS as c_long,
            std::ptr::null::<c_void>(),
            0usize,
        );
        let enter_err = if rc < 0 {
            Some(IoError::last_os_error())
        } else {
            None
        };

        let sq_h_after = sq_head_ref.load(Ordering::Acquire);
        let consumed = (sq_h_after.wrapping_sub(sq_h0) as usize).min(count);
        if consumed < count {
            tail_ref.store(sq_h0.wrapping_add(consumed as u32), Ordering::Release);
        }

        let drain_res = if consumed > 0 {
            self.drain_remaining_cqes(consumed, results_out)
        } else {
            Ok(true)
        };

        if let Some(err) = enter_err {
            if err.raw_os_error() != Some(EINTR) && consumed == 0 {
                return Err(err);
            }
        }
        drain_res
    }

    unsafe fn drain_remaining_cqes(
        &mut self,
        expected: usize,
        results_out: &mut [i32; URING_BATCH],
    ) -> Result<bool, IoError> {
        let cq_head_ref = &*self.cq_head;
        let cq_tail_ref = &*self.cq_tail;
        let mut cq_h = cq_head_ref.load(Ordering::Relaxed);
        let mut reaped = 0usize;
        let mut any_positive = false;
        let mut hit_eagain = false;
        let mut unsupported = false;
        let mut wait_errs = 0u32;

        while reaped < expected {
            let cq_t = cq_tail_ref.load(Ordering::Acquire);
            if cq_h == cq_t {
                let rem = expected - reaped;
                let wrc = syscall(
                    SYS_IO_URING_ENTER,
                    self.ring_fd.as_raw_fd() as c_long,
                    0 as c_long,
                    rem as c_long,
                    IORING_ENTER_GETEVENTS as c_long,
                    std::ptr::null::<c_void>(),
                    0usize,
                );
                if wrc < 0 {
                    let werr = IoError::last_os_error();
                    if werr.raw_os_error() != Some(EINTR) {
                        wait_errs += 1;
                        if wait_errs > 8 {
                            return Err(werr);
                        }
                    }
                }
                continue;
            }
            while cq_h != cq_t && reaped < expected {
                let cqe = *self.cqes_ptr.add((cq_h & self.cq_ring_mask) as usize);
                let slot = cqe.user_data as usize;
                if slot < expected {
                    results_out[slot] = cqe.res;
                }
                if cqe.res > 0 {
                    any_positive = true;
                } else if cqe.res == -EOPNOTSUPP || cqe.res == -EINVAL {
                    unsupported = true;
                    hit_eagain = true;
                } else {
                    hit_eagain = true;
                }
                cq_h = cq_h.wrapping_add(1);
                reaped += 1;
            }
            cq_head_ref.store(cq_h, Ordering::Release);
        }

        if unsupported && !any_positive {
            return Err(IoError::from_raw_os_error(EOPNOTSUPP));
        }
        Ok(hit_eagain)
    }
}

impl Drop for TunUringReader {
    fn drop(&mut self) {
        unsafe {
            let _ = munmap(self.sqes_ptr.cast(), self.sqes_mmap_len);
            if !self.single_mmap && self.cq_mmap_len > 0 {
                let _ = munmap(self.cq_ptr.cast(), self.cq_mmap_len);
            }
            let _ = munmap(self.sq_ptr.cast(), self.sq_mmap_len);
        }
    }
}

pub struct PacketTxRing {
    fd: OwnedFd,
    ring_ptr: *mut u8,
    ring_len: usize,
    frame_size: usize,
    frame_nr: usize,
    cursor: usize,
    pending: usize,
    sll_tx: SockAddrLl,
    max_frame_len: usize,
}

unsafe impl Send for PacketTxRing {}

impl PacketTxRing {
    pub fn open(out_ifindex: u32, max_frame_len: usize) -> Result<Self, String> {
        if out_ifindex == 0 {
            return Err("invalid output ifindex 0".into());
        }
        let raw_fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        if raw_fd < 0 {
            return Err(format!(
                "socket(AF_PACKET, SOCK_RAW) failed: {}",
                IoError::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // Drop all incoming traffic on this TX-only AF_PACKET socket
        let filter = [SockFilter {
            code: 0x0006,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        let prog = SockFprog {
            len: 1,
            _pad: [0u8; 6],
            filter: filter.as_ptr(),
        };
        unsafe {
            let _ = setsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_ATTACH_FILTER,
                (&prog as *const SockFprog).cast(),
                size_of::<SockFprog>() as c_uint,
            );
        }

        let ver: c_int = TPACKET_V2;
        if unsafe {
            setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_VERSION,
                (&ver as *const c_int).cast(),
                size_of::<c_int>() as c_uint,
            )
        } < 0
        {
            return Err(format!("PACKET_VERSION(V2) failed: {}", IoError::last_os_error()));
        }

        let loss: c_int = 1;
        unsafe {
            let _ = setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_LOSS,
                (&loss as *const c_int).cast(),
                size_of::<c_int>() as c_uint,
            );
            let bypass: c_int = 1;
            let _ = setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_QDISC_BYPASS,
                (&bypass as *const c_int).cast(),
                size_of::<c_int>() as c_uint,
            );
        }

        let needed = TPACKET2_TX_DATA_OFF + max_frame_len;
        let frame_size = needed.next_power_of_two().max(2048);
        if frame_size > 65536 {
            return Err("frame size exceeds 65536 for PACKET_TX_RING".into());
        }
        let block_size = 65536usize;
        let block_nr = 64usize;
        let total_len = block_size * block_nr;
        let frame_nr = total_len / frame_size;
        let req = TpacketReq {
            tp_block_size: block_size as u32,
            tp_block_nr: block_nr as u32,
            tp_frame_size: frame_size as u32,
            tp_frame_nr: frame_nr as u32,
        };
        if unsafe {
            setsockopt(
                fd.as_raw_fd(),
                SOL_PACKET,
                PACKET_TX_RING,
                (&req as *const TpacketReq).cast(),
                size_of::<TpacketReq>() as c_uint,
            )
        } < 0
        {
            return Err(format!("PACKET_TX_RING failed: {}", IoError::last_os_error()));
        }

        let ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                total_len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == (-1isize as *mut c_void) {
            return Err(format!("mmap PACKET_TX_RING failed: {}", IoError::last_os_error()));
        }

        let sll_bind = SockAddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: 0,
            sll_ifindex: out_ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0u8; 8],
        };
        if unsafe {
            bind(
                fd.as_raw_fd(),
                (&sll_bind as *const SockAddrLl).cast(),
                size_of::<SockAddrLl>() as c_uint,
            )
        } < 0
        {
            unsafe {
                munmap(ptr, total_len);
            }
            return Err(format!("bind(AF_PACKET) failed: {}", IoError::last_os_error()));
        }

        let sll_tx = SockAddrLl {
            sll_family: AF_PACKET as u16,
            sll_protocol: ETH_P_IP.to_be(),
            sll_ifindex: out_ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0u8; 8],
        };

        Ok(Self {
            fd,
            ring_ptr: ptr.cast::<u8>(),
            ring_len: total_len,
            frame_size,
            frame_nr,
            cursor: 0,
            pending: 0,
            sll_tx,
            max_frame_len: frame_size - TPACKET2_TX_DATA_OFF,
        })
    }

    pub fn max_frame_len(&self) -> usize {
        self.max_frame_len
    }

    #[inline]
    fn slot_hdr_ptr(&self, idx: usize) -> *mut Tpacket2Hdr {
        unsafe { self.ring_ptr.add(idx * self.frame_size).cast::<Tpacket2Hdr>() }
    }

    pub fn ensure_slot_ready(&mut self, frame_len: usize) -> bool {
        if frame_len > self.max_frame_len {
            return false;
        }
        let hdr = self.slot_hdr_ptr(self.cursor);
        let status_ref = unsafe { &*(std::ptr::addr_of!((*hdr).tp_status) as *const AtomicU32) };
        if status_ref.load(Ordering::Acquire) != TP_STATUS_AVAILABLE {
            if self.pending > 0 {
                self.kick();
            }
            if status_ref.load(Ordering::Acquire) != TP_STATUS_AVAILABLE {
                return false;
            }
        }
        true
    }

    /// Return the number of contiguous `TP_STATUS_AVAILABLE` slots starting at `self.cursor`,
    /// up to `max_slots`. Kicks pending frames first if the head slot is still in flight.
    pub fn available_run(&mut self, max_slots: usize, min_frame_cap: usize) -> usize {
        if min_frame_cap > self.max_frame_len || max_slots == 0 {
            return 0;
        }
        let cap = max_slots.min(self.frame_nr);
        let first_hdr = self.slot_hdr_ptr(self.cursor);
        let first_status =
            unsafe { &*(std::ptr::addr_of!((*first_hdr).tp_status) as *const AtomicU32) };
        if first_status.load(Ordering::Acquire) != TP_STATUS_AVAILABLE {
            if self.pending > 0 {
                self.kick();
            }
            if first_status.load(Ordering::Acquire) != TP_STATUS_AVAILABLE {
                return 0;
            }
        }
        let mut ready = 1usize;
        let mut idx = self.cursor + 1;
        if idx >= self.frame_nr {
            idx = 0;
        }
        while ready < cap {
            let hdr = self.slot_hdr_ptr(idx);
            let st = unsafe { &*(std::ptr::addr_of!((*hdr).tp_status) as *const AtomicU32) };
            if st.load(Ordering::Acquire) != TP_STATUS_AVAILABLE {
                break;
            }
            ready += 1;
            idx += 1;
            if idx >= self.frame_nr {
                idx = 0;
            }
        }
        ready
    }

    #[inline]
    pub fn slot_frame_ptr(&mut self, offset_from_cursor: usize) -> *mut u8 {
        let idx = (self.cursor + offset_from_cursor) % self.frame_nr;
        let hdr = self.slot_hdr_ptr(idx);
        unsafe { (hdr as *mut u8).add(TPACKET2_TX_DATA_OFF) }
    }

    #[inline]
    pub fn cur_frame_mut(&mut self, frame_len: usize) -> &mut [u8] {
        let hdr = self.slot_hdr_ptr(self.cursor);
        let data_ptr = unsafe { (hdr as *mut u8).add(TPACKET2_TX_DATA_OFF) };
        unsafe { std::slice::from_raw_parts_mut(data_ptr, frame_len) }
    }

    pub fn commit_frame(&mut self, frame_len: usize) {
        let hdr = self.slot_hdr_ptr(self.cursor);
        unsafe {
            (*hdr).tp_len = frame_len as u32;
            (*hdr).tp_snaplen = frame_len as u32;
            (*hdr).tp_mac = TPACKET2_TX_DATA_OFF as u16;
            (*hdr).tp_net = (TPACKET2_TX_DATA_OFF + 14) as u16;
            let status_ref = &*(std::ptr::addr_of!((*hdr).tp_status) as *const AtomicU32);
            status_ref.store(TP_STATUS_SEND_REQUEST, Ordering::Release);
        }
        self.cursor += 1;
        if self.cursor >= self.frame_nr {
            self.cursor = 0;
        }
        self.pending += 1;
        if self.pending >= 256 {
            self.kick();
        }
    }

    pub fn kick(&mut self) {
        if self.pending == 0 {
            return;
        }
        unsafe {
            let _ = sendto(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                MSG_DONTWAIT,
                (&self.sll_tx as *const SockAddrLl).cast(),
                size_of::<SockAddrLl>() as c_uint,
            );
        }
        self.pending = 0;
    }
}

impl Drop for PacketTxRing {
    fn drop(&mut self) {
        self.kick();
        unsafe {
            let _ = munmap(self.ring_ptr.cast(), self.ring_len);
        }
    }
}

pub fn get_interface_hwaddr(ifname: &str) -> Result<[u8; 6], String> {
    let sock = open_ioctl_dgram_sock()?;
    let mut ifr = make_ifreq(ifname)?;
    let rc = unsafe { call_ioctl_ptr(sock.as_raw_fd(), SIOCGIFHWADDR, (&mut ifr as *mut IfReq).cast()) };
    if rc < 0 {
        return Err(format!("SIOCGIFHWADDR('{ifname}') failed: {}", IoError::last_os_error()));
    }
    let family = i16::from_ne_bytes([ifr.data[0], ifr.data[1]]);
    if family != ARPHRD_ETHER {
        return Err(format!("interface '{ifname}' is not Ethernet (hwtype={family})"));
    }
    let mac = [
        ifr.data[2],
        ifr.data[3],
        ifr.data[4],
        ifr.data[5],
        ifr.data[6],
        ifr.data[7],
    ];
    if mac == [0u8; 6] {
        return Err(format!("interface '{ifname}' has zero MAC address"));
    }
    Ok(mac)
}

pub fn lookup_arp_mac(ip: Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    let content = fs::read_to_string("/proc/net/arp").ok()?;
    parse_arp_table_mac(&content, ip, ifname)
}

fn parse_arp_table_mac(content: &str, ip: Ipv4Addr, ifname: &str) -> Option<[u8; 6]> {
    let ip_str = ip.to_string();
    for line in content.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(row_ip) = cols.next() else { continue };
        let Some(_hw_type) = cols.next() else { continue };
        let Some(flags) = cols.next() else { continue };
        let Some(hw_addr) = cols.next() else { continue };
        let Some(_mask) = cols.next() else { continue };
        let Some(dev) = cols.next() else { continue };
        if row_ip != ip_str || dev != ifname || flags == "0x0" {
            continue;
        }
        let mut mac = [0u8; 6];
        let mut parts = hw_addr.split(':');
        let mut ok = true;
        for b in &mut mac {
            if let Some(hex) = parts.next() {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    *b = v;
                    continue;
                }
            }
            ok = false;
            break;
        }
        if ok && parts.next().is_none() && mac != [0u8; 6] {
            return Some(mac);
        }
    }
    None
}

pub fn trigger_arp_probe(ip: Ipv4Addr) {
    let raw = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: 9u16.to_be(),
        sin_addr: ip.octets(),
        sin_zero: [0u8; 8],
    };
    let byte = [0u8; 1];
    unsafe {
        let _ = sendto(
            fd.as_raw_fd(),
            byte.as_ptr().cast(),
            1,
            MSG_DONTWAIT,
            (&addr as *const SockAddrIn).cast(),
            size_of::<SockAddrIn>() as c_uint,
        );
    }
}

pub struct NeighWatchSocket {
    fd: OwnedFd,
}

impl NeighWatchSocket {
    pub fn open() -> Result<Self, String> {
        let raw = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE) };
        if raw < 0 {
            return Err(format!("socket(AF_NETLINK, RTMGRP_NEIGH) failed: {}", IoError::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let addr = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: RTMGRP_NEIGH,
        };
        let rc = unsafe {
            bind(
                fd.as_raw_fd(),
                (&addr as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as c_uint,
            )
        };
        if rc < 0 {
            return Err(format!("bind(AF_NETLINK, RTMGRP_NEIGH) failed: {}", IoError::last_os_error()));
        }
        Ok(Self { fd })
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn drain(&self) -> bool {
        let mut buf = [0u8; 4096];
        let mut any = false;
        loop {
            let n = unsafe {
                recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    MSG_DONTWAIT,
                )
            };
            if n > 0 {
                any = true;
            } else {
                break;
            }
        }
        any
    }
}

pub struct RxBatchBuffer {
    data: Vec<u8>,
    stride: usize,
    slot_cap: usize,
    iovs: Box<[IoVec; RX_BATCH_CAP]>,
    mmsgs: Box<[MMsgHdr; RX_BATCH_CAP]>,
}

unsafe impl Send for RxBatchBuffer {}

impl RxBatchBuffer {
    pub fn new(min_slot_size: usize) -> Self {
        let slot_cap = min_slot_size.clamp(2048, BATCH_SLOT_SIZE);
        // Odd multiple of 64 bytes prevents 64KB/4KB L1d/L2 cache-set conflict aliasing across slots
        let stride = ((slot_cap + 63) & !63) | 64;
        let data = vec![0u8; stride * RX_BATCH_CAP];
        let iovs = Box::new(
            [IoVec {
                iov_base: std::ptr::null_mut(),
                iov_len: slot_cap,
            }; RX_BATCH_CAP],
        );
        let mmsgs = Box::new(
            [MMsgHdr {
                msg_hdr: MsgHdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    _pad0: 0,
                    msg_iov: std::ptr::null_mut(),
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                    _pad1: 0,
                },
                msg_len: 0,
                _pad: 0,
            }; RX_BATCH_CAP],
        );
        Self {
            data,
            stride,
            slot_cap,
            iovs,
            mmsgs,
        }
    }

    #[inline]
    fn prepare_ptrs(&mut self) -> *mut MMsgHdr {
        let base_ptr = self.data.as_mut_ptr();
        let stride = self.stride;
        let slot_cap = self.slot_cap;
        let iovs_ptr = self.iovs.as_mut_ptr();
        let mmsgs_ptr = self.mmsgs.as_mut_ptr();
        unsafe {
            for i in 0..RX_BATCH_CAP {
                let iov = iovs_ptr.add(i);
                (*iov).iov_base = base_ptr.add(i * stride).cast();
                (*iov).iov_len = slot_cap;
                let mhdr = mmsgs_ptr.add(i);
                (*mhdr).msg_hdr.msg_iov = iov;
                (*mhdr).msg_hdr.msg_flags = 0;
                (*mhdr).msg_len = 0;
            }
        }
        mmsgs_ptr
    }

    #[inline]
    pub fn is_truncated(&self, idx: usize) -> bool {
        (self.mmsgs[idx].msg_hdr.msg_flags & MSG_TRUNC) != 0
            || (self.mmsgs[idx].msg_len as usize) > self.slot_cap
    }

    #[inline]
    pub fn slot_cap(&self) -> usize {
        self.slot_cap
    }

    #[inline]
    pub fn pkt_mut(&mut self, idx: usize) -> &mut [u8] {
        let len = (self.mmsgs[idx].msg_len as usize).min(self.slot_cap);
        let start = idx * self.stride;
        &mut self.data[start..start + len]
    }
}

pub struct RawGreSocket {
    fd: OwnedFd,
    local_bind: Option<Ipv4Addr>,
    is_hdrincl: bool,
    ip_id: u16,
    frag_fd: Option<OwnedFd>,
    last_tos: Option<c_int>,
    last_pmtudisc: Option<c_int>,
    connected_dst: Option<Ipv4Addr>,
}

impl RawGreSocket {
    pub fn open_rx() -> Result<Self, String> {
        let raw_fd = unsafe { socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_GRE) };
        if raw_fd < 0 {
            return Err(format!(
                "socket(AF_INET, SOCK_RAW, IPPROTO_GRE) failed: {} (ensure CAP_NET_RAW)",
                IoError::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let buf_sz: c_int = 32 * 1024 * 1024;
        unsafe {
            let rc = setsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_RCVBUFFORCE,
                (&buf_sz as *const c_int).cast(),
                size_of::<c_int>() as c_uint,
            );
            if rc < 0 {
                let _ = setsockopt(
                    fd.as_raw_fd(),
                    SOL_SOCKET,
                    SO_RCVBUF,
                    (&buf_sz as *const c_int).cast(),
                    size_of::<c_int>() as c_uint,
                );
            }
        }
        Ok(Self {
            fd,
            local_bind: None,
            is_hdrincl: false,
            ip_id: 1,
            frag_fd: None,
            last_tos: None,
            last_pmtudisc: None,
            connected_dst: None,
        })
    }

    pub fn open_tx(local_bind: Option<Ipv4Addr>) -> Result<Self, String> {
        // Open TX sockets with IPPROTO_RAW (255, IP_HDRINCL=1) so they live in raw_v4_hashinfo[255]
        // instead of raw_v4_hashinfo[47], avoiding per-socket skb_clone() storms on inbound GRE RX.
        let raw_fd = unsafe { socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_RAW) };
        if raw_fd < 0 {
            return Err(format!(
                "socket(AF_INET, SOCK_RAW, IPPROTO_RAW) TX failed: {}",
                IoError::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        if let Some(local_ip) = local_bind {
            let addr = SockAddrIn {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: local_ip.octets(),
                sin_zero: [0u8; 8],
            };
            let rc = unsafe {
                bind(
                    fd.as_raw_fd(),
                    (&addr as *const SockAddrIn).cast(),
                    size_of::<SockAddrIn>() as c_uint,
                )
            };
            if rc < 0 {
                return Err(format!("bind TX raw socket to {local_ip} failed: {}", IoError::last_os_error()));
            }
        }

        unsafe {
            let pmtudisc: c_int = IP_PMTUDISC_DONT;
            let _ = setsockopt(
                fd.as_raw_fd(),
                SOL_IP,
                IP_MTU_DISCOVER,
                (&pmtudisc as *const c_int).cast(),
                size_of::<c_int>() as c_uint,
            );
            let snd_sz: c_int = 8 * 1024 * 1024;
            let rc = setsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_SNDBUFFORCE,
                (&snd_sz as *const c_int).cast(),
                size_of::<c_int>() as c_uint,
            );
            if rc < 0 {
                let _ = setsockopt(
                    fd.as_raw_fd(),
                    SOL_SOCKET,
                    SO_SNDBUF,
                    (&snd_sz as *const c_int).cast(),
                    size_of::<c_int>() as c_uint,
                );
            }
        }

        Ok(Self {
            fd,
            local_bind,
            is_hdrincl: true,
            ip_id: 1,
            frag_fd: None,
            last_tos: None,
            last_pmtudisc: None,
            connected_dst: None,
        })
    }

    fn ensure_frag_fd(&mut self, dscp: u8) -> Result<RawFd, IoError> {
        let ffd = if let Some(ref existing) = self.frag_fd {
            existing.as_raw_fd()
        } else {
            let raw_fd =
                unsafe { socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_GRE) };
            if raw_fd < 0 {
                return Err(IoError::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            if let Some(local_ip) = self.local_bind {
                let addr = SockAddrIn {
                    sin_family: AF_INET as u16,
                    sin_port: 0,
                    sin_addr: local_ip.octets(),
                    sin_zero: [0u8; 8],
                };
                unsafe {
                    let _ = bind(
                        fd.as_raw_fd(),
                        (&addr as *const SockAddrIn).cast(),
                        size_of::<SockAddrIn>() as c_uint,
                    );
                }
            }
            let filter = [SockFilter {
                code: 0x0006,
                jt: 0,
                jf: 0,
                k: 0,
            }];
            let prog = SockFprog {
                len: 1,
                _pad: [0u8; 6],
                filter: filter.as_ptr(),
            };
            unsafe {
                let _ = setsockopt(
                    fd.as_raw_fd(),
                    SOL_SOCKET,
                    SO_ATTACH_FILTER,
                    (&prog as *const SockFprog).cast(),
                    size_of::<SockFprog>() as c_uint,
                );
                let pmtudisc: c_int = IP_PMTUDISC_DONT;
                let _ = setsockopt(
                    fd.as_raw_fd(),
                    SOL_IP,
                    IP_MTU_DISCOVER,
                    (&pmtudisc as *const c_int).cast(),
                    size_of::<c_int>() as c_uint,
                );
            }
            let raw = fd.as_raw_fd();
            self.frag_fd = Some(fd);
            raw
        };
        let tos: c_int = ((dscp & 0x3f) << 2) as c_int;
        if self.last_tos != Some(tos) {
            let rc = unsafe {
                setsockopt(
                    ffd,
                    SOL_IP,
                    IP_TOS,
                    (&tos as *const c_int).cast(),
                    size_of::<c_int>() as c_uint,
                )
            };
            if rc == 0 {
                self.last_tos = Some(tos);
            }
        }
        Ok(ffd)
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    pub fn recv_batch(&self, batch: &mut RxBatchBuffer) -> Result<usize, IoError> {
        let mmsgs_ptr = batch.prepare_ptrs();
        let n = unsafe {
            recvmmsg(
                self.fd.as_raw_fd(),
                mmsgs_ptr,
                RX_BATCH_CAP as c_uint,
                MSG_DONTWAIT | MSG_TRUNC,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn ensure_socket_opts(&mut self, dscp: u8, dont_fragment: bool) {
        let tos: c_int = ((dscp & 0x3f) << 2) as c_int;
        if self.last_tos != Some(tos) {
            let rc = unsafe {
                setsockopt(
                    self.fd.as_raw_fd(),
                    SOL_IP,
                    IP_TOS,
                    (&tos as *const c_int).cast(),
                    size_of::<c_int>() as c_uint,
                )
            };
            if rc == 0 {
                self.last_tos = Some(tos);
            }
        }

        let pmtudisc: c_int = if dont_fragment {
            IP_PMTUDISC_DO
        } else {
            IP_PMTUDISC_DONT
        };
        if self.last_pmtudisc != Some(pmtudisc) {
            let rc = unsafe {
                setsockopt(
                    self.fd.as_raw_fd(),
                    SOL_IP,
                    IP_MTU_DISCOVER,
                    (&pmtudisc as *const c_int).cast(),
                    size_of::<c_int>() as c_uint,
                )
            };
            if rc == 0 {
                self.last_pmtudisc = Some(pmtudisc);
            }
        }
    }

    fn ensure_connected(&mut self, dst: Ipv4Addr) -> bool {
        if self.connected_dst == Some(dst) {
            return true;
        }
        let addr = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: dst.octets(),
            sin_zero: [0u8; 8],
        };
        let rc = unsafe {
            connect(
                self.fd.as_raw_fd(),
                (&addr as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as c_uint,
            )
        };
        if rc == 0 {
            self.connected_dst = Some(dst);
            true
        } else {
            false
        }
    }

    pub fn send_to(
        &mut self,
        dst: Ipv4Addr,
        dscp: u8,
        dont_fragment: bool,
        payload: &[u8],
    ) -> Result<usize, IoError> {
        let addr = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: dst.octets(),
            sin_zero: [0u8; 8],
        };
        if self.is_hdrincl {
            let total_len = (20 + payload.len()).min(u16::MAX as usize) as u16;
            let id = self.ip_id;
            self.ip_id = self.ip_id.wrapping_add(1);
            let src = self.local_bind.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let mut pkt = [0u8; 128];
            if 20 + payload.len() <= pkt.len() {
                crate::packet::write_outer_ipv4_gre_header(
                    &mut pkt[..20],
                    src,
                    dst,
                    dscp,
                    dont_fragment,
                    id,
                    total_len,
                );
                pkt[20..20 + payload.len()].copy_from_slice(payload);
                let n = unsafe {
                    sendto(
                        self.fd.as_raw_fd(),
                        pkt.as_ptr().cast(),
                        20 + payload.len(),
                        MSG_DONTWAIT,
                        (&addr as *const SockAddrIn).cast(),
                        size_of::<SockAddrIn>() as c_uint,
                    )
                };
                if n >= 0 {
                    return Ok(payload.len());
                }
                let err = IoError::last_os_error();
                if err.raw_os_error() != Some(EMSGSIZE) || dont_fragment {
                    return Err(err);
                }
            }
            let ffd = self.ensure_frag_fd(dscp)?;
            let n = unsafe {
                sendto(
                    ffd,
                    payload.as_ptr().cast(),
                    payload.len(),
                    MSG_DONTWAIT,
                    (&addr as *const SockAddrIn).cast(),
                    size_of::<SockAddrIn>() as c_uint,
                )
            };
            return if n < 0 {
                Err(IoError::last_os_error())
            } else {
                Ok(n as usize)
            };
        }

        self.ensure_socket_opts(dscp, dont_fragment);
        let n = unsafe {
            sendto(
                self.fd.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                0,
                (&addr as *const SockAddrIn).cast(),
                size_of::<SockAddrIn>() as c_uint,
            )
        };
        if n < 0 {
            Err(IoError::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    pub fn send_batch(
        &mut self,
        dst: Ipv4Addr,
        dscp: u8,
        dont_fragment: bool,
        ip_packets_with_hdr: &[&[u8]],
        packets: &[&[u8]],
    ) -> SendBatchOutcome {
        if packets.is_empty() {
            return SendBatchOutcome {
                sent: 0,
                dropped: 0,
                emsgsize_mask: 0,
            };
        }
        let mut addr = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: dst.octets(),
            sin_zero: [0u8; 8],
        };
        let count = packets.len().min(BATCH_CAP);
        let mut sent = 0usize;
        let mut dropped = 0usize;
        let mut emsgsize_mask = 0u64;

        if self.is_hdrincl && ip_packets_with_hdr.len() >= count {
            let connected = self.ensure_connected(dst);
            let mut iovs = [IoVec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; BATCH_CAP];
            let mut mmsgs = [MMsgHdr {
                msg_hdr: MsgHdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    _pad0: 0,
                    msg_iov: std::ptr::null_mut(),
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                    _pad1: 0,
                },
                msg_len: 0,
                _pad: 0,
            }; BATCH_CAP];
            for i in 0..count {
                iovs[i].iov_base = ip_packets_with_hdr[i].as_ptr() as *mut c_void;
                iovs[i].iov_len = ip_packets_with_hdr[i].len();
                mmsgs[i].msg_hdr.msg_iov = &mut iovs[i];
                if !connected {
                    mmsgs[i].msg_hdr.msg_name = (&mut addr as *mut SockAddrIn).cast();
                    mmsgs[i].msg_hdr.msg_namelen = size_of::<SockAddrIn>() as c_uint;
                }
            }

            let mut offset = 0usize;
            let mut eagain_retried = false;
            while offset < count {
                let rem = count - offset;
                let n = unsafe {
                    syscall(
                        SYS_SENDMMSG,
                        self.fd.as_raw_fd() as c_long,
                        mmsgs.as_mut_ptr().add(offset),
                        rem as c_long,
                        MSG_DONTWAIT as c_long,
                    )
                };
                if n > 0 {
                    sent += n as usize;
                    offset += n as usize;
                    eagain_retried = false;
                    continue;
                }
                if n == 0 {
                    dropped += rem;
                    break;
                }
                let errno = IoError::last_os_error().raw_os_error().unwrap_or(0);
                if errno == EINTR {
                    continue;
                }
                if errno == EMSGSIZE {
                    if !dont_fragment {
                        if let Ok(ffd) = self.ensure_frag_fd(dscp) {
                            let fn_rc = unsafe {
                                sendto(
                                    ffd,
                                    packets[offset].as_ptr().cast(),
                                    packets[offset].len(),
                                    MSG_DONTWAIT,
                                    (&addr as *const SockAddrIn).cast(),
                                    size_of::<SockAddrIn>() as c_uint,
                                )
                            };
                            if fn_rc >= 0 {
                                sent += 1;
                                offset += 1;
                                continue;
                            }
                        }
                    }
                    emsgsize_mask |= 1u64 << offset;
                    dropped += 1;
                    offset += 1;
                    continue;
                }
                if errno == EAGAIN && !eagain_retried {
                    eagain_retried = true;
                    std::thread::yield_now();
                    continue;
                }
                dropped += rem;
                break;
            }
            return SendBatchOutcome {
                sent,
                dropped,
                emsgsize_mask,
            };
        }

        self.ensure_socket_opts(dscp, dont_fragment);
        let connected = self.ensure_connected(dst);
        let mut iovs = [IoVec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; BATCH_CAP];
        let mut mmsgs = [MMsgHdr {
            msg_hdr: MsgHdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                _pad0: 0,
                msg_iov: std::ptr::null_mut(),
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
                _pad1: 0,
            },
            msg_len: 0,
            _pad: 0,
        }; BATCH_CAP];

        for i in 0..count {
            iovs[i].iov_base = packets[i].as_ptr() as *mut c_void;
            iovs[i].iov_len = packets[i].len();
            mmsgs[i].msg_hdr.msg_iov = &mut iovs[i];
            if !connected {
                mmsgs[i].msg_hdr.msg_name = (&mut addr as *mut SockAddrIn).cast();
                mmsgs[i].msg_hdr.msg_namelen = size_of::<SockAddrIn>() as c_uint;
            }
        }
        let mut offset = 0usize;
        let mut eagain_retried = false;
        while offset < count {
            let rem = count - offset;
            let n = unsafe {
                syscall(
                    SYS_SENDMMSG,
                    self.fd.as_raw_fd() as c_long,
                    mmsgs.as_mut_ptr().add(offset),
                    rem as c_long,
                    MSG_DONTWAIT as c_long,
                )
            };
            if n > 0 {
                sent += n as usize;
                offset += n as usize;
                eagain_retried = false;
                continue;
            }
            if n == 0 {
                dropped += rem;
                break;
            }
            let errno = IoError::last_os_error().raw_os_error().unwrap_or(0);
            if errno == EINTR {
                continue;
            }
            if errno == EMSGSIZE {
                emsgsize_mask |= 1u64 << offset;
                dropped += 1;
                offset += 1;
                continue;
            }
            if errno == EAGAIN && !eagain_retried {
                eagain_retried = true;
                std::thread::yield_now();
                continue;
            }
            dropped += rem;
            break;
        }
        SendBatchOutcome {
            sent,
            dropped,
            emsgsize_mask,
        }
    }
}

pub struct Epoll {
    fd: OwnedFd,
}

impl Epoll {
    pub fn new() -> Result<Self, String> {
        let fd = unsafe { epoll_create1(SOCK_CLOEXEC) };
        if fd < 0 {
            return Err(format!("epoll_create1 failed: {}", IoError::last_os_error()));
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    pub fn add(&self, fd: i32, token: u64) -> Result<(), String> {
        let mut ev = EpollEvent {
            events: EPOLLIN | EPOLLERR | EPOLLHUP,
            data: token,
        };
        let rc = unsafe { epoll_ctl(self.fd.as_raw_fd(), EPOLL_CTL_ADD, fd, &mut ev) };
        if rc < 0 {
            return Err(format!("epoll_ctl(ADD, fd={fd}) failed: {}", IoError::last_os_error()));
        }
        Ok(())
    }

    pub fn wait(&self, tokens_out: &mut [u64], timeout_ms: i32) -> Result<usize, IoError> {
        let cap = tokens_out.len().min(64);
        let mut events = [EpollEvent { events: 0, data: 0 }; 64];
        let n = unsafe { epoll_wait(self.fd.as_raw_fd(), events.as_mut_ptr(), cap as c_int, timeout_ms) };
        if n < 0 {
            return Err(IoError::last_os_error());
        }
        let count = n as usize;
        for i in 0..count {
            tokens_out[i] = events[i].data;
        }
        Ok(count)
    }
}

struct NetlinkSocket {
    fd: OwnedFd,
    seq: u32,
}

impl NetlinkSocket {
    fn open() -> Result<Self, String> {
        let raw = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
        if raw < 0 {
            return Err(format!("socket(AF_NETLINK) failed: {}", IoError::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let tv = TimeVal {
            tv_sec: 2,
            tv_usec: 0,
        };
        unsafe {
            let _ = setsockopt(
                fd.as_raw_fd(),
                SOL_SOCKET,
                SO_RCVTIMEO,
                (&tv as *const TimeVal).cast(),
                size_of::<TimeVal>() as c_uint,
            );
        }
        let addr = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let rc = unsafe {
            bind(
                fd.as_raw_fd(),
                (&addr as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as c_uint,
            )
        };
        if rc < 0 {
            return Err(format!("bind(AF_NETLINK) failed: {}", IoError::last_os_error()));
        }
        Ok(Self { fd, seq: 1 })
    }

    fn send_and_recv(&mut self, msg: &mut [u8]) -> Result<Vec<u8>, String> {
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_ne_bytes());
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        msg[8..12].copy_from_slice(&seq.to_ne_bytes());

        let dst = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let sent = unsafe {
            sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&dst as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as c_uint,
            )
        };
        if sent < 0 {
            return Err(format!("netlink sendto failed: {}", IoError::last_os_error()));
        }

        let mut resp = vec![0u8; 8192];
        let n = unsafe { recv(self.fd.as_raw_fd(), resp.as_mut_ptr().cast(), resp.len(), 0) };
        if n < 0 {
            return Err(format!("netlink recv failed: {}", IoError::last_os_error()));
        }
        resp.truncate(n as usize);
        Ok(resp)
    }

    fn send_and_dump(&mut self, msg: &mut [u8]) -> Result<Vec<u8>, String> {
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_ne_bytes());
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        msg[8..12].copy_from_slice(&seq.to_ne_bytes());

        let dst = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let sent = unsafe {
            sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&dst as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as c_uint,
            )
        };
        if sent < 0 {
            return Err(format!("netlink dump sendto failed: {}", IoError::last_os_error()));
        }

        let mut all = Vec::with_capacity(8192);
        let mut chunk = vec![0u8; 16384];
        loop {
            let n = unsafe { recv(self.fd.as_raw_fd(), chunk.as_mut_ptr().cast(), chunk.len(), 0) };
            if n < 0 {
                let err = IoError::last_os_error();
                if err.raw_os_error() == Some(EINTR) {
                    continue;
                }
                return Err(format!("netlink dump recv failed: {err}"));
            }
            if n == 0 {
                break;
            }
            let n = n as usize;
            let mut off = 0usize;
            let mut done = false;
            let mut multipart = false;
            while off + size_of::<NlMsgHdr>() <= n {
                let hdr = unsafe { std::ptr::read_unaligned(chunk[off..].as_ptr() as *const NlMsgHdr) };
                let mlen = hdr.nlmsg_len as usize;
                if mlen < size_of::<NlMsgHdr>() || off + mlen > n {
                    break;
                }
                if (hdr.nlmsg_flags & NLM_F_MULTI) != 0 {
                    multipart = true;
                }
                if hdr.nlmsg_type == NLMSG_DONE {
                    done = true;
                    break;
                }
                if hdr.nlmsg_type == NLMSG_ERROR {
                    let err_code = parse_nlmsg_error(&chunk[off..off + mlen])?;
                    if err_code == 0 {
                        done = true;
                        break;
                    }
                    let errno = -err_code;
                    return Err(format!(
                        "netlink dump error errno={errno} ({})",
                        IoError::from_raw_os_error(errno)
                    ));
                }
                all.extend_from_slice(&chunk[off..off + mlen]);
                off += (mlen + 3) & !3;
            }
            if done || !multipart {
                break;
            }
        }
        Ok(all)
    }

    fn send_ack_errno(&mut self, msg: &mut [u8]) -> Result<(), i32> {
        let len = msg.len() as u32;
        msg[0..4].copy_from_slice(&len.to_ne_bytes());
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        msg[8..12].copy_from_slice(&seq.to_ne_bytes());
        let dst = SockAddrNl {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: 0,
            nl_groups: 0,
        };
        let sent = unsafe {
            sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&dst as *const SockAddrNl).cast(),
                size_of::<SockAddrNl>() as c_uint,
            )
        };
        if sent < 0 {
            return Err(IoError::last_os_error().raw_os_error().unwrap_or(EINVAL));
        }
        let mut resp = vec![0u8; 8192];
        let n = unsafe { recv(self.fd.as_raw_fd(), resp.as_mut_ptr().cast(), resp.len(), 0) };
        if n < 0 {
            return Err(IoError::last_os_error().raw_os_error().unwrap_or(EINVAL));
        }
        resp.truncate(n as usize);
        if resp.len() < size_of::<NlMsgHdr>() {
            return Err(EINVAL);
        }
        let hdr = unsafe { std::ptr::read_unaligned(resp.as_ptr() as *const NlMsgHdr) };
        if hdr.nlmsg_type == NLMSG_ERROR {
            let err_code = parse_nlmsg_error(&resp).map_err(|_| EINVAL)?;
            if err_code == 0 {
                return Ok(());
            }
            return Err(-err_code);
        }
        Ok(())
    }

    fn send_ack(&mut self, msg: &mut [u8], ignore_eexist: bool) -> Result<(), String> {
        let resp = self.send_and_recv(msg)?;
        if resp.len() < size_of::<NlMsgHdr>() {
            return Err("truncated netlink response".into());
        }
        let hdr = unsafe { std::ptr::read_unaligned(resp.as_ptr() as *const NlMsgHdr) };
        if hdr.nlmsg_type == NLMSG_ERROR {
            let err_code = parse_nlmsg_error(&resp)?;
            if err_code == 0 {
                return Ok(());
            }
            let errno = -err_code;
            if ignore_eexist && errno == EEXIST {
                return Ok(());
            }
            if errno == ESRCH {
                return Ok(());
            }
            return Err(format!(
                "netlink error errno={errno} ({})",
                IoError::from_raw_os_error(errno)
            ));
        }
        Ok(())
    }
}

fn parse_nlmsg_error(resp: &[u8]) -> Result<i32, String> {
    let hdr_sz = size_of::<NlMsgHdr>();
    if resp.len() < hdr_sz + size_of::<i32>() {
        return Err("truncated NLMSG_ERROR response".into());
    }
    let err = i32::from_ne_bytes([
        resp[hdr_sz],
        resp[hdr_sz + 1],
        resp[hdr_sz + 2],
        resp[hdr_sz + 3],
    ]);
    Ok(err)
}

fn push_struct<T: Copy>(buf: &mut Vec<u8>, val: &T) {
    let bytes = unsafe { std::slice::from_raw_parts((val as *const T).cast::<u8>(), size_of::<T>()) };
    buf.extend_from_slice(bytes);
}

fn push_rtattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let rta_len = (size_of::<RtAttr>() + payload.len()) as u16;
    let hdr = RtAttr {
        rta_len,
        rta_type: attr_type,
    };
    push_struct(buf, &hdr);
    buf.extend_from_slice(payload);
    let padded = (buf.len() + 3) & !3;
    buf.resize(padded, 0);
}

fn resolve_local_ip_via_udp(remote: Ipv4Addr, bind_ifname: Option<&str>) -> Result<Ipv4Addr, String> {
    let raw_fd = unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(format!("UDP route probe socket failed: {}", IoError::last_os_error()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    if let Some(ifname) = bind_ifname {
        if !ifname.is_empty() && ifname.len() <= 15 {
            let mut c_if = [0u8; 16];
            c_if[..ifname.len()].copy_from_slice(ifname.as_bytes());
            unsafe {
                let _ = setsockopt(
                    fd.as_raw_fd(),
                    SOL_SOCKET,
                    SO_BINDTODEVICE,
                    c_if.as_ptr().cast(),
                    (ifname.len() + 1) as c_uint,
                );
            }
        }
    }
    let remote_addr = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: 47u16.to_be(),
        sin_addr: remote.octets(),
        sin_zero: [0u8; 8],
    };
    let rc = unsafe {
        connect(
            fd.as_raw_fd(),
            (&remote_addr as *const SockAddrIn).cast(),
            size_of::<SockAddrIn>() as c_uint,
        )
    };
    if rc < 0 {
        return Err(format!(
            "failed to probe local source IP toward {remote}: {}",
            IoError::last_os_error()
        ));
    }
    let mut local_addr: SockAddrIn = unsafe { zeroed() };
    let mut addrlen = size_of::<SockAddrIn>() as c_uint;
    let rc = unsafe {
        getsockname(
            fd.as_raw_fd(),
            (&mut local_addr as *mut SockAddrIn).cast(),
            &mut addrlen,
        )
    };
    if rc < 0 {
        return Err(format!("getsockname failed: {}", IoError::last_os_error()));
    }
    Ok(Ipv4Addr::from(local_addr.sin_addr))
}

#[derive(Clone, Debug)]
struct DumpedRoute {
    family: u8,
    dst_len: u8,
    protocol: u8,
    scope: u8,
    dst_bytes: Vec<u8>,
    oif: u32,
    gateway: Vec<u8>,
    prefsrc_v4: Option<Ipv4Addr>,
    priority: u32,
}

fn dump_main_routes(nl: &mut NetlinkSocket, family: u8) -> Result<Vec<DumpedRoute>, String> {
    let mut req = Vec::with_capacity(64);
    let hdr = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_GETROUTE,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    push_struct(&mut req, &hdr);
    let rtmsg = RtMsg {
        rtm_family: family,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: 0,
        rtm_flags: 0,
    };
    push_struct(&mut req, &rtmsg);
    let raw = nl.send_and_dump(&mut req)?;
    Ok(parse_dumped_routes(&raw))
}

fn parse_dumped_routes(raw: &[u8]) -> Vec<DumpedRoute> {
    let mut out = Vec::new();
    let mut msg_off = 0usize;
    while msg_off + size_of::<NlMsgHdr>() + size_of::<RtMsg>() <= raw.len() {
        let nh = unsafe { std::ptr::read_unaligned(raw[msg_off..].as_ptr() as *const NlMsgHdr) };
        let mlen = nh.nlmsg_len as usize;
        if mlen < size_of::<NlMsgHdr>() + size_of::<RtMsg>() || msg_off + mlen > raw.len() {
            break;
        }
        if nh.nlmsg_type == RTM_NEWROUTE {
            let rtm = unsafe {
                std::ptr::read_unaligned(
                    raw[msg_off + size_of::<NlMsgHdr>()..].as_ptr() as *const RtMsg,
                )
            };
            let mut table = rtm.rtm_table as u32;
            let mut oif = 0u32;
            let mut dst_bytes = Vec::new();
            let mut gateway = Vec::new();
            let mut prefsrc_v4 = None;
            let mut priority = 0u32;
            let mut multipath_legs: Vec<(u32, Vec<u8>)> = Vec::new();

            let mut aoff = msg_off + size_of::<NlMsgHdr>() + size_of::<RtMsg>();
            let mend = msg_off + mlen;
            while aoff + size_of::<RtAttr>() <= mend {
                let rta = unsafe { std::ptr::read_unaligned(raw[aoff..].as_ptr() as *const RtAttr) };
                let alen = rta.rta_len as usize;
                if alen < size_of::<RtAttr>() || aoff + alen > mend {
                    break;
                }
                let p = &raw[aoff + size_of::<RtAttr>()..aoff + alen];
                match rta.rta_type {
                    RTA_TABLE if p.len() >= 4 => {
                        table = u32::from_ne_bytes([p[0], p[1], p[2], p[3]]);
                    }
                    RTA_OIF if p.len() >= 4 => {
                        oif = u32::from_ne_bytes([p[0], p[1], p[2], p[3]]);
                    }
                    RTA_DST => {
                        dst_bytes = p.to_vec();
                    }
                    RTA_GATEWAY => {
                        gateway = p.to_vec();
                    }
                    RTA_PREFSRC if p.len() >= 4 && rtm.rtm_family == AF_INET as u8 => {
                        prefsrc_v4 = Some(Ipv4Addr::new(p[0], p[1], p[2], p[3]));
                    }
                    RTA_PRIORITY if p.len() >= 4 => {
                        priority = u32::from_ne_bytes([p[0], p[1], p[2], p[3]]);
                    }
                    RTA_MULTIPATH => {
                        let mut nh_off = 0usize;
                        while nh_off + size_of::<RtNexthop>() <= p.len() {
                            let nh = unsafe {
                                std::ptr::read_unaligned(p[nh_off..].as_ptr() as *const RtNexthop)
                            };
                            let nh_len = nh.rtnh_len as usize;
                            if nh_len < size_of::<RtNexthop>() || nh_off + nh_len > p.len() {
                                break;
                            }
                            if (nh.rtnh_flags & (RTNH_F_DEAD | RTNH_F_LINKDOWN)) == 0
                                && nh.rtnh_ifindex > 0
                            {
                                let mut nh_gw = Vec::new();
                                let mut sub_off = nh_off + size_of::<RtNexthop>();
                                let sub_end = nh_off + nh_len;
                                while sub_off + size_of::<RtAttr>() <= sub_end {
                                    let srta = unsafe {
                                        std::ptr::read_unaligned(
                                            p[sub_off..].as_ptr() as *const RtAttr
                                        )
                                    };
                                    let salen = srta.rta_len as usize;
                                    if salen < size_of::<RtAttr>() || sub_off + salen > sub_end {
                                        break;
                                    }
                                    if srta.rta_type == RTA_GATEWAY {
                                        nh_gw = p[sub_off + size_of::<RtAttr>()..sub_off + salen]
                                            .to_vec();
                                    }
                                    sub_off += ((salen + 3) & !3).max(size_of::<RtAttr>());
                                }
                                multipath_legs.push((nh.rtnh_ifindex as u32, nh_gw));
                            }
                            nh_off += (nh_len + 3) & !3;
                        }
                    }
                    _ => {}
                }
                let aligned = (alen + 3) & !3;
                aoff += aligned.max(size_of::<RtAttr>());
            }

            if rtm.rtm_type == RTN_UNICAST && table == RT_TABLE_MAIN as u32 {
                if !multipath_legs.is_empty() && oif == 0 {
                    for (nh_oif, nh_gw) in multipath_legs {
                        out.push(DumpedRoute {
                            family: rtm.rtm_family,
                            dst_len: rtm.rtm_dst_len,
                            protocol: rtm.rtm_protocol,
                            scope: rtm.rtm_scope,
                            dst_bytes: dst_bytes.clone(),
                            oif: nh_oif,
                            gateway: nh_gw,
                            prefsrc_v4,
                            priority,
                        });
                    }
                } else {
                    out.push(DumpedRoute {
                        family: rtm.rtm_family,
                        dst_len: rtm.rtm_dst_len,
                        protocol: rtm.rtm_protocol,
                        scope: rtm.rtm_scope,
                        dst_bytes,
                        oif,
                        gateway,
                        prefsrc_v4,
                        priority,
                    });
                }
            }
        }
        msg_off += (mlen + 3) & !3;
    }
    out
}

fn find_first_ipv4_on_ifindex(nl: &mut NetlinkSocket, target_ifindex: u32) -> Option<Ipv4Addr> {
    let mut req = Vec::with_capacity(64);
    let hdr = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_GETADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    push_struct(&mut req, &hdr);
    let ifa = IfAddrMsg {
        ifa_family: AF_INET as u8,
        ifa_prefixlen: 0,
        ifa_flags: 0,
        ifa_scope: 0,
        ifa_index: 0,
    };
    push_struct(&mut req, &ifa);
    let raw = nl.send_and_dump(&mut req).ok()?;
    let mut off = 0usize;
    while off + size_of::<NlMsgHdr>() + size_of::<IfAddrMsg>() <= raw.len() {
        let nh = unsafe { std::ptr::read_unaligned(raw[off..].as_ptr() as *const NlMsgHdr) };
        let mlen = nh.nlmsg_len as usize;
        if mlen < size_of::<NlMsgHdr>() + size_of::<IfAddrMsg>() || off + mlen > raw.len() {
            break;
        }
        if nh.nlmsg_type == RTM_NEWADDR {
            let msg = unsafe {
                std::ptr::read_unaligned(
                    raw[off + size_of::<NlMsgHdr>()..].as_ptr() as *const IfAddrMsg,
                )
            };
            if msg.ifa_index == target_ifindex {
                let mut aoff = off + size_of::<NlMsgHdr>() + size_of::<IfAddrMsg>();
                let mend = off + mlen;
                while aoff + size_of::<RtAttr>() <= mend {
                    let rta =
                        unsafe { std::ptr::read_unaligned(raw[aoff..].as_ptr() as *const RtAttr) };
                    let alen = rta.rta_len as usize;
                    if alen < size_of::<RtAttr>() || aoff + alen > mend {
                        break;
                    }
                    let p = &raw[aoff + size_of::<RtAttr>()..aoff + alen];
                    if matches!(rta.rta_type, IFA_LOCAL | IFA_ADDRESS) && p.len() >= 4 {
                        let ip = Ipv4Addr::new(p[0], p[1], p[2], p[3]);
                        if !ip.is_unspecified() && !ip.is_loopback() {
                            return Some(ip);
                        }
                    }
                    let aligned = (alen + 3) & !3;
                    aoff += aligned.max(size_of::<RtAttr>());
                }
            }
        }
        off += (mlen + 3) & !3;
    }
    None
}

/// Remove leftover `RTPROT_EASYGRE` bypass routes belonging ONLY to dead (`SIGKILL`ed) EasyGRE
/// instance slots, leaving all routes owned by live sibling containers/processes intact.
pub fn cleanup_stale_easygre_routes(lease: &InstanceLease, legacy_status_orphan: bool) {
    let Ok(mut nl) = NetlinkSocket::open() else {
        return;
    };
    let no_other_live_instances = if legacy_status_orphan {
        (1..=MAX_INSTANCE_SLOTS).all(|s| s == lease.slot || is_instance_slot_free(s))
    } else {
        false
    };
    for family in [AF_INET as u8, AF_INET6 as u8] {
        let Ok(routes) = dump_main_routes(&mut nl, family) else {
            continue;
        };
        for r in routes {
            if r.protocol != RTPROT_EASYGRE {
                continue;
            }
            let is_dead_slot_route = if r.priority > BYPASS_METRIC_BASE
                && r.priority <= BYPASS_METRIC_BASE + MAX_INSTANCE_SLOTS
            {
                let route_slot = r.priority - BYPASS_METRIC_BASE;
                route_slot == lease.slot || is_instance_slot_free(route_slot)
            } else if r.priority == 0
                && r.family == AF_INET as u8
                && r.dst_len == 32
                && no_other_live_instances
            {
                true
            } else {
                // Never delete priority=0 tunnel routes; kernel auto-cleans TUN routes on fd close,
                // so any existing priority=0 route belongs to a live sibling EasyGRE TUN device.
                false
            };
            if !is_dead_slot_route {
                continue;
            }
            let mut buf = Vec::with_capacity(128);
            let hdr = NlMsgHdr {
                nlmsg_len: 0,
                nlmsg_type: RTM_DELROUTE,
                nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            };
            push_struct(&mut buf, &hdr);
            let rtmsg = RtMsg {
                rtm_family: r.family,
                rtm_dst_len: r.dst_len,
                rtm_src_len: 0,
                rtm_tos: 0,
                rtm_table: RT_TABLE_MAIN,
                rtm_protocol: RTPROT_EASYGRE,
                rtm_scope: r.scope,
                rtm_type: RTN_UNICAST,
                rtm_flags: 0,
            };
            push_struct(&mut buf, &rtmsg);
            if r.dst_len > 0 && !r.dst_bytes.is_empty() {
                push_rtattr(&mut buf, RTA_DST, &r.dst_bytes);
            }
            if r.oif > 0 {
                push_rtattr(&mut buf, RTA_OIF, &r.oif.to_ne_bytes());
            }
            if r.priority > 0 {
                push_rtattr(&mut buf, RTA_PRIORITY, &r.priority.to_ne_bytes());
            }
            if !r.gateway.is_empty() {
                push_rtattr(&mut buf, RTA_GATEWAY, &r.gateway);
            }
            let _ = nl.send_ack(&mut buf, true);
        }
    }
}

fn ifindex_to_name(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; 16];
    let ptr = unsafe { if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
    if ptr.is_null() {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

fn probe_route_direct(
    nl: &mut NetlinkSocket,
    remote: Ipv4Addr,
    local_override: Option<Ipv4Addr>,
) -> Result<RouteProbeResult, String> {
    let mut buf = Vec::with_capacity(128);
    let hdr = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_GETROUTE,
        nlmsg_flags: NLM_F_REQUEST,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    push_struct(&mut buf, &hdr);
    let rtmsg = RtMsg {
        rtm_family: AF_INET as u8,
        rtm_dst_len: 32,
        rtm_src_len: if local_override.is_some() { 32 } else { 0 },
        rtm_tos: 0,
        rtm_table: 0,
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: 0,
        rtm_flags: 0,
    };
    push_struct(&mut buf, &rtmsg);
    push_rtattr(&mut buf, RTA_DST, &remote.octets());
    if let Some(src) = local_override {
        push_rtattr(&mut buf, RTA_SRC, &src.octets());
    }

    let resp = nl.send_and_recv(&mut buf)?;
    if resp.len() < size_of::<NlMsgHdr>() {
        return Err("empty RTM_GETROUTE response".into());
    }
    let r_hdr = unsafe { std::ptr::read_unaligned(resp.as_ptr() as *const NlMsgHdr) };
    if r_hdr.nlmsg_type == NLMSG_ERROR {
        let err_code = parse_nlmsg_error(&resp)?;
        let errno = -err_code;
        return Err(format!(
            "route lookup for {remote} failed: errno={errno} ({})",
            IoError::from_raw_os_error(errno)
        ));
    }
    if r_hdr.nlmsg_type != RTM_NEWROUTE || resp.len() < size_of::<NlMsgHdr>() + size_of::<RtMsg>() {
        return Err("unexpected netlink response to RTM_GETROUTE".into());
    }

    let msg_end = (r_hdr.nlmsg_len as usize).min(resp.len());
    let mut off = size_of::<NlMsgHdr>() + size_of::<RtMsg>();
    let mut out_ifindex = 0u32;
    let mut prefsrc: Option<Ipv4Addr> = None;
    let mut gateway: Option<Ipv4Addr> = None;

    while off + size_of::<RtAttr>() <= msg_end {
        let rta = unsafe { std::ptr::read_unaligned(resp[off..].as_ptr() as *const RtAttr) };
        let rta_len = rta.rta_len as usize;
        if rta_len < size_of::<RtAttr>() || off + rta_len > msg_end {
            break;
        }
        let payload = &resp[off + size_of::<RtAttr>()..off + rta_len];
        match rta.rta_type {
            RTA_OIF if payload.len() >= 4 => {
                out_ifindex = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            RTA_PREFSRC if payload.len() >= 4 => {
                prefsrc = Some(Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]));
            }
            RTA_GATEWAY if payload.len() >= 4 => {
                gateway = Some(Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]));
            }
            _ => {}
        }
        let aligned = (rta_len + 3) & !3;
        off += aligned.max(size_of::<RtAttr>());
    }

    let local_ip = match local_override {
        Some(ip) => ip,
        None => match prefsrc {
            Some(ip) => ip,
            None => resolve_local_ip_via_udp(remote, None)?,
        },
    };

    let out_ifname = if out_ifindex > 0 {
        ifindex_to_name(out_ifindex).unwrap_or_else(|| format!("if{out_ifindex}"))
    } else {
        "unknown".into()
    };
    let out_mtu = if out_ifindex > 0 && out_ifname != "unknown" {
        get_interface_mtu(&out_ifname).unwrap_or(1500)
    } else {
        1500
    };

    Ok(RouteProbeResult {
        local_ip,
        out_ifindex,
        out_ifname,
        out_mtu,
        gateway,
    })
}

/// Probe physical egress route toward `remote`, automatically excluding both caller-supplied
/// TUN `ifindices` and any interface carrying `RTPROT_EASYGRE` tunnel routes (including sibling
/// EasyGRE instances' `/1` routes), so startup and DDNS lookups always resolve physical egress.
pub fn probe_route_excluding(
    remote: Ipv4Addr,
    local_override: Option<Ipv4Addr>,
    excluded_ifindices: &[u32],
) -> Result<RouteProbeResult, String> {
    let mut nl = NetlinkSocket::open()?;
    let routes = dump_main_routes(&mut nl, AF_INET as u8)?;
    if let Ok(direct) = probe_route_direct(&mut nl, remote, local_override) {
        let hit_easygre_tun = routes.iter().any(|r| {
            r.protocol == RTPROT_EASYGRE && r.priority == 0 && r.oif == direct.out_ifindex
        });
        if direct.out_ifindex > 0
            && !excluded_ifindices.contains(&direct.out_ifindex)
            && !hit_easygre_tun
        {
            return Ok(direct);
        }
    } else if excluded_ifindices.is_empty()
        && !routes.iter().any(|r| r.protocol == RTPROT_EASYGRE && r.priority == 0)
    {
        return probe_route_direct(&mut nl, remote, local_override);
    }

    let remote_u32 = u32::from(remote);
    let mut best: Option<&DumpedRoute> = None;
    for r in &routes {
        if r.oif == 0 || excluded_ifindices.contains(&r.oif) || r.protocol == RTPROT_EASYGRE {
            continue;
        }
        if r.dst_len > 32 {
            continue;
        }
        let dst_ip = if r.dst_len == 0 || r.dst_bytes.is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else if r.dst_bytes.len() >= 4 {
            Ipv4Addr::new(r.dst_bytes[0], r.dst_bytes[1], r.dst_bytes[2], r.dst_bytes[3])
        } else {
            continue;
        };
        let mask = if r.dst_len == 0 {
            0u32
        } else {
            u32::MAX << (32 - r.dst_len)
        };
        if (remote_u32 & mask) != (u32::from(dst_ip) & mask) {
            continue;
        }
        let replace = match best {
            None => true,
            Some(cur) => {
                r.dst_len > cur.dst_len
                    || (r.dst_len == cur.dst_len && r.priority < cur.priority)
            }
        };
        if replace {
            best = Some(r);
        }
    }

    let Some(win) = best else {
        return Err(format!(
            "no physical route toward {remote} found outside tunnel interfaces"
        ));
    };
    let out_ifindex = win.oif;
    let gateway = if win.gateway.len() >= 4 {
        Some(Ipv4Addr::new(
            win.gateway[0],
            win.gateway[1],
            win.gateway[2],
            win.gateway[3],
        ))
    } else {
        None
    };
    let out_ifname = ifindex_to_name(out_ifindex).unwrap_or_else(|| format!("if{out_ifindex}"));
    let out_mtu = get_interface_mtu(&out_ifname).unwrap_or(1500);
    let local_ip = match local_override {
        Some(ip) => ip,
        None => match win.prefsrc_v4 {
            Some(ip) => ip,
            None => resolve_local_ip_via_udp(gateway.unwrap_or(remote), Some(&out_ifname))
                .or_else(|_| {
                    find_first_ipv4_on_ifindex(&mut nl, out_ifindex).ok_or_else(|| {
                        format!("failed to determine source IPv4 on interface '{out_ifname}'")
                    })
                })?,
        },
    };

    Ok(RouteProbeResult {
        local_ip,
        out_ifindex,
        out_ifname,
        out_mtu,
        gateway,
    })
}

pub fn configure_interface_addr(ifindex: u32, cidr: &IpCidr) -> Result<(), String> {
    let mut nl = NetlinkSocket::open()?;
    let mut buf = Vec::with_capacity(96);
    let hdr = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type: RTM_NEWADDR,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    push_struct(&mut buf, &hdr);
    match cidr {
        IpCidr::V4 { addr, prefix_len } => {
            let ifa = IfAddrMsg {
                ifa_family: AF_INET as u8,
                ifa_prefixlen: *prefix_len,
                ifa_flags: 0,
                ifa_scope: RT_SCOPE_UNIVERSE,
                ifa_index: ifindex,
            };
            push_struct(&mut buf, &ifa);
            push_rtattr(&mut buf, IFA_LOCAL, &addr.octets());
            push_rtattr(&mut buf, IFA_ADDRESS, &addr.octets());
        }
        IpCidr::V6 { addr, prefix_len } => {
            let ifa = IfAddrMsg {
                ifa_family: AF_INET6 as u8,
                ifa_prefixlen: *prefix_len,
                ifa_flags: 0,
                ifa_scope: RT_SCOPE_UNIVERSE,
                ifa_index: ifindex,
            };
            push_struct(&mut buf, &ifa);
            push_rtattr(&mut buf, IFA_LOCAL, &addr.octets());
            push_rtattr(&mut buf, IFA_ADDRESS, &addr.octets());
        }
    }
    nl.send_ack(&mut buf, true)
}

fn build_route_nlmsg(
    nlmsg_type: u16,
    nlmsg_flags: u16,
    ifindex: u32,
    dst: &IpCidr,
    gateway: &RouteGateway,
    priority: Option<u32>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    let hdr = NlMsgHdr {
        nlmsg_len: 0,
        nlmsg_type,
        nlmsg_flags,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    };
    push_struct(&mut buf, &hdr);

    let (family, dst_len, dst_bytes): (u8, u8, Vec<u8>) = match dst {
        IpCidr::V4 { addr, prefix_len } => {
            let mask = if *prefix_len == 0 {
                0u32
            } else {
                u32::MAX << (32 - *prefix_len)
            };
            let net = Ipv4Addr::from(u32::from(*addr) & mask);
            (AF_INET as u8, *prefix_len, net.octets().to_vec())
        }
        IpCidr::V6 { addr, prefix_len } => {
            let mask = if *prefix_len == 0 {
                0u128
            } else {
                u128::MAX << (128 - *prefix_len)
            };
            let net = Ipv6Addr::from(u128::from(*addr) & mask);
            (AF_INET6 as u8, *prefix_len, net.octets().to_vec())
        }
    };

    let scope = match (gateway, family as c_int) {
        (RouteGateway::Via(_), _) => RT_SCOPE_UNIVERSE,
        (RouteGateway::InterfaceOnly, AF_INET) => RT_SCOPE_LINK,
        (RouteGateway::InterfaceOnly, _) => RT_SCOPE_UNIVERSE,
    };

    let rtmsg = RtMsg {
        rtm_family: family,
        rtm_dst_len: dst_len,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_EASYGRE,
        rtm_scope: scope,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    };
    push_struct(&mut buf, &rtmsg);

    if dst_len > 0 {
        push_rtattr(&mut buf, RTA_DST, &dst_bytes);
    }
    push_rtattr(&mut buf, RTA_OIF, &ifindex.to_ne_bytes());
    if let Some(prio) = priority {
        push_rtattr(&mut buf, RTA_PRIORITY, &prio.to_ne_bytes());
    }
    if let RouteGateway::Via(gw) = gateway {
        match gw {
            IpAddr::V4(v4) => push_rtattr(&mut buf, RTA_GATEWAY, &v4.octets()),
            IpAddr::V6(v6) => push_rtattr(&mut buf, RTA_GATEWAY, &v6.octets()),
        }
    }
    buf
}

/// Install static route(s) for a tunnel without overwriting host-owned routes:
/// - `0.0.0.0/0` is expanded to `0.0.0.0/1` + `128.0.0.0/1` (and `::/0` to `::/1` + `8000::/1`)
///   so the host's original default route remains intact in `main` at all times.
/// - Uses `NLM_F_CREATE | NLM_F_EXCL` with `RTPROT_EASYGRE` so conflicting host routes fail safely.
pub fn configure_route(ifindex: u32, route: &RouteSpec) -> Result<Vec<InstalledRoute>, String> {
    let mut nl = NetlinkSocket::open()?;
    let expanded: Vec<IpCidr> = match route.dst {
        IpCidr::V4 { prefix_len: 0, .. } => vec![
            IpCidr::V4 {
                addr: Ipv4Addr::new(0, 0, 0, 0),
                prefix_len: 1,
            },
            IpCidr::V4 {
                addr: Ipv4Addr::new(128, 0, 0, 0),
                prefix_len: 1,
            },
        ],
        IpCidr::V6 { prefix_len: 0, .. } => vec![
            IpCidr::V6 {
                addr: Ipv6Addr::UNSPECIFIED,
                prefix_len: 1,
            },
            IpCidr::V6 {
                addr: Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0),
                prefix_len: 1,
            },
        ],
        ref other => vec![other.clone()],
    };

    let mut installed = Vec::with_capacity(expanded.len());
    for cidr in expanded {
        let mut msg = build_route_nlmsg(
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            ifindex,
            &cidr,
            &route.gateway,
            None,
        );
        match nl.send_ack_errno(&mut msg) {
            Ok(()) => {
                installed.push(InstalledRoute {
                    dst: cidr,
                    gateway: route.gateway.clone(),
                    ifindex,
                });
            }
            Err(errno) if errno == EEXIST => {
                for prev in &installed {
                    remove_installed_route(prev);
                }
                return Err(format!(
                    "route {cidr} conflicts with an existing route in main table (refusing to overwrite host route)"
                ));
            }
            Err(errno) => {
                for prev in &installed {
                    remove_installed_route(prev);
                }
                return Err(format!(
                    "failed to install route {cidr}: errno={errno} ({})",
                    IoError::from_raw_os_error(errno)
                ));
            }
        }
    }
    Ok(installed)
}

pub fn remove_installed_route(route: &InstalledRoute) {
    if let Ok(mut nl) = NetlinkSocket::open() {
        let mut msg = build_route_nlmsg(
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            route.ifindex,
            &route.dst,
            &route.gateway,
            None,
        );
        let _ = nl.send_ack(&mut msg, true);
    }
}

/// Install a `/32` bypass route for `dst_ip` if no host-owned `/32` route already exists.
/// Uses per-instance `metric` (`19800 + slot`) so concurrent EasyGRE instances never overwrite
/// or steal each other's `/32` bypass routes.
/// Returns `Ok(true)` if EasyGRE created/owns the `/32` route (and should delete it on cleanup),
/// or `Ok(false)` if a pre-existing host `/32` route was left untouched.
pub fn install_host_bypass_route(
    dst_ip: Ipv4Addr,
    out_ifindex: u32,
    gateway: Option<Ipv4Addr>,
    metric: u32,
) -> Result<bool, String> {
    if out_ifindex == 0 {
        return Err("cannot install bypass route without output interface index".into());
    }
    let mut nl = NetlinkSocket::open()?;
    let existing = dump_main_routes(&mut nl, AF_INET as u8).unwrap_or_default();
    let host_owned_exists = existing.iter().any(|r| {
        r.dst_len == 32
            && r.dst_bytes.len() >= 4
            && r.dst_bytes[..4] == dst_ip.octets()
            && r.protocol != RTPROT_EASYGRE
    });
    if host_owned_exists {
        return Ok(false);
    }

    let gw_spec = match gateway {
        Some(gw) => RouteGateway::Via(IpAddr::V4(gw)),
        None => RouteGateway::InterfaceOnly,
    };
    let dst_cidr = IpCidr::V4 {
        addr: dst_ip,
        prefix_len: 32,
    };
    let mut excl_msg = build_route_nlmsg(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        out_ifindex,
        &dst_cidr,
        &gw_spec,
        Some(metric),
    );
    match nl.send_ack_errno(&mut excl_msg) {
        Ok(()) => Ok(true),
        Err(errno) if errno == EEXIST => Err(format!(
            "bypass route {dst_ip}/32 metric {metric} already exists in main table (refusing to overwrite)"
        )),
        Err(errno) => Err(format!(
            "failed to install bypass route {dst_ip}/32: errno={errno} ({})",
            IoError::from_raw_os_error(errno)
        )),
    }
}

pub fn remove_host_bypass_route(
    dst_ip: Ipv4Addr,
    out_ifindex: u32,
    gateway: Option<Ipv4Addr>,
    metric: u32,
) {
    if out_ifindex == 0 {
        return;
    }
    let Ok(mut nl) = NetlinkSocket::open() else {
        return;
    };
    let gw_spec = match gateway {
        Some(gw) => RouteGateway::Via(IpAddr::V4(gw)),
        None => RouteGateway::InterfaceOnly,
    };
    let dst_cidr = IpCidr::V4 {
        addr: dst_ip,
        prefix_len: 32,
    };
    let mut del_msg = build_route_nlmsg(
        RTM_DELROUTE,
        NLM_F_REQUEST | NLM_F_ACK,
        out_ifindex,
        &dst_cidr,
        &gw_spec,
        Some(metric),
    );
    let _ = nl.send_ack(&mut del_msg, true);
}

pub fn detect_system_warnings(routes_configured: bool, fast_path_enabled: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Ok(modules) = fs::read_to_string("/proc/modules") {
        if modules.lines().any(|l| l.starts_with("ip_gre ") || l.starts_with("gre ")) {
            warnings.push(
                "kernel module ip_gre/gre is loaded (~20% extra kernel CPU in gre_rcv/icmp_send); if unused, run 'modprobe -r ip_gre gre'".into(),
            );
        }
    }
    if routes_configured {
        if let Ok(fwd) = fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            if fwd.trim() == "0" {
                warnings.push(
                    "net.ipv4.ip_forward is 0; if routing traffic for other hosts/subnets through EasyGRE, enable ip_forward on the host".into(),
                );
            }
        }
    }
    if fast_path_enabled {
        if let Ok(nat_mod) = fs::read_to_string("/proc/modules") {
            if nat_mod.lines().any(|l| l.starts_with("nf_nat ")) {
                warnings.push(
                    "AF_PACKET fast-path bypasses host netfilter/qdisc on outer GRE frames; if host SNAT/firewall/tc rules apply to outer GRE traffic, set GRE_TX_MODE=raw or --no-allow-fast-path".into(),
                );
            }
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_abi_struct_sizes() {
        assert_eq!(size_of::<IfReq>(), 40);
        assert_eq!(size_of::<SockAddrIn>(), 16);
        assert_eq!(size_of::<SockAddrUn>(), 110);
        assert_eq!(size_of::<SockAddrNl>(), 12);
        assert_eq!(size_of::<TimeSpec>(), 16);
        assert_eq!(size_of::<NlMsgHdr>(), 16);
        assert_eq!(size_of::<NlMsgErr>(), 20);
        assert_eq!(size_of::<IfAddrMsg>(), 8);
        assert_eq!(size_of::<RtMsg>(), 12);
        assert_eq!(size_of::<RtAttr>(), 4);
        assert_eq!(size_of::<RtNexthop>(), 8);
        assert_eq!(size_of::<SockFilter>(), 8);
        assert_eq!(size_of::<SockFprog>(), 16);
        assert_eq!(size_of::<SockAddrLl>(), 20);
        assert_eq!(size_of::<TpacketReq>(), 16);
        assert_eq!(size_of::<Tpacket2Hdr>(), 32);
        assert_eq!(size_of::<IoVec>(), 16);
        assert_eq!(size_of::<MsgHdr>(), 56);
        assert_eq!(size_of::<MMsgHdr>(), 64);
        assert_eq!(size_of::<IoSqringOffsets>(), 40);
        assert_eq!(size_of::<IoCqringOffsets>(), 40);
        assert_eq!(size_of::<IoUringParams>(), 120);
        assert_eq!(size_of::<IoUringSqe>(), 64);
        assert_eq!(size_of::<IoUringCqe>(), 16);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(size_of::<EpollEvent>(), 12);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(size_of::<EpollEvent>(), 16);
    }

    #[test]
    fn test_parse_nlmsg_error_offset() {
        let mut pkt = vec![0u8; size_of::<NlMsgHdr>() + size_of::<NlMsgErr>()];
        let pkt_len = pkt.len() as u32;
        pkt[0..4].copy_from_slice(&pkt_len.to_ne_bytes());
        pkt[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        // Real error field starts at offset 16 (after outer NlMsgHdr)
        pkt[16..20].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(parse_nlmsg_error(&pkt).unwrap(), 0);

        pkt[16..20].copy_from_slice(&(-EEXIST).to_ne_bytes());
        assert_eq!(parse_nlmsg_error(&pkt).unwrap(), -EEXIST);
    }

    #[test]
    fn test_arp_parser_skips_malformed_lines_and_fuzz_netlink_routes() {
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
malformed_single_col
192.0.2.10       0x1         0x2         00:11:22:33
192.0.2.2        0x1         0x0         aa:bb:cc:dd:ee:ff     *        eth0
192.0.2.2        0x1         0x2         02:42:ac:11:00:02     *        eth0
";
        assert_eq!(
            parse_arp_table_mac(arp, Ipv4Addr::new(192, 0, 2, 2), "eth0"),
            Some([0x02, 0x42, 0xac, 0x11, 0x00, 0x02])
        );

        let mut rng = 0x4e4c_4655_5a5a_3031u64;
        let mut buf = [0u8; 384];
        for i in 0..10_000usize {
            rng = rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            let seed = z ^ (z >> 31);
            let len = (seed as usize) % (buf.len() + 1);
            for (idx, b) in buf[..len].iter_mut().enumerate() {
                *b = seed.wrapping_mul((idx as u64) + 131).swap_bytes() as u8;
            }
            if (i & 1) == 0 && len >= 36 {
                // Force RTM_NEWROUTE header with adversarial attribute/multipath lengths
                let mlen = (len as u32).to_ne_bytes();
                buf[0..4].copy_from_slice(&mlen);
                buf[4..6].copy_from_slice(&RTM_NEWROUTE.to_ne_bytes());
                buf[16] = AF_INET as u8;
                buf[20] = RT_TABLE_MAIN;
                buf[23] = RTN_UNICAST;
            }
            let _ = parse_dumped_routes(&buf[..len]);
            let _ = parse_nlmsg_error(&buf[..len]);
        }
    }
}
