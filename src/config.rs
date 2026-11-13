use std::collections::{BTreeMap, HashSet};
use std::env;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use crate::keepalive::KeepaliveConfig;
use crate::packet::{is_valid_unicast_ipv4, IpCidr};

pub const DEFAULT_STATUS_FILE: &str = "/run/easygre/status";

pub fn default_status_file() -> String {
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/run").is_dir() {
            return DEFAULT_STATUS_FILE.to_string();
        }
    }
    "/tmp/easygre.status".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuMode {
    Auto,
    Fixed(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DscpMode {
    Inherit,
    Fixed(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DontFragmentMode {
    No,
    Inherit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxMode {
    Auto,
    Mmap,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueMode {
    Auto,
    Fixed(usize),
}

impl QueueMode {
    pub fn resolve(self) -> usize {
        match self {
            QueueMode::Fixed(n) => n,
            QueueMode::Auto => std::thread::available_parallelism()
                .map(|p| p.get().clamp(1, 8))
                .unwrap_or(2),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteGateway {
    InterfaceOnly,
    Via(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSpec {
    pub dst: IpCidr,
    pub gateway: RouteGateway,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEndpoint {
    Ip(Ipv4Addr),
    Host(String),
}

impl RemoteEndpoint {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("remote address cannot be empty".into());
        }
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            if !is_valid_unicast_ipv4(ip) {
                return Err(format!(
                    "remote address '{ip}' must be a valid routable unicast IPv4 address"
                ));
            }
            return Ok(RemoteEndpoint::Ip(ip));
        }
        if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
            return Err("GRE over IPv6 outer transport is not supported (IPv4 remote-address required)".into());
        }
        if trimmed.contains(char::is_whitespace) || trimmed.contains('/') {
            return Err(format!("invalid remote hostname '{trimmed}'"));
        }
        Ok(RemoteEndpoint::Host(trimmed.to_string()))
    }

    pub fn resolve_ipv4(&self) -> Result<Ipv4Addr, String> {
        match self {
            RemoteEndpoint::Ip(ip) => Ok(*ip),
            RemoteEndpoint::Host(host) => {
                let addrs = (host.as_str(), 0u16)
                    .to_socket_addrs()
                    .map_err(|e| format!("failed to resolve remote '{host}': {e}"))?;
                for addr in addrs {
                    if let IpAddr::V4(v4) = addr.ip() {
                        if is_valid_unicast_ipv4(v4) {
                            return Ok(v4);
                        }
                    }
                }
                Err(format!(
                    "no valid routable unicast IPv4 address found for remote '{host}'"
                ))
            }
        }
    }

    pub fn as_display(&self) -> String {
        match self {
            RemoteEndpoint::Ip(ip) => ip.to_string(),
            RemoteEndpoint::Host(h) => h.clone(),
        }
    }

    pub fn canonical_key(&self) -> String {
        match self {
            RemoteEndpoint::Ip(ip) => ip.to_string(),
            RemoteEndpoint::Host(h) => h.to_ascii_lowercase(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub enabled: bool,
    pub name: String,
    pub comment: Option<String>,
    pub local_address: Option<Ipv4Addr>,
    pub public_ip: Option<Ipv4Addr>,
    pub remote: RemoteEndpoint,
    pub mtu: MtuMode,
    pub keepalive: KeepaliveConfig,
    pub dscp: DscpMode,
    pub dont_fragment: DontFragmentMode,
    pub clamp_tcp_mss: bool,
    pub allow_fast_path: bool,
    pub addresses: Vec<IpCidr>,
    pub routes: Vec<RouteSpec>,
    pub dns_refresh: Duration,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "gre-tunnel1".into(),
            comment: None,
            local_address: None,
            public_ip: None,
            remote: RemoteEndpoint::Ip(Ipv4Addr::new(192, 0, 2, 1)),
            mtu: MtuMode::Auto,
            keepalive: KeepaliveConfig::Enabled {
                interval: Duration::from_secs(10),
                retries: 10,
            },
            dscp: DscpMode::Inherit,
            dont_fragment: DontFragmentMode::No,
            clamp_tcp_mss: true,
            allow_fast_path: true,
            addresses: Vec::new(),
            routes: Vec::new(),
            dns_refresh: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub status_file: String,
    pub tx_mode: TxMode,
    pub queues: QueueMode,
    pub tunnels: Vec<TunnelConfig>,
}

pub fn parse_cli_and_env(args: &[String], env_vars: &BTreeMap<String, String>) -> Result<CliOutcome, String> {
    let mut idx = 1usize;
    let mut explicit_subcmd: Option<&str> = None;
    if let Some(first) = args.get(1) {
        match first.as_str() {
            "run" | "status" | "healthcheck" | "version" | "help" => {
                explicit_subcmd = Some(first.as_str());
                idx = 2;
            }
            "-h" | "--help" => return Ok(CliOutcome::Help),
            "-V" | "--version" => return Ok(CliOutcome::Version),
            _ => {}
        }
    }

    let mut status_file = env_vars
        .get("GRE_STATUS_FILE")
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .unwrap_or_else(default_status_file);

    let mut tx_mode = match env_vars.get("GRE_TX_MODE").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(v) => parse_tx_mode(v)?,
        None => TxMode::Auto,
    };
    let mut queues = match env_vars.get("GRE_QUEUES").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(v) => parse_queues(v)?,
        None => QueueMode::Auto,
    };

    let mut single_cli_fields: BTreeMap<String, String> = BTreeMap::new();
    let mut cli_tunnels: Vec<String> = Vec::new();

    while idx < args.len() {
        let arg = &args[idx];
        match arg.as_str() {
            "-h" | "--help" => return Ok(CliOutcome::Help),
            "-V" | "--version" => return Ok(CliOutcome::Version),
            "--status-file" => {
                idx += 1;
                status_file = take_val(args, idx, "--status-file")?;
            }
            "--tx-mode" => {
                idx += 1;
                tx_mode = parse_tx_mode(&take_val(args, idx, "--tx-mode")?)?;
            }
            "--queues" => {
                idx += 1;
                queues = parse_queues(&take_val(args, idx, "--queues")?)?;
            }
            "--tunnel" => {
                idx += 1;
                cli_tunnels.push(take_val(args, idx, "--tunnel")?);
            }
            _ if arg.starts_with("--") => {
                if let Some((k, v)) = arg[2..].split_once('=') {
                    if k == "status-file" {
                        status_file = v.to_string();
                    } else if k == "tx-mode" {
                        tx_mode = parse_tx_mode(v)?;
                    } else if k == "queues" {
                        queues = parse_queues(v)?;
                    } else if k == "tunnel" {
                        cli_tunnels.push(v.to_string());
                    } else {
                        single_cli_fields.insert(k.to_string(), v.to_string());
                    }
                } else {
                    let key = &arg[2..];
                    if matches!(key, "no-clamp-tcp-mss") {
                        single_cli_fields.insert("clamp-tcp-mss".into(), "false".into());
                    } else if matches!(key, "no-allow-fast-path") {
                        single_cli_fields.insert("allow-fast-path".into(), "false".into());
                    } else if matches!(key, "disabled") {
                        single_cli_fields.insert("enabled".into(), "false".into());
                    } else {
                        idx += 1;
                        let val = take_val(args, idx, arg)?;
                        single_cli_fields.insert(key.to_string(), val);
                    }
                }
            }
            other => return Err(format!("unknown argument '{other}' (see --help)")),
        }
        idx += 1;
    }

    match explicit_subcmd {
        Some("help") => return Ok(CliOutcome::Help),
        Some("version") => return Ok(CliOutcome::Version),
        Some("status") => return Ok(CliOutcome::Status { status_file }),
        Some("healthcheck") => return Ok(CliOutcome::Healthcheck { status_file }),
        _ => {}
    }

    let tunnels = resolve_tunnels(&single_cli_fields, &cli_tunnels, env_vars)?;
    Ok(CliOutcome::Run(AppConfig {
        status_file,
        tx_mode,
        queues,
        tunnels,
    }))
}

#[derive(Debug)]
pub enum CliOutcome {
    Run(AppConfig),
    Status { status_file: String },
    Healthcheck { status_file: String },
    Version,
    Help,
}

fn take_val(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn resolve_tunnels(
    single_cli_fields: &BTreeMap<String, String>,
    cli_tunnels: &[String],
    env_vars: &BTreeMap<String, String>,
) -> Result<Vec<TunnelConfig>, String> {
    let mut tunnels = Vec::new();

    if !cli_tunnels.is_empty() {
        for (i, spec) in cli_tunnels.iter().enumerate() {
            let default_name = format!("gre-tunnel{}", i + 1);
            let kv = parse_tunnel_spec(spec)?;
            tunnels.push(build_tunnel_from_map(&kv, Some(&default_name))?);
        }
    } else if !single_cli_fields.is_empty() {
        let mut merged = collect_single_env_fields(env_vars);
        for (k, v) in single_cli_fields {
            merged.insert(normalize_key(k), v.clone());
        }
        tunnels.push(build_tunnel_from_map(&merged, Some("gre-tunnel1"))?);
    } else if let Some(multi_env) = env_vars.get("GRE_TUNNELS").filter(|s| !s.trim().is_empty()) {
        for (i, part) in multi_env.split(['|', '\n']).enumerate() {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let default_name = format!("gre-tunnel{}", i + 1);
            let kv = parse_tunnel_spec(trimmed)?;
            tunnels.push(build_tunnel_from_map(&kv, Some(&default_name))?);
        }
    } else {
        let numbered = collect_numbered_env_tunnels(env_vars);
        if !numbered.is_empty() {
            for (idx, map) in numbered {
                let default_name = format!("gre-tunnel{idx}");
                tunnels.push(build_tunnel_from_map(&map, Some(&default_name))?);
            }
        } else {
            let single_env = collect_single_env_fields(env_vars);
            if single_env.is_empty() {
                return Err("no tunnel configuration provided (set GRE_REMOTE or pass --remote)".into());
            }
            tunnels.push(build_tunnel_from_map(&single_env, Some("gre-tunnel1"))?);
        }
    }

    let enabled_tunnels: Vec<TunnelConfig> = tunnels.into_iter().filter(|t| t.enabled).collect();
    if enabled_tunnels.is_empty() {
        return Err("all configured tunnels are disabled (enabled=false)".into());
    }

    let mut names = HashSet::new();
    let mut endpoints = HashSet::new();
    for t in &enabled_tunnels {
        if !names.insert(t.name.clone()) {
            return Err(format!("duplicate tunnel interface name '{}'", t.name));
        }
        let ep_key = (t.remote.canonical_key(), t.local_address);
        if !endpoints.insert(ep_key) {
            return Err(format!(
                "duplicate tunnel peer endpoint (remote='{}', local={:?}) on '{}'; unkeyed GRE cannot demultiplex identical endpoints",
                t.remote.as_display(),
                t.local_address,
                t.name
            ));
        }
    }
    Ok(enabled_tunnels)
}

fn collect_single_env_fields(env_vars: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (k, v) in env_vars {
        if let Some(rest) = k.strip_prefix("GRE_") {
            if matches!(rest, "TUNNELS" | "STATUS_FILE" | "TX_MODE" | "QUEUES") {
                continue;
            }
            // Ignore numbered entries like GRE_1_REMOTE
            if let Some((prefix, _)) = rest.split_once('_') {
                if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
            }
            if !v.trim().is_empty() {
                map.insert(normalize_key(rest), v.clone());
            }
        }
    }
    map
}

fn collect_numbered_env_tunnels(env_vars: &BTreeMap<String, String>) -> BTreeMap<usize, BTreeMap<String, String>> {
    let mut grouped: BTreeMap<usize, BTreeMap<String, String>> = BTreeMap::new();
    for (k, v) in env_vars {
        if let Some(rest) = k.strip_prefix("GRE_") {
            if let Some((num_str, field)) = rest.split_once('_') {
                if !num_str.is_empty() && num_str.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(num) = num_str.parse::<usize>() {
                        if !v.trim().is_empty() {
                            grouped
                                .entry(num)
                                .or_default()
                                .insert(normalize_key(field), v.clone());
                        }
                    }
                }
            }
        }
    }
    grouped
}

fn parse_tunnel_spec(spec: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for item in spec.split(';') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (k, v) = trimmed
            .split_once('=')
            .ok_or_else(|| format!("invalid tunnel option '{trimmed}', expected key=value"))?;
        map.insert(normalize_key(k), v.trim().to_string());
    }
    Ok(map)
}

fn normalize_key(k: &str) -> String {
    k.trim().to_ascii_lowercase().replace('_', "-")
}

fn build_tunnel_from_map(
    kv: &BTreeMap<String, String>,
    default_name: Option<&str>,
) -> Result<TunnelConfig, String> {
    let mut cfg = TunnelConfig::default();
    if let Some(n) = default_name {
        cfg.name = n.to_string();
    }

    let mut remote_raw: Option<String> = None;

    for (k, v) in kv {
        match k.as_str() {
            "enabled" => cfg.enabled = parse_bool(v, "enabled")?,
            "name" | "interface" => {
                validate_ifname(v)?;
                cfg.name = v.trim().to_string();
            }
            "comment" => {
                let c = v.trim();
                cfg.comment = if c.is_empty() { None } else { Some(c.to_string()) };
            }
            "local" | "local-address" => {
                let trimmed = v.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") || trimmed == "0.0.0.0" {
                    cfg.local_address = None;
                } else {
                    let ip: Ipv4Addr = trimmed
                        .parse()
                        .map_err(|_| format!("invalid local-address '{trimmed}' (must be IPv4)"))?;
                    if !is_valid_unicast_ipv4(ip) {
                        return Err(format!(
                            "local-address '{ip}' must be a valid routable unicast IPv4 address"
                        ));
                    }
                    cfg.local_address = Some(ip);
                }
            }
            "public-ip" | "public-address" => {
                let trimmed = v.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
                    cfg.public_ip = None;
                } else {
                    let ip: Ipv4Addr = trimmed
                        .parse()
                        .map_err(|_| format!("invalid public-ip '{trimmed}' (must be IPv4)"))?;
                    if !is_valid_unicast_ipv4(ip) {
                        return Err(format!(
                            "public-ip '{ip}' must be a valid routable unicast IPv4 address"
                        ));
                    }
                    cfg.public_ip = Some(ip);
                }
            }
            "remote" | "remote-address" => {
                remote_raw = Some(v.trim().to_string());
            }
            "mtu" => cfg.mtu = parse_mtu(v)?,
            "keepalive" => cfg.keepalive = parse_keepalive(v)?,
            "dscp" => cfg.dscp = parse_dscp(v)?,
            "dont-fragment" | "df" => cfg.dont_fragment = parse_dont_fragment(v)?,
            "clamp-tcp-mss" => cfg.clamp_tcp_mss = parse_bool(v, "clamp-tcp-mss")?,
            "allow-fast-path" => cfg.allow_fast_path = parse_bool(v, "allow-fast-path")?,
            "addr" | "address" | "addresses" => {
                for part in v.split(',') {
                    let p = part.trim();
                    if !p.is_empty() {
                        let cidr = IpCidr::parse(p)?;
                        if !cfg.addresses.contains(&cidr) {
                            cfg.addresses.push(cidr);
                        }
                    }
                }
            }
            "route" | "routes" => {
                for part in v.split(',') {
                    let p = part.trim();
                    if !p.is_empty() {
                        let rt = parse_route(p)?;
                        if !cfg.routes.contains(&rt) {
                            cfg.routes.push(rt);
                        }
                    }
                }
            }
            "dns-refresh" => {
                let dur = parse_duration_secs(v, "dns-refresh")?;
                if !(5..=86_400).contains(&dur.as_secs()) {
                    return Err(format!(
                        "dns-refresh {}s out of valid range [5s..86400s]",
                        dur.as_secs()
                    ));
                }
                cfg.dns_refresh = dur;
            }
            "ipsec-secret" => {
                if !v.trim().is_empty() {
                    return Err(
                        "ipsec-secret is not supported in EasyGRE (refusing to start unencrypted when a secret was specified)".into()
                    );
                }
            }
            other => return Err(format!("unknown tunnel parameter '{other}'")),
        }
    }

    validate_ifname(&cfg.name)?;

    if cfg.enabled {
        let raw = remote_raw.ok_or_else(|| {
            format!(
                "tunnel '{}' is missing required remote address (--remote / GRE_REMOTE)",
                cfg.name
            )
        })?;
        cfg.remote = RemoteEndpoint::parse(&raw)?;
    } else if let Some(raw) = remote_raw {
        cfg.remote = RemoteEndpoint::parse(&raw)?;
    }

    Ok(cfg)
}

fn validate_ifname(name: &str) -> Result<(), String> {
    let t = name.trim();
    if t.is_empty() {
        return Err("tunnel interface name cannot be empty".into());
    }
    if t.len() > 15 {
        return Err(format!(
            "tunnel interface name '{t}' exceeds Linux 15-byte IFNAMSIZ limit"
        ));
    }
    if t.bytes().any(|b| b == b'/' || b == 0 || b.is_ascii_whitespace()) {
        return Err(format!("invalid tunnel interface name '{t}'"));
    }
    Ok(())
}

pub fn parse_mtu(raw: &str) -> Result<MtuMode, String> {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("auto") {
        return Ok(MtuMode::Auto);
    }
    let val: u16 = t.parse().map_err(|_| format!("invalid mtu '{t}'"))?;
    if !(68..=65500).contains(&val) {
        return Err(format!("mtu {val} out of valid range [68..65500]"));
    }
    Ok(MtuMode::Fixed(val))
}

pub fn parse_dscp(raw: &str) -> Result<DscpMode, String> {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("inherit") {
        return Ok(DscpMode::Inherit);
    }
    let val: u8 = t.parse().map_err(|_| format!("invalid dscp '{t}'"))?;
    if val > 63 {
        return Err(format!("dscp {val} out of valid range [0..63]"));
    }
    Ok(DscpMode::Fixed(val))
}

pub fn parse_dont_fragment(raw: &str) -> Result<DontFragmentMode, String> {
    let t = raw.trim().to_ascii_lowercase();
    match t.as_str() {
        "no" | "false" | "0" => Ok(DontFragmentMode::No),
        "inherit" => Ok(DontFragmentMode::Inherit),
        "yes" | "true" | "1" => Err(
            "dont-fragment=yes is not supported; use 'no' or 'inherit'".into(),
        ),
        _ => Err(format!("invalid dont-fragment '{raw}', expected 'no' or 'inherit'")),
    }
}

/// Parse keepalive syntax:
/// - `off` | `none` | `disable` | `disabled`
/// - `10s,10` | `10,10` | `00:00:10,10` | `1m,5` | `10s` (default retries=10)
pub fn parse_keepalive(raw: &str) -> Result<KeepaliveConfig, String> {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("off")
        || t.eq_ignore_ascii_case("none")
        || t.eq_ignore_ascii_case("disable")
        || t.eq_ignore_ascii_case("disabled")
        || t.eq_ignore_ascii_case("false")
    {
        return Ok(KeepaliveConfig::Disabled);
    }
    let (interval_str, retries) = if let Some((left, right)) = t.split_once(',') {
        let r: u32 = right
            .trim()
            .parse()
            .map_err(|_| format!("invalid keepalive retries in '{t}'"))?;
        if !(1..=1000).contains(&r) {
            return Err("keepalive retries must be in range [1..1000]".into());
        }
        (left.trim(), r)
    } else {
        (t, 10u32)
    };
    let interval = parse_keepalive_time(interval_str)?;
    if !(1..=3600).contains(&interval.as_secs()) {
        return Err("keepalive interval must be in range [1s..3600s]".into());
    }
    Ok(KeepaliveConfig::Enabled { interval, retries })
}

fn parse_keepalive_time(s: &str) -> Result<Duration, String> {
    let t = s.trim();
    if t.contains(':') {
        let parts: Vec<&str> = t.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("invalid HH:MM:SS time '{t}'"));
        }
        let h: u64 = parts[0].parse().map_err(|_| format!("invalid hours in '{t}'"))?;
        let m: u64 = parts[1].parse().map_err(|_| format!("invalid minutes in '{t}'"))?;
        let sec: u64 = parts[2].parse().map_err(|_| format!("invalid seconds in '{t}'"))?;
        if m >= 60 || sec >= 60 {
            return Err(format!("invalid HH:MM:SS fields in '{t}'"));
        }
        let total = h
            .checked_mul(3600)
            .and_then(|v| v.checked_add(m * 60))
            .and_then(|v| v.checked_add(sec))
            .ok_or_else(|| format!("keepalive duration overflow in '{t}'"))?;
        return Ok(Duration::from_secs(total));
    }
    parse_duration_secs(t, "keepalive")
}

fn parse_duration_secs(s: &str, field: &str) -> Result<Duration, String> {
    let t = s.trim().to_ascii_lowercase();
    let secs = if let Some(num) = t.strip_suffix('s') {
        let v: u64 = num.trim().parse().map_err(|_| format!("invalid {field} duration '{s}'"))?;
        v
    } else if let Some(num) = t.strip_suffix('m') {
        let v: u64 = num.trim().parse().map_err(|_| format!("invalid {field} duration '{s}'"))?;
        v.checked_mul(60)
            .ok_or_else(|| format!("{field} duration overflow in '{s}'"))?
    } else if let Some(num) = t.strip_suffix('h') {
        let v: u64 = num.trim().parse().map_err(|_| format!("invalid {field} duration '{s}'"))?;
        v.checked_mul(3600)
            .ok_or_else(|| format!("{field} duration overflow in '{s}'"))?
    } else {
        let v: u64 = t.parse().map_err(|_| format!("invalid {field} duration '{s}'"))?;
        v
    };
    Ok(Duration::from_secs(secs))
}

fn parse_route(s: &str) -> Result<RouteSpec, String> {
    let normalized = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some((dst_str, gw_str)) = normalized.split_once(" via ") {
        let dst = IpCidr::parse(dst_str)?;
        let gw: IpAddr = gw_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid gateway IP '{gw_str}' in route '{s}'"))?;
        match (&dst, gw) {
            (IpCidr::V4 { .. }, IpAddr::V4(_)) | (IpCidr::V6 { .. }, IpAddr::V6(_)) => {}
            _ => return Err(format!("route address family mismatch in '{s}'")),
        }
        Ok(RouteSpec {
            dst,
            gateway: RouteGateway::Via(gw),
        })
    } else {
        Ok(RouteSpec {
            dst: IpCidr::parse(&normalized)?,
            gateway: RouteGateway::InterfaceOnly,
        })
    }
}

fn parse_bool(s: &str, field: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(format!("invalid boolean '{s}' for {field}")),
    }
}

pub fn parse_tx_mode(raw: &str) -> Result<TxMode, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(TxMode::Auto),
        "mmap" | "ring" | "packet" => Ok(TxMode::Mmap),
        "raw" => Ok(TxMode::Raw),
        _ => Err(format!("invalid tx-mode '{raw}', expected auto|mmap|raw")),
    }
}

pub fn parse_queues(raw: &str) -> Result<QueueMode, String> {
    let t = raw.trim();
    if t.eq_ignore_ascii_case("auto") {
        return Ok(QueueMode::Auto);
    }
    let n: usize = t.parse().map_err(|_| format!("invalid queues '{t}'"))?;
    if !(1..=16).contains(&n) {
        return Err(format!("queues {n} out of valid range [1..16]"));
    }
    Ok(QueueMode::Fixed(n))
}

pub fn collect_env_map() -> BTreeMap<String, String> {
    env::vars().collect()
}

pub fn print_help() {
    println!(
        "\
easygre {ver} - Zero-dependency Rust user-space GRE tunnel daemon

USAGE:
    easygre [run] [OPTIONS]
    easygre status [--status-file <path>]
    easygre healthcheck [--status-file <path>]

SINGLE-TUNNEL OPTIONS:
    --name <ifname>            Interface name (default: gre-tunnel1, env: GRE_NAME)
    --remote <ip|host>         Remote endpoint IPv4 or hostname (env: GRE_REMOTE)
    --local <ip|auto>          Local bind IPv4 or auto (env: GRE_LOCAL)
    --public-ip <ip>           Optional 1:1 NAT public IPv4 (env: GRE_PUBLIC_IP)
    --addr <cidr[,cidr...]>    Tunnel interface CIDRs, IPv4/IPv6 (env: GRE_ADDR)
    --route <cidr[ via gw],..> Static routes over tunnel (env: GRE_ROUTE)
    --mtu <auto|num>           Tunnel MTU, default auto = path_mtu - 24 (env: GRE_MTU)
    --keepalive <spec>         10s,10 | 00:00:10,10 | off (env: GRE_KEEPALIVE)
    --dscp <inherit|0..63>     Outer DSCP mode (default: inherit, env: GRE_DSCP)
    --dont-fragment <no|inherit> DF policy (default: no, env: GRE_DONT_FRAGMENT)
    --clamp-tcp-mss <bool>     Clamp TCP SYN MSS (default: true, env: GRE_CLAMP_TCP_MSS)
    --allow-fast-path <bool>   Fast-path compatibility flag (default: true)
    --dns-refresh <dur>        DDNS re-resolve interval (default: 60s, env: GRE_DNS_REFRESH)
    --comment <text>           Optional tunnel comment (env: GRE_COMMENT)

MULTI-TUNNEL OPTIONS:
    --tunnel \"name=...;remote=...;addr=...;route=...\"   (repeatable)
    ENV GRE_TUNNELS=\"name=t1;remote=1.1.1.1 | name=t2;remote=2.2.2.2\"
    ENV GRE_1_NAME=t1 GRE_1_REMOTE=1.1.1.1 GRE_1_ADDR=...

OTHER:
    --tx-mode <auto|mmap|raw>  Outbound packet engine (default: auto, env: GRE_TX_MODE)
    --queues <auto|1..16>      TUN multiqueue worker count (default: auto, env: GRE_QUEUES)
    --status-file <path>       Runtime status file (default: {DEFAULT_STATUS_FILE})
    -V, --version              Show version
    -h, --help                 Show this help",
        ver = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_keepalive_variants() {
        assert_eq!(
            parse_keepalive("00:00:10,10").unwrap(),
            KeepaliveConfig::Enabled {
                interval: Duration::from_secs(10),
                retries: 10
            }
        );
        assert_eq!(
            parse_keepalive("5s,3").unwrap(),
            KeepaliveConfig::Enabled {
                interval: Duration::from_secs(5),
                retries: 3
            }
        );
        assert_eq!(
            parse_keepalive("1m,4").unwrap(),
            KeepaliveConfig::Enabled {
                interval: Duration::from_secs(60),
                retries: 4
            }
        );
        assert_eq!(parse_keepalive("off").unwrap(), KeepaliveConfig::Disabled);
        assert!(parse_keepalive("0s,10").is_err());
    }

    #[test]
    fn test_parse_multi_tunnels_cli_and_env() {
        let args = vec![
            "easygre".into(),
            "--tunnel".into(),
            "name=gre1;remote=203.0.113.1;addr=172.16.1.2/30,fd00::2/64;route=10.1.0.0/16 via 172.16.1.1;keepalive=00:00:10,10".into(),
            "--tunnel".into(),
            "name=gre2;remote=vpn.example.com;mtu=1400;dscp=46;dont-fragment=inherit".into(),
        ];
        let out = parse_cli_and_env(&args, &BTreeMap::new()).unwrap();
        let CliOutcome::Run(cfg) = out else {
            panic!("expected Run");
        };
        assert_eq!(cfg.tunnels.len(), 2);
        assert_eq!(cfg.tunnels[0].addresses.len(), 2);
        assert_eq!(cfg.tunnels[0].routes.len(), 1);
        assert_eq!(cfg.tunnels[1].mtu, MtuMode::Fixed(1400));
        assert_eq!(cfg.tunnels[1].dscp, DscpMode::Fixed(46));
        assert_eq!(cfg.tunnels[1].dont_fragment, DontFragmentMode::Inherit);
    }

    #[test]
    fn test_numbered_env_tunnels() {
        let mut env_vars = BTreeMap::new();
        env_vars.insert("GRE_1_NAME".into(), "gre-a".into());
        env_vars.insert("GRE_1_REMOTE".into(), "198.51.100.1".into());
        env_vars.insert("GRE_1_ADDR".into(), "172.16.10.2/30".into());
        env_vars.insert("GRE_2_NAME".into(), "gre-b".into());
        env_vars.insert("GRE_2_REMOTE".into(), "198.51.100.2".into());
        env_vars.insert("GRE_2_ENABLED".into(), "false".into());

        let out = parse_cli_and_env(&["easygre".into()], &env_vars).unwrap();
        let CliOutcome::Run(cfg) = out else {
            panic!("expected Run");
        };
        assert_eq!(cfg.tunnels.len(), 1);
        assert_eq!(cfg.tunnels[0].name, "gre-a");
    }

    #[test]
    fn test_ipsec_secret_rejected() {
        let mut env_vars = BTreeMap::new();
        env_vars.insert("GRE_REMOTE".into(), "198.51.100.1".into());
        env_vars.insert("GRE_IPSEC_SECRET".into(), "mysecret".into());
        let err = parse_cli_and_env(&["easygre".into()], &env_vars).unwrap_err();
        assert!(err.contains("ipsec-secret"));
    }

    #[test]
    fn test_dont_fragment_yes_rejected() {
        assert!(parse_dont_fragment("yes").is_err());
        assert_eq!(parse_dont_fragment("no").unwrap(), DontFragmentMode::No);
        assert_eq!(parse_dont_fragment("inherit").unwrap(), DontFragmentMode::Inherit);
    }

    #[test]
    fn test_env_gre_tunnels_and_empty_vars_ignored() {
        let mut env_vars = BTreeMap::new();
        env_vars.insert("GRE_REMOTE".into(), "".into());
        env_vars.insert("GRE_LOCAL".into(), "   ".into());
        env_vars.insert(
            "GRE_TUNNELS".into(),
            "name=gre-a;remote=198.51.100.10;addr=172.16.1.2/30;route=0.0.0.0/0 | name=gre-b;remote=198.51.100.20;keepalive=off".into(),
        );
        let out = parse_cli_and_env(&["easygre".into()], &env_vars).unwrap();
        let CliOutcome::Run(cfg) = out else {
            panic!("expected Run");
        };
        assert_eq!(cfg.tunnels.len(), 2);
        assert_eq!(cfg.tunnels[0].routes[0].dst.to_string(), "0.0.0.0/0");
        assert_eq!(cfg.tunnels[1].keepalive, KeepaliveConfig::Disabled);
    }

    #[test]
    fn test_duplicate_tunnel_name_rejected() {
        let args = vec![
            "easygre".into(),
            "--tunnel".into(),
            "name=gre1;remote=1.1.1.1".into(),
            "--tunnel".into(),
            "name=gre1;remote=2.2.2.2".into(),
        ];
        let err = parse_cli_and_env(&args, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("duplicate tunnel interface name"));
    }

    #[test]
    fn test_tx_mode_and_queues_parsing() {
        let mut env_vars = BTreeMap::new();
        env_vars.insert("GRE_REMOTE".into(), "198.51.100.1".into());
        env_vars.insert("GRE_TX_MODE".into(), "mmap".into());
        env_vars.insert("GRE_QUEUES".into(), "4".into());
        let out = parse_cli_and_env(&["easygre".into()], &env_vars).unwrap();
        let CliOutcome::Run(cfg) = out else {
            panic!("expected Run");
        };
        assert_eq!(cfg.tx_mode, TxMode::Mmap);
        assert_eq!(cfg.queues, QueueMode::Fixed(4));

        let args = vec![
            "easygre".into(),
            "--remote".into(),
            "198.51.100.1".into(),
            "--tx-mode".into(),
            "raw".into(),
            "--queues".into(),
            "2".into(),
        ];
        let out2 = parse_cli_and_env(&args, &BTreeMap::new()).unwrap();
        let CliOutcome::Run(cfg2) = out2 else {
            panic!("expected Run");
        };
        assert_eq!(cfg2.tx_mode, TxMode::Raw);
        assert_eq!(cfg2.queues, QueueMode::Fixed(2));
    }

    #[test]
    fn test_duration_bounds_and_duplicate_endpoints_rejected() {
        // dns-refresh=0 and overflow durations must fail fast
        let args_zero = vec![
            "easygre".into(),
            "--remote".into(),
            "198.51.100.1".into(),
            "--dns-refresh".into(),
            "0s".into(),
        ];
        assert!(parse_cli_and_env(&args_zero, &BTreeMap::new()).is_err());

        let args_huge = vec![
            "easygre".into(),
            "--remote".into(),
            "198.51.100.1".into(),
            "--dns-refresh".into(),
            "999999999999999999h".into(),
        ];
        assert!(parse_cli_and_env(&args_huge, &BTreeMap::new()).is_err());

        assert!(parse_keepalive("7200s,5").is_err());
        assert!(parse_keepalive("999999999999999999h,5").is_err());

        // Duplicate (remote, local) across tunnels must be rejected
        let args_dup_ep = vec![
            "easygre".into(),
            "--tunnel".into(),
            "name=gre1;remote=203.0.113.1".into(),
            "--tunnel".into(),
            "name=gre2;remote=203.0.113.1".into(),
        ];
        let err = parse_cli_and_env(&args_dup_ep, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("duplicate tunnel peer endpoint"));
    }

    #[test]
    fn test_docker_compose_forwards_ipsec_secret_guard() {
        let content = include_str!("../docker-compose.yml");
        assert!(content.contains("GRE_IPSEC_SECRET:"));
        assert!(content.contains("GRE_ENABLED:"));
        assert!(content.contains("GRE_STATUS_FILE:"));
    }

    #[test]
    fn test_non_unicast_endpoints_rejected_in_config() {
        for bad in ["0.0.0.0", "127.0.0.1", "169.254.10.20", "224.0.0.1", "255.255.255.255"] {
            assert!(
                RemoteEndpoint::parse(bad).is_err(),
                "expected '{bad}' to be rejected as remote"
            );
            let args_local = vec![
                "easygre".into(),
                "--remote".into(),
                "198.51.100.1".into(),
                "--local".into(),
                bad.into(),
            ];
            if bad != "0.0.0.0" {
                assert!(parse_cli_and_env(&args_local, &BTreeMap::new()).is_err());
            }
            let args_pub = vec![
                "easygre".into(),
                "--remote".into(),
                "198.51.100.1".into(),
                "--public-ip".into(),
                bad.into(),
            ];
            assert!(parse_cli_and_env(&args_pub, &BTreeMap::new()).is_err());
        }
    }

    #[test]
    fn test_fuzz_cli_env_and_cidr_parsers() {
        let mut rng = 0x4346_475f_4655_5a5au64;
        let mut next = || -> u64 {
            rng = rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = rng;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };

        let alphabet = b"0123456789abcdefxyz.:;/|=,-_ \t\n";
        let flags = [
            "--name",
            "--remote",
            "--local",
            "--public-ip",
            "--addr",
            "--route",
            "--mtu",
            "--keepalive",
            "--dscp",
            "--dont-fragment",
            "--clamp-tcp-mss",
            "--dns-refresh",
            "--tx-mode",
            "--queues",
            "--tunnel",
            "--unknown",
        ];

        for _ in 0..5_000 {
            let slen = (next() as usize) % 48;
            let mut s = String::with_capacity(slen);
            for _ in 0..slen {
                s.push(alphabet[(next() as usize) % alphabet.len()] as char);
            }
            let _ = IpCidr::parse(&s);
            let _ = RemoteEndpoint::parse(&s);
            let _ = parse_keepalive(&s);

            let argc = 1 + ((next() as usize) % 6);
            let mut args = Vec::with_capacity(argc);
            args.push("easygre".to_string());
            for _ in 1..argc {
                if (next() & 1) == 0 {
                    args.push(flags[(next() as usize) % flags.len()].to_string());
                } else {
                    args.push(s.clone());
                }
            }
            let mut env_map = BTreeMap::new();
            if (next() & 1) == 0 {
                env_map.insert("GRE_TUNNELS".to_string(), s);
            }
            let _ = parse_cli_and_env(&args, &env_map);
        }
    }
}
