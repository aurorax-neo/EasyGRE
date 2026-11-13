use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::keepalive::random_u64;
use crate::sys::monotonic_now_secs;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW_FLAG: i32 = 0o100000;
#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
const O_NOFOLLOW_FLAG: i32 = 0o400000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_FLAG: i32 = 0x0100;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const O_NOFOLLOW_FLAG: i32 = 0;

#[derive(Debug, Clone)]
pub struct TunnelStatusSnapshot {
    pub name: String,
    pub comment: Option<String>,
    pub remote_config: String,
    pub remote_ip: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub public_ip: Option<Ipv4Addr>,
    pub mtu: u16,
    pub state: &'static str,
    pub carrier_up: bool,
    pub misses: u32,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_drops: u64,
    pub rx_drops: u64,
    pub rx_trunc: u64,
    pub ka_probes_sent: u64,
    pub ka_replies_rx: u64,
    pub ka_requests_ans: u64,
    pub ka_spoof_drops: u64,
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn write_status_file(
    path: &str,
    pid: u32,
    workers_ok: bool,
    tunnels: &[TunnelStatusSnapshot],
) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("refusing to overwrite symlink status path '{path}'"));
        }
    }

    let now = unix_now_secs();
    let mut out = String::with_capacity(640);
    if let Some(mono) = monotonic_now_secs() {
        out.push_str(&format!("mono_at={mono}\n"));
    }
    out.push_str(&format!(
        "updated_at={now}\npid={pid}\nworkers_ok={}\ntunnel_count={}\n",
        if workers_ok { 1 } else { 0 },
        tunnels.len()
    ));
    for t in tunnels {
        let pub_ip = t
            .public_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".into());
        let cmt = t
            .comment
            .as_deref()
            .unwrap_or("")
            .replace(['\n', '\r', '\t'], " ");
        out.push_str(&format!(
            "tunnel\tname={}\tstate={}\tcarrier={}\tlocal={}\tpublic={}\tremote_cfg={}\tremote_ip={}\tmtu={}\tmisses={}\ttx={}\trx={}\ttx_drop={}\trx_drop={}\trx_trunc={}\tka_tx={}\tka_rx={}\tka_ans={}\tka_drop={}\tcomment={}\n",
            t.name,
            t.state,
            if t.carrier_up { 1 } else { 0 },
            t.local_ip,
            pub_ip,
            t.remote_config,
            t.remote_ip,
            t.mtu,
            t.misses,
            t.tx_packets,
            t.rx_packets,
            t.tx_drops,
            t.rx_drops,
            t.rx_trunc,
            t.ka_probes_sent,
            t.ka_replies_rx,
            t.ka_requests_ans,
            t.ka_spoof_drops,
            cmt
        ));
    }

    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut b = fs::DirBuilder::new();
                b.recursive(true).mode(0o700);
                b.create(parent)
                    .map_err(|e| format!("failed to create status parent dir: {e}"))?;
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("failed to create status parent dir: {e}"))?;
            }
        }
    }

    let mut created: Option<(String, fs::File)> = None;
    let mut last_err = String::new();
    for _ in 0..4 {
        let nonce = random_u64();
        let candidate = format!("{path}.tmp.{pid}.{nonce:016x}");
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600).custom_flags(O_NOFOLLOW_FLAG);
        }
        match opts.open(&candidate) {
            Ok(f) => {
                created = Some((candidate, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = e.to_string();
                continue;
            }
            Err(e) => {
                return Err(format!("failed to create temp status file '{candidate}': {e}"));
            }
        }
    }
    let Some((tmp_path, mut file)) = created else {
        return Err(format!("failed to allocate unique temp status file: {last_err}"));
    };

    if let Err(e) = file.write_all(out.as_bytes()) {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to write status content: {e}"));
    }
    drop(file);

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("refusing to rename over symlink status path '{path}'"));
        }
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!("failed to rename status file to '{path}': {e}"));
    }
    Ok(())
}

pub fn remove_status_file(path: &str) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return;
        }
    }
    let _ = fs::remove_file(path);
}

pub fn read_status_pid(path: &str) -> Option<u32> {
    let (_, lines) = read_status_raw(path).ok()?;
    for line in lines {
        if let Some(p) = line.strip_prefix("pid=") {
            if let Ok(pid) = p.trim().parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

pub fn read_status_raw(path: &str) -> Result<(u64, Vec<String>), String> {
    if !Path::new(path).exists() {
        return Err(format!("status file '{path}' not found (is easygre running?)"));
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("refusing to read symlink status file '{path}'"));
        }
    }
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read status file '{path}': {e}"))?;
    let mut updated_at = 0u64;
    let mut lines = Vec::new();
    for line in content.lines() {
        if let Some(ts) = line.strip_prefix("updated_at=") {
            updated_at = ts.trim().parse().unwrap_or(0);
        }
        lines.push(line.to_string());
    }
    Ok((updated_at, lines))
}

/// Healthcheck rule:
/// - Status file exists and was updated within the last 30 seconds
/// - `workers_ok` is not 0
/// - At least one tunnel is `running`, `running(keepalive-off)`, or `probing` (during initial handshake)
/// - Returns non-zero if status is stale or ALL tunnels are `down`
pub fn evaluate_healthcheck(path: &str, max_stale_secs: u64) -> Result<String, String> {
    let (updated_at, lines) = read_status_raw(path)?;
    let mut mono_at: Option<u64> = None;
    for line in &lines {
        if let Some(ms) = line.strip_prefix("mono_at=") {
            mono_at = ms.trim().parse().ok();
            break;
        }
    }
    // Prefer CLOCK_MONOTONIC delta on Linux so NTP wall-clock jumps never trigger false unhealthiness
    let age_secs = match (mono_at, monotonic_now_secs()) {
        (Some(written_mono), Some(now_mono)) => now_mono.saturating_sub(written_mono),
        _ => unix_now_secs().saturating_sub(updated_at),
    };
    if age_secs > max_stale_secs {
        return Err(format!(
            "status file is stale ({age_secs}s old > {max_stale_secs}s)"
        ));
    }
    let mut total = 0usize;
    let mut healthy = 0usize;
    for line in &lines {
        if line.trim() == "workers_ok=0" {
            return Err("one or more data-plane workers exited unexpectedly".into());
        }
        if line.starts_with("tunnel\t") {
            total += 1;
            if line.contains("\tstate=running") || line.contains("\tstate=probing") {
                healthy += 1;
            }
        }
    }
    if total == 0 {
        return Err("no active tunnels reported in status file".into());
    }
    if healthy == 0 {
        return Err(format!("all {total} tunnels are down"));
    }
    Ok(format!("healthy: {healthy}/{total} tunnels active"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_write_and_healthcheck() {
        let path = format!("/tmp/easygre_test_status_{}.txt", std::process::id());
        let snaps = vec![TunnelStatusSnapshot {
            name: "gre-tunnel1".into(),
            comment: Some("hq".into()),
            remote_config: "203.0.113.1".into(),
            remote_ip: Ipv4Addr::new(203, 0, 113, 1),
            local_ip: Ipv4Addr::new(10, 0, 0, 2),
            public_ip: Some(Ipv4Addr::new(198, 51, 100, 9)),
            mtu: 1476,
            state: "running",
            carrier_up: true,
            misses: 0,
            tx_packets: 10,
            rx_packets: 12,
            tx_drops: 0,
            rx_drops: 0,
            rx_trunc: 0,
            ka_probes_sent: 2,
            ka_replies_rx: 2,
            ka_requests_ans: 1,
            ka_spoof_drops: 0,
        }];
        write_status_file(&path, 1234, true, &snaps).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let msg = evaluate_healthcheck(&path, 30).unwrap();
        assert!(msg.contains("1/1"));
        assert_eq!(read_status_pid(&path), Some(1234));

        // Unhealthy worker flag must fail healthcheck
        write_status_file(&path, 1234, false, &snaps).unwrap();
        assert!(evaluate_healthcheck(&path, 30).is_err());
        remove_status_file(&path);

        // Symlink at target path must be refused without clobbering target
        #[cfg(unix)]
        {
            let victim = format!("/tmp/easygre_victim_{}.txt", std::process::id());
            let sym = format!("/tmp/easygre_symlink_{}.status", std::process::id());
            fs::write(&victim, "keep-safe").unwrap();
            let _ = std::os::unix::fs::symlink(&victim, &sym);
            assert!(write_status_file(&sym, 1234, true, &snaps).is_err());
            assert_eq!(fs::read_to_string(&victim).unwrap(), "keep-safe");
            let _ = fs::remove_file(&sym);
            let _ = fs::remove_file(&victim);
        }
    }

    #[test]
    fn test_fuzz_status_and_healthcheck_corrupted_inputs() {
        let path = format!("/tmp/easygre_fuzz_status_{}.txt", std::process::id());
        let samples = [
            "",
            "\0\0\0",
            "mono_at=999999999999999999999999999\nupdated_at=abc\npid=-1\nworkers_ok=1\n",
            "updated_at=9999999999\nworkers_ok=0\ntunnel\tname=g1\tstate=running\n",
            "updated_at=9999999999\nworkers_ok=1\ntunnel\tname=g1\tstate=down\n",
            "mono_at=0\nupdated_at=0\nworkers_ok=1\ntunnel\tname=g1\tstate=probing\n",
        ];
        for sample in samples {
            fs::write(&path, sample).unwrap();
            let _ = read_status_raw(&path);
            let _ = read_status_pid(&path);
            let _ = evaluate_healthcheck(&path, 30);
        }
        remove_status_file(&path);
    }
}
