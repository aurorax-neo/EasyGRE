use std::fs::File;
use std::io::Read;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            let v = u64::from_ne_bytes(buf);
            if v != 0 {
                return v;
            }
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    splitmix64(nanos ^ (std::process::id() as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9))
}

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveConfig {
    Disabled,
    Enabled { interval: Duration, retries: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelLinkState {
    /// Keepalive is off; link is always up.
    AlwaysUp,
    /// Waiting for first keepalive response (carrier down until peer responds).
    Initial,
    /// Peer responded; carrier is up.
    Up,
    /// Peer failed `retries` consecutive probes; carrier is down until peer recovers.
    Down,
}

impl TunnelLinkState {
    pub fn is_carrier_up(self) -> bool {
        matches!(self, TunnelLinkState::AlwaysUp | TunnelLinkState::Up)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TunnelLinkState::AlwaysUp => "running(keepalive-off)",
            TunnelLinkState::Initial => "probing",
            TunnelLinkState::Up => "running",
            TunnelLinkState::Down => "down",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepalivePoll {
    pub should_send: bool,
    pub carrier_change: Option<bool>,
    pub state_changed: bool,
}

#[derive(Debug)]
pub struct KeepaliveStateMachine {
    config: KeepaliveConfig,
    state: TunnelLinkState,
    misses: u32,
    awaiting_reply: bool,
    seq: u16,
    secret: u64,
    next_probe_at: Option<Instant>,
    pub probes_sent: u64,
    pub replies_received: u64,
}

impl KeepaliveStateMachine {
    pub fn new(config: KeepaliveConfig, now: Instant) -> Self {
        Self::new_with_secret(config, now, random_u64())
    }

    pub fn new_with_secret(config: KeepaliveConfig, now: Instant, secret: u64) -> Self {
        let (state, next_probe_at) = match config {
            KeepaliveConfig::Disabled => (TunnelLinkState::AlwaysUp, None),
            KeepaliveConfig::Enabled { .. } => (TunnelLinkState::Initial, Some(now)),
        };
        Self {
            config,
            state,
            misses: 0,
            awaiting_reply: false,
            seq: 1,
            secret,
            next_probe_at,
            probes_sent: 0,
            replies_received: 0,
        }
    }

    pub fn state(&self) -> TunnelLinkState {
        self.state
    }

    pub fn misses(&self) -> u32 {
        self.misses
    }

    pub fn is_carrier_up(&self) -> bool {
        self.state.is_carrier_up()
    }

    pub fn next_probe_at(&self) -> Option<Instant> {
        self.next_probe_at
    }

    /// Allocate `(seq_id, non_zero_token)` for the next outbound keepalive probe.
    pub fn next_probe_ids(&mut self) -> (u16, u32) {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1).max(1);
        let mixed = splitmix64(self.secret ^ ((s as u64) << 32) ^ self.probes_sent);
        let tok = (mixed as u32) ^ ((mixed >> 32) as u32);
        (s, if tok == 0 { 0x6772_6531 } else { tok })
    }

    /// Advance timer on tick.
    pub fn poll(&mut self, now: Instant) -> KeepalivePoll {
        let KeepaliveConfig::Enabled { interval, retries } = self.config else {
            return KeepalivePoll {
                should_send: false,
                carrier_change: None,
                state_changed: false,
            };
        };
        let Some(due) = self.next_probe_at else {
            return KeepalivePoll {
                should_send: false,
                carrier_change: None,
                state_changed: false,
            };
        };
        if now < due {
            return KeepalivePoll {
                should_send: false,
                carrier_change: None,
                state_changed: false,
            };
        }
        self.next_probe_at = now.checked_add(interval).or(Some(now));

        let mut carrier_change = None;
        let mut state_changed = false;
        if self.awaiting_reply {
            self.misses = self.misses.saturating_add(1);
            if self.misses >= retries {
                match self.state {
                    TunnelLinkState::Up => {
                        self.state = TunnelLinkState::Down;
                        carrier_change = Some(false);
                        state_changed = true;
                    }
                    TunnelLinkState::Initial => {
                        self.state = TunnelLinkState::Down;
                        state_changed = true;
                    }
                    TunnelLinkState::Down | TunnelLinkState::AlwaysUp => {}
                }
            }
        }
        self.probes_sent += 1;
        self.awaiting_reply = true;
        KeepalivePoll {
            should_send: true,
            carrier_change,
            state_changed,
        }
    }

    /// Force an immediate probe (for instance after learning NAT public IP or DNS change).
    pub fn schedule_immediate_probe(&mut self, now: Instant) {
        if matches!(self.config, KeepaliveConfig::Enabled { .. }) {
            self.next_probe_at = Some(now);
        }
    }

    /// Record an incoming keepalive reply (outer GRE PT=0x0000).
    /// Returns `Some(true)` if carrier transitioned from down/initial to up.
    pub fn on_reply(&mut self) -> Option<bool> {
        if matches!(self.config, KeepaliveConfig::Disabled) || !self.awaiting_reply {
            return None;
        }
        self.replies_received += 1;
        self.awaiting_reply = false;
        self.misses = 0;
        match self.state {
            TunnelLinkState::Initial | TunnelLinkState::Down => {
                self.state = TunnelLinkState::Up;
                Some(true)
            }
            TunnelLinkState::Up | TunnelLinkState::AlwaysUp => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_lifecycle() {
        let t0 = Instant::now();
        let mut sm = KeepaliveStateMachine::new(
            KeepaliveConfig::Enabled {
                interval: Duration::from_secs(10),
                retries: 3,
            },
            t0,
        );
        assert!(!sm.is_carrier_up());
        assert_eq!(sm.state(), TunnelLinkState::Initial);

        // Immediate first probe at t0
        let p0 = sm.poll(t0);
        assert!(p0.should_send);
        assert_eq!(p0.carrier_change, None);

        // Peer replies -> carrier comes UP
        assert_eq!(sm.on_reply(), Some(true));
        assert!(sm.is_carrier_up());
        assert_eq!(sm.state(), TunnelLinkState::Up);
        // Duplicate/unsolicited reply when not awaiting_reply is ignored
        assert_eq!(sm.on_reply(), None);

        // First tick after healthy reply sends probe #2 with misses still 0
        assert_eq!(sm.poll(t0 + Duration::from_secs(10)).carrier_change, None);
        assert_eq!(sm.misses(), 0);
        // 3 missed intervals -> transition to Down after 3rd unacknowledged probes
        assert_eq!(sm.poll(t0 + Duration::from_secs(20)).carrier_change, None);
        assert_eq!(sm.misses(), 1);
        assert_eq!(sm.poll(t0 + Duration::from_secs(30)).carrier_change, None);
        assert_eq!(sm.misses(), 2);
        assert_eq!(
            sm.poll(t0 + Duration::from_secs(40)).carrier_change,
            Some(false)
        );
        assert_eq!(sm.misses(), 3);
        assert!(!sm.is_carrier_up());
        assert_eq!(sm.state(), TunnelLinkState::Down);

        // Peer recovers -> carrier UP again
        assert_eq!(sm.on_reply(), Some(true));
        assert!(sm.is_carrier_up());
        assert_eq!(sm.misses(), 0);
    }

    #[test]
    fn test_keepalive_retries_one_healthy_does_not_flap() {
        let t0 = Instant::now();
        let mut sm = KeepaliveStateMachine::new(
            KeepaliveConfig::Enabled {
                interval: Duration::from_secs(10),
                retries: 1,
            },
            t0,
        );
        assert_eq!(sm.poll(t0).carrier_change, None);
        assert_eq!(sm.on_reply(), Some(true));

        assert_eq!(sm.poll(t0 + Duration::from_secs(10)).carrier_change, None);
        assert_eq!(sm.misses(), 0);
        assert!(sm.is_carrier_up());
        assert_eq!(sm.on_reply(), None);

        assert_eq!(sm.poll(t0 + Duration::from_secs(20)).carrier_change, None);
        assert_eq!(
            sm.poll(t0 + Duration::from_secs(30)).carrier_change,
            Some(false)
        );
        assert!(!sm.is_carrier_up());
    }

    #[test]
    fn test_initial_probing_transitions_to_down_after_retries() {
        let t0 = Instant::now();
        let mut sm = KeepaliveStateMachine::new_with_secret(
            KeepaliveConfig::Enabled {
                interval: Duration::from_secs(5),
                retries: 2,
            },
            t0,
            0x1234_5678_9abc_def0,
        );
        assert_eq!(sm.state(), TunnelLinkState::Initial);
        let _ = sm.poll(t0); // probe 1 sent, misses = 0
        assert_eq!(sm.state(), TunnelLinkState::Initial);
        let _ = sm.poll(t0 + Duration::from_secs(5)); // miss 1
        assert_eq!(sm.state(), TunnelLinkState::Initial);
        let p2 = sm.poll(t0 + Duration::from_secs(10)); // miss 2 >= retries -> Down
        assert!(p2.state_changed);
        assert_eq!(sm.state(), TunnelLinkState::Down);
        let (s1, tok1) = sm.next_probe_ids();
        let (s2, tok2) = sm.next_probe_ids();
        assert_ne!(s1, s2);
        assert_ne!(tok1, 0);
        assert_ne!(tok1, tok2);
    }

    #[test]
    fn test_keepalive_disabled() {
        let t0 = Instant::now();
        let mut sm = KeepaliveStateMachine::new(KeepaliveConfig::Disabled, t0);
        assert!(sm.is_carrier_up());
        assert!(!sm.poll(t0 + Duration::from_secs(100)).should_send);
    }
}
