//! STAMP Session-Reflector, stateful mode (RFC 8762 §4.3).
//!
//! * Numbers packets per session (source ip:port) so the sender can split
//!   forward from return loss.
//! * Replies with the same size it received (no amplification) and, by default,
//!   the same DSCP (so the return path is classified like the forward path).
//! * Refuses to start without a source allowlist; rate-limits per source IP;
//!   bounds its session table.

use crate::clock;
use crate::ntp;
use crate::stamp::{ReflectorPacket, SenderPacket, MAX_LEN, PORT};
use crate::sys;
use crate::Throttle;
use serde::Deserialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectorConfig {
    #[serde(default = "d_listen")]
    pub listen: String,
    /// Source prefixes allowed to use this reflector, e.g. "10.0.0.0/8".
    #[serde(default)]
    pub allow: Vec<String>,
    /// Explicitly accept any source (lab only).
    #[serde(default)]
    pub allow_any: bool,
    #[serde(default = "d_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "d_session_idle_s")]
    pub session_idle_s: u64,
    /// Per source IP, packets per second (1-second burst).
    #[serde(default = "d_rate_limit_pps")]
    pub rate_limit_pps: u32,
    #[serde(default = "d_true")]
    pub reflect_dscp: bool,
    #[serde(default = "d_stats_interval_s")]
    pub stats_interval_s: u64,
}

/// Distinct source IPs tracked by the rate limiter (entries expire after 60 s idle).
const MAX_RATE_BUCKETS: usize = 100_000;

fn d_listen() -> String {
    format!("0.0.0.0:{PORT}")
}
fn d_max_sessions() -> usize {
    10_000
}
fn d_session_idle_s() -> u64 {
    300
}
fn d_rate_limit_pps() -> u32 {
    2_000
}
fn d_true() -> bool {
    true
}
fn d_stats_interval_s() -> u64 {
    60
}

impl Default for ReflectorConfig {
    fn default() -> Self {
        Self {
            listen: d_listen(),
            allow: Vec::new(),
            allow_any: false,
            max_sessions: d_max_sessions(),
            session_idle_s: d_session_idle_s(),
            rate_limit_pps: d_rate_limit_pps(),
            reflect_dscp: true,
            stats_interval_s: d_stats_interval_s(),
        }
    }
}

/// An IPv4 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: u32,
    mask: u32,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip, len) = match s.split_once('/') {
            Some((ip, len)) => (ip, len.parse::<u32>().map_err(|_| format!("bad prefix length in {s:?}"))?),
            None => (s, 32),
        };
        if len > 32 {
            return Err(format!("prefix length > 32 in {s:?}"));
        }
        let ip: Ipv4Addr = ip.parse().map_err(|_| format!("bad IPv4 address in {s:?}"))?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Ok(Self { net: u32::from(ip) & mask, mask })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask == self.net
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub reflected: u64,
    pub denied: u64,
    pub rate_limited: u64,
    pub malformed: u64,
    pub table_full: u64,
    pub send_errors: u64,
}

struct SessionState {
    next_seq: u32,
    last_seen: Instant,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct Reflector {
    sock: Socket,
    cfg: ReflectorConfig,
    allow: Vec<Cidr>,
    local: SocketAddrV4,
}

impl Reflector {
    pub fn bind(cfg: ReflectorConfig) -> Result<Self, String> {
        let allow = cfg.allow.iter().map(|s| Cidr::parse(s)).collect::<Result<Vec<_>, _>>()?;
        if allow.is_empty() && !cfg.allow_any {
            return Err("no source allowlist: set allow = [\"10.0.0.0/8\", ...] (or allow_any for a lab)".into());
        }
        if cfg.max_sessions == 0 || cfg.rate_limit_pps == 0 {
            return Err("max_sessions and rate_limit_pps must be > 0".into());
        }
        let listen = crate::config::parse_v4_endpoint(&cfg.listen, PORT)?;
        let io_err = |e: io::Error| format!("{listen}: {e}");
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(io_err)?;
        sock.bind(&SockAddr::from(listen)).map_err(io_err)?;
        sock.set_read_timeout(Some(Duration::from_millis(200))).map_err(io_err)?;
        let fd = sock.as_raw_fd();
        sys::enable_rx_timestamps(fd).map_err(io_err)?;
        sys::enable_recv_ttl(fd).map_err(io_err)?;
        sys::enable_recv_tos(fd).map_err(io_err)?;
        let local = sock.local_addr().ok().and_then(|a| a.as_socket()).and_then(|a| sys::v4(a).ok()).unwrap_or(listen);
        if cfg.allow_any {
            log::warn!("reflector accepts ANY source (allow_any); use an allowlist outside a lab");
        }
        Ok(Self { sock, cfg, allow, local })
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }

    fn allowed(&self, ip: Ipv4Addr) -> bool {
        self.cfg.allow_any || self.allow.iter().any(|c| c.contains(ip))
    }

    /// Runs until `stop` is set. Returns the final counters.
    pub fn run(self, stop: &AtomicBool) -> Stats {
        let fd = self.sock.as_raw_fd();
        let mut buf = [0_u8; 2048];
        let mut out = [0_u8; MAX_LEN];
        let mut sessions: HashMap<SocketAddrV4, SessionState> = HashMap::new();
        let mut buckets: HashMap<Ipv4Addr, Bucket> = HashMap::new();
        let mut stats = Stats::default();
        let mut last_maint = Instant::now();
        let mut last_stats = Instant::now();
        let mut err_throttle = Throttle::new(Duration::from_secs(30));
        let idle = Duration::from_secs(self.cfg.session_idle_s);
        let rate = f64::from(self.cfg.rate_limit_pps);
        log::info!("reflector listening on {} (allow: {:?})", self.local, self.cfg.allow);

        while !stop.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now.duration_since(last_maint) >= Duration::from_secs(1) {
                last_maint = now;
                sessions.retain(|_, s| now.duration_since(s.last_seen) < idle);
                buckets.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(60));
            }
            if now.duration_since(last_stats) >= Duration::from_secs(self.cfg.stats_interval_s) {
                last_stats = now;
                log::info!("reflector: {} sessions, {:?}", sessions.len(), stats);
            }

            let m = match sys::recv_meta(fd, &mut buf) {
                Ok(m) => m,
                Err(e) if sys::is_timeout(&e) => continue,
                Err(e) => {
                    if let Some(n) = err_throttle.ready() {
                        log::warn!("reflector receive error: {e} ({n} similar suppressed)");
                    }
                    continue;
                }
            };
            let t2 = m.kernel_ts_ns.unwrap_or_else(clock::now_ns);
            let Some(src) = m.src else { continue };
            if !self.allowed(*src.ip()) {
                stats.denied += 1;
                continue;
            }
            let now = Instant::now();
            // Bound the limiter table too: spoofed sources inside a wide
            // allowlist must not be able to grow it without limit.
            if !buckets.contains_key(src.ip()) && buckets.len() >= MAX_RATE_BUCKETS {
                stats.rate_limited += 1;
                continue;
            }
            let b = buckets.entry(*src.ip()).or_insert(Bucket { tokens: rate, last: now });
            b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * rate).min(rate);
            b.last = now;
            if b.tokens < 1.0 {
                stats.rate_limited += 1;
                continue;
            }
            b.tokens -= 1.0;

            let len = m.len.min(MAX_LEN);
            let Some(sp) = SenderPacket::decode(&buf[..len]) else {
                stats.malformed += 1;
                continue;
            };
            if !sessions.contains_key(&src) && sessions.len() >= self.cfg.max_sessions {
                stats.table_full += 1;
                continue;
            }
            let s = sessions.entry(src).or_insert(SessionState { next_seq: 0, last_seen: now });
            let seq = s.next_seq;
            s.next_seq = s.next_seq.wrapping_add(1);
            s.last_seen = now;

            let status = clock::status();
            let t3 = clock::now_ns();
            ReflectorPacket {
                seq,
                timestamp: ntp::from_unix_ns(t3),
                error_estimate: clock::encode_error_estimate(status),
                receive_timestamp: ntp::from_unix_ns(t2),
                sender_seq: sp.seq,
                sender_timestamp: sp.timestamp,
                sender_error_estimate: sp.error_estimate,
                sender_ttl: m.ttl.unwrap_or(0),
            }
            .encode(&mut out[..len]);
            // Reflect DSCP only; never echo ECN bits.
            let tos = if self.cfg.reflect_dscp { m.tos.map(|t| t & 0xFC) } else { None };
            match sys::send_to_tos(fd, &out[..len], src, tos) {
                Ok(_) => stats.reflected += 1,
                Err(e) => {
                    stats.send_errors += 1;
                    if let Some(n) = err_throttle.ready() {
                        log::warn!("reflector send to {src} failed: {e} ({n} similar suppressed)");
                    }
                }
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parsing_and_matching() {
        let c = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(c.contains("10.1.200.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(Cidr::parse("10.1.2.3").unwrap().contains("10.1.2.3".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("192.0.2.1".parse().unwrap()));
        // Host bits are masked off rather than rejected.
        assert_eq!(Cidr::parse("10.1.2.3/8").unwrap(), Cidr::parse("10.0.0.0/8").unwrap());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("not-an-ip/8").is_err());
    }

    #[test]
    fn refuses_to_start_without_allowlist() {
        let cfg = ReflectorConfig { listen: "127.0.0.1:0".into(), ..ReflectorConfig::default() };
        assert!(Reflector::bind(cfg).err().unwrap().contains("allowlist"));
    }
}
