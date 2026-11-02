//! STAMP Session-Reflector, stateful mode (RFC 8762 §4.3).
//!
//! * Numbers packets per session (source ip:port) so the sender can split
//!   forward from return loss.
//! * Replies with the same size it received (no amplification) and, by default,
//!   the same DSCP (so the return path is classified like the forward path).
//! * Refuses to start without a source allowlist; rate-limits per source IP;
//!   bounds its session table.
//! * Authenticated mode (RFC 8762 §4.2.2/4.3.2) for sources listed in
//!   `authenticated_sources`: the key is looked up by the packet's SSID (RFC
//!   8972) in `keys_file`, which is re-read when it changes. A packet whose HMAC
//!   fails gets no reply. TLVs are returned per RFC 8972: U cleared on what was
//!   processed, I set when the extensions fail their HMAC TLV, M on a malformed tail.

use crate::clock;
use crate::ntp;
use crate::stamp::{
    check_ext_hmac, reflect_tlvs, tlv_type, ExtIntegrity, Key, Mode, ParseError, ReflectorPacket, SenderPacket, PORT,
};
use crate::sys;
use crate::Throttle;
use serde::Deserialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
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
    /// Source prefixes whose sessions use RFC 8762 authenticated mode.
    #[serde(default)]
    pub authenticated_sources: Vec<String>,
    /// TOML file mapping SSID to hex HMAC key (`[keys]`, `4101 = "..."`).
    /// Root-owned, 0600. Re-read when it changes.
    pub keys_file: Option<String>,
    /// Require the HMAC TLV (RFC 8972 §4.8) on extensions in unauthenticated
    /// sessions too (key looked up by SSID).
    #[serde(default)]
    pub protect_unauthenticated_extensions: bool,
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
            authenticated_sources: Vec::new(),
            keys_file: None,
            protect_unauthenticated_extensions: false,
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
    /// Authenticated packets refused: unknown SSID or bad HMAC.
    pub auth_failed: u64,
    /// Packets whose extensions failed the HMAC TLV check (reflected with I set).
    pub integrity_failed: u64,
}

/// SSID -> HMAC key, from a TOML file, reloaded when its mtime changes.
pub struct KeyStore {
    path: PathBuf,
    mtime: Option<std::time::SystemTime>,
    keys: HashMap<u16, Key>,
}

impl KeyStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        let mut ks = Self { path: path.to_path_buf(), mtime: None, keys: HashMap::new() };
        ks.reload()?;
        Ok(ks)
    }

    pub fn get(&self, ssid: u16) -> Option<&Key> {
        self.keys.get(&ssid)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn reload(&mut self) -> Result<(), String> {
        let meta = std::fs::metadata(&self.path).map_err(|e| format!("keys file {}: {e}", self.path.display()))?;
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                log::warn!("keys file {} is accessible by group/others; chmod 600 it", self.path.display());
            }
        }
        let raw = std::fs::read_to_string(&self.path).map_err(|e| format!("keys file {}: {e}", self.path.display()))?;
        self.keys = parse_keys(&raw).map_err(|e| format!("keys file {}: {e}", self.path.display()))?;
        self.mtime = meta.modified().ok();
        Ok(())
    }

    /// Re-reads the file if it changed. A broken file keeps the old keys.
    pub fn refresh(&mut self) {
        let changed = std::fs::metadata(&self.path).ok().and_then(|m| m.modified().ok()) != self.mtime;
        if changed {
            match self.reload() {
                Ok(()) => log::info!("keys file {} reloaded: {} key(s)", self.path.display(), self.keys.len()),
                Err(e) => log::error!("{e}; keeping the previous {} key(s)", self.keys.len()),
            }
        }
    }
}

/// Parses `[keys]` with SSID (1-65535) -> hex key.
pub fn parse_keys(raw: &str) -> Result<HashMap<u16, Key>, String> {
    let doc: toml::Table = toml::from_str(raw).map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    let Some(keys) = doc.get("keys") else { return Ok(out) };
    let keys = keys.as_table().ok_or("[keys] must be a table")?;
    for (ssid, hex) in keys {
        let id: u16 = ssid.parse().ok().filter(|v| *v != 0).ok_or_else(|| format!("SSID {ssid:?} must be 1-65535"))?;
        let hex = hex.as_str().ok_or_else(|| format!("key for SSID {id} must be a hex string"))?;
        out.insert(id, Key::from_hex(hex).map_err(|e| format!("SSID {id}: {e}"))?);
    }
    Ok(out)
}

/// Creates a random 32-octet key for `ssid`: written to `key_out` (new file,
/// 0600) for the probe, and added to `keys_file` (created 0600 if missing,
/// replaced atomically). Refuses an SSID that already has a key unless `replace`.
pub fn add_key(keys_file: &Path, ssid: u16, key_out: &Path, replace: bool) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    if ssid == 0 {
        return Err("SSID must be 1-65535".into());
    }
    let mut doc: toml::Table = match std::fs::read_to_string(keys_file) {
        Ok(raw) => {
            parse_keys(&raw).map_err(|e| format!("{}: {e}", keys_file.display()))?;
            toml::from_str(&raw).map_err(|e| e.to_string())?
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(format!("{}: {e}", keys_file.display())),
    };
    let keys = doc.entry("keys").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let keys = keys.as_table_mut().ok_or("[keys] must be a table")?;
    if keys.contains_key(&ssid.to_string()) && !replace {
        return Err(format!("SSID {ssid} already has a key in {} (use --replace)", keys_file.display()));
    }
    let mut raw = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut raw))
        .map_err(|e| format!("urandom: {e}"))?;
    let key = Key::new(raw.to_vec())?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_out)
        .map_err(|e| format!("{}: {e} (it must not exist yet)", key_out.display()))?;
    writeln!(f, "{}", key.to_hex()).map_err(|e| format!("{}: {e}", key_out.display()))?;
    keys.insert(ssid.to_string(), toml::Value::String(key.to_hex()));
    let tmp = keys_file.with_extension("tmp");
    let body = format!(
        "# buffmon-reflector STAMP keys: SSID = hex HMAC key. Keep 0600.\n{}",
        toml::to_string(&doc).map_err(|e| e.to_string())?
    );
    let mut t = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    t.write_all(body.as_bytes()).and_then(|()| t.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, keys_file).map_err(|e| format!("{}: {e}", keys_file.display()))?;
    Ok(())
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
    auth_sources: Vec<Cidr>,
    keys: Option<KeyStore>,
    local: SocketAddrV4,
}

impl Reflector {
    pub fn bind(cfg: ReflectorConfig) -> Result<Self, String> {
        let allow = cfg.allow.iter().map(|s| Cidr::parse(s)).collect::<Result<Vec<_>, _>>()?;
        let auth_sources = cfg.authenticated_sources.iter().map(|s| Cidr::parse(s)).collect::<Result<Vec<_>, _>>()?;
        if (!auth_sources.is_empty() || cfg.protect_unauthenticated_extensions) && cfg.keys_file.is_none() {
            return Err("authenticated_sources / protect_unauthenticated_extensions need keys_file".into());
        }
        let keys = match &cfg.keys_file {
            Some(p) => Some(KeyStore::load(Path::new(&crate::config::expand_env(p)?))?),
            None => None,
        };
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
        if let Some(k) = &keys {
            log::info!("authenticated mode for {:?}; {} key(s) loaded", cfg.authenticated_sources, k.len());
        }
        Ok(Self { sock, cfg, allow, auth_sources, keys, local })
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }

    fn allowed(&self, ip: Ipv4Addr) -> bool {
        self.cfg.allow_any || self.allow.iter().any(|c| c.contains(ip))
    }

    fn mode_for(&self, ip: Ipv4Addr) -> Mode {
        if self.auth_sources.iter().any(|c| c.contains(ip)) {
            Mode::Authenticated
        } else {
            Mode::Unauthenticated
        }
    }

    /// Runs until `stop` is set. Returns the final counters.
    pub fn run(mut self, stop: &AtomicBool) -> Stats {
        let fd = self.sock.as_raw_fd();
        // Large enough for jumbo frames: a reply is always the size of the request.
        let mut buf = vec![0_u8; 9216];
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
                if let Some(k) = self.keys.as_mut() {
                    k.refresh();
                }
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

            let len = m.len.min(buf.len());
            let mode = self.mode_for(*src.ip());
            let keys = self.keys.as_ref();
            let (sp, ext, key) = match SenderPacket::parse(&buf[..len], mode, |ssid| keys.and_then(|k| k.get(ssid))) {
                Ok(v) => v,
                Err(ParseError::Short) => {
                    stats.malformed += 1;
                    continue;
                }
                Err(e) => {
                    // RFC 8762 §4.3: reflect only a validated packet.
                    stats.auth_failed += 1;
                    if let Some(n) = err_throttle.ready() {
                        log::warn!("reflector: refused authenticated packet from {src}: {e} ({n} similar suppressed)");
                    }
                    continue;
                }
            };
            if !sessions.contains_key(&src) && sessions.len() >= self.cfg.max_sessions {
                stats.table_full += 1;
                continue;
            }
            let s = sessions.entry(src).or_insert(SessionState { next_seq: 0, last_seen: now });
            let seq = s.next_seq;
            s.next_seq = s.next_seq.wrapping_add(1);
            s.last_seen = now;

            let integrity = if ext.is_empty() {
                ExtIntegrity::NotNeeded
            } else {
                let required = mode == Mode::Authenticated || self.cfg.protect_unauthenticated_extensions;
                check_ext_hmac(&ext, &sp.seq.to_be_bytes(), key, required)
            };
            if integrity == ExtIntegrity::Failed {
                stats.integrity_failed += 1;
            }
            let tlvs = reflect_tlvs(&ext, integrity, |t| t == tlv_type::EXTRA_PADDING || t == tlv_type::HMAC);

            let status = clock::status();
            let t3 = clock::now_ns();
            let out = match (ReflectorPacket {
                seq,
                timestamp: ntp::from_unix_ns(t3),
                error_estimate: clock::encode_error_estimate(status),
                ssid: sp.ssid,
                receive_timestamp: ntp::from_unix_ns(t2),
                sender_seq: sp.seq,
                sender_timestamp: sp.timestamp,
                sender_error_estimate: sp.error_estimate,
                sender_ttl: m.ttl.unwrap_or(0),
            })
            .build(mode, key, &tlvs, ext.malformed.as_deref(), len)
            {
                Ok(o) => o,
                Err(e) => {
                    stats.malformed += 1;
                    if let Some(n) = err_throttle.ready() {
                        log::warn!("reflector: cannot reflect a packet from {src}: {e} ({n} similar suppressed)");
                    }
                    continue;
                }
            };
            // Reflect DSCP only; never echo ECN bits.
            let tos = if self.cfg.reflect_dscp { m.tos.map(|t| t & 0xFC) } else { None };
            match sys::send_to_tos(fd, &out, src, tos) {
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
