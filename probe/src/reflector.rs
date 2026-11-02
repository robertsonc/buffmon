//! STAMP Session-Reflector, stateful mode (RFC 8762 §4.3).
//!
//! * Numbers packets per session (source ip:port) so the sender can split
//!   forward from return loss.
//! * Replies with the same size it received (no amplification) and, by default,
//!   the same DSCP (so the return path is classified like the forward path).
//! * Refuses to start without a source allowlist; rate-limits per source IP;
//!   bounds its session table.
//! * RFC 10052 return trains (`[reflected_control]`, off by default): one
//!   authenticated request with a valid HMAC TLV can ask for a train back.
//!   Limits per request (packets, volume, MTU) and per source (average
//!   bytes/s); out-of-order requests get a single reply with U set; trains go
//!   out from a worker thread so a paced train never delays other sessions.
//! * Authenticated mode (RFC 8762 §4.2.2/4.3.2) for sources listed in
//!   `authenticated_sources`: the key is looked up by the packet's SSID (RFC
//!   8972) in `keys_file`, which is re-read when it changes. A packet whose HMAC
//!   fails gets no reply. TLVs are returned per RFC 8972: U cleared on what was
//!   processed, I set when the extensions fail their HMAC TLV, M on a malformed tail.

use crate::clock;
use crate::ntp;
use crate::stamp::{
    check_ext_hmac, flag, reflect_tlvs, tlv_type, ExtIntegrity, Key, Mode, ParseError, ReflectedControl,
    ReflectorPacket, SenderPacket, Tlv, MAX_LEN, PORT,
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
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
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
    /// RFC 10052 return trains.
    #[serde(default)]
    pub reflected_control: ReflectedControlConfig,
}

/// `[reflected_control]`: RFC 10052. Off by default (RFC 10052 §5); only for
/// authenticated sessions whose extensions pass the HMAC TLV check (D13).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectedControlConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Most packets one request may ask for.
    #[serde(default = "d_rc_max_packets")]
    pub max_packets: u16,
    /// Most octets one request may ask for (count x packet length).
    #[serde(default = "d_rc_max_volume")]
    pub max_volume_bytes: u64,
    /// Average reflected-train octets per second per source IP (token bucket,
    /// burst = max_volume_bytes). A back-to-back train leaves at line rate; this
    /// bounds how often one can be asked for.
    #[serde(default = "d_rc_max_rate")]
    pub max_rate_bytes_per_s: u64,
    /// Largest reflected packet (the egress MTU minus IPv4/UDP headers).
    #[serde(default = "d_rc_max_len")]
    pub max_packet_len: usize,
}

fn d_rc_max_packets() -> u16 {
    256
}
fn d_rc_max_volume() -> u64 {
    393_216
}
fn d_rc_max_rate() -> u64 {
    1_000_000
}
fn d_rc_max_len() -> usize {
    MAX_LEN
}

impl Default for ReflectedControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_packets: d_rc_max_packets(),
            max_volume_bytes: d_rc_max_volume(),
            max_rate_bytes_per_s: d_rc_max_rate(),
            max_packet_len: d_rc_max_len(),
        }
    }
}

/// What to do with an RFC 10052 request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrainDecision {
    /// Not processed (disabled, unauthenticated, integrity failed, or out of
    /// order): one ordinary reply, the control TLV returned with U set.
    NotProcessed,
    /// Number of packets 0: send nothing.
    Silent,
    /// Over a limit or the MTU: one reply of `len` octets, C set.
    Refused {
        len: usize,
    },
    Train {
        len: usize,
        count: u16,
        interval_ns: u32,
    },
}

/// RFC 10052 §3 and §5 rules, in order. `tlvs` are the received TLVs other
/// than Extra Padding; `budget` is what the source's byte bucket allows now.
pub fn decide_train(
    ctl: ReflectedControl,
    cfg: &ReflectedControlConfig,
    mode: Mode,
    integrity: ExtIntegrity,
    in_order: bool,
    tlvs: &[Tlv],
    budget: f64,
) -> TrainDecision {
    if !cfg.enabled || mode != Mode::Authenticated || integrity != ExtIntegrity::Valid || !in_order {
        return TrainDecision::NotProcessed;
    }
    if ctl.count == 0 {
        return TrainDecision::Silent;
    }
    let len = ctl.reflected_len(mode, tlvs);
    if len > cfg.max_packet_len {
        return TrainDecision::Refused { len: cfg.max_packet_len };
    }
    let volume = u64::from(ctl.count) * len as u64;
    if ctl.count > cfg.max_packets || volume > cfg.max_volume_bytes || volume as f64 > budget {
        return TrainDecision::Refused { len };
    }
    TrainDecision::Train { len, count: ctl.count, interval_ns: ctl.interval_ns }
}

/// RFC 1982 serial number comparison: is `seq` after `prev`?
fn after(seq: u32, prev: u32) -> bool {
    (seq.wrapping_sub(prev) as i32) > 0
}

/// A train for the worker thread to send.
struct TrainJob {
    dst: SocketAddrV4,
    tos: Option<u8>,
    mode: Mode,
    key: Option<Key>,
    base: ReflectorPacket,
    tlvs: Vec<Tlv>,
    len: usize,
    count: u16,
    interval_ns: u32,
}

/// Sends trains: back to back with one sendmmsg, or paced (sleep, then spin
/// for the last stretch). T3 is taken as each packet is built.
fn train_worker(sock: Socket, jobs: Receiver<TrainJob>, stop: &AtomicBool) -> (u64, u64) {
    let fd = sock.as_raw_fd();
    let (mut sent_trains, mut send_errors) = (0_u64, 0_u64);
    let build = |job: &TrainJob| {
        let status = clock::status();
        let p = ReflectorPacket {
            timestamp: ntp::from_unix_ns(clock::now_ns()),
            error_estimate: clock::encode_error_estimate(status),
            ..job.base
        };
        p.build(job.mode, job.key.as_ref(), &job.tlvs, None, job.len)
    };
    while !stop.load(Ordering::Relaxed) {
        let job = match jobs.recv_timeout(Duration::from_millis(200)) {
            Ok(j) => j,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let ok = if job.interval_ns == 0 {
            match (0..job.count).map(|_| build(&job)).collect::<Result<Vec<_>, _>>() {
                Ok(bufs) => sys::send_many_to_tos(fd, &bufs, job.dst, job.tos).is_ok_and(|n| n == bufs.len()),
                Err(_) => false,
            }
        } else {
            let start = Instant::now();
            let step = Duration::from_nanos(u64::from(job.interval_ns));
            (0..job.count).all(|i| {
                let due = start + step * u32::from(i);
                let spin_from = due.checked_sub(Duration::from_micros(200)).unwrap_or(due);
                if let Some(d) = spin_from.checked_duration_since(Instant::now()) {
                    std::thread::sleep(d);
                }
                while Instant::now() < due {
                    std::hint::spin_loop();
                }
                build(&job).is_ok_and(|b| sys::send_to_tos(fd, &b, job.dst, job.tos).is_ok())
            })
        };
        if ok {
            sent_trains += 1;
        } else {
            send_errors += 1;
        }
    }
    (sent_trains, send_errors)
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
            reflected_control: ReflectedControlConfig::default(),
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
    /// RFC 10052: trains sent, requests refused (C) and not processed (U).
    pub trains_sent: u64,
    pub trains_refused: u64,
    pub trains_not_processed: u64,
    pub train_send_errors: u64,
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
    /// Sequence number of the last in-order RFC 10052 request (replay check).
    last_train_seq: Option<u32>,
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
        let rc = &cfg.reflected_control;
        if rc.enabled {
            if auth_sources.is_empty() {
                return Err("reflected_control needs authenticated_sources: return trains are only for \
                            authenticated sessions"
                    .into());
            }
            if rc.max_packets == 0 || rc.max_volume_bytes == 0 || rc.max_rate_bytes_per_s == 0 {
                return Err("reflected_control limits must be > 0".into());
            }
            if !(crate::stamp::BASE_LEN..=9000).contains(&rc.max_packet_len) {
                return Err("reflected_control.max_packet_len must be 44-9000".into());
            }
            log::warn!(
                "RFC 10052 return trains ENABLED: up to {} packets / {} B per request, {} B/s per source",
                rc.max_packets,
                rc.max_volume_bytes,
                rc.max_rate_bytes_per_s
            );
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
        // RFC 10052: per-source budget for reflected-train octets.
        let mut train_budget: HashMap<Ipv4Addr, Bucket> = HashMap::new();
        let rc = self.cfg.reflected_control.clone();
        let (jobs, worker) = if rc.enabled {
            let (tx, rx) = sync_channel::<TrainJob>(8);
            let sock = match self.sock.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    log::error!("reflector: cannot start the train sender ({e}); return trains disabled");
                    return Stats::default();
                }
            };
            // The worker gets its own stop flag, raised when this loop ends.
            let wstop = std::sync::Arc::new(AtomicBool::new(false));
            let ws = std::sync::Arc::clone(&wstop);
            let h = std::thread::Builder::new()
                .name("reflector-trains".into())
                .spawn(move || train_worker(sock, rx, &ws))
                .ok();
            (Some(tx), h.map(|h| (h, wstop)))
        } else {
            (None, None)
        };
        let jobs: Option<SyncSender<TrainJob>> = jobs;
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
                train_budget.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(600));
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
            let s = sessions.entry(src).or_insert(SessionState { next_seq: 0, last_seen: now, last_train_seq: None });
            let seq = s.next_seq;
            s.next_seq = s.next_seq.wrapping_add(1);
            s.last_seen = now;
            let ctl = ext.find(tlv_type::REFLECTED_CONTROL).and_then(ReflectedControl::parse);
            let in_order = s.last_train_seq.is_none_or(|prev| after(sp.seq, prev));
            if ctl.is_some() && in_order {
                s.last_train_seq = Some(sp.seq);
            }

            let integrity = if ext.is_empty() {
                ExtIntegrity::NotNeeded
            } else {
                let required = mode == Mode::Authenticated || self.cfg.protect_unauthenticated_extensions;
                check_ext_hmac(&ext, &sp.seq.to_be_bytes(), key, required)
            };
            if integrity == ExtIntegrity::Failed {
                stats.integrity_failed += 1;
            }
            // RFC 10052: decide before building, so the reply carries the right flags.
            let no_padding: Vec<Tlv> = ext.tlvs.iter().filter(|t| t.typ != tlv_type::EXTRA_PADDING).cloned().collect();
            let decision = match ctl {
                None => None,
                Some(c) => {
                    let b = train_budget
                        .entry(*src.ip())
                        .or_insert(Bucket { tokens: rc.max_volume_bytes as f64, last: now });
                    b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * rc.max_rate_bytes_per_s as f64)
                        .min(rc.max_volume_bytes as f64);
                    b.last = now;
                    let d = decide_train(c, &rc, mode, integrity, in_order, &no_padding, b.tokens);
                    if let TrainDecision::Train { len, count, .. } = d {
                        b.tokens -= (len * usize::from(count)) as f64;
                    }
                    Some(d)
                }
            };
            let processed_ctl = matches!(
                decision,
                Some(TrainDecision::Train { .. } | TrainDecision::Refused { .. } | TrainDecision::Silent)
            );
            let mut tlvs = reflect_tlvs(&ext, integrity, |t| {
                t == tlv_type::EXTRA_PADDING
                    || t == tlv_type::HMAC
                    || (t == tlv_type::REFLECTED_CONTROL && processed_ctl)
            });
            if matches!(decision, Some(TrainDecision::Silent)) {
                continue;
            }
            if matches!(decision, Some(TrainDecision::NotProcessed)) {
                stats.trains_not_processed += 1;
            }
            let tos = if self.cfg.reflect_dscp { m.tos.map(|t| t & 0xFC) } else { None };
            let train_base = ReflectorPacket {
                seq,
                timestamp: 0,
                error_estimate: 0,
                ssid: sp.ssid,
                receive_timestamp: ntp::from_unix_ns(t2),
                sender_seq: sp.seq,
                sender_timestamp: sp.timestamp,
                sender_error_estimate: sp.error_estimate,
                sender_ttl: m.ttl.unwrap_or(0),
            };
            let mut reply_len = len;
            let mut refused = matches!(decision, Some(TrainDecision::Refused { .. }));
            if let Some(TrainDecision::Train { len: tlen, count, interval_ns }) = decision {
                // Train packets carry the received TLVs other than Extra Padding.
                let train_tlvs: Vec<Tlv> = tlvs.iter().filter(|t| t.typ != tlv_type::EXTRA_PADDING).cloned().collect();
                let job = TrainJob {
                    dst: src,
                    tos,
                    mode,
                    key: key.cloned(),
                    base: train_base,
                    tlvs: train_tlvs,
                    len: tlen,
                    count,
                    interval_ns,
                };
                match jobs.as_ref().map(|j| j.try_send(job)) {
                    Some(Ok(())) => {
                        stats.trains_sent += 1;
                        continue;
                    }
                    Some(Err(TrySendError::Full(_) | TrySendError::Disconnected(_))) | None => {
                        // Overloaded: answer like a limit was hit.
                        refused = true;
                        reply_len = tlen;
                    }
                }
            }
            if refused {
                stats.trains_refused += 1;
                if let Some(TrainDecision::Refused { len: l }) = decision {
                    reply_len = l;
                }
                tlvs.retain(|t| t.typ != tlv_type::EXTRA_PADDING);
                for t in tlvs.iter_mut().filter(|t| t.typ == tlv_type::REFLECTED_CONTROL) {
                    t.flags |= flag::C;
                }
            }

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
            .build(mode, key, &tlvs, ext.malformed.as_deref(), reply_len)
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
        drop(jobs);
        if let Some((h, wstop)) = worker {
            wstop.store(true, Ordering::Relaxed);
            if let Ok((_, errors)) = h.join() {
                stats.train_send_errors = errors;
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

    fn rc(enabled: bool) -> ReflectedControlConfig {
        ReflectedControlConfig {
            enabled,
            max_packets: 64,
            max_volume_bytes: 50_000,
            ..ReflectedControlConfig::default()
        }
    }

    #[test]
    fn rfc_10052_decisions() {
        let ctl = ReflectedControl { len: 1200, count: 32, interval_ns: 0 };
        let tlvs = [ctl.tlv(), Tlv::new(tlv_type::HMAC, vec![0; 16])];
        let ok = |c: ReflectedControl, cfg: &ReflectedControlConfig| {
            decide_train(c, cfg, Mode::Authenticated, ExtIntegrity::Valid, true, &tlvs, 1e9)
        };
        assert_eq!(ok(ctl, &rc(true)), TrainDecision::Train { len: 1200, count: 32, interval_ns: 0 });
        // Off by default, authenticated only, integrity required, in order only.
        assert_eq!(ok(ctl, &rc(false)), TrainDecision::NotProcessed);
        let d = |mode, integ, in_order| decide_train(ctl, &rc(true), mode, integ, in_order, &tlvs, 1e9);
        assert_eq!(d(Mode::Unauthenticated, ExtIntegrity::Valid, true), TrainDecision::NotProcessed);
        assert_eq!(d(Mode::Authenticated, ExtIntegrity::NotNeeded, true), TrainDecision::NotProcessed);
        assert_eq!(d(Mode::Authenticated, ExtIntegrity::Failed, true), TrainDecision::NotProcessed);
        assert_eq!(d(Mode::Authenticated, ExtIntegrity::Valid, false), TrainDecision::NotProcessed);
        // Count 0: nothing. Too long: one MTU-sized packet. Over count/volume/budget: one packet, C.
        assert_eq!(ok(ReflectedControl { count: 0, ..ctl }, &rc(true)), TrainDecision::Silent);
        assert_eq!(ok(ReflectedControl { len: 4000, ..ctl }, &rc(true)), TrainDecision::Refused { len: MAX_LEN });
        assert_eq!(ok(ReflectedControl { count: 65, len: 200, ..ctl }, &rc(true)), TrainDecision::Refused { len: 200 });
        assert_eq!(ok(ReflectedControl { count: 64, ..ctl }, &rc(true)), TrainDecision::Refused { len: 1200 });
        let tight = decide_train(ctl, &rc(true), Mode::Authenticated, ExtIntegrity::Valid, true, &tlvs, 1000.0);
        assert_eq!(tight, TrainDecision::Refused { len: 1200 });
    }

    #[test]
    fn serial_number_order() {
        assert!(after(2, 1) && !after(1, 1) && !after(1, 2));
        assert!(after(0, u32::MAX), "wraps");
    }

    #[test]
    fn reflected_control_needs_authenticated_sources() {
        let cfg = ReflectorConfig {
            listen: "127.0.0.1:0".into(),
            allow_any: true,
            reflected_control: rc(true),
            ..ReflectorConfig::default()
        };
        assert!(Reflector::bind(cfg).err().unwrap().contains("authenticated_sources"));
    }

    #[test]
    fn refuses_to_start_without_allowlist() {
        let cfg = ReflectorConfig { listen: "127.0.0.1:0".into(), ..ReflectorConfig::default() };
        assert!(Reflector::bind(cfg).err().unwrap().contains("allowlist"));
    }
}
