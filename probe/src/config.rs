//! Probe configuration (TOML). Secrets never live here: the ingest token comes
//! from a file (systemd `LoadCredential=`) or an environment variable.

use serde::Deserialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    pub probe_id: String,
    pub site: String,
    pub output: OutputSection,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub stamp: Vec<StampTarget>,
    #[serde(default)]
    pub icmp: Vec<IcmpTarget>,
    #[serde(default)]
    pub tcp: Vec<TcpTarget>,
    /// RFC 9946 speed-test targets (P3.3). Tests run only when the collector
    /// asks for one and the request fits this probe's own limits below.
    #[serde(default)]
    pub speedtest: Vec<SpeedtestTarget>,
    #[serde(default)]
    pub jobs: JobsSection,
}

/// `[[speedtest]]`: an RFC 9946 (UDPSTP) server this probe may test against,
/// with OB-UDPST's `udpst` as the client. Every limit here is enforced by the
/// probe itself, whatever the collector asks for.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpeedtestTarget {
    pub name: String,
    /// Must be set to true: a speed test fills the path for its duration.
    #[serde(default)]
    pub enabled: bool,
    /// UDPSTP server, `host` or `host:port` (port 24601 by default).
    pub server: String,
    /// The OB-UDPST client binary (absolute path).
    #[serde(default = "d_udpst_path")]
    pub udpst: String,
    /// Highest rate a test may request, Mbit/s (`udpst -B`).
    pub max_mbps: u32,
    /// Longest test, seconds (`udpst -t`; RFC 9946 default 10).
    #[serde(default = "d_st_duration")]
    pub max_duration_s: u32,
    /// DSCP for the test traffic. Priority classes (32 and up) are refused.
    #[serde(default)]
    pub dscp: u8,
    /// Directions the collector may ask for: "down" and/or "up".
    #[serde(default = "d_st_directions")]
    pub directions: Vec<String>,
    /// RFC 9946 authentication: a udpst key file (`udpst -K`). Never passed on
    /// the command line, so the key does not show in the process list.
    pub key_file: String,
    /// Key ID within the key file (`udpst -y`).
    #[serde(default)]
    pub key_id: u8,
}

/// `[jobs]`: how a probe with speed-test targets asks the collector for work.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobsSection {
    #[serde(default = "d_jobs_poll_s")]
    pub poll_s: u64,
    /// Defaults to output.url with `/results` replaced by `/jobs`.
    pub url: Option<String>,
}

impl Default for JobsSection {
    fn default() -> Self {
        Self { poll_s: d_jobs_poll_s(), url: None }
    }
}

impl JobsSection {
    pub fn resolved_url(&self, output_url: Option<&str>) -> Option<String> {
        self.url
            .clone()
            .or_else(|| output_url.and_then(|u| u.strip_suffix("/results").map(|base| format!("{base}/jobs"))))
    }
}

/// DSCP 32 and above (CS4, AF4x, CS5, VOICE-ADMIT, EF, CS6, CS7): priority
/// classes where a speed test could starve real-time traffic or trip a policer.
pub const SPEEDTEST_MAX_DSCP: u8 = 31;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSection {
    /// e.g. `https://ingest.lab.example:8443/v1/probe/results`. Omit to only print.
    pub url: Option<String>,
    /// Path to a file holding the token. `${VAR}` is expanded, so
    /// `${CREDENTIALS_DIRECTORY}/probe-token` works with systemd credentials.
    pub token_file: Option<String>,
    /// Name of an environment variable holding the token.
    pub token_env: Option<String>,
    /// Explicit HTTP(S) proxy, e.g. `http://proxy.lab:3128`.
    pub proxy: Option<String>,
    /// Plain HTTP is refused except to localhost unless this is set.
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default = "d_batch_ms")]
    pub batch_ms: u64,
    #[serde(default = "d_max_batch")]
    pub max_batch: usize,
    #[serde(default = "d_queue_max")]
    pub queue_max: usize,
    #[serde(default = "d_http_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default = "d_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "d_app_class")]
    pub app_class: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self { timeout_ms: d_timeout_ms(), app_class: d_app_class() }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StampTarget {
    pub name: String,
    /// `ip` or `ip:port` (port defaults to 862).
    pub target: String,
    /// Fixed source `ip:port` so the 5-tuple is stable for IPFIX matching.
    pub source: Option<String>,
    #[serde(default = "d_stamp_pps")]
    pub pps: f64,
    #[serde(default)]
    pub dscp: u8,
    pub app_class: Option<String>,
    #[serde(default = "d_stamp_size")]
    pub size: usize,
    pub timeout_ms: Option<u64>,
    /// Set false for third-party (stateless) reflectors; the forward/return
    /// loss split is then not reported.
    #[serde(default = "d_true")]
    pub stateful_reflector: bool,
    /// Paris traceroute along this session's 5-tuple (on by default).
    #[serde(default)]
    pub trace: TraceConfig,
    /// Packet-train capacity estimate (off unless `enabled = true`).
    pub capacity: Option<CapacityConfig>,
    /// RFC 8762 authenticated mode (HMAC). Needed for extensions that make the
    /// reflector send more than it received (RFC 10052 return trains).
    pub auth: Option<StampAuth>,
}

/// `[stamp.auth]`: authenticated STAMP for this session.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StampAuth {
    /// RFC 8972 Session-Sender Identifier (1-65535). The reflector looks the
    /// session's key up by it, so it must be unique per reflector.
    pub ssid: u16,
    /// File holding the HMAC key as hex (16-64 octets). `${VAR}` is expanded,
    /// so `${CREDENTIALS_DIRECTORY}/stamp-key` works with systemd credentials.
    pub key_file: String,
}

impl StampTarget {
    pub fn mode(&self) -> crate::stamp::Mode {
        if self.auth.is_some() {
            crate::stamp::Mode::Authenticated
        } else {
            crate::stamp::Mode::Unauthenticated
        }
    }

    /// Packet length on the wire: `size`, but never below the mode's base packet.
    pub fn packet_len(&self) -> usize {
        self.size.max(self.mode().base_len())
    }
}

/// Loads a hex HMAC key from a file (`${VAR}` expanded).
pub fn load_key(path: &str) -> Result<crate::stamp::Key, String> {
    let path = expand_env(path)?;
    check_private(Path::new(&path));
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("cannot read key file {path}: {e}"))?;
    crate::stamp::Key::from_hex(raw.trim()).map_err(|e| format!("key file {path}: {e}"))
}

/// `[stamp.trace]`: forward path tracing on the session's own flow.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceConfig {
    #[serde(default = "d_true")]
    pub enabled: bool,
    /// Scheduled trace interval.
    #[serde(default = "d_trace_interval_s")]
    pub interval_s: u64,
    /// Minimum time between traces triggered by a TTL change.
    #[serde(default = "d_trace_min_gap_s")]
    pub min_gap_s: u64,
    #[serde(default = "d_trace_rounds")]
    pub rounds: u8,
    /// Upper bound when the forward hop count is not known yet.
    #[serde(default = "d_trace_max_ttl")]
    pub max_ttl: u8,
    #[serde(default = "d_trace_round_timeout_ms")]
    pub round_timeout_ms: u64,
    /// Delay before the first trace, so the session has learned the hop count.
    #[serde(default = "d_trace_start_delay_s")]
    pub start_delay_s: u64,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_s: d_trace_interval_s(),
            min_gap_s: d_trace_min_gap_s(),
            rounds: d_trace_rounds(),
            max_ttl: d_trace_max_ttl(),
            round_timeout_ms: d_trace_round_timeout_ms(),
            start_delay_s: d_trace_start_delay_s(),
        }
    }
}

/// `[stamp.capacity]`: forward bottleneck capacity from packet-train dispersion.
/// Trains are bursts by design; enable per target, on networks where that is agreed.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Fixed source `ip:port` for the train socket (a separate STAMP session on
    /// the reflector). Defaults to the session's source address, any port.
    pub source: Option<String>,
    #[serde(default = "d_cap_interval_s")]
    pub interval_s: u64,
    /// Packets per train.
    #[serde(default = "d_cap_packets")]
    pub packets: u32,
    /// STAMP packet size (UDP payload octets).
    #[serde(default = "d_cap_size")]
    pub size: usize,
    /// Trains per measurement; the result is their median.
    #[serde(default = "d_cap_trains")]
    pub trains: u32,
    #[serde(default = "d_cap_train_gap_ms")]
    pub train_gap_ms: u64,
    /// DSCP for the trains; defaults to the session's.
    pub dscp: Option<u8>,
    /// Also measure the return direction with RFC 10052 reflected trains
    /// (needs [stamp.auth] and a reflector with reflected_control enabled).
    #[serde(default)]
    pub return_trains: bool,
    #[serde(default = "d_cap_start_delay_s")]
    pub start_delay_s: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IcmpTarget {
    pub name: String,
    pub target: Ipv4Addr,
    #[serde(default = "d_icmp_pps")]
    pub pps: f64,
    #[serde(default)]
    pub dscp: u8,
    pub app_class: Option<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpTarget {
    pub name: String,
    /// `host:port`; resolved on every attempt.
    pub target: String,
    #[serde(default = "d_tcp_interval_ms")]
    pub interval_ms: u64,
    #[serde(default)]
    pub dscp: u8,
    pub app_class: Option<String>,
    /// Connect timeout.
    pub timeout_ms: Option<u64>,
}

fn d_batch_ms() -> u64 {
    1000
}
fn d_max_batch() -> usize {
    1000
}
fn d_queue_max() -> usize {
    20_000
}
fn d_http_timeout_ms() -> u64 {
    10_000
}
fn d_timeout_ms() -> u64 {
    2000
}
fn d_app_class() -> String {
    "bulk".to_string()
}
fn d_stamp_pps() -> f64 {
    10.0
}
fn d_stamp_size() -> usize {
    crate::stamp::BASE_LEN
}
fn d_icmp_pps() -> f64 {
    1.0
}
fn d_tcp_interval_ms() -> u64 {
    5000
}
fn d_true() -> bool {
    true
}
fn d_udpst_path() -> String {
    "/usr/local/bin/udpst".into()
}
fn d_st_duration() -> u32 {
    10
}
fn d_st_directions() -> Vec<String> {
    vec!["down".into(), "up".into()]
}
fn d_jobs_poll_s() -> u64 {
    15
}
fn d_trace_interval_s() -> u64 {
    300
}
fn d_trace_min_gap_s() -> u64 {
    30
}
fn d_trace_rounds() -> u8 {
    3
}
fn d_trace_max_ttl() -> u8 {
    30
}
fn d_trace_round_timeout_ms() -> u64 {
    1000
}
fn d_trace_start_delay_s() -> u64 {
    3
}
fn d_cap_interval_s() -> u64 {
    900
}
fn d_cap_packets() -> u32 {
    48
}
fn d_cap_size() -> usize {
    1200
}
fn d_cap_trains() -> u32 {
    5
}
fn d_cap_train_gap_ms() -> u64 {
    500
}
fn d_cap_start_delay_s() -> u64 {
    10
}

fn valid_name(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn valid_app_class(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

pub fn parse_v4_endpoint(s: &str, default_port: u16) -> Result<SocketAddrV4, String> {
    if let Ok(a) = s.parse::<SocketAddrV4>() {
        return Ok(a);
    }
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(ip, default_port));
    }
    Err(format!("{s:?} is not an IPv4 address or ip:port"))
}

impl ProbeConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let cfg: ProbeConfig = toml::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !valid_name(&self.probe_id, 64) {
            return Err(format!("probe_id {:?}: 1-64 chars of [A-Za-z0-9._-]", self.probe_id));
        }
        if self.site.is_empty() || self.site.len() > 64 {
            return Err("site: 1-64 characters".into());
        }
        if !valid_app_class(&self.defaults.app_class) {
            return Err(format!("defaults.app_class {:?}: 1-32 chars of [a-z0-9_-]", self.defaults.app_class));
        }
        check_timeout("defaults.timeout_ms", self.defaults.timeout_ms)?;

        let mut names = HashSet::new();
        let mut check_common =
            |kind: &str, name: &str, dscp: u8, app: &Option<String>, timeout: Option<u64>| -> Result<(), String> {
                if !valid_name(name, 64) {
                    return Err(format!("{kind} name {name:?}: 1-64 chars of [A-Za-z0-9._-]"));
                }
                if !names.insert(name.to_string()) {
                    return Err(format!("session name {name:?} is used twice"));
                }
                if dscp > 63 {
                    return Err(format!("{kind} {name}: dscp must be 0-63"));
                }
                if let Some(a) = app {
                    if !valid_app_class(a) {
                        return Err(format!("{kind} {name}: app_class {a:?}: 1-32 chars of [a-z0-9_-]"));
                    }
                }
                if let Some(t) = timeout {
                    check_timeout(&format!("{kind} {name}: timeout_ms"), t)?;
                }
                Ok(())
            };

        for s in &self.stamp {
            check_common("stamp", &s.name, s.dscp, &s.app_class, s.timeout_ms)?;
            parse_v4_endpoint(&s.target, crate::stamp::PORT).map_err(|e| format!("stamp {}: target {e}", s.name))?;
            if let Some(src) = &s.source {
                parse_v4_endpoint(src, 0).map_err(|e| format!("stamp {}: source {e}", s.name))?;
            }
            check_pps(&format!("stamp {}", s.name), s.pps)?;
            check_trace(&s.name, &s.trace)?;
            if let Some(c) = &s.capacity {
                check_capacity(&s.name, c)?;
                if c.return_trains && s.auth.is_none() {
                    return Err(format!(
                        "stamp {}: capacity.return_trains needs [stamp.auth]: reflectors only send return trains \
                         to authenticated sessions",
                        s.name
                    ));
                }
                if !crate::stamp::len_ok(s.mode().base_len(), c.size) {
                    return Err(format!(
                        "stamp {}: capacity.size must be the base packet ({}) or at least {} more",
                        s.name,
                        s.mode().base_len(),
                        crate::stamp::TLV_HEADER
                    ));
                }
            }
            if let Some(a) = &s.auth {
                if a.ssid == 0 {
                    return Err(format!("stamp {}: auth.ssid must be 1-65535 (0 means none)", s.name));
                }
                if a.key_file.trim().is_empty() {
                    return Err(format!("stamp {}: auth.key_file is empty", s.name));
                }
            }
            if !(crate::stamp::BASE_LEN..=crate::stamp::MAX_LEN).contains(&s.size) {
                return Err(format!(
                    "stamp {}: size must be {}-{}",
                    s.name,
                    crate::stamp::BASE_LEN,
                    crate::stamp::MAX_LEN
                ));
            }
            if !crate::stamp::len_ok(s.mode().base_len(), s.packet_len()) {
                return Err(format!(
                    "stamp {}: size must be the base packet ({}) or at least {} more (room for an Extra Padding TLV)",
                    s.name,
                    s.mode().base_len(),
                    crate::stamp::TLV_HEADER
                ));
            }
        }
        for s in &self.icmp {
            check_common("icmp", &s.name, s.dscp, &s.app_class, s.timeout_ms)?;
            check_pps(&format!("icmp {}", s.name), s.pps)?;
        }
        for s in &self.tcp {
            check_common("tcp", &s.name, s.dscp, &s.app_class, s.timeout_ms)?;
            if !s.target.contains(':') {
                return Err(format!("tcp {}: target must be host:port", s.name));
            }
            if !(500..=3_600_000).contains(&s.interval_ms) {
                return Err(format!("tcp {}: interval_ms must be 500-3600000", s.name));
            }
        }
        if names.is_empty() {
            return Err("no sessions configured ([[stamp]], [[icmp]] or [[tcp]])".into());
        }
        let mut st_names = HashSet::new();
        for t in &self.speedtest {
            check_speedtest(t)?;
            if !st_names.insert(t.name.clone()) {
                return Err(format!("speedtest name {:?} is used twice", t.name));
            }
        }
        if !(5..=3600).contains(&self.jobs.poll_s) {
            return Err("jobs.poll_s must be 5-3600".into());
        }
        if self.speedtest.iter().any(|t| t.enabled) && self.jobs.resolved_url(self.output.url.as_deref()).is_none() {
            return Err("speed tests need jobs.url (or an output.url ending in /results)".into());
        }

        let o = &self.output;
        if let Some(url) = &o.url {
            let lower = url.to_ascii_lowercase();
            let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"].iter().any(|p| lower.starts_with(p));
            if lower.starts_with("http://") && !local && !o.allow_insecure_http {
                return Err(
                    "output.url is plain HTTP to a non-local host; use HTTPS or set allow_insecure_http = true".into(),
                );
            }
            if !lower.starts_with("http://") && !lower.starts_with("https://") {
                return Err("output.url must be http(s)://".into());
            }
            if o.token_file.is_none() && o.token_env.is_none() {
                return Err("output.url needs token_file or token_env".into());
            }
        }
        if !(100..=60_000).contains(&o.batch_ms) || !(1..=5000).contains(&o.max_batch) || o.queue_max < o.max_batch {
            return Err("output: batch_ms 100-60000, max_batch 1-5000, queue_max >= max_batch".into());
        }
        if !(1000..=120_000).contains(&o.timeout_ms) {
            return Err("output.timeout_ms must be 1000-120000".into());
        }
        Ok(())
    }

    pub fn app_class<'a>(&'a self, specific: &'a Option<String>) -> &'a str {
        specific.as_deref().unwrap_or(&self.defaults.app_class)
    }

    pub fn timeout_ms(&self, specific: Option<u64>) -> u64 {
        specific.unwrap_or(self.defaults.timeout_ms)
    }
}

fn check_timeout(what: &str, t: u64) -> Result<(), String> {
    if (100..=30_000).contains(&t) {
        Ok(())
    } else {
        Err(format!("{what} must be 100-30000"))
    }
}

fn check_trace(name: &str, t: &TraceConfig) -> Result<(), String> {
    let bad = |what: &str| Err(format!("stamp {name}: trace.{what}"));
    if !(30..=86_400).contains(&t.interval_s) {
        return bad("interval_s must be 30-86400");
    }
    if !(5..=3600).contains(&t.min_gap_s) {
        return bad("min_gap_s must be 5-3600");
    }
    if !(1..=5).contains(&t.rounds) {
        return bad("rounds must be 1-5");
    }
    if !(1..=crate::trace::MAX_TTL).contains(&t.max_ttl) {
        return Err(format!("stamp {name}: trace.max_ttl must be 1-{}", crate::trace::MAX_TTL));
    }
    if !(200..=5000).contains(&t.round_timeout_ms) {
        return bad("round_timeout_ms must be 200-5000");
    }
    if t.start_delay_s > 60 {
        return bad("start_delay_s must be 0-60");
    }
    Ok(())
}

fn check_capacity(name: &str, c: &CapacityConfig) -> Result<(), String> {
    let bad = |what: &str| Err(format!("stamp {name}: capacity.{what}"));
    if let Some(src) = &c.source {
        parse_v4_endpoint(src, 0).map_err(|e| format!("stamp {name}: capacity.source {e}"))?;
    }
    if !(60..=86_400).contains(&c.interval_s) {
        return bad("interval_s must be 60-86400");
    }
    if !(8..=128).contains(&c.packets) {
        return bad("packets must be 8-128");
    }
    if !(200..=crate::stamp::MAX_LEN).contains(&c.size) {
        return Err(format!("stamp {name}: capacity.size must be 200-{}", crate::stamp::MAX_LEN));
    }
    if !(1..=10).contains(&c.trains) {
        return bad("trains must be 1-10");
    }
    if !(100..=10_000).contains(&c.train_gap_ms) {
        return bad("train_gap_ms must be 100-10000");
    }
    if c.dscp.is_some_and(|d| d > 63) {
        return bad("dscp must be 0-63");
    }
    if c.start_delay_s > 3600 {
        return bad("start_delay_s must be 0-3600");
    }
    Ok(())
}

fn check_speedtest(t: &SpeedtestTarget) -> Result<(), String> {
    let name = &t.name;
    if !valid_name(name, 64) {
        return Err(format!("speedtest name {name:?}: 1-64 chars of [A-Za-z0-9._-]"));
    }
    let host = t.server.rsplit_once(':').map_or(t.server.as_str(), |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
            h
        } else {
            t.server.as_str()
        }
    });
    if host.is_empty()
        || host.len() > 253
        || !host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        || host.starts_with('-')
    {
        return Err(format!("speedtest {name}: server must be a hostname or IPv4 address, optionally :port"));
    }
    if !t.udpst.starts_with('/') {
        return Err(format!("speedtest {name}: udpst must be an absolute path"));
    }
    if !(1..=10_000).contains(&t.max_mbps) {
        return Err(format!("speedtest {name}: max_mbps must be 1-10000"));
    }
    if !(1..=60).contains(&t.max_duration_s) {
        return Err(format!("speedtest {name}: max_duration_s must be 1-60"));
    }
    if t.dscp > SPEEDTEST_MAX_DSCP {
        return Err(format!(
            "speedtest {name}: dscp {} is a priority class; speed tests are limited to DSCP 0-{SPEEDTEST_MAX_DSCP}",
            t.dscp
        ));
    }
    if t.directions.is_empty() || t.directions.iter().any(|d| d != "down" && d != "up") {
        return Err(format!("speedtest {name}: directions must be \"down\" and/or \"up\""));
    }
    if t.key_file.trim().is_empty() {
        return Err(format!("speedtest {name}: key_file is required (RFC 9946 authentication)"));
    }
    Ok(())
}

fn check_pps(what: &str, pps: f64) -> Result<(), String> {
    if pps.is_finite() && pps > 0.0 && pps <= 1000.0 {
        Ok(())
    } else {
        Err(format!("{what}: pps must be > 0 and <= 1000"))
    }
}

/// Expands `${VAR}` references using the process environment.
pub fn expand_env(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| format!("unterminated ${{ in {s:?}"))?;
        let var = &after[..end];
        let val = std::env::var(var).map_err(|_| format!("environment variable {var} is not set (needed by {s:?})"))?;
        out.push_str(&val);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Resolves the ingest token from `token_file` or `token_env`.
pub fn resolve_token(o: &OutputSection) -> Result<String, String> {
    if let Some(path) = &o.token_file {
        let path = expand_env(path)?;
        check_private(Path::new(&path));
        let token = std::fs::read_to_string(&path).map_err(|e| format!("cannot read token file {path}: {e}"))?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(format!("token file {path} is empty"));
        }
        return Ok(token);
    }
    if let Some(var) = &o.token_env {
        let token = std::env::var(var).map_err(|_| format!("environment variable {var} (token_env) is not set"))?;
        if token.trim().is_empty() {
            return Err(format!("environment variable {var} is empty"));
        }
        return Ok(token.trim().to_string());
    }
    Err("no token_file or token_env configured".into())
}

fn check_private(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.permissions().mode() & 0o077 != 0 {
            log::warn!("secret file {} is readable by group/others; chmod 600 it", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: &str = r#"
        probe_id = "sjc-br01-p1"
        site = "SJC-BR01"
        [output]
        url = "https://ingest.example:8443/v1/probe/results"
        token_env = "BUFFMON_TOKEN"
        [[stamp]]
        name = "dc1-voice"
        target = "10.10.0.20"
        dscp = 46
        app_class = "voice"
    "#;

    #[test]
    fn minimal_config_parses_with_defaults() {
        let c: ProbeConfig = toml::from_str(MIN).unwrap();
        c.validate().unwrap();
        assert_eq!(c.stamp[0].pps, 10.0);
        assert_eq!(c.stamp[0].size, 44);
        assert!(c.stamp[0].stateful_reflector);
        assert_eq!(parse_v4_endpoint(&c.stamp[0].target, 862).unwrap().port(), 862);
        assert_eq!(c.timeout_ms(None), 2000);
    }

    #[test]
    fn rejects_unknown_fields_bad_dscp_duplicates_and_plain_http() {
        assert!(toml::from_str::<ProbeConfig>(&MIN.replace("dscp = 46", "dscp = 46\nbogus = 1")).is_err());
        let c: ProbeConfig = toml::from_str(&MIN.replace("dscp = 46", "dscp = 64")).unwrap();
        assert!(c.validate().is_err());
        let dup = format!("{MIN}\n[[icmp]]\nname = \"dc1-voice\"\ntarget = \"10.0.0.1\"\n");
        let c: ProbeConfig = toml::from_str(&dup).unwrap();
        assert!(c.validate().unwrap_err().contains("twice"));
        let c: ProbeConfig = toml::from_str(&MIN.replace("https://ingest.example", "http://ingest.example")).unwrap();
        assert!(c.validate().unwrap_err().contains("plain HTTP"));
        let c: ProbeConfig =
            toml::from_str(&MIN.replace("https://ingest.example:8443", "http://127.0.0.1:8080")).unwrap();
        c.validate().unwrap();
    }

    #[test]
    fn trace_is_on_and_capacity_off_by_default() {
        let c: ProbeConfig = toml::from_str(MIN).unwrap();
        assert!(c.stamp[0].trace.enabled && c.stamp[0].trace.interval_s == 300);
        assert!(c.stamp[0].capacity.is_none());
        let with = format!("{MIN}\n[stamp.trace]\ninterval_s = 60\n[stamp.capacity]\nenabled = true\npackets = 64\n");
        let c: ProbeConfig = toml::from_str(&with).unwrap();
        c.validate().unwrap();
        assert_eq!(c.stamp[0].trace.interval_s, 60);
        let cap = c.stamp[0].capacity.as_ref().unwrap();
        assert!(cap.enabled && cap.packets == 64 && cap.size == 1200 && cap.trains == 5);
        for (bad, msg) in [
            ("[stamp.trace]\ninterval_s = 5", "trace.interval_s"),
            ("[stamp.trace]\nmax_ttl = 40", "trace.max_ttl"),
            ("[stamp.capacity]\nenabled = true\npackets = 1000", "capacity.packets"),
            ("[stamp.capacity]\nenabled = true\nsize = 9000", "capacity.size"),
            ("[stamp.capacity]\nenabled = true\ninterval_s = 10", "capacity.interval_s"),
        ] {
            let c: ProbeConfig = toml::from_str(&format!("{MIN}\n{bad}\n")).unwrap();
            assert!(c.validate().unwrap_err().contains(msg), "{bad}");
        }
    }

    #[test]
    fn auth_section_selects_authenticated_mode_and_a_112_octet_minimum() {
        let c: ProbeConfig = toml::from_str(MIN).unwrap();
        assert_eq!((c.stamp[0].mode(), c.stamp[0].packet_len()), (crate::stamp::Mode::Unauthenticated, 44));
        let with = format!("{MIN}\n[stamp.auth]\nssid = 4101\nkey_file = \"/etc/buffmon/stamp-key\"\n");
        let c: ProbeConfig = toml::from_str(&with).unwrap();
        c.validate().unwrap();
        assert_eq!((c.stamp[0].mode(), c.stamp[0].packet_len()), (crate::stamp::Mode::Authenticated, 112));
        let zero = with.replace("ssid = 4101", "ssid = 0");
        assert!(toml::from_str::<ProbeConfig>(&zero).unwrap().validate().unwrap_err().contains("auth.ssid"));
        let odd = MIN.replace("app_class = \"voice\"", "app_class = \"voice\"\nsize = 46");
        assert!(toml::from_str::<ProbeConfig>(&odd).unwrap().validate().unwrap_err().contains("Extra Padding"));
    }

    #[test]
    fn keys_load_from_hex_files() {
        let dir = std::env::temp_dir().join(format!("bm-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("k");
        std::fs::write(&f, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n").unwrap();
        assert_eq!(load_key(f.to_str().unwrap()).unwrap().to_hex().len(), 64);
        std::fs::write(&f, "not hex").unwrap();
        assert!(load_key(f.to_str().unwrap()).unwrap_err().contains("hex"));
        assert!(load_key("/nonexistent/key").unwrap_err().contains("cannot read"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn speedtest_targets_are_validated() {
        let base = format!(
            "{MIN}\n[[speedtest]]\nname = \"dc1-st\"\nenabled = true\nserver = \"st.dc1.example:24601\"\n\
             max_mbps = 500\nkey_file = \"/etc/buffmon/udpst.keys\"\n"
        );
        let c: ProbeConfig = toml::from_str(&base).unwrap();
        c.validate().unwrap();
        let t = &c.speedtest[0];
        assert_eq!((t.max_duration_s, t.dscp, t.directions.len()), (10, 0, 2));
        assert_eq!(
            c.jobs.resolved_url(c.output.url.as_deref()).as_deref(),
            Some("https://ingest.example:8443/v1/probe/jobs")
        );
        for (from, to) in [
            ("max_mbps = 500", "max_mbps = 0"),
            ("max_mbps = 500", "max_mbps = 500\ndscp = 46"),
            ("max_mbps = 500", "max_mbps = 500\ndirections = [\"sideways\"]"),
            ("max_mbps = 500", "max_mbps = 500\nmax_duration_s = 600"),
            ("max_mbps = 500", "max_mbps = 500\nudpst = \"udpst\""),
            ("st.dc1.example:24601", "st.dc1.example;rm -rf /"),
        ] {
            let c: ProbeConfig = toml::from_str(&base.replace(from, to)).unwrap();
            assert!(c.validate().is_err(), "{to}");
        }
    }

    #[test]
    fn expand_env_substitutes_and_reports_missing() {
        std::env::set_var("BUFFMON_TEST_DIR", "/run/creds");
        assert_eq!(expand_env("${BUFFMON_TEST_DIR}/probe-token").unwrap(), "/run/creds/probe-token");
        assert!(expand_env("${BUFFMON_DEFINITELY_UNSET}/x").is_err());
    }
}
