//! Paris traceroute along a STAMP session's own 5-tuple and DSCP (Phase 3).
//!
//! Why the session's own flow: routers hash flows onto ECMP members, and
//! EdgeConnect steers flows onto overlays by DSCP, application and ports. A
//! traceroute sent from any other port, or with another DSCP, may follow a path
//! the probes never take. Trace packets leave through the session's own socket,
//! so source and destination address and port, protocol and DSCP are those of
//! the probes; only the TTL and the payload length differ.
//!
//! * Payload: `8 + ttl` octets (9-40). That is shorter than any STAMP packet
//!   (44), so a reflector that receives one discards it as malformed: trace
//!   packets never enter the session's loss accounting.
//! * Identification: the UDP length in the header a router quotes back in its
//!   ICMP Time Exceeded encodes the TTL. Every router quotes at least those 8
//!   octets (RFC 792), and NAT keeps the length, so matching does not depend on
//!   routers quoting more. When they do, the payload's magic and session tag
//!   are checked as well.
//! * Replies arrive on a raw ICMP socket (CAP_NET_RAW, which the probe already
//!   holds for ICMP sessions). Without it, tracing is disabled with a warning.
//! * Rounds: every TTL is probed once per round, rounds are a round-timeout
//!   apart, so each router sees at most one probe per round from this session
//!   (routers rate-limit Time Exceeded).
//! * Forward path only. The return path's length is watched through the
//!   received TTL of the STAMP replies; a change there triggers a trace, but a
//!   traceroute cannot show the return hops.
//! * A trace that reaches a closed port (reflector down) makes the kernel report
//!   ECONNREFUSED on the session socket; the session then counts its next send
//!   as refused, which is true at that point anyway.

use crate::clock;
use crate::config::TraceConfig;
use crate::record::SessionMeta;
use crate::sys;
use crate::{sleep_until, Throttle, POLL_INTERVAL};
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAGIC: &[u8; 4] = b"bmtr";
/// Payload octets before the TTL-dependent padding: magic, TTL, round, tag.
pub const BASE_PAYLOAD: usize = 8;
/// Highest TTL whose payload (8 + ttl) stays below a STAMP packet's 44 octets.
pub const MAX_TTL: u8 = 35;
const UDP_HEADER: usize = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_DEST_UNREACH: u8 = 3;
/// Responding addresses remembered per TTL (per-packet load balancing shows
/// several; more than this is noise).
const MAX_ADDRS_PER_HOP: usize = 8;

/// Trace packet payload for `ttl` in `round`.
pub fn payload(ttl: u8, round: u8, tag: u16) -> Vec<u8> {
    let mut p = vec![0_u8; BASE_PAYLOAD + usize::from(ttl)];
    p[0..4].copy_from_slice(MAGIC);
    p[4] = ttl;
    p[5] = round;
    p[6..8].copy_from_slice(&tag.to_be_bytes());
    p
}

/// TTL encoded by a quoted UDP length, if it is one of ours.
pub fn ttl_from_udp_len(udp_len: u16) -> Option<u8> {
    let extra = usize::from(udp_len).checked_sub(UDP_HEADER + BASE_PAYLOAD)?;
    u8::try_from(extra).ok().filter(|t| (1..=MAX_TTL).contains(t))
}

/// An ICMP error quoting a UDP datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpQuote {
    pub from: Ipv4Addr,
    pub icmp_type: u8,
    pub code: u8,
    pub q_src: Ipv4Addr,
    pub q_dst: Ipv4Addr,
    pub q_tos: u8,
    pub sport: u16,
    pub dport: u16,
    pub udp_len: u16,
    /// Quoted UDP payload, as far as the router quoted it.
    pub payload: Vec<u8>,
}

/// Parses a raw-socket ICMP packet (IP header included) carrying a Time
/// Exceeded or Destination Unreachable that quotes a UDP datagram.
pub fn parse_icmp_error(pkt: &[u8]) -> Option<IcmpQuote> {
    let ihl = usize::from(*pkt.first()? & 0x0F) * 4;
    if pkt.first()? >> 4 != 4 || ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let from = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let icmp = &pkt[ihl..];
    let (icmp_type, code) = (icmp[0], icmp[1]);
    if icmp_type != ICMP_TIME_EXCEEDED && icmp_type != ICMP_DEST_UNREACH {
        return None;
    }
    let q = &icmp[8..];
    let qihl = usize::from(*q.first()? & 0x0F) * 4;
    if q.first()? >> 4 != 4 || qihl < 20 || q.len() < qihl + UDP_HEADER || q[9] != libc::IPPROTO_UDP as u8 {
        return None;
    }
    let udp = &q[qihl..];
    Some(IcmpQuote {
        from,
        icmp_type,
        code,
        q_src: Ipv4Addr::new(q[12], q[13], q[14], q[15]),
        q_dst: Ipv4Addr::new(q[16], q[17], q[18], q[19]),
        q_tos: q[1],
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
        udp_len: u16::from_be_bytes([udp[4], udp[5]]),
        payload: udp[UDP_HEADER..].to_vec(),
    })
}

/// The flow being traced and how to recognise replies to it.
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub local: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub tag: u16,
}

impl Flow {
    /// The TTL this quote answers, if it quotes one of this flow's trace packets.
    pub fn matches(&self, q: &IcmpQuote, round: u8) -> Option<u8> {
        if q.q_dst != *self.dst.ip() || q.dport != self.dst.port() || q.sport != self.local.port() {
            return None;
        }
        if !self.local.ip().is_unspecified() && q.q_src != *self.local.ip() {
            return None;
        }
        let ttl = ttl_from_udp_len(q.udp_len)?;
        // Routers that quote more than 8 octets let us check the rest too.
        if q.payload.len() >= BASE_PAYLOAD
            && (&q.payload[0..4] != MAGIC
                || q.payload[4] != ttl
                || q.payload[5] != round
                || u16::from_be_bytes([q.payload[6], q.payload[7]]) != self.tag)
        {
            return None;
        }
        Some(ttl)
    }
}

/// One reply to one trace packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopReply {
    pub ttl: u8,
    pub from: Ipv4Addr,
    pub rtt_ns: i64,
    /// `Some(code)` for Destination Unreachable, None for Time Exceeded.
    pub unreachable: Option<u8>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Hop {
    pub ttl: u8,
    /// Addresses that answered for this TTL, sorted. Several under per-packet
    /// load balancing; empty when no router answered.
    pub addrs: Vec<String>,
    /// Lowest RTT over the replies, microseconds.
    pub rtt_us: Option<u32>,
    pub sent: u8,
    pub replies: u8,
    /// ICMP Destination Unreachable code, if the hop answered with one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreachable: Option<u8>,
}

/// Aggregates replies into one hop per TTL in `1..=max_ttl`. When the path
/// length is unknown, trailing silent hops are trimmed.
pub fn hops(replies: &[HopReply], max_ttl: u8, rounds: u8, length_known: bool) -> Vec<Hop> {
    let mut by_ttl: BTreeMap<u8, Vec<&HopReply>> = BTreeMap::new();
    for r in replies.iter().filter(|r| (1..=max_ttl).contains(&r.ttl)) {
        by_ttl.entry(r.ttl).or_default().push(r);
    }
    let mut out: Vec<Hop> = (1..=max_ttl)
        .map(|ttl| {
            let rs = by_ttl.get(&ttl).map(Vec::as_slice).unwrap_or(&[]);
            let addrs: BTreeSet<Ipv4Addr> = rs.iter().map(|r| r.from).collect();
            Hop {
                ttl,
                addrs: addrs.iter().take(MAX_ADDRS_PER_HOP).map(Ipv4Addr::to_string).collect(),
                rtt_us: rs.iter().map(|r| r.rtt_ns.max(0) / 1000).min().map(|us| u32::try_from(us).unwrap_or(u32::MAX)),
                sent: rounds,
                replies: u8::try_from(rs.len()).unwrap_or(u8::MAX),
                unreachable: rs.iter().find_map(|r| r.unreachable),
            }
        })
        .collect();
    // A Destination Unreachable ends the path: nothing beyond it is reachable.
    if let Some(end) = out.iter().position(|h| h.unreachable.is_some()) {
        out.truncate(end + 1);
    }
    if !length_known {
        while out.last().is_some_and(|h| h.addrs.is_empty()) {
            out.pop();
        }
    }
    out
}

/// `ttl1>ttl2>...`, each hop its sorted addresses joined by `|`, `*` if silent.
pub fn signature(hops: &[Hop]) -> String {
    hops.iter()
        .map(|h| if h.addrs.is_empty() { "*".to_string() } else { h.addrs.join("|") })
        .collect::<Vec<_>>()
        .join(">")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// First TTL whose responding routers are all new, if any.
    pub ttl: Option<u8>,
    pub reason: &'static str,
    pub prev_signature: String,
}

/// What the probe knows about the path: per TTL, every address seen since the
/// last change (so per-packet load balancing does not look like a change), and
/// the forward length from the STAMP TTL.
#[derive(Debug, Default)]
pub struct PathMemory {
    known: Vec<BTreeSet<Ipv4Addr>>,
    length: Option<u8>,
    signature: Option<String>,
}

impl PathMemory {
    /// Folds in a trace; returns the change it shows, if any.
    ///
    /// A change is a TTL where routers answered both before and now and none of
    /// the addresses match, or a different forward hop count. A silent hop is
    /// never a change: routers rate-limit and drop ICMP.
    pub fn observe(&mut self, hops: &[Hop], length: Option<u8>) -> Option<Change> {
        let cur: Vec<BTreeSet<Ipv4Addr>> =
            hops.iter().map(|h| h.addrs.iter().filter_map(|a| a.parse().ok()).collect()).collect();
        let sig = signature(hops);
        let Some(prev_sig) = self.signature.replace(sig) else {
            self.known = cur;
            self.length = length;
            return None;
        };
        let moved = self
            .known
            .iter()
            .zip(&cur)
            .position(|(k, c)| !k.is_empty() && !c.is_empty() && k.is_disjoint(c))
            .map(|i| i as u8 + 1);
        let lengthened = matches!((self.length, length), (Some(a), Some(b)) if a != b);
        if moved.is_some() || lengthened {
            self.known = cur;
            self.length = length;
            return Some(Change {
                ttl: moved,
                reason: if moved.is_some() { "hop" } else { "length" },
                prev_signature: prev_sig,
            });
        }
        for (i, c) in cur.into_iter().enumerate() {
            match self.known.get_mut(i) {
                Some(k) => {
                    k.extend(c);
                    while k.len() > MAX_ADDRS_PER_HOP {
                        k.pop_first();
                    }
                }
                None => self.known.push(c),
            }
        }
        if length.is_some() {
            self.length = length;
        }
        None
    }
}

/// Forward hop count from the TTL the reflector received and the TTL we sent.
pub fn hop_count(initial_ttl: u8, received_ttl: u8) -> Option<u8> {
    initial_ttl.checked_sub(received_ttl)
}

/// The STAMP receive loop publishes the TTLs it sees (forward as reported by
/// the reflector, return as received) once they have been stable for a few
/// replies; the trace thread re-traces when they change.
#[derive(Debug, Default)]
pub struct TtlHint {
    packed: AtomicU32,
}

impl TtlHint {
    const KNOWN: u32 = 1 << 16;

    pub fn set(&self, fwd: u8, back: u8) {
        self.packed.store(Self::KNOWN | u32::from(fwd) << 8 | u32::from(back), Ordering::Relaxed);
    }

    /// (forward TTL at the reflector, return TTL at the probe), once known.
    pub fn get(&self) -> Option<(u8, u8)> {
        let v = self.packed.load(Ordering::Relaxed);
        (v & Self::KNOWN != 0).then_some(((v >> 8) as u8, v as u8))
    }
}

/// Debounces per-reply TTL observations: publishes a pair after it was seen
/// `need` times in a row.
#[derive(Debug)]
pub struct TtlDebounce {
    cand: Option<(u8, u8)>,
    count: u32,
    need: u32,
}

impl TtlDebounce {
    pub fn new(need: u32) -> Self {
        Self { cand: None, count: 0, need }
    }

    pub fn observe(&mut self, fwd: u8, back: u8, hint: &TtlHint) {
        if self.cand == Some((fwd, back)) {
            self.count += 1;
        } else {
            self.cand = Some((fwd, back));
            self.count = 1;
        }
        if self.count == self.need {
            hint.set(fwd, back);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteResult {
    pub v: u32,
    pub probe_id: String,
    pub site: String,
    pub session: String,
    pub kind: &'static str,
    pub app_class: String,
    pub dscp: u8,
    pub src: String,
    pub dst: String,
    /// Trace start, Unix ms.
    pub ts_ms: i64,
    pub duration_ms: u32,
    /// "start", "schedule" or "ttl_change".
    pub trigger: &'static str,
    /// TTL the reflector received / the probe received, from the STAMP session.
    pub ttl_fwd: Option<u8>,
    pub ttl_back: Option<u8>,
    /// Routers between probe and reflector (sent TTL minus received TTL).
    pub hop_count_fwd: Option<u8>,
    pub hops: Vec<Hop>,
    /// Every hop up to the known forward length answered at least once.
    pub complete: bool,
    /// Some TTL answered from more than one address (per-packet load balancing,
    /// or the path moved during the trace).
    pub multipath: bool,
    pub signature: String,
    pub changed: bool,
    pub change_ttl: Option<u8>,
    pub change_reason: Option<&'static str>,
    pub prev_signature: Option<String>,
}

/// Probes every TTL in `1..=max_ttl` for `rounds` rounds and collects replies.
pub fn run_trace(
    send_fd: RawFd,
    icmp: &Socket,
    flow: Flow,
    max_ttl: u8,
    rounds: u8,
    round_timeout: Duration,
) -> io::Result<Vec<HopReply>> {
    let mut buf = [0_u8; 2048];
    let mut replies = Vec::new();
    let mut send_err = None;
    for round in 0..rounds {
        let mut sent_at = BTreeMap::new();
        for ttl in 1..=max_ttl {
            let t = clock::now_ns();
            match sys::send_with_ttl(send_fd, &payload(ttl, round, flow.tag), ttl) {
                Ok(_) => {
                    sent_at.insert(ttl, t);
                }
                // A pending ICMP error on the session socket (e.g. port
                // unreachable from a down reflector) surfaces here once.
                Err(e) => send_err = Some(e),
            }
        }
        let deadline = Instant::now() + round_timeout;
        let mut seen = BTreeSet::new();
        while Instant::now() < deadline && seen.len() < sent_at.len() {
            let m = match sys::recv_meta(icmp.as_raw_fd(), &mut buf) {
                Ok(m) => m,
                Err(e) if sys::is_timeout(&e) => continue,
                Err(e) => return Err(e),
            };
            let Some(q) = parse_icmp_error(&buf[..m.len]) else { continue };
            let Some(ttl) = flow.matches(&q, round) else { continue };
            let Some(t1) = sent_at.get(&ttl) else { continue };
            if !seen.insert(ttl) {
                continue;
            }
            let t = m.kernel_ts_ns.unwrap_or_else(clock::now_ns);
            replies.push(HopReply {
                ttl,
                from: q.from,
                rtt_ns: t - t1,
                unreachable: (q.icmp_type == ICMP_DEST_UNREACH).then_some(q.code),
            });
        }
    }
    if replies.is_empty() {
        if let Some(e) = send_err {
            return Err(e);
        }
    }
    Ok(replies)
}

/// Opens the raw ICMP socket a trace listens on.
pub fn open_icmp() -> io::Result<Socket> {
    let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    sys::icmp_filter(s.as_raw_fd(), &[ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH])?;
    sys::enable_rx_timestamps(s.as_raw_fd())?;
    s.set_read_timeout(Some(Duration::from_millis(50)))?;
    Ok(s)
}

/// Per-session trace thread: traces at start, every `interval_s`, and when the
/// STAMP TTLs change (at most once per `min_gap_s`).
#[allow(clippy::too_many_arguments)]
pub fn trace_loop(
    sock: &Socket,
    cfg: &TraceConfig,
    meta: &SessionMeta,
    flow: Flow,
    hint: &TtlHint,
    out: &std::sync::mpsc::Sender<crate::output::Item>,
    stop: &AtomicBool,
) {
    let icmp = match open_icmp() {
        Ok(s) => s,
        Err(e) => {
            log::warn!(
                "stamp {}: path tracing disabled: cannot open a raw ICMP socket ({e}); it needs CAP_NET_RAW",
                meta.session
            );
            return;
        }
    };
    let initial_ttl = sys::ip_ttl(sock.as_raw_fd()).unwrap_or(64);
    let interval = Duration::from_secs(cfg.interval_s);
    let min_gap = Duration::from_secs(cfg.min_gap_s);
    let round_timeout = Duration::from_millis(cfg.round_timeout_ms);
    let mut memory = PathMemory::default();
    let mut err_log = Throttle::new(Duration::from_secs(300));
    // Give the session a few replies first, so the forward length is known.
    let mut next_due = Instant::now() + Duration::from_secs(cfg.start_delay_s);
    let mut trigger = "start";
    let mut last_run: Option<Instant> = None;
    let mut traced_hint = None;

    while !stop.load(Ordering::Relaxed) {
        if !sleep_until(Instant::now() + POLL_INTERVAL, stop) {
            return;
        }
        let h = hint.get();
        let now = Instant::now();
        let ttl_moved = traced_hint.is_some() && h.is_some() && h != traced_hint;
        if ttl_moved && last_run.is_none_or(|t| now.duration_since(t) >= min_gap) {
            trigger = "ttl_change";
        } else if now < next_due {
            continue;
        }

        let (ttl_fwd, ttl_back) = h.map_or((None, None), |(f, b)| (Some(f), Some(b)));
        let length = ttl_fwd.and_then(|t| hop_count(initial_ttl, t));
        let max_ttl = match length {
            Some(n) => n.min(cfg.max_ttl),
            None => cfg.max_ttl,
        };
        let ts_ms = clock::now_ns().div_euclid(1_000_000);
        let started = Instant::now();
        let replies = if max_ttl == 0 {
            Ok(Vec::new())
        } else {
            run_trace(sock.as_raw_fd(), &icmp, flow, max_ttl, cfg.rounds, round_timeout)
        };
        last_run = Some(Instant::now());
        next_due = Instant::now() + interval;
        traced_hint = h;
        let replies = match replies {
            Ok(r) => r,
            Err(e) => {
                if let Some(n) = err_log.ready() {
                    log::warn!("stamp {}: trace failed: {e} ({n} similar suppressed)", meta.session);
                }
                trigger = "schedule";
                continue;
            }
        };
        let hops = hops(&replies, max_ttl, cfg.rounds, length.is_some());
        let change = memory.observe(&hops, length);
        let complete = length.is_some_and(|n| hops.len() == usize::from(n.min(cfg.max_ttl)))
            && hops.iter().all(|h| !h.addrs.is_empty());
        let result = RouteResult {
            v: crate::record::RECORD_VERSION,
            probe_id: meta.probe_id.clone(),
            site: meta.site.clone(),
            session: meta.session.clone(),
            kind: "route",
            app_class: meta.app_class.clone(),
            dscp: meta.dscp,
            src: meta.src.clone(),
            dst: meta.dst.clone(),
            ts_ms,
            duration_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
            trigger,
            ttl_fwd,
            ttl_back,
            hop_count_fwd: length,
            multipath: hops.iter().any(|h| h.addrs.len() > 1),
            signature: signature(&hops),
            complete,
            changed: change.is_some(),
            change_ttl: change.as_ref().and_then(|c| c.ttl),
            change_reason: change.as_ref().map(|c| c.reason),
            prev_signature: change.map(|c| c.prev_signature),
            hops,
        };
        if result.changed {
            log::info!(
                "stamp {}: path changed ({}{}): {} -> {}",
                meta.session,
                result.change_reason.unwrap_or("?"),
                result.change_ttl.map(|t| format!(" at TTL {t}")).unwrap_or_default(),
                result.prev_signature.as_deref().unwrap_or("?"),
                result.signature
            );
        }
        trigger = "schedule";
        if out.send(crate::output::Item::Route(result)).is_err() {
            return;
        }
    }
}

/// Starts the trace thread for a session, sharing its socket (same 5-tuple).
pub fn spawn(
    sock: Socket,
    cfg: TraceConfig,
    meta: SessionMeta,
    flow: Flow,
    hint: Arc<TtlHint>,
    out: std::sync::mpsc::Sender<crate::output::Item>,
    stop: Arc<AtomicBool>,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("stamp-trace-{}", meta.session))
        .spawn(move || trace_loop(&sock, &cfg, &meta, flow, &hint, &out, &stop))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(from: &str, ttl: u8, round: u8, tag: u16, full: bool) -> Vec<u8> {
        // Outer IPv4 (20) + ICMP header (8) + quoted IPv4 (20) + UDP (8) [+ payload].
        let pl = payload(ttl, round, tag);
        let mut p = vec![0_u8; 20 + 8 + 20 + 8];
        p[0] = 0x45;
        p[9] = 1;
        let f: Ipv4Addr = from.parse().unwrap();
        p[12..16].copy_from_slice(&f.octets());
        p[20] = ICMP_TIME_EXCEEDED;
        let q = 28;
        p[q] = 0x45;
        p[q + 1] = 46 << 2;
        p[q + 9] = 17;
        p[q + 12..q + 16].copy_from_slice(&[10, 90, 1, 2]);
        p[q + 16..q + 20].copy_from_slice(&[10, 90, 9, 2]);
        let u = q + 20;
        p[u..u + 2].copy_from_slice(&40001_u16.to_be_bytes());
        p[u + 2..u + 4].copy_from_slice(&862_u16.to_be_bytes());
        p[u + 4..u + 6].copy_from_slice(&((8 + pl.len()) as u16).to_be_bytes());
        if full {
            p.extend_from_slice(&pl);
        }
        p
    }

    fn flow() -> Flow {
        Flow { local: "10.90.1.2:40001".parse().unwrap(), dst: "10.90.9.2:862".parse().unwrap(), tag: 0xBEEF }
    }

    #[test]
    fn payload_is_shorter_than_stamp_and_encodes_the_ttl() {
        for ttl in 1..=MAX_TTL {
            let p = payload(ttl, 0, 1);
            assert!(p.len() < crate::stamp::BASE_LEN, "a reflector must discard trace packets");
            assert_eq!(ttl_from_udp_len((8 + p.len()) as u16), Some(ttl));
        }
        assert_eq!(ttl_from_udp_len(16), None);
        assert_eq!(ttl_from_udp_len(8 + 44), None, "a STAMP packet is not a trace packet");
    }

    #[test]
    fn replies_match_with_8_octet_quotes_and_with_full_quotes() {
        let f = flow();
        for full in [false, true] {
            let q = parse_icmp_error(&quote("10.90.2.2", 2, 1, 0xBEEF, full)).unwrap();
            assert_eq!(q.from, "10.90.2.2".parse::<Ipv4Addr>().unwrap());
            assert_eq!(q.q_tos >> 2, 46);
            assert_eq!(f.matches(&q, 1), Some(2));
        }
        // A full quote from another session (other tag) or round is not ours.
        let q = parse_icmp_error(&quote("10.90.2.2", 2, 1, 0x1234, true)).unwrap();
        assert_eq!(f.matches(&q, 1), None);
        let q = parse_icmp_error(&quote("10.90.2.2", 2, 0, 0xBEEF, true)).unwrap();
        assert_eq!(f.matches(&q, 1), None);
        // Another flow (source port) is not ours either.
        let other = Flow { local: "10.90.1.2:40002".parse().unwrap(), ..f };
        let q = parse_icmp_error(&quote("10.90.2.2", 2, 1, 0xBEEF, false)).unwrap();
        assert_eq!(other.matches(&q, 1), None);
    }

    #[test]
    fn non_udp_and_truncated_packets_are_ignored() {
        let mut p = quote("10.90.2.2", 2, 0, 1, false);
        assert!(parse_icmp_error(&p[..40]).is_none());
        p[28 + 9] = 6; // quoted TCP
        assert!(parse_icmp_error(&p).is_none());
    }

    fn r(ttl: u8, from: &str, rtt_us: i64) -> HopReply {
        HopReply { ttl, from: from.parse().unwrap(), rtt_ns: rtt_us * 1000, unreachable: None }
    }

    #[test]
    fn hops_aggregate_and_trim() {
        let replies = [r(1, "10.0.0.1", 300), r(1, "10.0.0.1", 200), r(3, "10.0.2.1", 900), r(3, "10.0.2.9", 800)];
        let h = hops(&replies, 5, 3, false);
        assert_eq!(h.len(), 3, "trailing silent hops trimmed when the length is unknown");
        assert_eq!(h[0].addrs, ["10.0.0.1"]);
        assert_eq!((h[0].rtt_us, h[0].replies, h[0].sent), (Some(200), 2, 3));
        assert!(h[1].addrs.is_empty());
        assert_eq!(h[2].addrs, ["10.0.2.1", "10.0.2.9"]);
        assert_eq!(signature(&h), "10.0.0.1>*>10.0.2.1|10.0.2.9");
        assert_eq!(hops(&replies, 5, 3, true).len(), 5, "kept when the length is known");
        let mut unreachable = replies.to_vec();
        unreachable.push(HopReply { unreachable: Some(1), ..r(2, "10.0.1.1", 500) });
        let h = hops(&unreachable, 5, 3, true);
        assert_eq!((h.len(), h[1].unreachable), (2, Some(1)), "the path ends at an unreachable");
    }

    fn path(addrs: &[&str]) -> Vec<Hop> {
        addrs
            .iter()
            .enumerate()
            .map(|(i, a)| Hop {
                ttl: i as u8 + 1,
                addrs: if a.is_empty() { vec![] } else { a.split('|').map(str::to_string).collect() },
                rtt_us: None,
                sent: 3,
                replies: 1,
                unreachable: None,
            })
            .collect()
    }

    #[test]
    fn a_new_router_at_a_ttl_is_a_change() {
        let mut m = PathMemory::default();
        assert_eq!(m.observe(&path(&["10.0.0.1", "10.0.1.1", "10.0.9.1"]), Some(3)), None);
        assert_eq!(m.observe(&path(&["10.0.0.1", "10.0.1.1", "10.0.9.1"]), Some(3)), None);
        let c = m.observe(&path(&["10.0.0.1", "10.0.2.1", "10.0.9.1"]), Some(3)).unwrap();
        assert_eq!((c.ttl, c.reason), (Some(2), "hop"));
        assert_eq!(c.prev_signature, "10.0.0.1>10.0.1.1>10.0.9.1");
        // And back again is a change too: memory restarted at the new path.
        assert_eq!(m.observe(&path(&["10.0.0.1", "10.0.1.1", "10.0.9.1"]), Some(3)).unwrap().ttl, Some(2));
    }

    #[test]
    fn silence_and_load_balancing_are_not_changes() {
        let mut m = PathMemory::default();
        m.observe(&path(&["10.0.0.1", "10.0.1.1", "10.0.9.1"]), Some(3));
        assert_eq!(m.observe(&path(&["10.0.0.1", "", "10.0.9.1"]), Some(3)), None, "rate-limited hop");
        assert_eq!(m.observe(&path(&["10.0.0.1", "10.0.1.1|10.0.1.2", "10.0.9.1"]), Some(3)), None);
        // The per-packet balanced sibling alone is still the same path.
        assert_eq!(m.observe(&path(&["10.0.0.1", "10.0.1.2", "10.0.9.1"]), Some(3)), None);
    }

    #[test]
    fn a_different_length_is_a_change_even_if_routers_stay_silent() {
        let mut m = PathMemory::default();
        m.observe(&path(&["10.0.0.1", "", "10.0.9.1"]), Some(3));
        let c = m.observe(&path(&["10.0.0.1", "", "", "10.0.9.1"]), Some(4)).unwrap();
        assert_eq!((c.ttl, c.reason), (None, "length"));
    }

    #[test]
    fn ttl_hint_publishes_only_stable_values() {
        let hint = TtlHint::default();
        let mut d = TtlDebounce::new(3);
        assert_eq!(hint.get(), None);
        d.observe(61, 62, &hint);
        d.observe(61, 62, &hint);
        assert_eq!(hint.get(), None);
        d.observe(61, 62, &hint);
        assert_eq!(hint.get(), Some((61, 62)));
        d.observe(60, 62, &hint);
        d.observe(61, 62, &hint);
        assert_eq!(hint.get(), Some((61, 62)), "one odd reply does not move it");
        assert_eq!(hop_count(64, 61), Some(3));
        assert_eq!(hop_count(64, 65), None);
    }
}
