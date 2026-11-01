//! Forward bottleneck capacity from packet-train dispersion (Phase 3).
//!
//! A train of `packets` back-to-back STAMP packets leaves the probe at LAN
//! speed. The narrowest link on the way spreads it out; the reflector stamps
//! each packet's arrival (T2, kernel timestamp), so the spacing at the far end
//! gives the forward bottleneck rate without any clock synchronisation (only
//! differences of the reflector's clock are used).
//!
//! * **Sustained rate** = one packet's wire size / median gap in the second half
//!   of the train. Token-bucket shapers and policers let the head of a train
//!   through at line rate until their bucket is empty; the tail is spaced at the
//!   configured rate. Whole-train dispersion (`adr`) would overestimate.
//! * **Burst allowance**: when the head is spaced clearly tighter than the tail,
//!   the octets that got through ahead of the sustained rate are reported.
//! * **Return direction**: the reflector sends each reply as its packet
//!   arrives, so the return train starts out spaced like the forward one. If it
//!   arrives spread wider (T4 vs T3), the return bottleneck is narrower and its
//!   rate is measured; otherwise only a lower bound is known.
//! * Rates are IP-layer (STAMP size + 28 octets of IP/UDP header per packet).
//!   A shaper that counts Ethernet framing reads ~1% higher for 1200-octet packets.
//! * Trains with reordering, more than half lost, no measurable spread, or a
//!   sender too slow to make a burst (send time > half the arrival spread) are
//!   discarded; the result is the median over the remaining trains.
//!
//! Through EdgeConnect this is the capacity of the overlay as the appliance
//! shapes it for this DSCP, not the underlay link rate. Packet order correction
//! can re-space packets; check `spread` (min/max over trains) before trusting it.

use crate::clock;
use crate::config::{parse_v4_endpoint, CapacityConfig};
use crate::ntp;
use crate::output::Item;
use crate::record::SessionMeta;
use crate::stamp::{ReflectorPacket, SenderPacket};
use crate::sys;
use crate::{sleep_until, Throttle};
use serde::Serialize;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// IPv4 (20) + UDP (8) header octets added to each STAMP packet on the wire.
pub const IP_UDP_OVERHEAD: u32 = 28;
/// A gap tighter than this fraction of the tail's median is "faster than sustained".
const BURST_GAP_FRACTION: f64 = 0.7;
/// Leading fast gaps needed to call it a burst (fewer is noise).
const MIN_BURST_GAPS: usize = 3;
/// The return train counts as re-spaced when it arrives this much wider than sent.
const RESPACED_RATIO: f64 = 1.15;

/// One reflected packet of a train.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainObs {
    /// Position in the train (0-based).
    pub idx: u32,
    /// Reflector receive time.
    pub t2_ns: i64,
    /// Reflector transmit time.
    pub t3_ns: i64,
    /// Probe receive time.
    pub t4_ns: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TrainEstimate {
    pub sent: u32,
    pub received: u32,
    /// Why the train was discarded, if it was.
    pub invalid: Option<&'static str>,
    pub fwd_bps: Option<f64>,
    pub fwd_adr_bps: Option<f64>,
    pub burst_bytes: Option<u64>,
    pub back_bps: Option<f64>,
    pub back_lower_bound: bool,
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let m = v.len() / 2;
    Some(if v.len() % 2 == 1 { v[m] } else { (v[m - 1] + v[m]) / 2.0 })
}

fn gaps(ts: &[i64]) -> Vec<f64> {
    ts.windows(2).map(|w| (w[1] - w[0]) as f64).collect()
}

/// Sustained rate from the tail's median gap, and the burst the head carried.
///
/// A burst is a leading run of at least [`MIN_BURST_GAPS`] gaps clearly tighter
/// than the tail (a token bucket draining at line rate). Its size is what got
/// through ahead of the sustained rate.
fn sustained(ts: &[i64], wire_bits: f64) -> Option<(f64, Option<u64>)> {
    let g = gaps(ts);
    if g.len() < 4 {
        return None;
    }
    let tail0 = median(&mut g[g.len() / 2..].to_vec())?;
    if tail0 <= 0.0 {
        return None;
    }
    let k = g.iter().position(|x| *x >= BURST_GAP_FRACTION * tail0).unwrap_or(g.len());
    if k < MIN_BURST_GAPS || g.len() - k < 4 {
        return Some((wire_bits / tail0 * 1e9, None));
    }
    // Sustained rate from the gaps after the burst only.
    let tail = median(&mut g[k..].to_vec()).filter(|t| *t > 0.0).unwrap_or(tail0);
    let rate = wire_bits / tail * 1e9;
    let head_bits = (k + 1) as f64 * wire_bits;
    let head_time_s = (ts[k] - ts[0]) as f64 / 1e9;
    let burst = ((head_bits - head_time_s * rate) / 8.0).max(0.0).round() as u64;
    Some((rate, Some(burst)))
}

/// Estimates one train. `wire_bytes` is the IP-layer size of one packet;
/// `send_spread_ns` how long the probe took to hand the whole train to the kernel.
pub fn estimate_train(obs: &[TrainObs], sent: u32, wire_bytes: u32, send_spread_ns: i64) -> TrainEstimate {
    let mut by_idx: BTreeMap<u32, TrainObs> = BTreeMap::new();
    for o in obs.iter().filter(|o| o.idx < sent) {
        by_idx.entry(o.idx).or_insert(*o);
    }
    let v: Vec<TrainObs> = by_idx.into_values().collect();
    let received = v.len() as u32;
    let mut e = TrainEstimate {
        sent,
        received,
        invalid: None,
        fwd_bps: None,
        fwd_adr_bps: None,
        burst_bytes: None,
        back_bps: None,
        back_lower_bound: true,
    };
    let invalid = |mut e: TrainEstimate, why| {
        e.invalid = Some(why);
        e
    };
    if received < 5 || received * 2 < sent {
        return invalid(e, "too_few");
    }
    let t2: Vec<i64> = v.iter().map(|o| o.t2_ns).collect();
    if t2.windows(2).any(|w| w[1] < w[0]) {
        return invalid(e, "reordered");
    }
    let spread2 = t2[t2.len() - 1] - t2[0];
    if spread2 <= 0 {
        return invalid(e, "no_spread");
    }
    if send_spread_ns * 2 > spread2 {
        return invalid(e, "sender_limited");
    }
    let wire_bits = f64::from(wire_bytes) * 8.0;
    let n = f64::from(received - 1);
    e.fwd_adr_bps = Some(n * wire_bits / spread2 as f64 * 1e9);
    let (fwd, burst) = sustained(&t2, wire_bits).unwrap_or((n * wire_bits / spread2 as f64 * 1e9, None));
    e.fwd_bps = Some(fwd);
    e.burst_bytes = burst;

    let t3: Vec<i64> = v.iter().map(|o| o.t3_ns).collect();
    let t4: Vec<i64> = v.iter().map(|o| o.t4_ns).collect();
    let (spread3, spread4) = (t3[t3.len() - 1] - t3[0], t4[t4.len() - 1] - t4[0]);
    if spread4 > 0 && t4.windows(2).all(|w| w[1] >= w[0]) {
        if spread4 as f64 > spread3.max(0) as f64 * RESPACED_RATIO {
            e.back_bps = sustained(&t4, wire_bits).map(|(r, _)| r).or(Some(n * wire_bits / spread4 as f64 * 1e9));
            e.back_lower_bound = false;
        } else {
            e.back_bps = Some(n * wire_bits / spread4 as f64 * 1e9);
        }
    }
    e
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CapacityResult {
    pub v: u32,
    pub probe_id: String,
    pub site: String,
    pub session: String,
    pub kind: &'static str,
    pub app_class: String,
    pub dscp: u8,
    pub src: String,
    pub dst: String,
    /// Measurement start, Unix ms.
    pub ts_ms: i64,
    pub packets: u32,
    pub size: u32,
    pub trains: u32,
    pub valid_trains: u32,
    /// Median sustained forward rate over valid trains, bit/s (IP layer).
    pub fwd_bps: Option<u64>,
    pub fwd_bps_min: Option<u64>,
    pub fwd_bps_max: Option<u64>,
    /// Median whole-train dispersion rate (includes any burst allowance).
    pub fwd_adr_bps: Option<u64>,
    /// Trains whose head passed faster than their tail, and the median burst.
    pub burst_trains: u32,
    pub burst_bytes: Option<u64>,
    pub back_bps: Option<u64>,
    /// True when the return path did not re-space the train: back_bps is a floor.
    pub back_is_lower_bound: bool,
    pub lost: u32,
    /// Discarded trains by reason.
    pub invalid: BTreeMap<String, u32>,
}

/// Combines per-train estimates into one result (fields other than the
/// measurement figures are filled by the caller).
pub fn aggregate(trains: &[TrainEstimate]) -> Aggregate {
    let valid: Vec<&TrainEstimate> = trains.iter().filter(|t| t.invalid.is_none()).collect();
    let mut fwd: Vec<f64> = valid.iter().filter_map(|t| t.fwd_bps).collect();
    let mut adr: Vec<f64> = valid.iter().filter_map(|t| t.fwd_adr_bps).collect();
    let mut bursts: Vec<f64> = valid.iter().filter_map(|t| t.burst_bytes.map(|b| b as f64)).collect();
    // A measured return rate beats a floor; use floors only if nothing better.
    let measured: Vec<f64> = valid.iter().filter(|t| !t.back_lower_bound).filter_map(|t| t.back_bps).collect();
    let floors: Vec<f64> = valid.iter().filter(|t| t.back_lower_bound).filter_map(|t| t.back_bps).collect();
    let (mut back, back_floor) = if measured.is_empty() { (floors, true) } else { (measured, false) };
    let mut invalid = BTreeMap::new();
    for t in trains {
        if let Some(why) = t.invalid {
            *invalid.entry(why.to_string()).or_insert(0) += 1;
        }
    }
    let round = |x: f64| x.round() as u64;
    Aggregate {
        valid_trains: valid.len() as u32,
        fwd_bps_min: fwd.iter().copied().reduce(f64::min).map(round),
        fwd_bps_max: fwd.iter().copied().reduce(f64::max).map(round),
        fwd_bps: median(&mut fwd).map(round),
        fwd_adr_bps: median(&mut adr).map(round),
        burst_trains: bursts.len() as u32,
        burst_bytes: median(&mut bursts).map(round),
        back_bps: median(&mut back).map(round),
        back_is_lower_bound: back_floor,
        lost: trains.iter().map(|t| t.sent - t.received).sum(),
        invalid,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Aggregate {
    pub valid_trains: u32,
    pub fwd_bps: Option<u64>,
    pub fwd_bps_min: Option<u64>,
    pub fwd_bps_max: Option<u64>,
    pub fwd_adr_bps: Option<u64>,
    pub burst_trains: u32,
    pub burst_bytes: Option<u64>,
    pub back_bps: Option<u64>,
    pub back_is_lower_bound: bool,
    pub lost: u32,
    pub invalid: BTreeMap<String, u32>,
}

/// Sends one train and collects its replies.
fn run_train(sock: &Socket, cfg: &CapacityConfig, seq0: u32, timeout: Duration) -> io::Result<(Vec<TrainObs>, i64)> {
    let status = clock::status();
    let t1 = clock::now_ns();
    let bufs: Vec<Vec<u8>> = (0..cfg.packets)
        .map(|i| {
            let mut b = vec![0_u8; cfg.size];
            SenderPacket {
                seq: seq0.wrapping_add(i),
                timestamp: ntp::from_unix_ns(t1),
                error_estimate: clock::encode_error_estimate(status),
            }
            .encode(&mut b);
            b
        })
        .collect();
    let started = Instant::now();
    let n = sys::send_many(sock.as_raw_fd(), &bufs)?;
    let send_spread_ns = i64::try_from(started.elapsed().as_nanos()).unwrap_or(i64::MAX);
    let mut obs = Vec::with_capacity(n);
    let mut buf = [0_u8; 2048];
    let deadline = Instant::now() + timeout;
    while obs.len() < n && Instant::now() < deadline {
        let m = match sys::recv_meta(sock.as_raw_fd(), &mut buf) {
            Ok(m) => m,
            Err(e) if sys::is_timeout(&e) => continue,
            Err(e) => return Err(e),
        };
        let Some(p) = ReflectorPacket::decode(&buf[..m.len]) else { continue };
        let idx = p.sender_seq.wrapping_sub(seq0);
        if idx >= cfg.packets {
            continue; // late reply from an earlier train
        }
        let t4 = m.kernel_ts_ns.unwrap_or_else(clock::now_ns);
        obs.push(TrainObs {
            idx,
            t2_ns: ntp::to_unix_ns_near(p.receive_timestamp, t4),
            t3_ns: ntp::to_unix_ns_near(p.timestamp, t4),
            t4_ns: t4,
        });
    }
    Ok((obs, send_spread_ns))
}

#[allow(clippy::too_many_arguments)]
fn capacity_loop(
    sock: &Socket,
    cfg: &CapacityConfig,
    meta: &SessionMeta,
    dscp: u8,
    timeout: Duration,
    out: &Sender<Item>,
    stop: &AtomicBool,
) {
    let wire = cfg.size as u32 + IP_UDP_OVERHEAD;
    let mut seq: u32 = 0;
    let mut err_log = Throttle::new(Duration::from_secs(300));
    let mut next = Instant::now() + Duration::from_secs(cfg.start_delay_s);
    let src = sock.local_addr().ok().and_then(|a| a.as_socket()).map(|a| a.to_string()).unwrap_or_default();
    loop {
        if !sleep_until(next, stop) {
            return;
        }
        next += Duration::from_secs(cfg.interval_s);
        let ts_ms = clock::now_ns().div_euclid(1_000_000);
        let mut trains = Vec::with_capacity(cfg.trains as usize);
        for i in 0..cfg.trains {
            if i > 0 && !sleep_until(Instant::now() + Duration::from_millis(cfg.train_gap_ms), stop) {
                return;
            }
            match run_train(sock, cfg, seq, timeout) {
                Ok((obs, spread)) => trains.push(estimate_train(&obs, cfg.packets, wire, spread)),
                Err(e) => {
                    if let Some(n) = err_log.ready() {
                        log::warn!("stamp {}: capacity train failed: {e} ({n} similar suppressed)", meta.session);
                    }
                }
            }
            seq = seq.wrapping_add(cfg.packets);
        }
        if trains.is_empty() {
            continue;
        }
        let a = aggregate(&trains);
        log::info!(
            "stamp {}: capacity fwd {} (min {}, max {}, {} of {} trains){}",
            meta.session,
            fmt_bps(a.fwd_bps),
            fmt_bps(a.fwd_bps_min),
            fmt_bps(a.fwd_bps_max),
            a.valid_trains,
            trains.len(),
            a.burst_bytes.map(|b| format!(", burst ~{b} B")).unwrap_or_default()
        );
        let result = CapacityResult {
            v: crate::record::RECORD_VERSION,
            probe_id: meta.probe_id.clone(),
            site: meta.site.clone(),
            session: meta.session.clone(),
            kind: "capacity",
            app_class: meta.app_class.clone(),
            dscp,
            src: src.clone(),
            dst: meta.dst.clone(),
            ts_ms,
            packets: cfg.packets,
            size: cfg.size as u32,
            trains: trains.len() as u32,
            valid_trains: a.valid_trains,
            fwd_bps: a.fwd_bps,
            fwd_bps_min: a.fwd_bps_min,
            fwd_bps_max: a.fwd_bps_max,
            fwd_adr_bps: a.fwd_adr_bps,
            burst_trains: a.burst_trains,
            burst_bytes: a.burst_bytes,
            back_bps: a.back_bps,
            back_is_lower_bound: a.back_is_lower_bound,
            lost: a.lost,
            invalid: a.invalid,
        };
        if out.send(Item::Capacity(result)).is_err() {
            return;
        }
    }
}

fn fmt_bps(v: Option<u64>) -> String {
    v.map_or_else(|| "-".to_string(), |b| format!("{:.1} Mbit/s", b as f64 / 1e6))
}

/// Opens the train socket (its own STAMP session on the reflector) and starts
/// the measurement thread.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    cfg: CapacityConfig,
    session_src: SocketAddrV4,
    dst: SocketAddrV4,
    session_dscp: u8,
    timeout: Duration,
    meta: SessionMeta,
    out: Sender<Item>,
    stop: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    let invalid = |e: String| io::Error::new(io::ErrorKind::InvalidInput, e);
    let src = match &cfg.source {
        Some(s) => parse_v4_endpoint(s, 0).map_err(invalid)?,
        None => SocketAddrV4::new(*session_src.ip(), 0),
    };
    let dscp = cfg.dscp.unwrap_or(session_dscp);
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.bind(&SockAddr::from(src))?;
    sock.set_tos(u32::from(dscp) << 2)?;
    sock.connect(&SockAddr::from(dst))?;
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    // Room for a whole train of replies while the sender is still busy.
    let _ = sock.set_recv_buffer_size((cfg.packets as usize * (cfg.size + 256)).max(256 * 1024));
    sys::enable_rx_timestamps(sock.as_raw_fd())?;
    log::warn!(
        "stamp {}: capacity trains ENABLED: {} x {} B every {} s ({} trains) to {dst}, dscp {dscp}",
        meta.session,
        cfg.packets,
        cfg.size,
        cfg.interval_s,
        cfg.trains
    );
    std::thread::Builder::new()
        .name(format!("stamp-capacity-{}", meta.session))
        .spawn(move || capacity_loop(&sock, &cfg, &meta, dscp, timeout, &out, &stop))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIRE: u32 = 1228;

    /// A train through a token bucket: `burst` octets pass at `line_bps`, the
    /// rest at `rate_bps`. Return path re-spaces to `back_bps` if lower.
    fn train(n: u32, line_bps: f64, rate_bps: f64, burst: f64, back_bps: Option<f64>) -> Vec<TrainObs> {
        let bits = f64::from(WIRE) * 8.0;
        let mut t2 = 0.0_f64;
        let mut tokens = burst * 8.0;
        let mut t4_prev: f64 = f64::MIN;
        (0..n)
            .map(|i| {
                if i > 0 {
                    let line_gap = bits / line_bps;
                    let gap = if tokens >= bits { line_gap } else { (bits - tokens) / rate_bps };
                    tokens = (tokens - bits + gap * rate_bps).max(0.0).min(burst * 8.0);
                    t2 += gap * 1e9;
                }
                let t3 = t2 + 20_000.0;
                let mut t4 = t3 + 5_000_000.0;
                if let Some(b) = back_bps {
                    t4 = t4.max(t4_prev + bits / b * 1e9);
                }
                t4_prev = t4;
                TrainObs { idx: i, t2_ns: t2 as i64, t3_ns: t3 as i64, t4_ns: t4 as i64 }
            })
            .collect()
    }

    fn close(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= b * tol
    }

    #[test]
    fn plain_bottleneck_is_measured() {
        let e = estimate_train(&train(48, 1e9, 20e6, 0.0, None), 48, WIRE, 50_000);
        assert_eq!(e.invalid, None);
        assert!(close(e.fwd_bps.unwrap(), 20e6, 0.01), "{e:?}");
        assert!(close(e.fwd_adr_bps.unwrap(), 20e6, 0.01));
        assert_eq!(e.burst_bytes, None);
        assert!(e.back_lower_bound, "return did not re-space the train");
    }

    #[test]
    fn a_shaper_burst_is_separated_from_the_sustained_rate() {
        let e = estimate_train(&train(64, 1e9, 10e6, 20_000.0, None), 64, WIRE, 50_000);
        let fwd = e.fwd_bps.unwrap();
        assert!(close(fwd, 10e6, 0.02), "sustained {fwd}");
        assert!(e.fwd_adr_bps.unwrap() > fwd * 1.3, "whole-train rate is inflated by the burst");
        let b = e.burst_bytes.unwrap() as f64;
        assert!(close(b, 20_000.0, 0.25), "burst {b}");
    }

    #[test]
    fn a_burst_longer_than_half_the_train_is_still_separated() {
        // 48 KB bucket, 64 x 1228 B train: ~40 packets ride the burst.
        let e = estimate_train(&train(64, 1e9, 10e6, 48_000.0, None), 64, WIRE, 50_000);
        assert!(close(e.fwd_bps.unwrap(), 10e6, 0.02), "{e:?}");
        assert!(close(e.burst_bytes.unwrap() as f64, 48_000.0, 0.1), "{e:?}");
    }

    #[test]
    fn a_small_burst_is_reported_and_a_plain_queue_has_none() {
        let e = estimate_train(&train(48, 1e9, 20e6, 8192.0, None), 48, WIRE, 50_000);
        assert!(close(e.fwd_bps.unwrap(), 20e6, 0.02));
        let b = e.burst_bytes.expect("8 KB burst") as f64;
        assert!(close(b, 8192.0, 0.25), "burst {b}");
        assert_eq!(estimate_train(&train(48, 1e9, 20e6, 0.0, None), 48, WIRE, 50_000).burst_bytes, None);
        // Line rate end to end (no shaper): no burst either, the tail is the line.
        assert_eq!(estimate_train(&train(48, 1e9, 1e9, 0.0, None), 48, WIRE, 0).burst_bytes, None);
    }

    #[test]
    fn a_narrower_return_path_is_measured_not_bounded() {
        let e = estimate_train(&train(48, 1e9, 50e6, 0.0, Some(10e6)), 48, WIRE, 50_000);
        assert!(!e.back_lower_bound);
        assert!(close(e.back_bps.unwrap(), 10e6, 0.02), "{e:?}");
        assert!(close(e.fwd_bps.unwrap(), 50e6, 0.02));
    }

    #[test]
    fn unusable_trains_are_discarded_with_a_reason() {
        let t = train(48, 1e9, 20e6, 0.0, None);
        assert_eq!(estimate_train(&t[..20], 48, WIRE, 0).invalid, Some("too_few"));
        let mut r = t.clone();
        r.swap(10, 11);
        r[10].idx = 10;
        r[11].idx = 11;
        assert_eq!(estimate_train(&r, 48, WIRE, 0).invalid, Some("reordered"));
        let spread = t[47].t2_ns - t[0].t2_ns;
        assert_eq!(estimate_train(&t, 48, WIRE, spread).invalid, Some("sender_limited"));
        let flat: Vec<TrainObs> = t.iter().map(|o| TrainObs { t2_ns: 0, ..*o }).collect();
        assert_eq!(estimate_train(&flat, 48, WIRE, 0).invalid, Some("no_spread"));
    }

    #[test]
    fn loss_inside_the_train_still_gives_the_rate() {
        // Tail drop at the bottleneck: the survivors are back to back there.
        let t: Vec<TrainObs> = train(40, 1e9, 20e6, 0.0, None)
            .into_iter()
            .enumerate()
            .map(|(i, o)| TrainObs { idx: o.idx + (i as u32 / 5), ..o })
            .collect();
        let e = estimate_train(&t, 48, WIRE, 0);
        assert!(close(e.fwd_bps.unwrap(), 20e6, 0.01), "{e:?}");
        assert_eq!(e.sent - e.received, 8);
    }

    #[test]
    fn aggregate_takes_the_median_and_counts_discards() {
        let mk = |bps: f64| TrainEstimate {
            sent: 48,
            received: 48,
            invalid: None,
            fwd_bps: Some(bps),
            fwd_adr_bps: Some(bps),
            burst_bytes: None,
            back_bps: Some(bps),
            back_lower_bound: true,
        };
        let bad = TrainEstimate { invalid: Some("reordered"), received: 40, ..mk(1.0) };
        let a = aggregate(&[mk(9e6), mk(10e6), mk(30e6), bad]);
        assert_eq!(
            (a.valid_trains, a.fwd_bps, a.fwd_bps_min, a.fwd_bps_max),
            (3, Some(10_000_000), Some(9_000_000), Some(30_000_000))
        );
        assert_eq!(a.invalid.get("reordered"), Some(&1));
        assert_eq!(a.lost, 8);
        assert!(a.back_is_lower_bound);
    }
}
