//! Per-session accounting: turns "sent" and "reply" events into 1-second
//! buckets, following the rules in `docs/PROBE-RECORD.md`.
//!
//! Pure logic with no I/O, so every rule is unit-tested below.
//!
//! * A packet belongs to the bucket of its **send** time.
//! * No reply within `timeout` → lost. A reply after that → `late`, never `received`.
//! * A reply for an already-received packet → `dup`.
//! * A reply whose sequence is below the highest already received → `reordered`.
//! * Jitter/IPDV pairs are consecutive received packets in sequence order and
//!   are counted in the later packet's bucket.
//! * Forward/return loss split (stateful STAMP reflector): between replies
//!   (s, r) and (s′, r′), forward losses = (s′ − s) − (r′ − r).
//! * A bucket is emitted once its second has ended and all its packets are
//!   resolved and, when it has losses, once a later reply has settled the split
//!   (or `split_wait` passed; the split is then unknown).

use std::collections::BTreeMap;

pub const NS_PER_MS: i64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct TrackerConfig {
    pub interval_ms: i64,
    pub timeout_ns: i64,
    /// Extra time a bucket with losses may wait for the reply that settles the
    /// forward/return split.
    pub split_wait_ns: i64,
    /// The peer is a stateful STAMP reflector (its sequence numbers count the
    /// packets it received). Disable for stateless/third-party reflectors.
    pub stateful_reflector: bool,
}

impl TrackerConfig {
    pub fn new(timeout_ms: u64, stateful_reflector: bool) -> Self {
        Self {
            interval_ms: 1000,
            timeout_ns: timeout_ms as i64 * NS_PER_MS,
            split_wait_ns: 3_000 * NS_PER_MS,
            stateful_reflector,
        }
    }
}

/// What the STAMP reflector reported for one packet.
#[derive(Debug, Clone, Copy)]
pub struct RemoteTimes {
    pub t2_ns: i64,
    pub t3_ns: i64,
    pub reflector_seq: u32,
    pub synced: bool,
    pub err_us: Option<u64>,
    pub ttl_fwd: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Reply {
    pub seq: u64,
    pub t4_ns: i64,
    pub kernel_ts: bool,
    pub remote: Option<RemoteTimes>,
    pub ttl_back: Option<u8>,
    pub local_synced: bool,
    pub local_err_us: Option<u64>,
    /// Use this RTT instead of T4 − T1 (e.g. the kernel's TCP handshake RTT).
    pub rtt_ns: Option<i64>,
    /// T1 as echoed back by the peer. If present it must match the T1 we
    /// recorded for this sequence number, or the reply is not ours (a stale
    /// reply from a previous run on the same 5-tuple, or a forged one).
    pub echoed_t1_ns: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyOutcome {
    Received,
    Duplicate,
    Late,
    /// Sequence number we never sent, or one so old it was already forgotten.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    InFlight,
    Received,
    Lost,
}

#[derive(Debug, Clone, Copy)]
struct Pkt {
    state: State,
    t1_ns: i64,
    bucket_ms: i64,
}

#[derive(Debug, Clone, Copy)]
struct RxPoint {
    seq: u64,
    rtt_ns: i64,
    /// (T2 − T1, T4 − T3) when the reflector reported timestamps.
    legs: Option<(i64, i64)>,
}

/// One emitted second. Field meanings: `docs/PROBE-RECORD.md`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bucket {
    pub ts_ms: i64,
    pub interval_ms: i64,
    pub sent: u32,
    pub received: u32,
    pub lost: u32,
    pub late: u32,
    pub dup: u32,
    pub reordered: u32,
    pub fwd_lost: Option<u32>,
    pub back_lost: Option<u32>,
    pub rtt_us: Vec<u32>,
    pub rtt_jitter_sum_us: u64,
    pub rtt_jitter_n: u32,
    pub ipdv_fwd_sum_us: u64,
    pub ipdv_fwd_n: u32,
    pub ipdv_back_sum_us: u64,
    pub ipdv_back_n: u32,
    pub owd_fwd_sum_us: Option<i64>,
    pub owd_back_sum_us: Option<i64>,
    pub owd_n: u32,
    pub clock_synced: bool,
    pub clock_err_us: Option<u64>,
    pub ttl_fwd: Option<u8>,
    pub ttl_back: Option<u8>,
    pub rx_kernel: bool,
    pub errors: BTreeMap<String, u32>,
}

#[derive(Debug)]
struct Open {
    b: Bucket,
    inflight: u32,
    max_seq: u64,
    fwd_assigned: u32,
    /// The forward/return split for this bucket can no longer be computed
    /// (reflector restarted mid-gap).
    split_broken: bool,
    owd_fwd_ns: i64,
    owd_back_ns: i64,
    owd_unsynced: bool,
    all_kernel: bool,
}

impl Open {
    fn new(ts_ms: i64, interval_ms: i64) -> Self {
        Self {
            b: Bucket { ts_ms, interval_ms, ..Bucket::default() },
            inflight: 0,
            max_seq: 0,
            fwd_assigned: 0,
            split_broken: false,
            owd_fwd_ns: 0,
            owd_back_ns: 0,
            owd_unsynced: false,
            all_kernel: true,
        }
    }
}

#[derive(Debug)]
pub struct Tracker {
    cfg: TrackerConfig,
    next_seq: u64,
    pkts: BTreeMap<u64, Pkt>,
    open: BTreeMap<i64, Open>,
    highest_rx: Option<u64>,
    prev_rx: Option<RxPoint>,
    /// Last (sender seq, widened reflector seq) used for the loss split.
    prev_split: Option<(u64, u64)>,
    /// Every packet up to this sequence has been through the split accounting.
    covered_upto: Option<u64>,
    /// Replies whose bucket had already been emitted (late/dup we could not attribute).
    pub stray_replies: u64,
    /// RTT samples that came out negative (clock stepped mid-flight) and were clamped.
    pub negative_rtts: u64,
}

impl Tracker {
    pub fn new(cfg: TrackerConfig) -> Self {
        Self {
            cfg,
            next_seq: 0,
            pkts: BTreeMap::new(),
            open: BTreeMap::new(),
            highest_rx: None,
            prev_rx: None,
            prev_split: None,
            covered_upto: None,
            stray_replies: 0,
            negative_rtts: 0,
        }
    }

    pub fn config(&self) -> &TrackerConfig {
        &self.cfg
    }

    fn bucket_of(&self, t1_ns: i64) -> i64 {
        let ms = t1_ns.div_euclid(NS_PER_MS);
        ms.div_euclid(self.cfg.interval_ms) * self.cfg.interval_ms
    }

    /// Records a transmission and returns its logical (64-bit) sequence number.
    pub fn on_sent(&mut self, t1_ns: i64) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        let bucket_ms = self.bucket_of(t1_ns);
        let interval = self.cfg.interval_ms;
        let open = self.open.entry(bucket_ms).or_insert_with(|| Open::new(bucket_ms, interval));
        open.b.sent += 1;
        open.inflight += 1;
        open.max_seq = seq;
        self.pkts.insert(seq, Pkt { state: State::InFlight, t1_ns, bucket_ms });
        seq
    }

    /// Maps a 32-bit wire sequence number back to the logical sequence space,
    /// choosing the value closest below the next sequence to be sent.
    pub fn widen32(&self, wire: u32) -> u64 {
        widen(wire as u64, 32, self.next_seq.saturating_sub(1))
    }

    /// As [`Self::widen32`] for 16-bit sequence numbers (ICMP echo).
    pub fn widen16(&self, wire: u16) -> u64 {
        widen(wire as u64, 16, self.next_seq.saturating_sub(1))
    }

    /// A send that failed outright, or a probe that failed with a known reason
    /// (TCP refused, DNS failure, ...). Counted as lost, with the reason.
    pub fn on_failure(&mut self, seq: u64, reason: &str) {
        if matches!(self.pkts.get(&seq), Some(p) if p.state == State::InFlight) {
            self.mark_lost(seq, Some(reason));
        }
    }

    fn mark_lost(&mut self, seq: u64, reason: Option<&str>) {
        let Some(pkt) = self.pkts.get_mut(&seq) else { return };
        pkt.state = State::Lost;
        if let Some(o) = self.open.get_mut(&pkt.bucket_ms) {
            o.inflight = o.inflight.saturating_sub(1);
            o.b.lost += 1;
            if let Some(r) = reason {
                *o.b.errors.entry(r.to_string()).or_insert(0) += 1;
            }
        }
    }

    /// Bumps a counter in the packet's own bucket if it is still open, else in
    /// the newest open bucket, else counts it as stray.
    fn bump(&mut self, bucket_ms: i64, f: impl FnOnce(&mut Bucket)) {
        if let Some(o) = self.open.get_mut(&bucket_ms) {
            f(&mut o.b);
        } else if let Some((_, o)) = self.open.iter_mut().next_back() {
            f(&mut o.b);
        } else {
            self.stray_replies += 1;
        }
    }

    pub fn on_reply(&mut self, r: Reply) -> ReplyOutcome {
        let Some(pkt) = self.pkts.get(&r.seq).copied() else {
            self.stray_replies += 1;
            return ReplyOutcome::Unknown;
        };
        // NTP encoding loses < 1 ns; allow 10 µs before calling it someone else's.
        if r.echoed_t1_ns.is_some_and(|e| (e - pkt.t1_ns).abs() > 10_000) {
            self.stray_replies += 1;
            return ReplyOutcome::Unknown;
        }
        match pkt.state {
            State::Received => {
                self.bump(pkt.bucket_ms, |b| b.dup += 1);
                return ReplyOutcome::Duplicate;
            }
            State::Lost => {
                self.bump(pkt.bucket_ms, |b| b.late += 1);
                return ReplyOutcome::Late;
            }
            State::InFlight => {}
        }
        if r.t4_ns - pkt.t1_ns > self.cfg.timeout_ns {
            // Arrived after the timeout but before poll() expired it.
            self.mark_lost(r.seq, None);
            self.bump(pkt.bucket_ms, |b| b.late += 1);
            return ReplyOutcome::Late;
        }

        let dwell = r.remote.map_or(0, |m| m.t3_ns - m.t2_ns);
        let mut rtt_ns = r.rtt_ns.unwrap_or(r.t4_ns - pkt.t1_ns - dwell);
        if rtt_ns < 0 {
            self.negative_rtts += 1;
            rtt_ns = 0;
        }
        let legs = r.remote.map(|m| (m.t2_ns - pkt.t1_ns, r.t4_ns - m.t3_ns));

        let reordered = matches!(self.highest_rx, Some(h) if r.seq < h);
        if !reordered {
            self.highest_rx = Some(r.seq);
        }
        let pair = match self.prev_rx {
            Some(p) if r.seq > p.seq => Some(p),
            _ => None,
        };
        if self.prev_rx.is_none_or(|p| r.seq > p.seq) {
            self.prev_rx = Some(RxPoint { seq: r.seq, rtt_ns, legs });
        }

        if let Some(p) = self.pkts.get_mut(&r.seq) {
            p.state = State::Received;
        }
        let Some(o) = self.open.get_mut(&pkt.bucket_ms) else {
            // The bucket cannot have been emitted while this packet was in flight.
            self.stray_replies += 1;
            return ReplyOutcome::Received;
        };
        o.inflight = o.inflight.saturating_sub(1);
        o.b.received += 1;
        o.b.rtt_us.push(u32::try_from(rtt_ns / 1000).unwrap_or(u32::MAX));
        if reordered {
            o.b.reordered += 1;
        }
        o.all_kernel &= r.kernel_ts;

        if let Some(p) = pair {
            o.b.rtt_jitter_sum_us += ((rtt_ns - p.rtt_ns).unsigned_abs()) / 1000;
            o.b.rtt_jitter_n += 1;
            if let (Some((f1, b1)), Some((f2, b2))) = (p.legs, legs) {
                o.b.ipdv_fwd_sum_us += ((f2 - f1).unsigned_abs()) / 1000;
                o.b.ipdv_fwd_n += 1;
                o.b.ipdv_back_sum_us += ((b2 - b1).unsigned_abs()) / 1000;
                o.b.ipdv_back_n += 1;
            }
        }

        if let (Some(m), Some((fwd, back))) = (r.remote, legs) {
            if r.local_synced && m.synced {
                o.owd_fwd_ns += fwd;
                o.owd_back_ns += back;
                o.b.owd_n += 1;
                let err = match (r.local_err_us, m.err_us) {
                    (Some(a), Some(b)) => Some(a.saturating_add(b)),
                    _ => None,
                };
                o.b.clock_err_us = match (o.b.clock_err_us, err) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
            } else {
                o.owd_unsynced = true;
            }
            o.b.ttl_fwd = Some(m.ttl_fwd);
        }
        if r.ttl_back.is_some() {
            o.b.ttl_back = r.ttl_back;
        }

        if self.cfg.stateful_reflector {
            if let Some(m) = r.remote {
                self.update_split(r.seq, m.reflector_seq);
            }
        }
        ReplyOutcome::Received
    }

    fn update_split(&mut self, s: u64, r_wire: u32) {
        let r = match self.prev_split {
            Some((_, pr)) => widen(r_wire as u64, 32, pr + 1),
            None => r_wire as u64,
        };
        // Both counters start at 0, so the first reply behaves as if the
        // previous pair were (-1, -1).
        let (lo, gap_sent, gap_rcvd) = match self.prev_split {
            None if r <= s => (0, s + 1, r + 1),
            None => {
                // The reflector already counted packets for this 5-tuple (probe
                // restarted within its idle timeout). Start from here.
                self.mark_split_broken(0, s);
                self.prev_split = Some((s, r));
                self.covered_upto = Some(s);
                return;
            }
            Some((ps, _)) if s <= ps => return, // reordered reply
            Some((ps, pr)) if r <= pr => {
                // Reflector restarted (or reordered at the reflector).
                self.mark_split_broken(ps + 1, s);
                self.prev_split = Some((s, r));
                self.covered_upto = Some(s);
                return;
            }
            Some((ps, pr)) => (ps + 1, s - ps, r - pr),
        };

        let mut remaining = gap_sent.saturating_sub(gap_rcvd);
        // Attribute the forward losses to the unanswered packets in the gap,
        // earliest first. Exact in total; per second it can shift by a bucket
        // during multi-second outages.
        for (_, pkt) in self.pkts.range(lo..s) {
            if remaining == 0 {
                break;
            }
            if pkt.state != State::Received {
                if let Some(o) = self.open.get_mut(&pkt.bucket_ms) {
                    o.fwd_assigned += 1;
                }
                remaining -= 1;
            }
        }
        self.prev_split = Some((s, r));
        self.covered_upto = Some(self.covered_upto.map_or(s, |c| c.max(s)));
    }

    fn mark_split_broken(&mut self, from: u64, to: u64) {
        for (_, pkt) in self.pkts.range(from..to) {
            if pkt.state != State::Received {
                if let Some(o) = self.open.get_mut(&pkt.bucket_ms) {
                    o.split_broken = true;
                }
            }
        }
    }

    /// Expires in-flight packets and returns the buckets that are complete.
    pub fn poll(&mut self, now_ns: i64) -> Vec<Bucket> {
        let deadline = now_ns - self.cfg.timeout_ns;
        let expired: Vec<u64> = self
            .pkts
            .iter()
            .filter(|(_, p)| p.state == State::InFlight && p.t1_ns <= deadline)
            .map(|(seq, _)| *seq)
            .collect();
        for seq in expired {
            self.mark_lost(seq, None);
        }

        let mut out = Vec::new();
        while let Some((&ts_ms, o)) = self.open.first_key_value() {
            let end_ns = (ts_ms + self.cfg.interval_ms) * NS_PER_MS;
            // Once the second has ended nothing new can be sent into it, so it
            // is complete as soon as every packet in it is resolved: normally
            // one RTT after the second ends, `timeout` later if a packet is lost.
            if o.inflight > 0 || now_ns < end_ns {
                break;
            }
            let covered = self.covered_upto.is_some_and(|c| c >= o.max_seq);
            let settled = !self.cfg.stateful_reflector
                || o.b.lost == 0
                || covered
                || o.split_broken
                || now_ns >= end_ns + self.cfg.timeout_ns + self.cfg.split_wait_ns;
            if !settled {
                break;
            }
            let Some((_, o)) = self.open.pop_first() else { break };
            out.push(self.finish(o, covered));
        }

        let horizon = now_ns - self.cfg.timeout_ns - 10_000 * NS_PER_MS;
        self.pkts.retain(|_, p| p.t1_ns > horizon || p.state == State::InFlight);
        out
    }

    fn finish(&self, o: Open, covered: bool) -> Bucket {
        let mut b = o.b;
        b.rx_kernel = o.all_kernel && b.received > 0;
        b.clock_synced = b.owd_n > 0 && !o.owd_unsynced;
        if b.clock_synced {
            b.owd_fwd_sum_us = Some(o.owd_fwd_ns / 1000);
            b.owd_back_sum_us = Some(o.owd_back_ns / 1000);
        } else {
            b.owd_n = 0;
            b.clock_err_us = None;
        }
        let split_known =
            self.cfg.stateful_reflector && self.prev_split.is_some() && (b.lost == 0 || (covered && !o.split_broken));
        if split_known {
            let fwd = o.fwd_assigned.min(b.lost);
            b.fwd_lost = Some(fwd);
            b.back_lost = Some(b.lost - fwd);
        }
        b
    }
}

/// Expands a `bits`-wide wrapped counter to the 64-bit value nearest `near`.
fn widen(wire: u64, bits: u32, near: u64) -> u64 {
    let modulus = 1_u64 << bits;
    let mask = modulus - 1;
    let base = near & !mask;
    [base.checked_sub(modulus), Some(base), base.checked_add(modulus)]
        .into_iter()
        .flatten()
        .map(|b| b | (wire & mask))
        .min_by_key(|c| c.abs_diff(near))
        .unwrap_or(wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i64 = NS_PER_MS;
    const T0: i64 = 1_761_955_200_000 * MS; // a whole second

    fn cfg(stateful: bool) -> TrackerConfig {
        TrackerConfig {
            interval_ms: 1000,
            timeout_ns: 500 * MS,
            split_wait_ns: 2_000 * MS,
            stateful_reflector: stateful,
        }
    }

    /// A STAMP reply with a symmetric one-way delay of `owd_ms` and no dwell.
    fn stamp_reply(seq: u64, t1: i64, owd_ms: i64, reflector_seq: u32) -> Reply {
        let t2 = t1 + owd_ms * MS;
        Reply {
            seq,
            t4_ns: t2 + owd_ms * MS,
            kernel_ts: true,
            remote: Some(RemoteTimes { t2_ns: t2, t3_ns: t2, reflector_seq, synced: false, err_us: None, ttl_fwd: 61 }),
            ttl_back: Some(60),
            local_synced: false,
            local_err_us: None,
            rtt_ns: None,
            echoed_t1_ns: None,
        }
    }

    /// Sends `n` packets 100 ms apart starting at `start`, returns (seq, t1).
    fn send_n(t: &mut Tracker, start: i64, n: usize) -> Vec<(u64, i64)> {
        (0..n)
            .map(|i| {
                let t1 = start + i as i64 * 100 * MS;
                (t.on_sent(t1), t1)
            })
            .collect()
    }

    #[test]
    fn clean_second_is_emitted_as_soon_as_it_closes() {
        let mut t = Tracker::new(cfg(true));
        let sent = send_n(&mut t, T0, 10);
        for (i, (seq, t1)) in sent.iter().enumerate() {
            assert_eq!(t.on_reply(stamp_reply(*seq, *t1, 10, i as u32)), ReplyOutcome::Received);
        }
        assert!(t.poll(T0 + 999 * MS).is_empty(), "not before the second ends");
        let out = t.poll(T0 + 1_000 * MS);
        assert_eq!(out.len(), 1);
        let b = &out[0];
        assert_eq!(b.ts_ms, T0 / MS);
        assert_eq!((b.sent, b.received, b.lost, b.late, b.dup, b.reordered), (10, 10, 0, 0, 0, 0));
        assert_eq!(b.rtt_us, vec![20_000; 10]);
        assert_eq!((b.fwd_lost, b.back_lost), (Some(0), Some(0)));
        assert_eq!((b.ttl_fwd, b.ttl_back), (Some(61), Some(60)));
        assert!(b.rx_kernel);
        assert_eq!(b.rtt_jitter_n, 9);
        assert_eq!(b.rtt_jitter_sum_us, 0);
        assert!(!b.clock_synced);
        assert_eq!(b.owd_fwd_sum_us, None);
    }

    #[test]
    fn timeout_marks_lost_and_late_reply_is_not_received() {
        let mut t = Tracker::new(cfg(false));
        let sent = send_n(&mut t, T0, 2);
        t.on_reply(stamp_reply(sent[0].0, sent[0].1, 5, 0));
        let _ = t.poll(T0 + 700 * MS); // packet 1 (t1 = T0+100ms) expires at T0+600ms
        let late = stamp_reply(sent[1].0, sent[1].1, 400, 1);
        assert_eq!(t.on_reply(late), ReplyOutcome::Late);
        let out = t.poll(T0 + 1_500 * MS);
        let b = &out[0];
        assert_eq!((b.sent, b.received, b.lost, b.late), (2, 1, 1, 1));
        assert_eq!(b.rtt_us.len(), 1);
        assert_eq!(b.fwd_lost, None, "no split without a stateful reflector");
    }

    #[test]
    fn reply_after_timeout_before_poll_is_late() {
        let mut t = Tracker::new(cfg(false));
        let sent = send_n(&mut t, T0, 1);
        assert_eq!(t.on_reply(stamp_reply(sent[0].0, sent[0].1, 300, 0)), ReplyOutcome::Late);
        let b = &t.poll(T0 + 2_000 * MS)[0];
        assert_eq!((b.received, b.lost, b.late), (0, 1, 1));
    }

    #[test]
    fn duplicates_and_reordering_are_counted() {
        let mut t = Tracker::new(cfg(false));
        let sent = send_n(&mut t, T0, 3);
        t.on_reply(stamp_reply(sent[0].0, sent[0].1, 5, 0));
        t.on_reply(stamp_reply(sent[2].0, sent[2].1, 5, 2));
        t.on_reply(stamp_reply(sent[1].0, sent[1].1, 5, 1)); // arrives after seq 2
        assert_eq!(t.on_reply(stamp_reply(sent[1].0, sent[1].1, 5, 1)), ReplyOutcome::Duplicate);
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!((b.received, b.reordered, b.dup), (3, 1, 1));
        // Pairs: (0,2) only — the reordered packet is not paired backwards.
        assert_eq!(b.rtt_jitter_n, 1);
    }

    #[test]
    fn forward_loss_is_split_from_return_loss() {
        // Packets 0..10. Packet 3 is lost on the way out (the reflector never
        // counts it); packet 6 is lost on the way back (counted, never returned).
        let mut t = Tracker::new(cfg(true));
        let sent = send_n(&mut t, T0, 10);
        let mut reflector = 0_u32;
        for (seq, t1) in &sent {
            if *seq == 3 {
                continue; // forward loss: reflector never saw it
            }
            let r = reflector;
            reflector += 1;
            if *seq == 6 {
                continue; // return loss: reflector counted it, reply lost
            }
            t.on_reply(stamp_reply(*seq, *t1, 10, r));
        }
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!((b.sent, b.received, b.lost), (10, 8, 2));
        assert_eq!((b.fwd_lost, b.back_lost), (Some(1), Some(1)));
    }

    #[test]
    fn first_packets_lost_forward_are_counted() {
        let mut t = Tracker::new(cfg(true));
        let sent = send_n(&mut t, T0, 4);
        // Packets 0 and 1 never reach the reflector; it counts 2 as its first (0).
        t.on_reply(stamp_reply(sent[2].0, sent[2].1, 10, 0));
        t.on_reply(stamp_reply(sent[3].0, sent[3].1, 10, 1));
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!((b.lost, b.fwd_lost, b.back_lost), (2, Some(2), Some(0)));
    }

    #[test]
    fn lossy_bucket_waits_for_the_reply_that_settles_the_split() {
        let mut t = Tracker::new(cfg(true));
        // Second 0: 10 packets, the last one lost forward.
        let s0 = send_n(&mut t, T0, 10);
        for (i, (seq, t1)) in s0.iter().take(9).enumerate() {
            t.on_reply(stamp_reply(*seq, *t1, 10, i as u32));
        }
        // At end + timeout the split is not settled yet: nothing after seq 9 replied.
        assert!(t.poll(T0 + 1_500 * MS).is_empty());
        // Second 1: the next reply arrives with reflector seq 9 (packet 9 never counted).
        let s1 = send_n(&mut t, T0 + 1_000 * MS, 1);
        t.on_reply(stamp_reply(s1[0].0, s1[0].1, 10, 9));
        let out = t.poll(T0 + 1_600 * MS);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].lost, out[0].fwd_lost, out[0].back_lost), (1, Some(1), Some(0)));
    }

    #[test]
    fn total_outage_gives_up_on_the_split_after_split_wait() {
        let mut t = Tracker::new(cfg(true));
        let s0 = send_n(&mut t, T0, 2);
        t.on_reply(stamp_reply(s0[0].0, s0[0].1, 10, 0));
        assert!(t.poll(T0 + 1_500 * MS).is_empty());
        let out = t.poll(T0 + 3_500 * MS); // end + timeout + split_wait
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].lost, out[0].fwd_lost, out[0].back_lost), (1, None, None));
    }

    #[test]
    fn reflector_restart_breaks_the_split_instead_of_inventing_one() {
        let mut t = Tracker::new(cfg(true));
        let s = send_n(&mut t, T0, 4);
        t.on_reply(stamp_reply(s[0].0, s[0].1, 10, 100));
        // Packet 1 lost; reflector restarts and numbers packet 2 as 0.
        t.on_reply(stamp_reply(s[2].0, s[2].1, 10, 0));
        t.on_reply(stamp_reply(s[3].0, s[3].1, 10, 1));
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!(b.lost, 1);
        assert_eq!((b.fwd_lost, b.back_lost), (None, None));
    }

    #[test]
    fn ipdv_per_direction_cancels_clock_offset() {
        let mut t = Tracker::new(cfg(true));
        let s = send_n(&mut t, T0, 3);
        // Reflector clock is 5 s ahead; forward delay 10, 14, 10 ms; return 10 ms.
        let offset = 5_000 * MS;
        for (i, (seq, t1)) in s.iter().enumerate() {
            let fwd = [10, 14, 10][i] * MS;
            let t2 = t1 + fwd + offset;
            let reply = Reply {
                seq: *seq,
                t4_ns: t1 + fwd + 10 * MS,
                kernel_ts: true,
                remote: Some(RemoteTimes {
                    t2_ns: t2,
                    t3_ns: t2,
                    reflector_seq: i as u32,
                    synced: true,
                    err_us: Some(50),
                    ttl_fwd: 64,
                }),
                ttl_back: Some(64),
                local_synced: true,
                local_err_us: Some(20),
                rtt_ns: None,
                echoed_t1_ns: None,
            };
            t.on_reply(reply);
        }
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!((b.ipdv_fwd_n, b.ipdv_fwd_sum_us), (2, 8_000));
        assert_eq!((b.ipdv_back_n, b.ipdv_back_sum_us), (2, 0));
        // Both ends claim sync, so one-way sums are reported (with the offset
        // baked in — that is what "synced" asserts is not there).
        assert!(b.clock_synced);
        assert_eq!(b.owd_n, 3);
        assert_eq!(b.clock_err_us, Some(70));
    }

    #[test]
    fn failures_carry_reasons() {
        let mut t = Tracker::new(cfg(false));
        let seq = t.on_sent(T0);
        t.on_failure(seq, "refused");
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!((b.sent, b.lost), (1, 1));
        assert_eq!(b.errors.get("refused"), Some(&1));
    }

    #[test]
    fn rtt_override_is_used() {
        let mut t = Tracker::new(cfg(false));
        let seq = t.on_sent(T0);
        t.on_reply(Reply {
            seq,
            t4_ns: T0 + 9 * MS,
            kernel_ts: false,
            remote: None,
            ttl_back: None,
            local_synced: false,
            local_err_us: None,
            rtt_ns: Some(4_321_000),
            echoed_t1_ns: None,
        });
        let b = &t.poll(T0 + 1_500 * MS)[0];
        assert_eq!(b.rtt_us, vec![4_321]);
        assert!(!b.rx_kernel);
    }

    #[test]
    fn reply_echoing_a_different_t1_is_not_ours() {
        let mut t = Tracker::new(cfg(true));
        let seq = t.on_sent(T0);
        let mut stale = stamp_reply(seq, T0, 5, 0);
        stale.echoed_t1_ns = Some(T0 - 3_000 * MS); // same seq, previous run
        assert_eq!(t.on_reply(stale), ReplyOutcome::Unknown);
        let mut ours = stamp_reply(seq, T0, 5, 0);
        ours.echoed_t1_ns = Some(T0 + 1); // NTP rounding
        assert_eq!(t.on_reply(ours), ReplyOutcome::Received);
        assert_eq!(t.stray_replies, 1);
    }

    #[test]
    fn a_lost_packet_holds_its_second_until_the_timeout() {
        let mut t = Tracker::new(cfg(false));
        let sent = send_n(&mut t, T0, 10);
        for (seq, t1) in sent.iter().take(9) {
            t.on_reply(stamp_reply(*seq, *t1, 5, 0));
        }
        // Packet 9 (t1 = T0 + 900 ms) is unresolved until T0 + 1400 ms.
        assert!(t.poll(T0 + 1_200 * MS).is_empty());
        let out = t.poll(T0 + 1_400 * MS);
        assert_eq!((out[0].received, out[0].lost), (9, 1));
    }

    #[test]
    fn buckets_are_emitted_in_order_and_idle_seconds_are_skipped() {
        let mut t = Tracker::new(cfg(false));
        let a = t.on_sent(T0);
        let b = t.on_sent(T0 + 3_000 * MS);
        t.on_reply(stamp_reply(a, T0, 1, 0));
        t.on_reply(stamp_reply(b, T0 + 3_000 * MS, 1, 1));
        let out = t.poll(T0 + 5_000 * MS);
        assert_eq!(out.iter().map(|b| b.ts_ms).collect::<Vec<_>>(), vec![T0 / MS, T0 / MS + 3_000]);
    }

    #[test]
    fn widen_handles_wraparound() {
        assert_eq!(widen(5, 16, 65_540), 65_541);
        assert_eq!(widen(65_535, 16, 65_537), 65_535);
        assert_eq!(widen(3, 32, 10), 3);
        assert_eq!(widen(u32::MAX as u64, 32, 1 << 32), u32::MAX as u64);
        assert_eq!(widen(2, 32, (1 << 32) + 1), (1 << 32) + 2);
    }
}
