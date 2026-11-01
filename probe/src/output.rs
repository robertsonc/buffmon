//! Ships records to the ingest service (docs/PROBE-RECORD.md "Transport").
//!
//! * Bounded in-memory queue; when full the oldest records are dropped and
//!   counted (a probe must never grow without bound during an ingest outage).
//! * One gzip-compressed batch per `batch_ms`.
//! * Status handling follows the contract: 200 delete; 400 drop; 401/403 keep
//!   and back off; 413 split; 429/5xx/network keep and retry with backoff.
//!   Retrying is safe: (probe_id, session, ts_ms) is an idempotency key.

use crate::capacity::CapacityResult;
use crate::config::OutputSection;
use crate::record::Record;
use crate::trace::RouteResult;
use crate::Throttle;
use serde::Serialize;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Anything a session produces for the ingest service.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum Item {
    /// One second of a session (`records`).
    Record(Record),
    /// One forward route trace (`routes`).
    Route(RouteResult),
    /// One capacity measurement (`capacity`).
    Capacity(CapacityResult),
}

impl From<Record> for Item {
    fn from(r: Record) -> Self {
        Item::Record(r)
    }
}

/// The ingest batch. `routes` and `capacity` are left out when empty, so a batch
/// of records alone is exactly the v1 shape.
#[derive(Serialize)]
struct Batch<'a> {
    probe_id: &'a str,
    records: Vec<&'a Record>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routes: Vec<&'a RouteResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capacity: Vec<&'a CapacityResult>,
}

impl<'a> Batch<'a> {
    fn of(probe_id: &'a str, items: &'a [Item]) -> Self {
        let mut b = Batch { probe_id, records: Vec::new(), routes: Vec::new(), capacity: Vec::new() };
        for i in items {
            match i {
                Item::Record(r) => b.records.push(r),
                Item::Route(p) => b.routes.push(p),
                Item::Capacity(c) => b.capacity.push(c),
            }
        }
        b
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Delivered {
        accepted: u64,
        duplicates: u64,
        rejected: u64,
    },
    /// Unusable batch (400): retrying cannot help.
    Drop(String),
    /// Auth problem (401/403): keep the data, back off, shout.
    AuthFailed(String),
    /// 413: split and retry.
    TooLarge,
    /// 429/5xx/network: keep and retry later.
    Retry(String),
}

pub struct Uploader {
    agent: ureq::Agent,
    url: String,
    auth_header: String,
    probe_id: String,
}

impl Uploader {
    pub fn new(o: &OutputSection, url: &str, token: &str, probe_id: &str) -> Result<Self, String> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout(Duration::from_millis(o.timeout_ms))
            .user_agent(&format!("buffmon-probe/{}", crate::VERSION));
        if let Some(p) = &o.proxy {
            builder = builder.proxy(ureq::Proxy::new(p).map_err(|e| format!("output.proxy {p:?}: {e}"))?);
        }
        Ok(Self {
            agent: builder.build(),
            url: url.to_string(),
            auth_header: format!("Bearer {token}"),
            probe_id: probe_id.to_string(),
        })
    }

    pub fn post(&self, items: &[Item]) -> Outcome {
        let body = match serde_json::to_vec(&Batch::of(&self.probe_id, items)) {
            Ok(b) => b,
            Err(e) => return Outcome::Drop(format!("serialise: {e}")),
        };
        let gz = match gzip(&body) {
            Ok(g) => g,
            Err(e) => return Outcome::Drop(format!("gzip: {e}")),
        };
        let resp = self
            .agent
            .post(&self.url)
            .set("authorization", &self.auth_header)
            .set("content-type", "application/json")
            .set("content-encoding", "gzip")
            .send_bytes(&gz);
        match resp {
            Ok(r) => {
                let v: serde_json::Value =
                    r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::Value::Null);
                let n = |k: &str| v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
                let rejected = n("rejected");
                if rejected > 0 {
                    log::warn!(
                        "ingest rejected {rejected} record(s): {}",
                        v.get("errors").unwrap_or(&serde_json::Value::Null)
                    );
                }
                Outcome::Delivered { accepted: n("accepted"), duplicates: n("duplicates"), rejected }
            }
            Err(ureq::Error::Status(code, r)) => {
                let text: String = r.into_string().unwrap_or_default().chars().take(300).collect();
                match code {
                    400 => Outcome::Drop(format!("HTTP 400: {text}")),
                    401 | 403 => Outcome::AuthFailed(format!("HTTP {code}: {text}")),
                    413 => Outcome::TooLarge,
                    _ => Outcome::Retry(format!("HTTP {code}: {text}")),
                }
            }
            Err(e) => Outcome::Retry(e.to_string()),
        }
    }
}

fn gzip(body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::with_capacity(body.len() / 4), flate2::Compression::fast());
    enc.write_all(body)?;
    enc.finish()
}

/// Exponential backoff with ±20% jitter (deterministic enough for tests, spread
/// enough that a fleet does not retry in lockstep).
fn next_backoff(current: Duration) -> Duration {
    let doubled = (current * 2).clamp(BACKOFF_MIN, BACKOFF_MAX);
    let nanos = crate::clock::now_ns().unsigned_abs();
    let jitter = 0.8 + (nanos % 400) as f64 / 1000.0;
    doubled.mul_f64(jitter).min(BACKOFF_MAX)
}

pub struct SinkStats {
    pub delivered: u64,
    pub dropped_overflow: u64,
    pub dropped_rejected: u64,
}

/// Runs the output loop until `stop` is set and the queue is drained (or a final
/// short flush attempt fails). `print` writes each record as a JSON line.
pub fn run(
    o: &OutputSection,
    uploader: Option<Uploader>,
    rx: Receiver<Item>,
    stop: &AtomicBool,
    print: bool,
) -> SinkStats {
    let mut queue: VecDeque<Item> = VecDeque::new();
    let mut stats = SinkStats { delivered: 0, dropped_overflow: 0, dropped_rejected: 0 };
    let mut overflow_log = Throttle::new(Duration::from_secs(30));
    let mut error_log = Throttle::new(Duration::from_secs(30));
    let mut backoff = Duration::ZERO;
    let mut next_attempt = Instant::now();
    let mut max_batch = o.max_batch;
    let batch_every = Duration::from_millis(o.batch_ms);
    let stdout = std::io::stdout();

    loop {
        // Gather for up to one batch interval.
        let deadline = Instant::now() + batch_every;
        let mut disconnected = false;
        loop {
            let wait = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(wait) {
                Ok(r) => {
                    if print {
                        if let Ok(line) = serde_json::to_string(&r) {
                            let _ = writeln!(stdout.lock(), "{line}");
                        }
                    }
                    if uploader.is_some() {
                        queue.push_back(r);
                    }
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if queue.len() > o.queue_max {
            let excess = queue.len() - o.queue_max;
            queue.drain(..excess);
            stats.dropped_overflow += excess as u64;
            if let Some(n) = overflow_log.ready() {
                log::warn!(
                    "output queue full: dropped {excess} oldest record(s), {} total ({n} logs suppressed)",
                    stats.dropped_overflow
                );
            }
        }

        let stopping = stop.load(Ordering::Relaxed) || disconnected;
        if let Some(up) = &uploader {
            // While stopping, make one final pass regardless of backoff.
            while !queue.is_empty() && (stopping || Instant::now() >= next_attempt) {
                let n = queue.len().min(max_batch);
                let batch: Vec<Item> = queue.drain(..n).collect();
                match up.post(&batch) {
                    Outcome::Delivered { accepted, duplicates, rejected } => {
                        stats.delivered += accepted + duplicates;
                        stats.dropped_rejected += rejected;
                        backoff = Duration::ZERO;
                        max_batch = (max_batch * 2).min(o.max_batch);
                    }
                    Outcome::Drop(why) => {
                        stats.dropped_rejected += batch.len() as u64;
                        log::error!("ingest refused a batch of {} record(s), dropping it: {why}", batch.len());
                    }
                    Outcome::TooLarge if batch.len() > 1 => {
                        max_batch = (batch.len() / 2).max(1);
                        requeue(&mut queue, batch);
                    }
                    Outcome::TooLarge => {
                        stats.dropped_rejected += 1;
                        log::error!("ingest says a single record is too large; dropping it");
                    }
                    Outcome::AuthFailed(why) => {
                        requeue(&mut queue, batch);
                        backoff = next_backoff(backoff.max(Duration::from_secs(15)));
                        next_attempt = Instant::now() + backoff;
                        log::error!(
                            "ingest rejected the probe token ({why}); keeping {} record(s), retry in {:?}",
                            queue.len(),
                            backoff
                        );
                        break;
                    }
                    Outcome::Retry(why) => {
                        requeue(&mut queue, batch);
                        backoff = next_backoff(backoff);
                        next_attempt = Instant::now() + backoff;
                        if let Some(n) = error_log.ready() {
                            log::warn!(
                                "upload failed ({why}); {} record(s) queued, retry in {:?} ({n} similar suppressed)",
                                queue.len(),
                                backoff
                            );
                        }
                        break;
                    }
                }
            }
        }
        if stopping {
            if !queue.is_empty() {
                log::warn!("shutting down with {} undelivered record(s)", queue.len());
            }
            return stats;
        }
    }
}

fn requeue(queue: &mut VecDeque<Item>, batch: Vec<Item>) {
    for r in batch.into_iter().rev() {
        queue.push_front(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut b = Duration::ZERO;
        let mut seen = Vec::new();
        for _ in 0..12 {
            b = next_backoff(b);
            seen.push(b);
        }
        assert!(seen[0] >= Duration::from_millis(800) && seen[0] <= Duration::from_millis(1200));
        assert!(seen.iter().all(|d| *d <= BACKOFF_MAX));
        assert!(*seen.last().unwrap() >= BACKOFF_MAX.mul_f64(0.8));
    }

    #[test]
    fn batch_keeps_the_v1_shape_and_adds_routes_and_capacity_only_when_present() {
        let meta = crate::record::SessionMeta {
            probe_id: "p".into(),
            site: "S".into(),
            session: "s".into(),
            kind: "stamp",
            app_class: "bulk".into(),
            dscp: 0,
            src: "10.0.0.1:1".into(),
            dst: "10.0.0.2:862".into(),
        };
        let rec = Record::new(&meta, crate::tracker::Bucket { ts_ms: 1000, interval_ms: 1000, ..Default::default() });
        let only_records = [Item::from(rec.clone())];
        let v = serde_json::to_value(Batch::of("p", &only_records)).unwrap();
        assert_eq!(v.as_object().unwrap().keys().collect::<Vec<_>>(), ["probe_id", "records"]);
        let path = crate::trace::RouteResult {
            v: 1,
            probe_id: "p".into(),
            site: "S".into(),
            session: "s".into(),
            kind: "route",
            app_class: "bulk".into(),
            dscp: 0,
            src: "10.0.0.1:1".into(),
            dst: "10.0.0.2:862".into(),
            ts_ms: 1000,
            duration_ms: 3000,
            trigger: "start",
            ttl_fwd: Some(61),
            ttl_back: Some(61),
            hop_count_fwd: Some(3),
            hops: vec![],
            complete: false,
            multipath: false,
            signature: String::new(),
            changed: false,
            change_ttl: None,
            change_reason: None,
            prev_signature: None,
        };
        let mixed = [Item::from(rec), Item::Route(path)];
        let v = serde_json::to_value(Batch::of("p", &mixed)).unwrap();
        assert_eq!(v["records"].as_array().unwrap().len(), 1);
        assert_eq!(v["routes"][0]["kind"], "route");
        assert!(v.get("capacity").is_none());
    }

    #[test]
    fn gzip_round_trips() {
        use std::io::Read;
        let gz = gzip(b"{\"hello\":1}").unwrap();
        let mut s = String::new();
        flate2::read::GzDecoder::new(&gz[..]).read_to_string(&mut s).unwrap();
        assert_eq!(s, "{\"hello\":1}");
    }
}
