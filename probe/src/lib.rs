//! buffmon site probe.
//!
//! STAMP (RFC 8762) sender and stateful reflector, ICMP echo and TCP connect
//! probes. Every session produces one record per second in the format defined by
//! `docs/PROBE-RECORD.md`. STAMP sessions also trace their forward path (Paris
//! traceroute on the session's own flow) and, where enabled, estimate the
//! forward bottleneck capacity from packet trains.

#[cfg(not(target_os = "linux"))]
compile_error!("buffmon-probe targets Linux: it relies on SO_TIMESTAMPNS, IP_RECVTTL/IP_RECVTOS and raw sockets.");

pub mod capacity;
pub mod clock;
pub mod config;
pub mod icmp;
pub mod ntp;
pub mod output;
pub mod record;
pub mod reflector;
pub mod stamp;
pub mod stamp_session;
pub mod sys;
pub mod tcp;
pub mod trace;
pub mod tracker;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How often session loops wake up to expire packets and emit records.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Locks a mutex, recovering the data if another thread panicked while holding
/// it (release builds abort on panic, so this only matters in tests).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Rate-limits a repeating log message: at most one per `every`, reporting how
/// many were suppressed in between.
#[derive(Debug)]
pub struct Throttle {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl Throttle {
    pub fn new(every: Duration) -> Self {
        Self { every, last: None, suppressed: 0 }
    }

    /// Returns `Some(suppressed_since_last)` when the caller should log now.
    pub fn ready(&mut self) -> Option<u64> {
        let now = Instant::now();
        if self.last.is_none_or(|t| now.duration_since(t) >= self.every) {
            self.last = Some(now);
            Some(std::mem::take(&mut self.suppressed))
        } else {
            self.suppressed += 1;
            None
        }
    }
}

/// Sleeps until `deadline`, waking every [`POLL_INTERVAL`] to honour `stop`.
/// Returns false if stopped.
pub fn sleep_until(deadline: Instant, stop: &std::sync::atomic::AtomicBool) -> bool {
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        std::thread::sleep((deadline - now).min(POLL_INTERVAL));
    }
}

/// Short reason string for a socket error, used in the record's `errors` map.
pub fn error_reason(e: &std::io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(libc::ECONNREFUSED) => "refused",
        Some(libc::EHOSTUNREACH) | Some(libc::ENETUNREACH) => "unreachable",
        Some(libc::ETIMEDOUT) => "timeout",
        Some(libc::ECONNRESET) => "reset",
        Some(libc::EPERM) | Some(libc::EACCES) => "denied",
        _ => "error",
    }
}
