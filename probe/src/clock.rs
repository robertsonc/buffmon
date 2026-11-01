//! Wall clock, kernel clock-sync status, and the STAMP Error Estimate field.

use std::time::{SystemTime, UNIX_EPOCH};

/// CLOCK_REALTIME in nanoseconds since the Unix epoch.
pub fn now_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockStatus {
    /// The kernel reports the clock as synchronised (NTP/PTP discipline active).
    pub synced: bool,
    /// The kernel's estimated error, microseconds.
    pub est_error_us: Option<u64>,
}

/// Reads the kernel's clock discipline state via `adjtimex` (read-only:
/// `modes = 0`, so no capability is needed).
pub fn status() -> ClockStatus {
    const TIME_ERROR: libc::c_int = 5;
    const STA_UNSYNC: libc::c_int = 0x0040;

    // SAFETY: timex is plain old data; modes = 0 makes adjtimex a pure read.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::adjtimex(&mut tx) };
    if state < 0 {
        return ClockStatus { synced: false, est_error_us: None };
    }
    let synced = state != TIME_ERROR && (tx.status & STA_UNSYNC) == 0;
    let est_error_us = if synced && tx.esterror >= 0 { Some((tx.esterror as u64).max(1)) } else { None };
    ClockStatus { synced, est_error_us }
}

/// Encodes the 16-bit Error Estimate of RFC 4656 §4.1.2 as used by STAMP:
/// `S | Z | Scale(6) | Multiplier(8)`, error = Multiplier × 2^(Scale − 32) s.
/// Z = 0 (NTP timestamp format). An unknown error is encoded as the largest
/// representable value; the Multiplier is never zero.
pub fn encode_error_estimate(status: ClockStatus) -> u16 {
    let s_bit: u16 = if status.synced { 0x8000 } else { 0 };
    let (scale, multiplier) = match status.est_error_us {
        Some(us) => scale_multiplier(us),
        None => (63, 255),
    };
    s_bit | (u16::from(scale) << 8) | u16::from(multiplier)
}

fn scale_multiplier(error_us: u64) -> (u8, u8) {
    // Error in units of 2^-32 s, rounded up so the bound is never understated.
    let mut m: u128 = (u128::from(error_us.max(1)) << 32).div_ceil(1_000_000);
    let mut scale: u8 = 0;
    while m > 255 && scale < 63 {
        m = m.div_ceil(2);
        scale += 1;
    }
    (scale, m.clamp(1, 255) as u8)
}

/// Decodes an Error Estimate into (synchronised, error in µs). A zero
/// Multiplier is invalid per RFC 4656; the error is then unknown.
pub fn decode_error_estimate(v: u16) -> (bool, Option<u64>) {
    let synced = v & 0x8000 != 0;
    let scale = u32::from((v >> 8) & 0x3F);
    let multiplier = u128::from(v & 0xFF);
    if multiplier == 0 {
        return (synced, None);
    }
    let units = multiplier << scale; // ≤ 255 · 2^63, fits in u128
    let us = (units * 1_000_000).div_ceil(1 << 32);
    (synced, Some(u64::try_from(us).unwrap_or(u64::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_estimate_round_trip_never_understates() {
        for us in [1_u64, 7, 250, 1_000, 15_625, 1_000_000, 60_000_000] {
            let v = encode_error_estimate(ClockStatus { synced: true, est_error_us: Some(us) });
            let (synced, back) = decode_error_estimate(v);
            assert!(synced);
            let back = back.expect("known error");
            assert!(back >= us, "{us} decoded as {back}");
            // Coarse encoding: within a factor of ~2 of the input above 1 µs.
            assert!(back <= us * 2 + 1, "{us} decoded as {back}");
        }
    }

    #[test]
    fn unsynced_clears_s_bit_and_encodes_unknown_as_max() {
        let v = encode_error_estimate(ClockStatus { synced: false, est_error_us: None });
        assert_eq!(v & 0x8000, 0);
        assert_eq!(v & 0xFF, 255);
        assert_eq!((v >> 8) & 0x3F, 63);
    }

    #[test]
    fn zero_multiplier_is_unknown() {
        assert_eq!(decode_error_estimate(0x8000), (true, None));
    }
}
