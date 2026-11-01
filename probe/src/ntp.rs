//! NTP 64-bit timestamps (RFC 5905 §6), the format STAMP uses on the wire.
//!
//! Internally every time is `i64` nanoseconds since the Unix epoch
//! (CLOCK_REALTIME).

/// Seconds from 1900-01-01 (NTP era 0) to 1970-01-01 (Unix epoch).
pub const NTP_UNIX_OFFSET_S: i64 = 2_208_988_800;
const NS_PER_S: i64 = 1_000_000_000;
const ERA_S: i64 = 1 << 32;

/// Unix nanoseconds → NTP timestamp. The seconds field wraps every 2^32 s
/// (next wrap: 2036-02-07); [`to_unix_ns_near`] resolves the era on decode.
pub fn from_unix_ns(ns: i64) -> u64 {
    let secs = ns.div_euclid(NS_PER_S) + NTP_UNIX_OFFSET_S;
    let frac_ns = ns.rem_euclid(NS_PER_S) as u64;
    // frac_ns < 2^30, so frac_ns << 32 < 2^62: no overflow.
    let frac = (frac_ns << 32) / NS_PER_S as u64;
    ((secs.rem_euclid(ERA_S) as u64) << 32) | frac
}

/// NTP timestamp → Unix nanoseconds, choosing the NTP era that puts the result
/// closest to `reference_ns` (normally "now").
pub fn to_unix_ns_near(ts: u64, reference_ns: i64) -> i64 {
    let secs_in_era = (ts >> 32) as i64;
    let frac = ts & 0xFFFF_FFFF;
    // frac < 2^32, frac * 1e9 < 2^62: no overflow. Rounded to nearest ns.
    let frac_ns = ((frac * NS_PER_S as u64 + (1 << 31)) >> 32) as i64;

    let ref_ntp_s = reference_ns.div_euclid(NS_PER_S) + NTP_UNIX_OFFSET_S;
    let ref_era = ref_ntp_s.div_euclid(ERA_S);
    let best_era = [ref_era - 1, ref_era, ref_era + 1]
        .into_iter()
        .min_by_key(|era| (era * ERA_S + secs_in_era - ref_ntp_s).abs())
        .unwrap_or(ref_era);
    (best_era * ERA_S + secs_in_era - NTP_UNIX_OFFSET_S) * NS_PER_S + frac_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_is_within_one_ns() {
        for ns in [0_i64, 1, 999_999_999, 1_761_955_200_123_456_789, 2_085_978_495_999_999_999] {
            let back = to_unix_ns_near(from_unix_ns(ns), ns);
            assert!((back - ns).abs() <= 1, "{ns} -> {back}");
        }
    }

    #[test]
    fn unix_epoch_is_ntp_offset() {
        assert_eq!(from_unix_ns(0) >> 32, NTP_UNIX_OFFSET_S as u64);
        assert_eq!(from_unix_ns(0) & 0xFFFF_FFFF, 0);
    }

    #[test]
    fn half_second_is_half_fraction() {
        assert_eq!(from_unix_ns(500_000_000) & 0xFFFF_FFFF, 1 << 31);
    }

    #[test]
    fn era_rollover_2036_decodes_correctly() {
        // 2036-02-07T06:28:16Z is NTP second 2^32; one second before and after.
        let rollover_unix_s = ERA_S - NTP_UNIX_OFFSET_S;
        for delta in [-1_i64, 0, 1, 3600] {
            let ns = (rollover_unix_s + delta) * NS_PER_S + 250_000_000;
            let back = to_unix_ns_near(from_unix_ns(ns), ns);
            assert!((back - ns).abs() <= 1, "delta {delta}: {ns} -> {back}");
        }
    }
}
