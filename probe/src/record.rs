//! The wire record (docs/PROBE-RECORD.md, v1).

use crate::tracker::Bucket;
use serde::Serialize;
use std::collections::BTreeMap;

pub const RECORD_VERSION: u32 = 1;

/// Fields that are the same for every record of a session.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub probe_id: String,
    pub site: String,
    pub session: String,
    pub kind: &'static str,
    pub app_class: String,
    pub dscp: u8,
    pub src: String,
    pub dst: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Record {
    pub v: u32,
    pub probe_id: String,
    pub site: String,
    pub session: String,
    pub kind: &'static str,
    pub app_class: String,
    pub dscp: u8,
    pub src: String,
    pub dst: String,
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
    pub rx_ts: &'static str,
    pub errors: BTreeMap<String, u32>,
}

impl Record {
    pub fn new(meta: &SessionMeta, b: Bucket) -> Self {
        Self {
            v: RECORD_VERSION,
            probe_id: meta.probe_id.clone(),
            site: meta.site.clone(),
            session: meta.session.clone(),
            kind: meta.kind,
            app_class: meta.app_class.clone(),
            dscp: meta.dscp,
            src: meta.src.clone(),
            dst: meta.dst.clone(),
            ts_ms: b.ts_ms,
            interval_ms: b.interval_ms,
            sent: b.sent,
            received: b.received,
            lost: b.lost,
            late: b.late,
            dup: b.dup,
            reordered: b.reordered,
            fwd_lost: b.fwd_lost,
            back_lost: b.back_lost,
            rtt_us: b.rtt_us,
            rtt_jitter_sum_us: b.rtt_jitter_sum_us,
            rtt_jitter_n: b.rtt_jitter_n,
            ipdv_fwd_sum_us: b.ipdv_fwd_sum_us,
            ipdv_fwd_n: b.ipdv_fwd_n,
            ipdv_back_sum_us: b.ipdv_back_sum_us,
            ipdv_back_n: b.ipdv_back_n,
            owd_fwd_sum_us: b.owd_fwd_sum_us,
            owd_back_sum_us: b.owd_back_sum_us,
            owd_n: b.owd_n,
            clock_synced: b.clock_synced,
            clock_err_us: b.clock_err_us,
            ttl_fwd: b.ttl_fwd,
            ttl_back: b.ttl_back,
            rx_ts: if b.rx_kernel { "kernel" } else { "user" },
            errors: b.errors,
        }
    }
}
