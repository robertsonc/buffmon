-- buffmon Phase 3.3: RFC 9946 (UDPSTP) speed-test results (ClickHouse 25.8 LTS).
--
-- One row per job a probe ran (or refused), from the probe's `speedtests`
-- array (docs/PROBE-RECORD.md). Keyed by (probe_id, job_id): a resent result
-- collapses on merge; a retried insert with the same dedup token is dropped.

CREATE DATABASE IF NOT EXISTS buffmon;

CREATE TABLE IF NOT EXISTS buffmon.speedtests
(
    ts                    DateTime64(3, 'UTC'),
    probe_id              LowCardinality(String),
    site                  LowCardinality(String),
    target                LowCardinality(String),
    server                String,
    job_id                String,
    direction             LowCardinality(String),
    duration_s            UInt8,
    max_mbps              UInt16,
    dscp                  UInt8,
    -- completed, warning, failed, refused (by the probe)
    status                LowCardinality(String),
    error_status          Nullable(UInt8),
    error                 Nullable(String),
    -- RFC 9097 Maximum IP-Layer Capacity, Mbit/s, and conditions at that maximum
    max_ip_capacity_mbps  Nullable(Float64),
    loss_ratio_at_max     Nullable(Float64),
    rtt_range_ms_at_max   Nullable(Float64),
    pdv_range_ms_at_max   Nullable(Float64),
    summary_capacity_mbps Nullable(Float64),
    summary_loss_ratio    Nullable(Float64),
    delivered_pct         Nullable(Float64),
    ecn_bleaching         Nullable(Bool),
    udpst_version         Nullable(String),
    ingested_at           DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)
ORDER BY (probe_id, job_id, ts)
TTL toDateTime(ts) + INTERVAL 400 DAY
SETTINGS non_replicated_deduplication_window = 1000;
