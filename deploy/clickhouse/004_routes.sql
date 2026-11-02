-- buffmon Phase 3: forward route traces and packet-train capacity (ClickHouse 25.8 LTS).
--
-- Written by the ingest service from the probe's `routes` and `capacity`
-- arrays (docs/PROBE-RECORD.md). One row per trace / per measurement.
--
-- Idempotency: (probe_id, session, ts) is the natural key; a resent result
-- collapses on merge, and a retried insert carrying the same
-- insert_deduplication_token is dropped immediately.

CREATE DATABASE IF NOT EXISTS buffmon;

CREATE TABLE IF NOT EXISTS buffmon.route_traces
(
    ts              DateTime64(3, 'UTC'),
    probe_id        LowCardinality(String),
    site            LowCardinality(String),
    session         LowCardinality(String),
    app_class       LowCardinality(String),
    dscp            UInt8,
    src             String,
    dst             String,
    trigger         LowCardinality(String),
    duration_ms     UInt32,
    ttl_fwd         Nullable(UInt8),
    ttl_back        Nullable(UInt8),
    hop_count_fwd   Nullable(UInt8),
    -- Hops as parallel arrays, index i = TTL i + 1.
    hop_addrs       Array(Array(String)),
    hop_rtt_us      Array(Nullable(UInt32)),
    hop_sent        Array(UInt8),
    hop_replies     Array(UInt8),
    hop_unreachable Array(Nullable(UInt8)),
    complete        Bool,
    multipath       Bool,
    signature       String,
    changed         Bool,
    change_ttl      Nullable(UInt8),
    change_reason   LowCardinality(Nullable(String)),
    prev_signature  Nullable(String),
    ingested_at     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)
ORDER BY (probe_id, session, ts)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS buffmon.capacity
(
    ts                  DateTime64(3, 'UTC'),
    probe_id            LowCardinality(String),
    site                LowCardinality(String),
    session             LowCardinality(String),
    app_class           LowCardinality(String),
    dscp                UInt8,
    src                 String,
    dst                 String,
    packets             UInt16,
    size                UInt16,
    trains              UInt8,
    valid_trains        UInt8,
    -- bit/s at the IP layer
    fwd_bps             Nullable(UInt64),
    fwd_bps_min         Nullable(UInt64),
    fwd_bps_max         Nullable(UInt64),
    fwd_adr_bps         Nullable(UInt64),
    burst_trains        UInt8,
    burst_bytes         Nullable(UInt64),
    back_bps            Nullable(UInt64),
    back_is_lower_bound Bool,
    -- forward_train (from the forward trains' replies) or reflected_train (RFC 10052)
    back_method         LowCardinality(String) DEFAULT 'forward_train',
    back_trains         UInt8 DEFAULT 0,
    back_valid_trains   UInt8 DEFAULT 0,
    back_bps_min        Nullable(UInt64),
    back_bps_max        Nullable(UInt64),
    back_burst_bytes    Nullable(UInt64),
    lost                UInt32,
    invalid             Map(LowCardinality(String), UInt32),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)
ORDER BY (probe_id, session, ts)
TTL toDateTime(ts) + INTERVAL 400 DAY
SETTINGS non_replicated_deduplication_window = 1000;
