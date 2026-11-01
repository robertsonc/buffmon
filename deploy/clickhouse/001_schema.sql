-- buffmon Phase 1 schema (ClickHouse 25.8 LTS).
--
-- probe_second: one row per (probe, session, 1-second bucket), exactly as the
-- probe reported it (docs/PROBE-RECORD.md). ReplacingMergeTree on the
-- idempotency key so a retried record cannot double count once parts merge.
-- The ingest service also drops duplicates before insert (see DESIGN.md §8).
--
-- probe_minute: 1-minute rollup fed by a materialised view. Sums are stored so
-- any ratio (loss %, jitter means) can be recomputed over any range, RTT
-- percentiles are kept as t-digest states over every raw sample.

CREATE DATABASE IF NOT EXISTS buffmon;

CREATE TABLE IF NOT EXISTS buffmon.probe_second
(
    ts                  DateTime64(3, 'UTC'),
    probe_id            LowCardinality(String),
    site                LowCardinality(String),
    session             LowCardinality(String),
    kind                LowCardinality(String),
    app_class           LowCardinality(String),
    dscp                UInt8,
    src_ip              IPv6,          -- IPv4 stored as ::ffff:a.b.c.d
    src_port            UInt16,
    dst_ip              IPv6,
    dst_port            UInt16,
    interval_ms         UInt32,
    sent                UInt32,
    received            UInt32,
    lost                UInt32,
    late                UInt32,
    dup                 UInt32,
    reordered           UInt32,
    fwd_lost            Nullable(UInt32),
    back_lost           Nullable(UInt32),
    rtt_us              Array(UInt32),
    rtt_jitter_sum_us   UInt64,
    rtt_jitter_n        UInt32,
    ipdv_fwd_sum_us     UInt64,
    ipdv_fwd_n          UInt32,
    ipdv_back_sum_us    UInt64,
    ipdv_back_n         UInt32,
    owd_fwd_sum_us      Nullable(Int64),
    owd_back_sum_us     Nullable(Int64),
    owd_n               UInt32,
    clock_synced        Bool,
    clock_err_us        Nullable(UInt32),
    ttl_fwd             Nullable(UInt8),
    ttl_back            Nullable(UInt8),
    rx_ts               LowCardinality(String),
    errors              Map(LowCardinality(String), UInt32),
    ingested_at         DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(ts)
ORDER BY (probe_id, session, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS buffmon.probe_minute
(
    minute              DateTime('UTC'),
    probe_id            LowCardinality(String),
    session             LowCardinality(String),
    site                SimpleAggregateFunction(anyLast, LowCardinality(String)),
    kind                SimpleAggregateFunction(anyLast, LowCardinality(String)),
    app_class           SimpleAggregateFunction(anyLast, LowCardinality(String)),
    dscp                SimpleAggregateFunction(anyLast, UInt8),
    sent                SimpleAggregateFunction(sum, UInt64),
    received            SimpleAggregateFunction(sum, UInt64),
    lost                SimpleAggregateFunction(sum, UInt64),
    late                SimpleAggregateFunction(sum, UInt64),
    dup                 SimpleAggregateFunction(sum, UInt64),
    reordered           SimpleAggregateFunction(sum, UInt64),
    -- Forward/return split only exists for STAMP rows with a stateful
    -- reflector; dir_sent is the denominator for those rows only.
    fwd_lost            SimpleAggregateFunction(sum, UInt64),
    back_lost           SimpleAggregateFunction(sum, UInt64),
    dir_sent            SimpleAggregateFunction(sum, UInt64),
    rtt_sum_us          SimpleAggregateFunction(sum, UInt64),
    rtt_n               SimpleAggregateFunction(sum, UInt64),
    rtt_max_us          SimpleAggregateFunction(max, UInt32),
    rtt_q               AggregateFunction(quantilesTDigestArray(0.5, 0.95, 0.99), Array(UInt32)),
    rtt_jitter_sum_us   SimpleAggregateFunction(sum, UInt64),
    rtt_jitter_n        SimpleAggregateFunction(sum, UInt64),
    ipdv_fwd_sum_us     SimpleAggregateFunction(sum, UInt64),
    ipdv_fwd_n          SimpleAggregateFunction(sum, UInt64),
    ipdv_back_sum_us    SimpleAggregateFunction(sum, UInt64),
    ipdv_back_n         SimpleAggregateFunction(sum, UInt64),
    owd_fwd_sum_us      SimpleAggregateFunction(sum, Int64),
    owd_back_sum_us     SimpleAggregateFunction(sum, Int64),
    owd_n               SimpleAggregateFunction(sum, UInt64),
    seconds             SimpleAggregateFunction(sum, UInt64)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (probe_id, session, minute)
TTL minute + INTERVAL 400 DAY
-- Required, not optional: a retried insert is dropped from probe_second by its
-- insert_deduplication_token, but the materialised view still pushes its block
-- here. With this window the view's block (whose token is derived from the
-- source token) is deduplicated too — but only if the INSERT also sets
-- deduplicate_blocks_in_dependent_materialized_views = 1 (default 0 on 25.8 LTS;
-- the ingest service always sets it). Without both, every retry double counts in
-- the rollup (verified on 25.8.33.6 and by tests/test_integration_clickhouse.py).
SETTINGS non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS buffmon.probe_minute_mv
TO buffmon.probe_minute
AS
-- Source columns are qualified with "s." because each output alias reuses a
-- source column name, and ClickHouse resolves bare names to aliases first.
SELECT
    toStartOfMinute(s.ts)                                   AS minute,
    s.probe_id                                              AS probe_id,
    s.session                                               AS session,
    anyLast(s.site)                                         AS site,
    anyLast(s.kind)                                         AS kind,
    anyLast(s.app_class)                                    AS app_class,
    anyLast(s.dscp)                                         AS dscp,
    sum(toUInt64(s.sent))                                   AS sent,
    sum(toUInt64(s.received))                               AS received,
    sum(toUInt64(s.lost))                                   AS lost,
    sum(toUInt64(s.late))                                   AS late,
    sum(toUInt64(s.dup))                                    AS dup,
    sum(toUInt64(s.reordered))                              AS reordered,
    sum(toUInt64(ifNull(s.fwd_lost, 0)))                    AS fwd_lost,
    sum(toUInt64(ifNull(s.back_lost, 0)))                   AS back_lost,
    sumIf(toUInt64(s.sent), s.fwd_lost IS NOT NULL)         AS dir_sent,
    sum(toUInt64(arraySum(s.rtt_us)))                       AS rtt_sum_us,
    sum(toUInt64(length(s.rtt_us)))                         AS rtt_n,
    max(arrayMax(arrayPushBack(s.rtt_us, toUInt32(0))))     AS rtt_max_us,
    quantilesTDigestArrayState(0.5, 0.95, 0.99)(s.rtt_us)   AS rtt_q,
    sum(s.rtt_jitter_sum_us)                                AS rtt_jitter_sum_us,
    sum(toUInt64(s.rtt_jitter_n))                           AS rtt_jitter_n,
    sum(s.ipdv_fwd_sum_us)                                  AS ipdv_fwd_sum_us,
    sum(toUInt64(s.ipdv_fwd_n))                             AS ipdv_fwd_n,
    sum(s.ipdv_back_sum_us)                                 AS ipdv_back_sum_us,
    sum(toUInt64(s.ipdv_back_n))                            AS ipdv_back_n,
    sum(ifNull(s.owd_fwd_sum_us, 0))                        AS owd_fwd_sum_us,
    sum(ifNull(s.owd_back_sum_us, 0))                       AS owd_back_sum_us,
    sum(toUInt64(s.owd_n))                                  AS owd_n,
    count()                                                 AS seconds
FROM buffmon.probe_second AS s
GROUP BY minute, probe_id, session;
