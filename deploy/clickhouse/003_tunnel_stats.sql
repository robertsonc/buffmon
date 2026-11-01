-- buffmon Phase 2: normalized Orchestrator data (ClickHouse 25.8 LTS).
--
-- Written by buffmon-orch-poll from whatever the per-version mapping file
-- (deploy/orchestrator/mapping.*.yaml) maps. Every metric is Nullable: which of
-- them a given Orchestrator release exposes is only known once the mapping has
-- been filled from its Swagger export.
--
-- Idempotency: a re-poll of the same sample produces the same (appliance,
-- tunnel_id, ts) key and collapses on merge; a retried insert carrying the same
-- insert_deduplication_token is dropped immediately.

CREATE DATABASE IF NOT EXISTS buffmon;

CREATE TABLE IF NOT EXISTS buffmon.tunnel_stats
(
    ts                 DateTime64(3, 'UTC'),
    site               LowCardinality(String) DEFAULT '',
    appliance          LowCardinality(String),
    tunnel_id          String,
    tunnel_name        String DEFAULT '',
    overlay            LowCardinality(String) DEFAULT '',
    -- Customer's label for the underlay: INET, MPLS, LTE, ...
    transport          LowCardinality(String) DEFAULT '',
    peer               String DEFAULT '',
    -- overlay (bonded) or underlay (physical) tunnel, as the mapping labels it
    tunnel_kind        LowCardinality(String) DEFAULT '',
    -- Packet counts per sample: additive, so any window's loss % can be
    -- recomputed exactly (averaging per-sample percentages cannot).
    rx_pkts            Nullable(UInt64),
    ohead_rx_pkts      Nullable(UInt64),
    loss_pre_fec_pkts  Nullable(UInt64),
    loss_post_fec_pkts Nullable(UInt64),
    ooo_pre_poc_pkts   Nullable(UInt64),
    ooo_post_poc_pkts  Nullable(UInt64),
    loss_pre_fec_pct   Nullable(Float32),
    loss_post_fec_pct  Nullable(Float32),
    ooo_pre_poc_pct    Nullable(Float32),
    ooo_post_poc_pct   Nullable(Float32),
    latency_ms         Nullable(Float32),
    jitter_ms          Nullable(Float32),
    mos                Nullable(Float32),
    bytes_tx           Nullable(UInt64),
    bytes_rx           Nullable(UInt64),
    orch_version       LowCardinality(String),
    ingested_at        DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(ts)
ORDER BY (appliance, tunnel_id, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
SETTINGS non_replicated_deduplication_window = 1000;

-- One row per alarm state seen; the latest ingest of (appliance, alarm_id, ts,
-- state) wins. Query the current state with argMax(state, ingested_at).
CREATE TABLE IF NOT EXISTS buffmon.alarms
(
    ts            DateTime64(3, 'UTC'),
    alarm_id      String,
    site          LowCardinality(String) DEFAULT '',
    appliance     LowCardinality(String) DEFAULT '',
    severity      LowCardinality(String) DEFAULT '',
    -- alarm category (Orchestrator 10.x: SW, TUN, ...)
    source        LowCardinality(String) DEFAULT '',
    -- alarm name, e.g. "BGP peer down"
    name          String DEFAULT '',
    -- the affected object: a prefix, tunnel, peer address, ...
    object        String DEFAULT '',
    description   String DEFAULT '',
    state         LowCardinality(String) DEFAULT '',
    cleared_ts    Nullable(DateTime64(3, 'UTC')),
    orch_version  LowCardinality(String),
    ingested_at   DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(ts)
ORDER BY (appliance, alarm_id, ts, state)
TTL toDateTime(ts) + INTERVAL 90 DAY
SETTINGS non_replicated_deduplication_window = 1000;
