-- buffmon Phase 2: EdgeConnect IPFIX flow records (ClickHouse 25.8 LTS).
--
-- Written by `buffmon-flows`, which reads goflow2's JSON output, drops records
-- from exporters that are not in sites.yaml, and attaches site / appliance /
-- interface names / transport labels on arrival (docs/DESIGN.md D8).
--
-- Only standard IPFIX information elements (RFC 7011 / IANA) are stored so
-- far. EdgeConnect enterprise-specific elements (overlay, tunnel, application)
-- are added once a capture of the real export confirms their numbers.
--
-- IPv4 addresses are stored as IPv4-mapped IPv6 (::ffff:a.b.c.d), as in
-- probe_second, so IPv6 needs no schema change.

-- Every accepted flow record. Raw, short retention: it is the evidence behind
-- the rollups and the path view, not the long-term store.
CREATE TABLE IF NOT EXISTS buffmon.flows
(
    ts_start              DateTime64(3, 'UTC'),
    ts_end                DateTime64(3, 'UTC'),
    received_at           DateTime64(3, 'UTC'),
    exporter              IPv6,
    observation_domain_id UInt32,
    flow_type             LowCardinality(String),   -- IPFIX / NETFLOW_V9 / ...
    site                  LowCardinality(String),
    appliance             LowCardinality(String),
    src_ip                IPv6,
    dst_ip                IPv6,
    proto                 UInt8,
    src_port              UInt16,
    dst_port              UInt16,
    dscp                  UInt8,                    -- ipClassOfService >> 2
    ecn                   UInt8,                    -- ipClassOfService & 3
    bytes                 UInt64,
    packets               UInt64,
    sampling_rate         UInt32,                   -- 0 or 1 = unsampled
    in_if                 UInt32,
    out_if                UInt32,
    in_if_name            LowCardinality(String),   -- from sites.yaml, '' if unmapped
    out_if_name           LowCardinality(String),
    in_transport          LowCardinality(String),   -- customer label, e.g. INET / MPLS / LTE
    out_transport         LowCardinality(String),
    ingested_at           DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts_end)
ORDER BY (site, appliance, ts_end)
TTL toDateTime(ts_end) + INTERVAL 7 DAY
SETTINGS non_replicated_deduplication_window = 1000;

-- Flows of probe sessions only (UDP to/from a reflector port listed in
-- sites.yaml `probe_ports`), kept longer and ordered for 5-tuple lookups: this
-- is what answers "which appliance, interface and DSCP did this probe really use?"
CREATE TABLE IF NOT EXISTS buffmon.probe_flows
(
    ts_start      DateTime64(3, 'UTC'),
    ts_end        DateTime64(3, 'UTC'),
    exporter      IPv6,
    site          LowCardinality(String),
    appliance     LowCardinality(String),
    src_ip        IPv6,
    src_port      UInt16,
    dst_ip        IPv6,
    dst_port      UInt16,
    proto         UInt8,
    dscp          UInt8,
    bytes         UInt64,
    packets       UInt64,
    in_if         UInt32,
    out_if        UInt32,
    in_if_name    LowCardinality(String),
    out_if_name   LowCardinality(String),
    in_transport  LowCardinality(String),
    out_transport LowCardinality(String),
    ingested_at   DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts_end)
ORDER BY (src_ip, src_port, dst_ip, dst_port, ts_end)
TTL toDateTime(ts_end) + INTERVAL 30 DAY
SETTINGS non_replicated_deduplication_window = 1000;

-- Traffic context per appliance / egress interface / DSCP / protocol / minute.
CREATE TABLE IF NOT EXISTS buffmon.flow_minute
(
    minute        DateTime('UTC'),
    site          LowCardinality(String),
    appliance     LowCardinality(String),
    out_if        UInt32,
    out_if_name   LowCardinality(String),
    out_transport LowCardinality(String),
    dscp          UInt8,
    proto         UInt8,
    flows         UInt64,
    bytes         UInt64,
    packets       UInt64
)
ENGINE = SummingMergeTree((flows, bytes, packets))
PARTITION BY toYYYYMM(minute)
ORDER BY (site, appliance, out_if, out_if_name, out_transport, dscp, proto, minute)
TTL minute + INTERVAL 400 DAY
-- Same retry rule as probe_minute: inserts set
-- deduplicate_blocks_in_dependent_materialized_views = 1 (default 0 on 25.8).
SETTINGS non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS buffmon.flow_minute_mv
TO buffmon.flow_minute
AS SELECT
    toStartOfMinute(ts_end) AS minute,
    site,
    appliance,
    out_if,
    out_if_name,
    out_transport,
    dscp,
    proto,
    count() AS flows,
    -- Scale sampled exports back to estimated totals.
    sum(bytes * greatest(sampling_rate, 1)) AS bytes,
    sum(packets * greatest(sampling_rate, 1)) AS packets
FROM buffmon.flows
GROUP BY minute, site, appliance, out_if, out_if_name, out_transport, dscp, proto;
