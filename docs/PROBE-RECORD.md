# Probe record format (v1)

The contract between `buffmon-probe` and the ingest service. One record per
(probe, session, 1-second bucket). The bucket is assigned by the **send** time of
each packet, so a record describes the packets sent in that second.

## Transport

```
POST /v1/probe/results
authorization: Bearer <probe token>
content-type: application/json
content-encoding: gzip            (optional)

{ "probe_id": "sjc-br01-p1", "records": [ <record>, ... ],
  "routes": [ <route>, ... ],        (optional, Phase 3)
  "capacity": [ <capacity>, ... ] }  (optional, Phase 3)
```

`routes` and `capacity` are omitted when empty, so a batch of records alone has
exactly the v1 shape. An ingest service that predates them ignores them.

- At most 5,000 records and 4 MiB (decompressed) per request.
- The token is bound to one `probe_id`. Every record's `probe_id` must match it.
- `(probe_id, session, ts_ms)` is the idempotency key, separately for records,
  routes and capacity results. Sending one twice is safe; the second copy is
  counted as a duplicate and dropped.

Responses:

| Status | Meaning | Probe action |
|---|---|---|
| 200 | `{"accepted": n, "duplicates": n, "rejected": n, "errors": [...]}` | Delete the batch. Rejected records are logged, not retried. |
| 400 | Body unusable (not JSON, wrong shape) | Drop the batch, log it |
| 401 / 403 | Token missing, unknown, or not allowed for this probe_id | Keep the batch, back off, log loudly |
| 413 | Too large | Split the batch and retry |
| 429 / 5xx / network error | Transient | Keep the batch, retry with exponential backoff (1 s → 60 s) |

## Record

```json
{
  "v": 1,
  "probe_id": "sjc-br01-p1",
  "site": "SJC-BR01",
  "session": "dc1-voice",
  "kind": "stamp",
  "app_class": "voice",
  "dscp": 46,
  "src": "10.1.1.10:40001",
  "dst": "10.10.0.20:862",
  "ts_ms": 1761955200000,
  "interval_ms": 1000,
  "sent": 10,
  "received": 10,
  "lost": 0,
  "late": 0,
  "dup": 0,
  "reordered": 0,
  "fwd_lost": 0,
  "back_lost": 0,
  "rtt_us": [21450, 21388, 21502, 21410, 21399, 21471, 21420, 21455, 21390, 21433],
  "rtt_jitter_sum_us": 412,
  "rtt_jitter_n": 9,
  "ipdv_fwd_sum_us": 180,
  "ipdv_fwd_n": 9,
  "ipdv_back_sum_us": 233,
  "ipdv_back_n": 9,
  "owd_fwd_sum_us": null,
  "owd_back_sum_us": null,
  "owd_n": 0,
  "clock_synced": false,
  "clock_err_us": null,
  "ttl_fwd": 61,
  "ttl_back": 61,
  "rx_ts": "kernel",
  "errors": {}
}
```

| Field | Type | Notes |
|---|---|---|
| `v` | int | Record version, `1` |
| `probe_id` | string ≤ 64, `[A-Za-z0-9._-]` | Must match the token |
| `site` | string ≤ 64 | Site name as used in Orchestrator / Central |
| `session` | string ≤ 64, `[A-Za-z0-9._-]` | Unique per probe |
| `kind` | `stamp` \| `icmp` \| `tcp` | |
| `app_class` | string ≤ 32 | Selects thresholds, e.g. `voice`, `video`, `interactive`, `bulk` |
| `dscp` | int 0–63 | DSCP the probe marked |
| `src`, `dst` | `ip:port` | IPv4 in Phase 1. ICMP uses port 0. Stable per session (for IPFIX matching) |
| `ts_ms` | int | Start of the bucket, epoch ms, multiple of `interval_ms` |
| `interval_ms` | int | 1000 in Phase 1 |
| `sent` | int | Packets (or connect attempts) sent in the bucket |
| `received` | int | Replies received within the timeout |
| `lost` | int | No reply within the timeout. `sent = received + lost` |
| `late` | int | Replies that arrived after being declared lost (not in `received`) |
| `dup` | int | Duplicate replies |
| `reordered` | int | Replies with a sequence number below the highest already received |
| `fwd_lost`, `back_lost` | int \| null | STAMP with a stateful reflector only |
| `rtt_us` | int[] | Every RTT sample in µs, in send order. Length = `received` |
| `rtt_jitter_sum_us`, `rtt_jitter_n` | int | Σ\|RTTᵢ − RTTᵢ₋₁\| over consecutive received packets, and the pair count |
| `ipdv_fwd_sum_us`, `ipdv_fwd_n` | int | Σ\|forward IPDV\| (STAMP only; 0/0 otherwise) |
| `ipdv_back_sum_us`, `ipdv_back_n` | int | Σ\|return IPDV\| (STAMP only; 0/0 otherwise) |
| `owd_fwd_sum_us`, `owd_back_sum_us` | int \| null | Sum of one-way delays; only when `clock_synced` |
| `owd_n` | int | Samples in the one-way sums |
| `clock_synced` | bool | Both ends reported a synchronised clock |
| `clock_err_us` | int \| null | Combined error estimate of both clocks, µs |
| `ttl_fwd` | int \| null | IP TTL of the probe packet as seen by the reflector (last in bucket) |
| `ttl_back` | int \| null | IP TTL of the reply as seen by the probe (last in bucket) |
| `rx_ts` | `kernel` \| `user` | Source of the receive timestamp |
| `errors` | object | Failure reasons → counts, e.g. `{"timeout": 2, "refused": 1}` |

Pairs that straddle two buckets (jitter, IPDV) are counted in the later bucket.

## Route (Phase 3)

One forward route trace of a STAMP session: a Paris traceroute sent from the
session's own socket, so the 5-tuple and DSCP are the probes'. Emitted at start,
every `trace.interval_s` (default 300 s), and within a second or two of the
STAMP TTLs changing.

```json
{
  "v": 1, "probe_id": "sjc-br01-p1", "site": "SJC-BR01", "session": "dc1-voice",
  "kind": "route", "app_class": "voice", "dscp": 46,
  "src": "10.1.1.10:40001", "dst": "10.10.0.20:862",
  "ts_ms": 1761955230123, "duration_ms": 12, "trigger": "ttl_change",
  "ttl_fwd": 60, "ttl_back": 61, "hop_count_fwd": 4,
  "hops": [
    {"ttl": 1, "addrs": ["10.1.1.1"], "rtt_us": 310, "sent": 3, "replies": 3},
    {"ttl": 2, "addrs": ["192.0.2.6"], "rtt_us": 8120, "sent": 3, "replies": 3},
    {"ttl": 3, "addrs": [], "rtt_us": null, "sent": 3, "replies": 0},
    {"ttl": 4, "addrs": ["10.10.0.1"], "rtt_us": 20950, "sent": 3, "replies": 2}
  ],
  "complete": false, "multipath": false,
  "signature": "10.1.1.1>192.0.2.6>*>10.10.0.1",
  "changed": true, "change_ttl": 2, "change_reason": "hop",
  "prev_signature": "10.1.1.1>192.0.2.2>10.10.0.1"
}
```

| Field | Type | Notes |
|---|---|---|
| `kind` | `route` | |
| `ts_ms` | int | Trace start, epoch ms (not bucket-aligned) |
| `duration_ms` | int | |
| `trigger` | `start` \| `schedule` \| `ttl_change` | `ttl_change`: the forward or return TTL of the STAMP replies moved |
| `ttl_fwd`, `ttl_back` | int \| null | TTLs the session saw when the trace started |
| `hop_count_fwd` | int \| null | Routers between probe and reflector: sent TTL − `ttl_fwd`. Traces stop there |
| `hops[].ttl` | int | 1… |
| `hops[].addrs` | string[] | Routers that answered for this TTL, sorted. Empty: none did (ICMP filtered or rate-limited). More than one: per-packet load balancing, or the path moved mid-trace |
| `hops[].rtt_us` | int \| null | Lowest RTT over the replies |
| `hops[].sent`, `hops[].replies` | int | Probes sent for this TTL (one per round) and replies |
| `hops[].unreachable` | int | Present when the hop answered ICMP Destination Unreachable (its code); the path ends there |
| `complete` | bool | Every TTL up to `hop_count_fwd` answered |
| `multipath` | bool | Some TTL answered from more than one address |
| `signature` | string | Hops joined by `>`, addresses of one hop by `\|`, `*` for silence |
| `changed` | bool | Differs from the path known before: a TTL where routers answered both times and none match, or another `hop_count_fwd`. Silent hops never count |
| `change_ttl` | int \| null | First TTL with all-new routers |
| `change_reason` | `hop` \| `length` \| null | |
| `prev_signature` | string \| null | The path before the change |

Forward path only: a traceroute cannot show return hops. Return-path changes
show as a change in `ttl_back`, which triggers a trace.

## Capacity (Phase 3)

Forward bottleneck capacity from packet-train dispersion, for STAMP sessions
with `[stamp.capacity] enabled = true` (off by default). Trains run on their own
socket (a separate STAMP session on the reflector) with the session's
destination and, unless overridden, its DSCP.

```json
{
  "v": 1, "probe_id": "sjc-br01-p1", "site": "SJC-BR01", "session": "dc1-voice",
  "kind": "capacity", "app_class": "voice", "dscp": 0,
  "src": "10.1.1.10:45122", "dst": "10.10.0.20:862",
  "ts_ms": 1761955290000, "packets": 64, "size": 1200, "trains": 5, "valid_trains": 5,
  "fwd_bps": 9950000, "fwd_bps_min": 9870000, "fwd_bps_max": 10060000,
  "fwd_adr_bps": 25470000, "burst_trains": 5, "burst_bytes": 47296,
  "back_bps": 7930000, "back_is_lower_bound": false, "back_method": "reflected_train",
  "back_trains": 5, "back_valid_trains": 5, "back_bps_min": 7890000, "back_bps_max": 7930000,
  "back_burst_bytes": 8045,
  "lost": 0, "invalid": {}
}
```

| Field | Type | Notes |
|---|---|---|
| `kind` | `capacity` | |
| `ts_ms` | int | Measurement start, epoch ms |
| `dscp`, `src` | | Of the train socket (may differ from the session's) |
| `packets`, `size` | int | Packets per train, STAMP size in octets |
| `trains`, `valid_trains` | int | Sent / usable |
| `fwd_bps` | int \| null | Median sustained forward rate, bit/s at the IP layer (size + 28 octets per packet). From the tail of each train, so a shaper's burst allowance does not inflate it |
| `fwd_bps_min`, `fwd_bps_max` | int \| null | Spread over valid trains |
| `fwd_adr_bps` | int \| null | Median whole-train dispersion rate. Above `fwd_bps` when a burst got through first |
| `burst_trains`, `burst_bytes` | int, int \| null | Trains whose head passed faster than the sustained rate, and the median octets that did |
| `back_bps` | int \| null | Return rate |
| `back_is_lower_bound` | bool | The return path did not re-space the train, so `back_bps` is a floor, not a measurement |
| `back_method` | `forward_train` \| `reflected_train` | `reflected_train`: measured with RFC 10052 return trains (`return_trains = true`, authenticated session). Absent from older probes = `forward_train` |
| `back_trains`, `back_valid_trains` | int | RFC 10052 return trains requested / usable |
| `back_bps_min`, `back_bps_max`, `back_burst_bytes` | int \| null | Spread over return trains, and the return shaper's burst |
| `lost` | int | Train packets without a reply |
| `invalid` | object | Discarded trains by reason: `too_few`, `reordered`, `no_spread`, `sender_limited`; return trains as `back_too_few`, `back_reordered`, `back_no_spread`, `back_reflector_limited`; RFC 10052 requests as `back_not_processed` (U: reflector does not do it for this session), `back_refused` (C: a limit), `back_no_reply` |

