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

{ "probe_id": "sjc-br01-p1", "records": [ <record>, ... ] }
```

- At most 5,000 records and 4 MiB (decompressed) per request.
- The token is bound to one `probe_id`. Every record's `probe_id` must match it.
- `(probe_id, session, ts_ms)` is the idempotency key. Sending a record twice is
  safe; the second copy is counted as a duplicate and dropped.

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
