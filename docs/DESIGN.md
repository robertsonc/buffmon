# buffmon — design (v0.1)

End-user network experience monitoring for HPE Aruba Networking EdgeConnect
SD-WAN + HPE SSE environments and campus LAN/WLAN fabrics. Synthetic probes are
the primary real-time signal; EdgeConnect, UXI, SSE and passive TCP analysis
explain *where* and *why*.

Status: Phases 1-3 are implemented in this repository (see §10). Later phases
are design only.

## 1. Goals and non-goals

**Goals**

- A live view (seconds) of loss, latency and jitter per site and per application
  class, from probes that ride the same path as the user traffic they represent.
- Fault localisation by segment: client/Wi-Fi → access → branch edge → underlay
  → overlay → DC or SSE PoP → application.
- Near-real-time (about 1 min) traffic context from EdgeConnect: which overlay and
  transport carried which flows, underlay loss before FEC against what users got.
- Analytic views (5–15 min): good vs bad TCP sessions over time, UXI, SSE
  experience data, all joined to the same sites, devices and users.
- The same probes and views across two kinds of deployment: SD-WAN fabrics
  (EdgeConnect overlays, SSE) and campus fabrics (wired and wireless, including
  EVPN-VXLAN). Measurements run across both, and often across one into the other.

**Non-goals (for now)**

- A single opaque "experience score". Health is shown per segment and per app
  class, as threshold compliance plus session good/bad ratios. An exec roll-up
  may come later and must always drill down to a segment and a metric.
- Writes to any network device. Every integration is read-only.

## 2. Decisions that shape everything else

| # | Decision | Why |
|---|---|---|
| D1 | **Probes must follow the user's path.** Every probe session has an app class, a DSCP mark and a stable source port. In Phase 2 the probe's own IPFIX record is used to confirm which overlay and transport it actually took. | EdgeConnect steers by business-intent overlay (app/DSCP/ACL). A probe on the wrong overlay measures a path nobody uses. |
| D2 | **Loss is reported with its sample count and a 95% upper bound** (Wilson score interval). Real-time loss uses 10 s and 30 s rolling windows. | With zero losses in *n* packets the Wilson 95% bound is ≈3.84/*n* (the rule of three gives ≈3/*n*). Showing <1% takes about 380 packets: voice/video sessions run at 20 pps (600 per 30 s, bound ≈0.64%). At 10 pps the bound never drops below 1.26% and the status stays "insufficient samples". |
| D3 | **STAMP (RFC 8762), stateful reflector, is the quality probe.** ICMP is for reachability and topology only. TCP connect is for service reachability and handshake time. | ICMP is rate-limited and deprioritised by control-plane policing (SRX/MX/CX, cloud). Per-hop ICMP numbers are artefacts. |
| D4 | **Direction matters.** The stateful reflector's counter splits loss into forward and return. IPDV (RFC 3393/5481) is computed per direction; clock offset cancels out. One-way delay is reported only when both ends say they are synchronised, together with the combined error bound. | SD-WAN paths are frequently asymmetric. "Which direction" halves the search. |
| D5 | **The reflector reflects the DSCP and the packet size** it received. | So the return path is classified like the forward path, and there is no amplification. |
| D6 | **TTL is tracked in both directions** (reflector reports the TTL it saw; the probe reads the reply's TTL). | A cheap path-change detector at 1 s resolution. |
| D7 | **Packet-train dispersion is a periodic capacity *estimate*,** run from wired site probes to our own reflectors, kept out of the health status until validated. | Dispersion is distorted by Wi-Fi contention/aggregation, shapers and policers, EdgeConnect FEC/POC/shaping, and host interrupt coalescing. |
| D8 | **Correlation goes through a time-aware identity graph,** never through MAC or IP alone. Join key: (site, VRF/segment, IP, time window) → MAC → device → user. Identity is attached when data arrives, not at query time. | EdgeConnect and SSE never see client MACs; MACs are randomised; IPs churn and overlap across sites and VRFs. |
| D9 | **UXI is a control group,** joined by site / AP / BSSID / SSID / test target, never by user. | UXI fine + users bad on the same AP → client side. Both bad → infrastructure. |
| D10 | **Passive TCP analysis needs care in where it captures.** EdgeConnect TCP acceleration terminates TCP on the appliance; SSE agents encapsulate; QUIC has no TCP signals; asymmetric paths give a SPAN half a conversation. Sensors go where traffic is not proxied or tunnelled, and each session verdict records where it was observed. | Otherwise "retransmissions" describe the LAN leg only. |
| D11 | **STAMP for the real-time signal, not pathchar-style per-hop characterisation** (pathchar, pchar, clink). Path characterisation is a Paris traceroute on the session's own flow plus end-to-end packet trains timed at our reflector (§5). | pathchar estimates each hop's raw link rate from RTT-versus-size slopes of ICMP Time Exceeded replies. Overlays (EdgeConnect, EVPN-VXLAN, MPLS without TTL propagation) hide the hops that matter; control-plane ICMP jitter (100s of µs to ms) swamps serialisation differences on fast links (1500 B vs 64 B at 1 Gbit/s is ~11.5 µs); it measures raw link rate, not the shaped rate users get; it is round-trip only and takes minutes and thousands of packets per hop. What it gives up: naming *which* hop is the bottleneck; localisation comes from combining route changes, underlay stats and capacity instead. |
| D12 | **Authenticated STAMP** (RFC 8762 authenticated mode, RFC 8972 HMAC TLV) for every session that uses an extension which makes a reflector send more than it received. Keys are per session (SSID), provisioned out of band; the reflector decides the mode per source prefix and refuses packets that fail HMAC. | A source allowlist does not stop a spoofed source inside the allowed range from aiming a reflector at a victim. HMAC does (RFC 10052 §5 requires identity protection). |
| D13 | **Return-direction capacity uses RFC 10052 reflected trains:** one small authenticated request, the reflector sends the train back. Off by default on the reflector; per-session rate and volume limits; non-increasing sequence numbers get a single reply (replay); probes start with a 1-packet request. | Downstream is the direction branch users feel, and trains sent from the probe can only give a floor for it (the reflector echoes their spacing). RFC 10052 measures it directly with almost no upstream load (LTE and broadband uplinks). |
| D14 | **Intrusive speed tests use RFC 9946 (UDPSTP, RFC 9097 Maximum IP-Layer Capacity) and are not monitoring:** on demand or in a maintenance window, off by default, never in a priority DSCP, with a rate cap, one test per appliance/overlay at a time, scheduled by the collector. Results record what was measured. | A test fills the path for up to ~10 s. Through an overlay it measures the capacity EdgeConnect gives that traffic class (shaping, QoS, FEC overhead, bonding), with production traffic present, not the circuit. A circuit test needs the test flow to bypass the overlay: an EdgeConnect policy change, outside buffmon's read-only scope. Two probes behind one appliance testing at once measure each other. |
| D15 | **Campus and WLAN:** wireless probes carry radio context (RSSI, noise, MCS, band, channel, BSSID) on every result; route traces in EVPN-VXLAN fabrics show gateways only; underlay visibility inside a fabric needs AOS-CX / Junos-Mist telemetry. | A Wi-Fi loss or capacity number without radio context cannot be interpreted. The VXLAN source port, and so the spine a flow crosses, is hashed from the inner flow, which is why probes keep a fixed 5-tuple (D1). |

## 3. Segment model

```mermaid
flowchart LR
  C[Client / Wi-Fi] --> A[Access AP / switch] --> E[Branch EdgeConnect]
  E --> U[Underlay transports<br/>INET · MPLS · LTE] --> O[Overlay]
  O --> DC[DC / cloud]
  O --> S[SSE PoP] --> APP[SaaS / app]
  DC --> APP2[Private app]
```

Each segment's evidence:

| Segment | Real-time (probes) | Near-real-time / analytic |
|---|---|---|
| Client / Wi-Fi | — (site probes are wired) | UXI sensor tests, ClearPass/Central client data |
| Access | ICMP to default gateway | AOS-CX / Mist stats (later) |
| Branch edge | ICMP/STAMP to EdgeConnect LAN IP (if allowed) | Orchestrator appliance health |
| Underlay | — (hidden by the overlay) | Orchestrator tunnel stats per transport, pre-FEC loss |
| Overlay | STAMP to DC/cloud reflectors, per app-class DSCP | IPFIX: which overlay/transport each flow used; post-FEC loss |
| SSE PoP | TCP connect to SaaS through SSE | SSE experience/explore data |
| Application | TCP connect / handshake time | Passive TCP session verdicts, SSE app data |

**Localising a fault with nested targets.** Probe the gateway, the EdgeConnect LAN
interface, a DC reflector over the overlay, and a SaaS front door through SSE.
The first target that degrades marks the segment. EdgeConnect underlay statistics
then say whether the overlay problem is an underlay problem.

## 4. Architecture

```mermaid
flowchart LR
  subgraph Site[Branch]
    P[buffmon-probe<br/>STAMP · ICMP · TCP<br/>DSCP-marked, stable 5-tuples]
  end
  subgraph Core[DC / cloud]
    R[buffmon-reflector<br/>STAMP stateful]
  end
  P <-->|UDP 862| R
  P -->|HTTPS batches, 1 s records| I[ingest service]
  I -->|hot path| L[live hub<br/>rolling 10/30/60 s] -->|WebSocket| UI[dashboard]
  I -->|batched, idempotent| CH[(ClickHouse<br/>probe_second · probe_minute)]
  CH --> UI
  EC[EdgeConnect] -.->|IPFIX · P2| GF[goflow2] -.-> RP[(Redpanda)] -.-> CH
  ORCH[Orchestrator 9.7.2 / 10.x] -.->|REST · P2| PL[pollers] -.-> RP
  UXI[UXI] -.-> PL
  SSE[HPE SSE] -.-> PL
  IDS[ClearPass · DHCP · Central] -.-> IG[(identity graph · P4)] -.-> I
```

Dashed = later phases. Phase 1 writes straight from ingest to ClickHouse; the bus
(Redpanda) arrives in Phase 2, when there is more than one producer.

**Stack.** Probe and reflector in Rust: precise pacing, kernel receive
timestamps, raw sockets, no runtime. Services in Python 3.12 (FastAPI). ClickHouse
25.8 LTS for time series and flows. goflow2 for IPFIX (no hand-written flow
collector). Dashboard: dependency-free HTML/JS served by the ingest service.

## 5. Probe measurement method (Phase 1)

**STAMP session** (one per target × app class):

- Sender transmits 44-byte unauthenticated STAMP test packets (larger if
  `size` is set) at `pps`, from a fixed source port, with IP TOS = `dscp << 2`.
- T1 = sender transmit time (user space, CLOCK_REALTIME, immediately before
  `send`). T2/T3 = reflector receive/transmit time. T4 = sender receive time from
  the kernel (`SO_TIMESTAMPNS`), falling back to user space and flagged.
- RTT = (T4 − T1) − (T3 − T2): reflector dwell time removed.
- Forward IPDV between consecutive replies i, j: (T2ⱼ − T1ⱼ) − (T2ᵢ − T1ᵢ).
  Return IPDV: (T4ⱼ − T3ⱼ) − (T4ᵢ − T3ᵢ). Reported as mean |IPDV|.
- One-way delay (T2 − T1, T4 − T3) only when both ends set the STAMP "S" bit
  (from `adjtimex`), with the combined error estimate.
- A packet with no reply after `timeout_ms` (default 2000) is lost. A reply after
  that is counted `late`, never `received`.
- Duplicates and reordering (sequence below the highest seen) are counted.
- Forward/return loss split: the reflector numbers packets per session
  (RFC 8762 stateful mode). Between two replies (s, r) and (s′, r′):
  forward losses = (s′ − s) − (r′ − r). Return losses = total − forward.

**ICMP echo**: raw socket (`CAP_NET_RAW`), falls back to unprivileged datagram
ICMP. Loss and RTT, labelled as reachability.

**TCP connect**: non-blocking connect with timeout, DSCP-marked; RTT from the
kernel's `TCP_INFO` handshake RTT when available. Failures are classified
(timeout, refused, unreachable, dns).

**Records.** Each session emits one record per 1-second bucket, keyed by the
*send* time of the packets in it. A bucket is emitted as soon as its second has
ended and every packet in it is resolved: normally one RTT after the second ends,
up to `timeout` later when a packet is lost, and up to a further 3 s when the
forward/return split is waiting for the next reply. See `docs/PROBE-RECORD.md`
for the wire format.

### Route and capacity (Phase 3)

**Authenticated STAMP** (P3.1, per session): RFC 8762 authenticated mode
(HMAC-SHA-256/128 over the 96-octet base) and the RFC 8972 HMAC TLV over the
extensions. Keys are per SSID, minted with `buffmon-reflector --new-key`; the
reflector picks the mode per source prefix (`authenticated_sources`) and sends
nothing back for a packet that fails. The probe drops replies that fail, so a
forged reply cannot count as received. Packets larger than the base carry an
Extra Padding TLV with pseudorandom content (RFC 8972 §4.1), not zeros: a
compressing WAN optimiser cannot shrink them, and a TLV-aware reflector reads
them correctly.

**Route trace** (every STAMP session, on by default):

- Paris traceroute sent from the STAMP session's **own socket**, so the 5-tuple
  and DSCP are the probes': ECMP hashing and EdgeConnect overlay policy put the
  trace on the same path as the measurement. Only the TTL (per packet, as
  ancillary data) and the payload length differ.
- Payload is 9-40 octets, below STAMP's 44, so a reflector discards trace
  packets and the session's loss accounting never sees them. The UDP length in
  the header a router quotes back identifies the TTL; every router quotes at
  least those 8 octets, and NAT preserves them.
- TTLs 1..*n*, where *n* = sent TTL − the TTL the reflector reports (the
  forward router count); 3 rounds, one probe per router per round (routers
  rate-limit Time Exceeded). Replies on a raw ICMP socket (CAP_NET_RAW).
- Runs at start, every `interval_s` (300 s) and, as a **tripwire**, within
  ~1 s of the STAMP TTLs changing (forward or return; 3 equal replies in a row).
- Change = a TTL where routers answered both times and none of the addresses
  match the ones seen since the last change, or a different router count. A
  silent hop is never a change; per-packet load balancing is absorbed.
- Limits: forward hops only (a return change shows as `ttl_back` moving); an
  EdgeConnect overlay is one hop (the tunnel hides the underlay); a proxy (SSE)
  ends the visible route at the proxy.
- Third-party reflectors: RFC 8762 §4.6 has a STAMP reflector answer a packet
  shorter than the base with a base packet (TWAMP Light interop). Trace packets
  stop at the known router count, so they reach the reflector only while that
  count is unknown or right after the path got shorter. If one reaches a
  third-party stateful reflector, its counter moves by one and that second's
  forward/return split can be off by one packet (buffmon's own reflector
  discards trace packets).

**Capacity** (per STAMP session, off unless enabled):

- `trains` × `packets` back-to-back STAMP packets of `size` octets (`sendmmsg`),
  on a separate socket (its own reflector session), same destination, DSCP
  configurable. The reflector's kernel receive timestamps (T2) give the spacing
  at the far end; only differences of one clock are used, so no sync is needed.
- **Sustained rate** from the median gap after any leading burst: token-bucket
  shapers pass the head of a train at line rate, so whole-train dispersion
  overestimates. The burst is reported separately (octets ahead of the rate).
- Return: the reflector replies as packets arrive, so the return train starts
  spaced like the forward one. Wider on arrival (T4 vs T3) means a narrower
  return bottleneck, measured; otherwise only a floor.
- Return trains (P3.2, RFC 10052, `return_trains = true`): one small
  authenticated request (144 octets) asks the reflector for a back-to-back
  train; the probe times its arrival (T4) against the reflector's send times
  (T3). Same sustained/burst estimator. Each run opens with a 1-packet request
  (RFC 10052 §5). Reflector side: off by default, authenticated sessions with a
  valid HMAC TLV only, per-request packet/volume/MTU limits and a per-source
  average-rate bucket (over a limit: one packet back with C), out-of-order
  requests get one packet with U, trains sent by a worker thread so they never
  delay other sessions' replies. RFC 10052 §3 says the TLV Length "MUST NOT be
  smaller than 12" while its fixed fields are 8 octets of value (RFC 8972
  defines Length as the Value only); we send 8 and accept 8 or more.
- Trains with reordering, > 50% loss, no spread or a sender slower than half
  the arrival spread are discarded; median over the rest; IP-layer bit/s.
- Through EdgeConnect this is the overlay's capacity as the appliance shapes it
  for that DSCP, not the underlay link. Packet order correction and per-packet
  path spraying can re-space trains: `fwd_bps_min`/`max` show when they did.

## 6. Health model

Per session, over rolling windows:

- **Loss**: point estimate and 95% Wilson upper bound over 30 s. If the point
  estimate is within target but the bound is not, the status is
  "insufficient samples", not "good".
- **Latency**: RTT p50/p95 over 10 s and 30 s.
- **Jitter**: mean |IPDV| per direction (STAMP), mean |ΔRTT| otherwise.
- **Status** per app class: `good`, `degraded`, `bad`, `no-data`. Thresholds live
  in `services/thresholds.yaml`. The defaults are starting points: voice/video
  from Microsoft's published Teams network targets (client to Microsoft edge:
  RTT < 100 ms, loss < 1% per 15 s, jitter < 30 ms per 15 s), with ITU-T G.114
  as the outer limit for one-way delay. Tune per customer.

## 7. Correlation keys by source

| Source | Native keys | Joins through |
|---|---|---|
| Site probe | probe_id, site, session 5-tuple, DSCP | site; 5-tuple ↔ IPFIX (P2) |
| EdgeConnect IPFIX | 5-tuple, appliance, overlay/tunnel, app ID (verify per release) | (site, VRF, IP, t) |
| Orchestrator stats | appliance, tunnel, overlay, transport | site, appliance |
| ClearPass / DHCP / Central | MAC, IP, user, AP/NAS, lease or session interval | builds the identity graph |
| HPE SSE | user, device, app, PoP; source IP often NATed | user/device; IP only if pre-NAT IP is present |
| UXI | sensor, site, SSID, BSSID/AP, test target | location and target, never user |
| Passive TCP | 5-tuple, observation point | (site, VRF, IP, t) |

## 8. Storage

- `probe_second`: one row per (probe, session, second). `ReplacingMergeTree`
  ordered by (probe_id, session, ts) so a retried batch cannot double count.
  RTT samples are kept as an array so percentiles over any window are exact.
  30-day TTL.
- `probe_minute`: `AggregatingMergeTree` rollup via materialised view, 400-day
  TTL.
- Duplicates are stopped at three points. (1) Ingest drops records whose key it
  has seen in the last 15 minutes (in memory), which catches probe retries.
  (2) Each ClickHouse insert carries an `insert_deduplication_token` with
  `deduplicate_blocks_in_dependent_materialized_views = 1`, so an ingest → ClickHouse
  retry is applied once to both tables. (3) `probe_second` is a
  `ReplacingMergeTree`, so any duplicate that still lands collapses on merge.
  Known gap: if the ingest service restarts and a probe then re-sends a batch,
  (1) has forgotten it and (2) sees a new block, so `probe_minute` counts it
  twice; `probe_second` is still exact after merge. Bounded by the probe's
  retry window; closing it needs a persistent dedup key store (Phase 2, with
  the bus).

## 9. Security

- Probe → ingest over HTTPS using the OS trust store (enterprise CAs work) with an
  optional explicit proxy. Per-probe bearer tokens, stored hashed on the server,
  bound to the probe_id; a probe cannot write another probe's records.
- Secrets never live in config files: systemd `LoadCredential=` or an env var.
- Probe runs with `CAP_NET_RAW` only; reflector with `CAP_NET_BIND_SERVICE` (port
  862). No root, no `privileged` containers.
- Reflector: source allowlist (required), per-source rate limit, bounded session
  table, reply size equal to request size (no amplification).
- Dashboard and read APIs require a login (token → signed, expiring cookie). Put
  an identity-aware proxy in front for production.
- Every external integration is read-only. Probe traffic on a non-lab network
  needs an explicit go-ahead: packet trains (P3) are bursty by design.
- Orchestrator: GET only, except reads that exist only as POST. Each of those is
  a rule in `deploy/orchestrator/post-allowlist.yaml` (`effect: read` only;
  exact path; typed limits on every parameter and body key; approver and the
  releases it was verified on), enforced before sending and again on the wire.
  No policy, no POST; `--deny-posts` is the kill switch.

## 10. Phases

| Phase | Scope | Done when |
|---|---|---|
| P1 (done) | STAMP sender + stateful reflector, ICMP, TCP; ingest with auth and dedup; ClickHouse; live dashboard; systemd units | In the lab, loss/latency/jitter per site and target reach the dashboard within 5 s; an injected 2% loss (`tc netem`) shows within 30 s, attributed to the right direction |
| P2 (done, 9.7.2 mapping open) | EdgeConnect: IPFIX via goflow2 → ClickHouse; Orchestrator poller for tunnel/overlay stats and alarms, 9.7.2 and 10.x; probe path validation; underlay vs delivered loss | Each probe session shows the appliance and interfaces it actually used; pre-FEC vs post-FEC loss next to probe loss |
| P3 (done, lab-verified) | Path characterisation: Paris-style traceroute with change detection; packet-train capacity estimate | Path changes flagged within one cycle; capacity estimate within ±20% of a known shaped rate on wired lab links |
| P3.1 (done) | Authenticated STAMP (RFC 8762 authenticated mode) and RFC 8972 TLVs (Extra Padding, HMAC) in probe and reflector; per-session keys | Authenticated and unauthenticated sessions run side by side against one reflector; a packet with a bad HMAC or unknown SSID is refused; byte layouts match the RFC figures |
| P3.2 (done, lab-verified) | RFC 10052 return-direction trains: reflector support (off by default, authenticated sessions only, rate and volume limits, replay check) and probe-side return capacity | Return capacity measured, not bounded, within ±20% of a known shaped return rate; limits and the C flag verified |
| P3.3 | RFC 9946 (UDPSTP) speed test as a guarded, on-demand test type, scheduled by the collector (one per appliance/overlay) | Upstream and downstream Maximum IP-Layer Capacity within ±10% of a shaped lab rate; refused without an explicit enable, above the rate cap, in a priority DSCP, or while another test runs behind the same appliance |
| P4 | Identity graph: ClearPass, DHCP, Central/Mist; enrichment on arrival | Any IP at any time resolves to MAC, device and user where the sources know them |
| P5 | UXI and HPE SSE ingestion; segment view; UXI as control group; wireless probes with radio context (D15) | One screen shows, per site, which segment is degraded and the evidence for it |
| P6 | Passive TCP: SPAN sensor where traffic is not proxied or tunnelled; good/bad session % over time; reports | Hourly good-session % per site and app, with the observation point recorded |

### Phase 2 status

- Done: per-target threshold overrides; flow pipeline (standard IPFIX
  elements) with exporter allowlist and probe path validation; Orchestrator
  10.x tunnel stats and alarms, verified against a live 10.0.0.40724
  Orchestrator (`deploy/orchestrator/README.md`); tunnel health on the
  dashboard and next to each probe's path; the POST allowlist and its review
  tool (`buffmon-orch-policy`).
- Deviation: no Redpanda yet. One collector process writes straight to
  ClickHouse with the same batching and dedup guarantees as ingest; the bus
  comes in when there is more than one collector or the flow rate needs it.
- Open: EdgeConnect enterprise IPFIX elements (overlay/tunnel per flow), which
  would tie a probe to its overlay directly instead of via its appliance; the
  9.7.2 mapping; Orchestrator's loss-percentage scale under real loss.

### Phase 3 status

Built and verified in a routed network-namespace lab (`probe/lab/netns.sh`,
acceptance run `probe/lab/verify-p3.sh`): probe → r1 → three alternate paths
→ r3 → reflector, real binaries, Linux tbf shaping on r3 → reflector.

- **Route changes**: a same-length reroute was flagged by the next scheduled
  trace (22 s after the change, 30 s interval); a reroute one hop longer was
  flagged in the same second through the STAMP TTL tripwire. No false changes
  over 10 further traces; the reflector saw 0 trace packets.
- **Capacity** (64 × 1200 B trains, 5 per run; expected = tbf rate × 1228/1242,
  since tbf counts Ethernet framing and the estimate is IP-layer):

  | tbf | expected | sustained estimate | burst, configured → measured | whole-train rate |
  |---|---|---|---|---|
  | 20 Mbit/s, 8 KB | 19.77 | 19.79 | 8192 → 8031 B | 21.66 |
  | 5 Mbit/s, 4 KB | 4.94 | 4.94 | 4096 → 4035 B | 5.13 |
  | 50 Mbit/s, 16 KB | 49.44 | 49.45 | 16384 → 16008 B | 61.23 |
  | 10 Mbit/s, 48 KB | 9.89 | 9.89 | 49152 → 48515 B | 25.47 |
  | return 8 Mbit/s | 7.91 | 7.91 (measured) | | |

- Not verified yet: an EdgeConnect overlay (packet order correction, FEC and
  per-packet path spraying can re-space trains), real routers' ICMP rate
  limiting at scale, and capacity above ~1 Gbit/s (interrupt coalescing makes
  kernel timestamps bunch up).

### Phase 3.1 / 3.2 status

- **P3.1 authenticated STAMP**: byte layouts tested against the RFC 8762 / 8972
  figures and the RFC 4231 HMAC vector; authenticated and unauthenticated
  sessions side by side on one reflector; wrong key or tampered base: no reply;
  tampered extensions: reflected with I; older zero-padded probes still served.
- **P3.2 RFC 10052 return trains** (`probe/lab/verify-return.sh`, authenticated
  session, tbf each way; expected = tbf rate × 1228/1242):

  | forward / return tbf | return expected | return measured | burst, configured → measured |
  |---|---|---|---|
  | 10 / 30 Mbit/s | 29.66 | 29.69 | 16384 → 15786 B |
  | 50 / 8 Mbit/s | 7.91 | 7.91 | 8192 → 8045 B |
  | unshaped / 100 Mbit/s | 98.87 | 98.97 | 32768 → 32076 B |

  In the first row the forward-train method could only report a floor of ~10.
  Limits, C and U flags, replay, count 0 and budget are covered by tests.

## 11. What has to be confirmed in the lab before P2+

Not guessed here; each changes a design detail.

- ~~Orchestrator 10.x: tunnel/overlay statistics endpoints, granularity, loss
  before/after FEC.~~ Confirmed on 10.0.0.40724: per-minute, per tunnel, loss
  and reorder before/after correction, latency, jitter, MOS. Still needed: a
  9.7.2 export (if any Orchestrator still runs 9.7.2).
- EdgeConnect IPFIX: template fields on your ECOS releases (overlay/tunnel ID,
  application, segment/VRF). A short pcap of the export is enough.
- Which sites run TCP acceleration (affects passive TCP placement).
- UXI: data access path (API or export) and fields.
- HPE SSE: what Explore and Experience data can be exported, whether it carries
  the pre-NAT client IP and device ID, and whether the agent tunnels ICMP/UDP.
- ClearPass: RADIUS accounting / Insight / API access for MAC↔IP↔user bindings.
