# buffmon

End-user network experience monitoring for EdgeConnect SD-WAN + HPE SSE
environments. Synthetic probes are the primary real-time signal; EdgeConnect
flow data, UXI, SSE experience data and passive TCP analysis join in later
phases and are correlated through a time-aware identity graph.

**Status: Phase 1** — site probes, reflectors, ingest, storage and the live
dashboard. Design and roadmap: [docs/DESIGN.md](docs/DESIGN.md).

```
 branch site probe ──STAMP UDP 862──▶ reflector (DC / cloud)
   (Rust, Linux)   ──ICMP / TCP────▶ gateway, EdgeConnect LAN, SaaS via SSE
        │
        │ HTTPS, 1-second records (docs/PROBE-RECORD.md)
        ▼
   ingest service ──▶ live hub ──WebSocket──▶ dashboard (seconds)
   (Python)       └─▶ ClickHouse 25.8: probe_second ─▶ probe_minute (history)
```

## What Phase 1 measures

| Probe | What it tells you | Notes |
|---|---|---|
| **STAMP** (RFC 8762) to a buffmon reflector | Loss (with forward/return split), RTT, per-direction jitter (IPDV), one-way delay when both clocks are synced, hop-count changes in both directions | DSCP-marked per app class so it rides the same EdgeConnect overlay as the traffic it stands for |
| **ICMP echo** | Reachability of gateway / EdgeConnect LAN | Labelled reachability, not quality (ICMP is rate-limited and deprioritised) |
| **TCP connect** | Service reachability and handshake time through the SSE path | Failures classified: timeout, refused, unreachable, dns |

Loss is always shown with its 95% upper bound, because a few hundred packets
cannot prove less than ~1% loss. Health is per segment and app class
(`services/thresholds.yaml`), not one opaque score.

## Repository map

```
docs/DESIGN.md          decisions, segment model, architecture, phases, lab prerequisites
docs/PROBE-RECORD.md    probe → ingest wire contract
probe/                  Rust: buffmon-probe, buffmon-reflector, examples/impair (lab loss relay)
services/               Python: ingest API, live hub, ClickHouse writer, dashboard, tools
deploy/                 systemd units, example configs, ClickHouse schema, docker compose
```

## Quick start (lab)

```bash
# 1. Storage + ingest/dashboard (see deploy/docker-compose.yml for secrets setup)
cd deploy && cp .env.example .env && $EDITOR .env && docker compose up -d --build

# 2. A reflector in the DC (or a cloud VM)
cd probe && cargo build --release
sudo install -m 0755 target/release/buffmon-reflector /usr/local/bin/
sudo install -D -m 0644 ../deploy/reflector.example.toml /etc/buffmon/reflector.toml   # edit allow = [...]
sudo install -m 0644 ../deploy/systemd/buffmon-reflector.service /etc/systemd/system/
sudo systemctl enable --now buffmon-reflector

# 3. A probe at the branch
buffmon-mint-token probe --probe-id sjc-br01-p1 --tokens-file <server tokens file>   # prints the token once
sudo install -m 0755 target/release/buffmon-probe /usr/local/bin/
sudo install -D -m 0644 ../deploy/probe.example.toml /etc/buffmon/probe.toml          # edit targets
sudo install -m 0600 /dev/stdin /etc/buffmon/probe-token <<< '<token>'
sudo install -m 0644 ../deploy/systemd/buffmon-probe.service /etc/systemd/system/
sudo systemctl enable --now buffmon-probe
```

Then open `http://127.0.0.1:8080` on the server and log in with the token from
`buffmon-mint-token ui`. Without probes, `buffmon-simulate` (dev only, ids
prefixed `sim-`) drives the real ingest API. Details: `services/README.md`.

To demo directional loss without `tc netem`, put the lab relay between a probe
and its reflector: `cargo run --release --example impair -- --listen 0.0.0.0:8621
--to <reflector>:862 --forward-loss 2`.

## Development

```bash
cd probe && cargo test && cargo clippy --all-targets -- -D warnings
cd services && pytest && ruff check buffmon tests && mypy buffmon tests
# storage tests against a real ClickHouse server:
BUFFMON_IT_CLICKHOUSE_URL=http://127.0.0.1:8123 pytest tests/test_integration_clickhouse_server.py
```

## Security posture

- Probe tokens are per probe, stored hashed, bound to the probe id; delivered
  to the probe with systemd `LoadCredential=`, never in a config file.
- Probe runs with `CAP_NET_RAW` only, reflector with `CAP_NET_BIND_SERVICE`
  only; both `DynamicUser`, strict sandboxing.
- Reflector requires a source allowlist, rate-limits per source, bounds its
  tables and never replies larger than the request.
- Dashboard and read APIs require login; put TLS and an identity-aware proxy in
  front before exposing it.
- Every planned integration (Orchestrator, UXI, SSE, ClearPass) is read-only.
