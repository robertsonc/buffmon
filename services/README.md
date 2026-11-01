# buffmon services (Phase 1)

Ingest API, live hub and dashboard for buffmon site probes. Contract:
`docs/PROBE-RECORD.md`. Design: `docs/DESIGN.md`.

```
probe ──HTTPS──▶ POST /v1/probe/results ──▶ live hub (memory, 15 min) ──WebSocket──▶ dashboard
                                         └─▶ ClickHouse writer (batched, idempotent) ──▶ probe_second ─MV─▶ probe_minute
```

The live path never waits on ClickHouse: if storage is down, the dashboard keeps
updating and `/v1/health` reports `degraded`.

## Run locally

```bash
cd services
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.lock && pip install --no-deps -e . && pip install -e '.[dev]'

mkdir -p dev
buffmon-mint-token ui                       # prints a login token + two env lines
export BUFFMON_UI_TOKEN_SHA256=...  BUFFMON_SESSION_SECRET=...  BUFFMON_COOKIE_SECURE=false
export BUFFMON_PROBE_TOKENS_FILE=dev/probe-tokens.json
export BUFFMON_CLICKHOUSE_URL=http://127.0.0.1:8123 BUFFMON_CLICKHOUSE_USER=buffmon BUFFMON_CLICKHOUSE_PASSWORD=...
# or, live view only:  export BUFFMON_CLICKHOUSE_ENABLED=false
buffmon-ingest                              # http://127.0.0.1:8080

# DEV ONLY: simulated probes through the real API (probe ids start with sim-)
buffmon-simulate --tokens-file dev/probe-tokens.json --probes 4 --backfill-minutes 30 \
  --inject "sim-nyc-br02/dc1-voice:loss=4,dir=fwd,after=60,for=180"
```

Apply the schema to ClickHouse with `clickhouse-client --multiquery < ../deploy/clickhouse/001_schema.sql`,
or use `deploy/docker-compose.yml`, which applies it on first start.

## Probe credentials

```bash
buffmon-mint-token probe --probe-id sjc-br01-p1 --tokens-file /etc/buffmon/probe-tokens.json
```

Prints the token once (hand it to the probe through systemd `LoadCredential=`)
and stores only its SHA-256 in the tokens file. The server re-reads the file
within 5 s. Rotate with `--replace`.

## Configuration (environment, prefix `BUFFMON_`)

| Variable | Default | Notes |
|---|---|---|
| `HOST`, `PORT` | `127.0.0.1`, `8080` | |
| `CLICKHOUSE_URL`, `_USER`, `_PASSWORD`, `_DATABASE` | `http://127.0.0.1:8123`, `default`, empty, `buffmon` | Credentials go in headers |
| `CLICKHOUSE_ENABLED` | `true` | `false` = live view only |
| `PROBE_TOKENS_FILE` | unset (all ingest rejected) | JSON `{probe_id: sha256}` |
| `THRESHOLDS_FILE` | `services/thresholds.yaml` | Per app-class limits |
| `UI_AUTH` | `enabled` | `disabled` for local dev only (logs a warning) |
| `UI_TOKEN_SHA256`, `SESSION_SECRET` | required when `UI_AUTH=enabled` | From `buffmon-mint-token ui` |
| `COOKIE_SECURE` | `true` | `false` only for plain-HTTP lab use |
| `LIVE_RETENTION_S`, `NO_DATA_AFTER_S` | `900`, `10` | |
| `MAX_BODY_BYTES`, `MAX_RECORDS` | 4 MiB, 5000 | Per request (contract) |

## API

| Method | Path | Auth | |
|---|---|---|---|
| POST | `/v1/probe/results` | probe bearer token | Contract in `docs/PROBE-RECORD.md` |
| GET | `/v1/health` | none / UI cookie | `{"status"}` publicly; queue depth, drops, last insert error with login |
| GET | `/v1/sessions` | UI cookie | Current summary of every session |
| GET | `/v1/sessions/{probe_id}/{session}/history?range=1h\|6h\|24h\|7d` | UI cookie | ≤ 6 h from `probe_second`, beyond from `probe_minute` |
| WS | `/v1/live` | UI cookie, same origin | `hello`, `backfill`, then a `snapshot` every second |

## Tests

```bash
pytest                      # unit + API tests
pip install -e '.[integration]' && pytest tests/test_integration_clickhouse.py   # schema + SQL on a real ClickHouse engine (chdb)
ruff check buffmon tests && mypy buffmon
```
