# Orchestrator integration (Phase 2)

buffmon reads EdgeConnect tunnel health and alarms from Orchestrator so the
dashboard can show **underlay loss before FEC** next to **the loss users
actually got** (the probes). This directory holds one mapping file per
Orchestrator release:

| File | Release | State |
|---|---|---|
| `mapping.9.7.2.yaml` | 9.7.2 | empty: every collector disabled, every vendor value null (no export yet) |
| `mapping.10.x.yaml`  | 10.x  | **filled and verified** against Orchestrator 10.0.0.40724 (see below) |

## Verified on Orchestrator 10.0.0.40724 (2026-11-01)

Filled from that release's OpenAPI export, then checked with read-only GETs
against a lab Orchestrator managing six EdgeConnect 9.7.2 appliances. Where the
live API disagreed with the export, the mapping follows the live API:

| Topic | Export says | Live behaviour |
|---|---|---|
| Authentication | no securityScheme; samples mix `X-AUTH-TOKEN`, `X-API-Key`, `Authorization: Bearer` | `X-Auth-Token: <API key>` works |
| `GET /stats/aggregate/tunnel` time range | epoch **milliseconds** | epoch **seconds** (milliseconds return `{}`) |
| `GET /stats/timeseries/tunnel` `data` | object keyed by appliance | a plain list of rows |
| `GET /stats3/timeseries/tunnel` `column_def` | names with trailing commas (in the example) | yes, really: `"TIMESTAMP,"` |
| `GET /tunnels2/physical?nePk=` | `{nePk: {tunnelId: …}}` | `{tunnelId: …}` when `nePk` is given |
| `mos` in aggregate tunnel stats | — | MOS × 100 (439 = 4.39) |
| `avg_mos_prefec` | MOS 1.0–5.0 | implausible values on idle tunnels; not used |

Choices in the 10.x mapping:

- **Tunnel stats** come from `GET /stats/aggregate/tunnel` (one call per
  appliance returns every overlay and underlay tunnel), polled in exact
  one-minute buckets with a two-minute lag and the last three buckets re-polled
  each cycle, so late statistics replace earlier rows instead of being missed.
  Cost: 3 calls per appliance per minute.
- `bondedTunnel_*` are **overlay** tunnels (overlay name from `overlayid`, via
  `GET /gms/overlays/config`; add your overlays to the `map`); `tunnel_*` are
  **underlay** tunnels (local WAN label parsed from the alias).
- Loss is stored as **packet counts** before and after FEC (additive) and as
  Orchestrator's per-minute percentage. The percentage scale is the export's
  ("Packet loss percentage"); the lab had no loss to confirm it against.
- **Alarms** use `GET /alarm/correlatedAlarms` (root-cause view). The full
  per-appliance alarm list is `POST /alarm/appliance`, which this read-only
  client will not send.
- The tunnel configuration endpoints (`/tunnels2/physical`) return IPsec fields
  including pre-shared keys to any key with read access. The poller never
  calls them, but use a **read-only** API key and treat it as sensitive.

## Ground rules

- **Read-only.** The client can only send GET. Any other method raises before
  a byte leaves the host, and a second check runs on every outgoing request.
  The one exception is the login request you declare in `auth.login` (if your
  release uses session login rather than an API token); it is sent once per
  login and never retried.
- **Nothing is guessed.** No endpoint path, query parameter, header name or
  response field is built into the code. They come from your Orchestrator's own
  Swagger/OpenAPI export, release by release.
- **Unmapped means NULL.** A metric your release does not expose stays NULL in
  ClickHouse; it is never reported as 0.

## 1. Export the API description from each release

Download the Swagger/OpenAPI document (JSON or YAML) from your Orchestrator's
API documentation page. Where that page lives, and whether the download is one
file or several, varies by release; your Orchestrator's documentation for that
release is the authority. Do it once per release you run (9.7.2 and 10.x).

## 2. Find the endpoints

```bash
buffmon-orch-discover orch-9.7.2.json                     # GET operations matching tunnel/overlay/stats/alarm/…
buffmon-orch-discover orch-9.7.2.json -k tunnel -k fec    # your own keywords
buffmon-orch-discover orch-9.7.2.json --show <path>       # every response field of one path
buffmon-orch-discover orch-9.7.2.json --diff orch-10.x.json   # what changed between releases
buffmon-orch-discover orch-9.7.2.json --json > ops.json   # machine-readable
```

The tool only reads the file. It resolves `$ref`, merges `allOf`, lists
`oneOf`/`anyOf` variants, and flags circular or unresolved references instead
of failing. Response fields are shown as dotted paths: `[]` is a list element,
`{*}` is the value of a free-form map (an object keyed by, say, tunnel id).

For each collector you want, note:

- the GET path, and whether it is per appliance (then use `fan_out: appliances`
  and a `{appliance_id}`/`{hostname}`/`{site}` placeholder);
- where the list of records sits in the response (`records`);
- which response field holds each normalized value, and its unit;
- the authentication scheme (`securityDefinitions` / `components.securitySchemes`).

## 3. Fill the mapping

Edit `mapping.<release>.yaml`: set `auth`, then a collector's `path`, `records`
and `fields`, and `enabled: true`. Field paths are relative to one record; `$key`
(the record's key when records are an object), `$parent.x` (with `expand`),
`$ctx.x` (the inventory row in a fan-out) and `$now` are also available.
Conversions: `us_to_ms`, `s_to_ms`, `fraction_to_pct`, `epoch_s`/`epoch_ms`/
`epoch_us`/`iso8601` for timestamps, plus `scale`, `map` (e.g. WAN label → the
customer's `INET`/`MPLS`/`LTE`) and `default`.

Loading a mapping with an enabled but incomplete collector fails and lists
every missing piece.

## 4. Dry run against the real Orchestrator

```bash
export BUFFMON_ORCH_URL=https://<orchestrator>
export BUFFMON_ORCH_TOKEN_FILE=/etc/buffmon/orch-token        # chmod 600; for auth.mode: header
# or BUFFMON_ORCH_USERNAME + BUFFMON_ORCH_PASSWORD_FILE         # for auth.mode: login
export BUFFMON_ORCH_CA_BUNDLE=/etc/buffmon/orch-ca.pem         # if Orchestrator uses a private CA
buffmon-orch-poll --mapping mapping.9.7.2.yaml --once --dry-run
```

`--dry-run` prints normalized rows as JSON lines and writes nothing. Check
them against what the Orchestrator UI shows for the same tunnels, especially
units (fraction vs percent, µs vs ms) and the pre-/post-FEC pairing. Records
missing a required field are skipped and reported, never half-written.

Use a read-only Orchestrator account for buffmon: the client is read-only by
construction, and the account should be too.

## 5. Enable writes

Apply `deploy/clickhouse/003_tunnel_stats.sql`, then run without `--dry-run`
(add `--once` for a single pass, omit it to poll on each collector's
`interval_s`). Re-polling the same sample is idempotent: rows are keyed by
(appliance, tunnel_id, ts) and collapse on merge; a retried insert is dropped
immediately by its dedup token.
