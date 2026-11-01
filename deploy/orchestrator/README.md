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
- **Alarms** use `POST /alarm/appliance` (rule `alarm-appliance-read` of the
  POST policy, below) with the
  inventory's appliance ids in the body, `view=active`, every minute. LIVE: the
  API's `source` is the affected object (prefix, tunnel, BGP peer), not the
  subsystem the export describes; `type` is the category (SW, TUN, ...); `name`
  is the alarm name. Closure history stays in Orchestrator.
- The tunnel configuration endpoints (`/tunnels2/physical`) return IPsec fields
  including pre-shared keys to any key with read access. The poller never
  calls them, but use a **read-only** API key and treat it as sensitive.

## Ground rules

- **Read-only.** The client sends GET. Any other method raises before a byte
  leaves the host, and a second check runs on every outgoing request. Two
  exceptions, both explicit:
  - the login request you declare in `auth.login` (if your release uses session
    login rather than an API token), sent once per login and never retried;
  - the **POST policy**, `post-allowlist.yaml`: reads that Orchestrator only
    offers as POST. Today exactly one rule, `alarm-appliance-read`
    (`POST /alarm/appliance`, approved by the deployment owner 2026-11-01).
    See "Allowing a new POST" below.
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
export BUFFMON_ORCH_POST_POLICY=/etc/buffmon/orchestrator/post-allowlist.yaml   # if a collector uses POST
buffmon-orch-poll --mapping mapping.9.7.2.yaml --once --dry-run
```

A mapping with an enabled POST collector will not start without the policy.
`--deny-posts` (or `BUFFMON_ORCH_DENY_POSTS=1`) runs it anyway with every POST
collector switched off: the kill switch if a POST is ever in doubt.

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

## Allowing a new POST

Some Orchestrator reads exist only as POST (the query is in the body:
`/alarm/appliance`, `/stats/aggregate/*` for many appliances, `.../getBatch`).
The Orchestrator 10.0 export has 419 POST operations; most change something.
buffmon sends one only when a rule in `post-allowlist.yaml` allows it.

How a rule is enforced:

| Where | What is checked |
|---|---|
| Loading the policy | `effect: read` (the only accepted value); exact path; typed limits on every query parameter and body key; approver, date, `verified_on`; the tripwire (below); the file is not group/world-writable |
| Poller start-up | each POST collector names a rule (`post_rule`), uses the rule's path, sends only allowed keys within limits, and targets a release in the rule's `verified_on`; otherwise the poller exits before any request. The client gets only the rules the mapping uses. The policy's sha256 and each rule in use are logged |
| Before each POST | the request (rendered parameters and body) fits the rule, body size included |
| On the wire | the httpx request hook re-checks the path, query string and body bytes actually being sent; a POST without a rule is refused |

**The tripwire.** A rule's path, spec operationId and spec summary are scanned
for write-sounding words (`acknowledge`, `clear`, `delete`, `note`, `assign`,
`init`, `store`, `increment`, ...), secret-sounding words (`config`, `key`,
`token`, ...) and a missing read verb (`get`, `retrieve`, `list`, ...). Each
flag must be listed under `reviewed_terms`, and nothing else may be. Over the
10.0 export it leaves 53 of 419 POST operations unflagged, all statistics,
state or inventory reads. It is a prompt to look harder, not proof: words cannot
show that a call is read-only. The approval is the control.

**Procedure.**

1. Find the operation in your release's export and read it in the API
   reference. Ask: does it change anything (state, counters, notes,
   acknowledgements), trigger anything on an appliance (tests, pings, syncs), or
   return secrets? If yes to any, stop: it does not belong in buffmon.
2. Draft the rule from the export (the draft deliberately does not load):
   ```bash
   buffmon-orch-policy draft --spec orch-10.x.json --path /stats/aggregate/mos > rule.yaml
   ```
3. Complete it: add `effect: read`; delete every parameter and body key the
   collector does not need and narrow the rest (`enum`, `min`/`max`, `pattern`,
   `max_items`); fill `purpose`, `approved_by`, `approved_on`; copy the
   tripwire flags from the draft header into `reviewed_terms` only after
   confirming each one.
4. Call it against a lab Orchestrator and add that release to `verified_on`.
   A mapping for another release fails start-up until the rule is verified there.
5. Reference it from the mapping collector (`method: POST`, `post_rule: <id>`,
   same `path`).
6. Check, then open a PR with the rule, the mapping change and the check output:
   ```bash
   buffmon-orch-policy check --policy post-allowlist.yaml --spec orch-10.x.json \
       --mapping mapping.10.x.yaml --mapping mapping.9.7.2.yaml
   ```
   `check --spec` also catches drift after an upgrade: a changed summary or
   operationId, a parameter or body key that no longer exists, or an enum or
   limit wider than the spec's.
7. Deploy the file root-owned, mode 0644, and confirm the new sha256 in the
   poller's start-up log.

Removing a rule is a one-line PR; `--deny-posts` stops every POST immediately
without one.
