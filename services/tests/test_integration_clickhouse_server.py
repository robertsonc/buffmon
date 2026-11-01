"""Storage tests against a real ClickHouse *server* over HTTP, through the
production ``HttpTransport``.

The chdb-based tests in test_integration_clickhouse.py run a newer engine
in-process and bypass the HTTP interface. This file covers what they cannot:
the deployed 25.8 LTS server, and the exact HTTP parameters the ingest service
sends. It runs only when a server is named:

    BUFFMON_IT_CLICKHOUSE_URL=http://127.0.0.1:8123 pytest tests/test_integration_clickhouse_server.py

Each test creates (and drops) its own database, so it is safe on a shared lab server.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from buffmon.flows.consumer import FlowConsumer
from buffmon.flows.path import analyse, query_paths
from buffmon.flows.sites import SitesFile
from buffmon.models import ProbeRecord
from buffmon.store import (
    FLOWS_TABLE,
    PROBE_FLOWS_TABLE,
    HttpTransport,
    batch_token,
    content_token,
    query_history,
    record_to_row,
)
from tests.test_flows import PROBE, REFLECTOR, SITES, goflow_line
from tests.test_integration_clickhouse import schema_statements, sim_records

URL = os.environ.get("BUFFMON_IT_CLICKHOUSE_URL")
USER = os.environ.get("BUFFMON_IT_CLICKHOUSE_USER", "default")
PASSWORD = os.environ.get("BUFFMON_IT_CLICKHOUSE_PASSWORD", "")

pytestmark = pytest.mark.skipif(not URL, reason="BUFFMON_IT_CLICKHOUSE_URL not set")

SCHEMA = Path(__file__).resolve().parents[2] / "deploy" / "clickhouse" / "001_schema.sql"


def _admin(sql: str, **params: str) -> str:
    assert URL
    r = httpx.post(
        URL,
        params={f"param_{k}": v for k, v in params.items()},
        content=sql.encode(),
        headers={"X-ClickHouse-User": USER, "X-ClickHouse-Key": PASSWORD},
        timeout=30,
    )
    assert r.status_code == 200, f"{sql[:80]}: {r.text[:300]}"
    return r.text.strip()


@pytest.fixture
def db() -> Iterator[str]:
    name = f"buffmon_it_{secrets.token_hex(4)}"
    for stmt in schema_statements():
        _admin(stmt.replace("buffmon.", f"{name}.").replace("DATABASE IF NOT EXISTS buffmon", f"DATABASE {name}"))
    try:
        yield name
    finally:
        _admin("DROP DATABASE IF EXISTS {db:Identifier}", db=name)


def _transport(db: str) -> HttpTransport:
    assert URL
    return HttpTransport(URL, db, USER, PASSWORD, timeout_s=30)


def test_server_version_is_reported() -> None:
    print("ClickHouse server", _admin("SELECT version()"))


def test_retried_insert_is_applied_once_including_the_rollup(db: str) -> None:
    rows = [record_to_row(ProbeRecord.model_validate(r)) for r in sim_records(2)]
    token = batch_token(rows)

    async def go() -> None:
        t = _transport(db)
        try:
            await t.insert_rows("probe_second", rows, token)
            await t.insert_rows("probe_second", rows, token)  # retry after a timeout
        finally:
            await t.aclose()

    asyncio.run(go())
    assert int(_admin("SELECT count() FROM {db:Identifier}.probe_second", db=db)) == len(rows)
    sent = sum(int(r["sent"]) for r in rows)
    minute_sent = int(_admin("SELECT sum(sent) FROM {db:Identifier}.probe_minute", db=db))
    assert minute_sent == sent, "rollup double counted a retry"


def test_history_queries_run_on_the_server(db: str) -> None:
    recs = sim_records(12, inject="sim-sjc-br01/dc1-voice:loss=5,dir=fwd,after=-300,for=120")
    rows = [record_to_row(ProbeRecord.model_validate(r)) for r in recs]
    now_ms = int(time.time() * 1000)

    async def go() -> tuple[dict, dict]:  # type: ignore[type-arg]
        t = _transport(db)
        try:
            for i in range(0, len(rows), 2000):
                chunk = rows[i : i + 2000]
                await t.insert_rows("probe_second", chunk, batch_token(chunk))
            h1 = await query_history(t, "p1", "dc1-voice", "1h", now_ms)
            h24 = await query_history(t, "p1", "dc1-voice", "24h", now_ms)
            return h1, h24
        finally:
            await t.aclose()

    h1, h24 = asyncio.run(go())
    assert h1["source"] == "probe_second" and len(h1["points"]) >= 70
    assert h24["source"] == "probe_minute" and h24["points"]
    assert sum(p["sent"] for p in h24["points"]) == sum(p["sent"] for p in h1["points"])
    lossy = [p for p in h1["points"] if (p["loss_pct"] or 0) > 2]
    assert lossy
    assert sum(p["fwd_loss_pct"] or 0 for p in lossy) > 5 * sum(p["back_loss_pct"] or 0 for p in lossy)


# -- Phase 2: flows ------------------------------------------------------------------

def _statements(*files: str) -> list[str]:
    out: list[str] = []
    for f in files:
        path = SCHEMA.parent / f
        text = "\n".join(line for line in path.read_text().splitlines() if not line.strip().startswith("--"))
        out += [s.strip() for s in text.split(";") if s.strip()]
    return out


@pytest.fixture
def flows_db() -> Iterator[str]:
    name = f"buffmon_it_{secrets.token_hex(4)}"
    for stmt in _statements("001_schema.sql", "002_flows.sql"):
        _admin(stmt.replace("buffmon.", f"{name}.").replace("DATABASE IF NOT EXISTS buffmon", f"DATABASE {name}"))
    try:
        yield name
    finally:
        _admin("DROP DATABASE IF EXISTS {db:Identifier}", db=name)


def _flow_rows(tmp_path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    sites = tmp_path / "sites.yaml"
    sites.write_text(yaml.safe_dump(SITES))
    consumer = FlowConsumer(SitesFile(sites))
    now_ns = time.time_ns()
    lines = [
        goflow_line(time_received_ns=now_ns, time_flow_end_ns=now_ns - 1_000_000, ip_tos=0),  # re-marked to BE
        goflow_line(time_received_ns=now_ns, time_flow_end_ns=now_ns - 1_000_000, src_addr=REFLECTOR[0],
                    src_port=862, dst_addr=PROBE[0], dst_port=PROBE[1], in_if=3, out_if=2),
        goflow_line(time_received_ns=now_ns, time_flow_end_ns=now_ns - 1_000_000, proto="TCP", dst_port=443,
                    sampling_rate=10, bytes=1000, packets=10),
    ]
    flows, probes = [], []
    for line in lines:
        f, p = consumer.handle(line)
        assert f is not None
        flows.append(f)
        if p is not None:
            probes.append(p)
    return flows, probes


def test_flows_paths_and_rollup_on_the_server(flows_db: str, tmp_path: Path) -> None:
    flows, probes = _flow_rows(tmp_path)

    async def go() -> list[dict[str, Any]]:
        t = _transport(flows_db)
        try:
            await t.insert_rows(FLOWS_TABLE, flows, content_token(flows))
            await t.insert_rows(FLOWS_TABLE, flows, content_token(flows))  # retried batch
            await t.insert_rows(PROBE_FLOWS_TABLE, probes, content_token(probes))
            return await query_paths(t, int(time.time() * 1000) - 10 * 60_000)
        finally:
            await t.aclose()

    rows = asyncio.run(go())
    assert int(_admin("SELECT count() FROM {db:Identifier}.flows", db=flows_db)) == 3, "retry deduplicated"
    # Rollup: retry not double counted, sampled flow scaled by its sampling rate.
    rollup = _admin("SELECT sum(flows), sum(bytes) FROM {db:Identifier}.flow_minute WHERE proto = 6", db=flows_db)
    assert rollup.split() == ["1", "10000"]
    assert int(_admin("SELECT sum(flows) FROM {db:Identifier}.flow_minute", db=flows_db)) == 3

    result = analyse(f"{PROBE[0]}:{PROBE[1]}", f"{REFLECTOR[0]}:{REFLECTOR[1]}", 46, "voice", rows, 10)
    assert result["status"] == "warn"
    assert {f["code"] for f in result["findings"]} == {"forward_dscp_mismatch"}, "return flow kept EF"
    assert result["forward"][0]["out_if_name"] == "wan0" and result["return"][0]["in_transport"] == "INET"



# -- Phase 2: Orchestrator tunnel_stats ---------------------------------------------

@pytest.fixture
def orch_db() -> Iterator[str]:
    name = f"buffmon_it_{secrets.token_hex(4)}"
    for stmt in _statements("003_tunnel_stats.sql"):
        _admin(stmt.replace("buffmon.", f"{name}.").replace("DATABASE IF NOT EXISTS buffmon", f"DATABASE {name}"))
    try:
        yield name
    finally:
        _admin("DROP DATABASE IF EXISTS {db:Identifier}", db=name)


def test_tunnel_summary_query_on_the_server(orch_db: str) -> None:
    from buffmon.orch.mapping import bucket_context, load_mapping, normalize
    from buffmon.orch.poller import OrchTransport, rows_token
    from buffmon.tunnels import query_tunnels

    mapping = load_mapping(Path(__file__).resolve().parents[2] / "deploy" / "orchestrator" / "mapping.10.x.yaml")
    fixture = Path(__file__).resolve().parent / "fixtures" / "orch" / "aggregate_tunnel_10x.json"
    response = {k: v for k, v in json.loads(fixture.read_text()).items() if not k.startswith("_")}
    now_s = int(time.time()) // 60 * 60
    rows: list[dict[str, Any]] = []
    for start in (now_s - 180, now_s - 120):  # two minutes of the same tunnels
        ctx = {"appliance_id": "1.NE", "hostname": "ec-a-01", "site": "A", **bucket_context(start, start + 60)}
        got, problems = normalize("tunnel_stats", mapping.collectors["tunnel_stats"], response,
                                  datetime.now(tz=UTC), "10.0", ctx)
        assert problems == []
        rows += got

    async def go() -> list[dict[str, Any]]:
        assert URL
        sink = OrchTransport(URL, orch_db, USER, PASSWORD, timeout_s=30)
        try:
            await sink.insert_rows("tunnel_stats", rows, rows_token("tunnel_stats", rows))
            await sink.insert_rows("tunnel_stats", rows, rows_token("tunnel_stats", rows))  # re-poll
            return await query_tunnels(sink, (now_s - 600) * 1000)
        finally:
            await sink.aclose()

    tunnels = {t["tunnel_id"]: t for t in asyncio.run(go())}
    assert set(tunnels) == {"bondedTunnel_17", "tunnel_47", "tunnel_27"}
    t47 = tunnels["tunnel_47"]
    assert t47["minutes"] == 2, "re-poll replaced, not duplicated"
    assert (t47["loss_pre_pkts"], t47["loss_post_pkts"], t47["fec_recovered_pkts"]) == (80, 4, 76)
    assert (t47["tunnel_kind"], t47["transport"], t47["peer"]) == ("underlay", "INET1", "ec-b-01")
    assert t47["latency_ms"] == 42.0 and t47["latency_max_ms"] == 42.0
    assert tunnels["bondedTunnel_17"]["overlay"] == "DEFAULT"


# -- Phase 3: route traces and capacity ----------------------------------------------

@pytest.fixture
def routes_db() -> Iterator[str]:
    name = f"buffmon_it_{secrets.token_hex(4)}"
    for stmt in _statements("004_routes.sql"):
        _admin(stmt.replace("buffmon.", f"{name}.").replace("DATABASE IF NOT EXISTS buffmon", f"DATABASE {name}"))
    try:
        yield name
    finally:
        _admin("DROP DATABASE IF EXISTS {db:Identifier}", db=name)


def test_routes_and_capacity_on_the_server(routes_db: str) -> None:
    from buffmon.routes import (
        CAPACITY_TABLE,
        ROUTE_TABLE,
        CapacityResult,
        RouteResult,
        capacity_to_row,
        query_route_history,
        route_to_row,
    )
    from tests.test_routes import PROBE_OUTPUT

    now_ms = int(time.time() * 1000)
    routes, caps = [], []
    for i, line in enumerate(PROBE_OUTPUT.read_text().splitlines()):
        d = {**json.loads(line), "ts_ms": now_ms - 60_000 + i * 1000}  # real probe output, recent
        if d["kind"] == "route":
            routes.append(route_to_row(RouteResult.model_validate(d)))
        else:
            caps.append(capacity_to_row(CapacityResult.model_validate(d)))

    async def go() -> dict[str, Any]:
        t = _transport(routes_db)
        try:
            for _ in range(2):  # a retried batch
                await t.insert_rows(ROUTE_TABLE, routes, batch_token(routes))
                await t.insert_rows(CAPACITY_TABLE, caps, batch_token(caps))
            return await query_route_history(t, "lab-p1", "dc-voice", now_ms - 3_600_000)
        finally:
            await t.aclose()

    h = asyncio.run(go())
    assert int(_admin("SELECT count() FROM {db:Identifier}.route_traces", db=routes_db)) == len(routes)
    assert len(h["traces"]) == len(routes) and len(h["capacity"]) == len(caps)
    (change,) = h["changes"]
    assert change["changed"] is True and change["change_ttl"] == 2 and change["change_reason"] == "hop"
    assert change["prev_signature"] == "10.90.1.1>10.90.2.2>10.90.4.2"
    cap = h["capacity"][0]
    assert cap["fwd_bps"] == 19_790_571 and cap["back_is_lower_bound"] is True and cap["burst_bytes"] == 7991
    hops = _admin("SELECT hop_addrs FROM {db:Identifier}.route_traces ORDER BY ts LIMIT 1 FORMAT TSV", db=routes_db)
    assert hops == "[['10.90.1.1'],['10.90.2.2'],['10.90.4.2']]"
