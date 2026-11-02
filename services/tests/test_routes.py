"""Phase 3 results: route traces and capacity, from the probe's batch to the API."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from buffmon.app import create_app
from buffmon.config import Settings
from buffmon.routes import CapacityResult, RouteResult, RouteView, capacity_to_row, route_to_row
from tests.conftest import TOKEN, FakeTransport, make_record, now_bucket_ms

AUTH = {"authorization": f"Bearer {TOKEN}"}
PROBE_OUTPUT = Path(__file__).resolve().parent / "fixtures" / "probe" / "routes_capacity.jsonl"


def hop(ttl: int, *addrs: str, rtt_us: int | None = 500) -> dict[str, Any]:
    return {"ttl": ttl, "addrs": list(addrs), "rtt_us": rtt_us if addrs else None, "sent": 3,
            "replies": 3 if addrs else 0}


def make_route(**overrides: Any) -> dict[str, Any]:
    hops = [hop(1, "10.1.1.1"), hop(2, "192.0.2.2"), hop(3, "10.10.0.1")]
    r: dict[str, Any] = {
        "v": 1, "probe_id": "p1", "site": "SJC-BR01", "session": "dc1-voice", "kind": "route",
        "app_class": "voice", "dscp": 46, "src": "10.1.1.10:40001", "dst": "10.10.0.20:862",
        "ts_ms": int(time.time() * 1000) - 5000, "duration_ms": 12, "trigger": "schedule",
        "ttl_fwd": 61, "ttl_back": 61, "hop_count_fwd": 3, "hops": hops,
        "complete": True, "multipath": False, "signature": "10.1.1.1>192.0.2.2>10.10.0.1",
        "changed": False, "change_ttl": None, "change_reason": None, "prev_signature": None,
    }
    r.update(overrides)
    return r


def changed_route(**overrides: Any) -> dict[str, Any]:
    return make_route(
        hops=[hop(1, "10.1.1.1"), hop(2, "192.0.2.6"), hop(3, "10.10.0.1")],
        signature="10.1.1.1>192.0.2.6>10.10.0.1", changed=True, change_ttl=2, change_reason="hop",
        prev_signature="10.1.1.1>192.0.2.2>10.10.0.1", trigger="ttl_change",
        **{"ts_ms": int(time.time() * 1000) - 2000, **overrides},
    )


def make_capacity(**overrides: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "v": 1, "probe_id": "p1", "site": "SJC-BR01", "session": "dc1-voice", "kind": "capacity",
        "app_class": "voice", "dscp": 0, "src": "10.1.1.10:45122", "dst": "10.10.0.20:862",
        "ts_ms": int(time.time() * 1000) - 4000, "packets": 64, "size": 1200, "trains": 5, "valid_trains": 5,
        "fwd_bps": 19_740_000, "fwd_bps_min": 19_690_000, "fwd_bps_max": 19_820_000, "fwd_adr_bps": 21_670_000,
        "burst_trains": 5, "burst_bytes": 8018, "back_bps": 21_740_000, "back_is_lower_bound": True,
        "lost": 0, "invalid": {},
    }
    c.update(overrides)
    return c


# -- validation ---------------------------------------------------------------------

def test_valid_results_and_rows() -> None:
    r = RouteResult.model_validate(make_route())
    row = route_to_row(r)
    assert row["hop_addrs"] == [["10.1.1.1"], ["192.0.2.2"], ["10.10.0.1"]] and row["hop_sent"] == [3, 3, 3]
    assert r.key == ("route", "p1", "dc1-voice", r.ts_ms)
    c = CapacityResult.model_validate(make_capacity())
    crow = capacity_to_row(c)
    assert crow["fwd_bps"] == 19_740_000 and "ts" in crow and "kind" not in crow and "ts_ms" not in crow
    assert c.key[0] == "capacity"


@pytest.mark.parametrize("over,match", [
    ({"signature": "10.1.1.1>*>10.10.0.1"}, "signature does not match"),
    ({"hops": [hop(2, "10.1.1.1")], "signature": "10.1.1.1"}, "TTL 1, 2, 3"),
    ({"hops": [hop(1, "not-an-ip")], "signature": "not-an-ip"}, "IPv4"),
    ({"hops": [hop(1, "10.1.1.1", "10.1.1.1")], "signature": "10.1.1.1|10.1.1.1", "multipath": True}, "distinct"),
    ({"changed": True}, "change_reason"),
    ({"change_ttl": 2}, "need changed"),
    ({"multipath": True}, "multipath"),
    ({"trigger": "manual"}, "trigger"),
    ({"kind": "path"}, "kind"),
    ({"hops": [hop(i + 1, "10.0.0.1") for i in range(65)]}, "at most 64"),
])
def test_invalid_routes(over: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        RouteResult.model_validate(make_route(**over))


@pytest.mark.parametrize("over,match", [
    ({"valid_trains": 6}, "valid_trains <= trains"),
    ({"burst_trains": 6}, "burst_trains"),
    ({"lost": 10_000}, "lost exceeds"),
    ({"fwd_bps_min": 30_000_000}, "fwd_bps_min <= fwd_bps"),
    ({"valid_trains": 0, "burst_trains": 0}, "needs a valid train"),
    ({"fwd_bps": -1}, "greater than or equal"),
    ({"invalid": {"Bad Key": 1}}, "pattern"),
    ({"back_method": "reflected_train"}, "measured"),
    ({"back_method": "reflected_train", "back_is_lower_bound": False}, "measured"),
    ({"back_trains": 1, "back_valid_trains": 2}, "back_valid_trains"),
    ({"back_method": "guess"}, "back_method"),
])
def test_invalid_capacity(over: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        CapacityResult.model_validate(make_capacity(**over))


def test_real_probe_output_validates() -> None:
    """Contract test: lines printed by buffmon-probe in the namespace lab."""
    kinds = []
    for line in PROBE_OUTPUT.read_text().splitlines():
        d = json.loads(line)
        model = RouteResult if d["kind"] == "route" else CapacityResult
        kinds.append(model.model_validate(d).kind)
    assert {"route", "capacity"} <= set(kinds)
    methods = [json.loads(line).get("back_method") for line in PROBE_OUTPUT.read_text().splitlines()]
    assert "reflected_train" in methods, "an RFC 10052 measurement from the lab is in the fixture"


# -- the in-memory view ---------------------------------------------------------------

def test_route_view_keeps_latest_and_recent_changes() -> None:
    v = RouteView(max_sessions=2, keep_changes=2)
    t = int(time.time() * 1000)
    v.add_route(RouteResult.model_validate(make_route(ts_ms=t)))
    v.add_route(RouteResult.model_validate(changed_route(ts_ms=t + 1000)))
    v.add_route(RouteResult.model_validate(make_route(ts_ms=t - 5000)))  # older, out of order
    v.add_capacity(CapacityResult.model_validate(make_capacity(ts_ms=t)))
    snap = v.snapshot()["p1/dc1-voice"]
    assert snap["route"]["ts_ms"] == t + 1000, "an older trace does not replace a newer one"
    assert [c["change_ttl"] for c in snap["changes"]] == [2]
    assert snap["capacity"]["fwd_bps"] == 19_740_000
    for s in ("a", "b"):
        v.add_route(RouteResult.model_validate(make_route(session=s)))
    assert len(v) == 2 and "p1/dc1-voice" not in v.snapshot(), "least recently updated session evicted"


# -- ingest and API -----------------------------------------------------------------

@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def client(settings: Settings, transport: FakeTransport) -> Iterator[TestClient]:
    with TestClient(create_app(settings, transport=transport)) as c:
        yield c


def post(client: TestClient, **body: Any) -> Any:
    return client.post("/v1/probe/results", json={"probe_id": "p1", "records": [], **body}, headers=AUTH)


def wait_for(cond: Any, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def test_ingest_routes_and_capacity(client: TestClient, transport: FakeTransport) -> None:
    rec = make_record(ts_ms=now_bucket_ms(-10))
    body = {"records": [rec], "routes": [make_route(), changed_route()], "capacity": [make_capacity()]}
    r = post(client, **body)
    assert r.json() == {"accepted": 4, "duplicates": 0, "rejected": 0, "errors": []}
    r = post(client, **body)
    assert r.json()["duplicates"] == 4, "resent results are recognised"
    wait_for(lambda: {t for t, _, _ in transport.inserts} == {"probe_second", "route_traces", "capacity"})
    routes = [row for t, rows, _ in transport.inserts if t == "route_traces" for row in rows]
    assert len(routes) == 2 and routes[1]["changed"] is True

    snap = client.get("/v1/routes").json()["sessions"]["p1/dc1-voice"]
    assert snap["route"]["signature"] == "10.1.1.1>192.0.2.6>10.10.0.1"
    assert snap["changes"][0]["prev_signature"] == "10.1.1.1>192.0.2.2>10.10.0.1"
    assert snap["capacity"]["burst_bytes"] == 8018


def test_ingest_rejects_bad_results_individually(client: TestClient) -> None:
    r = post(client, routes=[make_route(signature="x"), make_route(probe_id="p2"), make_route()],
             capacity=[make_capacity(ts_ms=1_000)])
    out = r.json()
    assert (out["accepted"], out["rejected"]) == (1, 3)
    assert [(e["section"], e["index"]) for e in out["errors"]] == [("routes", 0), ("routes", 1), ("capacity", 0)]
    assert "24 h" in out["errors"][2]["error"]


def test_old_batches_and_limits(client: TestClient, settings: Settings) -> None:
    r = post(client, records=[make_record(ts_ms=now_bucket_ms(-20))])
    assert r.json()["accepted"] == 1
    too_many = [make_route(ts_ms=int(time.time() * 1000) - i) for i in range(settings.max_records + 1)]
    assert post(client, routes=too_many).status_code == 413


def test_route_history_api(client: TestClient, transport: FakeTransport) -> None:
    transport.select_rows = [{"ts_ms": 1, "changed": 1, "complete": 0, "multipath": 0, "back_is_lower_bound": 1}]
    r = client.get("/v1/sessions/p1/dc1-voice/routes?hours=24")
    assert r.status_code == 200
    body = r.json()
    assert body["changes"][0]["changed"] is True and body["capacity"][0]["back_is_lower_bound"] is True
    sqls = [s for s, _ in transport.selects]
    assert any("FROM route_traces" in s for s in sqls) and any("FROM capacity" in s for s in sqls)
    assert client.get("/v1/sessions/p1/dc1-voice/routes?hours=0").status_code == 400
    assert client.get("/v1/sessions/p1/bad name/routes").status_code == 400
    transport.fail_selects = True
    assert client.get("/v1/sessions/p1/dc1-voice/routes").status_code == 503
