from __future__ import annotations

import gzip
import json
import time
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from buffmon.app import create_app
from buffmon.config import Settings
from tests.conftest import THRESHOLDS, TOKEN, UI_TOKEN, FakeTransport, lossy, make_record, now_bucket_ms

AUTH = {"authorization": f"Bearer {TOKEN}"}


def post(client: TestClient, records: list[Any], probe_id: str = "p1", **kw: Any) -> Any:
    return client.post("/v1/probe/results", json={"probe_id": probe_id, "records": records},
                       headers=kw.pop("headers", AUTH), **kw)


def batch(n: int, start_offset_s: int = -60) -> list[dict[str, Any]]:
    base = now_bucket_ms(start_offset_s)
    return [make_record(ts_ms=base + i * 1000) for i in range(n)]


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def client(settings: Settings, transport: FakeTransport) -> Iterator[TestClient]:
    with TestClient(create_app(settings, transport=transport)) as c:
        yield c


@pytest.fixture
def auth_client(auth_settings: Settings, transport: FakeTransport) -> Iterator[TestClient]:
    with TestClient(create_app(auth_settings, transport=transport)) as c:
        yield c


def wait_for(cond: Any, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


# ---------------------------------------------------------------- ingest


def test_ingest_requires_token(client: TestClient) -> None:
    r = post(client, batch(1), headers={})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    r = post(client, batch(1), headers={"authorization": "Bearer bm_" + "z" * 40})
    assert r.status_code == 401


def test_ingest_accepts_dedups_and_stores(client: TestClient, transport: FakeTransport) -> None:
    recs = batch(5)
    r = post(client, recs)
    assert r.status_code == 200
    assert r.json() == {"accepted": 5, "duplicates": 0, "rejected": 0, "errors": []}
    r = post(client, recs[2:] + batch(1, start_offset_s=-10))
    assert r.json()["accepted"] == 1 and r.json()["duplicates"] == 3
    wait_for(lambda: len(transport.rows) == 6)
    row = transport.rows[0]
    assert row["src_ip"] == "::ffff:10.1.1.10" and row["dst_port"] == 862
    assert row["ts"].endswith(".000")
    assert all(t == "probe_second" and len(tok) == 64 for t, _, tok in transport.inserts)


def test_ingest_rejects_individual_records(client: TestClient) -> None:
    good = batch(2)
    bad_sum = {**make_record(ts_ms=now_bucket_ms(-30)), "lost": 2}
    skewed = make_record(ts_ms=(int(time.time()) - 3 * 86400) * 1000)
    other_probe = make_record(ts_ms=now_bucket_ms(-20), probe_id="p2")
    r = post(client, [*good, bad_sum, skewed, other_probe, "not-an-object"])
    body = r.json()
    assert r.status_code == 200
    assert (body["accepted"], body["rejected"]) == (2, 4)
    by_index = {e["index"]: e["error"] for e in body["errors"]}
    assert "sent must equal received + lost" in by_index[2]
    assert "24 h" in by_index[3]
    assert "does not match the token" in by_index[4]
    assert 5 in by_index


def test_ingest_probe_id_must_match_token(client: TestClient) -> None:
    r = post(client, batch(1), probe_id="p2")
    assert r.status_code == 403


@pytest.mark.parametrize(
    ("body", "status"),
    [(b"not json", 400), (b'{"records": []}', 400), (b'{"probe_id": "p1", "records": {}}', 400), (b"[]", 400)],
)
def test_ingest_bad_bodies(client: TestClient, body: bytes, status: int) -> None:
    r = client.post("/v1/probe/results", content=body, headers={**AUTH, "content-type": "application/json"})
    assert r.status_code == status


def test_ingest_gzip_and_limits(tokens_file: Any, transport: FakeTransport) -> None:
    s = Settings(ui_auth="disabled", probe_tokens_file=tokens_file, max_records=3, max_body_bytes=20_000,
                 thresholds_file=THRESHOLDS)
    with TestClient(create_app(s, transport=transport)) as c:
        body = gzip.compress(json.dumps({"probe_id": "p1", "records": batch(2)}).encode())
        r = c.post("/v1/probe/results", content=body,
                   headers={**AUTH, "content-encoding": "gzip", "content-type": "application/json"})
        assert r.status_code == 200 and r.json()["accepted"] == 2
        r = post(c, batch(4, start_offset_s=-120))
        assert r.status_code == 413
        bomb = gzip.compress(b'{"probe_id":"p1","records":[' + b" " * 5_000_000 + b"]}")
        r = c.post("/v1/probe/results", content=bomb, headers={**AUTH, "content-encoding": "gzip"})
        assert r.status_code == 413
        r = c.post("/v1/probe/results", content=b"x" * 30_000, headers=AUTH)
        assert r.status_code == 413
        r = c.post("/v1/probe/results", content=b"\x1f\x8b garbage", headers={**AUTH, "content-encoding": "gzip"})
        assert r.status_code == 400
        r = c.post("/v1/probe/results", content=b"{}", headers={**AUTH, "content-encoding": "br"})
        assert r.status_code == 400


def test_live_view_survives_storage_outage(client: TestClient, transport: FakeTransport) -> None:
    transport.fail_inserts = 1000
    assert post(client, batch(3)).json()["accepted"] == 3
    sessions = client.get("/v1/sessions").json()["sessions"]
    assert sessions[0]["key"] == "p1/dc1-voice"
    wait_for(lambda: client.get("/v1/health").json()["status"] == "degraded")
    h = client.get("/v1/health").json()
    assert h["store"]["failed_attempts"] >= 1 and "simulated outage" in h["store"]["last_error"]


# ---------------------------------------------------------------- read APIs


def test_history_validation_and_shape(client: TestClient, transport: FakeTransport) -> None:
    assert client.get("/v1/sessions/p1/dc1-voice/history?range=2h").status_code == 400
    assert client.get("/v1/sessions/p1/bad%20name/history").status_code == 400
    transport.select_rows = [{
        "ts_ms": 1_761_955_200_000, "sent": 100, "received": 99, "lost": 1, "q_us": [21000, 25000],
        "rtt_max_us": 30000, "rtt_jitter_sum_us": 900, "rtt_jitter_n": 90, "ipdv_fwd_sum_us": 450,
        "ipdv_fwd_n": 90, "ipdv_back_sum_us": 0, "ipdv_back_n": 0, "fwd_lost": 1, "back_lost": 0, "dir_sent": 100,
    }]
    r = client.get("/v1/sessions/p1/dc1-voice/history?range=24h")
    assert r.status_code == 200
    h = r.json()
    assert (h["source"], h["bucket_s"]) == ("probe_minute", 300)
    assert h["points"][0] == {
        "ts_ms": 1_761_955_200_000, "sent": 100, "received": 99, "lost": 1, "loss_pct": 1.0, "rtt_p50_ms": 21.0,
        "rtt_p95_ms": 25.0, "rtt_max_ms": 30.0, "rtt_jitter_ms": 0.01, "ipdv_fwd_ms": 0.01, "ipdv_back_ms": None,
        "fwd_loss_pct": 1.0, "back_loss_pct": 0.0,
    }
    sql, params = transport.selects[-1]
    assert "{probe_id:String}" in sql and "dc1-voice" not in sql
    assert params["probe_id"] == "p1" and params["session"] == "dc1-voice" and params["bucket"] == 300
    transport.fail_selects = True
    assert client.get("/v1/sessions/p1/dc1-voice/history?range=1h").status_code == 503


def test_security_headers(client: TestClient) -> None:
    r = client.get("/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


# ---------------------------------------------------------------- UI auth


def test_ui_auth_flow(auth_client: TestClient) -> None:
    c = auth_client
    assert c.get("/v1/sessions").status_code == 401
    assert set(c.get("/v1/health").json()) == {"status"}
    r = c.get("/", follow_redirects=False)
    assert (r.status_code, r.headers["location"]) == (303, "/login")
    assert c.get("/login").status_code == 200
    r = c.post("/login", data={"token": "wrong"}, follow_redirects=False)
    assert r.headers["location"] == "/login?error=1"
    r = c.post("/login", data={"token": UI_TOKEN}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert c.get("/v1/sessions").status_code == 200
    assert "ingest" in c.get("/v1/health").json()
    assert c.get("/").status_code == 200
    c.post("/logout", follow_redirects=False)
    assert c.get("/v1/sessions").status_code == 401


def test_login_throttle(auth_client: TestClient) -> None:
    for _ in range(3):
        auth_client.post("/login", data={"token": "nope"}, follow_redirects=False)
    assert auth_client.post("/login", data={"token": UI_TOKEN}, follow_redirects=False).status_code == 429


def test_websocket_requires_login(auth_client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as exc, auth_client.websocket_connect("/v1/live") as ws:
        ws.receive_json()
    assert exc.value.code == 4401


def test_websocket_rejects_cross_origin(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as exc, client.websocket_connect(
        "/v1/live", headers={"origin": "https://evil.example"}
    ) as ws:
        ws.receive_json()
    assert exc.value.code == 4403


def test_websocket_backfill_then_incremental(client: TestClient) -> None:
    post(client, batch(5, start_offset_s=-40))
    with client.websocket_connect("/v1/live") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello" and hello["windows_s"] == [10, 30, 60]
        assert "voice" in hello["thresholds"]["classes"]
        back = ws.receive_json()
        assert back["type"] == "backfill"
        assert len(back["points"]["p1/dc1-voice"]) == 5
        assert back["sessions"][0]["status"] in {"insufficient-samples", "good"}
        newest = make_record(ts_ms=now_bucket_ms(-20))
        post(client, [lossy(newest, 2, fwd=2)])
        for _ in range(50):
            snap = ws.receive_json()
            assert snap["type"] == "snapshot"
            if snap["points"]:
                break
        pts = snap["points"]["p1/dc1-voice"]
        assert len(pts) == 1 and pts[0][0] == newest["ts_ms"] and pts[0][3] == 20.0
        s = snap["sessions"][0]
        assert s["w10"]["fwd_lost"] == 2 and s["w10"]["back_lost"] == 0
