"""RFC 9946 speed tests on demand: policy, coordination, the probe's job poll,
and results coming back through ingest."""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from buffmon.app import create_app
from buffmon.config import Settings
from buffmon.speedtest import JobBoard, Policy, PolicyError, Poll, Refused, SpeedtestResult, Window, load_policy
from tests.conftest import TOKEN, FakeTransport

AUTH = {"authorization": f"Bearer {TOKEN}"}
POLICY: dict[str, Any] = {"enabled": True, "probes": ["p*"], "max_mbps": 300, "max_duration_s": 10,
                          "allowed_dscp": [0], "max_concurrent": 2}


def cap(**over: Any) -> dict[str, Any]:
    return {"name": "dc1-st", "server": "st.dc1.example:24601", "directions": ["down", "up"], "max_mbps": 500,
            "max_duration_s": 10, "dscp": 0, **over}


def poll(probe_id: str = "p1", site: str = "SJC", **over: Any) -> Poll:
    return Poll.model_validate({"probe_id": probe_id, "site": site, "targets": [cap(**over)]})


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 11, 4, 12, 0, tzinfo=UTC).timestamp()  # a Wednesday

    def __call__(self) -> float:
        return self.t


def board(**policy: Any) -> tuple[JobBoard, Clock]:
    c = Clock()
    return JobBoard(Policy.model_validate({**POLICY, **policy}), clock=c, poll_s=15), c


# -- policy ---------------------------------------------------------------------------

def test_no_policy_file_means_disabled(tmp_path: Path) -> None:
    assert load_policy(None).enabled is False
    p = tmp_path / "p.yaml"
    p.write_text(yaml.safe_dump({**POLICY, "allowed_dscp": [46]}))
    with pytest.raises(PolicyError, match="less than or equal to 31"):
        load_policy(p)
    p.write_text(yaml.safe_dump({**POLICY, "surprise": 1}))
    with pytest.raises(PolicyError, match="surprise"):
        load_policy(p)


def test_windows_including_overnight() -> None:
    w = Window(days=["wed"], start="22:00", end="05:00", tz="UTC")
    def at(d: int, h: int) -> float:  # 4 Nov 2026 is a Wednesday
        return datetime(2026, 11, d, h, 30, tzinfo=UTC).timestamp()

    assert w.open_at(at(4, 23)) and w.open_at(at(5, 2)), "Wednesday night, into Thursday morning"
    assert not w.open_at(at(4, 12)) and not w.open_at(at(5, 23)) and not w.open_at(at(4, 2))
    la = Window(days=["wed"], start="09:00", end="10:00", tz="America/Los_Angeles")
    assert la.open_at(datetime(2026, 11, 4, 17, 30, tzinfo=UTC).timestamp()), "09:30 PST"
    with pytest.raises(ValidationError, match="time zone"):
        Window(start="00:00", end="01:00", tz="Mars/Olympus")


# -- the board -------------------------------------------------------------------------

def test_request_dispatch_complete() -> None:
    b, _ = board()
    b.poll(poll())
    job = b.request("p1", "dc1-st", "down", None, None)
    assert (job.max_mbps, job.duration_s, job.state) == (300, 10, "queued"), "defaults to the lower cap"
    jobs = b.poll(poll())
    assert jobs == [{"job_id": job.job_id, "target": "dc1-st", "direction": "down", "max_mbps": 300, "duration_s": 10}]
    assert b.poll(poll()) == [], "handed out once"
    res = SpeedtestResult.model_validate(result(job.job_id))
    assert b.complete(res) and b.jobs[job.job_id].state == "completed"
    assert not b.complete(res), "only once"
    stored = b.jobs[job.job_id].result
    assert stored is not None and stored["max_ip_capacity_mbps"] == 287.4


@pytest.mark.parametrize("setup,args,status,match", [
    ({"enabled": False}, ("p1", "dc1-st", "down", None, None), 403, "disabled"),
    ({"probes": ["other*"]}, ("p1", "dc1-st", "down", None, None), 403, "not in the speed-test policy"),
    ({"windows": [{"days": ["sat"], "start": "00:00", "end": "23:59"}]}, ("p1", "dc1-st", "down", None, None), 403,
     "windows"),
    ({}, ("x9", "dc1-st", "down", None, None), 403, "not in the speed-test policy"),
    ({}, ("p9", "dc1-st", "down", None, None), 409, "checked in"),
    ({"probes": ["*"]}, ("q1", "dc1-st", "down", None, None), 409, "checked in"),
    ({}, ("p1", "nope", "down", None, None), 404, "no enabled speed-test target"),
    ({}, ("p1", "dc1-st", "down", 301, None), 422, "1-300"),
    ({}, ("p1", "dc1-st", "down", None, 11), 422, "1-10"),
    ({"allowed_dscp": [8]}, ("p1", "dc1-st", "down", None, None), 403, "DSCP 0"),
])
def test_refusals(setup: dict[str, Any], args: tuple[Any, ...], status: int, match: str) -> None:
    b, _ = board(**setup)
    b.poll(poll())
    with pytest.raises(Refused, match=match) as e:
        b.request(*args)
    assert e.value.status == status


def test_direction_must_be_advertised_and_probe_limits_apply() -> None:
    b, _ = board(max_mbps=1000)
    b.poll(poll(directions=["down"], max_mbps=200))
    with pytest.raises(Refused, match="direction up"):
        b.request("p1", "dc1-st", "up", None, None)
    assert b.request("p1", "dc1-st", "down", None, None).max_mbps == 200, "the probe's cap is lower"


def test_one_test_per_site_and_a_global_cap() -> None:
    b, _ = board(max_concurrent=2)
    for pid, site in (("p1", "SJC"), ("p2", "SJC"), ("p3", "NYC"), ("p4", "DAL")):
        b.poll(poll(pid, site))
    b.request("p1", "dc1-st", "down", None, None)
    with pytest.raises(Refused, match="already running at site SJC") as e:
        b.request("p2", "dc1-st", "down", None, None)
    assert e.value.status == 409
    b.request("p3", "dc1-st", "down", None, None)
    with pytest.raises(Refused, match="max_concurrent") as e:
        b.request("p4", "dc1-st", "down", None, None)
    assert e.value.status == 429


def test_lost_and_expired_jobs_free_the_site() -> None:
    b, c = board()
    b.poll(poll())
    j = b.request("p1", "dc1-st", "down", None, 5)
    c.t += 80  # never picked up (3 polls + 30 s)
    b.poll(poll("p2", "NYC"))
    assert b.jobs[j.job_id].state == "expired"
    b.poll(poll())  # the probe is back
    j2 = b.request("p1", "dc1-st", "down", None, 5)
    b.poll(poll())
    c.t += 5 + 91  # taken, never answered
    b.expire(c.t)
    assert b.jobs[j2.job_id].state == "lost"
    b.poll(poll())
    assert b.request("p1", "dc1-st", "down", None, 5).state == "queued"


def result(job_id: str, **over: Any) -> dict[str, Any]:
    r: dict[str, Any] = {
        "v": 1, "probe_id": "p1", "site": "SJC", "kind": "speedtest", "target": "dc1-st",
        "server": "st.dc1.example:24601", "job_id": job_id, "direction": "down",
        "ts_ms": int(time.time() * 1000) - 15_000, "duration_s": 10, "max_mbps": 300, "dscp": 0,
        "status": "completed", "error_status": 0, "error": None, "max_ip_capacity_mbps": 287.4,
        "loss_ratio_at_max": 0.0004, "rtt_range_ms_at_max": 6.1, "pdv_range_ms_at_max": 4.0,
        "summary_capacity_mbps": 250.2, "summary_loss_ratio": 0.001, "delivered_pct": 99.9,
        "ecn_bleaching": False, "udpst_version": "9.1.0",
    }
    r.update(over)
    return r


@pytest.mark.parametrize("over,match", [
    ({"status": "completed", "max_ip_capacity_mbps": None}, "completed test"),
    ({"status": "refused"}, "refused test"),
    ({"loss_ratio_at_max": 1.5}, "less than or equal to 1"),
    ({"job_id": "x; DROP"}, "pattern"),
    ({"direction": "sideways"}, "direction"),
])
def test_invalid_results(over: dict[str, Any], match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        SpeedtestResult.model_validate({**result("st-1"), **over})


# -- API ------------------------------------------------------------------------------

@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def client(settings: Settings, transport: FakeTransport, tmp_path: Path) -> Iterator[TestClient]:
    p = tmp_path / "speedtest.yaml"
    p.write_text(yaml.safe_dump(POLICY))
    s = settings.model_copy(update={"speedtest_policy": p})
    with TestClient(create_app(s, transport=transport)) as c:
        yield c


def probe_poll(client: TestClient, **body: Any) -> Any:
    payload = {"probe_id": "p1", "site": "SJC", "targets": [cap()], **body}
    return client.post("/v1/probe/jobs", json=payload, headers=AUTH)


def test_end_to_end_through_the_api(client: TestClient, transport: FakeTransport) -> None:
    assert probe_poll(client).json() == {"jobs": []}
    r = client.post("/v1/speedtests", json={"probe_id": "p1", "target": "dc1-st", "direction": "up"})
    assert r.status_code == 202, r.text
    job_id = r.json()["job"]["job_id"]
    again = client.post("/v1/speedtests", json={"probe_id": "p1", "target": "dc1-st", "direction": "down"})
    assert again.status_code == 409 and "SJC" in again.json()["error"]
    jobs = probe_poll(client).json()["jobs"]
    assert [j["job_id"] for j in jobs] == [job_id]
    out = client.post("/v1/probe/results", headers=AUTH,
                      json={"probe_id": "p1", "records": [], "speedtests": [result(job_id, direction="up")]}).json()
    assert out == {"accepted": 1, "duplicates": 0, "rejected": 0, "errors": []}
    snap = client.get("/v1/speedtests").json()
    assert snap["jobs"][0]["state"] == "completed" and snap["probes"]["p1"]["site"] == "SJC"
    # A result for a job this probe was never given is refused.
    out = client.post("/v1/probe/results", headers=AUTH,
                      json={"probe_id": "p1", "records": [], "speedtests": [result("st-forged")]}).json()
    assert out["rejected"] == 1 and "not a job" in out["errors"][0]["error"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not any(t == "speedtests" for t, _, _ in transport.inserts):
        time.sleep(0.02)
    rows = [row for t, rs, _ in transport.inserts if t == "speedtests" for row in rs]
    assert rows and rows[0]["max_ip_capacity_mbps"] == 287.4 and "ts" in rows[0]


def test_api_guards(client: TestClient) -> None:
    probe_poll(client)
    body = {"probe_id": "p1", "target": "dc1-st", "direction": "down"}
    assert client.post("/v1/speedtests", json=body, headers={"origin": "https://evil.example"}).status_code == 403
    assert client.post("/v1/speedtests", content=b"probe_id=p1",
                       headers={"content-type": "application/x-www-form-urlencoded"}).status_code == 415
    assert client.post("/v1/speedtests", json={**body, "max_mbps": "lots"}).status_code == 400
    assert client.post("/v1/speedtests", json={**body, "direction": "both"}).status_code == 400
    # The probe poll needs the probe's own token, for its own probe_id.
    assert client.post("/v1/probe/jobs", json={"probe_id": "p1", "site": "S", "targets": []}).status_code == 401
    r = client.post("/v1/probe/jobs", json={"probe_id": "p2", "site": "S", "targets": []}, headers=AUTH)
    assert r.status_code == 403
    r = client.post("/v1/probe/jobs", json={"probe_id": "p1", "site": "S", "targets": [cap(dscp=46)]}, headers=AUTH)
    assert r.status_code == 400, "a priority DSCP is not even accepted as a capability"


def test_disabled_without_a_policy(settings: Settings, transport: FakeTransport) -> None:
    with TestClient(create_app(settings, transport=transport)) as c:
        assert c.get("/v1/speedtests").json()["enabled"] is False
        r = c.post("/v1/speedtests", json={"probe_id": "p1", "target": "dc1-st", "direction": "down"})
        assert r.status_code == 403 and "disabled" in r.json()["error"]


def test_history_endpoint(client: TestClient, transport: FakeTransport) -> None:
    transport.select_rows = [{"ts_ms": 1, "job_id": "st-1", "status": "completed"}]
    r = client.get("/v1/probes/p1/speedtests?days=7")
    assert r.status_code == 200 and r.json()["tests"][0]["job_id"] == "st-1"
    assert any("FROM speedtests" in s for s, _ in transport.selects)
    assert client.get("/v1/probes/p1/speedtests?days=0").status_code == 400
