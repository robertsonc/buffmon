"""The shipped Orchestrator 10.x mapping, filled from the 10.0.0.40724 export and
verified with read-only calls, plus the mapping features it needs (time
buckets, templated parameters, regex fields)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from buffmon.orch.mapping import Buckets, MappingFile, bucket_context, load_mapping, normalize, render_params
from buffmon.orch.poller import main
from buffmon.orch.post_policy import load_policy

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "orchestrator"
POLICY = DEPLOY / "post-allowlist.yaml"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "orch" / "aggregate_tunnel_10x.json"
MAPPING = load_mapping(DEPLOY / "mapping.10.x.yaml")


def test_shipped_10x_mapping_is_complete_and_get_only() -> None:
    assert MAPPING.auth.mode == "header" and MAPPING.auth.header_name == "X-Auth-Token"
    assert set(MAPPING.enabled()) == {"appliances", "tunnel_stats", "alarms"}
    # Every collector is GET except alarms: a read sent under the POST policy.
    assert {n: c.method for n, c in MAPPING.collectors.items()} == \
        {"appliances": "GET", "tunnel_stats": "GET", "alarms": "POST"}
    assert MAPPING.collectors["alarms"].path == "/alarm/appliance"
    assert MAPPING.collectors["alarms"].post_rule == "alarm-appliance-read"
    ts = MAPPING.collectors["tunnel_stats"]
    assert ts.fan_out == "appliances" and ts.buckets == Buckets(size_s=60, lag_s=120, count=3)
    # LIVE: seconds, not the milliseconds the export documents.
    assert ts.params["startTime"] == "{bucket_start_s}" and ts.params["endTime"] == "{bucket_end_s}"


def test_live_shaped_response_normalizes_through_the_shipped_mapping() -> None:
    response = {k: v for k, v in json.loads(FIXTURE.read_text()).items() if not k.startswith("_")}
    ctx = {"appliance_id": "27.NE", "hostname": "ec-a-01", "site": "SITE-A", **bucket_context(1793556000, 1793556060)}
    rows, problems = normalize("tunnel_stats", MAPPING.collectors["tunnel_stats"], response,
                               datetime.now(tz=UTC), "10.0", ctx)
    assert problems == []
    by_id = {r["tunnel_id"]: r for r in rows}
    bonded, inet1, azr = by_id["bondedTunnel_17"], by_id["tunnel_47"], by_id["tunnel_27"]
    assert bonded["ts"] == "2026-11-01 18:00:00.000"
    assert (bonded["appliance"], bonded["site"]) == ("ec-a-01", "SITE-A")
    assert (bonded["tunnel_kind"], bonded["overlay"], bonded["transport"], bonded["peer"]) == \
        ("overlay", "DEFAULT", "", "ec-b-01")
    assert (inet1["tunnel_kind"], inet1["overlay"], inet1["transport"]) == ("underlay", "", "INET1")
    assert azr["transport"] == "AZR_INET", "labels may contain underscores"
    assert azr["peer"] == "ec-c-02"
    assert (inet1["loss_pre_fec_pkts"], inet1["loss_post_fec_pkts"], inet1["ooo_pre_poc_pkts"]) == (40, 2, 5)
    assert (inet1["loss_pre_fec_pct"], inet1["loss_post_fec_pct"]) == (3.0, 0.15)
    assert inet1["rx_pkts"] == 1300 and inet1["ohead_rx_pkts"] == 25
    assert bonded["mos"] == pytest.approx(4.38), "mos is reported x100"
    assert (inet1["latency_ms"], inet1["jitter_ms"]) == (42.0, 2.1)
    assert "avg_mos_prefec" not in json.dumps(rows)


def test_buckets_are_exact_lagged_minutes() -> None:
    now = 1793556185  # 18:03:05 UTC; 1793556000 is 18:00:00
    # Newest bucket that ended at least 120 s ago: 18:00-18:01 (ended 2 min 5 s ago).
    assert Buckets(size_s=60, lag_s=120, count=3).windows(now) == [
        (1793556000, 1793556060), (1793555940, 1793556000), (1793555880, 1793555940)]


def test_params_are_templated_from_inventory_and_bucket() -> None:
    ctx = {"appliance_id": "27.NE", **bucket_context(100, 160)}
    assert render_params({"nePk": "{appliance_id}", "startTime": "{bucket_start_s}", "endTime": "{bucket_end_ms}",
                          "groupByNE": False}, ctx) == \
        {"nePk": "27.NE", "startTime": "100", "endTime": "160000", "groupByNE": False}
    with pytest.raises(ValueError, match="hostname"):
        render_params({"h": "{hostname}"}, ctx)


def _base(**collector: Any) -> dict[str, Any]:
    return {"orchestrator_version": "synthetic", "auth": {"mode": "header", "header_name": "X-Synthetic"},
            "collectors": {"alarms": {"enabled": True, "path": "/synthetic/alarms", "records": "",
                                      "fields": {"ts": {"from": "$now"}, "alarm_id": {"from": "id"}}, **collector}}}


def test_bucket_placeholders_and_sources_require_buckets() -> None:
    with pytest.raises(ValidationError, match="bucket_start_s"):
        MappingFile.model_validate(_base(params={"from": "{bucket_start_s}"}))
    bad = _base()
    bad["collectors"]["alarms"]["fields"]["ts"] = {"from": "$bucket_start"}
    with pytest.raises(ValidationError, match="needs buckets"):
        MappingFile.model_validate(bad)
    ok = _base(params={"from": "{bucket_start_ms}"}, buckets={"size_s": 60, "lag_s": 0, "count": 1})
    MappingFile.model_validate(ok)


def test_pattern_must_have_a_group_and_no_match_gives_default() -> None:
    bad = _base()
    bad["collectors"]["alarms"]["fields"]["source"] = {"from": "x", "pattern": "^abc$"}
    with pytest.raises(ValidationError, match="capturing group"):
        MappingFile.model_validate(bad)
    good = _base()
    good["collectors"]["alarms"]["fields"]["source"] = {"from": "x", "pattern": "^to_([^_]+)_", "default": "none"}
    m = MappingFile.model_validate(good)
    rows, _ = normalize("alarms", m.collectors["alarms"], [{"id": 1, "x": "no-match"}, {"id": 2, "x": "to_ec-1_L"}],
                        datetime.now(tz=UTC), "s")
    assert [r["source"] for r in rows] == ["none", "ec-1"]


def test_poller_requests_against_the_shipped_mapping(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[httpx.Request] = []
    agg = {k: v for k, v in json.loads(FIXTURE.read_text()).items() if not k.startswith("_")}

    def h(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        if r.url.path.endswith("/appliance") and r.method == "GET":
            return httpx.Response(200, json=[{"nePk": "1.NE", "hostName": "ec-a-01", "site": "A"},
                                             {"nePk": "2.NE", "hostName": "ec-a-02", "site": "A"}])
        if r.url.path.endswith("/stats/aggregate/tunnel"):
            return httpx.Response(200, json=agg)
        if r.url.path.endswith("/alarm/appliance") and r.method == "POST":
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={})

    token = tmp_path / "token"
    token.write_text("synthetic-token")
    code = main(["--mapping", str(DEPLOY / "mapping.10.x.yaml"), "--url", "https://orch.synthetic.invalid/gms/rest",
                 "--token-file", str(token), "--post-policy", str(POLICY), "--once", "--dry-run"],
                transport=httpx.MockTransport(h))
    out = capsys.readouterr()
    assert code == 0, out.err
    assert all(r.method == "GET" or r.url.path == "/gms/rest/alarm/appliance" for r in seen)
    assert all(r.headers.get("x-auth-token") == "synthetic-token" for r in seen)
    stats = [r for r in seen if r.url.path.endswith("/stats/aggregate/tunnel")]
    assert len(stats) == 2 * 3, "one request per appliance per bucket"
    for r in stats:
        start, end = int(r.url.params["startTime"]), int(r.url.params["endTime"])
        assert end - start == 60 and start % 60 == 0 and start < 10**11, "whole minutes, epoch seconds"
        assert r.url.params["groupByNE"] in ("false", "False")
    rows = [json.loads(line) for line in out.out.splitlines()]
    assert sum(1 for r in rows if r["collector"] == "tunnel_stats") == 2 * 3 * 3


# -- POST /alarm/appliance under rule alarm-appliance-read ------------------------------

ALARMS_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "orch" / "alarm_appliance_10x.json"


def _client(handler: Any) -> Any:
    from pydantic import SecretStr

    from buffmon.orch.client import AuthConfig, ClientConfig, OrchClient

    return OrchClient(
        ClientConfig(base_url="https://orch.synthetic.invalid/gms/rest",
                     auth=AuthConfig(mode="header", header_name="X-Auth-Token", token=SecretStr("synthetic-token")),
                     backoff_base_s=0.0, backoff_max_s=0.0, post_policy=load_policy(POLICY)),
        transport=httpx.MockTransport(handler),
    )


async def _stream() -> Any:
    yield b'{"nePks": ["1.NE"]}'


def test_only_requests_that_fit_the_rule_are_sent() -> None:
    import asyncio

    from buffmon.orch.client import POST_RULE_EXTENSION, ReadOnlyViolationError

    seen: list[httpx.Request] = []

    def h(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        return httpx.Response(200, json=[])

    rule = "alarm-appliance-read"
    ext = {POST_RULE_EXTENSION: rule}

    async def go() -> None:
        c = _client(h)
        try:
            assert await c.post_json(rule, {"view": "active", "maxAlarms": 5000}, {"nePks": ["1.NE"]}) == []
            refused = [
                c.post_json("alarm-acknowledge", None, {"ids": [1]}),                    # no such rule
                c.post_json(rule, {"view": "acknowledged"}, {"nePks": ["1.NE"]}),        # not in the enum
                c.post_json(rule, {"maxAlarms": 0}, {"nePks": ["1.NE"]}),                # below min
                c.post_json(rule, {"acknowledge": "true"}, {"nePks": ["1.NE"]}),         # unknown parameter
                c.post_json(rule, None, {"nePks": ["1.NE"], "action": "clear"}),         # unknown body key
                c.post_json(rule, None, {"nePks": ["1.NE; DROP"]}),                      # pattern
                c.post_json(rule, None, {"nePks": [f"{i}.NE" for i in range(1001)]}),    # max_items
                c.post_json(rule, None, {}),                                             # required key
                c.post_json(rule, None, ["1.NE"]),                                       # not an object
                # The request hook, for anything that bypasses post_json:
                c._client.post("/alarm/clearance/appliance", json={}),                   # no rule
                c._client.post("/alarm/note/appliance", json={"nePks": ["1.NE"]}, extensions=ext),  # wrong path
                c._client.post("https://orch.synthetic.invalid/other/alarm/appliance",              # outside API base
                               json={"nePks": ["1.NE"]}, extensions=ext),
                c._client.post("/alarm/appliance", params={"view": "active", "x": "1"},             # extra parameter
                               json={"nePks": ["1.NE"]}, extensions=ext),
                c._client.post("/alarm/appliance", params=[("view", "active"), ("view", "all")],    # repeated parameter
                               json={"nePks": ["1.NE"]}, extensions=ext),
                c._client.post("/alarm/appliance", content=b"nePks=1.NE", extensions=ext),          # not JSON
                c._client.post("/alarm/appliance", content=_stream(), extensions=ext),              # streamed
            ]
            for i, coro in enumerate(refused):
                with pytest.raises(ReadOnlyViolationError):
                    await coro
                assert len(seen) == 1, f"refused request {i} reached the server"
        finally:
            await c.aclose()

    asyncio.run(go())
    assert [(r.method, r.url.path) for r in seen] == [("POST", "/gms/rest/alarm/appliance")]
    assert json.loads(seen[0].content) == {"nePks": ["1.NE"]}


def test_no_policy_means_no_post() -> None:
    import asyncio

    from pydantic import SecretStr

    from buffmon.orch.client import POST_RULE_EXTENSION, AuthConfig, ClientConfig, OrchClient, ReadOnlyViolationError

    seen: list[httpx.Request] = []
    c = OrchClient(ClientConfig(base_url="https://orch.synthetic.invalid/gms/rest",
                                auth=AuthConfig(mode="header", header_name="X-Auth-Token",
                                                token=SecretStr("synthetic-token"))),
                   transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200, json=[])))

    async def go() -> None:
        try:
            with pytest.raises(ReadOnlyViolationError, match="no rules"):
                await c.post_json("alarm-appliance-read", None, {"nePks": ["1.NE"]})
            with pytest.raises(ReadOnlyViolationError):
                await c._client.post("/alarm/appliance", json={"nePks": ["1.NE"]},
                                     extensions={POST_RULE_EXTENSION: "alarm-appliance-read"})
        finally:
            await c.aclose()

    asyncio.run(go())
    assert seen == []


def test_approved_post_is_retried_like_a_read() -> None:
    import asyncio

    calls = {"n": 0}

    def h(r: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] == 1 else httpx.Response(200, json=[{"id": 1}])

    async def go() -> Any:
        c = _client(h)
        try:
            return await c.post_json("alarm-appliance-read", None, {"nePks": ["1.NE"]})
        finally:
            await c.aclose()

    assert asyncio.run(go()) == [{"id": 1}] and calls["n"] == 2


@pytest.mark.parametrize("collector,match", [
    ({"method": "POST", "path": "/synthetic/alarms", "body": {"x": 1}}, "needs post_rule"),
    ({"method": "POST", "path": "/alarm/appliance", "post_rule": "r-1"}, "needs a body"),
    ({"method": "GET", "path": "/synthetic/alarms", "body": {"x": 1}}, "cannot have a body"),
    ({"method": "GET", "path": "/synthetic/alarms", "post_rule": "r-1"}, "cannot have a body or post_rule"),
    ({"method": "POST", "path": "/alarm/appliance", "body": {"nePks": "{appliance_ids}"}}, "appliances collector"),
])
def test_post_collectors_are_validated(collector: dict[str, Any], match: str) -> None:
    raw = _base(**collector)
    with pytest.raises(ValidationError, match=match):
        MappingFile.model_validate(raw)


def test_live_shaped_alarms_normalize_through_the_shipped_mapping() -> None:
    records = json.loads(ALARMS_FIXTURE.read_text())["records"]
    rows, problems = normalize("alarms", MAPPING.collectors["alarms"], records, datetime.now(tz=UTC), "10.0")
    assert problems == []
    bgp, tun = rows
    assert (bgp["alarm_id"], bgp["appliance"], bgp["severity"]) == ("101", "ec-a-01", "MAJOR")
    assert (bgp["source"], bgp["name"], bgp["object"]) == ("SW", "BGP peer down", "192.0.2.10")
    assert bgp["state"] == "active" and bgp["cleared_ts"] is None, "clearedTimeInMills 0 means not cleared"
    assert tun["state"] == "closed" and tun["cleared_ts"] == "2026-10-31 12:15:04.000"


def test_alarm_post_sends_inventory_ids_in_chunks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import yaml

    raw = yaml.safe_load((DEPLOY / "mapping.10.x.yaml").read_text())
    raw["collectors"]["alarms"]["body_chunk"] = 2
    raw["collectors"]["tunnel_stats"]["enabled"] = False
    mapping = tmp_path / "m.yaml"
    mapping.write_text(yaml.safe_dump(raw))
    records = json.loads(ALARMS_FIXTURE.read_text())["records"]
    seen: list[httpx.Request] = []

    def h(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        if r.url.path.endswith("/appliance") and r.method == "GET":
            return httpx.Response(200, json=[{"nePk": f"{i}.NE", "hostName": f"ec-{i}", "site": "A"} for i in range(5)])
        if r.url.path.endswith("/alarm/appliance") and r.method == "POST":
            return httpx.Response(200, json=records[:1])
        return httpx.Response(404, json={})

    token = tmp_path / "token"
    token.write_text("synthetic-token")
    code = main(["--mapping", str(mapping), "--url", "https://orch.synthetic.invalid/gms/rest",
                 "--token-file", str(token), "--post-policy", str(POLICY), "--once", "--dry-run"],
                transport=httpx.MockTransport(h))
    assert code == 0, capsys.readouterr().err
    posts = [r for r in seen if r.method == "POST"]
    assert [json.loads(r.content)["nePks"] for r in posts] == [["0.NE", "1.NE"], ["2.NE", "3.NE"], ["4.NE"]]
    assert all(r.url.params["view"] == "active" for r in posts)
    assert {r.method for r in seen} == {"GET", "POST"} and all(r.url.path.endswith("/alarm/appliance") for r in posts)
