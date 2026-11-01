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

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "orchestrator"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "orch" / "aggregate_tunnel_10x.json"
MAPPING = load_mapping(DEPLOY / "mapping.10.x.yaml")


def test_shipped_10x_mapping_is_complete_and_get_only() -> None:
    assert MAPPING.auth.mode == "header" and MAPPING.auth.header_name == "X-Auth-Token"
    assert set(MAPPING.enabled()) == {"appliances", "tunnel_stats", "alarms"}
    assert all(c.method == "GET" for c in MAPPING.collectors.values())
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
        if r.url.path.endswith("/appliance"):
            return httpx.Response(200, json=[{"nePk": "1.NE", "hostName": "ec-a-01", "site": "A"},
                                             {"nePk": "2.NE", "hostName": "ec-a-02", "site": "A"}])
        if r.url.path.endswith("/stats/aggregate/tunnel"):
            return httpx.Response(200, json=agg)
        if r.url.path.endswith("/alarm/correlatedAlarms"):
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={})

    token = tmp_path / "token"
    token.write_text("synthetic-token")
    code = main(["--mapping", str(DEPLOY / "mapping.10.x.yaml"), "--url", "https://orch.synthetic.invalid/gms/rest",
                 "--token-file", str(token), "--once", "--dry-run"], transport=httpx.MockTransport(h))
    out = capsys.readouterr()
    assert code == 0, out.err
    assert all(r.method == "GET" for r in seen)
    assert all(r.headers.get("x-auth-token") == "synthetic-token" for r in seen)
    stats = [r for r in seen if r.url.path.endswith("/stats/aggregate/tunnel")]
    assert len(stats) == 2 * 3, "one request per appliance per bucket"
    for r in stats:
        start, end = int(r.url.params["startTime"]), int(r.url.params["endTime"])
        assert end - start == 60 and start % 60 == 0 and start < 10**11, "whole minutes, epoch seconds"
        assert r.url.params["groupByNE"] in ("false", "False")
    rows = [json.loads(line) for line in out.out.splitlines()]
    assert sum(1 for r in rows if r["collector"] == "tunnel_stats") == 2 * 3 * 3
