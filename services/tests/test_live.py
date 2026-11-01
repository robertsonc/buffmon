from __future__ import annotations

from typing import Any

import pytest
import yaml

from buffmon import live as live_mod
from buffmon.live import LiveHub
from buffmon.models import ProbeRecord
from buffmon.thresholds import Thresholds, load_thresholds
from tests.conftest import THRESHOLDS, lossy, make_record

T0 = 1_761_955_200_000


class Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def feed(hub: LiveHub, clock: Clock, seconds: int, start_ms: int = T0, **rec: Any) -> None:
    """Feeds one record per second, advancing the clock as a real probe would."""
    lose = rec.pop("lose_every", None)
    for i in range(seconds):
        r = make_record(ts_ms=start_ms + i * 1000, **rec)
        if lose and i % lose == 0:
            r = lossy(r, 1)
        clock.t = (start_ms + i * 1000) / 1000 + 3
        hub.ingest(ProbeRecord.model_validate(r))


@pytest.fixture
def clock() -> Clock:
    return Clock(T0 / 1000)


@pytest.fixture
def hub(clock: Clock) -> LiveHub:
    return LiveHub(load_thresholds(THRESHOLDS), retention_s=900, no_data_after_s=10, clock=clock)


def summary(hub: LiveHub, key: str = "p1/dc1-voice") -> dict[str, Any]:
    return hub.summary(hub.sessions[key])


def test_ten_pps_cannot_prove_one_percent_in_thirty_seconds(hub: LiveHub, clock: Clock) -> None:
    # 300 packets, zero loss: the 95% bound is 1.26%, above the 1% voice target.
    feed(hub, clock, 30)
    s = summary(hub)
    assert s["status"] == "insufficient-samples"
    assert s["w30"]["loss_pct"] == 0
    assert 1.2 < s["w30"]["loss_hi_pct"] < 1.3
    assert "not yet provable" in s["reasons"][0]


def test_twenty_pps_proves_it(hub: LiveHub, clock: Clock) -> None:
    rtts = [21000 + 20 * i for i in range(20)]
    feed(hub, clock, 30, sent=20, received=20, rtt_us=rtts, rtt_jitter_n=19, ipdv_fwd_n=19, ipdv_back_n=19)
    s = summary(hub)
    assert s["status"] == "good", s["reasons"]
    assert s["reasons"] == []
    assert s["w10"]["rtt_p50_ms"] == pytest.approx(21.19, abs=0.01)


@pytest.mark.parametrize(("lose_every", "expected"), [(5, "degraded"), (2, "bad")])
def test_loss_grades(hub: LiveHub, clock: Clock, lose_every: int, expected: str) -> None:
    # 1 lost per 10 sent on every 5th second = 2%; every 2nd second = 5%
    feed(hub, clock, 30, lose_every=lose_every)
    s = summary(hub)
    assert s["status"] == expected
    assert any("loss" in r for r in s["reasons"])
    assert s["w30"]["fwd_loss_pct"] == s["w30"]["loss_pct"]
    assert s["w30"]["back_loss_pct"] == 0


def test_rtt_and_jitter_grades(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 40, sent=20, received=20, rtt_us=[180_000] * 20, rtt_jitter_n=19, ipdv_fwd_n=19,
         ipdv_back_n=19)
    s = summary(hub)
    assert s["status"] == "degraded"
    assert any("RTT p95 180 ms" in r for r in s["reasons"])
    feed(hub, clock, 40, start_ms=T0 + 40_000, sent=20, received=20, rtt_us=[20_000] * 20, rtt_jitter_n=19,
         ipdv_fwd_sum_us=19 * 60_000, ipdv_fwd_n=19, ipdv_back_n=19)
    s = summary(hub)
    assert s["status"] == "bad"
    assert s["w10"]["ipdv_fwd_ms"] == 60.0
    assert any("jitter 60.0 ms" in r for r in s["reasons"])


def test_jitter_not_graded_for_bulk(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 40, app_class="bulk", session="dc1-bulk", ipdv_fwd_sum_us=9 * 90_000)
    s = summary(hub, "p1/dc1-bulk")
    assert s["status"] == "good"
    assert s["w10"]["jitter_ms"] == 90.0


def test_unknown_class_falls_back_to_default(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 5, app_class="mystery")
    assert summary(hub)["effective_class"] == "bulk"


def test_icmp_is_reachability_only(hub: LiveHub, clock: Clock) -> None:
    icmp: dict[str, Any] = {"kind": "icmp", "session": "gw", "dst": "10.0.0.1:0", "fwd_lost": None, "back_lost": None,
            "ipdv_fwd_sum_us": 0, "ipdv_fwd_n": 0, "ipdv_back_sum_us": 0, "ipdv_back_n": 0,
            "sent": 1, "received": 1, "rtt_us": [900_000], "rtt_jitter_n": 0}
    feed(hub, clock, 30, **icmp)
    s = summary(hub, "p1/gw")
    assert s["status"] == "good"  # 900 ms ICMP RTT is shown but never graded
    feed(hub, clock, 10, start_ms=T0 + 30_000, **{**icmp, "received": 0, "lost": 1, "rtt_us": [],
                                                   "errors": {"timeout": 1}})
    s = summary(hub, "p1/gw")
    assert s["status"] == "bad"
    assert s["reasons"][0].startswith("unreachable")


def test_tcp_connect_failures(hub: LiveHub, clock: Clock) -> None:
    tcp: dict[str, Any] = {"kind": "tcp", "session": "m365", "dst": "52.96.0.10:443", "app_class": "interactive",
           "fwd_lost": None, "back_lost": None, "ipdv_fwd_sum_us": 0, "ipdv_fwd_n": 0, "ipdv_back_sum_us": 0,
           "ipdv_back_n": 0, "sent": 1, "received": 1, "rtt_us": [30_000], "rtt_jitter_n": 0}
    for i in range(6):
        r = make_record(ts_ms=T0 + i * 5000, **tcp)
        if i == 2:
            r = {**r, "received": 0, "lost": 1, "rtt_us": [], "errors": {"refused": 1}}
        clock.t = (T0 + i * 5000) / 1000 + 3
        hub.ingest(ProbeRecord.model_validate(r))
    s = summary(hub, "p1/m365")
    assert s["status"] == "degraded"
    assert "1 of 6 connects failed (refused 1)" in s["reasons"][0]


def test_no_data_after_silence(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 5)
    clock.t += 11
    s = summary(hub)
    assert s["status"] == "no-data"
    assert s["age_s"] >= 11


def test_windows_anchor_on_latest_record_not_wall_clock(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 60)
    s = summary(hub)
    assert (s["w10"]["seconds"], s["w30"]["seconds"], s["w60"]["seconds"]) == (10, 30, 60)


def test_path_change_detected(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 5, ttl_fwd=57)
    feed(hub, clock, 5, start_ms=T0 + 5000, ttl_fwd=55)
    pc = summary(hub)["path_change"]
    assert pc == {"ts_ms": T0 + 5000, "direction": "fwd", "hops_from": 7, "hops_to": 9}


def test_retention_trim(clock: Clock) -> None:
    hub = LiveHub(load_thresholds(THRESHOLDS), retention_s=60, clock=clock)
    feed(hub, clock, 120)
    st = hub.sessions["p1/dc1-voice"]
    assert len(st.points) == 60
    assert st.ts_index[0] == T0 + 60_000


def test_out_of_order_and_overwrite(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 3, start_ms=T0 + 2000)
    hub.ingest(ProbeRecord.model_validate(make_record(ts_ms=T0)))
    hub.ingest(ProbeRecord.model_validate(make_record(ts_ms=T0)))
    assert hub.sessions["p1/dc1-voice"].ts_index == [T0, T0 + 2000, T0 + 3000, T0 + 4000]


def test_change_log_increments_and_truncation(monkeypatch: pytest.MonkeyPatch, clock: Clock) -> None:
    monkeypatch.setattr(live_mod, "CHANGE_LOG_MAX", 5)
    hub = LiveHub(load_thresholds(THRESHOLDS), clock=clock)
    feed(hub, clock, 3)
    seq = hub.seq
    feed(hub, clock, 2, start_ms=T0 + 3000)
    delta = hub.changes_since(seq)
    assert delta is not None
    assert [p[0] for p in delta["p1/dc1-voice"]] == [T0 + 3000, T0 + 4000]
    assert hub.changes_since(hub.seq) == {}
    feed(hub, clock, 10, start_ms=T0 + 5000)
    assert hub.changes_since(seq) is None  # log no longer reaches back: client must take a backfill


def test_snapshot_is_sorted_and_cached(hub: LiveHub, clock: Clock) -> None:
    feed(hub, clock, 3, site="B-SITE")
    feed(hub, clock, 3, site="A-SITE", probe_id="p2")
    snap = hub.snapshot()
    assert [s["site"] for s in snap] == ["A-SITE", "B-SITE"]
    assert hub.snapshot() is snap


def test_per_target_override_changes_the_grade_and_reload_regrades(hub: LiveHub, clock: Clock) -> None:
    # A London site whose best path to DC1 is ~150 ms: degraded against the voice class...
    feed(hub, clock, 40, site="LON-BR03", sent=20, received=20, rtt_us=[150_000] * 20, rtt_jitter_n=19,
         ipdv_fwd_n=19, ipdv_back_n=19)
    s = summary(hub)
    assert s["status"] == "degraded" and s["threshold_override"] is None
    assert s["thresholds"]["rtt_p95_ms"] == {"good": 100.0, "bad": 300.0}

    # ...and good once an override for that site/target is applied.
    raw = yaml.safe_load(THRESHOLDS.read_text())
    raw["overrides"] = [{"name": "lon-dc1", "match": {"site": "LON-*", "session": "dc1-*"},
                         "rtt_p95_ms": {"good": 180, "bad": 300}}]
    hub.set_thresholds(Thresholds.model_validate(raw))
    s = summary(hub)
    assert s["status"] == "good", s["reasons"]
    assert s["threshold_override"] == "lon-dc1"
    assert s["thresholds"]["rtt_p95_ms"] == {"good": 180.0, "bad": 300.0}
    assert s["thresholds"]["loss_pct"] == {"good": 1.0, "bad": 3.0}, "unset metrics keep the class limits"
