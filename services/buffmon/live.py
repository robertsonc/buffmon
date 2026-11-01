"""In-memory live hub: the real-time path from ingest to the dashboard.

Keeps the last ``retention_s`` seconds of 1-second records per session, computes
rolling 10/30/60 s windows and a status per session (docs/DESIGN.md §6). It does
not depend on ClickHouse, so the live view keeps working when storage is down.

Windows are anchored on the newest record of each session, not on wall-clock
"now": records arrive ``1 s + probe timeout`` after the fact, and anchoring on
"now" would make every window look partially empty.
"""

from __future__ import annotations

import bisect
import time
from array import array
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .models import ProbeRecord
from .stats import hops_from_ttl, percentile, ratio, wilson_upper
from .thresholds import ClassThresholds, Thresholds

WINDOWS_S = (10, 30, 60)
STATUS_RANK = {"good": 0, "insufficient-samples": 1, "degraded": 2, "bad": 3}
CHANGE_LOG_MAX = 250_000


def _r(value: float | None, digits: int = 2) -> float | None:
    return None if value is None else round(value, digits)


@dataclass(slots=True)
class Point:
    ts_ms: int
    sent: int
    received: int
    lost: int
    late: int
    dup: int
    reordered: int
    fwd_lost: int | None
    back_lost: int | None
    rtt_sorted_us: array[int]
    rtt_jitter_sum_us: int
    rtt_jitter_n: int
    ipdv_fwd_sum_us: int
    ipdv_fwd_n: int
    ipdv_back_sum_us: int
    ipdv_back_n: int
    owd_fwd_sum_us: int | None
    owd_back_sum_us: int | None
    owd_n: int
    ttl_fwd: int | None
    ttl_back: int | None
    errors: dict[str, int]
    view: list[float | int | None]  # [ts_ms, rtt_p50_ms, rtt_p95_ms, loss_pct, jitter_ms]

    @classmethod
    def from_record(cls, rec: ProbeRecord) -> Point:
        rtts = array("I", sorted(rec.rtt_us))
        p50 = percentile(rtts, 0.5)
        p95 = percentile(rtts, 0.95)
        jitter = _point_jitter_ms(rec.kind, rec.ipdv_fwd_sum_us, rec.ipdv_fwd_n, rec.ipdv_back_sum_us,
                                  rec.ipdv_back_n, rec.rtt_jitter_sum_us, rec.rtt_jitter_n)
        loss = ratio(100.0 * rec.lost, rec.sent)
        view: list[float | int | None] = [
            rec.ts_ms,
            _r(None if p50 is None else p50 / 1000.0),
            _r(None if p95 is None else p95 / 1000.0),
            _r(loss),
            _r(jitter),
        ]
        return cls(
            ts_ms=rec.ts_ms, sent=rec.sent, received=rec.received, lost=rec.lost, late=rec.late,
            dup=rec.dup, reordered=rec.reordered, fwd_lost=rec.fwd_lost, back_lost=rec.back_lost,
            rtt_sorted_us=rtts, rtt_jitter_sum_us=rec.rtt_jitter_sum_us, rtt_jitter_n=rec.rtt_jitter_n,
            ipdv_fwd_sum_us=rec.ipdv_fwd_sum_us, ipdv_fwd_n=rec.ipdv_fwd_n,
            ipdv_back_sum_us=rec.ipdv_back_sum_us, ipdv_back_n=rec.ipdv_back_n,
            owd_fwd_sum_us=rec.owd_fwd_sum_us, owd_back_sum_us=rec.owd_back_sum_us, owd_n=rec.owd_n,
            ttl_fwd=rec.ttl_fwd, ttl_back=rec.ttl_back, errors=dict(rec.errors), view=view,
        )


def _point_jitter_ms(kind: str, f_sum: int, f_n: int, b_sum: int, b_n: int, r_sum: int, r_n: int) -> float | None:
    """Jitter used for status and charts: worst direction of mean |IPDV| for STAMP,
    mean |ΔRTT| otherwise."""
    if kind == "stamp" and (f_n or b_n):
        vals = [s / n / 1000.0 for s, n in ((f_sum, f_n), (b_sum, b_n)) if n]
        return max(vals)
    if r_n:
        return r_sum / r_n / 1000.0
    return None


@dataclass(slots=True)
class SessionState:
    probe_id: str
    session: str
    site: str
    kind: str
    app_class: str
    dscp: int
    src: str
    dst: str
    rx_ts: str = "kernel"
    clock_synced: bool = False
    clock_err_us: int | None = None
    points: dict[int, Point] = field(default_factory=dict)
    ts_index: list[int] = field(default_factory=list)
    last_arrival: float = 0.0
    path_change: dict[str, Any] | None = None

    @property
    def key(self) -> str:
        return f"{self.probe_id}/{self.session}"

    @property
    def last_ts_ms(self) -> int | None:
        return self.ts_index[-1] if self.ts_index else None

    def window(self, seconds: int) -> list[Point]:
        last = self.last_ts_ms
        if last is None:
            return []
        lo = bisect.bisect_right(self.ts_index, last - seconds * 1000)
        return [self.points[t] for t in self.ts_index[lo:]]


def window_stats(points: Iterable[Point], kind: str) -> dict[str, Any]:
    sent = received = lost = late = dup = reordered = 0
    fwd = back = dir_sent = 0
    has_dir = False
    j_sum = j_n = f_sum = f_n = b_sum = b_n = 0
    owd_f = owd_b = owd_n = 0
    errors: dict[str, int] = {}
    rtts: list[int] = []
    seconds = 0
    for p in points:
        seconds += 1
        sent += p.sent
        received += p.received
        lost += p.lost
        late += p.late
        dup += p.dup
        reordered += p.reordered
        if p.fwd_lost is not None and p.back_lost is not None:
            has_dir = True
            fwd += p.fwd_lost
            back += p.back_lost
            dir_sent += p.sent
        j_sum += p.rtt_jitter_sum_us
        j_n += p.rtt_jitter_n
        f_sum += p.ipdv_fwd_sum_us
        f_n += p.ipdv_fwd_n
        b_sum += p.ipdv_back_sum_us
        b_n += p.ipdv_back_n
        if p.owd_n and p.owd_fwd_sum_us is not None and p.owd_back_sum_us is not None:
            owd_f += p.owd_fwd_sum_us
            owd_b += p.owd_back_sum_us
            owd_n += p.owd_n
        for k, v in p.errors.items():
            errors[k] = errors.get(k, 0) + v
        rtts.extend(p.rtt_sorted_us)
    rtts.sort()
    p50 = percentile(rtts, 0.5)
    p95 = percentile(rtts, 0.95)
    loss_pct = ratio(100.0 * lost, sent)
    return {
        "seconds": seconds,
        "sent": sent,
        "received": received,
        "lost": lost,
        "late": late,
        "dup": dup,
        "reordered": reordered,
        "loss_pct": _r(loss_pct, 3),
        "loss_hi_pct": _r(100.0 * wilson_upper(lost, sent), 3) if sent else None,
        "rtt_p50_ms": _r(None if p50 is None else p50 / 1000.0),
        "rtt_p95_ms": _r(None if p95 is None else p95 / 1000.0),
        "rtt_max_ms": _r(rtts[-1] / 1000.0) if rtts else None,
        "jitter_ms": _r(_point_jitter_ms(kind, f_sum, f_n, b_sum, b_n, j_sum, j_n)),
        "rtt_jitter_ms": _r(ratio(j_sum, j_n * 1000.0) if j_n else None),
        "ipdv_fwd_ms": _r(f_sum / f_n / 1000.0) if f_n else None,
        "ipdv_back_ms": _r(b_sum / b_n / 1000.0) if b_n else None,
        "fwd_lost": fwd if has_dir else None,
        "back_lost": back if has_dir else None,
        "fwd_loss_pct": _r(ratio(100.0 * fwd, dir_sent), 3) if has_dir else None,
        "back_loss_pct": _r(ratio(100.0 * back, dir_sent), 3) if has_dir else None,
        "owd_fwd_ms": _r(owd_f / owd_n / 1000.0) if owd_n else None,
        "owd_back_ms": _r(owd_b / owd_n / 1000.0) if owd_n else None,
        "errors": errors,
    }


def evaluate(
    kind: str, th: ClassThresholds, loss_w: dict[str, Any], lat_w: dict[str, Any], reach_w: dict[str, Any],
    loss_window_s: int, latency_window_s: int,
) -> tuple[str, list[str]]:
    """Status and human-readable reasons for one session (DESIGN §6)."""
    grades: list[tuple[str, str | None]] = []

    if kind == "icmp":
        # ICMP is reachability only (DESIGN D3): RTT and jitter are shown, never graded.
        if reach_w["sent"] and reach_w["received"] == 0:
            grades.append(("bad", f"unreachable: no echo replies in {reach_w['seconds']} s"))
        elif loss_w["loss_pct"] is not None and loss_w["loss_pct"] > th.loss_pct.good:
            grades.append(("degraded", f"echo loss {loss_w['loss_pct']:.1f}% ({loss_window_s} s)"))
        else:
            grades.append(("good", None))
    elif kind == "tcp":
        attempts, failed = loss_w["sent"], loss_w["lost"]
        why = ", ".join(f"{k} {v}" for k, v in sorted(loss_w["errors"].items())) or "no reason"
        if attempts and failed == attempts:
            grades.append(("bad", f"all {attempts} connects failed in {loss_window_s} s ({why})"))
        elif failed:
            grades.append(("degraded", f"{failed} of {attempts} connects failed ({why})"))
        if lat_w["rtt_p95_ms"] is not None:
            g = th.rtt_p95_ms.grade(lat_w["rtt_p95_ms"])
            grades.append((g, None if g == "good" else
                           f"handshake p95 {lat_w['rtt_p95_ms']:.0f} ms > {th.rtt_p95_ms.good:g} ms"))
    else:  # stamp
        lp, hi = loss_w["loss_pct"], loss_w["loss_hi_pct"]
        if lp is not None and hi is not None:
            g = th.loss_pct.grade(lp)
            if g == "good" and hi > th.loss_pct.good:
                grades.append(("insufficient-samples",
                               f"loss ≤ {th.loss_pct.good:g}% not yet provable: {loss_w['sent']} packets, "
                               f"95% bound {hi:.2f}%"))
            elif g == "good":
                grades.append(("good", None))
            else:
                grades.append((g, f"loss {lp:.2f}% > {th.loss_pct.good:g}% ({loss_window_s} s)"))
        p95 = lat_w["rtt_p95_ms"]
        if p95 is not None:
            g = th.rtt_p95_ms.grade(p95)
            grades.append((g, None if g == "good" else
                           f"RTT p95 {p95:.0f} ms > {th.rtt_p95_ms.good:g} ms ({latency_window_s} s)"))
        jit = lat_w["jitter_ms"]
        if th.jitter_ms is not None and jit is not None:
            g = th.jitter_ms.grade(jit)
            grades.append((g, None if g == "good" else
                           f"jitter {jit:.1f} ms > {th.jitter_ms.good:g} ms ({latency_window_s} s)"))

    if not grades:
        return "no-data", ["no samples in window"]
    worst = max(grades, key=lambda g: STATUS_RANK[g[0]])[0]
    reasons = [r for g, r in sorted(grades, key=lambda g: -STATUS_RANK[g[0]]) if r]
    return worst, reasons


class LiveHub:
    def __init__(
        self,
        thresholds: Thresholds,
        retention_s: int = 900,
        session_expiry_s: int = 3600,
        no_data_after_s: float = 10.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.thresholds = thresholds
        self.retention_ms = retention_s * 1000
        self.session_expiry_s = session_expiry_s
        self.no_data_after_s = no_data_after_s
        self._clock = clock
        self.sessions: dict[str, SessionState] = {}
        self.seq = 0
        self._changes: deque[tuple[int, str, int]] = deque(maxlen=CHANGE_LOG_MAX)
        self._snapshot_cache: tuple[int, list[dict[str, Any]]] | None = None

    # -- writes ---------------------------------------------------------------
    def ingest(self, rec: ProbeRecord) -> None:
        now = self._clock()
        key = rec.session_key
        st = self.sessions.get(key)
        if st is None:
            st = SessionState(probe_id=rec.probe_id, session=rec.session, site=rec.site, kind=rec.kind,
                              app_class=rec.app_class, dscp=rec.dscp, src=rec.src, dst=rec.dst)
            self.sessions[key] = st
        newest = st.last_ts_ms is None or rec.ts_ms > st.last_ts_ms
        if newest:
            prev = st.points.get(st.last_ts_ms) if st.last_ts_ms is not None else None
            if prev is not None:
                self._detect_path_change(st, prev, rec)
            st.site, st.kind, st.app_class, st.dscp = rec.site, rec.kind, rec.app_class, rec.dscp
            st.src, st.dst, st.rx_ts = rec.src, rec.dst, rec.rx_ts
            st.clock_synced, st.clock_err_us = rec.clock_synced, rec.clock_err_us
        if rec.ts_ms not in st.points:
            bisect.insort(st.ts_index, rec.ts_ms)
        st.points[rec.ts_ms] = Point.from_record(rec)
        st.last_arrival = now
        self.seq += 1
        self._changes.append((self.seq, key, rec.ts_ms))
        self._snapshot_cache = None
        self._trim(st)

    @staticmethod
    def _detect_path_change(st: SessionState, prev: Point, rec: ProbeRecord) -> None:
        for direction, old, new in (("fwd", prev.ttl_fwd, rec.ttl_fwd), ("back", prev.ttl_back, rec.ttl_back)):
            if old is not None and new is not None and old != new:
                st.path_change = {
                    "ts_ms": rec.ts_ms,
                    "direction": direction,
                    "hops_from": hops_from_ttl(old),
                    "hops_to": hops_from_ttl(new),
                }

    def _trim(self, st: SessionState) -> None:
        last = st.last_ts_ms
        if last is None:
            return
        cut = bisect.bisect_right(st.ts_index, last - self.retention_ms)
        if cut:
            for t in st.ts_index[:cut]:
                del st.points[t]
            del st.ts_index[:cut]

    def expire(self) -> int:
        """Drops sessions that have not reported for ``session_expiry_s``."""
        now = self._clock()
        stale = [k for k, s in self.sessions.items() if now - s.last_arrival > self.session_expiry_s]
        for k in stale:
            del self.sessions[k]
        if stale:
            self._snapshot_cache = None
        return len(stale)

    # -- reads ----------------------------------------------------------------
    def summary(self, st: SessionState) -> dict[str, Any]:
        now = self._clock()
        th_cfg = self.thresholds
        eff_class, th = th_cfg.for_class(st.app_class)
        needed = {*WINDOWS_S, th_cfg.windows.loss_s, th_cfg.windows.latency_s}
        computed = {s: window_stats(st.window(s), st.kind) for s in needed}
        windows = {f"w{s}": computed[s] for s in WINDOWS_S}
        age_s = now - st.last_arrival
        loss_w = computed[th_cfg.windows.loss_s]
        lat_w = computed[th_cfg.windows.latency_s]
        if age_s > self.no_data_after_s:
            status, reasons = "no-data", [f"no records for {age_s:.0f} s"]
        else:
            status, reasons = evaluate(st.kind, th, loss_w, lat_w, lat_w,
                                       th_cfg.windows.loss_s, th_cfg.windows.latency_s)
        last = st.points[st.last_ts_ms] if st.last_ts_ms is not None else None
        path_change = st.path_change
        if path_change and st.last_ts_ms is not None and st.last_ts_ms - path_change["ts_ms"] > self.retention_ms:
            path_change = None
        return {
            "key": st.key,
            "probe_id": st.probe_id,
            "site": st.site,
            "session": st.session,
            "kind": st.kind,
            "app_class": st.app_class,
            "effective_class": eff_class,
            "dscp": st.dscp,
            "src": st.src,
            "dst": st.dst,
            "status": status,
            "reasons": reasons,
            "last_ts_ms": st.last_ts_ms,
            "age_s": round(age_s, 1),
            **windows,
            "ttl_fwd": last.ttl_fwd if last else None,
            "ttl_back": last.ttl_back if last else None,
            "hops_fwd": hops_from_ttl(last.ttl_fwd) if last else None,
            "hops_back": hops_from_ttl(last.ttl_back) if last else None,
            "path_change": path_change,
            "clock_synced": st.clock_synced,
            "clock_err_us": st.clock_err_us,
            "rx_ts": st.rx_ts,
        }

    def snapshot(self) -> list[dict[str, Any]]:
        """Summaries of every session, cached per wall-clock second so many
        dashboard connections share one computation."""
        tick = int(self._clock())
        if self._snapshot_cache is not None and self._snapshot_cache[0] == tick:
            return self._snapshot_cache[1]
        out = [self.summary(s) for s in sorted(self.sessions.values(), key=lambda s: (s.site, s.probe_id, s.session))]
        self._snapshot_cache = (tick, out)
        return out

    def series(self, key: str) -> list[list[float | int | None]]:
        st = self.sessions.get(key)
        if st is None:
            return []
        return [st.points[t].view for t in st.ts_index]

    def backfill(self) -> dict[str, list[list[float | int | None]]]:
        return {k: self.series(k) for k in self.sessions}

    def changes_since(self, seq: int) -> dict[str, list[list[float | int | None]]] | None:
        """Points stored after ``seq``, grouped by session. None when the change
        log no longer reaches back that far (the client must take a backfill)."""
        if seq >= self.seq:
            return {}
        if not self._changes or self._changes[0][0] > seq + 1:
            return None
        seen: set[tuple[str, int]] = set()
        out: dict[str, list[list[float | int | None]]] = {}
        for change_seq, key, ts in reversed(self._changes):
            if change_seq <= seq:
                break
            if (key, ts) in seen:
                continue
            seen.add((key, ts))
            st = self.sessions.get(key)
            if st is None or ts not in st.points:
                continue
            out.setdefault(key, []).append(st.points[ts].view)
        for pts in out.values():
            pts.sort(key=lambda v: v[0] or 0)
        return out
