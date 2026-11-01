"""Phase 3 results: forward route traces and packet-train capacity.

Validation (the probe is never trusted), ClickHouse rows, the in-memory "latest
per session" view the dashboard reads, and the history queries.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict, deque
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from .models import CLASS_PATTERN, ERROR_KEY_PATTERN, MAX_RTT_US, NAME_PATTERN, Ttl, parse_endpoint
from .store import CAPACITY_TABLE, ROUTE_TABLE, Transport, ts_text

__all__ = ["CAPACITY_TABLE", "ROUTE_TABLE", "CapacityResult", "RouteResult", "RouteView"]

MAX_HOPS = 64
MAX_SIGNATURE = 8192
MAX_BPS = 10**12

Bps = Annotated[StrictInt, Field(ge=0, le=MAX_BPS)] | None
Small = Annotated[StrictInt, Field(ge=0, le=255)]


class _Header(BaseModel):
    """Fields every probe result shares with the v1 record."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    v: Literal[1]
    probe_id: Annotated[str, Field(pattern=NAME_PATTERN)]
    site: Annotated[str, Field(min_length=1, max_length=64)]
    session: Annotated[str, Field(pattern=NAME_PATTERN)]
    app_class: Annotated[str, Field(pattern=CLASS_PATTERN)]
    dscp: Annotated[StrictInt, Field(ge=0, le=63)]
    src: str
    dst: str
    ts_ms: Annotated[StrictInt, Field(gt=0)]

    @field_validator("site")
    @classmethod
    def _site_printable(cls, v: str) -> str:
        if not v.isprintable() or v != v.strip():
            raise ValueError("site must be printable with no leading/trailing whitespace")
        return v

    @field_validator("src", "dst")
    @classmethod
    def _endpoint(cls, v: str) -> str:
        parse_endpoint(v)
        return v

    @property
    def key(self) -> tuple[str, str, str, int]:
        """Idempotency key (kind-qualified, so it never collides with a record's)."""
        return (str(getattr(self, "kind", "")), self.probe_id, self.session, self.ts_ms)

    @property
    def session_key(self) -> str:
        return f"{self.probe_id}/{self.session}"


class Hop(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    ttl: Annotated[StrictInt, Field(ge=1, le=MAX_HOPS)]
    addrs: Annotated[list[str], Field(max_length=8)]
    rtt_us: Annotated[StrictInt, Field(ge=0, le=MAX_RTT_US)] | None = None
    sent: Annotated[StrictInt, Field(ge=0, le=16)]
    replies: Small
    unreachable: Small | None = None

    @field_validator("addrs")
    @classmethod
    def _ipv4(cls, v: list[str]) -> list[str]:
        for a in v:
            try:
                ipaddress.IPv4Address(a)
            except ValueError as exc:
                raise ValueError(f"{a!r} is not an IPv4 address") from exc
        if len(set(v)) != len(v):
            raise ValueError("addrs must be distinct")
        return v


def signature(hops: list[Hop]) -> str:
    return ">".join("|".join(h.addrs) if h.addrs else "*" for h in hops)


class RouteResult(_Header):
    kind: Literal["route"]
    duration_ms: Annotated[StrictInt, Field(ge=0, le=600_000)]
    trigger: Literal["start", "schedule", "ttl_change"]
    ttl_fwd: Ttl = None
    ttl_back: Ttl = None
    hop_count_fwd: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    hops: Annotated[list[Hop], Field(max_length=MAX_HOPS)]
    complete: StrictBool
    multipath: StrictBool
    signature: Annotated[str, Field(max_length=MAX_SIGNATURE)]
    changed: StrictBool
    change_ttl: Annotated[StrictInt, Field(ge=1, le=MAX_HOPS)] | None = None
    change_reason: Literal["hop", "length"] | None = None
    prev_signature: Annotated[str, Field(max_length=MAX_SIGNATURE)] | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if [h.ttl for h in self.hops] != list(range(1, len(self.hops) + 1)):
            raise ValueError("hops must be TTL 1, 2, 3, ... in order")
        if self.signature != signature(self.hops):
            raise ValueError("signature does not match hops")
        if self.changed != (self.change_reason is not None):
            raise ValueError("change_reason is set exactly when changed")
        if not self.changed and (self.change_ttl is not None or self.prev_signature is not None):
            raise ValueError("change_ttl/prev_signature need changed")
        if self.multipath != any(len(h.addrs) > 1 for h in self.hops):
            raise ValueError("multipath does not match hops")
        return self


class CapacityResult(_Header):
    kind: Literal["capacity"]
    packets: Annotated[StrictInt, Field(ge=1, le=1024)]
    size: Annotated[StrictInt, Field(ge=44, le=1472)]
    trains: Annotated[StrictInt, Field(ge=1, le=100)]
    valid_trains: Annotated[StrictInt, Field(ge=0, le=100)]
    fwd_bps: Bps = None
    fwd_bps_min: Bps = None
    fwd_bps_max: Bps = None
    fwd_adr_bps: Bps = None
    burst_trains: Annotated[StrictInt, Field(ge=0, le=100)]
    burst_bytes: Annotated[StrictInt, Field(ge=0, le=10**9)] | None = None
    back_bps: Bps = None
    back_is_lower_bound: StrictBool
    lost: Annotated[StrictInt, Field(ge=0, le=102_400)]
    invalid: Annotated[
        dict[Annotated[str, Field(pattern=ERROR_KEY_PATTERN)], Annotated[StrictInt, Field(ge=0, le=100)]],
        Field(max_length=8),
    ]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.valid_trains > self.trains or self.burst_trains > self.valid_trains:
            raise ValueError("burst_trains <= valid_trains <= trains")
        if self.lost > self.trains * self.packets:
            raise ValueError("lost exceeds packets sent")
        if self.valid_trains == 0 and self.fwd_bps is not None:
            raise ValueError("fwd_bps needs a valid train")
        lo, mid, hi = self.fwd_bps_min, self.fwd_bps, self.fwd_bps_max
        if None not in (lo, mid, hi) and not (lo <= mid <= hi):  # type: ignore[operator]
            raise ValueError("fwd_bps_min <= fwd_bps <= fwd_bps_max")
        return self


# -- ClickHouse rows ---------------------------------------------------------------

def route_to_row(r: RouteResult) -> dict[str, Any]:
    return {
        "ts": ts_text(r.ts_ms),
        "probe_id": r.probe_id,
        "site": r.site,
        "session": r.session,
        "app_class": r.app_class,
        "dscp": r.dscp,
        "src": r.src,
        "dst": r.dst,
        "trigger": r.trigger,
        "duration_ms": r.duration_ms,
        "ttl_fwd": r.ttl_fwd,
        "ttl_back": r.ttl_back,
        "hop_count_fwd": r.hop_count_fwd,
        "hop_addrs": [h.addrs for h in r.hops],
        "hop_rtt_us": [h.rtt_us for h in r.hops],
        "hop_sent": [h.sent for h in r.hops],
        "hop_replies": [h.replies for h in r.hops],
        "hop_unreachable": [h.unreachable for h in r.hops],
        "complete": r.complete,
        "multipath": r.multipath,
        "signature": r.signature,
        "changed": r.changed,
        "change_ttl": r.change_ttl,
        "change_reason": r.change_reason,
        "prev_signature": r.prev_signature,
    }


def capacity_to_row(c: CapacityResult) -> dict[str, Any]:
    row = c.model_dump(exclude={"v", "kind", "ts_ms"})
    row["ts"] = ts_text(c.ts_ms)
    return row


# -- latest per session (dashboard) --------------------------------------------------

class RouteView:
    """Latest route trace, recent route changes and latest capacity result per
    session, in memory. Bounded: the least recently updated sessions go first."""

    def __init__(self, max_sessions: int = 10_000, keep_changes: int = 10) -> None:
        self._max = max_sessions
        self._keep = keep_changes
        self._s: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._s)

    def _entry(self, key: str) -> dict[str, Any]:
        e = self._s.get(key)
        if e is None:
            e = {"route": None, "changes": deque(maxlen=self._keep), "capacity": None}
            self._s[key] = e
            while len(self._s) > self._max:
                self._s.popitem(last=False)
        self._s.move_to_end(key)
        return e

    def add_route(self, r: RouteResult) -> None:
        e = self._entry(r.session_key)
        cur = e["route"]
        if cur is None or r.ts_ms >= cur["ts_ms"]:
            e["route"] = r.model_dump()
        if r.changed:
            e["changes"].appendleft(
                {k: v for k, v in r.model_dump().items()
                 if k in ("ts_ms", "signature", "prev_signature", "change_ttl", "change_reason", "trigger")}
            )

    def add_capacity(self, c: CapacityResult) -> None:
        e = self._entry(c.session_key)
        cur = e["capacity"]
        if cur is None or c.ts_ms >= cur["ts_ms"]:
            e["capacity"] = c.model_dump()

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            k: {"route": e["route"], "changes": list(e["changes"]), "capacity": e["capacity"]}
            for k, e in self._s.items()
        }


# -- history ------------------------------------------------------------------------

ROUTES_SQL = """
SELECT
    toUnixTimestamp64Milli(ts) AS ts_ms,
    trigger, hop_count_fwd, signature, changed, change_ttl, change_reason, prev_signature,
    complete, multipath
FROM route_traces FINAL
WHERE probe_id = {probe_id:String} AND session = {session:String}
  AND ts >= fromUnixTimestamp64Milli({from_ms:Int64})
ORDER BY ts DESC
LIMIT {limit:UInt32}
"""

CAPACITY_SQL = """
SELECT
    toUnixTimestamp64Milli(ts) AS ts_ms,
    dscp, packets, size, trains, valid_trains, fwd_bps, fwd_bps_min, fwd_bps_max, fwd_adr_bps,
    burst_trains, burst_bytes, back_bps, back_is_lower_bound, lost
FROM capacity FINAL
WHERE probe_id = {probe_id:String} AND session = {session:String}
  AND ts >= fromUnixTimestamp64Milli({from_ms:Int64})
ORDER BY ts ASC
LIMIT {limit:UInt32}
"""


def _bool(v: Any) -> bool:
    return v in (True, 1, "1", "true")


async def query_route_history(
    transport: Transport, probe_id: str, session: str, from_ms: int, limit: int = 500
) -> dict[str, Any]:
    params: dict[str, str | int] = {"probe_id": probe_id, "session": session, "from_ms": from_ms, "limit": limit}
    traces = await transport.select(ROUTES_SQL, params)
    capacity = await transport.select(CAPACITY_SQL, params)
    for t in traces:
        for k in ("changed", "complete", "multipath"):
            t[k] = _bool(t[k])
    for c in capacity:
        c["back_is_lower_bound"] = _bool(c["back_is_lower_bound"])
    return {
        "probe_id": probe_id,
        "session": session,
        "from_ms": from_ms,
        "changes": [t for t in traces if t["changed"]],
        "traces": traces,
        "capacity": capacity,
    }
