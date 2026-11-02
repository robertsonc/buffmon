"""RFC 9946 (UDPSTP) speed tests on demand (P3.3, DESIGN D14).

A speed test fills the path for up to its duration, so it is never monitoring.
The collector side here decides *whether* a test may run; the probe then
applies its own limits again before it runs anything.

Policy (YAML, ``BUFFMON_SPEEDTEST_POLICY``; no file = speed tests disabled):

* which probes may be asked (glob patterns), the highest rate and longest
  duration a request may carry, the DSCPs allowed (never a priority class),
  optional time windows (in a named time zone) outside which requests are
  refused, and how many tests may run at once in total;
* one test per site at a time, so two probes behind one EdgeConnect never
  measure each other.

Jobs live in memory (the ingest service is a single process). A job a probe
took but never answered is marked lost after its duration plus a margin, so a
site is never locked forever.
"""

from __future__ import annotations

import fnmatch
import logging
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)

from .models import NAME_PATTERN
from .store import SPEEDTEST_TABLE, Transport, ts_text

__all__ = ["SPEEDTEST_TABLE", "JobBoard", "Policy", "PolicyError", "SpeedtestResult", "load_policy"]

log = logging.getLogger(__name__)

PRIORITY_DSCP_FROM = 32
Day = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAYS: tuple[Day, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
JOB_ID = r"^[A-Za-z0-9-]{1,64}$"
Direction = Literal["down", "up"]


class PolicyError(ValueError):
    pass


class Window(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    days: list[Day] = list(DAYS)
    start: Annotated[str, Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]
    end: Annotated[str, Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]
    tz: str = "UTC"

    @field_validator("tz")
    @classmethod
    def _tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {v!r}") from exc
        return v

    def open_at(self, now: float) -> bool:
        local = datetime.fromtimestamp(now, ZoneInfo(self.tz))
        minutes = local.hour * 60 + local.minute
        start = int(self.start[:2]) * 60 + int(self.start[3:])
        end = int(self.end[:2]) * 60 + int(self.end[3:])
        day = DAYS[local.weekday()]
        if start <= end:
            return day in self.days and start <= minutes < end
        # Overnight window (22:00-05:00): the part after midnight belongs to the previous day.
        prev = DAYS[(local.weekday() - 1) % 7]
        return (day in self.days and minutes >= start) or (prev in self.days and minutes < end)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: StrictBool = False
    probes: list[str] = []
    max_mbps: Annotated[StrictInt, Field(ge=1, le=10_000)] = 1000
    max_duration_s: Annotated[StrictInt, Field(ge=1, le=60)] = 10
    allowed_dscp: list[Annotated[StrictInt, Field(ge=0, le=PRIORITY_DSCP_FROM - 1)]] = list(range(PRIORITY_DSCP_FROM))
    windows: list[Window] = []
    max_concurrent: Annotated[StrictInt, Field(ge=1, le=100)] = 4

    def probe_allowed(self, probe_id: str) -> bool:
        return any(fnmatch.fnmatchcase(probe_id, p) for p in self.probes)

    def window_open(self, now: float) -> bool:
        return not self.windows or any(w.open_at(now) for w in self.windows)


DISABLED = Policy()


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return DISABLED
    try:
        raw = yaml.safe_load(path.read_text())
    except OSError as exc:
        raise PolicyError(f"cannot read speed-test policy {path}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise PolicyError(f"speed-test policy {path} is not valid YAML: {exc}") from exc
    try:
        return Policy.model_validate(raw or {})
    except ValidationError as exc:
        raise PolicyError(f"speed-test policy {path} is invalid:\n{exc}") from exc


# -- what probes send ------------------------------------------------------------------

class Capability(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    name: Annotated[str, Field(pattern=NAME_PATTERN)]
    server: Annotated[str, Field(min_length=1, max_length=260)]
    directions: Annotated[list[Direction], Field(min_length=1, max_length=2)]
    max_mbps: Annotated[StrictInt, Field(ge=1, le=10_000)]
    max_duration_s: Annotated[StrictInt, Field(ge=1, le=60)]
    dscp: Annotated[StrictInt, Field(ge=0, le=PRIORITY_DSCP_FROM - 1)]


class Poll(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    probe_id: Annotated[str, Field(pattern=NAME_PATTERN)]
    site: Annotated[str, Field(min_length=1, max_length=64)]
    targets: Annotated[list[Capability], Field(max_length=32)]


Ratio = Annotated[float, Field(ge=0.0, le=1.0)] | None
Mbps = Annotated[float, Field(ge=0.0, le=1e6)] | None
Ms = Annotated[float, Field(ge=0.0, le=600_000.0)] | None


class SpeedtestResult(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    v: Literal[1]
    probe_id: Annotated[str, Field(pattern=NAME_PATTERN)]
    site: Annotated[str, Field(min_length=1, max_length=64)]
    kind: Literal["speedtest"]
    target: Annotated[str, Field(min_length=1, max_length=64)]
    server: Annotated[str, Field(max_length=260)]
    job_id: Annotated[str, Field(pattern=JOB_ID)]
    direction: Direction
    ts_ms: Annotated[StrictInt, Field(gt=0)]
    duration_s: Annotated[StrictInt, Field(ge=0, le=60)]
    max_mbps: Annotated[StrictInt, Field(ge=0, le=10_000)]
    dscp: Annotated[StrictInt, Field(ge=0, le=63)]
    status: Literal["completed", "warning", "failed", "refused"]
    error_status: Annotated[StrictInt, Field(ge=0, le=255)] | None = None
    error: Annotated[str, Field(max_length=600)] | None = None
    max_ip_capacity_mbps: Mbps = None
    loss_ratio_at_max: Ratio = None
    rtt_range_ms_at_max: Ms = None
    pdv_range_ms_at_max: Ms = None
    summary_capacity_mbps: Mbps = None
    summary_loss_ratio: Ratio = None
    delivered_pct: Annotated[float, Field(ge=0.0, le=100.0)] | None = None
    ecn_bleaching: StrictBool | None = None
    udpst_version: Annotated[str, Field(max_length=32)] | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.status == "completed" and self.max_ip_capacity_mbps is None:
            raise ValueError("a completed test has max_ip_capacity_mbps")
        if self.status == "refused" and self.max_ip_capacity_mbps is not None:
            raise ValueError("a refused test has no result")
        return self

    @property
    def key(self) -> tuple[str, str, str]:
        return ("speedtest", self.probe_id, self.job_id)


def result_to_row(r: SpeedtestResult) -> dict[str, Any]:
    row = r.model_dump(exclude={"v", "kind", "ts_ms"})
    row["ts"] = ts_text(r.ts_ms)
    return row


# -- the job board ---------------------------------------------------------------------

ACTIVE = ("queued", "dispatched")


@dataclass
class Job:
    job_id: str
    probe_id: str
    site: str
    target: str
    direction: str
    max_mbps: int
    duration_s: int
    created: float
    state: str = "queued"
    dispatched_at: float | None = None
    finished_at: float | None = None
    result: dict[str, Any] | None = None
    note: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id, "probe_id": self.probe_id, "site": self.site, "target": self.target,
            "direction": self.direction, "max_mbps": self.max_mbps, "duration_s": self.duration_s,
            "state": self.state, "created_ms": int(self.created * 1000),
            "finished_ms": int(self.finished_at * 1000) if self.finished_at else None,
            "note": self.note, "result": self.result,
        }

    def for_probe(self) -> dict[str, Any]:
        return {"job_id": self.job_id, "target": self.target, "direction": self.direction,
                "max_mbps": self.max_mbps, "duration_s": self.duration_s}


@dataclass
class ProbeCaps:
    site: str
    targets: dict[str, Capability]
    last_poll: float


class Refused(Exception):
    """A request the policy, the probe's advertised limits or the coordination refuses."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass
class JobBoard:
    policy: Policy
    clock: Any = time.time
    poll_s: float = 15.0
    keep: int = 200
    jobs: OrderedDict[str, Job] = field(default_factory=OrderedDict)
    caps: dict[str, ProbeCaps] = field(default_factory=dict)

    # -- probes ----------------------------------------------------------------
    def poll(self, p: Poll) -> list[dict[str, Any]]:
        """A probe checks in: remember what it can test; hand it its queued jobs."""
        now = self.clock()
        self.caps[p.probe_id] = ProbeCaps(p.site, {t.name: t for t in p.targets}, now)
        self.expire(now)
        out = []
        for j in self.jobs.values():
            if j.probe_id == p.probe_id and j.state == "queued":
                j.state, j.dispatched_at = "dispatched", now
                out.append(j.for_probe())
        return out

    def complete(self, r: SpeedtestResult) -> bool:
        """Records a result; False if it does not answer a job this probe was given."""
        j = self.jobs.get(r.job_id)
        if j is None or j.probe_id != r.probe_id or j.state not in ACTIVE:
            return False
        j.state, j.finished_at = r.status, self.clock()
        j.result = r.model_dump(exclude={"v", "kind", "probe_id", "site", "job_id"})
        return True

    # -- people ----------------------------------------------------------------
    def request(self, probe_id: str, target: str, direction: str, max_mbps: int | None,
                duration_s: int | None) -> Job:
        now = self.clock()
        self.expire(now)
        pol = self.policy
        if not pol.enabled:
            raise Refused(403, "speed tests are disabled (no BUFFMON_SPEEDTEST_POLICY, or enabled: false)")
        if not pol.probe_allowed(probe_id):
            raise Refused(403, f"probe {probe_id} is not in the speed-test policy")
        if not pol.window_open(now):
            raise Refused(403, "outside the speed-test windows in the policy")
        caps = self.caps.get(probe_id)
        if caps is None or now - caps.last_poll > 3 * self.poll_s + 30:
            raise Refused(409, f"probe {probe_id} has not checked in for jobs recently (speed tests not enabled "
                               "on it, or it is offline)")
        cap = caps.targets.get(target)
        if cap is None:
            raise Refused(404, f"probe {probe_id} has no enabled speed-test target {target!r}")
        if direction not in cap.directions:
            raise Refused(403, f"direction {direction} is not allowed on {probe_id}/{target}")
        if cap.dscp not in pol.allowed_dscp:
            raise Refused(403, f"{probe_id}/{target} uses DSCP {cap.dscp}, which the policy does not allow")
        ceiling = min(pol.max_mbps, cap.max_mbps)
        mbps = ceiling if max_mbps is None else max_mbps
        if not 1 <= mbps <= ceiling:
            raise Refused(422, f"max_mbps must be 1-{ceiling} (policy {pol.max_mbps}, probe {cap.max_mbps})")
        longest = min(pol.max_duration_s, cap.max_duration_s)
        secs = longest if duration_s is None else duration_s
        if not 1 <= secs <= longest:
            raise Refused(422, f"duration_s must be 1-{longest}")
        busy = [j for j in self.jobs.values() if j.state in ACTIVE]
        same_site = [j for j in busy if j.site == caps.site]
        if same_site:
            raise Refused(409, f"a speed test is already running at site {caps.site} ({same_site[0].job_id}); "
                               "two at once would measure each other")
        if len(busy) >= pol.max_concurrent:
            raise Refused(429, f"{len(busy)} speed tests already running (policy max_concurrent)")
        job = Job(job_id=f"st-{secrets.token_hex(6)}", probe_id=probe_id, site=caps.site, target=target,
                  direction=direction, max_mbps=mbps, duration_s=secs, created=now)
        self.jobs[job.job_id] = job
        while len(self.jobs) > self.keep:
            oldest = next(iter(self.jobs))
            if self.jobs[oldest].state in ACTIVE:
                break
            self.jobs.popitem(last=False)
        log.warning("speed test %s queued: %s/%s %s up to %d Mbit/s for %d s", job.job_id, probe_id, target,
                    direction, mbps, secs)
        return job

    def expire(self, now: float) -> None:
        """Frees sites whose job will not come back."""
        for j in self.jobs.values():
            if j.state == "queued" and now - j.created > 3 * self.poll_s + 30:
                j.state, j.finished_at, j.note = "expired", now, "the probe did not pick it up"
            elif j.state == "dispatched" and j.dispatched_at and now - j.dispatched_at > j.duration_s + 90:
                j.state, j.finished_at, j.note = "lost", now, "no result from the probe"

    def snapshot(self) -> dict[str, Any]:
        self.expire(self.clock())
        return {
            "enabled": self.policy.enabled,
            "window_open": self.policy.window_open(self.clock()),
            "probes": {
                pid: {"site": c.site, "last_poll_ms": int(c.last_poll * 1000),
                      "allowed": self.policy.probe_allowed(pid),
                      "targets": [t.model_dump() for t in c.targets.values()]}
                for pid, c in self.caps.items()
            },
            "jobs": [j.public() for j in reversed(self.jobs.values())][:100],
        }


# -- history --------------------------------------------------------------------------

HISTORY_SQL = """
SELECT
    toUnixTimestamp64Milli(ts) AS ts_ms, probe_id, site, target, direction, job_id, status, max_mbps, duration_s,
    max_ip_capacity_mbps, loss_ratio_at_max, rtt_range_ms_at_max, pdv_range_ms_at_max, error
FROM speedtests FINAL
WHERE probe_id = {probe_id:String} AND ts >= fromUnixTimestamp64Milli({from_ms:Int64})
ORDER BY ts DESC
LIMIT 200
"""


async def query_history(transport: Transport, probe_id: str, from_ms: int) -> list[dict[str, Any]]:
    return await transport.select(HISTORY_SQL, {"probe_id": probe_id, "from_ms": from_ms})
