"""Validation of probe records (docs/PROBE-RECORD.md, v1).

The ingest service never trusts a probe: every record is checked for type,
range and internal consistency. A record that fails is rejected individually;
it is never repaired or re-stamped.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

NAME_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"
CLASS_PATTERN = r"^[A-Za-z0-9._-]{1,32}$"
ERROR_KEY_PATTERN = r"^[a-z0-9_]{1,32}$"

MAX_COUNT = 1_000_000
MAX_RTT_US = 60_000_000  # 60 s
MAX_SUM_US = 2**62

Count = Annotated[StrictInt, Field(ge=0, le=MAX_COUNT)]
OptCount = Annotated[StrictInt, Field(ge=0, le=MAX_COUNT)] | None
SumUs = Annotated[StrictInt, Field(ge=0, le=MAX_SUM_US)]
SignedSumUs = Annotated[StrictInt, Field(ge=-MAX_SUM_US, le=MAX_SUM_US)] | None
RttUs = Annotated[StrictInt, Field(ge=0, le=MAX_RTT_US)]
Ttl = Annotated[StrictInt, Field(ge=0, le=255)] | None


def parse_endpoint(value: str) -> tuple[ipaddress.IPv4Address, int]:
    """Parses ``a.b.c.d:port``. Phase 1 is IPv4 only."""
    host, sep, port_s = value.rpartition(":")
    if not sep or not host or not port_s.isdigit():
        raise ValueError("must be ip:port")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"invalid IP address {host!r}") from exc
    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError("IPv6 endpoints are not supported in record v1")
    port = int(port_s)
    if port > 65535:
        raise ValueError("port out of range")
    return ip, port


class ProbeRecord(BaseModel):
    """One (probe, session, bucket) record. Unknown fields are ignored so newer
    probes can add fields without breaking older ingest services."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    v: Literal[1]
    probe_id: Annotated[str, Field(pattern=NAME_PATTERN)]
    site: Annotated[str, Field(min_length=1, max_length=64)]
    session: Annotated[str, Field(pattern=NAME_PATTERN)]
    kind: Literal["stamp", "icmp", "tcp"]
    app_class: Annotated[str, Field(pattern=CLASS_PATTERN)]
    dscp: Annotated[StrictInt, Field(ge=0, le=63)]
    src: str
    dst: str
    ts_ms: Annotated[StrictInt, Field(gt=0)]
    interval_ms: Annotated[StrictInt, Field(ge=100, le=60_000)]
    sent: Count
    received: Count
    lost: Count
    late: Count
    dup: Count
    reordered: Count
    fwd_lost: OptCount = None
    back_lost: OptCount = None
    rtt_us: Annotated[list[RttUs], Field(max_length=MAX_COUNT)]
    rtt_jitter_sum_us: SumUs
    rtt_jitter_n: Count
    ipdv_fwd_sum_us: SumUs
    ipdv_fwd_n: Count
    ipdv_back_sum_us: SumUs
    ipdv_back_n: Count
    owd_fwd_sum_us: SignedSumUs = None
    owd_back_sum_us: SignedSumUs = None
    owd_n: Count
    clock_synced: StrictBool
    clock_err_us: Annotated[StrictInt, Field(ge=0, le=2**32 - 1)] | None = None
    ttl_fwd: Ttl = None
    ttl_back: Ttl = None
    rx_ts: Literal["kernel", "user"]
    errors: Annotated[dict[Annotated[str, Field(pattern=ERROR_KEY_PATTERN)], Count], Field(max_length=16)]

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

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.sent != self.received + self.lost:
            raise ValueError("sent must equal received + lost")
        if len(self.rtt_us) != self.received:
            raise ValueError("len(rtt_us) must equal received")
        if self.ts_ms % self.interval_ms != 0:
            raise ValueError("ts_ms must be a multiple of interval_ms")
        if self.rtt_jitter_n > self.received or self.ipdv_fwd_n > self.received:
            raise ValueError("jitter/ipdv pair counts cannot exceed received")
        if self.ipdv_back_n > self.received or self.owd_n > self.received:
            raise ValueError("ipdv/owd counts cannot exceed received")
        if self.kind != "stamp" and (self.ipdv_fwd_n or self.ipdv_back_n):
            raise ValueError("ipdv is only defined for stamp sessions")
        if self.kind != "stamp" and (self.fwd_lost is not None or self.back_lost is not None):
            raise ValueError("fwd_lost/back_lost are only defined for stamp sessions")
        if not self.clock_synced and (
            self.owd_n or self.owd_fwd_sum_us is not None or self.owd_back_sum_us is not None
        ):
            raise ValueError("one-way delay requires clock_synced")
        if self.owd_n and (self.owd_fwd_sum_us is None or self.owd_back_sum_us is None):
            raise ValueError("owd_n > 0 requires both owd sums")
        return self

    @property
    def key(self) -> tuple[str, str, int]:
        """Idempotency key."""
        return (self.probe_id, self.session, self.ts_ms)

    @property
    def session_key(self) -> str:
        return f"{self.probe_id}/{self.session}"


class IngestBatch(BaseModel):
    """Top-level body. Records are validated one by one afterwards so a single
    bad record does not reject the batch."""

    model_config = ConfigDict(extra="ignore")

    probe_id: Annotated[str, Field(pattern=NAME_PATTERN)]
    records: list[object]
    # Phase 3 (optional): forward route traces and capacity measurements.
    routes: list[object] = []
    capacity: list[object] = []
    # Phase 3.3 (optional): RFC 9946 speed-test results.
    speedtests: list[object] = []
