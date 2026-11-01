"""Parser for goflow2's JSON output (``-format=json``, one object per line).

Field names and rendering follow goflow2 v2.2.7 (github.com/netsampler/goflow2):
keys are the protobuf JSON names from ``pb/flow.proto`` (``sampler_address``,
``time_flow_start_ns``, ``src_addr``, ``in_if``, ``ip_tos``, ...); addresses are
rendered as text; ``proto`` is rendered as an IANA protocol name; ``type`` as
the flow type name (``IPFIX``). Derived from the goflow2 source; not yet checked
against a live capture of an EdgeConnect export (docs/DESIGN.md §11).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# goflow2 renders `proto` with IANA keyword names; accept numbers too.
_PROTO_BY_NAME = {
    "HOPOPT": 0, "ICMP": 1, "IGMP": 2, "IPv4": 4, "TCP": 6, "UDP": 17, "IPv6": 41, "GRE": 47,
    "ESP": 50, "AH": 51, "IPv6-ICMP": 58, "SCTP": 132,
}

_MAX_U64 = 2**64 - 1


class FlowParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GoflowRecord:
    flow_type: str
    time_received_ns: int
    exporter: IPAddress
    observation_domain_id: int
    start_ns: int
    end_ns: int
    src_ip: IPAddress
    dst_ip: IPAddress
    proto: int
    src_port: int
    dst_port: int
    ip_tos: int
    bytes: int
    packets: int
    sampling_rate: int
    in_if: int
    out_if: int


def _int(obj: dict[str, Any], key: str, lo: int = 0, hi: int = _MAX_U64, default: int | None = 0) -> int:
    v = obj.get(key, default)
    if v is None:
        raise FlowParseError(f"missing {key}")
    if isinstance(v, bool):
        raise FlowParseError(f"{key} is not a number")
    if isinstance(v, str) and v.isdigit():
        v = int(v)
    if not isinstance(v, int):
        raise FlowParseError(f"{key} is not an integer")
    if not lo <= v <= hi:
        raise FlowParseError(f"{key}={v} out of range")
    return v


def _ip(obj: dict[str, Any], key: str) -> IPAddress:
    v = obj.get(key)
    if not isinstance(v, str) or not v:
        raise FlowParseError(f"missing {key}")
    try:
        return ipaddress.ip_address(v)
    except ValueError as exc:
        raise FlowParseError(f"{key} {v!r} is not an IP address") from exc


def _proto(obj: dict[str, Any]) -> int:
    v = obj.get("proto", 0)
    if isinstance(v, str):
        if v in _PROTO_BY_NAME:
            return _PROTO_BY_NAME[v]
        if v.isdigit() and int(v) <= 255:
            return int(v)
        raise FlowParseError(f"unknown proto {v!r}")
    if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 255:
        return v
    raise FlowParseError("proto is not a protocol")


def parse_line(line: str | bytes) -> GoflowRecord:
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FlowParseError(f"not JSON: {exc.msg if isinstance(exc, json.JSONDecodeError) else exc}") from exc
    if not isinstance(obj, dict):
        raise FlowParseError("not a JSON object")

    received = _int(obj, "time_received_ns")
    start = _int(obj, "time_flow_start_ns")
    end = _int(obj, "time_flow_end_ns")
    # Exporters that omit flow timestamps leave them 0: fall back to arrival time.
    end = end or received
    start = start or end
    if start > end:
        start, end = end, start
    flow_type = obj.get("type", "")
    return GoflowRecord(
        flow_type=str(flow_type)[:16],
        time_received_ns=received,
        exporter=_ip(obj, "sampler_address"),
        observation_domain_id=_int(obj, "observation_domain_id", hi=2**32 - 1),
        start_ns=start,
        end_ns=end,
        src_ip=_ip(obj, "src_addr"),
        dst_ip=_ip(obj, "dst_addr"),
        proto=_proto(obj),
        src_port=_int(obj, "src_port", hi=65535),
        dst_port=_int(obj, "dst_port", hi=65535),
        ip_tos=_int(obj, "ip_tos", hi=255),
        bytes=_int(obj, "bytes"),
        packets=_int(obj, "packets"),
        sampling_rate=_int(obj, "sampling_rate", hi=2**32 - 1),
        in_if=_int(obj, "in_if", hi=2**32 - 1),
        out_if=_int(obj, "out_if", hi=2**32 - 1),
    )
