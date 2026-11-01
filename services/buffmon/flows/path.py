"""Probe path validation (docs/DESIGN.md D1).

A probe only stands for user traffic if it takes the same path. This looks up
the probe's own 5-tuple in the EdgeConnect flow export (``probe_flows``) and
reports which appliance and interfaces it crossed, with which DSCP, in each
direction, plus findings when something is off.

What the exporter reports is taken at face value: which ifIndex is "egress"
for an overlay-carried flow, and whether ipClassOfService is observed before
or after the appliance's own marking, depend on the EdgeConnect release and
must be confirmed from a capture (DESIGN.md §11). Findings say "as exported".
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..models import parse_endpoint
from ..store import Transport

ALL_PATHS_SQL = """
SELECT
    toString(src_ip) AS src_ip, src_port, toString(dst_ip) AS dst_ip, dst_port,
    toString(exporter) AS exporter, site, appliance,
    in_if, in_if_name, in_transport, out_if, out_if_name, out_transport, dscp,
    sum(packets) AS packets, sum(bytes) AS bytes,
    toUnixTimestamp64Milli(min(ts_start)) AS first_ms,
    toUnixTimestamp64Milli(max(ts_end)) AS last_ms
FROM probe_flows
WHERE ts_end >= fromUnixTimestamp64Milli({from_ms:Int64})
GROUP BY src_ip, src_port, dst_ip, dst_port, exporter, site, appliance,
         in_if, in_if_name, in_transport, out_if, out_if_name, out_transport, dscp
ORDER BY last_ms DESC
LIMIT {limit:UInt32}
"""

DSCP_NAMES = {0: "BE", 8: "CS1", 10: "AF11", 18: "AF21", 26: "AF31", 34: "AF41", 46: "EF", 48: "CS6"}


def _strip_mapped(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _dscp(d: int) -> str:
    return f"{d} ({DSCP_NAMES[d]})" if d in DSCP_NAMES else str(d)


def _hop(g: dict[str, Any]) -> dict[str, Any]:
    return {
        "exporter": _strip_mapped(g["exporter"]),
        "site": g["site"],
        "appliance": g["appliance"],
        "in_if": int(g["in_if"]),
        "in_if_name": g["in_if_name"],
        "in_transport": g["in_transport"],
        "out_if": int(g["out_if"]),
        "out_if_name": g["out_if_name"],
        "out_transport": g["out_transport"],
        "dscp": int(g["dscp"]),
        "packets": int(g["packets"]),
        "bytes": int(g["bytes"]),
        "first_ms": int(g["first_ms"]),
        "last_ms": int(g["last_ms"]),
    }


def _if_label(name: str, index: int, transport: str) -> str:
    label = name or f"ifIndex {index}"
    return f"{label} ({transport})" if transport else label


def analyse(
    src: str, dst: str, dscp: int, app_class: str, rows: list[dict[str, Any]], minutes: int
) -> dict[str, Any]:
    """Path and findings for one session from the grouped ``probe_flows`` rows."""
    s_ip, s_port = parse_endpoint(src)
    d_ip, d_port = parse_endpoint(dst)
    fwd_key = (str(s_ip), s_port, str(d_ip), d_port)
    ret_key = (str(d_ip), d_port, str(s_ip), s_port)
    forward: list[dict[str, Any]] = []
    back: list[dict[str, Any]] = []
    for r in rows:
        key = (_strip_mapped(r["src_ip"]), int(r["src_port"]), _strip_mapped(r["dst_ip"]), int(r["dst_port"]))
        if key == fwd_key:
            forward.append(_hop(r))
        elif key == ret_key:
            back.append(_hop(r))
    forward.sort(key=lambda h: -h["last_ms"])
    back.sort(key=lambda h: -h["last_ms"])

    findings: list[dict[str, str]] = []
    if not forward and not back:
        findings.append({
            "severity": "info", "code": "not_seen",
            "text": f"No EdgeConnect flow records for this probe in the last {minutes} min. Check the appliance's "
                    "IPFIX export and that its address is listed in sites.yaml.",
        })
    elif not back:
        findings.append({
            "severity": "info", "code": "return_not_seen",
            "text": "Only the forward direction appears in the flow export (the exporter may export one "
                    "direction only).",
        })
    for direction, hops in (("forward", forward), ("return", back)):
        for h in hops:
            if h["dscp"] != dscp:
                where = h["appliance"]
                if direction == "forward":
                    text = (f"Forward flow exported by {where} with DSCP {_dscp(h['dscp'])}; the probe marks "
                            f"{_dscp(dscp)}. If the overlay policy classifies on DSCP, this probe is not on the "
                            f"{app_class} overlay. Check for re-marking between the probe and the EdgeConnect.")
                else:
                    text = (f"Return flow exported by {where} with DSCP {_dscp(h['dscp'])}; the reflector "
                            f"reflects {_dscp(dscp)}. The return path may be classified differently from the "
                            "forward path.")
                findings.append({"severity": "warn", "code": f"{direction}_dscp_mismatch", "text": text})
                break
    for direction, hops in (("forward", forward), ("return", back)):
        by_appliance: dict[str, set[str]] = {}
        for h in hops:
            label = _if_label(h["out_if_name"], h["out_if"], h["out_transport"])
            by_appliance.setdefault(h["appliance"], set()).add(label)
        for appliance, labels in by_appliance.items():
            if len(labels) > 1:
                findings.append({
                    "severity": "info", "code": f"{direction}_multiple_egress",
                    "text": f"{direction.capitalize()} traffic left {appliance} on {len(labels)} interfaces in the "
                            f"window: {', '.join(sorted(labels))}. Path changed or is load-shared.",
                })
    unmapped = sorted({f"{h['appliance']} ifIndex {i}" for h in forward + back
                       for i, name in ((h["in_if"], h["in_if_name"]), (h["out_if"], h["out_if_name"]))
                       if i and not name})
    if unmapped:
        findings.append({
            "severity": "info", "code": "unmapped_interface",
            "text": f"Name these interfaces in sites.yaml to see transports: {', '.join(unmapped)}.",
        })

    summary = None
    if forward:
        h = forward[0]
        summary = f"{h['appliance']} → {_if_label(h['out_if_name'], h['out_if'], h['out_transport'])}"
    worst = "warn" if any(f["severity"] == "warn" for f in findings) else ("ok" if forward else "unknown")
    return {"status": worst, "summary": summary, "forward": forward, "return": back, "findings": findings}


async def query_paths(transport: Transport, from_ms: int, limit: int = 20_000) -> list[dict[str, Any]]:
    return await transport.select(ALL_PATHS_SQL, {"from_ms": from_ms, "limit": limit})
