"""EdgeConnect tunnel health from Orchestrator (``tunnel_stats``, written by
``buffmon-orch-poll``): one summary row per tunnel over a recent window.

Loss is reported as packet counts (additive) plus Orchestrator's own per-minute
percentage maximum. No percentage is derived here: which packets Orchestrator
counts in the denominator is not documented.
"""

from __future__ import annotations

from typing import Any

from .store import Transport

# Aliases never reuse a column name: ClickHouse resolves aliases everywhere in
# the query, so `avg(latency_ms) AS latency_ms` would turn max(latency_ms) into
# a nested aggregate.
TUNNELS_SQL = """
SELECT
    appliance, site, tunnel_id,
    argMax(tunnel_name, ts) AS last_tunnel_name,
    argMax(tunnel_kind, ts) AS last_tunnel_kind,
    argMax(overlay, ts)     AS last_overlay,
    argMax(transport, ts)   AS last_transport,
    argMax(peer, ts)        AS last_peer,
    sum(rx_pkts)            AS rx_pkts,
    sum(ohead_rx_pkts)      AS ohead_rx_pkts,
    sum(loss_pre_fec_pkts)  AS loss_pre_pkts,
    sum(loss_post_fec_pkts) AS loss_post_pkts,
    sum(ooo_pre_poc_pkts)   AS ooo_pre_pkts,
    sum(ooo_post_poc_pkts)  AS ooo_post_pkts,
    max(loss_pre_fec_pct)   AS loss_pre_pct_max,
    max(loss_post_fec_pct)  AS loss_post_pct_max,
    avg(latency_ms)         AS latency_avg_ms,
    max(latency_ms)         AS latency_max_ms,
    avg(jitter_ms)          AS jitter_avg_ms,
    min(mos)                AS mos_min,
    toUnixTimestamp64Milli(max(ts)) AS last_ms,
    count()                 AS minutes
FROM tunnel_stats FINAL
WHERE ts >= fromUnixTimestamp64Milli({from_ms:Int64})
  AND ({appliance:String} = '' OR appliance = {appliance:String})
GROUP BY appliance, site, tunnel_id
ORDER BY appliance, last_tunnel_kind, tunnel_id
LIMIT 5000
"""

_INTS = ("rx_pkts", "ohead_rx_pkts", "loss_pre_pkts", "loss_post_pkts", "ooo_pre_pkts", "ooo_post_pkts",
         "last_ms", "minutes")
_FLOATS = ("loss_pre_pct_max", "loss_post_pct_max", "latency_ms", "latency_max_ms", "jitter_ms", "mos_min")


def _num(v: Any, cast: type) -> Any:
    if v is None:
        return None
    try:
        return cast(v)
    except (TypeError, ValueError):
        return None


_RENAMED = {"last_tunnel_name": "tunnel_name", "last_tunnel_kind": "tunnel_kind", "last_overlay": "overlay",
            "last_transport": "transport", "last_peer": "peer", "latency_avg_ms": "latency_ms",
            "jitter_avg_ms": "jitter_ms"}


def shape(row: dict[str, Any]) -> dict[str, Any]:
    row = {_RENAMED.get(k, k): v for k, v in row.items()}
    out: dict[str, Any] = {k: row.get(k) or "" for k in
                           ("appliance", "site", "tunnel_id", "tunnel_name", "tunnel_kind", "overlay", "transport",
                            "peer")}
    for k in _INTS:
        out[k] = _num(row.get(k), int)
    for k in _FLOATS:
        v = _num(row.get(k), float)
        out[k] = round(v, 2) if v is not None else None
    pre, post = out["loss_pre_pkts"] or 0, out["loss_post_pkts"] or 0
    # What forward error correction recovered in the window: the SD-WAN's
    # contribution to what users got, in packets.
    out["fec_recovered_pkts"] = max(pre - post, 0) if pre else 0
    return out


async def query_tunnels(transport: Transport, from_ms: int, appliance: str = "") -> list[dict[str, Any]]:
    rows = await transport.select(TUNNELS_SQL, {"from_ms": from_ms, "appliance": appliance})
    return [shape(r) for r in rows]
