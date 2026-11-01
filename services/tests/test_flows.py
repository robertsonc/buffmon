"""EdgeConnect flow pipeline: goflow2 parsing, exporter allowlist + enrichment,
the consumer loop, path analysis and the path API.

goflow2 lines below follow goflow2 v2.2.7's JSON rendering (protobuf JSON field
names, text IPs, protocol names), derived from its source. They are not a
capture from a live EdgeConnect export.
"""

from __future__ import annotations

import asyncio
import io
import json
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from buffmon.app import create_app
from buffmon.config import Settings
from buffmon.flows.config import FlowSettings
from buffmon.flows.consumer import FlowConsumer, goflow2_argv, run
from buffmon.flows.goflow2 import FlowParseError, parse_line
from buffmon.flows.path import analyse
from buffmon.flows.sites import SitesConfig, SitesFile
from buffmon.store import FLOWS_TABLE, PROBE_FLOWS_TABLE
from tests.conftest import TOKEN, FakeTransport, make_record

EC = "10.1.1.2"
PROBE = ("10.1.1.10", 40001)
REFLECTOR = ("10.10.0.20", 862)
NOW_NS = 1_793_500_000_000_000_000

SITES: dict[str, Any] = {
    "probe_ports": [862],
    "exporters": {
        EC: {
            "site": "SJC-BR01",
            "appliance": "sjc-br01-ec1",
            "interfaces": {2: {"name": "lan0"}, 3: {"name": "wan0", "transport": "INET"},
                           4: {"name": "wan1", "transport": "MPLS"}},
        },
    },
}


def goflow_line(**over: Any) -> str:
    rec: dict[str, Any] = {
        "type": "IPFIX", "time_received_ns": NOW_NS, "sequence_num": 7, "sampling_rate": 0,
        "sampler_address": EC, "time_flow_start_ns": NOW_NS - 60_000_000_000, "time_flow_end_ns": NOW_NS - 1_000_000,
        "bytes": 26400, "packets": 600, "src_addr": PROBE[0], "dst_addr": REFLECTOR[0], "etype": "IPv4",
        "proto": "UDP", "src_port": PROBE[1], "dst_port": REFLECTOR[1], "in_if": 2, "out_if": 3,
        "src_mac": "00:00:00:00:00:00", "dst_mac": "00:00:00:00:00:00", "ip_tos": 46 << 2,
        "observation_domain_id": 1, "next_hop": "", "tcp_flags": 0,
    }
    rec.update(over)
    return json.dumps(rec)


@pytest.fixture
def sites_file(tmp_path: Path) -> SitesFile:
    p = tmp_path / "sites.yaml"
    p.write_text(yaml.safe_dump(SITES))
    return SitesFile(p)


# -- goflow2 parsing -----------------------------------------------------------

def test_parses_goflow2_ipfix_json() -> None:
    r = parse_line(goflow_line())
    assert (str(r.exporter), str(r.src_ip), r.src_port, str(r.dst_ip), r.dst_port) == (EC, *PROBE, *REFLECTOR)
    assert (r.proto, r.ip_tos, r.bytes, r.packets, r.in_if, r.out_if) == (17, 184, 26400, 600, 2, 3)
    assert r.flow_type == "IPFIX" and r.start_ns < r.end_ns


@pytest.mark.parametrize("proto,expected", [("UDP", 17), ("TCP", 6), (17, 17), ("50", 50), ("IPv6-ICMP", 58)])
def test_proto_names_and_numbers(proto: Any, expected: int) -> None:
    assert parse_line(goflow_line(proto=proto)).proto == expected


def test_missing_flow_times_fall_back_to_arrival() -> None:
    r = parse_line(goflow_line(time_flow_start_ns=0, time_flow_end_ns=0))
    assert r.start_ns == r.end_ns == NOW_NS


@pytest.mark.parametrize("line", [
    "not json", "[]", goflow_line(src_addr="nope"), goflow_line(dst_port=70000), goflow_line(proto="BOGUS"),
    goflow_line(bytes=-1), goflow_line(sampler_address=None), goflow_line(ip_tos=True),
])
def test_malformed_lines_raise(line: str) -> None:
    with pytest.raises(FlowParseError):
        parse_line(line)


# -- sites.yaml ------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"exporters": {"not-an-ip": {"site": "A", "appliance": "a"}}},
    {"exporters": {"::1": {"site": "A", "appliance": "a"}, "0::1": {"site": "B", "appliance": "b"}}},
    {"probe_ports": [], "exporters": {}},
    {"probe_ports": [0], "exporters": {}},
    {"exporters": {EC: {"site": "A", "appliance": "a", "vrf": "x"}}},
])
def test_invalid_sites_are_rejected(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SitesConfig.model_validate(bad)


# -- consumer ---------------------------------------------------------------------

def test_known_exporter_is_enriched_and_probe_flow_detected(sites_file: SitesFile) -> None:
    c = FlowConsumer(sites_file)
    flow, probe = c.handle(goflow_line(ip_tos=(46 << 2) | 1))
    assert flow is not None and probe is not None
    assert (flow["site"], flow["appliance"]) == ("SJC-BR01", "sjc-br01-ec1")
    assert (flow["in_if_name"], flow["out_if_name"], flow["out_transport"]) == ("lan0", "wan0", "INET")
    assert (flow["dscp"], flow["ecn"]) == (46, 1)
    assert flow["exporter"] == f"::ffff:{EC}" and flow["src_ip"] == f"::ffff:{PROBE[0]}"
    assert flow["ts_end"].startswith("2026-") and len(flow["ts_end"]) == 23
    assert "ecn" not in probe and probe["dst_port"] == 862


def test_return_direction_is_also_a_probe_flow(sites_file: SitesFile) -> None:
    c = FlowConsumer(sites_file)
    _, probe = c.handle(goflow_line(src_addr=REFLECTOR[0], src_port=862, dst_addr=PROBE[0], dst_port=PROBE[1]))
    assert probe is not None


def test_non_probe_flows_are_not_in_probe_flows(sites_file: SitesFile) -> None:
    c = FlowConsumer(sites_file)
    flow, probe = c.handle(goflow_line(dst_port=443, proto="TCP"))
    assert flow is not None and probe is None
    _, probe = c.handle(goflow_line(proto="TCP"))  # TCP to 862 is not STAMP
    assert probe is None


def test_unknown_exporters_are_dropped_and_reported(sites_file: SitesFile) -> None:
    c = FlowConsumer(sites_file)
    assert c.handle(goflow_line(sampler_address="192.0.2.99")) == (None, None)
    assert c.handle("garbage") == (None, None)
    counts, unknown, err = c.take_stats()
    assert counts["unknown_exporter"] == 1 and counts["malformed"] == 1
    assert unknown == {"192.0.2.99": 1} and err is not None


def test_unmapped_interfaces_keep_their_index(sites_file: SitesFile) -> None:
    flow, _ = FlowConsumer(sites_file).handle(goflow_line(out_if=99))
    assert flow is not None and (flow["out_if"], flow["out_if_name"], flow["out_transport"]) == (99, "", "")


def test_goflow2_argv_has_no_shell_and_fixed_flags(tmp_path: Path) -> None:
    s = FlowSettings(flows_goflow2_bin=Path("/usr/local/bin/goflow2"), flows_goflow2_mapping=tmp_path / "m.yaml")
    assert goflow2_argv(s) == [
        "/usr/local/bin/goflow2", "-listen=netflow://0.0.0.0:2055", "-format=json", "-transport=file",
        f"-mapping={tmp_path / 'm.yaml'}",
    ]


def test_run_from_stdin_writes_both_tables(tmp_path: Path) -> None:
    sites = tmp_path / "sites.yaml"
    sites.write_text(yaml.safe_dump(SITES))
    lines = [goflow_line(), goflow_line(dst_port=443, proto="TCP"), "garbage",
             goflow_line(sampler_address="192.0.2.99")]
    stdin = io.BytesIO(("\n".join(lines) + "\n").encode())
    transport = FakeTransport()
    settings = FlowSettings(flows_sites_file=sites, flows_flush_interval_s=0.05, flows_stats_interval_s=0.05)
    assert asyncio.run(run(settings, transport=transport, stdin=stdin)) == 0
    by_table: dict[str, list[dict[str, Any]]] = {}
    for table, rows, token in transport.inserts:
        assert len(token) == 64
        by_table.setdefault(table, []).extend(rows)
    assert len(by_table[FLOWS_TABLE]) == 2
    assert len(by_table[PROBE_FLOWS_TABLE]) == 1


# -- path analysis -----------------------------------------------------------------

def path_row(direction: str = "forward", **over: Any) -> dict[str, Any]:
    src, dst = (PROBE, REFLECTOR) if direction == "forward" else (REFLECTOR, PROBE)
    row: dict[str, Any] = {
        "src_ip": f"::ffff:{src[0]}", "src_port": src[1], "dst_ip": f"::ffff:{dst[0]}", "dst_port": dst[1],
        "exporter": f"::ffff:{EC}", "site": "SJC-BR01", "appliance": "sjc-br01-ec1",
        "in_if": 2, "in_if_name": "lan0", "in_transport": "", "out_if": 3, "out_if_name": "wan0",
        "out_transport": "INET", "dscp": 46, "packets": 600, "bytes": 26400,
        "first_ms": 1_793_499_940_000, "last_ms": 1_793_500_000_000,
    }
    if direction == "return":
        row.update(in_if=3, in_if_name="wan0", in_transport="INET", out_if=2, out_if_name="lan0", out_transport="")
    row.update(over)
    return row


def run_analyse(rows: list[dict[str, Any]], dscp: int = 46) -> dict[str, Any]:
    return analyse(f"{PROBE[0]}:{PROBE[1]}", f"{REFLECTOR[0]}:{REFLECTOR[1]}", dscp, "voice", rows, 5)


def codes(result: dict[str, Any]) -> set[str]:
    return {f["code"] for f in result["findings"]}


def test_clean_path_in_both_directions() -> None:
    r = run_analyse([path_row(), path_row("return")])
    assert r["status"] == "ok" and r["findings"] == []
    assert r["summary"] == "sjc-br01-ec1 → wan0 (INET)"
    assert r["forward"][0]["exporter"] == EC and r["return"][0]["out_if_name"] == "lan0"


def test_dscp_remarked_before_the_edgeconnect_is_a_warning() -> None:
    r = run_analyse([path_row(dscp=0), path_row("return")])
    assert r["status"] == "warn" and "forward_dscp_mismatch" in codes(r)
    text = next(f["text"] for f in r["findings"] if f["code"] == "forward_dscp_mismatch")
    assert "0 (BE)" in text and "46 (EF)" in text and "voice" in text


def test_multiple_egress_interfaces_and_unmapped_ifindex() -> None:
    r = run_analyse([path_row(), path_row(out_if=4, out_if_name="wan1", out_transport="MPLS", last_ms=1),
                     path_row(out_if=7, out_if_name="", out_transport="", last_ms=2), path_row("return")])
    assert {"forward_multiple_egress", "unmapped_interface"} <= codes(r)
    assert r["status"] == "ok"


def test_not_seen_and_one_direction_only() -> None:
    assert codes(run_analyse([])) == {"not_seen"} and run_analyse([])["status"] == "unknown"
    assert codes(run_analyse([path_row()])) == {"return_not_seen"}
    other = path_row(src_port=40999)
    assert codes(run_analyse([other])) == {"not_seen"}, "other sessions' flows must not match"


# -- API ------------------------------------------------------------------------------

def test_paths_api_uses_live_sessions(settings: Settings) -> None:
    transport = FakeTransport()
    transport.select_rows = [path_row(dscp=0), path_row("return")]
    with TestClient(create_app(settings, transport=transport)) as client:
        rec = make_record(src=f"{PROBE[0]}:{PROBE[1]}", dst=f"{REFLECTOR[0]}:{REFLECTOR[1]}")
        r = client.post("/v1/probe/results", json={"probe_id": "p1", "records": [rec]},
                        headers={"authorization": f"Bearer {TOKEN}"})
        assert r.status_code == 200 and r.json()["accepted"] == 1
        body = client.get("/v1/paths?minutes=5").json()
        assert body["paths"]["p1/dc1-voice"]["status"] == "warn"
        sql, params = transport.selects[-1]
        assert "probe_flows" in sql and int(params["from_ms"]) <= int(time.time() * 1000) - 5 * 60_000 + 5_000
        one = client.get("/v1/sessions/p1/dc1-voice/path?minutes=10")
        assert one.status_code == 200 and "p1/dc1-voice" in one.json()["paths"]
        assert client.get("/v1/sessions/p1/nope/path").status_code == 404
        assert client.get("/v1/paths?minutes=0").status_code == 400
        transport.fail_selects = True
        assert client.get("/v1/paths").status_code == 503


def test_shipped_sites_example_is_valid() -> None:
    from buffmon.flows.sites import load_sites

    cfg = load_sites(Path(__file__).resolve().parents[2] / "deploy" / "sites.example.yaml")
    assert cfg.probe_ports == [862] and len(cfg.exporters) == 2
