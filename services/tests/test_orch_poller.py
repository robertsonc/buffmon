"""Poller and buffmon-orch-poll against a SYNTHETIC mock Orchestrator.

Every path, header and field name below is invented for the test."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from pydantic import SecretStr

from buffmon.orch.client import AuthConfig, ClientConfig, OrchClient
from buffmon.orch.mapping import MappingFile
from buffmon.orch.poller import Poller, main, rows_token

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "orchestrator"

SYNTHETIC_MAPPING: dict[str, Any] = {
    "orchestrator_version": "synthetic",
    "source": "tests only",
    "auth": {"mode": "header", "header_name": "X-Synthetic-Token"},
    "collectors": {
        "appliances": {
            "enabled": True, "path": "/synthetic/appliances", "records": "data",
            "fields": {"appliance_id": {"from": "id"}, "hostname": {"from": "name"}, "site": {"from": "siteName"}},
        },
        "tunnel_stats": {
            "enabled": True, "path": "/synthetic/appliances/{appliance_id}/tunnels", "fan_out": "appliances",
            "params": {"window": 60}, "records": "tunnels",
            "fields": {
                "ts": {"from": "$now"},
                "appliance": {"from": "$ctx.hostname"},
                "tunnel_id": {"from": "$key"},
                "transport": {"from": "label", "map": {"wan0": "INET", "wan1": "MPLS"}},
                "loss_pre_fec_pct": {"from": "stats.lossPre", "convert": "fraction_to_pct"},
                "loss_post_fec_pct": {"from": "stats.lossPost", "convert": "fraction_to_pct"},
                "latency_ms": {"from": "stats.latencyUs", "convert": "us_to_ms"},
            },
        },
        "alarms": {"enabled": False},
    },
}

APPLIANCES = {"data": [{"id": "a1", "name": "sjc-ec1", "siteName": "SJC-BR01"},
                       {"id": "a2", "name": "lon-ec1", "siteName": "LON-BR03"}]}
TUNNELS = {
    "a1": {"tunnels": {"t-inet": {"label": "wan0", "stats": {"lossPre": 0.021, "lossPost": 0.001, "latencyUs": 21000}},
                       "t-mpls": {"label": "wan1", "stats": {"lossPre": 0.0, "lossPost": 0.0, "latencyUs": 18000}}}},
    "a2": {"tunnels": {"t-inet": {"label": "wan0", "stats": {"lossPre": 0.05, "latencyUs": 140000}}}},
}


def handler(seen: list[httpx.Request]) -> httpx.MockTransport:
    def h(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        assert r.method == "GET", "the poller must only ever GET"
        assert r.headers.get("X-Synthetic-Token") == "synthetic-token-0001"
        if r.url.path == "/synthetic/appliances":
            return httpx.Response(200, json=APPLIANCES)
        parts = r.url.path.split("/")
        if len(parts) == 5 and parts[4] == "tunnels" and parts[3] in TUNNELS:
            assert r.url.params.get("window") == "60"
            return httpx.Response(200, json=TUNNELS[parts[3]])
        return httpx.Response(404, text="synthetic not found")
    return httpx.MockTransport(h)


class MemorySink:
    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict[str, Any]], str]] = []

    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None:
        self.inserts.append((table, [dict(r) for r in rows], dedup_token))


def test_poller_fans_out_normalizes_and_writes_once_per_collector() -> None:
    seen: list[httpx.Request] = []
    mapping = MappingFile.model_validate(SYNTHETIC_MAPPING)
    client = OrchClient(
        ClientConfig(base_url="https://orch.synthetic.invalid",
                     auth=AuthConfig(mode="header", header_name="X-Synthetic-Token",
                                     token=SecretStr("synthetic-token-0001")), min_interval_s=0),
        transport=handler(seen),
    )
    sink = MemorySink()
    results = asyncio.run(Poller(mapping, client, sink).run_once())

    assert next(r.url.path for r in seen) == "/synthetic/appliances", "inventory first"
    assert len(seen) == 3
    assert len(results["appliances"]) == 2 and "alarms" not in results
    assert len(sink.inserts) == 1
    table, rows, token = sink.inserts[0]
    assert table == "tunnel_stats" and token == rows_token("tunnel_stats", rows)
    by = {(r["appliance"], r["tunnel_id"]): r for r in rows}
    sjc = by[("sjc-ec1", "t-inet")]
    assert sjc["site"] == "SJC-BR01" and sjc["transport"] == "INET"
    assert sjc["loss_pre_fec_pct"] == pytest.approx(2.1) and sjc["loss_post_fec_pct"] == pytest.approx(0.1)
    assert sjc["latency_ms"] == pytest.approx(21.0) and sjc["orch_version"] == "synthetic"
    assert by[("lon-ec1", "t-inet")]["loss_post_fec_pct"] is None, "absent metric stays null"


def test_one_appliance_failing_does_not_lose_the_others() -> None:
    mapping = MappingFile.model_validate(SYNTHETIC_MAPPING)
    broken = {**APPLIANCES, "data": [*APPLIANCES["data"], {"id": "a9", "name": "ghost", "siteName": "X"}]}

    def h(r: httpx.Request) -> httpx.Response:
        if r.url.path == "/synthetic/appliances":
            return httpx.Response(200, json=broken)
        appliance = r.url.path.split("/")[3]
        return httpx.Response(200, json=TUNNELS[appliance]) if appliance in TUNNELS else httpx.Response(404)

    client = OrchClient(ClientConfig(base_url="https://orch.synthetic.invalid", min_interval_s=0,
                                     auth=AuthConfig(mode="header", header_name="X-Synthetic-Token",
                                                     token=SecretStr("synthetic-token-0001"))),
                        transport=httpx.MockTransport(h))
    rows = asyncio.run(Poller(mapping, client, None).poll("tunnel_stats"))
    assert len(rows) == 3


def test_cli_dry_run_prints_rows_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "mapping.synthetic.yaml"
    path.write_text(yaml.safe_dump(SYNTHETIC_MAPPING))
    token = tmp_path / "token"
    token.write_text("synthetic-token-0001\n")
    token.chmod(0o600)
    seen: list[httpx.Request] = []
    code = main(["--mapping", str(path), "--url", "https://orch.synthetic.invalid", "--token-file", str(token),
                 "--dry-run"], transport=handler(seen))
    out = capsys.readouterr()
    assert code == 0, out.err
    lines = [json.loads(line) for line in out.out.splitlines()]
    assert {line["collector"] for line in lines} == {"appliances", "tunnel_stats"}
    assert sum(1 for line in lines if line["collector"] == "tunnel_stats") == 3
    assert "# tunnel_stats: 3 row(s)" in out.err
    assert all(r.method == "GET" for r in seen)


@pytest.mark.parametrize("version", ["9.7.2"])
def test_cli_refuses_the_unfilled_shipped_mapping(version: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--mapping", str(DEPLOY / f"mapping.{version}.yaml"), "--url", "https://x.invalid", "--dry-run"])
    assert code == 2
    assert "no collector is enabled" in capsys.readouterr().err


def test_cli_reports_missing_url(tmp_path: Path, capsys: pytest.CaptureFixture[str],
                                 monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BUFFMON_ORCH_URL", raising=False)
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump(SYNTHETIC_MAPPING))
    assert main(["--mapping", str(path), "--dry-run"]) == 2
    assert "BUFFMON_ORCH_URL" in capsys.readouterr().err
