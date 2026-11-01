"""Mapping validation and field conversion. All vendor values here are SYNTHETIC."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from buffmon.orch.mapping import (
    ConversionError,
    FieldMap,
    MappingFile,
    convert_value,
    extract_records,
    load_mapping,
    normalize,
    render_path,
)

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "orchestrator"
NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def mapping(collectors: dict[str, Any], auth: dict[str, Any] | None = None) -> MappingFile:
    return MappingFile.model_validate({
        "orchestrator_version": "synthetic",
        "auth": auth if auth is not None else {"mode": "header", "header_name": "X-Synthetic-Token"},
        "collectors": collectors,
    })


TUNNELS: dict[str, Any] = {
    "enabled": True,
    "path": "/synthetic/tunnels",
    "records": "data",
    "fields": {
        "ts": {"from": "t", "convert": "epoch_ms"},
        "appliance": {"from": "host"},
        "tunnel_id": {"from": "id"},
        "loss_pre_fec_pct": {"from": "lp", "convert": "fraction_to_pct"},
        "latency_ms": {"from": "lat", "convert": "us_to_ms"},
        "transport": {"from": "wan", "map": {"wan0": "INET", "wan1": "MPLS"}},
        "bytes_tx": {"from": "tx"},
    },
}


# 10.x is filled from a real export and verified live (tests/test_orch_10x.py).
@pytest.mark.parametrize("version", ["9.7.2"])
def test_shipped_mappings_are_disabled_and_carry_no_vendor_values(version: str) -> None:
    m = load_mapping(DEPLOY / f"mapping.{version}.yaml")
    assert m.orchestrator_version == version
    assert m.enabled() == {}
    assert m.auth.mode is None and m.auth.header_name is None and m.auth.login is None
    for col in m.collectors.values():
        assert col.path is None and col.records is None and col.params == {}
        assert all(f.from_ is None for f in col.fields.values())


def test_enabled_but_incomplete_fails_with_every_problem_listed() -> None:
    with pytest.raises(ValidationError) as exc:
        MappingFile.model_validate({
            "orchestrator_version": "synthetic",
            "collectors": {"tunnel_stats": {"enabled": True}},
        })
    msg = str(exc.value)
    assert "collectors.tunnel_stats is enabled but path is null" in msg
    assert "records is null" in msg
    assert "required field 'appliance' has no 'from'" in msg
    assert "required field 'tunnel_id' has no 'from'" in msg
    assert "auth.mode is null" in msg


@pytest.mark.parametrize(("change", "expected"), [
    ({"path": "/synthetic/{appliance_id}/tunnels"}, "placeholders ['appliance_id'] without fan_out"),
    ({"path": "/synthetic/{syntheticKey}/tunnels", "fan_out": "appliances"}, "are not inventory fields"),
    ({"fan_out": "appliances"}, "needs the appliances collector enabled"),
    ({"path": "synthetic/tunnels"}, "does not start with '/'"),
    ({"fields": {**TUNNELS["fields"], "ts": {"from": "t"}}}, "datetime field needs convert"),
    ({"fields": {**TUNNELS["fields"], "vlan": {"from": "v"}}}, "unknown field(s) vlan"),
    ({"fields": {**TUNNELS["fields"], "peer": {"from": "$now"}}}, "$now is only valid for datetime"),
])
def test_specific_validation_messages(change: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValidationError, match=None) as exc:
        mapping({"tunnel_stats": {**TUNNELS, **change}})
    assert expected in str(exc.value)


def test_only_get_is_accepted() -> None:
    with pytest.raises(ValidationError):
        mapping({"tunnel_stats": {**TUNNELS, "method": "POST"}})


def test_auth_header_mode_needs_header_name() -> None:
    with pytest.raises(ValidationError, match="header_name is null"):
        mapping({"tunnel_stats": TUNNELS}, auth={"mode": "header"})


def test_disabled_and_empty_is_valid() -> None:
    m = mapping({"tunnel_stats": {"enabled": False}}, auth={})
    assert m.enabled() == {}


@pytest.mark.parametrize(("raw", "fm", "ftype", "expected"), [
    (1761998400, {"convert": "epoch_s"}, "datetime", datetime(2025, 11, 1, 12, 0, tzinfo=UTC)),
    (1761998400123, {"convert": "epoch_ms"}, "datetime", datetime(2025, 11, 1, 12, 0, 0, 123000, tzinfo=UTC)),
    (1761998400000000, {"convert": "epoch_us"}, "datetime", datetime(2025, 11, 1, 12, 0, tzinfo=UTC)),
    ("2025-11-01T12:00:00Z", {"convert": "iso8601"}, "datetime", datetime(2025, 11, 1, 12, 0, tzinfo=UTC)),
    ("2025-11-01T12:00:00", {"convert": "iso8601"}, "datetime", datetime(2025, 11, 1, 12, 0, tzinfo=UTC)),
    (0.025, {"convert": "fraction_to_pct"}, "float", 2.5),
    (21500, {"convert": "us_to_ms"}, "float", 21.5),
    (0.0215, {"convert": "s_to_ms"}, "float", 21.5),
    ("3.5", {"convert": "pct"}, "float", 3.5),
    (12.6, {"convert": "int"}, "int", 13),
    (1024, {"scale": 8}, "int", 8192),
    ("wan1", {"map": {"wan1": "MPLS"}}, "str", "MPLS"),
    ("lte0", {"map": {"wan1": "MPLS"}}, "str", "lte0"),
    (None, {"default": "INET"}, "str", "INET"),
    (None, {}, "float", None),
])
def test_conversions(raw: Any, fm: dict[str, Any], ftype: Any, expected: Any) -> None:
    value = convert_value(raw, FieldMap.model_validate(fm), ftype)
    assert value == pytest.approx(expected) if isinstance(expected, float) else value == expected


@pytest.mark.parametrize("raw", [{"a": 1}, [1], "not-a-number"])
def test_bad_values_raise(raw: Any) -> None:
    with pytest.raises(ConversionError):
        convert_value(raw, FieldMap(), "float")


def test_normalize_rows_and_skips_incomplete_records() -> None:
    m = mapping({"tunnel_stats": TUNNELS})
    response = {"data": [
        {"t": 1761998400000, "host": "ec1", "id": "t1", "lp": 0.02, "lat": 21000, "wan": "wan0", "tx": 10},
        {"t": 1761998400000, "host": "ec1", "lp": 0.5},  # no tunnel id: skipped, reported
        {"t": "garbage", "host": "ec1", "id": "t3"},     # bad timestamp: skipped, reported
    ]}
    rows, problems = normalize("tunnel_stats", m.collectors["tunnel_stats"], response, NOW, "synthetic")
    assert len(rows) == 1 and len(problems) == 2
    r = rows[0]
    assert r["ts"] == "2025-11-01 12:00:00.000"
    assert (r["appliance"], r["tunnel_id"], r["transport"]) == ("ec1", "t1", "INET")
    assert r["loss_pre_fec_pct"] == pytest.approx(2.0) and r["latency_ms"] == pytest.approx(21.0)
    assert r["loss_post_fec_pct"] is None, "unmapped metrics are null, never zero"
    assert r["site"] == "" and r["orch_version"] == "synthetic"
    assert "tunnel_id: missing" in problems[0] and "ts: cannot convert" in problems[1]


def test_records_as_object_key_expand_parent_ctx_and_now() -> None:
    col = mapping({"tunnel_stats": {
        "enabled": True, "path": "/synthetic/x", "records": "tunnels", "expand": "samples",
        "fields": {"ts": {"from": "$now"}, "tunnel_id": {"from": "$key"}, "appliance": {"from": "$ctx.hostname"},
                   "tunnel_name": {"from": "$parent.label"}, "jitter_ms": {"from": "j"}},
    }}).collectors["tunnel_stats"]
    response = {"tunnels": {"tA": {"label": "to-dc1", "samples": [{"j": 1.5}, {"j": 2.5}]}}}
    assert len(extract_records(response, col)) == 2
    rows, problems = normalize("tunnel_stats", col, response, NOW, "synthetic",
                               ctx={"hostname": "sjc-ec1", "site": "SJC"})
    assert problems == []
    assert [(r["tunnel_id"], r["tunnel_name"], r["jitter_ms"]) for r in rows] == [
        ("tA", "to-dc1", 1.5), ("tA", "to-dc1", 2.5)]
    assert rows[0]["appliance"] == "sjc-ec1", "$ctx reads the fan-out inventory row"
    assert rows[0]["site"] == "SJC", "unmapped site falls back to the inventory row"
    assert rows[0]["ts"] == "2026-11-01 12:00:00.000"


def test_render_path_escapes_and_requires_values() -> None:
    assert render_path("/synthetic/{appliance_id}/t", {"appliance_id": "a/1 x"}) == "/synthetic/a%2F1%20x/t"
    with pytest.raises(ValueError, match="no 'hostname'"):
        render_path("/synthetic/{hostname}", {"appliance_id": "a"})


def test_mapping_file_round_trips_through_yaml(tmp_path: Path) -> None:
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump({"orchestrator_version": "synthetic",
                                    "auth": {"mode": "header", "header_name": "X-Synthetic-Token"},
                                    "collectors": {"tunnel_stats": TUNNELS}}))
    assert load_mapping(path).enabled().keys() == {"tunnel_stats"}
    path.write_text("collectors: [")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_mapping(path)
