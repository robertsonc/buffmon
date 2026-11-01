"""buffmon-orch-discover against SYNTHETIC specs (tests/fixtures/orch/)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buffmon.orch.swagger import Spec, diff_specs, discover, load_spec, main

FIX = Path(__file__).parent / "fixtures" / "orch"
S2 = FIX / "swagger2_synthetic.json"
O3 = FIX / "openapi3_synthetic.yaml"


def fields(spec: Spec, path: str) -> dict[str, tuple[str, str]]:
    op = next(o for o in spec.operations() if o.path == path)
    return {f.path: (f.type, f.note) for f in op.response_fields}


def test_detects_both_formats() -> None:
    assert load_spec(S2).version == "swagger-2.0"
    assert load_spec(O3).version.startswith("openapi-3")
    with pytest.raises(ValueError, match="neither"):
        Spec({"paths": {}})


def test_only_get_operations_and_non_path_keys_are_ignored() -> None:
    ops = load_spec(S2).operations()
    assert {o.method for o in ops} == {"GET"}
    assert "x-vendor-extension" not in {o.path for o in ops}
    assert not any(o.operation_id == "createTunnel" for o in ops)


def test_params_merge_path_level_and_resolve_refs() -> None:
    op = next(o for o in load_spec(S2).operations() if o.operation_id == "getTunnelStats")
    assert [(p.location, p.name, p.type, p.required) for p in op.params] == [
        ("path", "applianceId", "string", True),
        ("query", "window", "integer(int32)", False),
    ]
    assert op.summary == "Per-tunnel stats"


def test_allof_ref_and_additional_properties_flatten() -> None:
    f = fields(load_spec(S2), "/synthetic/appliances/{applianceId}/tunnels")
    assert f["tunnels"][0] == "object"
    assert f["tunnels.{*}.tunnelId"][0] == "string"
    assert f["tunnels.{*}.stats.lossPre"][0] == "number(float)"
    assert f["tunnels.{*}.stats.latencyUs"][0] == "integer(int64)"
    assert f["ts"][0] == "integer(int64)"


def test_circular_ref_is_reported_not_followed() -> None:
    f = fields(load_spec(S2), "/synthetic/tree")
    assert f["children"][0] == "array"
    assert "circular $ref Node" in f["children[]"][1]


def test_unresolved_and_external_refs_are_reported() -> None:
    f = fields(load_spec(S2), "/synthetic/broken")
    assert "unresolved $ref #/definitions/DoesNotExist" in f["missing"][1]
    assert "unresolved $ref other.json#/definitions/X" in f["external"][1]


def test_missing_response_schema_is_a_note() -> None:
    op = next(o for o in load_spec(S2).operations() if o.path == "/synthetic/noschema/health")
    assert op.response_fields == [] and "no schema" in op.response_note


def test_openapi3_oneof_and_default_response() -> None:
    spec = load_spec(O3)
    f = fields(spec, "/synthetic/alarms")
    assert f["[].alarmId"][0] == "string"
    assert f["[].severity"][0].startswith("string enum[critical")
    assert "oneOf variant" in f["[].severity"][1] or "oneOf variant" in f["[]"][1]
    tree = next(o for o in spec.operations() if o.path == "/synthetic/tree")
    assert tree.response_status == "default"


def test_keyword_discovery_ranks_by_matches() -> None:
    ops = discover(load_spec(S2), ["tunnel", "stats", "alarm"])
    assert ops[0].path == "/synthetic/appliances/{applianceId}/tunnels"
    assert set(ops[0].matched) == {"tunnel", "stats"}
    assert "/synthetic/tree" not in {o.path for o in ops}
    assert {o.path for o in discover(load_spec(S2), None)} >= {"/synthetic/tree"}


def test_depth_and_field_caps() -> None:
    path = "/synthetic/appliances/{applianceId}/tunnels"
    shallow = load_spec(S2, max_depth=1)
    op = next(o for o in shallow.operations() if o.path == path)
    assert {f.path: f.note for f in op.response_fields}["tunnels"] == "depth limit"
    capped = load_spec(S2, max_fields=3)
    op = next(o for o in capped.operations() if o.path == path)
    assert len(op.response_fields) == 3 and "truncated" in op.response_note


def test_diff_between_releases() -> None:
    d = diff_specs(load_spec(S2), load_spec(O3))
    assert d.added == ["/synthetic/alarms"]
    assert set(d.removed) == {"/synthetic/broken", "/synthetic/legacy/alarms", "/synthetic/noschema/health"}
    tun = next(c for c in d.changed if "tunnels" in c.path_a)
    # A renamed path parameter is matched as the same operation, not as add + remove.
    assert tun.path_b == "/synthetic/appliances/{syntheticApplianceKey}/tunnels"
    assert "path syntheticApplianceKey (string)" in tun.params_added
    assert "path applianceId (string)" in tun.params_removed
    assert any(c.startswith("query window:") and "required" in c for c in tun.params_changed)
    assert "tunnels.{*}.stats.lossPost (number(double))" in tun.fields_added
    assert "ts: integer(int64) -> string(date-time)" in tun.fields_changed
    app = next(c for c in d.changed if c.path_a == "/synthetic/appliances")
    assert app.fields_added == ["[].model (string)"]


def test_cli_text_json_and_diff(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(S2)]) == 0
    out = capsys.readouterr().out
    assert "GET /synthetic/appliances/{applianceId}/tunnels" in out and "tunnels.{*}.stats.lossPre" in out
    assert main([str(S2), "--json", "-k", "tree"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [o["path"] for o in data["operations"]] == ["/synthetic/tree"]
    assert main([str(S2), "--diff", str(O3)]) == 0
    assert "+ /synthetic/alarms" in capsys.readouterr().out
    assert main([str(FIX / "README.md")]) == 2
