"""The POST policy: the only way buffmon sends a POST to Orchestrator."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from pydantic import ValidationError

from buffmon.orch.mapping import MappingFile, check_against_policy, load_mapping
from buffmon.orch.policy_cli import check_rule_against_spec, draft_rule
from buffmon.orch.policy_cli import main as policy_main
from buffmon.orch.poller import main, resolve_post_policy
from buffmon.orch.post_policy import (
    NO_READ_VERB,
    PostPolicy,
    PostPolicyError,
    PostRule,
    load_policy,
    tripwire,
)
from buffmon.orch.swagger import Spec

DEPLOY = Path(__file__).resolve().parents[2] / "deploy" / "orchestrator"
POLICY = DEPLOY / "post-allowlist.yaml"
MAPPING = DEPLOY / "mapping.10.x.yaml"

RULE: dict[str, Any] = {
    "id": "synthetic-read",
    "method": "POST",
    "path": "/synthetic/alarms",
    "effect": "read",
    "purpose": "synthetic read for the tests",
    "spec": {"operation_id": "getSyntheticAlarms", "summary": "Retrieve synthetic alarms"},
    "verified_on": ["9.9.0.1"],
    "approved_by": "tester",
    "approved_on": "2026-11-01",
    "params": {"view": {"type": "string", "enum": ["active"]}, "max": {"type": "int", "min": 1, "max": 10}},
    "body": {"ids": {"type": "list_of_string", "pattern": "^[0-9]+\\.NE$", "max_items": 3, "required": True}},
}


def rule(**over: Any) -> dict[str, Any]:
    return {**copy.deepcopy(RULE), **over}


# -- the shipped policy -----------------------------------------------------------------

def test_shipped_policy_has_exactly_the_approved_rule() -> None:
    policy = load_policy(POLICY)
    assert [(r.id, r.method, r.path, r.effect) for r in policy.rules] == \
        [("alarm-appliance-read", "POST", "/alarm/appliance", "read")], "adding a POST needs explicit approval"
    assert policy.sha256 == hashlib.sha256(POLICY.read_bytes()).hexdigest()
    r = policy.rules[0]
    assert r.spec.operation_id == "getApplianceAlarms" and r.verified_on == ["10.0.0.40724"]
    assert set(r.params) == {"view", "maxAlarms", "from", "to"} and set(r.body) == {"nePks"}


def test_shipped_mapping_fits_the_shipped_policy() -> None:
    assert check_against_policy(load_mapping(MAPPING), load_policy(POLICY)) == []


# -- what a rule may say ----------------------------------------------------------------

@pytest.mark.parametrize("over,match", [
    ({"effect": "write"}, "effect"),
    ({"effect": None}, "effect"),
    ({"method": "PUT"}, "method"),
    ({"path": "/alarm/{id}"}, "exact path"),
    ({"path": "/alarm?x=1"}, "exact path"),
    ({"path": "/alarm/../config"}, "exact path"),
    ({"path": "alarm"}, "exact path"),
    ({"id": "Alarm Read"}, "rule id"),
    ({"purpose": "x"}, "purpose"),
    ({"verified_on": []}, "verified_on"),
    ({"approved_by": ""}, "approved_by"),
    ({"approved_on": "yesterday"}, "approved_on"),
    ({"surprise": 1}, "surprise"),
    ({"params": {"x": {"type": "string", "min": 1}}}, "min/max only apply"),
    ({"params": {"x": {"type": "int", "max_items": 2}}}, "max_items only applies"),
    ({"params": {"x": {"type": "string", "pattern": "("}}}, "not a valid regex"),
])
def test_invalid_rules_are_rejected(over: dict[str, Any], match: str) -> None:
    raw = rule(**over)
    if over.get("effect", "") is None:
        del raw["effect"]
    with pytest.raises(ValidationError, match=match):
        PostRule.model_validate(raw)


def test_ids_and_paths_are_unique() -> None:
    with pytest.raises(ValidationError, match="ids must be unique"):
        PostPolicy.model_validate({"rules": [rule(), rule(path="/synthetic/other")]})
    with pytest.raises(ValidationError, match="paths must be unique"):
        PostPolicy.model_validate({"rules": [rule(), rule(id="synthetic-other")]})


# -- tripwire ---------------------------------------------------------------------------
# Cases taken from POST operations of the Orchestrator 10.0 API reference.

@pytest.mark.parametrize("path,op_id,summary,expected", [
    ("/alarm/appliance", "getApplianceAlarms", "Retrieve appliance alarms for specified appliances", []),
    ("/stats2/aggregate/mos", "getAggregateMosStats", "Get aggregate Mean Opinion Score (MOS) statistics", []),
    ("/tunnels/physical/state/getBatch", "getPhysicalTunnelStateBatch", "Retrieve batch of physical tunnel states", []),
    ("/alarm/acknowledgement/appliance", "ackAlarms", "Acknowledge appliance alarms",
     ["ack", "acknowledge", NO_READ_VERB]),
    ("/alarm/note/appliance", "alarmNotes26", "Capture comments for appliance alarms",
     ["capture", "comment", NO_READ_VERB, "note"]),
    ("/appliance/discovered/deny", "denyDiscoveredAppliances55", "Deny a discovered appliance",
     ["deny", "discover", NO_READ_VERB]),
    ("/appliance/rediscoverAppliance", "rediscoverAppliance68", "Rediscover a denied appliance",
     ["discover", NO_READ_VERB]),
    ("/spPortal/account/license/appliance/ecsp/unassign", "spPortalECSPLicenseUnassign565",
     "Unassign EC-SP licenses on Portal", ["assign", NO_READ_VERB]),
    ("/cluster/initForEdgeHA", "initForEdgeHA", "Initialize Appliances for EdgeHA Cluster",
     ["init", "initialize", NO_READ_VERB]),
    ("/appliance/cpustat/historical/fetch", "applianceCPUstatsGet1",
     "Fetch CPU historical statistics from appliance and store in Orchestrator database", ["store"]),
    ("/uiUsageStats", "uiUsageStats904", "Increment UI feature usage counter", ["increment", NO_READ_VERB]),
    # Reads, but of secrets: flagged so the approver decides deliberately.
    ("/tunnels/physical/config/getBatch", "getPhysicalTunnelConfigBatch",
     "Retrieve batch of physical tunnel configurations", ["config"]),
    ("/thirdPartyServices/zscaler/orchestratedList", "getZscalerOrchestratedList",
     "Get Zscaler orchestrated configuration for appliances", ["config"]),
])
def test_tripwire(path: str, op_id: str, summary: str, expected: list[str]) -> None:
    assert tripwire(path, op_id, summary) == sorted(expected)


def test_tripwire_flags_must_be_reviewed_exactly() -> None:
    write_ish = {"path": "/synthetic/alarms/clear", "spec": {"operation_id": "clearAlarms", "summary": "Clear alarms"}}
    with pytest.raises(ValidationError, match=r"trips \['clear', 'no-read-verb'\]"):
        PostRule.model_validate(rule(**write_ish))
    # The reviewer can acknowledge them (the rule then loads; whether that was
    # right is what the PR review is for) ...
    assert PostRule.model_validate(rule(**write_ish, reviewed_terms=["clear", NO_READ_VERB]))
    # ... but cannot pre-approve words that are not flagged.
    with pytest.raises(ValidationError, match="not flagged"):
        PostRule.model_validate(rule(reviewed_terms=["delete"]))


# -- loading ----------------------------------------------------------------------------

def _write(tmp_path: Path, doc: Any, mode: int = 0o644) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(doc))
    p.chmod(mode)
    return p


def test_load_policy_refuses_files_others_can_change(tmp_path: Path) -> None:
    for mode in (0o664, 0o646):
        with pytest.raises(PostPolicyError, match="writable by group or others"):
            load_policy(_write(tmp_path, {"rules": [rule()]}, mode))
    assert load_policy(_write(tmp_path, {"rules": [rule()]}, 0o600)).rules


@pytest.mark.parametrize("doc,match", [
    (["not", "a", "mapping"], "must be a mapping"),
    ({"rules": [rule()], "sha256": "0" * 64}, "computed from the file"),
    ({"version": 2, "rules": []}, "invalid"),
    ({"rules": [rule(effect="write")]}, "invalid"),
])
def test_load_policy_errors(tmp_path: Path, doc: Any, match: str) -> None:
    with pytest.raises(PostPolicyError, match=match):
        load_policy(_write(tmp_path, doc))


def test_missing_policy_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(PostPolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


# -- request checks ---------------------------------------------------------------------

@pytest.mark.parametrize("params,body,match", [
    ({"view": "active", "max": "5"}, {"ids": ["1.NE"]}, None),
    ({}, {"ids": []}, None),
    ({"view": "all"}, {"ids": ["1.NE"]}, "not one of"),
    ({"max": 11}, {"ids": ["1.NE"]}, "above 10"),
    ({"max": True}, {"ids": ["1.NE"]}, "must be an integer"),
    ({"max": "5; drop"}, {"ids": ["1.NE"]}, "must be an integer"),
    ({"other": 1}, {"ids": ["1.NE"]}, "not allowed"),
    ({}, {"ids": ["1.NE", "2.NE", "3.NE", "4.NE"]}, "max 3"),
    ({}, {"ids": "1.NE"}, "must be a list"),
    ({}, {"ids": ["1.NE\n"]}, "does not match"),
    ({}, {"ids": [1]}, "must be a string"),
    ({}, {}, "required"),
    ({}, {"ids": ["1.NE"], "action": "ack"}, "not allowed"),
    ({}, None, "JSON object"),
])
def test_check_request(params: dict[str, Any], body: Any, match: str | None) -> None:
    problems = PostRule.model_validate(rule()).check_request(params, body)
    if match is None:
        assert problems == []
    else:
        assert any(match in p for p in problems), problems


# -- mapping <-> policy -----------------------------------------------------------------

def _mapping(**alarms: Any) -> MappingFile:
    collectors: dict[str, Any] = {
        "appliances": {"enabled": True, "path": "/appliance", "records": "",
                       "fields": {"appliance_id": {"from": "nePk"}, "hostname": {"from": "hostName"}}},
        "alarms": {"enabled": True, "method": "POST", "post_rule": "synthetic-read", "path": "/synthetic/alarms",
                   "params": {"view": "active"}, "body": {"ids": "{appliance_ids}"}, "body_chunk": 3, "records": "",
                   "fields": {"ts": {"from": "$now"}, "alarm_id": {"from": "id"}}, **alarms},
    }
    return MappingFile.model_validate({"orchestrator_version": "9.9", "auth": {"mode": "header",
                                       "header_name": "X-Synthetic"}, "collectors": collectors})


POLICY_1 = PostPolicy.model_validate({"rules": [rule()]})


@pytest.mark.parametrize("alarms,match", [
    ({}, None),
    ({"post_rule": "other-rule"}, "not in the POST policy"),
    ({"path": "/synthetic/other"}, "differs from the rule's"),
    ({"params": {"view": "active", "extra": 1}}, "'extra' is not allowed"),
    ({"params": {"view": "all"}}, "not one of"),
    ({"params": {"max": "{bucket_start_s}"}}, None),  # templated: checked per request instead
    ({"body": {"ids": "{appliance_ids}", "more": 1}}, "'more' is not allowed"),
    ({"body_chunk": 4}, "exceeds the rule's max_items"),
])
def test_check_against_policy(alarms: dict[str, Any], match: str | None) -> None:
    if alarms.get("params", {}).get("max") == "{bucket_start_s}":
        alarms = {**alarms, "buckets": {"size_s": 60, "lag_s": 0, "count": 1}}
    problems = check_against_policy(_mapping(**alarms), POLICY_1)
    if match is None:
        assert problems == []
    else:
        assert any(match in p for p in problems), problems


def test_rule_must_be_verified_on_the_mappings_release() -> None:
    raw = _mapping().model_dump(by_alias=True)
    raw["orchestrator_version"] = "9.10"  # 9.9.0.1 is verified; 9.10 is a different release
    problems = check_against_policy(MappingFile.model_validate(raw), POLICY_1)
    assert any("verified on 9.9.0.1, not on this mapping's Orchestrator 9.10" in p for p in problems), problems


def test_appliance_ids_need_a_string_list() -> None:
    policy = PostPolicy.model_validate({"rules": [rule(body={"ids": {"type": "list_of_int"}})]})
    assert any("types it as list_of_int" in p for p in check_against_policy(_mapping(), policy))


# -- poller start-up --------------------------------------------------------------------

def test_post_collectors_without_a_policy_fail_closed() -> None:
    with pytest.raises(PostPolicyError, match="--deny-posts"):
        resolve_post_policy(_mapping(), None, deny_posts=False)


def test_deny_posts_switches_post_collectors_off() -> None:
    mapping, policy = resolve_post_policy(_mapping(), POLICY, deny_posts=True)
    assert set(mapping.enabled()) == {"appliances"} and policy.rules == []


def test_client_gets_only_the_rules_the_mapping_uses(tmp_path: Path) -> None:
    path = _write(tmp_path, {"rules": [rule(), rule(id="synthetic-unused", path="/synthetic/unused")]})
    _, policy = resolve_post_policy(_mapping(), path, deny_posts=False)
    assert [r.id for r in policy.rules] == ["synthetic-read"]
    assert policy.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_get_only_mapping_needs_no_policy() -> None:
    m = _mapping(enabled=False)
    assert resolve_post_policy(m, None, deny_posts=False) == (m, PostPolicy())


def _orch(seen: list[httpx.Request]) -> httpx.MockTransport:
    def h(r: httpx.Request) -> httpx.Response:
        seen.append(r)
        if r.method == "GET" and r.url.path.endswith("/appliance"):
            return httpx.Response(200, json=[{"nePk": "1.NE", "hostName": "ec-a-01", "site": "A"}])
        return httpx.Response(200, json=[] if r.method == "POST" else {})
    return httpx.MockTransport(h)


def _args(tmp_path: Path, *extra: str) -> list[str]:
    token = tmp_path / "token"
    token.write_text("synthetic-token")
    raw = yaml.safe_load(MAPPING.read_text())
    raw["collectors"]["tunnel_stats"]["enabled"] = False
    mapping = tmp_path / "m.yaml"
    mapping.write_text(yaml.safe_dump(raw))
    return ["--mapping", str(mapping), "--url", "https://orch.synthetic.invalid/gms/rest",
            "--token-file", str(token), "--once", "--dry-run", *extra]


def test_poller_refuses_to_start_without_the_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str],
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BUFFMON_ORCH_POST_POLICY", raising=False)
    monkeypatch.delenv("BUFFMON_ORCH_DENY_POSTS", raising=False)
    seen: list[httpx.Request] = []
    assert main(_args(tmp_path), transport=_orch(seen)) == 2
    assert "needs the POST policy" in capsys.readouterr().err and seen == []


def test_poller_with_policy_logs_it_and_posts(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    seen: list[httpx.Request] = []
    caplog.set_level("INFO")
    assert main(_args(tmp_path, "--post-policy", str(POLICY)), transport=_orch(seen)) == 0
    assert [r.url.path for r in seen if r.method == "POST"] == ["/gms/rest/alarm/appliance"]
    sha = hashlib.sha256(POLICY.read_bytes()).hexdigest()
    assert f"sha256={sha}" in caplog.text and "POST allowed: alarm-appliance-read" in caplog.text


@pytest.mark.parametrize("how", ["flag", "env"])
def test_deny_posts_sends_no_post(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    seen: list[httpx.Request] = []
    extra = ["--post-policy", str(POLICY)]
    if how == "flag":
        extra.append("--deny-posts")
    else:
        monkeypatch.setenv("BUFFMON_ORCH_DENY_POSTS", "1")
    assert main(_args(tmp_path, *extra), transport=_orch(seen)) == 0
    assert seen and {r.method for r in seen} == {"GET"}


def test_poller_refuses_a_mapping_that_asks_for_more_than_its_rule(tmp_path: Path,
                                                                   capsys: pytest.CaptureFixture[str]) -> None:
    args = _args(tmp_path, "--post-policy", str(POLICY))
    mapping = Path(args[1])
    raw = yaml.safe_load(mapping.read_text())
    raw["collectors"]["alarms"]["params"]["orderBySeverity"] = True
    mapping.write_text(yaml.safe_dump(raw))
    seen: list[httpx.Request] = []
    assert main(args, transport=_orch(seen)) == 2
    assert "'orderBySeverity' is not allowed" in capsys.readouterr().err and seen == []


# -- review CLI -------------------------------------------------------------------------

SPEC_DOC: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "synthetic", "version": "1"},
    "paths": {
        "/alarm/appliance": {"post": {
            "operationId": "getApplianceAlarms",
            "summary": "Retrieve appliance alarms for specified appliances",
            "parameters": [
                {"name": "view", "in": "query", "schema": {"type": "string", "enum": ["active", "closed", "all"]}},
                {"name": "maxAlarms", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100000}},
                {"name": "from", "in": "query", "schema": {"type": "integer"}},
                {"name": "to", "in": "query", "schema": {"type": "integer"}},
            ],
            "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Body"}}}},
        }},
        "/alarm/note/appliance": {"post": {"operationId": "alarmNotes26",
                                           "summary": "Capture comments for appliance alarms"}},
    },
    "components": {"schemas": {
        "Body": {"type": "object", "required": ["nePks"], "properties": {"nePks": {"$ref": "#/components/schemas/L"}}},
        "L": {"type": "array", "items": {"$ref": "#/components/schemas/P"}},
        "P": {"type": "string", "pattern": "^\\d+\\.NE$"},
    }},
}


def test_shipped_rule_matches_the_spec() -> None:
    spec = Spec(copy.deepcopy(SPEC_DOC))
    assert check_rule_against_spec(load_policy(POLICY).rules[0], spec) == []


@pytest.mark.parametrize("change,match", [
    (lambda d: d["paths"]["/alarm/appliance"]["post"].update(summary="Retrieve and acknowledge alarms"),
     "re-review"),
    (lambda d: d["paths"]["/alarm/appliance"]["post"].update(operationId="ackApplianceAlarms"), "operationId"),
    (lambda d: d["paths"]["/alarm/appliance"]["post"]["parameters"][0]["schema"].update(enum=["active"]),
     "not in the spec's"),
    (lambda d: d["paths"]["/alarm/appliance"]["post"]["parameters"].pop(), "'to' is not in the spec"),
    (lambda d: d["components"]["schemas"]["Body"]["properties"].update(ids={"type": "array"})
     or d["components"]["schemas"]["Body"]["properties"].pop("nePks"), "'nePks' is not in the spec"),
    (lambda d: d["paths"].pop("/alarm/appliance"), "has no POST"),
])
def test_spec_drift_is_reported(change: Any, match: str) -> None:
    doc = copy.deepcopy(SPEC_DOC)
    change(doc)
    problems = check_rule_against_spec(load_policy(POLICY).rules[0], Spec(doc))
    assert any(match in p for p in problems), problems


def test_draft_does_not_load_until_a_person_completes_it(tmp_path: Path) -> None:
    text = draft_rule(Spec(copy.deepcopy(SPEC_DOC)), "/alarm/note/appliance")
    assert "['capture', 'comment', 'no-read-verb', 'note']" in text
    draft = yaml.safe_load(text)
    with pytest.raises(PostPolicyError):
        load_policy(_write(tmp_path, {"rules": draft}))
    alarms = yaml.safe_load(draft_rule(Spec(copy.deepcopy(SPEC_DOC)), "/alarm/appliance"))[0]
    assert alarms["id"] == "get-appliance-alarms" and "effect" not in alarms
    assert alarms["body"] == {"nePks": {"type": "list_of_string", "pattern": "^\\d+\\.NE$", "required": True}}
    assert alarms["params"]["maxAlarms"] == {"type": "int", "min": 1, "max": 100000}
    alarms.update(effect="read", purpose="completed by a reviewer", verified_on=["10.0.0.1"],
                  approved_by="reviewer", approved_on="2026-11-01")
    assert load_policy(_write(tmp_path, {"rules": [alarms]})).rules[0].id == "get-appliance-alarms"


def test_policy_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps(SPEC_DOC))
    assert policy_main(["check", "--policy", str(POLICY), "--spec", str(spec), "--mapping", str(MAPPING)]) == 0
    assert "OK: 1 rule(s)" in capsys.readouterr().err
    assert policy_main(["show", "--policy", str(POLICY)]) == 0
    assert hashlib.sha256(POLICY.read_bytes()).hexdigest() in capsys.readouterr().out
    doc = copy.deepcopy(SPEC_DOC)
    doc["paths"]["/alarm/appliance"]["post"]["summary"] = "Retrieve and clear appliance alarms"
    spec.write_text(json.dumps(doc))
    assert policy_main(["check", "--policy", str(POLICY), "--spec", str(spec)]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "'clear'" in out
