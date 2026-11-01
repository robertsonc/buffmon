"""Review tool for the Orchestrator POST policy (deploy/orchestrator/post-allowlist.yaml).

    buffmon-orch-policy show  --policy post-allowlist.yaml
    buffmon-orch-policy check --policy post-allowlist.yaml --spec orch-10.x.json --mapping mapping.10.x.yaml
    buffmon-orch-policy draft --spec orch-10.x.json --path /some/post/path > rule.yaml

``check`` is what a reviewer (or CI) runs on a change to the policy: the policy
loads (which runs the tripwire on every rule), each rule still matches the
vendor's API description (same operation, same summary, parameters and body
keys that exist, enums and limits no wider than the spec's), and each mapping's
POST collectors fit their rules.

``draft`` writes a rule skeleton from the spec. It deliberately does not load:
a person has to add ``effect: read``, the purpose, the approval, the releases it
was verified on, and acknowledge the tripwire flags, after reading the operation.

Reads local files only; never contacts Orchestrator.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from .mapping import check_against_policy, load_mapping
from .post_policy import PostPolicyError, PostRule, ValueRule, load_policy, tripwire
from .swagger import Spec, load_spec


def _resolve(spec: Spec, node: Any, depth: int = 0) -> Any:
    while isinstance(node, dict) and "$ref" in node and depth < 20:
        node = spec.deref(node["$ref"])
        depth += 1
    return node


def _raw_operation(spec: Spec, path: str) -> dict[str, Any] | None:
    item = _resolve(spec, (spec.doc.get("paths") or {}).get(path))
    if not isinstance(item, dict):
        return None
    op = item.get("post")
    return op if isinstance(op, dict) else None


def _query_params(spec: Spec, path: str, op: dict[str, Any]) -> dict[str, dict[str, Any]]:
    item = _resolve(spec, (spec.doc.get("paths") or {}).get(path)) or {}
    out: dict[str, dict[str, Any]] = {}
    for raw in [*(item.get("parameters") or []), *(op.get("parameters") or [])]:
        p = _resolve(spec, raw)
        if isinstance(p, dict) and p.get("in") == "query" and "name" in p:
            schema = _resolve(spec, p.get("schema")) if isinstance(p.get("schema"), dict) else p
            out[str(p["name"])] = schema if isinstance(schema, dict) else {}
    return out


def _body_schema(spec: Spec, op: dict[str, Any]) -> dict[str, Any] | None:
    """Top-level JSON body schema: OpenAPI 3 requestBody, or a Swagger 2 `in: body` parameter."""
    rb = _resolve(spec, op.get("requestBody"))
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        media = content.get("application/json") or next(iter(content.values()), None)
        schema = _resolve(spec, (media or {}).get("schema"))
        return schema if isinstance(schema, dict) else None
    for raw in op.get("parameters") or []:
        p = _resolve(spec, raw)
        if isinstance(p, dict) and p.get("in") == "body":
            schema = _resolve(spec, p.get("schema"))
            return schema if isinstance(schema, dict) else None
    return None


def _body_properties(spec: Spec, schema: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    props: dict[str, dict[str, Any]] = {}
    required: list[str] = list(schema.get("required") or [])
    for part in [schema, *(schema.get("allOf") or [])]:
        part = _resolve(spec, part)
        if isinstance(part, dict):
            for k, v in (part.get("properties") or {}).items():
                props[str(k)] = _resolve(spec, v) or {}
            required += list(part.get("required") or [])
    return props, sorted(set(required))


def _spec_value_rule(spec: Spec, schema: dict[str, Any]) -> dict[str, Any] | None:
    t = schema.get("type")
    out: dict[str, Any]
    if t == "integer":
        out = {"type": "int"}
        if isinstance(schema.get("minimum"), int):
            out["min"] = schema["minimum"]
        if isinstance(schema.get("maximum"), int):
            out["max"] = schema["maximum"]
    elif t == "boolean":
        out = {"type": "bool"}
    elif t == "string":
        out = {"type": "string"}
        if isinstance(schema.get("enum"), list):
            out["enum"] = [str(e) for e in schema["enum"]]
        if isinstance(schema.get("pattern"), str):
            out["pattern"] = schema["pattern"]
    elif t == "array":
        items = _resolve(spec, schema.get("items")) or {}
        item_type = items.get("type") if isinstance(items, dict) else None
        if item_type not in ("string", "integer"):
            return None
        out = {"type": "list_of_string" if item_type == "string" else "list_of_int"}
        if isinstance(schema.get("maxItems"), int):
            out["max_items"] = schema["maxItems"]
        if item_type == "string" and isinstance(items.get("pattern"), str):
            out["pattern"] = items["pattern"]
    else:
        return None
    return out


_RULE_TYPE_FOR_SPEC = {"int": ("integer",), "bool": ("boolean",), "string": ("string",),
                       "list_of_string": ("array",), "list_of_int": ("array",)}


def _compare_value(where: str, rule: ValueRule, schema: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    spec_type = schema.get("type")
    if spec_type and spec_type not in _RULE_TYPE_FOR_SPEC[rule.type]:
        problems.append(f"{where}: rule type {rule.type}, spec type {spec_type}")
    spec_enum = schema.get("enum")
    if rule.enum is not None and isinstance(spec_enum, list):
        extra = sorted(set(rule.enum) - {str(e) for e in spec_enum})
        if extra:
            problems.append(f"{where}: enum values {extra} are not in the spec's {spec_enum}")
    if isinstance(schema.get("minimum"), int | float) and rule.min is not None and rule.min < schema["minimum"]:
        problems.append(f"{where}: min {rule.min} is below the spec minimum {schema['minimum']}")
    if isinstance(schema.get("maximum"), int | float) and rule.max is not None and rule.max > schema["maximum"]:
        problems.append(f"{where}: max {rule.max} is above the spec maximum {schema['maximum']}")
    return problems


def check_rule_against_spec(rule: PostRule, spec: Spec) -> list[str]:
    """Where ``rule`` no longer matches the vendor's API description."""
    where = f"rule {rule.id} (POST {rule.path})"
    op = _raw_operation(spec, rule.path)
    if op is None:
        return [f"{where}: the spec has no POST {rule.path}"]
    problems: list[str] = []
    op_id = str(op.get("operationId", "")) or None
    if rule.spec.operation_id is not None and rule.spec.operation_id != op_id:
        problems.append(f"{where}: spec operationId is {op_id!r}, the rule records {rule.spec.operation_id!r}")
    summary = str(op.get("summary") or "").strip()
    if summary != rule.spec.summary.strip():
        problems.append(f"{where}: spec summary is {summary!r}, the rule records {rule.spec.summary!r}; "
                        f"re-review the operation")
    # The tripwire runs on what the spec says, not only on what the rule records.
    flags = tripwire(rule.path, op_id, summary)
    unreviewed = sorted(set(flags) - set(rule.reviewed_terms))
    if unreviewed:
        problems.append(f"{where}: the spec operation trips {unreviewed}, not in reviewed_terms")
    params = _query_params(spec, rule.path, op)
    for name, vr in rule.params.items():
        if name not in params:
            problems.append(f"{where}: query parameter {name!r} is not in the spec")
        else:
            problems += _compare_value(f"{where} query parameter {name!r}", vr, params[name])
    if rule.body:
        schema = _body_schema(spec, op)
        if schema is None:
            problems.append(f"{where}: the spec declares no JSON body for this operation")
        else:
            props, _required = _body_properties(spec, schema)
            if props:
                for name, vr in rule.body.items():
                    if name not in props:
                        problems.append(f"{where}: body key {name!r} is not in the spec's body schema")
                    else:
                        problems += _compare_value(f"{where} body key {name!r}", vr, props[name])
            else:
                problems.append(f"{where}: the spec's body schema lists no properties; check the body keys by hand")
    return problems


def draft_rule(spec: Spec, path: str, rule_id: str | None = None) -> str:
    op = _raw_operation(spec, path)
    if op is None:
        raise ValueError(f"the spec has no POST {path}")
    op_id = str(op.get("operationId", "")) or None
    summary = str(op.get("summary") or "").strip() or str(op.get("description") or "").strip().splitlines()[0]
    if rule_id is None:
        base = re.sub(r"\d+$", "", op_id or path.strip("/").replace("/", "-"))
        rule_id = re.sub(r"[^a-z0-9]+", "-", re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", base).lower()).strip("-")
    params: dict[str, Any] = {}
    unsupported: list[str] = []
    for name, schema in _query_params(spec, path, op).items():
        vr = _spec_value_rule(spec, schema)
        if vr is None:
            unsupported.append(f"query {name} ({schema.get('type')})")
        else:
            params[name] = vr
    body: dict[str, Any] = {}
    body_schema = _body_schema(spec, op)
    if body_schema is not None:
        props, required = _body_properties(spec, body_schema)
        for name, prop in props.items():
            vr = _spec_value_rule(spec, prop)
            if vr is None:
                unsupported.append(f"body {name} ({prop.get('type')})")
            else:
                body[name] = {**vr, **({"required": True} if name in required else {})}
    flags = tripwire(path, op_id, summary)
    rule: dict[str, Any] = {
        "id": rule_id,
        "method": "POST",
        "path": path,
        "purpose": "",
        "spec": {"operation_id": op_id, "summary": summary},
        "verified_on": [],
        "approved_by": "",
        "approved_on": None,
        "params": params,
        "body": body,
        "max_body_bytes": 65536,
        "reviewed_terms": [],
    }
    header = [
        f"# DRAFT generated {datetime.now(tz=UTC):%Y-%m-%d} from {spec.source}. It does not load until a",
        "# person completes it. Before adding it to post-allowlist.yaml:",
        "#  1. Read the operation in the API reference. Add `effect: read` ONLY if it changes nothing:",
        "#     no state, no counters, no notes, nothing sent to appliances.",
        f"#  2. Tripwire flags for this operation: {flags or 'none'}. Copy them into reviewed_terms only",
        "#     once you have confirmed each one does not mean a write here.",
        "#  3. Delete every parameter and body key the collector does not need; narrow the rest",
        "#     (enum, min/max, pattern, max_items).",
        "#  4. Call it read-only against a lab Orchestrator; add that release to verified_on.",
        "#  5. Fill purpose, approved_by, approved_on.",
    ]
    if unsupported:
        header.append("# Not representable as a rule value (left out, so they cannot be sent): "
                      + ", ".join(unsupported))
    return "\n".join(header) + "\n" + yaml.safe_dump([rule], sort_keys=False, default_flow_style=None)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="buffmon-orch-policy", description="Review the Orchestrator POST policy.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    show = sub.add_parser("show", help="list the rules and the file's sha256")
    show.add_argument("--policy", type=Path, required=True)
    check = sub.add_parser("check", help="validate the policy against the spec and mappings")
    check.add_argument("--policy", type=Path, required=True)
    check.add_argument("--spec", type=Path, help="Orchestrator Swagger/OpenAPI export to compare each rule with")
    check.add_argument("--mapping", type=Path, action="append", default=[], help="mapping file (repeatable)")
    draft = sub.add_parser("draft", help="print a rule skeleton for a POST operation in the spec")
    draft.add_argument("--spec", type=Path, required=True)
    draft.add_argument("--path", required=True, help="the operation's path, as in the spec")
    draft.add_argument("--id", dest="rule_id", help="rule id (default: from the operationId)")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "draft":
            print(draft_rule(load_spec(args.spec), args.path, args.rule_id), end="")
            return 0
        policy = load_policy(args.policy)
    except (PostPolicyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "show":
        print(f"{args.policy}  sha256={policy.sha256}  rules={len(policy.rules)}")
        for rule, line in zip(policy.rules, policy.describe(), strict=True):
            print(f"  {line}")
            print(f"      purpose: {rule.purpose}")
            print(f"      params: {', '.join(rule.params) or '-'}; body: {', '.join(rule.body) or '-'}; "
                  f"max_body_bytes: {rule.max_body_bytes}; reviewed_terms: {rule.reviewed_terms or '-'}")
        return 0

    problems: list[str] = []
    if args.spec is not None:
        try:
            spec = load_spec(args.spec)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        for rule in policy.rules:
            problems += check_rule_against_spec(rule, spec)
    for mpath in args.mapping:
        try:
            mapping = load_mapping(mpath)
        except ValueError as exc:
            problems.append(f"{mpath}: {exc}")
            continue
        problems += [f"{mpath}: {p}" for p in check_against_policy(mapping, policy)]
    for p in problems:
        print(f"FAIL {p}")
    checked = ["policy"] + (["spec"] if args.spec else []) + [str(m) for m in args.mapping]
    print(f"{'FAILED' if problems else 'OK'}: {len(policy.rules)} rule(s), sha256={policy.sha256[:16]}…, "
          f"checked {', '.join(checked)}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
