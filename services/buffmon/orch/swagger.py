"""Swagger 2.0 / OpenAPI 3.x explorer for filling the Orchestrator mapping.

    buffmon-orch-discover orch-9.7.2.json                     # GET operations matching default keywords
    buffmon-orch-discover orch-9.7.2.json -k tunnel -k fec    # your own keywords
    buffmon-orch-discover orch-9.7.2.json --show /some/path   # full detail for matching paths
    buffmon-orch-discover orch-9.7.2.json --diff orch-10.x.json
    ... --json                                                # machine-readable output

Only reads the spec file. It never talks to an Orchestrator.

Built to survive large, messy specs: unresolved or external ``$ref``, circular
references, ``allOf``/``oneOf``/``anyOf``, missing response schemas, and
non-standard keys are all reported instead of crashing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_KEYWORDS = (
    "tunnel", "overlay", "stats", "statistics", "alarm", "appliance", "interface",
    "flow", "health", "loss", "latency", "jitter", "fec",
)
HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")


@dataclass
class Param:
    name: str
    location: str
    type: str
    required: bool
    description: str = ""


@dataclass
class SchemaField:
    path: str
    type: str
    description: str = ""
    note: str = ""


@dataclass
class Operation:
    method: str
    path: str
    operation_id: str = ""
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    params: list[Param] = field(default_factory=list)
    response_status: str | None = None
    response_fields: list[SchemaField] = field(default_factory=list)
    response_note: str = ""
    matched: list[str] = field(default_factory=list)


def _first_line(text: Any, limit: int = 120) -> str:
    if not isinstance(text, str):
        return ""
    line = text.strip().splitlines()[0] if text.strip() else ""
    return line if len(line) <= limit else line[: limit - 1] + "…"


class Spec:
    def __init__(self, doc: Any, source: str = "<spec>", max_depth: int = 8, max_fields: int = 400) -> None:
        if not isinstance(doc, dict):
            raise ValueError(f"{source}: not a Swagger/OpenAPI document (top level is not an object)")
        self.doc = doc
        self.source = source
        self.max_depth = max_depth
        self.max_fields = max_fields
        if str(doc.get("swagger", "")).startswith("2"):
            self.version = "swagger-2.0"
        elif str(doc.get("openapi", "")).startswith("3"):
            self.version = f"openapi-{doc['openapi']}"
        else:
            raise ValueError(f"{source}: neither 'swagger: 2.x' nor 'openapi: 3.x' found")
        self.title = str((doc.get("info") or {}).get("title", ""))
        self.api_version = str((doc.get("info") or {}).get("version", ""))

    # -- references -----------------------------------------------------------
    def deref(self, ref: str) -> Any | None:
        """Resolves a local JSON pointer ("#/definitions/X"). None if it cannot."""
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None
        cur: Any = self.doc
        for raw in ref[2:].split("/"):
            key = raw.replace("~1", "/").replace("~0", "~")
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return None
        return cur

    @staticmethod
    def _short(ref: str) -> str:
        return ref.rsplit("/", 1)[-1]

    # -- operations -----------------------------------------------------------
    def operations(self, methods: Iterable[str] = ("get",)) -> list[Operation]:
        wanted = {m.lower() for m in methods}
        out: list[Operation] = []
        paths = self.doc.get("paths") or {}
        if not isinstance(paths, dict):
            return out
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            if "$ref" in item:
                item = self.deref(item["$ref"]) or item
            path_params = item.get("parameters") if isinstance(item.get("parameters"), list) else []
            for key, op in item.items():
                method = str(key).lower()
                if method not in HTTP_METHODS or method not in wanted or not isinstance(op, dict):
                    continue
                out.append(self._operation(method, str(path), op, path_params))
        out.sort(key=lambda o: (o.path, o.method))
        return out

    def _operation(self, method: str, path: str, op: dict[str, Any], path_params: list[Any]) -> Operation:
        params: dict[tuple[str, str], Param] = {}
        for raw in [*path_params, *(op.get("parameters") or [])]:
            p = self._param(raw)
            if p is not None:
                params[(p.location, p.name)] = p
        status, schema, note = self._response_schema(op.get("responses") or {})
        fields: list[SchemaField] = []
        if schema is not None:
            fields, truncated = self.flatten(schema)
            if truncated:
                note = (note + "; " if note else "") + f"truncated at {self.max_fields} fields"
        tags = [str(t) for t in op.get("tags") or [] if isinstance(t, str | int)]
        return Operation(
            method=method.upper(),
            path=path,
            operation_id=str(op.get("operationId", "")),
            summary=_first_line(op.get("summary") or op.get("description")),
            tags=tags,
            params=sorted(params.values(), key=lambda p: (p.location != "path", p.location, p.name)),
            response_status=status,
            response_fields=fields,
            response_note=note,
        )

    def _param(self, raw: Any) -> Param | None:
        if isinstance(raw, dict) and "$ref" in raw:
            raw = self.deref(raw["$ref"])
        if not isinstance(raw, dict) or "name" not in raw:
            return None
        schema = raw.get("schema") if isinstance(raw.get("schema"), dict) else raw
        return Param(
            name=str(raw["name"]),
            location=str(raw.get("in", "?")),
            type=self._type_label(schema),
            required=bool(raw.get("required", False)),
            description=_first_line(raw.get("description")),
        )

    def _response_schema(self, responses: Any) -> tuple[str | None, Any | None, str]:
        if not isinstance(responses, dict) or not responses:
            return None, None, "no responses in spec"
        keys = [str(k) for k in responses]
        order = sorted(keys, key=lambda k: (k != "200", not k.startswith("2"), k != "default", k))
        for status in order:
            resp = responses.get(status, responses.get(int(status)) if status.isdigit() else None)
            if isinstance(resp, dict) and "$ref" in resp:
                resp = self.deref(resp["$ref"])
            if not isinstance(resp, dict):
                continue
            if "schema" in resp:  # Swagger 2
                return status, resp["schema"], ""
            content = resp.get("content")
            if isinstance(content, dict) and content:  # OpenAPI 3
                ctype = next((c for c in content if "json" in c), next(iter(content)))
                media = content.get(ctype)
                if isinstance(media, dict) and "schema" in media:
                    note = "" if "json" in ctype else f"content type {ctype}"
                    return status, media["schema"], note
            if status.startswith("2"):
                return status, None, f"{status} response has no schema in the spec"
        return None, None, "no response schema in spec"

    # -- schemas --------------------------------------------------------------
    def _type_label(self, schema: Any) -> str:
        if not isinstance(schema, dict):
            return "unknown"
        if "$ref" in schema:
            return self._short(schema["$ref"])
        t = schema.get("type")
        if isinstance(t, list):  # OpenAPI 3.1
            t = next((x for x in t if x != "null"), "null")
        label = str(t) if t else ("object" if "properties" in schema else "any")
        if label == "array":
            label = f"array<{self._type_label(schema.get('items'))}>"
        if schema.get("format"):
            label += f"({schema['format']})"
        if isinstance(schema.get("enum"), list):
            values = ", ".join(str(v) for v in schema["enum"][:6])
            label += f" enum[{values}{', …' if len(schema['enum']) > 6 else ''}]"
        return label

    def _merge_all_of(self, parts: list[Any], stack: tuple[str, ...]) -> tuple[dict[str, Any], list[str]]:
        merged: dict[str, Any] = {"type": "object", "properties": {}}
        notes: list[str] = []
        for part in parts:
            if isinstance(part, dict) and "$ref" in part:
                ref = part["$ref"]
                if ref in stack:
                    notes.append(f"circular $ref {self._short(ref)} in allOf")
                    continue
                target = self.deref(ref)
                if target is None:
                    notes.append(f"unresolved $ref {ref} in allOf")
                    continue
                stack = (*stack, ref)
                part = target
            if not isinstance(part, dict):
                continue
            if "allOf" in part:
                sub, sub_notes = self._merge_all_of(list(part["allOf"]), stack)
                merged["properties"].update(sub["properties"])
                notes.extend(sub_notes)
            if isinstance(part.get("properties"), dict):
                merged["properties"].update(part["properties"])
            if "items" in part and "properties" not in part:
                merged = {"type": "array", "items": part["items"]}
        return merged, notes

    def flatten(self, schema: Any) -> tuple[list[SchemaField], bool]:
        """Every leaf (and container) in the schema as a dotted path. Lists are ``[]``,
        free-form maps are ``{*}``. Returns (fields, truncated)."""
        out: list[SchemaField] = []
        seen: set[tuple[str, str]] = set()
        state = {"truncated": False}

        def add(path: str, typ: str, desc: str = "", note: str = "") -> None:
            if len(out) >= self.max_fields:
                state["truncated"] = True
                return
            key = (path, typ)
            if key in seen:
                return
            seen.add(key)
            out.append(SchemaField(path or "$", typ, desc, note))

        def walk(node: Any, prefix: str, depth: int, stack: tuple[str, ...], note: str = "") -> None:
            if state["truncated"]:
                return
            if not isinstance(node, dict):
                add(prefix, "unknown", note=note)
                return
            if "$ref" in node:
                ref = node["$ref"]
                if ref in stack:
                    add(prefix, self._short(ref), note=f"circular $ref {self._short(ref)}")
                    return
                target = self.deref(ref)
                if target is None:
                    add(prefix, "unknown", note=f"unresolved $ref {ref}")
                    return
                walk(target, prefix, depth, (*stack, ref), note)
                return
            if "allOf" in node and isinstance(node["allOf"], list):
                merged, notes = self._merge_all_of(node["allOf"], stack)
                extra = {k: v for k, v in node.items() if k != "allOf"}
                if isinstance(extra.get("properties"), dict):
                    merged.setdefault("properties", {}).update(extra["properties"])
                walk(merged, prefix, depth, stack, "; ".join(n for n in [note, *notes] if n))
                return
            for combo in ("oneOf", "anyOf"):
                if isinstance(node.get(combo), list):
                    for i, variant in enumerate(node[combo]):
                        walk(variant, prefix, depth, stack, f"{combo} variant {i + 1}")
                    return
            desc = _first_line(node.get("description"), 80)
            t = node.get("type")
            if isinstance(t, list):
                t = next((x for x in t if x != "null"), None)
            if t == "array" or ("items" in node and t is None):
                add(prefix, "array", desc, note)
                if depth >= self.max_depth:
                    return
                walk(node.get("items", {}), f"{prefix}[]", depth + 1, stack)
                return
            props = node.get("properties")
            addl = node.get("additionalProperties")
            if t == "object" or isinstance(props, dict) or isinstance(addl, dict):
                if prefix:
                    add(prefix, "object", desc, note)
                if depth >= self.max_depth:
                    if out:
                        out[-1].note = (out[-1].note + "; " if out[-1].note else "") + "depth limit"
                    return
                for name, sub in (props or {}).items():
                    walk(sub, f"{prefix}.{name}" if prefix else str(name), depth + 1, stack)
                if isinstance(addl, dict):
                    walk(addl, f"{prefix}.{{*}}" if prefix else "{*}", depth + 1, stack)
                return
            add(prefix, self._type_label(node), desc, note)

        walk(schema, "", 0, ())
        return out, state["truncated"]


def load_spec(path: Path, max_depth: int = 8, max_fields: int = 400) -> Spec:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        doc = json.loads(text) if text.lstrip().startswith("{") else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"{path}: not valid JSON/YAML: {exc}") from exc
    return Spec(doc, str(path), max_depth=max_depth, max_fields=max_fields)


def discover(spec: Spec, keywords: Iterable[str] | None, path_filter: str | None = None) -> list[Operation]:
    """GET operations whose path, operationId, summary or tags contain a keyword."""
    kws = [k.lower() for k in keywords] if keywords else []
    out = []
    for op in spec.operations(("get",)):
        if path_filter and path_filter.lower() not in op.path.lower():
            continue
        hay = " ".join([op.path, op.operation_id, op.summary, *op.tags]).lower()
        op.matched = [k for k in kws if k in hay]
        if kws and not op.matched:
            continue
        out.append(op)
    out.sort(key=lambda o: (-len(o.matched), o.path))
    return out


# -- diff ---------------------------------------------------------------------
_PARAM_RE = re.compile(r"\{[^}]*\}")


def _norm(path: str) -> str:
    return _PARAM_RE.sub("{}", path.rstrip("/") or "/")


@dataclass
class OpChange:
    path_a: str
    path_b: str
    params_added: list[str] = field(default_factory=list)
    params_removed: list[str] = field(default_factory=list)
    params_changed: list[str] = field(default_factory=list)
    fields_added: list[str] = field(default_factory=list)
    fields_removed: list[str] = field(default_factory=list)
    fields_changed: list[str] = field(default_factory=list)

    def empty(self) -> bool:
        return self.path_a == self.path_b and not any(
            (self.params_added, self.params_removed, self.params_changed,
             self.fields_added, self.fields_removed, self.fields_changed)
        )


@dataclass
class SpecDiff:
    a: str
    b: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[OpChange] = field(default_factory=list)
    unchanged: int = 0


def diff_specs(a: Spec, b: Spec, keywords: Iterable[str] | None = None) -> SpecDiff:
    ops_a = {_norm(o.path): o for o in discover(a, keywords)}
    ops_b = {_norm(o.path): o for o in discover(b, keywords)}
    d = SpecDiff(a=f"{a.source} ({a.api_version or a.version})", b=f"{b.source} ({b.api_version or b.version})")
    d.added = sorted(ops_b[k].path for k in ops_b.keys() - ops_a.keys())
    d.removed = sorted(ops_a[k].path for k in ops_a.keys() - ops_b.keys())
    for key in sorted(ops_a.keys() & ops_b.keys()):
        oa, ob = ops_a[key], ops_b[key]
        ch = OpChange(path_a=oa.path, path_b=ob.path)
        pa = {(p.location, p.name): p for p in oa.params}
        pb = {(p.location, p.name): p for p in ob.params}
        ch.params_added = [f"{k[0]} {k[1]} ({pb[k].type})" for k in sorted(pb.keys() - pa.keys())]
        ch.params_removed = [f"{k[0]} {k[1]} ({pa[k].type})" for k in sorted(pa.keys() - pb.keys())]
        for k in sorted(pa.keys() & pb.keys()):
            if (pa[k].type, pa[k].required) != (pb[k].type, pb[k].required):
                ch.params_changed.append(
                    f"{k[0]} {k[1]}: {pa[k].type}{' required' if pa[k].required else ''} -> "
                    f"{pb[k].type}{' required' if pb[k].required else ''}"
                )
        fa = {f.path: f.type for f in oa.response_fields}
        fb = {f.path: f.type for f in ob.response_fields}
        ch.fields_added = [f"{p} ({fb[p]})" for p in sorted(fb.keys() - fa.keys())]
        ch.fields_removed = [f"{p} ({fa[p]})" for p in sorted(fa.keys() - fb.keys())]
        ch.fields_changed = [f"{p}: {fa[p]} -> {fb[p]}" for p in sorted(fa.keys() & fb.keys()) if fa[p] != fb[p]]
        if ch.empty():
            d.unchanged += 1
        else:
            d.changed.append(ch)
    return d


# -- output -------------------------------------------------------------------
def format_operation(op: Operation, show_fields: int | None = 40) -> str:
    lines = [f"{op.method} {op.path}" + (f"   [{', '.join(op.matched)}]" if op.matched else "")]
    meta = []
    if op.operation_id:
        meta.append(f"operationId: {op.operation_id}")
    if op.tags:
        meta.append(f"tags: {', '.join(op.tags)}")
    if meta:
        lines.append("  " + "   ".join(meta))
    if op.summary:
        lines.append(f"  summary: {op.summary}")
    for p in op.params:
        lines.append(f"  param  {p.location:<6} {p.name} ({p.type}){' required' if p.required else ''}"
                     + (f" — {p.description}" if p.description else ""))
    if op.response_status:
        lines.append(f"  response {op.response_status}:" + (f" ({op.response_note})" if op.response_note else ""))
    elif op.response_note:
        lines.append(f"  response: {op.response_note}")
    fields = op.response_fields if show_fields is None else op.response_fields[:show_fields]
    width = max((len(f.path) for f in fields), default=0)
    for f in fields:
        parts = (f"— {f.description}" if f.description else "", f"[{f.note}]" if f.note else "")
        extra = " ".join(x for x in parts if x)
        lines.append(f"    {f.path:<{width}}  {f.type}" + (f"  {extra}" if extra else ""))
    if show_fields is not None and len(op.response_fields) > show_fields:
        lines.append(f"    … {len(op.response_fields) - show_fields} more fields (use --show {op.path})")
    return "\n".join(lines)


def format_diff(d: SpecDiff) -> str:
    lines = [f"A: {d.a}", f"B: {d.b}",
             f"{len(d.added)} added, {len(d.removed)} removed, {len(d.changed)} changed, "
             f"{d.unchanged} unchanged GET paths", ""]
    for p in d.added:
        lines.append(f"+ {p}")
    for p in d.removed:
        lines.append(f"- {p}")
    for ch in d.changed:
        lines.append("")
        lines.append(f"~ {ch.path_a}" + (f"  ->  {ch.path_b}" if ch.path_a != ch.path_b else ""))
        for label, items in (
            ("param +", ch.params_added), ("param -", ch.params_removed), ("param ~", ch.params_changed),
            ("field +", ch.fields_added), ("field -", ch.fields_removed), ("field ~", ch.fields_changed),
        ):
            lines.extend(f"    {label} {i}" for i in items)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="buffmon-orch-discover",
        description="Explore an Orchestrator Swagger/OpenAPI export to fill the buffmon mapping file. "
                    "Reads the file only; never contacts Orchestrator.",
    )
    ap.add_argument("spec", type=Path, help="Swagger 2.0 or OpenAPI 3.x export (JSON or YAML)")
    ap.add_argument("-k", "--keyword", action="append", help="match keyword (repeatable; replaces the defaults)")
    ap.add_argument("--all", action="store_true", help="list every GET operation, no keyword filter")
    ap.add_argument("--show", metavar="PATH", help="only paths containing PATH, with every response field")
    ap.add_argument("--diff", metavar="OTHER", type=Path, help="compare GET operations with another export")
    ap.add_argument("--depth", type=int, default=8, help="response schema depth limit (default 8)")
    ap.add_argument("--max-fields", type=int, default=400, help="fields per operation (default 400)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        spec = load_spec(args.spec, args.depth, args.max_fields)
        other = load_spec(args.diff, args.depth, args.max_fields) if args.diff else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    keywords: list[str] | None = None if args.all or args.show else (args.keyword or list(DEFAULT_KEYWORDS))

    if other is not None:
        d = diff_specs(spec, other, None if args.all or not args.keyword else keywords)
        print(json.dumps(asdict(d), indent=2) if args.json else format_diff(d))
        return 0

    ops = discover(spec, keywords, args.show)
    if args.json:
        print(json.dumps({"spec": spec.source, "format": spec.version, "title": spec.title,
                          "api_version": spec.api_version, "operations": [asdict(o) for o in ops]}, indent=2))
        return 0
    print(f"{spec.source}: {spec.title} {spec.api_version} ({spec.version})")
    print(f"{len(ops)} GET operation(s)" + (f" matching {', '.join(keywords)}" if keywords else ""))
    for op in ops:
        print()
        print(format_operation(op, None if args.show else 40))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
