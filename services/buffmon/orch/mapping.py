"""Per-Orchestrator-version mapping: where the data lives and how it maps to
buffmon's normalized tables.

The mapping is the ONLY place vendor-specific knowledge lives. The shipped
files (``deploy/orchestrator/mapping.*.yaml``) have every collector disabled and
every vendor value null; fill them from that release's Swagger export with
``buffmon-orch-discover``.

Field paths (``from``), relative to one record:

* ``a.b.c`` / ``items.0.x`` — dotted path through objects and lists;
* ``$key``                  — the record's key when ``records`` points at an object;
* ``$parent.a.b``           — the enclosing record when ``expand`` is used;
* ``$ctx.<field>``          — the inventory row in a fan-out (``appliance_id``, ``hostname``, ``site``);
* ``$now``                  — poll time (only for ``datetime`` fields);
* ``$bucket_start`` / ``$bucket_end`` — the time bucket being polled (``buckets``; datetime fields only).

Query parameters may use ``{appliance_id}``/``{hostname}``/``{site}`` (with
``fan_out``) and ``{bucket_start_s}``/``{bucket_end_s}``/``{bucket_start_ms}``/
``{bucket_end_ms}`` (with ``buckets``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Self
from urllib.parse import quote

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .client import READ_ONLY_POSTS, dig

FieldType = Literal["datetime", "str", "float", "int"]
Convert = Literal[
    "none", "ms", "us_to_ms", "s_to_ms", "pct", "fraction_to_pct",
    "epoch_s", "epoch_ms", "epoch_us", "iso8601", "int", "float", "str",
]
DATETIME_CONVERTS = frozenset({"epoch_s", "epoch_ms", "epoch_us", "iso8601"})
CollectorName = Literal["appliances", "tunnel_stats", "alarms"]


class NormField(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: FieldType
    required: bool = False


# The normalized schema. Field names here are buffmon's, not Orchestrator's.
NORMALIZED: dict[str, dict[str, NormField]] = {
    # Inventory used for fan-out and for site/appliance labels. Not stored.
    "appliances": {
        "appliance_id": NormField(type="str", required=True),
        "hostname": NormField(type="str", required=True),
        "site": NormField(type="str"),
    },
    "tunnel_stats": {
        "ts": NormField(type="datetime", required=True),
        "site": NormField(type="str"),
        "appliance": NormField(type="str", required=True),
        "tunnel_id": NormField(type="str", required=True),
        "tunnel_name": NormField(type="str"),
        "overlay": NormField(type="str"),
        "transport": NormField(type="str"),
        "peer": NormField(type="str"),
        "tunnel_kind": NormField(type="str"),
        "rx_pkts": NormField(type="int"),
        "ohead_rx_pkts": NormField(type="int"),
        "loss_pre_fec_pkts": NormField(type="int"),
        "loss_post_fec_pkts": NormField(type="int"),
        "ooo_pre_poc_pkts": NormField(type="int"),
        "ooo_post_poc_pkts": NormField(type="int"),
        "loss_pre_fec_pct": NormField(type="float"),
        "loss_post_fec_pct": NormField(type="float"),
        "ooo_pre_poc_pct": NormField(type="float"),
        "ooo_post_poc_pct": NormField(type="float"),
        "latency_ms": NormField(type="float"),
        "jitter_ms": NormField(type="float"),
        "mos": NormField(type="float"),
        "bytes_tx": NormField(type="int"),
        "bytes_rx": NormField(type="int"),
    },
    "alarms": {
        "ts": NormField(type="datetime", required=True),
        "alarm_id": NormField(type="str", required=True),
        "site": NormField(type="str"),
        "appliance": NormField(type="str"),
        "severity": NormField(type="str"),
        "source": NormField(type="str"),
        "name": NormField(type="str"),
        "object": NormField(type="str"),
        "description": NormField(type="str"),
        "state": NormField(type="str"),
        "cleared_ts": NormField(type="datetime"),
    },
}
STORED_TABLES = {"tunnel_stats": "tunnel_stats", "alarms": "alarms"}
FAN_OUT_FIELDS = frozenset(NORMALIZED["appliances"])
BUCKET_FIELDS = frozenset({"bucket_start_s", "bucket_end_s", "bucket_start_ms", "bucket_end_ms"})
TIME_SOURCES = frozenset({"$now", "$bucket_start", "$bucket_end"})
_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


class FieldMap(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    from_: str | None = Field(default=None, alias="from")
    convert: Convert = "none"
    # Multiplier applied after `convert` (numeric fields only).
    scale: float | None = None
    # Raw value -> normalized value lookup, applied before `convert`
    # (e.g. a WAN label -> "INET"/"MPLS"/"LTE" as the customer names them).
    map: dict[str, str] | None = None
    default: str | float | int | None = None
    # Regex applied to the raw value first; the first group is kept. No match
    # gives `default`. E.g. a WAN label inside a tunnel alias.
    pattern: str | None = None
    # Raw values that mean "no value" (e.g. a cleared time of 0).
    null_if: list[str | int | float] = []

    @model_validator(mode="after")
    def _pattern_compiles(self) -> Self:
        if self.pattern is not None:
            try:
                rx = re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"pattern {self.pattern!r} is not a valid regex: {exc}") from exc
            if rx.groups < 1:
                raise ValueError(f"pattern {self.pattern!r} needs a capturing group")
        return self


class Buckets(BaseModel):
    """Poll exact, non-overlapping time buckets instead of "the last N minutes".

    Each poll requests the `count` most recent complete buckets that ended at
    least `lag_s` ago. Re-polling a bucket on the next cycle replaces it
    (same key), which picks up statistics that reached Orchestrator late, while
    keeping every stored row additive."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    size_s: int = Field(default=60, ge=60, le=3600)
    lag_s: int = Field(default=120, ge=0, le=3600)
    count: int = Field(default=3, ge=1, le=10)

    def windows(self, now_s: int) -> list[tuple[int, int]]:
        last_end = ((now_s - self.lag_s) // self.size_s) * self.size_s
        return [(last_end - (i + 1) * self.size_s, last_end - i * self.size_s) for i in range(self.count)]


class Collector(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    # GET, or POST for an endpoint in client.READ_ONLY_POSTS (reads Orchestrator
    # only offers as POST). Any other POST fails validation and is refused by
    # the client before sending.
    method: Literal["GET", "POST"] = "GET"
    path: str | None = None
    params: dict[str, str | int | float | bool] = {}
    # JSON body for an approved read-only POST. A string value that is exactly
    # "{appliance_ids}" becomes the list of inventory appliance ids (sent in
    # chunks of `body_chunk`).
    body: dict[str, Any] | None = None
    body_chunk: int = Field(default=200, ge=1, le=5000)
    interval_s: int = Field(default=60, ge=10, le=3600)
    # Where the records are in the response: "" = the response itself; dotted path otherwise.
    records: str | None = None
    # Optional list inside each record to flatten (each element becomes a row;
    # the outer record is reachable as $parent.*).
    expand: str | None = None
    # Run once per inventory row, substituting {appliance_id}/{hostname}/{site}.
    fan_out: Literal["appliances"] | None = None
    buckets: Buckets | None = None
    fields: dict[str, FieldMap] = {}


class LoginSection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["POST", "GET"] | None = None
    path: str | None = None
    body: dict[str, Any] = {}
    token_field: str | None = None
    token_header: str | None = None


class AuthSection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["header", "login"] | None = None
    header_name: str | None = None
    login: LoginSection | None = None


class MappingFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    orchestrator_version: str = Field(min_length=1)
    # Free text: which Swagger export this mapping was filled from.
    source: str = ""
    auth: AuthSection = AuthSection()
    collectors: dict[CollectorName, Collector] = {}

    @model_validator(mode="after")
    def _complete_when_enabled(self) -> Self:
        problems: list[str] = []
        for name, col in self.collectors.items():
            known = NORMALIZED[name]
            unknown = sorted(set(col.fields) - set(known))
            if unknown:
                problems.append(f"collectors.{name}.fields: unknown field(s) {', '.join(unknown)} "
                                f"(allowed: {', '.join(known)})")
            for fname, fm in col.fields.items():
                spec = known.get(fname)
                if spec is None:
                    continue
                if spec.type == "datetime" and fm.from_ not in (None, *TIME_SOURCES) \
                        and fm.convert not in DATETIME_CONVERTS:
                    problems.append(f"collectors.{name}.fields.{fname}: datetime field needs convert "
                                    f"epoch_s, epoch_ms, epoch_us or iso8601 (or from: $now / $bucket_start)")
                if fm.from_ in TIME_SOURCES and spec.type != "datetime":
                    problems.append(f"collectors.{name}.fields.{fname}: {fm.from_} is only valid for datetime fields")
                if fm.from_ in ("$bucket_start", "$bucket_end") and col.buckets is None:
                    problems.append(f"collectors.{name}.fields.{fname}: {fm.from_} needs buckets")
                if fm.scale is not None and spec.type not in ("float", "int"):
                    problems.append(f"collectors.{name}.fields.{fname}: scale only applies to numeric fields")
            if not col.enabled:
                continue
            where = f"collectors.{name} is enabled but"
            if not col.path:
                problems.append(f"{where} path is null — find the GET path with buffmon-orch-discover")
            elif not col.path.startswith("/"):
                problems.append(f"{where} path {col.path!r} does not start with '/'")
            if col.records is None:
                problems.append(f"{where} records is null — set the dotted path to the record list "
                                f"in the response (\"\" if the response is the list)")
            for fname, spec in known.items():
                mapped = col.fields.get(fname)
                if spec.required and (mapped is None or (mapped.from_ is None and mapped.default is None)):
                    problems.append(f"{where} required field {fname!r} has no 'from' (or default)")
            placeholders = set(_PLACEHOLDER.findall(col.path or ""))
            if placeholders and col.fan_out is None:
                problems.append(f"{where} path has placeholders {sorted(placeholders)} without fan_out")
            if placeholders - FAN_OUT_FIELDS:
                problems.append(f"{where} path placeholders {sorted(placeholders - FAN_OUT_FIELDS)} "
                                f"are not inventory fields ({', '.join(sorted(FAN_OUT_FIELDS))})")
            if col.method == "POST":
                if col.path not in READ_ONLY_POSTS:
                    problems.append(f"{where} method POST is only allowed for the approved read-only POSTs "
                                    f"({', '.join(sorted(READ_ONLY_POSTS))}); {col.path!r} is not one of them")
                if col.body is None:
                    problems.append(f"{where} method POST needs a body")
            elif col.body is not None:
                problems.append(f"{where} a GET collector cannot have a body")
            if _uses_appliance_ids(col.body):
                inv = self.collectors.get("appliances")
                if inv is None or not inv.enabled:
                    problems.append(f"{where} body uses {{appliance_ids}}, which needs the appliances collector")
            in_params = {p for v in col.params.values() if isinstance(v, str) for p in _PLACEHOLDER.findall(v)}
            allowed = (FAN_OUT_FIELDS if col.fan_out else set()) | (BUCKET_FIELDS if col.buckets else set())
            if in_params - allowed:
                problems.append(f"{where} params use placeholders {sorted(in_params - allowed)} that are not "
                                f"available (inventory fields need fan_out; bucket_* need buckets)")
            if col.fan_out == "appliances":
                inv = self.collectors.get("appliances")
                if inv is None or not inv.enabled:
                    problems.append(f"{where} fan_out: appliances needs the appliances collector enabled")
        if any(c.enabled for c in self.collectors.values()):
            a = self.auth
            if a.mode is None:
                problems.append("a collector is enabled but auth.mode is null — set 'header' or 'login' "
                                "from the Swagger security definitions")
            elif a.mode == "header" and not a.header_name:
                problems.append("auth.mode is 'header' but auth.header_name is null")
            elif a.mode == "login":
                if a.login is None or not a.login.method or not a.login.path:
                    problems.append("auth.mode is 'login' but auth.login.method/path are not set")
                elif a.login.token_field and not a.login.token_header:
                    problems.append("auth.login.token_field is set but token_header is null")
        if problems:
            raise ValueError("mapping incomplete:\n  - " + "\n  - ".join(problems))
        return self

    def enabled(self) -> dict[CollectorName, Collector]:
        return {n: c for n, c in self.collectors.items() if c.enabled}


def load_mapping(path: Path) -> MappingFile:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read mapping {path}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"mapping {path} is not valid YAML: {exc}") from exc
    try:
        return MappingFile.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"mapping {path} is invalid:\n{exc}") from exc


# -- normalization -------------------------------------------------------------
class ConversionError(ValueError):
    pass


def _to_datetime(raw: Any, convert: str) -> datetime:
    if convert == "iso8601":
        text = str(raw).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    divisor = {"epoch_s": 1.0, "epoch_ms": 1e3, "epoch_us": 1e6}[convert]
    return datetime.fromtimestamp(float(raw) / divisor, tz=UTC)


def convert_value(raw: Any, fm: FieldMap, ftype: FieldType) -> Any:
    """Applies map -> convert -> scale, then coerces to the normalized type."""
    if raw is None or (fm.null_if and raw in fm.null_if):
        return fm.default
    if isinstance(raw, dict | list):
        raise ConversionError(f"expected a scalar, got {type(raw).__name__}")
    if fm.pattern is not None:
        m = re.search(fm.pattern, str(raw))
        if m is None or m.group(1) is None:
            return fm.default
        raw = m.group(1)
    if fm.map is not None and str(raw) in fm.map:
        raw = fm.map[str(raw)]
    try:
        if ftype == "datetime":
            return _to_datetime(raw, fm.convert)
        if ftype == "str":
            return str(raw)
        value = float(raw)
        value = {
            "us_to_ms": value / 1000.0,
            "s_to_ms": value * 1000.0,
            "fraction_to_pct": value * 100.0,
        }.get(fm.convert, value)
        if fm.scale is not None:
            value *= fm.scale
        return round(value) if ftype == "int" else value
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise ConversionError(f"cannot convert {raw!r} with {fm.convert}: {exc}") from exc


def _resolve(path: str, record: Any, key: str | None, parent: Any, ctx: Mapping[str, Any]) -> Any:
    if path == "$key":
        return key
    if path.startswith("$parent."):
        return dig(parent, path[len("$parent."):])
    if path.startswith("$ctx."):
        return ctx.get(path[len("$ctx."):])
    return dig(record, path)


def extract_records(response: Any, col: Collector) -> list[tuple[Any, str | None, Any]]:
    """(record, key, parent) triples for the collector's records/expand settings."""
    container = response if not col.records else dig(response, col.records)
    if container is None:
        return []
    if isinstance(container, list):
        items: list[tuple[Any, str | None]] = [(r, None) for r in container]
    elif isinstance(container, dict):
        items = [(r, str(k)) for k, r in container.items()]
    else:
        return []
    if not col.expand:
        return [(r, k, None) for r, k in items]
    out: list[tuple[Any, str | None, Any]] = []
    for r, k in items:
        inner = dig(r, col.expand)
        if isinstance(inner, list):
            out.extend((x, k, r) for x in inner)
    return out


def _ch_datetime(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def normalize(
    name: str,
    col: Collector,
    response: Any,
    now: datetime,
    orch_version: str,
    ctx: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Maps one response to normalized rows. Returns (rows, problems); a record
    missing a required field is skipped and reported, never half-written."""
    spec = NORMALIZED[name]
    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    ctx = ctx or {}
    for i, (record, key, parent) in enumerate(extract_records(response, col)):
        row: dict[str, Any] = {}
        bad: list[str] = []
        for fname, nf in spec.items():
            fm = col.fields.get(fname)
            if fm is None:
                value = None
            elif fm.from_ == "$now":
                value = now
            elif fm.from_ in ("$bucket_start", "$bucket_end"):
                value = ctx.get(fm.from_[1:])
            else:
                raw = _resolve(fm.from_, record, key, parent, ctx) if fm.from_ else None
                try:
                    value = convert_value(raw, fm, nf.type)
                except ConversionError as exc:
                    bad.append(f"{fname}: {exc}")
                    continue
            if value is None and fname in ("site", "appliance") and name != "appliances":
                value = ctx.get("site" if fname == "site" else "hostname")
            if nf.required and value in (None, ""):
                bad.append(f"{fname}: missing")
            row[fname] = _ch_datetime(value) if isinstance(value, datetime) else value
        if bad:
            problems.append(f"{name} record {i}: " + "; ".join(bad))
            continue
        if name == "tunnel_stats" and row.get("tunnel_kind") == "overlay":
            # An overlay (bonded) tunnel spans several underlays: no single transport.
            row["transport"] = None
        if name in STORED_TABLES:
            for fname, nf in spec.items():
                if nf.type == "str" and row.get(fname) is None and not nf.required:
                    row[fname] = ""
            row["orch_version"] = orch_version
        rows.append(row)
    return rows, problems


def render_params(params: Mapping[str, str | int | float | bool], ctx: Mapping[str, Any]) -> dict[str, Any]:
    """Fills {placeholders} in string parameter values from the fan-out row and bucket."""

    def sub(m: re.Match[str]) -> str:
        value = ctx.get(m.group(1))
        if value in (None, ""):
            raise ValueError(f"no value for parameter placeholder {m.group(1)!r}")
        return str(value)

    return {k: _PLACEHOLDER.sub(sub, v) if isinstance(v, str) else v for k, v in params.items()}


APPLIANCE_IDS = "{appliance_ids}"


def _uses_appliance_ids(body: Any) -> bool:
    if body == APPLIANCE_IDS:
        return True
    if isinstance(body, dict):
        return any(_uses_appliance_ids(v) for v in body.values())
    if isinstance(body, list):
        return any(_uses_appliance_ids(v) for v in body)
    return False


def render_body(body: Any, appliance_ids: list[str]) -> Any:
    """Replaces every "{appliance_ids}" string in the body with the id list."""
    if body == APPLIANCE_IDS:
        return list(appliance_ids)
    if isinstance(body, dict):
        return {k: render_body(v, appliance_ids) for k, v in body.items()}
    if isinstance(body, list):
        return [render_body(v, appliance_ids) for v in body]
    return body


def bucket_context(start_s: int, end_s: int) -> dict[str, Any]:
    return {
        "bucket_start_s": start_s, "bucket_end_s": end_s,
        "bucket_start_ms": start_s * 1000, "bucket_end_ms": end_s * 1000,
        "bucket_start": datetime.fromtimestamp(start_s, tz=UTC),
        "bucket_end": datetime.fromtimestamp(end_s, tz=UTC),
    }


def render_path(template: str, ctx: Mapping[str, Any]) -> str:
    """Fills {placeholders} from an inventory row (values are URL-path-escaped)."""

    def sub(m: re.Match[str]) -> str:
        value = ctx.get(m.group(1))
        if value in (None, ""):
            raise ValueError(f"inventory row has no {m.group(1)!r} for path {template}")
        return quote(str(value), safe="")

    return _PLACEHOLDER.sub(sub, template)
