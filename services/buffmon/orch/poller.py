"""Polls Orchestrator through the read-only client and writes normalized rows.

    buffmon-orch-poll --mapping deploy/orchestrator/mapping.9.7.2.yaml --once --dry-run

``--dry-run`` prints normalized rows as JSON lines and writes nothing: the safe
first thing to run against a real Orchestrator. Without it, rows go to the
ClickHouse tables from ``deploy/clickhouse/003_tunnel_stats.sql``.

Connection settings come from the environment (or flags), never from the mapping:

    BUFFMON_ORCH_URL            https://orchestrator.example
    BUFFMON_ORCH_TOKEN_FILE     file holding the API token        (auth.mode: header)
    BUFFMON_ORCH_TOKEN          the API token itself (prefer the file)
    BUFFMON_ORCH_USERNAME / BUFFMON_ORCH_PASSWORD_FILE             (auth.mode: login)
    BUFFMON_ORCH_CA_BUNDLE      PEM bundle for a private CA (TLS verification stays on)
    BUFFMON_CLICKHOUSE_URL / _USER / _PASSWORD / _DATABASE         (writes)
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import SecretStr

from ..store import HttpTransport
from .client import AuthConfig, ClientConfig, LoginSpec, OrchClient, OrchError, load_secret
from .mapping import (
    STORED_TABLES,
    Collector,
    CollectorName,
    MappingFile,
    bucket_context,
    load_mapping,
    normalize,
    render_body,
    render_params,
    render_path,
)

log = logging.getLogger(__name__)

ORCH_TABLES = frozenset(STORED_TABLES.values())
# Natural keys per table: a re-poll of the same sample yields the same key, so
# ReplacingMergeTree collapses it and the dedup token makes retries a no-op.
TABLE_KEYS: dict[str, tuple[str, ...]] = {
    "tunnel_stats": ("appliance", "tunnel_id", "ts"),
    "alarms": ("appliance", "alarm_id", "ts", "state"),
}


class RowSink(Protocol):
    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None: ...


class OrchTransport(HttpTransport):
    """The ingest service's ClickHouse transport, restricted to the Orchestrator tables."""

    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None:
        if table not in ORCH_TABLES:
            raise ValueError(f"unknown table {table!r}")
        body = "\n".join(json.dumps(r, separators=(",", ":")) for r in rows).encode("utf-8")
        params = {
            "query": f"INSERT INTO {self._db}.{table} FORMAT JSONEachRow",
            "insert_deduplication_token": dedup_token,
        }
        try:
            resp = await self._client.post("/", params=params, content=body)
        except httpx.HTTPError as exc:
            raise OrchError(f"insert into {table} failed: {type(exc).__name__}: {exc}") from exc
        if resp.status_code != 200:
            raise OrchError(f"insert into {table} failed: HTTP {resp.status_code}: {resp.text[:300]}")


def rows_token(table: str, rows: Sequence[Mapping[str, Any]]) -> str:
    h = hashlib.sha256(table.encode())
    for r in rows:
        h.update("\x1f".join(str(r.get(k)) for k in TABLE_KEYS[table]).encode() + b"\x1e")
    return h.hexdigest()


class Poller:
    def __init__(
        self,
        mapping: MappingFile,
        client: OrchClient,
        sink: RowSink | None,
        now: Callable[[], datetime] = lambda: datetime.now(tz=UTC),
    ) -> None:
        self.mapping = mapping
        self.client = client
        self.sink = sink
        self._now = now
        self.inventory: list[dict[str, Any]] = []
        self.problems = 0
        for name in ("appliances", "tunnel_stats", "alarms"):
            col = mapping.collectors.get(name)
            if col is None or not col.enabled:
                log.info("collector %s is not enabled in the %s mapping; it stays idle",
                         name, mapping.orchestrator_version)

    async def _fetch(
        self, name: CollectorName, col: Collector, ctx: Mapping[str, Any] | None
    ) -> list[dict[str, Any]]:
        assert col.path is not None  # guaranteed by mapping validation for enabled collectors
        path = render_path(col.path, ctx) if ctx else col.path
        now = self._now()
        windows: list[dict[str, Any]] = (
            [bucket_context(s, e) for s, e in col.buckets.windows(int(now.timestamp()))] if col.buckets else [{}]
        )
        rows: list[dict[str, Any]] = []
        for window in windows:
            full_ctx = {**(ctx or {}), **window}
            params = render_params(col.params, full_ctx)
            if col.method == "POST":
                ids = [str(r["appliance_id"]) for r in self.inventory]
                responses = [
                    await self.client.post_read_json(
                        path, params, render_body(col.body, ids[i:i + col.body_chunk])
                    )
                    for i in range(0, max(len(ids), 1), col.body_chunk)
                ]
            else:
                responses = [await self.client.get_json(path, params)]
            for response in responses:
                got, problems = normalize(name, col, response, now, self.mapping.orchestrator_version, full_ctx)
                rows.extend(got)
                for p in problems[:5]:
                    log.warning("%s: %s", path, p)
                if len(problems) > 5:
                    log.warning("%s: %d more records skipped", path, len(problems) - 5)
                self.problems += len(problems)
        return rows

    async def poll(self, name: CollectorName) -> list[dict[str, Any]]:
        col = self.mapping.collectors[name]
        if col.method == "POST" and not self.inventory and name != "appliances":
            await self.poll("appliances")
        if col.fan_out == "appliances":
            if not self.inventory:
                await self.poll("appliances")
            results = await asyncio.gather(
                *(self._fetch(name, col, ctx) for ctx in self.inventory), return_exceptions=True
            )
            rows: list[dict[str, Any]] = []
            for ctx, res in zip(self.inventory, results, strict=True):
                if isinstance(res, BaseException):
                    if not isinstance(res, OrchError | ValueError):
                        raise res
                    log.warning("%s for %s failed: %s", name, ctx.get("hostname"), res)
                else:
                    rows.extend(res)
        else:
            rows = await self._fetch(name, col, None)
        if name == "appliances":
            self.inventory = rows
            log.info("inventory: %d appliances", len(rows))
        elif rows and self.sink is not None:
            table = STORED_TABLES[name]
            await self.sink.insert_rows(table, rows, rows_token(table, rows))
        return rows

    async def run_once(self) -> dict[str, list[dict[str, Any]]]:
        out: dict[str, list[dict[str, Any]]] = {}
        enabled = self.mapping.enabled()
        if "appliances" in enabled:
            out["appliances"] = await self.poll("appliances")
        for name in enabled:
            if name != "appliances":
                out[name] = await self.poll(name)
        return out

    async def run(self, stop: asyncio.Event) -> None:
        enabled = self.mapping.enabled()
        due = dict.fromkeys(enabled, 0.0)
        while not stop.is_set():
            now = time.monotonic()
            for name, col in enabled.items():
                if now >= due[name]:
                    due[name] = now + col.interval_s
                    try:
                        await self.poll(name)
                    except (OrchError, ValueError) as exc:
                        log.error("collector %s failed: %s", name, exc)
            wait = max(0.5, min(due.values(), default=now + 60) - time.monotonic())
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=wait)


def build_auth(mapping: MappingFile, args: argparse.Namespace) -> AuthConfig:
    a = mapping.auth
    if a.mode == "header":
        token = load_secret(args.token_file, args.token_env, "Orchestrator token")
        return AuthConfig(mode="header", header_name=a.header_name, token=token)
    if a.mode == "login" and a.login is not None and a.login.method and a.login.path:
        password = load_secret(args.password_file, "BUFFMON_ORCH_PASSWORD", "Orchestrator password")
        username = os.environ.get("BUFFMON_ORCH_USERNAME", "")
        return AuthConfig(
            mode="login",
            login=LoginSpec(method=a.login.method, path=a.login.path, body=a.login.body,
                            token_field=a.login.token_field, token_header=a.login.token_header),
            username=SecretStr(username) if username else None,
            password=password,
        )
    raise OrchError("the mapping has no usable auth section (auth.mode is null)")


def _env_path(name: str) -> Path | None:
    # Not `Path(x or "") or None`: Path("") is Path(".") and is truthy.
    value = os.environ.get(name, "").strip()
    return Path(value) if value else None


def main(argv: list[str] | None = None, *, transport: httpx.AsyncBaseTransport | None = None) -> int:
    env = os.environ.get
    ap = argparse.ArgumentParser(prog="buffmon-orch-poll", description="Poll Orchestrator (read-only).")
    ap.add_argument("--mapping", type=Path, required=True, help="deploy/orchestrator/mapping.<version>.yaml")
    ap.add_argument("--url", default=env("BUFFMON_ORCH_URL"), help="Orchestrator base URL (BUFFMON_ORCH_URL)")
    ap.add_argument("--token-file", type=Path, default=_env_path("BUFFMON_ORCH_TOKEN_FILE"))
    ap.add_argument("--token-env", default="BUFFMON_ORCH_TOKEN", help="env var holding the token")
    ap.add_argument("--password-file", type=Path, default=_env_path("BUFFMON_ORCH_PASSWORD_FILE"))
    ap.add_argument("--ca-bundle", type=Path, default=_env_path("BUFFMON_ORCH_CA_BUNDLE"))
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--once", action="store_true", help="poll every enabled collector once and exit")
    ap.add_argument("--dry-run", action="store_true", help="print normalized rows; write nothing")
    ap.add_argument("--limit", type=int, default=20, help="rows printed per collector in --dry-run")
    ap.add_argument("--log-level", default=env("BUFFMON_LOG_LEVEL", "INFO"))
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        mapping = load_mapping(args.mapping)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not mapping.enabled():
        print(f"error: no collector is enabled in {args.mapping}; fill it from the Swagger export first "
              f"(see deploy/orchestrator/README.md)", file=sys.stderr)
        return 2
    if not args.url:
        print("error: set --url or BUFFMON_ORCH_URL", file=sys.stderr)
        return 2
    try:
        cfg = ClientConfig(base_url=args.url, auth=build_auth(mapping, args), timeout_s=args.timeout,
                           ca_bundle=args.ca_bundle)
        client = OrchClient(cfg, transport=transport)
    except OrchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    sink: OrchTransport | None = None
    if not args.dry_run:
        sink = OrchTransport(
            base_url=env("BUFFMON_CLICKHOUSE_URL", "http://127.0.0.1:8123"),
            database=env("BUFFMON_CLICKHOUSE_DATABASE", "buffmon"),
            user=env("BUFFMON_CLICKHOUSE_USER", "default"),
            password=env("BUFFMON_CLICKHOUSE_PASSWORD", ""),
            timeout_s=30,
        )
    poller = Poller(mapping, client, sink)

    async def go() -> int:
        try:
            if args.once or args.dry_run:
                results = await poller.run_once()
                for name, rows in results.items():
                    print(f"# {name}: {len(rows)} row(s)", file=sys.stderr)
                    if args.dry_run:
                        for r in rows[: args.limit]:
                            print(json.dumps({"collector": name, **r}, default=str))
                return 0 if poller.problems == 0 else 1
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, stop.set)
            await poller.run(stop)
            return 0
        except OrchError as exc:
            log.error("%s", exc)
            return 1
        finally:
            await client.aclose()
            if sink is not None:
                await sink.aclose()

    return asyncio.run(go())


if __name__ == "__main__":
    raise SystemExit(main())
