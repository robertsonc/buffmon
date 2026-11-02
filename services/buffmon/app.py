"""FastAPI application: probe ingest, live WebSocket, history API and dashboard."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
import zlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from .auth import ProbeTokens, bearer_token
from .config import Settings
from .dedup import RecentKeys
from .flows.path import analyse, query_paths
from .live import WINDOWS_S, LiveHub
from .models import NAME_PATTERN, IngestBatch, ProbeRecord
from .routes import (
    CAPACITY_TABLE,
    ROUTE_TABLE,
    CapacityResult,
    RouteResult,
    RouteView,
    capacity_to_row,
    query_route_history,
    route_to_row,
)
from .speedtest import (
    SPEEDTEST_TABLE,
    JobBoard,
    PolicyError,
    Poll,
    Refused,
    SpeedtestResult,
    load_policy,
    result_to_row,
)
from .speedtest import query_history as query_speedtests
from .store import (
    HISTORY_RANGES,
    ClickHouseError,
    HttpTransport,
    SampleWriter,
    Transport,
    batch_token,
    content_token,
    query_history,
    record_to_row,
)
from .thresholds import ThresholdsFile
from .tunnels import query_tunnels
from .uiauth import COOKIE_NAME, UiAuth

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
_NAME_RE = re.compile(NAME_PATTERN)

_CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


class PayloadTooLargeError(Exception):
    pass


@dataclass
class Counters:
    requests: int = 0
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    auth_failures: int = 0
    bad_requests: int = 0


@dataclass
class AppState:
    settings: Settings
    tokens: ProbeTokens
    dedup: RecentKeys
    thresholds_file: ThresholdsFile
    hub: LiveHub
    ui: UiAuth
    transport: Transport | None
    writer: SampleWriter | None
    clock: Callable[[], float]
    route_writer: SampleWriter | None = None
    capacity_writer: SampleWriter | None = None
    speedtest_writer: SampleWriter | None = None
    routes: RouteView = field(default_factory=RouteView)
    jobs: JobBoard | None = None
    counters: Counters = field(default_factory=Counters)
    started_at: float = field(default_factory=time.time)


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", _CSP)
        if request.url.path.startswith("/v1/") or request.url.path in ("/", "/login"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


async def _read_limited(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise PayloadTooLargeError
    size = 0
    chunks: list[bytes] = []
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise PayloadTooLargeError
        chunks.append(chunk)
    return b"".join(chunks)


def _gunzip_limited(data: bytes, limit: int) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, limit + 1)
    except zlib.error as exc:
        raise ValueError(f"invalid gzip body: {exc}") from exc
    if len(out) > limit or d.unconsumed_tail:
        raise PayloadTooLargeError
    if not d.eof:
        raise ValueError("truncated gzip body")
    return out


def _short_validation_error(exc: ValidationError) -> str:
    errs = exc.errors(include_url=False)
    first = errs[0]
    loc = ".".join(str(p) for p in first.get("loc", ())) or "record"
    more = f" (+{len(errs) - 1} more)" if len(errs) > 1 else ""
    return f"{loc}: {first.get('msg', 'invalid')}{more}"


def _client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def build_state(settings: Settings, transport: Transport | None, clock: Callable[[], float]) -> AppState:
    thresholds_file = ThresholdsFile(settings.thresholds_file)
    if transport is None and settings.clickhouse_enabled:
        transport = HttpTransport(
            base_url=settings.clickhouse_url,
            database=settings.clickhouse_database,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password.get_secret_value(),
            timeout_s=settings.clickhouse_timeout_s,
        )
    writer = (
        SampleWriter(
            transport,
            batch_max=settings.insert_batch_max,
            flush_interval_s=settings.insert_flush_interval_s,
            buffer_max=settings.insert_buffer_max,
            retry_max_s=settings.insert_retry_max_s,
        )
        if transport is not None
        else None
    )
    side_writers = {
        table: SampleWriter(transport, batch_max=1000, flush_interval_s=settings.insert_flush_interval_s,
                            buffer_max=20_000, retry_max_s=settings.insert_retry_max_s, table=table,
                            # Speed-test rows are keyed by job, not by session second.
                            token_fn=content_token if table == SPEEDTEST_TABLE else batch_token)
        for table in (ROUTE_TABLE, CAPACITY_TABLE, SPEEDTEST_TABLE)
    } if transport is not None else {}
    try:
        policy = load_policy(settings.speedtest_policy)
    except PolicyError as exc:
        raise ValueError(str(exc)) from exc
    if policy.enabled:
        log.warning("RFC 9946 speed tests ENABLED for probes %s (max %d Mbit/s, %d s, %d at once)",
                    policy.probes, policy.max_mbps, policy.max_duration_s, policy.max_concurrent)
    if writer is None:
        log.warning("ClickHouse is disabled: live view only, nothing is stored and history is unavailable")
    return AppState(
        settings=settings,
        tokens=ProbeTokens(settings.probe_tokens_file, settings.probe_tokens_reload_s),
        dedup=RecentKeys(settings.dedup_ttl_s, settings.dedup_max_keys),
        thresholds_file=thresholds_file,
        hub=LiveHub(
            thresholds_file.current,
            retention_s=settings.live_retention_s,
            session_expiry_s=settings.live_session_expiry_s,
            no_data_after_s=settings.no_data_after_s,
            clock=clock,
        ),
        ui=UiAuth(
            enabled=settings.ui_auth == "enabled",
            token_sha256=settings.ui_token_sha256,
            secret=settings.session_secret.get_secret_value() if settings.session_secret else None,
            ttl_s=settings.session_ttl_s,
            max_failures_per_min=settings.login_max_failures_per_min,
        ),
        transport=transport,
        writer=writer,
        clock=clock,
        route_writer=side_writers.get(ROUTE_TABLE),
        capacity_writer=side_writers.get(CAPACITY_TABLE),
        speedtest_writer=side_writers.get(SPEEDTEST_TABLE),
        jobs=JobBoard(policy, clock=clock, poll_s=settings.speedtest_poll_s),
    )


def create_app(
    settings: Settings,
    transport: Transport | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    state = build_state(settings, transport, clock)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        stop = asyncio.Event()
        tasks: list[asyncio.Task[None]] = []
        if state.writer is not None:
            tasks.append(asyncio.create_task(state.writer.run(stop), name="clickhouse-writer"))
        for w in (state.route_writer, state.capacity_writer, state.speedtest_writer):
            if w is not None:
                tasks.append(asyncio.create_task(w.run(stop), name="clickhouse-writer"))
        tasks.append(asyncio.create_task(_housekeeping(state, stop), name="housekeeping"))
        try:
            yield
        finally:
            stop.set()
            for t in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await asyncio.wait_for(t, timeout=5)
            for w in (state.writer, state.route_writer, state.capacity_writer, state.speedtest_writer):
                if w is not None and w.depth:
                    try:
                        await asyncio.wait_for(w.flush_once(), timeout=10)
                    except TimeoutError:
                        log.warning("shutdown flush timed out with %d rows unwritten", w.depth)
            if state.transport is not None:
                await state.transport.aclose()

    app = FastAPI(title="buffmon ingest", version="0.1.0", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.buffmon = state
    app.add_middleware(SecurityHeaders)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    def ui_ok(request: Request) -> bool:
        return state.ui.valid(request.cookies.get(COOKIE_NAME))

    def unauthorized() -> JSONResponse:
        return JSONResponse({"error": "login required"}, status_code=401)

    # -- probe ingest ---------------------------------------------------------
    @app.post("/v1/probe/results")
    async def ingest(request: Request) -> JSONResponse:
        c = state.counters
        c.requests += 1
        probe_id = state.tokens.authenticate(bearer_token(request.headers.get("authorization")))
        if probe_id is None:
            c.auth_failures += 1
            return JSONResponse({"error": "missing or unknown probe token"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        limit = state.settings.max_body_bytes
        try:
            body = await _read_limited(request, limit)
            encoding = request.headers.get("content-encoding", "").strip().lower()
            if encoding == "gzip":
                body = _gunzip_limited(body, limit)
            elif encoding not in ("", "identity"):
                c.bad_requests += 1
                return JSONResponse({"error": f"unsupported content-encoding {encoding!r}"}, status_code=400)
        except PayloadTooLargeError:
            return JSONResponse({"error": f"body exceeds {limit} bytes; split the batch"}, status_code=413)
        except ValueError as exc:
            c.bad_requests += 1
            return JSONResponse({"error": str(exc)}, status_code=400)

        try:
            parsed: Any = json.loads(body)
            batch = IngestBatch.model_validate(parsed)
        except (json.JSONDecodeError, UnicodeDecodeError):
            c.bad_requests += 1
            return JSONResponse({"error": "body is not valid JSON"}, status_code=400)
        except ValidationError as exc:
            c.bad_requests += 1
            return JSONResponse({"error": f"invalid batch: {_short_validation_error(exc)}"}, status_code=400)

        if batch.probe_id != probe_id:
            c.auth_failures += 1
            log.warning("probe token for %s used to submit probe_id %s", probe_id, batch.probe_id)
            return JSONResponse({"error": "token is not valid for this probe_id"}, status_code=403)
        if len(batch.records) + len(batch.routes) + len(batch.capacity) + len(batch.speedtests) > \
                state.settings.max_records:
            return JSONResponse(
                {"error": f"at most {state.settings.max_records} records per request; split the batch"},
                status_code=413,
            )

        now_ms = int(state.clock() * 1000)
        skew = state.settings.ts_skew_ms
        accepted = duplicates = rejected = 0
        errors: list[dict[str, Any]] = []
        rows: list[dict[str, Any]] = []
        for i, raw in enumerate(batch.records):
            try:
                rec = ProbeRecord.model_validate(raw)
            except ValidationError as exc:
                rejected += 1
                errors.append({"index": i, "error": _short_validation_error(exc)})
                continue
            if rec.probe_id != probe_id:
                rejected += 1
                errors.append({"index": i, "error": "probe_id does not match the token"})
                continue
            if abs(rec.ts_ms - now_ms) > skew:
                rejected += 1
                errors.append({"index": i, "error": "ts_ms is more than 24 h from server time; check the probe clock"})
                continue
            if state.dedup.seen(rec.key):
                duplicates += 1
                continue
            state.dedup.add(rec.key)
            state.hub.ingest(rec)
            rows.append(record_to_row(rec))
            accepted += 1

        if state.writer is not None:
            state.writer.enqueue(rows)

        # Phase 3 results: same checks (token, clock skew, idempotency), their own tables.
        route_rows: list[dict[str, Any]] = []
        capacity_rows: list[dict[str, Any]] = []
        sections: tuple[tuple[str, list[object], type[RouteResult] | type[CapacityResult]], ...] = (
            ("routes", batch.routes, RouteResult),
            ("capacity", batch.capacity, CapacityResult),
        )
        for section, items, model in sections:
            for i, raw in enumerate(items):
                try:
                    res = model.model_validate(raw)
                except ValidationError as exc:
                    rejected += 1
                    errors.append({"section": section, "index": i, "error": _short_validation_error(exc)})
                    continue
                if res.probe_id != probe_id:
                    rejected += 1
                    errors.append({"section": section, "index": i, "error": "probe_id does not match the token"})
                    continue
                if abs(res.ts_ms - now_ms) > skew:
                    rejected += 1
                    errors.append({"section": section, "index": i,
                                   "error": "ts_ms is more than 24 h from server time; check the probe clock"})
                    continue
                if state.dedup.seen(res.key):
                    duplicates += 1
                    continue
                state.dedup.add(res.key)
                if isinstance(res, RouteResult):
                    state.routes.add_route(res)
                    route_rows.append(route_to_row(res))
                else:
                    state.routes.add_capacity(res)
                    capacity_rows.append(capacity_to_row(res))
                accepted += 1
        # Phase 3.3: speed-test results answer jobs this probe was given.
        speed_rows: list[dict[str, Any]] = []
        for i, raw in enumerate(batch.speedtests):
            try:
                st = SpeedtestResult.model_validate(raw)
            except ValidationError as exc:
                rejected += 1
                errors.append({"section": "speedtests", "index": i, "error": _short_validation_error(exc)})
                continue
            if st.probe_id != probe_id:
                rejected += 1
                errors.append({"section": "speedtests", "index": i, "error": "probe_id does not match the token"})
                continue
            if state.dedup.seen(st.key):
                duplicates += 1
                continue
            state.dedup.add(st.key)
            if state.jobs is None or not state.jobs.complete(st):
                rejected += 1
                errors.append({"section": "speedtests", "index": i, "error": "not a job given to this probe"})
                continue
            speed_rows.append(result_to_row(st))
            accepted += 1
        if state.speedtest_writer is not None:
            state.speedtest_writer.enqueue(speed_rows)
        if state.route_writer is not None:
            state.route_writer.enqueue(route_rows)
        if state.capacity_writer is not None:
            state.capacity_writer.enqueue(capacity_rows)
        c.accepted += accepted
        c.duplicates += duplicates
        c.rejected += rejected
        if rejected:
            log.warning("probe %s: rejected %d of %d results (first: %s)", probe_id, rejected,
                        len(batch.records) + len(batch.routes) + len(batch.capacity) + len(batch.speedtests),
                        errors[0]["error"])
        return JSONResponse(
            {"accepted": accepted, "duplicates": duplicates, "rejected": rejected, "errors": errors[:20]}
        )

    # -- RFC 9946 speed tests (P3.3) -----------------------------------------
    @app.post("/v1/probe/jobs")
    async def probe_jobs(request: Request) -> JSONResponse:
        """A probe with speed-test targets checks in and collects its jobs."""
        probe_id = state.tokens.authenticate(bearer_token(request.headers.get("authorization")))
        if probe_id is None:
            return JSONResponse({"error": "missing or unknown probe token"}, status_code=401,
                                headers={"WWW-Authenticate": "Bearer"})
        try:
            body = await _read_limited(request, 64 * 1024)
            poll = Poll.model_validate(json.loads(body))
        except PayloadTooLargeError:
            return JSONResponse({"error": "body too large"}, status_code=413)
        except (ValueError, ValidationError) as exc:
            msg = _short_validation_error(exc) if isinstance(exc, ValidationError) else "body is not valid JSON"
            return JSONResponse({"error": msg}, status_code=400)
        if poll.probe_id != probe_id:
            return JSONResponse({"error": "token is not valid for this probe_id"}, status_code=403)
        jobs = state.jobs.poll(poll) if state.jobs is not None else []
        return JSONResponse({"jobs": jobs})

    @app.get("/v1/speedtests")
    async def speedtests(request: Request) -> JSONResponse:
        if not ui_ok(request):
            return unauthorized()
        board = state.jobs.snapshot() if state.jobs is not None else {"enabled": False, "probes": {}, "jobs": []}
        return JSONResponse({"server_ms": int(state.clock() * 1000), **board})

    @app.post("/v1/speedtests")
    async def request_speedtest(request: Request) -> JSONResponse:
        """Queue a speed test (dashboard). The policy, the site lock and the
        probe's own limits all apply."""
        if not ui_ok(request):
            return unauthorized()
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            return JSONResponse({"error": "cross-origin request refused"}, status_code=403)
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            return JSONResponse({"error": "content-type must be application/json"}, status_code=415)
        try:
            raw = json.loads(await _read_limited(request, 4096))
        except (PayloadTooLargeError, ValueError):
            return JSONResponse({"error": "body is not valid JSON"}, status_code=400)
        if not isinstance(raw, dict):
            return JSONResponse({"error": "body must be an object"}, status_code=400)
        probe_id, target, direction = raw.get("probe_id"), raw.get("target"), raw.get("direction")
        mbps, secs = raw.get("max_mbps"), raw.get("duration_s")
        if not (isinstance(probe_id, str) and _NAME_RE.match(probe_id) and isinstance(target, str)
                and _NAME_RE.match(target) and direction in ("down", "up")
                and (mbps is None or type(mbps) is int) and (secs is None or type(secs) is int)):
            return JSONResponse({"error": "need probe_id, target, direction (down|up); max_mbps and duration_s "
                                          "are optional integers"}, status_code=400)
        if state.jobs is None:
            return JSONResponse({"error": "speed tests are disabled"}, status_code=403)
        try:
            job = state.jobs.request(probe_id, target, direction, mbps, secs)
        except Refused as exc:
            return JSONResponse({"error": exc.reason}, status_code=exc.status)
        return JSONResponse({"job": job.public()}, status_code=202)

    @app.get("/v1/probes/{probe_id}/speedtests")
    async def speedtest_history(request: Request, probe_id: str, days: int = 30) -> JSONResponse:
        if not ui_ok(request):
            return unauthorized()
        if not _NAME_RE.match(probe_id) or not 1 <= days <= 400:
            return JSONResponse({"error": "invalid probe_id or days (1-400)"}, status_code=400)
        if state.transport is None:
            return JSONResponse({"error": "history unavailable: ClickHouse is disabled"}, status_code=503)
        try:
            rows = await query_speedtests(state.transport, probe_id, int(state.clock() * 1000) - days * 86_400_000)
        except ClickHouseError as exc:
            log.warning("speed-test history query failed: %s", exc)
            return JSONResponse({"error": "history unavailable: storage query failed"}, status_code=503)
        return JSONResponse({"probe_id": probe_id, "tests": rows})

    # -- health ---------------------------------------------------------------
    @app.get("/v1/health")
    async def health(request: Request) -> JSONResponse:
        store = state.writer.status() if state.writer is not None else None
        degraded = bool(
            store and store["last_error_at"] and (store["last_insert_at"] or 0) < store["last_error_at"]
        )
        body: dict[str, Any] = {"status": "degraded" if degraded else "ok"}
        if ui_ok(request):
            body.update(
                {
                    "uptime_s": round(time.time() - state.started_at, 1),
                    "ingest": state.counters.__dict__,
                    "store": store if store is not None else {"enabled": False},
                    "store_routes": state.route_writer.status() if state.route_writer is not None else None,
                    "store_capacity": state.capacity_writer.status() if state.capacity_writer is not None else None,
                    "routes": {"sessions": len(state.routes)},
                    "live": {"sessions": len(state.hub.sessions), "seq": state.hub.seq},
                    "dedup_keys": len(state.dedup),
                    "probe_tokens": state.tokens.count,
                }
            )
        return JSONResponse(body)

    # -- read APIs ------------------------------------------------------------
    @app.get("/v1/sessions")
    async def sessions(request: Request) -> JSONResponse:
        if not ui_ok(request):
            return unauthorized()
        return JSONResponse({"server_ms": int(state.clock() * 1000), "sessions": state.hub.snapshot()})

    @app.get("/v1/sessions/{probe_id}/{session}/history")
    async def history(request: Request, probe_id: str, session: str, range: str = "1h") -> JSONResponse:  # noqa: A002
        if not ui_ok(request):
            return unauthorized()
        if not _NAME_RE.match(probe_id) or not _NAME_RE.match(session):
            return JSONResponse({"error": "invalid probe_id or session"}, status_code=400)
        if range not in HISTORY_RANGES:
            return JSONResponse({"error": f"range must be one of {sorted(HISTORY_RANGES)}"}, status_code=400)
        if state.transport is None:
            return JSONResponse({"error": "history unavailable: ClickHouse is disabled"}, status_code=503)
        try:
            data = await query_history(state.transport, probe_id, session, range, int(state.clock() * 1000))
        except ClickHouseError as exc:
            log.warning("history query failed: %s", exc)
            return JSONResponse({"error": "history unavailable: storage query failed"}, status_code=503)
        return JSONResponse(data)

    # -- probe path validation (EdgeConnect flow export) ---------------------
    async def _paths(minutes: int, only: str | None) -> JSONResponse:
        if state.transport is None:
            return JSONResponse({"error": "paths unavailable: ClickHouse is disabled"}, status_code=503)
        now_ms = int(state.clock() * 1000)
        try:
            rows = await query_paths(state.transport, now_ms - minutes * 60_000)
        except ClickHouseError as exc:
            log.warning("path query failed: %s", exc)
            return JSONResponse({"error": "paths unavailable: storage query failed"}, status_code=503)
        out: dict[str, Any] = {}
        for key, st in list(state.hub.sessions.items()):
            if st.kind != "stamp" or (only is not None and key != only):
                continue
            out[key] = analyse(st.src, st.dst, st.dscp, st.app_class, rows, minutes)
        if only is not None and only not in out:
            return JSONResponse({"error": "no live STAMP session with that name"}, status_code=404)
        return JSONResponse({"server_ms": now_ms, "minutes": minutes, "paths": out})

    @app.get("/v1/paths")
    async def paths(request: Request, minutes: int = 5) -> JSONResponse:
        """Path summary for every live STAMP session (the dashboard polls this)."""
        if not ui_ok(request):
            return unauthorized()
        if not 1 <= minutes <= 60:
            return JSONResponse({"error": "minutes must be 1-60"}, status_code=400)
        return await _paths(minutes, None)

    @app.get("/v1/sessions/{probe_id}/{session}/path")
    async def session_path(request: Request, probe_id: str, session: str, minutes: int = 10) -> JSONResponse:
        if not ui_ok(request):
            return unauthorized()
        if not _NAME_RE.match(probe_id) or not _NAME_RE.match(session):
            return JSONResponse({"error": "invalid probe_id or session"}, status_code=400)
        if not 1 <= minutes <= 60:
            return JSONResponse({"error": "minutes must be 1-60"}, status_code=400)
        return await _paths(minutes, f"{probe_id}/{session}")

    # -- forward route traces and capacity (probe, Phase 3) ------------------
    @app.get("/v1/routes")
    async def routes(request: Request) -> JSONResponse:
        """Latest route trace, recent route changes and latest capacity per session
        (in memory; the dashboard polls this)."""
        if not ui_ok(request):
            return unauthorized()
        return JSONResponse({"server_ms": int(state.clock() * 1000), "sessions": state.routes.snapshot()})

    @app.get("/v1/sessions/{probe_id}/{session}/routes")
    async def session_routes(request: Request, probe_id: str, session: str, hours: int = 24) -> JSONResponse:
        if not ui_ok(request):
            return unauthorized()
        if not _NAME_RE.match(probe_id) or not _NAME_RE.match(session):
            return JSONResponse({"error": "invalid probe_id or session"}, status_code=400)
        if not 1 <= hours <= 24 * 90:
            return JSONResponse({"error": "hours must be 1-2160"}, status_code=400)
        if state.transport is None:
            return JSONResponse({"error": "route history unavailable: ClickHouse is disabled"}, status_code=503)
        from_ms = int(state.clock() * 1000) - hours * 3_600_000
        try:
            data = await query_route_history(state.transport, probe_id, session, from_ms)
        except ClickHouseError as exc:
            log.warning("route history query failed: %s", exc)
            return JSONResponse({"error": "route history unavailable: storage query failed"}, status_code=503)
        return JSONResponse(data)

    # -- EdgeConnect tunnel health (Orchestrator, via buffmon-orch-poll) -----
    @app.get("/v1/tunnels")
    async def tunnels(request: Request, minutes: int = 15, appliance: str = "") -> JSONResponse:
        if not ui_ok(request):
            return unauthorized()
        if not 1 <= minutes <= 1440:
            return JSONResponse({"error": "minutes must be 1-1440"}, status_code=400)
        if appliance and not _NAME_RE.match(appliance):
            return JSONResponse({"error": "invalid appliance"}, status_code=400)
        if state.transport is None:
            return JSONResponse({"error": "tunnels unavailable: ClickHouse is disabled"}, status_code=503)
        now_ms = int(state.clock() * 1000)
        try:
            rows = await query_tunnels(state.transport, now_ms - minutes * 60_000, appliance)
        except ClickHouseError as exc:
            log.warning("tunnel query failed: %s", exc)
            return JSONResponse({"error": "tunnels unavailable: storage query failed"}, status_code=503)
        return JSONResponse({"server_ms": now_ms, "minutes": minutes, "tunnels": rows})

    # -- live WebSocket -------------------------------------------------------
    @app.websocket("/v1/live")
    async def live(ws: WebSocket) -> None:
        if not state.ui.valid(ws.cookies.get(COOKIE_NAME)):
            await ws.close(code=4401)
            return
        origin = ws.headers.get("origin")
        if origin and urlsplit(origin).netloc != ws.headers.get("host"):
            await ws.close(code=4403)
            return
        await ws.accept()
        hub = state.hub
        closed = asyncio.Event()

        async def reader() -> None:
            try:
                while True:
                    msg = await ws.receive()
                    if msg["type"] == "websocket.disconnect":
                        return
            finally:
                closed.set()

        reader_task = asyncio.create_task(reader())

        def backfill() -> dict[str, Any]:
            return {"type": "backfill", "server_ms": int(state.clock() * 1000), "seq": hub.seq,
                    "sessions": hub.snapshot(), "points": hub.backfill()}

        try:
            await ws.send_json({
                "type": "hello",
                "server_ms": int(state.clock() * 1000),
                "retention_s": state.settings.live_retention_s,
                "windows_s": list(WINDOWS_S),
                "thresholds": hub.thresholds.model_dump(),
            })
            msg = backfill()
            last_seq = msg["seq"]
            await ws.send_json(msg)
            while not closed.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(closed.wait(), timeout=state.settings.live_push_interval_s)
                if closed.is_set():
                    break
                points = hub.changes_since(last_seq)
                if points is None:
                    msg = backfill()
                else:
                    msg = {"type": "snapshot", "server_ms": int(state.clock() * 1000), "seq": hub.seq,
                           "sessions": hub.snapshot(), "points": points}
                last_seq = msg["seq"]
                await ws.send_json(msg)
        except OSError as exc:
            log.debug("live websocket closed: %s", exc)
        finally:
            reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await reader_task

    # -- dashboard + login ----------------------------------------------------
    @app.get("/", response_model=None)
    async def index(request: Request) -> Response:
        if not ui_ok(request):
            return RedirectResponse("/login", status_code=303)
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/login", response_model=None)
    async def login_page() -> Response:
        if not state.ui.enabled:
            return RedirectResponse("/", status_code=303)
        return FileResponse(STATIC_DIR / "login.html")

    @app.post("/login", response_model=None)
    async def login(request: Request) -> Response:
        if not state.ui.enabled:
            return RedirectResponse("/", status_code=303)
        client = _client_id(request)
        if state.ui.throttled(client):
            return JSONResponse({"error": "too many failed logins; wait a minute"}, status_code=429)
        try:
            raw = await _read_limited(request, 4096)
        except PayloadTooLargeError:
            return JSONResponse({"error": "body too large"}, status_code=413)
        token = ""
        ctype = request.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError, AttributeError):
                token = str(json.loads(raw).get("token", ""))
        else:
            token = parse_qs(raw.decode("utf-8", "replace")).get("token", [""])[0]
        if not token or not state.ui.check_token(token, client):
            return RedirectResponse("/login?error=1", status_code=303)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(
            COOKIE_NAME, state.ui.issue(), max_age=state.ui.ttl_s, httponly=True,
            secure=state.settings.cookie_secure, samesite="strict", path="/",
        )
        return resp

    @app.post("/logout", response_model=None)
    async def logout() -> Response:
        resp = RedirectResponse("/login", status_code=303)
        resp.delete_cookie(COOKIE_NAME, path="/")
        return resp

    return app


async def _housekeeping(state: AppState, stop: asyncio.Event) -> None:
    while not stop.is_set():
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=30)
        dropped = state.hub.expire()
        if dropped:
            log.info("expired %d idle sessions from the live view", dropped)
        state.tokens.maybe_reload()
        if state.thresholds_file.maybe_reload():
            state.hub.set_thresholds(state.thresholds_file.current)
