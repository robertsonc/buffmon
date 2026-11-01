"""ClickHouse storage: batched inserts and parameterised history reads.

Inserts run in a background task, off the request path. Every batch carries an
``insert_deduplication_token`` (the tables set ``non_replicated_deduplication_window``)
so a retried batch is applied once, and the materialised rollup is not fed twice.
Reads only ever bind values through ClickHouse query parameters (``{name:Type}``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import random
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Protocol

import httpx

from .models import ProbeRecord, parse_endpoint

log = logging.getLogger(__name__)

SECOND_TABLE = "probe_second"
MINUTE_TABLE = "probe_minute"
FLOWS_TABLE = "flows"
PROBE_FLOWS_TABLE = "probe_flows"
# Tables the ingest side may write. Anything else is refused before a request is made.
_TABLES = frozenset({SECOND_TABLE, FLOWS_TABLE, PROBE_FLOWS_TABLE})

# range key -> (span seconds, bucket seconds, source table)
HISTORY_RANGES: dict[str, tuple[int, int, str]] = {
    "1h": (3600, 10, SECOND_TABLE),
    "6h": (6 * 3600, 60, SECOND_TABLE),
    "24h": (24 * 3600, 300, MINUTE_TABLE),
    "7d": (7 * 24 * 3600, 1800, MINUTE_TABLE),
}


class ClickHouseError(RuntimeError):
    pass


class Transport(Protocol):
    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None: ...

    async def select(self, sql: str, params: Mapping[str, str | int]) -> list[dict[str, Any]]: ...

    async def aclose(self) -> None: ...


class HttpTransport:
    """ClickHouse HTTP interface. Credentials go in headers, never in the URL."""

    def __init__(
        self,
        base_url: str,
        database: str,
        user: str,
        password: str,
        timeout_s: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._db = database
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(timeout_s),
            headers={"X-ClickHouse-User": user, "X-ClickHouse-Key": password},
        )

    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None:
        if table not in _TABLES:
            raise ValueError(f"unknown table {table!r}")
        body = "\n".join(json.dumps(r, separators=(",", ":")) for r in rows).encode("utf-8")
        params = {
            "query": f"INSERT INTO {self._db}.{table} FORMAT JSONEachRow",
            "insert_deduplication_token": dedup_token,
            # Without this a retried (deduplicated) block is still pushed into the
            # materialised view, so probe_minute double counts. The default is 0
            # on ClickHouse 25.8 LTS (verified against 25.8.33.6).
            "deduplicate_blocks_in_dependent_materialized_views": "1",
        }
        try:
            resp = await self._client.post("/", params=params, content=body)
        except httpx.HTTPError as exc:
            raise ClickHouseError(f"insert into {table} failed: {exc.__class__.__name__}: {exc}") from exc
        if resp.status_code != 200:
            raise ClickHouseError(f"insert into {table} failed: HTTP {resp.status_code}: {resp.text[:300]}")

    async def select(self, sql: str, params: Mapping[str, str | int]) -> list[dict[str, Any]]:
        query_params: dict[str, str] = {
            "database": self._db,
            "default_format": "JSON",
            "output_format_json_quote_64bit_integers": "0",
            "readonly": "2",
        }
        for name, value in params.items():
            query_params[f"param_{name}"] = str(value)
        try:
            resp = await self._client.post("/", params=query_params, content=sql.encode("utf-8"))
        except httpx.HTTPError as exc:
            raise ClickHouseError(f"query failed: {exc.__class__.__name__}: {exc}") from exc
        if resp.status_code != 200:
            raise ClickHouseError(f"query failed: HTTP {resp.status_code}: {resp.text[:300]}")
        try:
            data = resp.json()["data"]
        except (ValueError, KeyError) as exc:
            raise ClickHouseError("query returned an unexpected body") from exc
        if not isinstance(data, list):
            raise ClickHouseError("query returned an unexpected body")
        return data

    async def aclose(self) -> None:
        await self._client.aclose()


def _ts_text(ts_ms: int) -> str:
    return datetime.fromtimestamp(ts_ms / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def record_to_row(rec: ProbeRecord) -> dict[str, Any]:
    src_ip, src_port = parse_endpoint(rec.src)
    dst_ip, dst_port = parse_endpoint(rec.dst)
    return {
        "ts": _ts_text(rec.ts_ms),
        "probe_id": rec.probe_id,
        "site": rec.site,
        "session": rec.session,
        "kind": rec.kind,
        "app_class": rec.app_class,
        "dscp": rec.dscp,
        "src_ip": f"::ffff:{src_ip}",
        "src_port": src_port,
        "dst_ip": f"::ffff:{dst_ip}",
        "dst_port": dst_port,
        "interval_ms": rec.interval_ms,
        "sent": rec.sent,
        "received": rec.received,
        "lost": rec.lost,
        "late": rec.late,
        "dup": rec.dup,
        "reordered": rec.reordered,
        "fwd_lost": rec.fwd_lost,
        "back_lost": rec.back_lost,
        "rtt_us": list(rec.rtt_us),
        "rtt_jitter_sum_us": rec.rtt_jitter_sum_us,
        "rtt_jitter_n": rec.rtt_jitter_n,
        "ipdv_fwd_sum_us": rec.ipdv_fwd_sum_us,
        "ipdv_fwd_n": rec.ipdv_fwd_n,
        "ipdv_back_sum_us": rec.ipdv_back_sum_us,
        "ipdv_back_n": rec.ipdv_back_n,
        "owd_fwd_sum_us": rec.owd_fwd_sum_us,
        "owd_back_sum_us": rec.owd_back_sum_us,
        "owd_n": rec.owd_n,
        "clock_synced": rec.clock_synced,
        "clock_err_us": rec.clock_err_us,
        "ttl_fwd": rec.ttl_fwd,
        "ttl_back": rec.ttl_back,
        "rx_ts": rec.rx_ts,
        "errors": dict(rec.errors),
    }


def batch_token(rows: Sequence[Mapping[str, Any]]) -> str:
    h = hashlib.sha256()
    for r in rows:
        h.update(f"{r['probe_id']}\x1f{r['session']}\x1f{r['ts']}\x1e".encode())
    return h.hexdigest()


def content_token(rows: Sequence[Mapping[str, Any]]) -> str:
    """Dedup token for rows without a natural key (flow records): a hash of the
    batch content, so resending the same batch is recognised as a retry."""
    h = hashlib.sha256()
    for r in rows:
        h.update(json.dumps(r, sort_keys=True, separators=(",", ":"), default=str).encode())
        h.update(b"\x1e")
    return h.hexdigest()


class SampleWriter:
    """Bounded buffer + background batch inserter for one table (``probe_second`` by default)."""

    def __init__(
        self,
        transport: Transport,
        batch_max: int = 5000,
        flush_interval_s: float = 1.0,
        buffer_max: int = 200_000,
        retry_max_s: float = 30.0,
        table: str = SECOND_TABLE,
        token_fn: Callable[[Sequence[Mapping[str, Any]]], str] = batch_token,
    ) -> None:
        if table not in _TABLES:
            raise ValueError(f"unknown table {table!r}")
        self._table = table
        self._token_fn = token_fn
        self._transport = transport
        self._batch_max = batch_max
        self._flush_interval_s = flush_interval_s
        self._buffer_max = buffer_max
        self._retry_max_s = retry_max_s
        self._buf: deque[dict[str, Any]] = deque()
        self._wake = asyncio.Event()
        self._inflight = 0
        self.dropped = 0
        self.inserted = 0
        self.batches = 0
        self.failed_attempts = 0
        self.last_error: str | None = None
        self.last_error_at: float | None = None
        self.last_insert_at: float | None = None

    @property
    def depth(self) -> int:
        return len(self._buf) + self._inflight

    def enqueue(self, rows: Sequence[dict[str, Any]]) -> None:
        if not rows:
            return
        overflow = len(self._buf) + len(rows) - self._buffer_max
        if overflow > 0:
            for _ in range(min(overflow, len(self._buf))):
                self._buf.popleft()
            self.dropped += overflow
            log.warning("insert buffer full: dropped %d oldest rows (%d dropped in total)", overflow, self.dropped)
            rows = rows[-self._buffer_max:] if len(rows) > self._buffer_max else rows
        self._buf.extend(rows)
        if len(self._buf) >= self._batch_max:
            self._wake.set()

    def status(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "buffer_max": self._buffer_max,
            "dropped": self.dropped,
            "inserted": self.inserted,
            "batches": self.batches,
            "failed_attempts": self.failed_attempts,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
            "last_insert_at": self.last_insert_at,
        }

    async def run(self, stop: asyncio.Event) -> None:
        log.info("insert writer for %s started (batch_max=%d, flush every %.1fs)",
                 self._table, self._batch_max, self._flush_interval_s)
        while not stop.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=self._flush_interval_s)
            self._wake.clear()
            while self._buf and not stop.is_set():
                n = min(self._batch_max, len(self._buf))
                batch = [self._buf.popleft() for _ in range(n)]
                self._inflight = n
                try:
                    await self._insert_with_retry(batch, stop)
                finally:
                    self._inflight = 0
        if self._buf:
            log.warning("insert writer stopping with %d rows not written", len(self._buf))

    async def flush_once(self) -> None:
        """Writes everything buffered now (used by tests and on shutdown)."""
        stop = asyncio.Event()
        while self._buf:
            n = min(self._batch_max, len(self._buf))
            batch = [self._buf.popleft() for _ in range(n)]
            await self._insert_with_retry(batch, stop, max_attempts=3)

    async def _insert_with_retry(
        self, batch: list[dict[str, Any]], stop: asyncio.Event, max_attempts: int | None = None
    ) -> None:
        token = self._token_fn(batch)
        delay = 0.5
        attempt = 0
        while True:
            attempt += 1
            try:
                await self._transport.insert_rows(self._table, batch, token)
            except ClickHouseError as exc:
                self.failed_attempts += 1
                self.last_error = str(exc)
                self.last_error_at = time.time()
                if max_attempts is not None and attempt >= max_attempts:
                    log.error("giving up on a batch of %d rows after %d attempts: %s", len(batch), attempt, exc)
                    self.dropped += len(batch)
                    return
                log.warning("insert attempt %d failed (%s); retrying in %.1fs", attempt, exc, delay)
                try:
                    await asyncio.wait_for(stop.wait(), timeout=delay * (0.8 + 0.4 * random.random()))  # noqa: S311
                    log.warning("stopping with an unwritten batch of %d rows", len(batch))
                    return
                except TimeoutError:
                    pass
                delay = min(delay * 2, self._retry_max_s)
                continue
            self.inserted += len(batch)
            self.batches += 1
            self.last_insert_at = time.time()
            return


_SECOND_SQL = """
SELECT
    toUnixTimestamp64Milli(toDateTime64(toStartOfInterval(p.ts, toIntervalSecond({bucket:UInt32})), 3, 'UTC')) AS ts_ms,
    sum(p.sent)                                                     AS sent,
    sum(p.received)                                                 AS received,
    sum(p.lost)                                                     AS lost,
    quantilesExactArray(0.5, 0.95)(p.rtt_us)                        AS q_us,
    max(arrayMax(arrayPushBack(p.rtt_us, toUInt32(0))))             AS rtt_max_us,
    sum(p.rtt_jitter_sum_us)                                        AS rtt_jitter_sum_us,
    sum(p.rtt_jitter_n)                                             AS rtt_jitter_n,
    sum(p.ipdv_fwd_sum_us)                                          AS ipdv_fwd_sum_us,
    sum(p.ipdv_fwd_n)                                               AS ipdv_fwd_n,
    sum(p.ipdv_back_sum_us)                                         AS ipdv_back_sum_us,
    sum(p.ipdv_back_n)                                              AS ipdv_back_n,
    sum(ifNull(p.fwd_lost, 0))                                      AS fwd_lost,
    sum(ifNull(p.back_lost, 0))                                     AS back_lost,
    sumIf(p.sent, p.fwd_lost IS NOT NULL)                           AS dir_sent
FROM probe_second AS p FINAL
WHERE p.probe_id = {probe_id:String}
  AND p.session = {session:String}
  AND p.ts >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')
  AND p.ts <  fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')
GROUP BY ts_ms
ORDER BY ts_ms
"""

_MINUTE_SQL = """
SELECT
    toInt64(toUnixTimestamp(toStartOfInterval(m.minute, toIntervalSecond({bucket:UInt32})))) * 1000 AS ts_ms,
    sum(m.sent)                                                       AS sent,
    sum(m.received)                                                   AS received,
    sum(m.lost)                                                       AS lost,
    quantilesTDigestArrayMerge(0.5, 0.95, 0.99)(m.rtt_q)              AS q_us,
    max(m.rtt_max_us)                                                 AS rtt_max_us,
    sum(m.rtt_jitter_sum_us)                                          AS rtt_jitter_sum_us,
    sum(m.rtt_jitter_n)                                               AS rtt_jitter_n,
    sum(m.ipdv_fwd_sum_us)                                            AS ipdv_fwd_sum_us,
    sum(m.ipdv_fwd_n)                                                 AS ipdv_fwd_n,
    sum(m.ipdv_back_sum_us)                                           AS ipdv_back_sum_us,
    sum(m.ipdv_back_n)                                                AS ipdv_back_n,
    sum(m.fwd_lost)                                                   AS fwd_lost,
    sum(m.back_lost)                                                  AS back_lost,
    sum(m.dir_sent)                                                   AS dir_sent
FROM probe_minute AS m
WHERE m.probe_id = {probe_id:String}
  AND m.session = {session:String}
  AND m.minute >= toDateTime(intDiv({from_ms:Int64}, 1000), 'UTC')
  AND m.minute <  toDateTime(intDiv({to_ms:Int64}, 1000), 'UTC')
GROUP BY ts_ms
ORDER BY ts_ms
"""


def _num(v: Any) -> float | None:
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return None if f != f else f  # NaN -> None


def _shape_history_row(row: Mapping[str, Any]) -> dict[str, Any]:
    sent = int(row["sent"])
    lost = int(row["lost"])
    q = row.get("q_us") or []
    p50 = _num(q[0]) if len(q) > 0 else None
    p95 = _num(q[1]) if len(q) > 1 else None
    j_n = int(row["rtt_jitter_n"])
    f_n = int(row["ipdv_fwd_n"])
    b_n = int(row["ipdv_back_n"])
    dir_sent = int(row["dir_sent"])
    received = int(row["received"])

    def ms(v: float | None) -> float | None:
        return None if v is None else round(v / 1000.0, 2)

    return {
        "ts_ms": int(row["ts_ms"]),
        "sent": sent,
        "received": received,
        "lost": lost,
        "loss_pct": round(100.0 * lost / sent, 3) if sent else None,
        "rtt_p50_ms": ms(p50) if received else None,
        "rtt_p95_ms": ms(p95) if received else None,
        "rtt_max_ms": ms(_num(row["rtt_max_us"])) if received else None,
        "rtt_jitter_ms": round(int(row["rtt_jitter_sum_us"]) / j_n / 1000.0, 2) if j_n else None,
        "ipdv_fwd_ms": round(int(row["ipdv_fwd_sum_us"]) / f_n / 1000.0, 2) if f_n else None,
        "ipdv_back_ms": round(int(row["ipdv_back_sum_us"]) / b_n / 1000.0, 2) if b_n else None,
        "fwd_loss_pct": round(100.0 * int(row["fwd_lost"]) / dir_sent, 3) if dir_sent else None,
        "back_loss_pct": round(100.0 * int(row["back_lost"]) / dir_sent, 3) if dir_sent else None,
    }


async def query_history(
    transport: Transport, probe_id: str, session: str, range_key: str, now_ms: int
) -> dict[str, Any]:
    span_s, bucket_s, table = HISTORY_RANGES[range_key]
    to_ms = now_ms
    from_ms = to_ms - span_s * 1000
    sql = _SECOND_SQL if table == SECOND_TABLE else _MINUTE_SQL
    params: dict[str, str | int] = {
        "probe_id": probe_id,
        "session": session,
        "from_ms": from_ms,
        "to_ms": to_ms,
        "bucket": bucket_s,
    }
    rows = await transport.select(sql, params)
    return {
        "probe_id": probe_id,
        "session": session,
        "range": range_key,
        "bucket_s": bucket_s,
        "source": table,
        "from_ms": from_ms,
        "to_ms": to_ms,
        "points": [_shape_history_row(r) for r in rows],
    }
