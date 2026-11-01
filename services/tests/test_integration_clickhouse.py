"""Storage integration test against a real ClickHouse engine.

Runs the shipped schema (deploy/clickhouse/001_schema.sql), the ingest app, the
simulator's record generator and the history API end to end. The engine is
chdb (ClickHouse in-process), so this needs no server; it is skipped when chdb
is not installed (``pip install -e '.[integration]'``).

What this does NOT cover: the ClickHouse HTTP interface itself (see
test_store.py for the request shape) and version differences between chdb's
engine and the 25.8 LTS server used in deployment.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from buffmon.app import create_app
from buffmon.config import Settings
from buffmon.store import batch_token
from buffmon.tools.simulate import build_fleet, parse_inject
from tests.conftest import TOKEN

chdb_session = pytest.importorskip("chdb.session")

SCHEMA = Path(__file__).resolve().parents[2] / "deploy" / "clickhouse" / "001_schema.sql"


def schema_statements() -> list[str]:
    text = "\n".join(line for line in SCHEMA.read_text().splitlines() if not line.strip().startswith("--"))
    return [s.strip() for s in text.split(";") if s.strip()]


class ChdbTransport:
    """Executes exactly the SQL and parameters the HTTP transport would send."""

    def __init__(self, path: str) -> None:
        self.session = chdb_session.Session(path)
        self.lock = threading.Lock()
        for stmt in schema_statements():
            self.session.query(stmt)
        self.session.query("USE buffmon")

    def _q(self, sql: str, fmt: str = "JSON", params: Mapping[str, Any] | None = None) -> Any:
        with self.lock:
            return self.session.query(sql, fmt, params=dict(params) if params else None)

    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None:
        assert re.fullmatch(r"[0-9a-f]{64}", dedup_token)
        body = "\n".join(json.dumps(r) for r in rows)
        sql = (f"INSERT INTO buffmon.{table} SETTINGS insert_deduplication_token='{dedup_token}' "
               f"FORMAT JSONEachRow\n{body}")
        await asyncio.to_thread(self._q, sql, "CSV")

    async def select(self, sql: str, params: Mapping[str, str | int]) -> list[dict[str, Any]]:
        res = await asyncio.to_thread(self._q, sql, "JSON", params)
        data: list[dict[str, Any]] = json.loads(res.bytes())["data"]
        return data

    async def aclose(self) -> None:
        return None

    def scalar(self, sql: str) -> str:
        return str(self._q(sql, "TSV").bytes().decode().strip())


@pytest.fixture
def ch(tmp_path: Path) -> Iterator[ChdbTransport]:
    t = ChdbTransport(str(tmp_path / "chdb"))
    yield t
    t.session.close()


def sim_records(minutes: int, inject: str | None = None) -> list[dict[str, Any]]:
    """Realistic records for one simulated probe, re-labelled as probe p1."""
    start = time.time()
    injects = [parse_inject(inject)] if inject else []
    fleet = build_fleet(1, seed=3, injects=injects)
    sims = next(iter(fleet.values()))
    out: list[dict[str, Any]] = []
    first = int(start) - 3 - minutes * 60
    for sec in range(first, int(start) - 3):
        for sim in sims:
            rec = sim.bucket(sec * 1000, start)
            if rec:
                rec["probe_id"] = "p1"
                out.append(rec)
    return out


def test_end_to_end_storage_and_history(ch: ChdbTransport, settings: Settings) -> None:
    recs = sim_records(12, inject="sim-sjc-br01/dc1-voice:loss=5,dir=fwd,after=-300,for=120")
    with TestClient(create_app(settings, transport=ch)) as client:
        auth = {"authorization": f"Bearer {TOKEN}"}
        for i in range(0, len(recs), 2000):
            r = client.post("/v1/probe/results", json={"probe_id": "p1", "records": recs[i:i + 2000]}, headers=auth)
            assert r.status_code == 200, r.text
            assert r.json()["rejected"] == 0, r.json()["errors"]
        # retried request: dropped by the in-memory dedup before ClickHouse
        r = client.post("/v1/probe/results", json={"probe_id": "p1", "records": recs[:500]}, headers=auth)
        assert r.json() == {"accepted": 0, "duplicates": 500, "rejected": 0, "errors": []}

        writer = client.app.state.buffmon.writer  # type: ignore[attr-defined]
        deadline = time.monotonic() + 20
        while writer.inserted < len(recs) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert writer.inserted == len(recs)

        n_second = int(ch.scalar("SELECT count() FROM buffmon.probe_second"))
        assert n_second == len(recs)
        sent_second = int(ch.scalar("SELECT sum(sent) FROM buffmon.probe_second"))
        sent_minute = int(ch.scalar("SELECT sum(sent) FROM buffmon.probe_minute"))
        assert sent_minute == sent_second
        n_minutes = int(ch.scalar("SELECT count() FROM (SELECT DISTINCT minute FROM buffmon.probe_minute)"))
        assert 12 <= n_minutes <= 13

        h1 = client.get("/v1/sessions/p1/dc1-voice/history?range=1h").json()
        assert h1["source"] == "probe_second" and h1["bucket_s"] == 10
        assert len(h1["points"]) >= 70
        lossy = [p for p in h1["points"] if (p["loss_pct"] or 0) > 2]
        assert lossy, "injected forward loss should show up in history"
        # The injected loss is forward-only; the return direction only carries the
        # simulator's small background loss (compare in aggregate: a partial edge
        # bucket with a single background loss can show a high percentage).
        fwd = sum(p["fwd_loss_pct"] or 0 for p in lossy)
        back = sum(p["back_loss_pct"] or 0 for p in lossy)
        assert fwd > 5 * back, (fwd, back)
        assert all(p["rtt_p50_ms"] and 10 < p["rtt_p50_ms"] < 40 for p in h1["points"])

        h24 = client.get("/v1/sessions/p1/dc1-voice/history?range=24h").json()
        assert h24["source"] == "probe_minute" and h24["bucket_s"] == 300
        assert sum(p["sent"] for p in h24["points"]) == sum(p["sent"] for p in h1["points"])
        assert all(p["rtt_p95_ms"] is not None for p in h24["points"])

        icmp = client.get("/v1/sessions/p1/gw-reach/history?range=6h").json()
        assert icmp["points"] and all(p["fwd_loss_pct"] is None for p in icmp["points"])


def test_retried_block_is_deduplicated_by_clickhouse(ch: ChdbTransport) -> None:
    """A batch retried with the same token (after a timeout, say) must not be
    written twice, and must not feed the minute rollup twice."""
    from buffmon.models import ProbeRecord
    from buffmon.store import record_to_row

    rows = [record_to_row(ProbeRecord.model_validate(r)) for r in sim_records(2)]
    token = batch_token(rows)
    asyncio.run(ch.insert_rows("probe_second", rows, token))
    asyncio.run(ch.insert_rows("probe_second", rows, token))
    assert int(ch.scalar("SELECT count() FROM buffmon.probe_second")) == len(rows)
    assert int(ch.scalar("SELECT sum(sent) FROM buffmon.probe_minute")) == sum(int(r["sent"]) for r in rows)
