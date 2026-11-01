"""003_tunnel_stats.sql on a real ClickHouse server, through OrchTransport.

    BUFFMON_IT_CLICKHOUSE_URL=http://127.0.0.1:8123 pytest tests/test_orch_clickhouse_server.py
"""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from buffmon.orch.poller import OrchTransport, rows_token

URL = os.environ.get("BUFFMON_IT_CLICKHOUSE_URL")
USER = os.environ.get("BUFFMON_IT_CLICKHOUSE_USER", "default")
PASSWORD = os.environ.get("BUFFMON_IT_CLICKHOUSE_PASSWORD", "")
SCHEMA = Path(__file__).resolve().parents[2] / "deploy" / "clickhouse" / "003_tunnel_stats.sql"

pytestmark = pytest.mark.skipif(not URL, reason="BUFFMON_IT_CLICKHOUSE_URL not set")


def _admin(sql: str, **params: str) -> str:
    assert URL
    r = httpx.post(URL, params={f"param_{k}": v for k, v in params.items()}, content=sql.encode(),
                   headers={"X-ClickHouse-User": USER, "X-ClickHouse-Key": PASSWORD}, timeout=30)
    assert r.status_code == 200, f"{sql[:80]}: {r.text[:300]}"
    return r.text.strip()


def _statements() -> list[str]:
    text = "\n".join(line for line in SCHEMA.read_text().splitlines() if not line.strip().startswith("--"))
    return [s.strip() for s in text.split(";") if s.strip()]


@pytest.fixture
def db() -> Iterator[str]:
    name = f"buffmon_orch_it_{secrets.token_hex(4)}"
    for stmt in _statements():
        _admin(stmt.replace("buffmon.", f"{name}.").replace("DATABASE IF NOT EXISTS buffmon", f"DATABASE {name}"))
    try:
        yield name
    finally:
        _admin("DROP DATABASE IF EXISTS {db:Identifier}", db=name)


def tunnel_rows(latency: float) -> list[dict[str, Any]]:
    return [
        {"ts": "2026-11-01 12:00:00.000", "site": "SJC-BR01", "appliance": "sjc-ec1", "tunnel_id": f"t{i}",
         "tunnel_name": "", "overlay": "", "transport": "INET", "peer": "", "loss_pre_fec_pct": 2.1,
         "loss_post_fec_pct": None, "ooo_pre_poc_pct": None, "ooo_post_poc_pct": None, "latency_ms": latency,
         "jitter_ms": None, "mos": None, "bytes_tx": 10, "bytes_rx": None, "orch_version": "synthetic"}
        for i in range(5)
    ]


def _insert(db: str, table: str, rows: list[dict[str, Any]], token: str) -> None:
    async def go() -> None:
        assert URL
        t = OrchTransport(URL, db, USER, PASSWORD, timeout_s=30)
        try:
            await t.insert_rows(table, rows, token)
        finally:
            await t.aclose()

    asyncio.run(go())


def test_retried_insert_is_dropped_immediately(db: str) -> None:
    rows = tunnel_rows(21.0)
    token = rows_token("tunnel_stats", rows)
    _insert(db, "tunnel_stats", rows, token)
    _insert(db, "tunnel_stats", rows, token)
    assert _admin("SELECT count() FROM {db:Identifier}.tunnel_stats", db=db) == "5"


def test_repoll_of_the_same_sample_collapses_and_keeps_the_latest(db: str) -> None:
    _insert(db, "tunnel_stats", tunnel_rows(21.0), "poll-1")
    _insert(db, "tunnel_stats", tunnel_rows(22.0), "poll-2")  # same samples re-polled, value revised
    _admin("OPTIMIZE TABLE {db:Identifier}.tunnel_stats FINAL", db=db)
    assert _admin("SELECT count() FROM {db:Identifier}.tunnel_stats", db=db) == "5"
    assert _admin("SELECT DISTINCT latency_ms FROM {db:Identifier}.tunnel_stats", db=db) == "22"
    nulls = _admin("SELECT countIf(loss_post_fec_pct IS NULL) FROM {db:Identifier}.tunnel_stats", db=db)
    assert nulls == "5", "unmapped metrics stay NULL, not 0"


def test_alarms_table_accepts_rows_and_rejects_other_tables(db: str) -> None:
    alarm = {"ts": "2026-11-01 12:00:00.000", "alarm_id": "al-1", "site": "SJC-BR01", "appliance": "sjc-ec1",
             "severity": "major", "source": "tunnel", "object": "t1", "description": "synthetic", "state": "raised",
             "cleared_ts": None, "orch_version": "synthetic"}
    _insert(db, "alarms", [alarm], rows_token("alarms", [alarm]))
    assert _admin("SELECT count() FROM {db:Identifier}.alarms", db=db) == "1"
    with pytest.raises(ValueError, match="unknown table"):
        _insert(db, "probe_second", [alarm], "x")
