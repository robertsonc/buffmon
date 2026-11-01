from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from buffmon.models import ProbeRecord
from buffmon.store import ClickHouseError, HttpTransport, SampleWriter, batch_token, query_history, record_to_row
from tests.conftest import FakeTransport, make_record


def rows(n: int) -> list[dict[str, object]]:
    return [record_to_row(ProbeRecord.model_validate(make_record(ts_ms=1_761_955_200_000 + i * 1000)))
            for i in range(n)]


def test_record_to_row() -> None:
    row = rows(1)[0]
    assert row["ts"] == "2025-11-01 00:00:00.000"
    assert row["src_ip"] == "::ffff:10.1.1.10" and row["src_port"] == 40001
    assert row["dst_ip"] == "::ffff:10.10.0.20" and row["dst_port"] == 862
    assert row["rtt_us"] == [21000 + 50 * i for i in range(10)]


def test_batch_token_is_stable_and_order_sensitive() -> None:
    r = rows(3)
    assert batch_token(r) == batch_token(list(r))
    assert batch_token(r) != batch_token(r[::-1])


def test_http_transport_insert_and_select_never_interpolate() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if "INSERT" in req.url.params.get("query", ""):
            return httpx.Response(200, text="")
        return httpx.Response(200, json={"data": [{"x": 1}]})

    client = httpx.AsyncClient(base_url="http://ch:8123", transport=httpx.MockTransport(handler),
                               headers={"X-ClickHouse-User": "u", "X-ClickHouse-Key": "secret"})
    t = HttpTransport("http://ch:8123", "buffmon", "u", "secret", 5, client=client)

    async def go() -> None:
        await t.insert_rows("probe_second", rows(2), "tok123")
        out = await t.select("SELECT {probe_id:String} AS x", {"probe_id": "p1'; DROP TABLE x --"})
        assert out == [{"x": 1}]
        with pytest.raises(ValueError):
            await t.insert_rows("orgs", rows(1), "t")
        await t.aclose()

    asyncio.run(go())
    ins, sel = seen
    q = parse_qs(urlsplit(str(ins.url)).query)
    assert q["query"] == ["INSERT INTO buffmon.probe_second FORMAT JSONEachRow"]
    assert q["insert_deduplication_token"] == ["tok123"]
    assert ins.headers["x-clickhouse-key"] == "secret" and "secret" not in str(ins.url)
    assert len(ins.content.splitlines()) == 2 and json.loads(ins.content.splitlines()[0])["probe_id"] == "p1"
    sq = parse_qs(urlsplit(str(sel.url)).query)
    assert sq["param_probe_id"] == ["p1'; DROP TABLE x --"]
    assert sq["readonly"] == ["2"]
    assert sel.content == b"SELECT {probe_id:String} AS x"


def test_http_transport_errors() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Code: 241. MEMORY_LIMIT_EXCEEDED")

    client = httpx.AsyncClient(base_url="http://ch", transport=httpx.MockTransport(handler))
    t = HttpTransport("http://ch", "buffmon", "u", "", 5, client=client)
    with pytest.raises(ClickHouseError, match="HTTP 500"):
        asyncio.run(t.select("SELECT 1", {}))


def test_writer_batches_retries_with_same_token_and_drops_oldest() -> None:
    ft = FakeTransport()
    w = SampleWriter(ft, batch_max=2, buffer_max=4, retry_max_s=0.01)

    async def go() -> None:
        w.enqueue(rows(3))
        ft.fail_inserts = 1
        stop = asyncio.Event()
        task = asyncio.create_task(w.run(stop))
        for _ in range(200):
            if w.inserted == 3:
                break
            await asyncio.sleep(0.01)
        stop.set()
        await task

    asyncio.run(go())
    assert w.inserted == 3 and w.batches == 2 and w.failed_attempts == 1
    assert [len(r) for _, r, _ in ft.inserts] == [2, 1]
    w.enqueue(rows(6))
    assert w.dropped == 2 and w.depth == 4


def test_query_history_routes_by_range() -> None:
    ft = FakeTransport()
    for rng, table, bucket in (("1h", "probe_second", 10), ("6h", "probe_second", 60),
                               ("24h", "probe_minute", 300), ("7d", "probe_minute", 1800)):
        out = asyncio.run(query_history(ft, "p1", "s1", rng, 1_800_000_000_000))
        assert (out["source"], out["bucket_s"]) == (table, bucket)
        assert table in ft.selects[-1][0]
        params = ft.selects[-1][1]
        assert int(params["to_ms"]) - int(params["from_ms"]) == out["to_ms"] - out["from_ms"]
