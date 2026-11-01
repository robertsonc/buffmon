from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from buffmon.auth import hash_token
from buffmon.config import Settings

SERVICES_DIR = Path(__file__).resolve().parent.parent
THRESHOLDS = SERVICES_DIR / "thresholds.yaml"
TOKEN = "bm_test-token-0123456789abcdefghijklmnopqrstuvwxyz"
UI_TOKEN = "bm_ui-token-0123456789abcdefghijklmnopqrstuvwxyz"
SECRET = "s" * 48


def now_bucket_ms(offset_s: int = 0) -> int:
    return (int(time.time()) - 3 + offset_s) * 1000


def make_record(**overrides: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "v": 1,
        "probe_id": "p1",
        "site": "SJC-BR01",
        "session": "dc1-voice",
        "kind": "stamp",
        "app_class": "voice",
        "dscp": 46,
        "src": "10.1.1.10:40001",
        "dst": "10.10.0.20:862",
        "ts_ms": now_bucket_ms(),
        "interval_ms": 1000,
        "sent": 10,
        "received": 10,
        "lost": 0,
        "late": 0,
        "dup": 0,
        "reordered": 0,
        "fwd_lost": 0,
        "back_lost": 0,
        "rtt_us": [21000 + 50 * i for i in range(10)],
        "rtt_jitter_sum_us": 450,
        "rtt_jitter_n": 9,
        "ipdv_fwd_sum_us": 180,
        "ipdv_fwd_n": 9,
        "ipdv_back_sum_us": 230,
        "ipdv_back_n": 9,
        "owd_fwd_sum_us": None,
        "owd_back_sum_us": None,
        "owd_n": 0,
        "clock_synced": False,
        "clock_err_us": None,
        "ttl_fwd": 57,
        "ttl_back": 57,
        "rx_ts": "kernel",
        "errors": {},
    }
    rec.update(overrides)
    return rec


def lossy(rec: dict[str, Any], lost: int, fwd: int | None = None) -> dict[str, Any]:
    """Turns ``lost`` of the record's packets into losses, keeping it consistent."""
    received = rec["sent"] - lost
    out = dict(rec)
    out["received"] = received
    out["lost"] = lost
    out["rtt_us"] = rec["rtt_us"][:received]
    out["rtt_jitter_n"] = max(0, min(rec["rtt_jitter_n"], received - 1))
    if rec["kind"] == "stamp":
        out["ipdv_fwd_n"] = out["ipdv_back_n"] = out["rtt_jitter_n"]
        f = lost if fwd is None else fwd
        out["fwd_lost"] = f
        out["back_lost"] = lost - f
    out["errors"] = {"timeout": lost} if lost else {}
    return out


@pytest.fixture
def tokens_file(tmp_path: Path) -> Path:
    p = tmp_path / "probe-tokens.json"
    p.write_text(json.dumps({"p1": hash_token(TOKEN)}))
    p.chmod(0o600)
    return p


@pytest.fixture
def settings(tokens_file: Path) -> Settings:
    return Settings(
        ui_auth="disabled",
        probe_tokens_file=tokens_file,
        thresholds_file=THRESHOLDS,
        insert_flush_interval_s=0.05,
        live_push_interval_s=0.05,
        cookie_secure=False,
    )


@pytest.fixture
def auth_settings(tokens_file: Path) -> Settings:
    return Settings(
        ui_auth="enabled",
        ui_token_sha256=hash_token(UI_TOKEN),
        session_secret=SECRET,
        probe_tokens_file=tokens_file,
        thresholds_file=THRESHOLDS,
        insert_flush_interval_s=0.05,
        live_push_interval_s=0.05,
        cookie_secure=False,
        login_max_failures_per_min=3,
    )


class FakeTransport:
    """In-memory stand-in for ClickHouse."""

    def __init__(self) -> None:
        self.inserts: list[tuple[str, list[dict[str, Any]], str]] = []
        self.selects: list[tuple[str, dict[str, str | int]]] = []
        self.fail_inserts = 0
        self.fail_selects = False
        self.select_rows: list[dict[str, Any]] = []
        self.closed = False

    async def insert_rows(self, table: str, rows: Sequence[Mapping[str, Any]], dedup_token: str) -> None:
        from buffmon.store import ClickHouseError

        if self.fail_inserts:
            self.fail_inserts -= 1
            raise ClickHouseError("simulated outage")
        self.inserts.append((table, [dict(r) for r in rows], dedup_token))

    async def select(self, sql: str, params: Mapping[str, str | int]) -> list[dict[str, Any]]:
        from buffmon.store import ClickHouseError

        self.selects.append((sql, dict(params)))
        if self.fail_selects:
            raise ClickHouseError("simulated outage")
        return self.select_rows

    async def aclose(self) -> None:
        self.closed = True

    @property
    def rows(self) -> list[dict[str, Any]]:
        return [r for _, rows, _ in self.inserts for r in rows]
