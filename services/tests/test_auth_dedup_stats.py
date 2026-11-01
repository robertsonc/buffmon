from __future__ import annotations

import json
import math
import os
from pathlib import Path

import pytest

from buffmon.auth import ProbeTokens, bearer_token, hash_token
from buffmon.dedup import RecentKeys
from buffmon.stats import hops_from_ttl, percentile, wilson_upper
from buffmon.uiauth import UiAuth
from tests.conftest import TOKEN

# ---------------------------------------------------------------- auth


def test_bearer_parsing() -> None:
    assert bearer_token(f"Bearer {TOKEN}") == TOKEN
    assert bearer_token(f"bearer   {TOKEN}  ") == TOKEN
    assert bearer_token("Basic abc") is None
    assert bearer_token("Bearer short") is None
    assert bearer_token(None) is None


def test_tokens_authenticate_and_reload(tokens_file: Path) -> None:
    tokens = ProbeTokens(tokens_file, reload_interval_s=0)
    assert tokens.authenticate(TOKEN) == "p1"
    assert tokens.authenticate(TOKEN + "x") is None
    other = "bm_other-token-0123456789abcdefghijklmnopqrstuv"
    tokens_file.write_text(json.dumps({"p1": hash_token(TOKEN), "p2": hash_token(other)}))
    st = tokens_file.stat()
    os.utime(tokens_file, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert tokens.authenticate(other) == "p2"


def test_tokens_skip_invalid_entries(tmp_path: Path) -> None:
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"good": hash_token(TOKEN), "bad id": hash_token("x" * 40), "p3": "not-hex"}))
    tokens = ProbeTokens(p)
    assert tokens.count == 1
    assert tokens.authenticate(TOKEN) == "good"


def test_tokens_missing_file_rejects_everything(tmp_path: Path) -> None:
    assert ProbeTokens(tmp_path / "absent.json").authenticate(TOKEN) is None
    assert ProbeTokens(None).authenticate(TOKEN) is None


def test_ui_cookie_sign_verify_and_expiry() -> None:
    ui = UiAuth(True, hash_token("ui-token-value-xxxxxxxxxxxxxxxxxxxx"), "k" * 40, ttl_s=60)
    cookie = ui.issue(now=1000)
    assert ui.valid(cookie, now=1030)
    assert not ui.valid(cookie, now=1061)
    exp, nonce, sig = cookie.split(".")
    assert not ui.valid(f"{int(exp) + 999}.{nonce}.{sig}", now=1030)
    assert not ui.valid("garbage", now=1030)
    assert ui.check_token("ui-token-value-xxxxxxxxxxxxxxxxxxxx", "c1")
    assert not ui.check_token("wrong", "c1")


def test_ui_login_throttle() -> None:
    ui = UiAuth(True, hash_token("right-token-xxxxxxxxxxxxxxxxxxxxxxx"), "k" * 40, ttl_s=60, max_failures_per_min=2)
    assert not ui.check_token("a", "c")
    assert not ui.check_token("b", "c")
    assert ui.throttled("c")
    assert not ui.check_token("right-token-xxxxxxxxxxxxxxxxxxxxxxx", "c")  # blocked while throttled
    assert not ui.throttled("other")


# ---------------------------------------------------------------- dedup


def test_recent_keys_ttl_and_cap() -> None:
    keys = RecentKeys(ttl_s=10, max_keys=3)
    keys.add(("a",), now=0)
    assert keys.seen(("a",), now=5)
    assert not keys.seen(("a",), now=10.5)
    for i in range(5):
        keys.add((i,), now=20)
    assert len(keys) == 3
    assert not keys.seen((0,), now=20)
    assert keys.seen((4,), now=20)
    with pytest.raises(ValueError):
        RecentKeys(0, 1)


# ---------------------------------------------------------------- stats


def test_wilson_upper_bound() -> None:
    # zero failures: z^2 / (n + z^2)
    assert math.isclose(wilson_upper(0, 300), 3.8415 / (300 + 3.8415), rel_tol=1e-3)
    # textbook value: 5 of 100 -> (0.0215, 0.1118)
    assert math.isclose(wilson_upper(5, 100), 0.1118, abs_tol=5e-4)
    assert wilson_upper(0, 0) == 1.0
    assert wilson_upper(10, 10) == 1.0
    # 381 packets is the smallest count that proves < 1% with zero losses
    assert wilson_upper(0, 381) <= 0.01 < wilson_upper(0, 380)
    with pytest.raises(ValueError):
        wilson_upper(5, 3)


def test_percentile_interpolates() -> None:
    assert percentile([], 0.5) is None
    assert percentile([10], 0.95) == 10
    assert percentile([1, 2, 3, 4], 0.5) == 2.5
    assert math.isclose(percentile(list(range(1, 101)), 0.95) or 0, 95.05)


def test_hops_from_ttl() -> None:
    assert hops_from_ttl(57) == 7
    assert hops_from_ttl(120) == 8
    assert hops_from_ttl(250) == 5
    assert hops_from_ttl(None) is None
