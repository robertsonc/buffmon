"""Read-only Orchestrator client against httpx.MockTransport. Paths and the
header name are SYNTHETIC; nothing here describes a real Orchestrator API."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from buffmon.orch.client import (
    AuthConfig,
    ClientConfig,
    LoginSpec,
    OrchClient,
    OrchError,
    OrchHttpError,
    OrchTimeoutError,
    ReadOnlyViolationError,
)

TOKEN = "synthetic-SECRET-token-123456"
HEADER = "X-Synthetic-Token"


class Recorder:
    def __init__(self, handler: Callable[[httpx.Request], Any]) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        result = self.handler(request)
        if asyncio.iscoroutine(result):
            result = await result
        assert isinstance(result, httpx.Response)
        return result


def make(handler: Callable[[httpx.Request], Any], **cfg: Any) -> tuple[OrchClient, Recorder, list[float]]:
    rec = Recorder(handler)
    sleeps: list[float] = []

    async def fake_sleep(d: float) -> None:
        sleeps.append(d)

    auth = cfg.pop("auth", AuthConfig(mode="header", header_name=HEADER, token=SecretStr(TOKEN)))
    config = ClientConfig(base_url="https://orch.synthetic.invalid/api", auth=auth, min_interval_s=0, **cfg)
    client = OrchClient(config, transport=httpx.MockTransport(rec), sleep=fake_sleep, rand=lambda: 1.0,
                        clock=lambda: 0.0)
    return client, rec, sleeps


def ok(body: Any = None) -> httpx.Response:
    return httpx.Response(200, json=body if body is not None else {"ok": True})


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_get_sends_token_in_the_configured_header_and_params() -> None:
    client, rec, _ = make(lambda r: ok({"x": 1}))
    assert run(client.get_json("/synthetic/tunnels", {"window": 60, "all": True})) == {"x": 1}
    req = rec.requests[0]
    assert req.method == "GET" and req.url.path == "/api/synthetic/tunnels"
    assert req.headers[HEADER] == TOKEN
    assert dict(req.url.params) == {"window": "60", "all": "true"}


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "post"])
def test_refuses_every_non_get_before_sending(method: str) -> None:
    client, rec, _ = make(lambda r: ok())
    with pytest.raises(ReadOnlyViolationError, match="read-only"):
        run(client.request(method, "/synthetic/config"))
    assert rec.requests == [], "nothing may reach the wire"


def test_request_hook_blocks_writes_even_through_the_raw_client() -> None:
    client, rec, _ = make(lambda r: ok())

    async def sneaky() -> None:
        await client._client.post("/synthetic/config", json={"x": 1})  # deliberately bypassing the public API

    with pytest.raises(ReadOnlyViolationError):
        run(sneaky())
    assert rec.requests == []


def test_retries_503_then_succeeds_with_backoff() -> None:
    codes = iter([503, 503, 200])
    client, rec, sleeps = make(lambda r: httpx.Response(next(codes), json={"ok": True}))
    assert run(client.get_json("/synthetic/tunnels")) == {"ok": True}
    assert len(rec.requests) == 3
    assert sleeps == [0.5, 1.0], "exponential backoff (jitter pinned by rand=1.0)"


def test_honours_retry_after() -> None:
    codes = iter([429, 200])
    client, _, sleeps = make(lambda r: httpx.Response(next(codes), headers={"retry-after": "7"}, json={}))
    run(client.get_json("/synthetic/tunnels"))
    assert sleeps == [7.0]


@pytest.mark.parametrize(("status", "hint"), [(404, "check the path"), (401, "check the token"), (400, "")])
def test_does_not_retry_client_errors(status: int, hint: str) -> None:
    client, rec, sleeps = make(lambda r: httpx.Response(status, text="nope"))
    with pytest.raises(OrchHttpError) as exc:
        run(client.get_json("/synthetic/tunnels"))
    assert exc.value.status == status and len(rec.requests) == 1 and sleeps == []
    assert hint in str(exc.value)


def test_gives_up_after_max_attempts_with_a_clear_message() -> None:
    client, rec, _ = make(lambda r: httpx.Response(502, text="bad gateway"), max_attempts=3)
    with pytest.raises(OrchHttpError, match=r"GET /synthetic/tunnels: HTTP 502 .*\(gave up after 3 attempts\)"):
        run(client.get_json("/synthetic/tunnels"))
    assert len(rec.requests) == 3


def test_token_is_redacted_from_errors() -> None:
    client, _, _ = make(lambda r: httpx.Response(400, text=f"invalid token {TOKEN} for user"))
    with pytest.raises(OrchHttpError) as exc:
        run(client.get_json("/synthetic/tunnels"))
    assert TOKEN not in str(exc.value) and "***" in str(exc.value)

    def boom(r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect, header was {TOKEN}")

    client, _, _ = make(boom, max_attempts=2)
    with pytest.raises(OrchError) as exc2:
        run(client.get_json("/synthetic/tunnels"))
    assert TOKEN not in str(exc2.value) and "ConnectError" in str(exc2.value)


def test_honours_the_timeout_on_a_stalled_server() -> None:
    async def stall(r: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return ok()

    client, rec, _ = make(stall, timeout_s=0.05, max_attempts=2)
    started = time.monotonic()
    with pytest.raises(OrchTimeoutError, match=r"within 0\.05 s"):
        run(client.get_json("/synthetic/tunnels"))
    assert time.monotonic() - started < 1.0
    assert len(rec.requests) == 2, "a timeout is transient for a GET and is retried"


def test_non_json_response_is_an_error() -> None:
    client, _, _ = make(lambda r: httpx.Response(200, text="<html>login page</html>",
                                                 headers={"content-type": "text/html"}))
    with pytest.raises(OrchError, match=r"not JSON .*text/html"):
        run(client.get_json("/synthetic/tunnels"))


def test_rate_limit_spaces_requests() -> None:
    client, _, sleeps = make(lambda r: ok())
    object.__setattr__(client.cfg, "min_interval_s", 0.5)
    for _ in range(3):
        run(client.get_json("/synthetic/tunnels"))
    assert sleeps == [0.5, 1.0]


def test_header_auth_requires_header_name_and_token() -> None:
    with pytest.raises(OrchError, match="header_name"):
        make(lambda r: ok(), auth=AuthConfig(mode="header", token=SecretStr(TOKEN)))
    with pytest.raises(OrchError, match="no API token"):
        make(lambda r: ok(), auth=AuthConfig(mode="header", header_name=HEADER))


LOGIN = LoginSpec(method="POST", path="/synthetic/login", body={"user": "${USERNAME}", "pass": "${PASSWORD}"},
                  token_field="session.token", token_header="X-Synthetic-Session")
LOGIN_AUTH = AuthConfig(mode="login", login=LOGIN, username=SecretStr("svc-buffmon"),
                        password=SecretStr("synthetic-PASSWORD-9876"))


def test_login_is_the_single_allowed_non_get_and_its_token_is_used() -> None:
    def handler(r: httpx.Request) -> httpx.Response:
        if r.method == "POST":
            assert json.loads(r.content) == {"user": "svc-buffmon", "pass": "synthetic-PASSWORD-9876"}
            return ok({"session": {"token": "sess-abcdef"}})
        assert r.headers["X-Synthetic-Session"] == "sess-abcdef"
        return ok({"tunnels": []})

    client, rec, _ = make(handler, auth=LOGIN_AUTH)
    assert run(client.get_json("/synthetic/tunnels")) == {"tunnels": []}
    assert [r.method for r in rec.requests] == ["POST", "GET"]
    with pytest.raises(ReadOnlyViolationError):
        run(client.request("POST", "/synthetic/login"))  # not even the login path outside login()


def test_login_failure_is_not_retried_and_password_is_redacted() -> None:
    client, rec, sleeps = make(lambda r: httpx.Response(503, text="pass synthetic-PASSWORD-9876 rejected"),
                               auth=LOGIN_AUTH)
    with pytest.raises(OrchHttpError) as exc:
        run(client.get_json("/synthetic/tunnels"))
    assert len(rec.requests) == 1 and sleeps == []
    assert "synthetic-PASSWORD-9876" not in str(exc.value)


def test_session_expiry_triggers_one_relogin() -> None:
    gets = iter([401, 200])

    def handler(r: httpx.Request) -> httpx.Response:
        if r.method == "POST":
            return ok({"session": {"token": "sess-new"}})
        return httpx.Response(next(gets), json={"ok": True})

    client, rec, _ = make(handler, auth=LOGIN_AUTH)
    assert run(client.get_json("/synthetic/tunnels")) == {"ok": True}
    assert [r.method for r in rec.requests] == ["POST", "GET", "POST", "GET"]
