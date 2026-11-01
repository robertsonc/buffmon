"""Read-only Orchestrator HTTP client.

Read-only is enforced, not promised:

* the only public request method is :meth:`OrchClient.get_json`;
* :meth:`OrchClient.request` raises :class:`ReadOnlyViolationError` for any
  method other than GET *before* anything is sent;
* an httpx request hook re-checks every outgoing request, so even code that
  reaches the underlying client directly cannot send a write.

Two documented exceptions:

* the login request declared in the mapping file (``auth.mode: login``), sent at
  most once per login, never retried, only while :meth:`OrchClient.login` runs;
* POSTs allowed by the POST policy (:mod:`buffmon.orch.post_policy`, file
  ``deploy/orchestrator/post-allowlist.yaml``): reads that Orchestrator only
  offers as POST. Each request goes through :meth:`OrchClient.post_json` with a
  rule id; the rule supplies the path and limits every parameter and body key,
  and the request hook re-checks that the outgoing POST carries that rule's id
  and exact path. No policy, no POSTs.

No endpoint, header name or field name is built in: they come from the mapping
file, the POST policy and the deployment's settings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import ssl
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import SecretStr

from .post_policy import EMPTY_POLICY, PostPolicy

log = logging.getLogger(__name__)

# Request extension that tells the request hook which POST-policy rule a POST was sent under.
POST_RULE_EXTENSION = "buffmon_post_rule"

TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})
ParamValue = str | int | float | bool


class OrchError(RuntimeError):
    """Something went wrong talking to Orchestrator. The message says what and why."""


class ReadOnlyViolationError(OrchError):
    """Refused to send a request that could change Orchestrator state."""


class OrchTimeoutError(OrchError):
    pass


class OrchHttpError(OrchError):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class LoginSpec:
    """The one non-GET request the client may send (mapping ``auth.login``)."""

    method: Literal["POST", "GET"]
    path: str
    # JSON body; string values may contain ${USERNAME} and ${PASSWORD}.
    body: Mapping[str, Any] = field(default_factory=dict)
    # Dotted path of a token in the JSON response, sent on later GETs in
    # ``token_header``. None: the login sets a session cookie instead.
    token_field: str | None = None
    token_header: str | None = None


@dataclass(frozen=True)
class AuthConfig:
    mode: Literal["header", "login"]
    header_name: str | None = None
    token: SecretStr | None = None
    login: LoginSpec | None = None
    username: SecretStr | None = None
    password: SecretStr | None = None

    def validate(self) -> None:
        if self.mode == "header":
            if not self.header_name:
                raise OrchError("auth.mode is 'header' but auth.header_name is not set in the mapping")
            if self.token is None or not self.token.get_secret_value():
                raise OrchError("auth.mode is 'header' but no API token was provided (token file or env)")
        else:
            if self.login is None:
                raise OrchError("auth.mode is 'login' but auth.login is not set in the mapping")
            if self.username is None or self.password is None:
                raise OrchError("auth.mode is 'login' but no username/password was provided")
            if self.login.token_field and not self.login.token_header:
                raise OrchError("auth.login.token_field is set but auth.login.token_header is not")


@dataclass(frozen=True)
class ClientConfig:
    base_url: str
    auth: AuthConfig
    timeout_s: float = 15.0
    ca_bundle: Path | None = None
    max_concurrency: int = 4
    # Rate limit: at most one request starts every min_interval_s.
    min_interval_s: float = 0.1
    max_attempts: int = 4
    backoff_base_s: float = 0.5
    backoff_max_s: float = 30.0
    max_response_bytes: int = 64 * 1024 * 1024
    # Which POSTs may be sent at all (fails closed: empty policy, no POSTs).
    post_policy: PostPolicy = EMPTY_POLICY


def load_secret(file: Path | None, env_name: str | None, what: str) -> SecretStr | None:
    """Reads a secret from a file (preferred) or an environment variable."""
    if file is not None:
        try:
            value = file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise OrchError(f"cannot read {what} file {file}: {exc.strerror or exc}") from exc
        if not value:
            raise OrchError(f"{what} file {file} is empty")
        if file.stat().st_mode & 0o077:
            log.warning("%s file %s is readable by group/others; chmod 600 it", what, file)
        return SecretStr(value)
    if env_name:
        value = os.environ.get(env_name, "").strip()
        return SecretStr(value) if value else None
    return None


def dig(obj: Any, path: str) -> Any:
    """Follows a dotted path ("a.b.0.c") through dicts and lists; None if absent."""
    cur = obj
    for seg in path.split(".") if path else []:
        if isinstance(cur, dict):
            cur = cur.get(seg)
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return None
    return cur


def _substitute(value: Any, subs: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        for k, v in subs.items():
            value = value.replace("${" + k + "}", v)
        return value
    if isinstance(value, dict):
        return {k: _substitute(v, subs) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, subs) for v in value]
    return value


class OrchClient:
    def __init__(
        self,
        cfg: ClientConfig,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rand: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        cfg.auth.validate()
        self.cfg = cfg
        self._sleep = sleep
        self._rand = rand
        self._clock = clock
        verify: ssl.SSLContext | bool = True
        if cfg.ca_bundle is not None:
            verify = ssl.create_default_context(cafile=str(cfg.ca_bundle))
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            timeout=httpx.Timeout(cfg.timeout_s),
            verify=verify,
            transport=transport,
            follow_redirects=False,
            event_hooks={"request": [self._guard]},
        )
        # rule id -> exact URL path (API base + rule path) the request hook accepts for it.
        base_path = httpx.URL(cfg.base_url).path.rstrip("/")
        self._post_paths = {r.id: base_path + r.path for r in cfg.post_policy.rules}
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self._slot_lock = asyncio.Lock()
        self._next_slot = 0.0
        self._login_in_progress = False
        self._login_lock = asyncio.Lock()
        self._session_token: str | None = None
        self._logged_in = False
        self._secrets: list[str] = [
            s.get_secret_value()
            for s in (cfg.auth.token, cfg.auth.username, cfg.auth.password)
            if s is not None and s.get_secret_value()
        ]
        self.requests_sent = 0

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- safety ---------------------------------------------------------------
    def _redact(self, text: str) -> str:
        for s in self._secrets:
            if len(s) >= 4:
                text = text.replace(s, "***")
        return text

    async def _guard(self, request: httpx.Request) -> None:
        """Last line of defence: runs for every request the httpx client sends."""
        if request.method == "GET":
            return
        if request.method == "POST" and POST_RULE_EXTENSION in request.extensions:
            why = self._post_refusal(request)
            if why is None:
                return
            raise ReadOnlyViolationError(f"refused to send POST {request.url.path}: {why}")
        login = self.cfg.auth.login
        if (
            self._login_in_progress
            and login is not None
            and request.method == login.method
            and request.url.path.endswith(login.path)
        ):
            return
        raise ReadOnlyViolationError(
            f"refused to send {request.method} {request.url.path}: the Orchestrator client is read-only"
        )

    def _post_refusal(self, request: httpx.Request) -> str | None:
        """Why the outgoing POST does not fit the POST-policy rule it claims (None: it fits).
        Checks what is actually on the wire: path, query string and body bytes."""
        rule_id = request.extensions.get(POST_RULE_EXTENSION)
        rule = self.cfg.post_policy.rule(rule_id) if isinstance(rule_id, str) else None
        if rule is None:
            return f"rule {rule_id!r} is not in the POST policy"
        if request.url.path != self._post_paths[rule.id]:
            return f"rule {rule.id} allows only {self._post_paths[rule.id]}"
        items = request.url.params.multi_items()
        if len({k for k, _ in items}) != len(items):
            return "repeated query parameters"
        try:
            content = request.content
        except httpx.RequestNotRead:
            return "streamed body (a rule's body must be checked before sending)"
        if len(content) > rule.max_body_bytes:
            return f"body is {len(content)} bytes (rule {rule.id} allows {rule.max_body_bytes})"
        try:
            body = json.loads(content) if content else None
        except ValueError:
            return "body is not JSON"
        problems = rule.check_request(dict(items), body)
        return "; ".join(problems) if problems else None

    # -- auth -----------------------------------------------------------------
    def _auth_headers(self) -> dict[str, str]:
        auth = self.cfg.auth
        if auth.mode == "header" and auth.header_name and auth.token is not None:
            return {auth.header_name: auth.token.get_secret_value()}
        if auth.mode == "login" and auth.login and auth.login.token_header and self._session_token:
            return {auth.login.token_header: self._session_token}
        return {}

    async def login(self) -> None:
        """Performs the mapping's login request once (no retry: it is not a GET)."""
        auth = self.cfg.auth
        if auth.mode != "login" or auth.login is None or auth.username is None or auth.password is None:
            return
        spec = auth.login
        async with self._login_lock:
            body = _substitute(
                dict(spec.body),
                {"USERNAME": auth.username.get_secret_value(), "PASSWORD": auth.password.get_secret_value()},
            )
            self._login_in_progress = True
            try:
                async with asyncio.timeout(self.cfg.timeout_s):
                    resp = await self._client.request(
                        spec.method, spec.path, json=body if spec.method == "POST" else None
                    )
            except TimeoutError as exc:
                raise OrchTimeoutError(
                    f"login {spec.method} {spec.path}: no response in {self.cfg.timeout_s:g} s"
                ) from exc
            except httpx.TransportError as exc:
                raise OrchError(self._redact(f"login {spec.method} {spec.path}: {type(exc).__name__}: {exc}")) from exc
            finally:
                self._login_in_progress = False
            self.requests_sent += 1
            if resp.status_code >= 400:
                raise OrchHttpError(
                    self._redact(
                        f"login {spec.method} {spec.path} rejected: HTTP {resp.status_code} "
                        f"{resp.reason_phrase}: {resp.text[:200]}"
                    ),
                    resp.status_code,
                )
            if spec.token_field:
                try:
                    token = dig(resp.json(), spec.token_field)
                except ValueError as exc:
                    raise OrchError(f"login {spec.path}: response is not JSON, cannot read {spec.token_field}") from exc
                if not isinstance(token, str) or not token:
                    raise OrchError(f"login {spec.path}: no string token at {spec.token_field!r} in the response")
                self._session_token = token
                self._secrets.append(token)
            self._logged_in = True
            log.info("logged in to Orchestrator at %s", self.cfg.base_url)

    # -- requests -------------------------------------------------------------
    async def _rate_limit(self) -> None:
        async with self._slot_lock:
            now = self._clock()
            start = max(now, self._next_slot)
            self._next_slot = start + self.cfg.min_interval_s
        if start > now:
            await self._sleep(start - now)

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after is not None:
            try:
                return min(float(retry_after), self.cfg.backoff_max_s)
            except ValueError:
                pass  # HTTP-date form: fall back to exponential backoff
        ceiling = min(self.cfg.backoff_max_s, self.cfg.backoff_base_s * (2.0 ** (attempt - 1)))
        return ceiling * (0.5 + 0.5 * self._rand())

    async def request(self, method: str, path: str, params: Mapping[str, ParamValue] | None = None) -> Any:
        """GET only. Any other method raises before a byte is sent."""
        if method.upper() != "GET":
            raise ReadOnlyViolationError(
                f"refused to send {method.upper()} {path}: the Orchestrator client is read-only"
            )
        return await self.get_json(path, params)

    async def get_json(self, path: str, params: Mapping[str, ParamValue] | None = None) -> Any:
        """GET ``path`` and return the decoded JSON, retrying transient failures."""
        return await self._send("GET", path, params, None)

    async def post_json(self, rule_id: str, params: Mapping[str, ParamValue] | None, body: Any) -> Any:
        """POST under a POST-policy rule: the rule supplies the path, and every
        query parameter and body key must fit it. Refused before sending
        otherwise. Retried like a GET (policy rules only read)."""
        rule = self.cfg.post_policy.rule(rule_id)
        if rule is None:
            raise ReadOnlyViolationError(
                f"refused to send POST: rule {rule_id!r} is not in the POST policy "
                f"(policy has: {', '.join(r.id for r in self.cfg.post_policy.rules) or 'no rules'})"
            )
        problems = rule.check_request(params or {}, body)
        size = len(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        if size > rule.max_body_bytes:
            problems.append(f"body is {size} bytes (rule {rule.id} allows {rule.max_body_bytes})")
        if problems:
            raise ReadOnlyViolationError(f"refused to send POST {rule.path}: " + "; ".join(problems))
        return await self._send("POST", rule.path, params, body, rule.id)

    async def _send(
        self,
        method: str,
        path: str,
        params: Mapping[str, ParamValue] | None,
        json_body: Any,
        post_rule: str | None = None,
    ) -> Any:
        if self.cfg.auth.mode == "login" and not self._logged_in:
            await self.login()
        q = {k: (str(v).lower() if isinstance(v, bool) else v) for k, v in (params or {}).items()}
        what = f"{method} {path}"
        last: OrchError | None = None
        relogged = False
        attempt = 0
        while attempt < self.cfg.max_attempts:
            attempt += 1
            await self._rate_limit()
            retry_after: str | None = None
            body = b""
            async with self._sem:
                try:
                    async with asyncio.timeout(self.cfg.timeout_s):
                        if method == "GET":
                            resp = await self._client.get(path, params=q, headers=self._auth_headers())
                        else:
                            resp = await self._client.post(
                                path, params=q, json=json_body, headers=self._auth_headers(),
                                extensions={POST_RULE_EXTENSION: post_rule},
                            )
                        body = resp.content
                except TimeoutError:
                    last = OrchTimeoutError(f"{what}: no complete response within {self.cfg.timeout_s:g} s")
                    resp = None
                except httpx.TimeoutException:
                    last = OrchTimeoutError(f"{what}: timed out after {self.cfg.timeout_s:g} s")
                    resp = None
                except httpx.TransportError as exc:
                    last = OrchError(self._redact(f"{what}: {type(exc).__name__}: {exc}"))
                    resp = None
                self.requests_sent += 1
            if resp is not None:
                if resp.status_code < 400:
                    if len(body) > self.cfg.max_response_bytes:
                        raise OrchError(
                            f"{what}: response of {len(body)} bytes exceeds the "
                            f"{self.cfg.max_response_bytes} byte limit"
                        )
                    try:
                        return json.loads(body)
                    except ValueError as exc:
                        ctype = resp.headers.get("content-type", "?")
                        raise OrchError(f"{what}: response is not JSON (content-type {ctype})") from exc
                excerpt = self._redact(resp.text[:200].replace("\n", " "))
                if resp.status_code == 401 and self.cfg.auth.mode == "login" and not relogged:
                    log.info("%s: session expired (401), logging in again", what)
                    self._logged_in = False
                    relogged = True
                    await self.login()
                    attempt -= 1  # the re-login does not consume a retry
                    continue
                if resp.status_code not in TRANSIENT_STATUS:
                    hint = ""
                    if resp.status_code in (401, 403):
                        hint = " (check the token and auth settings in the mapping)"
                    elif resp.status_code == 404:
                        hint = " (check the path in the mapping against this Orchestrator's Swagger)"
                    raise OrchHttpError(
                        f"{what}: HTTP {resp.status_code} {resp.reason_phrase}{hint}: {excerpt}", resp.status_code
                    )
                last = OrchHttpError(
                    f"{what}: HTTP {resp.status_code} {resp.reason_phrase}: {excerpt}", resp.status_code
                )
                retry_after = resp.headers.get("retry-after")
            if attempt < self.cfg.max_attempts:
                delay = self._backoff(attempt, retry_after)
                log.warning("%s (attempt %d/%d); retrying in %.1f s", last, attempt, self.cfg.max_attempts, delay)
                await self._sleep(delay)
        if last is None:  # unreachable: max_attempts >= 1
            raise OrchError(f"{what}: no attempt was made (max_attempts={self.cfg.max_attempts})")
        msg = f"{last} (gave up after {self.cfg.max_attempts} attempts)"
        if isinstance(last, OrchHttpError):
            raise OrchHttpError(msg, last.status) from last
        if isinstance(last, OrchTimeoutError):
            raise OrchTimeoutError(msg) from last
        raise OrchError(msg) from last
