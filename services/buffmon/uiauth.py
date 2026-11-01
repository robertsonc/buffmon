"""Dashboard login: a shared UI token exchanged for a signed, expiring cookie.

The server only stores sha256(token). The cookie is ``<expiry>.<nonce>.<hmac>``
signed with BUFFMON_SESSION_SECRET. This is deliberately minimal; production
deployments should sit behind an identity-aware proxy (DESIGN §9).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from collections import deque

log = logging.getLogger(__name__)

COOKIE_NAME = "bm_session"


class UiAuth:
    def __init__(
        self,
        enabled: bool,
        token_sha256: str | None,
        secret: str | None,
        ttl_s: int,
        max_failures_per_min: int = 10,
    ) -> None:
        self.enabled = enabled
        self._token_sha256 = (token_sha256 or "").lower().encode("ascii")
        self._secret = (secret or "").encode("utf-8")
        self.ttl_s = ttl_s
        self._max_failures = max_failures_per_min
        self._failures: dict[str, deque[float]] = {}
        if not enabled:
            log.warning("dashboard authentication is DISABLED (BUFFMON_UI_AUTH=disabled); "
                        "anyone who can reach this port can read all telemetry")

    def _sign(self, payload: str) -> str:
        return hmac.new(self._secret, payload.encode("ascii"), hashlib.sha256).hexdigest()

    def throttled(self, client: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        q = self._failures.get(client)
        if q is None:
            return False
        while q and now - q[0] > 60:
            q.popleft()
        if not q:
            del self._failures[client]
            return False
        return len(q) >= self._max_failures

    def check_token(self, token: str, client: str) -> bool:
        if self.throttled(client):
            return False
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest().encode("ascii")
        ok = hmac.compare_digest(digest, self._token_sha256)
        if not ok:
            self._failures.setdefault(client, deque()).append(time.monotonic())
            if len(self._failures) > 10_000:  # bound memory under a spray of sources
                self._failures.pop(next(iter(self._failures)))
            log.warning("failed dashboard login from %s", client)
        return ok

    def issue(self, now: float | None = None) -> str:
        now = time.time() if now is None else now
        payload = f"{int(now) + self.ttl_s}.{secrets.token_hex(8)}"
        return f"{payload}.{self._sign(payload)}"

    def valid(self, cookie: str | None, now: float | None = None) -> bool:
        if not self.enabled:
            return True
        if not cookie:
            return False
        now = time.time() if now is None else now
        parts = cookie.split(".")
        if len(parts) != 3 or not parts[0].isdigit():
            return False
        payload = f"{parts[0]}.{parts[1]}"
        if not hmac.compare_digest(self._sign(payload).encode("ascii"), parts[2].encode("ascii")):
            return False
        return int(parts[0]) > now
