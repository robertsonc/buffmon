"""Probe authentication.

Tokens are minted by ``buffmon-mint-token probe`` and stored only as SHA-256
hashes in a JSON file ``{"probe_id": "<sha256 hex>"}``. Each token is bound to
exactly one probe_id. The file is re-read when it changes, so adding a probe
does not need a restart.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
from pathlib import Path

log = logging.getLogger(__name__)

TOKEN_PREFIX = "bm_"  # noqa: S105 - a public prefix that makes leaked tokens greppable, not a secret
MIN_TOKEN_LEN = 32
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PROBE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    value = value.strip()
    if len(value) < MIN_TOKEN_LEN or len(value) > 256:
        return None
    return value


class ProbeTokens:
    """Maps token hash -> probe_id, reloaded from disk when the file changes."""

    def __init__(self, path: Path | None, reload_interval_s: float = 5.0) -> None:
        self._path = path
        self._reload_interval_s = reload_interval_s
        self._by_hash: dict[str, str] = {}
        self._mtime_ns: int | None = None
        self._checked_at = 0.0
        if path is None:
            log.warning("BUFFMON_PROBE_TOKENS_FILE is not set: every ingest request will be rejected")
        else:
            self._load()

    @property
    def count(self) -> int:
        return len(self._by_hash)

    def _load(self) -> None:
        assert self._path is not None
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            if self._by_hash:
                log.error("probe tokens file %s disappeared; keeping %d known tokens",
                          self._path, len(self._by_hash))
            else:
                log.warning("probe tokens file %s does not exist yet", self._path)
            return
        if stat.st_mode & 0o077:
            log.warning("probe tokens file %s is readable by group/other (mode %o); tighten to 0600",
                        self._path, stat.st_mode & 0o777)
        if self._mtime_ns == stat.st_mtime_ns:
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("cannot load probe tokens file %s: %s (keeping previous tokens)", self._path, exc)
            return
        if not isinstance(raw, dict):
            log.error("probe tokens file %s must be a JSON object of probe_id -> sha256", self._path)
            return
        by_hash: dict[str, str] = {}
        for probe_id, digest in raw.items():
            if not isinstance(probe_id, str) or not _PROBE_ID.match(probe_id):
                log.error("ignoring invalid probe_id %r in tokens file", probe_id)
                continue
            if not isinstance(digest, str) or not _HEX64.match(digest):
                log.error("ignoring probe %s: value must be a lowercase sha256 hex digest", probe_id)
                continue
            by_hash[digest] = probe_id
        self._by_hash = by_hash
        self._mtime_ns = stat.st_mtime_ns
        log.info("loaded %d probe tokens from %s", len(by_hash), self._path)

    def maybe_reload(self, now: float | None = None) -> None:
        if self._path is None:
            return
        now = time.monotonic() if now is None else now
        if now - self._checked_at < self._reload_interval_s:
            return
        self._checked_at = now
        self._load()

    def authenticate(self, token: str | None) -> str | None:
        """Returns the probe_id the token is bound to, or None."""
        if token is None:
            return None
        self.maybe_reload()
        digest = hash_token(token).encode("ascii")
        # Compare against every entry with compare_digest and no early exit, so
        # timing does not depend on where (or whether) the token matches.
        # Thousands of probes cost well under a millisecond.
        match: str | None = None
        for known, probe_id in self._by_hash.items():
            if hmac.compare_digest(known.encode("ascii"), digest):
                match = probe_id
        return match
