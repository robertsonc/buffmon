"""Recently-seen idempotency keys.

Probes retry a batch when they did not get a response, so the same record can
arrive twice. Dropping repeats here keeps the live hub and the ClickHouse
rollup (which a materialised view feeds at insert time) from double counting.
ReplacingMergeTree on probe_second is the backstop after a restart.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Hashable


class RecentKeys:
    def __init__(self, ttl_s: float, max_keys: int) -> None:
        if ttl_s <= 0 or max_keys <= 0:
            raise ValueError("ttl_s and max_keys must be positive")
        self._ttl_s = ttl_s
        self._max = max_keys
        self._keys: OrderedDict[Hashable, float] = OrderedDict()

    def __len__(self) -> int:
        return len(self._keys)

    def _expire(self, now: float) -> None:
        keys = self._keys
        while keys:
            _, expires = next(iter(keys.items()))
            if expires > now:
                break
            keys.popitem(last=False)
        while len(keys) > self._max:
            keys.popitem(last=False)

    def seen(self, key: Hashable, now: float | None = None) -> bool:
        """True if the key was seen within the TTL. Does not record it."""
        now = time.monotonic() if now is None else now
        self._expire(now)
        expires = self._keys.get(key)
        return expires is not None and expires > now

    def add(self, key: Hashable, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._keys[key] = now + self._ttl_s
        self._keys.move_to_end(key)
        self._expire(now)
