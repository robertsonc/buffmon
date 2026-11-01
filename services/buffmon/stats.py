"""Small, dependency-free statistics helpers."""

from __future__ import annotations

import math
from collections.abc import Sequence

Z95 = 1.959963984540054


def wilson_upper(failures: int, trials: int, z: float = Z95) -> float:
    """Upper bound of the Wilson score interval for a proportion.

    With zero failures in n trials this is z²/(n+z²) ≈ 3.84/(n+3.84), the
    well-behaved cousin of the "rule of three". Returns 1.0 when n == 0.
    """
    if trials <= 0:
        return 1.0
    if failures < 0 or failures > trials:
        raise ValueError("failures must be within [0, trials]")
    if failures == trials:
        return 1.0
    n = float(trials)
    p = failures / n
    z2 = z * z
    centre = p + z2 / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return min(1.0, (centre + margin) / (1 + z2 / n))


def percentile(sorted_values: Sequence[float], q: float) -> float | None:
    """Linear-interpolation percentile (same as numpy's default) of an
    already-sorted sequence. ``q`` is in [0, 1]."""
    if not sorted_values:
        return None
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be within [0, 1]")
    pos = (len(sorted_values) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(sorted_values[lo])
    frac = pos - lo
    return float(sorted_values[lo]) * (1 - frac) + float(sorted_values[hi]) * frac


def ratio(num: float, den: float) -> float | None:
    return num / den if den > 0 else None


def initial_ttl_guess(ttl: int) -> int:
    """Common initial TTLs are 64 (Linux, macOS), 128 (Windows) and 255 (network gear)."""
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


def hops_from_ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None
    return initial_ttl_guess(ttl) - ttl
