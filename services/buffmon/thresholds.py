"""Application-class thresholds, loaded from ``services/thresholds.yaml``."""

from __future__ import annotations

import logging
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

log = logging.getLogger(__name__)


class Limit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    good: float = Field(ge=0)
    bad: float = Field(ge=0)

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.good > self.bad:
            raise ValueError("good must be <= bad")
        return self

    def grade(self, value: float) -> str:
        if value <= self.good:
            return "good"
        if value <= self.bad:
            return "degraded"
        return "bad"


class ClassThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str = ""
    rtt_p95_ms: Limit
    loss_pct: Limit
    jitter_ms: Limit | None = None


class Windows(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    loss_s: int = Field(default=30, ge=1, le=600)
    latency_s: int = Field(default=10, ge=1, le=600)


class OverrideMatch(BaseModel):
    """Shell-style globs (``fnmatch``, case-sensitive). Every given field must match."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    site: str | None = None
    probe_id: str | None = None
    session: str | None = None
    app_class: str | None = None

    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not any((self.site, self.probe_id, self.session, self.app_class)):
            raise ValueError("match needs at least one of site, probe_id, session, app_class")
        return self

    def matches(self, site: str, probe_id: str, session: str, app_class: str) -> bool:
        pairs = ((self.site, site), (self.probe_id, probe_id), (self.session, session), (self.app_class, app_class))
        return all(pattern is None or fnmatchcase(value, pattern) for pattern, value in pairs)


class Override(BaseModel):
    """Per-target limits, e.g. a long-haul site whose best path is 140 ms."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=64)
    match: OverrideMatch
    note: str = ""
    rtt_p95_ms: Limit | None = None
    loss_pct: Limit | None = None
    jitter_ms: Limit | None = None

    @model_validator(mode="after")
    def _overrides_something(self) -> Self:
        if self.rtt_p95_ms is None and self.loss_pct is None and self.jitter_ms is None:
            raise ValueError(f"override {self.name!r} sets no limits (rtt_p95_ms, loss_pct or jitter_ms)")
        return self


class Resolved(BaseModel):
    """The limits that actually apply to one session."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    effective_class: str
    limits: ClassThresholds
    override: str | None = None


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    windows: Windows = Windows()
    default_class: str
    classes: dict[str, ClassThresholds]
    # Ordered; the first matching override wins. Metrics an override does not
    # set fall back to the session's app class.
    overrides: list[Override] = []

    @model_validator(mode="after")
    def _default_exists(self) -> Self:
        if self.default_class not in self.classes:
            raise ValueError(f"default_class {self.default_class!r} is not defined in classes")
        names = [o.name for o in self.overrides]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"override names must be unique: {', '.join(dupes)}")
        return self

    def for_class(self, app_class: str) -> tuple[str, ClassThresholds]:
        """Returns (effective class name, thresholds), falling back to the default class."""
        if app_class in self.classes:
            return app_class, self.classes[app_class]
        return self.default_class, self.classes[self.default_class]

    def resolve(self, site: str, probe_id: str, session: str, app_class: str) -> Resolved:
        """Class limits for the session, with the first matching override applied."""
        eff_class, base = self.for_class(app_class)
        for o in self.overrides:
            if o.match.matches(site, probe_id, session, app_class):
                merged = base.model_copy(
                    update={
                        "rtt_p95_ms": o.rtt_p95_ms or base.rtt_p95_ms,
                        "loss_pct": o.loss_pct or base.loss_pct,
                        "jitter_ms": o.jitter_ms or base.jitter_ms,
                    }
                )
                return Resolved(effective_class=eff_class, limits=merged, override=o.name)
        return Resolved(effective_class=eff_class, limits=base)


class ThresholdsFile:
    """Thresholds plus hot reload: an edited file applies without a restart. A
    file that fails validation is logged and the previous thresholds stay."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.current = load_thresholds(path)
        self._mtime_ns = path.stat().st_mtime_ns

    def maybe_reload(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError as exc:
            log.warning("thresholds file %s unreadable, keeping current thresholds: %s", self.path, exc)
            return False
        if mtime == self._mtime_ns:
            return False
        self._mtime_ns = mtime
        try:
            self.current = load_thresholds(self.path)
        except (RuntimeError, ValueError) as exc:
            log.error("thresholds file %s rejected, keeping current thresholds: %s", self.path, exc)
            return False
        log.info("reloaded thresholds from %s (%d overrides)", self.path, len(self.current.overrides))
        return True


def load_thresholds(path: Path) -> Thresholds:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"cannot read thresholds file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuntimeError(f"thresholds file {path} is not valid YAML: {exc}") from exc
    return Thresholds.model_validate(raw)
