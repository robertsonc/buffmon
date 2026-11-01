"""Application-class thresholds, loaded from ``services/thresholds.yaml``."""

from __future__ import annotations

from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    windows: Windows = Windows()
    default_class: str
    classes: dict[str, ClassThresholds]

    @model_validator(mode="after")
    def _default_exists(self) -> Self:
        if self.default_class not in self.classes:
            raise ValueError(f"default_class {self.default_class!r} is not defined in classes")
        return self

    def for_class(self, app_class: str) -> tuple[str, ClassThresholds]:
        """Returns (effective class name, thresholds), falling back to the default class."""
        if app_class in self.classes:
            return app_class, self.classes[app_class]
        return self.default_class, self.classes[self.default_class]


def load_thresholds(path: Path) -> Thresholds:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"cannot read thresholds file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuntimeError(f"thresholds file {path} is not valid YAML: {exc}") from exc
    return Thresholds.model_validate(raw)
