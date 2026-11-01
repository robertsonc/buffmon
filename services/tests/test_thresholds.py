"""Per-target threshold overrides and hot reload."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from buffmon.thresholds import Thresholds, ThresholdsFile, load_thresholds
from tests.conftest import THRESHOLDS


def with_overrides(overrides: list[dict[str, Any]]) -> Thresholds:
    raw = yaml.safe_load(THRESHOLDS.read_text())
    raw["overrides"] = overrides
    return Thresholds.model_validate(raw)


LON: dict[str, Any] = {
    "name": "lon-dc1",
    "match": {"site": "LON-*", "session": "dc1-*"},
    "rtt_p95_ms": {"good": 180, "bad": 300},
}


def test_shipped_file_has_no_active_overrides() -> None:
    assert load_thresholds(THRESHOLDS).overrides == []


def test_override_replaces_only_the_metrics_it_sets() -> None:
    t = with_overrides([LON])
    r = t.resolve("LON-BR03", "lon-p1", "dc1-voice", "voice")
    assert r.override == "lon-dc1" and r.effective_class == "voice"
    assert (r.limits.rtt_p95_ms.good, r.limits.rtt_p95_ms.bad) == (180, 300)
    voice = t.classes["voice"]
    assert r.limits.loss_pct == voice.loss_pct and r.limits.jitter_ms == voice.jitter_ms


def test_every_given_field_must_match_and_globs_are_case_sensitive() -> None:
    t = with_overrides([LON])
    assert t.resolve("LON-BR03", "p", "m365-https", "interactive").override is None  # session differs
    assert t.resolve("lon-br03", "p", "dc1-voice", "voice").override is None  # case
    assert t.resolve("NYC-BR02", "p", "dc1-voice", "voice").override is None


def test_first_matching_override_wins() -> None:
    narrow: dict[str, Any] = {"name": "lon-voice", "match": {"site": "LON-*", "session": "dc1-voice"},
              "rtt_p95_ms": {"good": 160, "bad": 260}}
    t = with_overrides([narrow, LON])
    assert t.resolve("LON-1", "p", "dc1-voice", "voice").override == "lon-voice"
    assert t.resolve("LON-1", "p", "dc1-video", "video").override == "lon-dc1"


def test_unknown_app_class_still_gets_override_on_the_default_class() -> None:
    t = with_overrides([LON])
    r = t.resolve("LON-1", "p", "dc1-x", "mystery")
    assert r.effective_class == t.default_class and r.override == "lon-dc1"


@pytest.mark.parametrize("bad", [
    {"name": "x", "match": {}, "rtt_p95_ms": {"good": 1, "bad": 2}},                      # empty match
    {"name": "x", "match": {"site": "A"}},                                                 # sets nothing
    {"name": "x", "match": {"site": "A"}, "rtt_p95_ms": {"good": 3, "bad": 2}},            # good > bad
    {"name": "x", "match": {"site": "A", "vlan": "1"}, "loss_pct": {"good": 1, "bad": 2}},  # unknown key
])
def test_invalid_overrides_are_rejected(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        with_overrides([bad])


def test_duplicate_override_names_are_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        with_overrides([LON, LON])


def test_hot_reload_applies_valid_edits_and_ignores_broken_ones(tmp_path: Path) -> None:
    path = tmp_path / "thresholds.yaml"
    raw = yaml.safe_load(THRESHOLDS.read_text())
    path.write_text(yaml.safe_dump(raw))
    tf = ThresholdsFile(path)
    assert not tf.maybe_reload()

    raw["overrides"] = [LON]
    path.write_text(yaml.safe_dump(raw))
    os.utime(path, ns=(1, tf._mtime_ns + 1_000_000))
    assert tf.maybe_reload() and tf.current.overrides[0].name == "lon-dc1"

    path.write_text("overrides: [ {name: broken} ]\n")
    os.utime(path, ns=(1, tf._mtime_ns + 2_000_000))
    assert not tf.maybe_reload()
    assert tf.current.overrides[0].name == "lon-dc1", "a broken edit keeps the previous thresholds"
