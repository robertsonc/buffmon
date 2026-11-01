from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from buffmon.models import ProbeRecord, parse_endpoint
from tests.conftest import lossy, make_record


def test_valid_record() -> None:
    rec = ProbeRecord.model_validate(make_record())
    assert rec.key == ("p1", "dc1-voice", rec.ts_ms)
    assert rec.session_key == "p1/dc1-voice"


def test_unknown_fields_are_ignored() -> None:
    ProbeRecord.model_validate(make_record(new_field_from_newer_probe=1))


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"lost": 1}, "sent must equal received + lost"),
        ({"rtt_us": [1, 2]}, "len(rtt_us) must equal received"),
        ({"ts_ms": 1_761_955_200_500}, "multiple of interval_ms"),
        ({"rtt_jitter_n": 11}, "cannot exceed received"),
        ({"owd_n": 3, "owd_fwd_sum_us": 1, "owd_back_sum_us": 1}, "requires clock_synced"),
        ({"clock_synced": True, "owd_n": 3}, "requires both owd sums"),
        ({"v": 2}, "v"),
        ({"probe_id": "bad id"}, "probe_id"),
        ({"session": "x" * 65}, "session"),
        ({"kind": "udp"}, "kind"),
        ({"dscp": 64}, "dscp"),
        ({"sent": True}, "sent"),
        ({"sent": 10.0}, "sent"),
        ({"src": "10.1.1.10"}, "ip:port"),
        ({"dst": "[2001:db8::1]:862"}, "IPv6"),
        ({"dst": "10.1.1.1:70000"}, "port out of range"),
        ({"rx_ts": "nic"}, "rx_ts"),
        ({"ttl_fwd": 256}, "ttl_fwd"),
        ({"errors": {"Bad Key": 1}}, "errors"),
        ({"site": " padded"}, "site"),
        ({"rtt_us": [-1] + [1] * 9}, "rtt_us"),
    ],
)
def test_invalid_records(overrides: dict[str, Any], fragment: str) -> None:
    with pytest.raises(ValidationError) as exc:
        ProbeRecord.model_validate(make_record(**overrides))
    assert fragment in str(exc.value)


def test_icmp_cannot_carry_direction_or_ipdv() -> None:
    base = make_record(kind="icmp", dst="10.1.1.1:0", fwd_lost=None, back_lost=None,
                       ipdv_fwd_sum_us=0, ipdv_fwd_n=0, ipdv_back_sum_us=0, ipdv_back_n=0)
    ProbeRecord.model_validate(base)
    with pytest.raises(ValidationError, match="only defined for stamp"):
        ProbeRecord.model_validate({**base, "fwd_lost": 0, "back_lost": 0})
    with pytest.raises(ValidationError, match="only defined for stamp"):
        ProbeRecord.model_validate({**base, "ipdv_fwd_n": 2})


def test_lossy_helper_produces_valid_records() -> None:
    rec = ProbeRecord.model_validate(lossy(make_record(), 3, fwd=2))
    assert (rec.lost, rec.fwd_lost, rec.back_lost, len(rec.rtt_us)) == (3, 2, 1, 7)


def test_parse_endpoint() -> None:
    ip, port = parse_endpoint("10.0.0.1:862")
    assert (str(ip), port) == ("10.0.0.1", 862)
    with pytest.raises(ValueError, match="invalid IP"):
        parse_endpoint("host.example:443")
