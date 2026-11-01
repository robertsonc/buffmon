"""DEV ONLY: fleet simulator that drives the real ingest API.

Generates per-packet STAMP/ICMP/TCP behaviour for N simulated site probes,
aggregates it exactly as docs/PROBE-RECORD.md specifies, and POSTs it to
``/v1/probe/results`` with real bearer tokens. All probe ids start with
``sim-`` and all sites with ``SIM-`` so simulated data is never mistaken for
real measurements.

    buffmon-simulate --url http://127.0.0.1:8080 --tokens-file dev/probe-tokens.json \\
        --probes 4 --backfill-minutes 60 \\
        --inject "sim-nyc-br02/dc1-voice:loss=4,rtt=+60,dir=fwd,after=45,for=120"

Inject keys: loss (percent), rtt (+ms), jitter (ms of extra random delay),
hops (+n, a path change), dir (fwd|back|both), after (s from start, may be
negative to land in the backfill), for (s, 0 = until exit).

The simulator mints its own tokens and merges their hashes into --tokens-file,
which the ingest service re-reads within a few seconds.
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import math
import random
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from buffmon.auth import hash_token
from buffmon.tools.mint_token import merge_into, new_token

log = logging.getLogger("buffmon.simulate")

REPORT_DELAY_S = 3  # a real probe emits a bucket ~1 s + 2 s timeout after it starts

SITES: list[tuple[str, str, float, int]] = [
    # (probe suffix, site, base RTT to DC1 in ms, hops)
    ("sjc-br01", "SIM-SJC-BR01", 14.0, 7),
    ("nyc-br02", "SIM-NYC-BR02", 68.0, 9),
    ("lon-br03", "SIM-LON-BR03", 138.0, 11),
    ("sin-br04", "SIM-SIN-BR04", 182.0, 12),
    ("dfw-br05", "SIM-DFW-BR05", 41.0, 8),
    ("fra-br06", "SIM-FRA-BR06", 151.0, 11),
    ("syd-br07", "SIM-SYD-BR07", 156.0, 13),
    ("chi-br08", "SIM-CHI-BR08", 52.0, 8),
]


@dataclass
class SessionSpec:
    name: str
    kind: str
    app_class: str
    dscp: int
    pps: float
    dst: str
    rtt_ms: float
    hops: int
    loss_pct: float
    jitter_ms: float


@dataclass
class Inject:
    probe_id: str
    session: str
    loss_pct: float = 0.0
    rtt_ms: float = 0.0
    jitter_ms: float = 0.0
    hops: int = 0
    direction: str = "both"
    after_s: float = 0.0
    for_s: float = 0.0

    def active(self, t: float, start: float) -> bool:
        begin = start + self.after_s
        return t >= begin and (self.for_s <= 0 or t < begin + self.for_s)


def parse_inject(spec: str) -> Inject:
    target, _, opts = spec.partition(":")
    probe_id, _, session = target.partition("/")
    if not probe_id or not session:
        raise ValueError("inject target must be probe_id/session")
    inj = Inject(probe_id=probe_id, session=session)
    for part in filter(None, opts.split(",")):
        k, _, v = part.partition("=")
        k = k.strip()
        v = v.strip()
        if k == "loss":
            inj.loss_pct = float(v)
        elif k == "rtt":
            inj.rtt_ms = float(v)
        elif k == "jitter":
            inj.jitter_ms = float(v)
        elif k == "hops":
            inj.hops = int(v)
        elif k == "dir":
            if v not in ("fwd", "back", "both"):
                raise ValueError("dir must be fwd, back or both")
            inj.direction = v
        elif k == "after":
            inj.after_s = float(v)
        elif k == "for":
            inj.for_s = float(v)
        else:
            raise ValueError(f"unknown inject key {k!r}")
    return inj


@dataclass
class SessionSim:
    probe_id: str
    site: str
    spec: SessionSpec
    src: str
    rng: random.Random
    seq: int = 0
    prev_rtt: float | None = None
    prev_fwd: float | None = None
    prev_back: float | None = None
    injects: list[Inject] = field(default_factory=list)

    def _conditions(self, t: float, start: float) -> tuple[float, float, float, float, float, int]:
        """(fwd_loss, back_loss, fwd_add_ms, back_add_ms, extra_jitter_ms, hops_add) at time t."""
        s = self.spec
        # A gentle busy-hour bump so the history charts are not flat lines.
        hour = (t / 3600.0) % 24
        busy = 1.0 + 0.08 * math.sin((hour - 9) / 24 * 2 * math.pi)
        fl = bl = s.loss_pct / 2
        fa = ba = 0.0
        jit = 0.0
        hops = 0
        for inj in self.injects:
            if not inj.active(t, start):
                continue
            if inj.direction in ("fwd", "both"):
                fl += inj.loss_pct
                fa += inj.rtt_ms if inj.direction == "fwd" else inj.rtt_ms / 2
            if inj.direction in ("back", "both"):
                bl += inj.loss_pct
                ba += inj.rtt_ms if inj.direction == "back" else inj.rtt_ms / 2
            jit += inj.jitter_ms
            hops += inj.hops
        fa += s.rtt_ms / 2 * (busy - 1)
        ba += s.rtt_ms / 2 * (busy - 1)
        return fl / 100, bl / 100, fa, ba, jit, hops

    def _delay(self, base_ms: float, jitter_ms: float, extra_jitter: float) -> float:
        r = self.rng
        tail = r.lognormvariate(0, 0.9) * jitter_ms * 0.35
        return max(0.05, base_ms + r.gauss(0, jitter_ms * 0.25) + tail + r.random() * extra_jitter)

    def bucket(self, ts_ms: int, start: float) -> dict[str, Any] | None:
        s = self.spec
        t = ts_ms / 1000.0
        if s.kind == "tcp":
            # one connect attempt every 1/pps seconds
            period = max(1, round(1 / s.pps))
            if (ts_ms // 1000) % period:
                return None
            n = 1
        else:
            n = max(1, round(s.pps))
        fl, bl, fa, ba, xj, hops_add = self._conditions(t, start)
        rec: dict[str, Any] = {
            "v": 1, "probe_id": self.probe_id, "site": self.site, "session": s.name, "kind": s.kind,
            "app_class": s.app_class, "dscp": s.dscp, "src": self.src, "dst": s.dst, "ts_ms": ts_ms,
            "interval_ms": 1000, "sent": n, "received": 0, "lost": 0, "late": 0, "dup": 0, "reordered": 0,
            "fwd_lost": 0 if s.kind == "stamp" else None, "back_lost": 0 if s.kind == "stamp" else None,
            "rtt_us": [], "rtt_jitter_sum_us": 0, "rtt_jitter_n": 0, "ipdv_fwd_sum_us": 0, "ipdv_fwd_n": 0,
            "ipdv_back_sum_us": 0, "ipdv_back_n": 0, "owd_fwd_sum_us": None, "owd_back_sum_us": None,
            "owd_n": 0, "clock_synced": False, "clock_err_us": None, "ttl_fwd": None, "ttl_back": None,
            "rx_ts": "kernel", "errors": {},
        }
        errors: dict[str, int] = {}
        for _ in range(n):
            self.seq += 1
            if self.rng.random() < fl:
                rec["lost"] += 1
                if s.kind == "stamp":
                    rec["fwd_lost"] += 1
                errors["timeout"] = errors.get("timeout", 0) + 1
                continue
            if self.rng.random() < bl:
                rec["lost"] += 1
                if s.kind == "stamp":
                    rec["back_lost"] += 1
                errors["timeout"] = errors.get("timeout", 0) + 1
                continue
            fwd = self._delay(s.rtt_ms / 2 + fa, s.jitter_ms, xj)
            back = self._delay(s.rtt_ms / 2 + ba, s.jitter_ms, xj)
            rtt = fwd + back
            rec["received"] += 1
            rec["rtt_us"].append(round(rtt * 1000))
            if self.prev_rtt is not None:
                rec["rtt_jitter_sum_us"] += round(abs(rtt - self.prev_rtt) * 1000)
                rec["rtt_jitter_n"] += 1
            if s.kind == "stamp":
                if self.prev_fwd is not None and self.prev_back is not None:
                    rec["ipdv_fwd_sum_us"] += round(abs(fwd - self.prev_fwd) * 1000)
                    rec["ipdv_back_sum_us"] += round(abs(back - self.prev_back) * 1000)
                    rec["ipdv_fwd_n"] += 1
                    rec["ipdv_back_n"] += 1
                self.prev_fwd, self.prev_back = fwd, back
            self.prev_rtt = rtt
        if s.kind == "tcp" and rec["lost"]:
            errors = {"timeout": rec["lost"]}
        rec["errors"] = errors
        if rec["received"]:
            hops = s.hops + hops_add
            rec["ttl_back"] = 64 - hops
            if s.kind == "stamp":
                rec["ttl_fwd"] = 64 - hops
        return rec


def build_fleet(n_probes: int, seed: int, injects: list[Inject]) -> dict[str, list[SessionSim]]:
    # Voice/video at 20 pps: a 30 s window of 600 packets can prove loss < 1%
    # (needs >= 381). At 10 pps those sessions would sit at "insufficient-samples".
    fleet: dict[str, list[SessionSim]] = {}
    for i, (suffix, site, rtt, hops) in enumerate(SITES[:n_probes]):
        probe_id = f"sim-{suffix}"
        lan = f"10.{100 + i}.1.10"
        specs = [
            SessionSpec("dc1-voice", "stamp", "voice", 46, 20, "10.10.0.20:862", rtt, hops, 0.05, 0.6 + rtt / 120),
            SessionSpec("dc1-video", "stamp", "video", 34, 20, "10.10.0.20:862", rtt * 1.02, hops, 0.08,
                        0.9 + rtt / 100),
            SessionSpec("dc1-bulk", "stamp", "bulk", 0, 10, "10.10.0.21:862", rtt * 1.1, hops, 0.3, 2 + rtt / 40),
            SessionSpec("gw-reach", "icmp", "interactive", 0, 1, f"10.{100 + i}.1.1:0", 0.9, 1, 0.0, 0.2),
            SessionSpec("m365-https", "tcp", "interactive", 0, 0.2, "52.96.0.10:443", 9 + rtt * 0.15, hops + 3,
                        0.0, 1.5),
        ]
        sims = []
        for j, spec in enumerate(specs):
            port = 0 if spec.kind == "icmp" else 40001 + j
            sim = SessionSim(probe_id=probe_id, site=site, spec=spec, src=f"{lan}:{port}",
                             rng=random.Random(f"{seed}/{probe_id}/{spec.name}"))
            sim.injects = [x for x in injects if x.probe_id == probe_id and x.session == spec.name]
            sims.append(sim)
        fleet[probe_id] = sims
    return fleet


class Poster:
    def __init__(self, url: str, tokens: dict[str, str], timeout_s: float = 10.0) -> None:
        self._client = httpx.Client(base_url=url, timeout=httpx.Timeout(timeout_s))
        self._tokens = tokens

    def close(self) -> None:
        self._client.close()

    def post(self, probe_id: str, records: list[dict[str, Any]]) -> bool:
        """POSTs one batch, retrying transient failures. Safe to retry: records
        are idempotent on (probe_id, session, ts_ms)."""
        body = gzip.compress(json.dumps({"probe_id": probe_id, "records": records}).encode())
        headers = {"authorization": f"Bearer {self._tokens[probe_id]}", "content-type": "application/json",
                   "content-encoding": "gzip"}
        delay = 1.0
        for attempt in range(1, 8):
            try:
                resp = self._client.post("/v1/probe/results", content=body, headers=headers)
            except httpx.HTTPError as exc:
                log.warning("%s: POST failed (%s), retry %d in %.0fs", probe_id, exc, attempt, delay)
            else:
                if resp.status_code == 200:
                    out = resp.json()
                    if out.get("rejected"):
                        log.warning("%s: %d rejected: %s", probe_id, out["rejected"], out.get("errors"))
                    return True
                if resp.status_code == 401 and attempt <= 4:
                    log.info("%s: token not loaded by the server yet, retrying", probe_id)
                elif resp.status_code in (429, 500, 502, 503, 504):
                    log.warning("%s: HTTP %d, retry %d in %.0fs", probe_id, resp.status_code, attempt, delay)
                else:
                    log.error("%s: HTTP %d %s (dropping batch)", probe_id, resp.status_code, resp.text[:200])
                    return False
            time.sleep(delay)
            delay = min(delay * 2, 30)
        return False


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    ap = argparse.ArgumentParser(prog="buffmon-simulate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--tokens-file", type=Path, required=True,
                    help="server tokens file to merge simulated probe token hashes into")
    ap.add_argument("--probes", type=int, default=4, choices=range(1, len(SITES) + 1))
    ap.add_argument("--backfill-minutes", type=int, default=0)
    ap.add_argument("--duration", type=float, default=0, help="live seconds to run (0 = until interrupted)")
    ap.add_argument("--no-live", action="store_true", help="only backfill, then exit")
    ap.add_argument("--inject", action="append", default=[], help="see module docstring")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args(argv)

    try:
        injects = [parse_inject(x) for x in args.inject]
    except ValueError as exc:
        log.error("bad --inject: %s", exc)
        return 2

    fleet = build_fleet(args.probes, args.seed, injects)
    tokens: dict[str, str] = {}
    for probe_id in fleet:
        token = new_token()
        try:
            merge_into(args.tokens_file, probe_id, hash_token(token), replace=True)
        except (OSError, ValueError) as exc:
            log.error("cannot write %s: %s", args.tokens_file, exc)
            return 1
        tokens[probe_id] = token
    log.warning("DEV ONLY: simulating %d probes (%s) into %s", len(fleet), ", ".join(fleet), args.url)

    poster = Poster(args.url, tokens)
    start = time.time()
    now_s = int(start) - REPORT_DELAY_S
    try:
        if args.backfill_minutes > 0:
            first = now_s - args.backfill_minutes * 60
            log.info("backfilling %d minutes", args.backfill_minutes)
            for probe_id, sims in fleet.items():
                batch: list[dict[str, Any]] = []
                for sec in range(first, now_s):
                    for sim in sims:
                        rec = sim.bucket(sec * 1000, start)
                        if rec:
                            batch.append(rec)
                    if len(batch) >= 4000:
                        poster.post(probe_id, batch)
                        batch = []
                if batch:
                    poster.post(probe_id, batch)
        if args.no_live:
            return 0
        log.info("live mode: one bucket per probe per second (Ctrl-C to stop)")
        next_sec = now_s
        while args.duration <= 0 or time.time() - start < args.duration:
            target = int(time.time()) - REPORT_DELAY_S
            while next_sec <= target:
                for probe_id, sims in fleet.items():
                    recs = [r for r in (sim.bucket(next_sec * 1000, start) for sim in sims) if r]
                    if recs:
                        poster.post(probe_id, recs)
                next_sec += 1
            time.sleep(max(0.05, 1.0 - (time.time() % 1.0)))
    except KeyboardInterrupt:
        log.info("stopped")
    finally:
        poster.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
