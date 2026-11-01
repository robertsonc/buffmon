"""``buffmon-flows``: goflow2 JSON → exporter allowlist + enrichment → ClickHouse.

Runs goflow2 as a child process (fixed argument list, no shell) and reads its
stdout, or reads goflow2 JSON from stdin when no binary is configured. A reader
thread hands lines to the event loop through a bounded queue, so a slow
ClickHouse backs up into counted drops, never into unbounded memory.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import queue
import signal
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from typing import IO, Any

from pydantic import ValidationError

from ..store import FLOWS_TABLE, PROBE_FLOWS_TABLE, HttpTransport, SampleWriter, Transport, content_token
from .config import FlowSettings
from .goflow2 import FlowParseError, GoflowRecord, parse_line
from .sites import IPAddress, SitesFile

log = logging.getLogger(__name__)

UDP = 17
_UNKNOWN_EXPORTERS_TRACKED = 100


def _ip_text(ip: IPAddress) -> str:
    return f"::ffff:{ip}" if isinstance(ip, ipaddress.IPv4Address) else str(ip)


def _ts_text(ns: int) -> str:
    ms = ns // 1_000_000
    secs, rem = divmod(ms, 1000)
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(secs)) + f".{rem:03d}"


class FlowConsumer:
    """Turns goflow2 lines into ``flows`` / ``probe_flows`` rows. No I/O."""

    def __init__(self, sites: SitesFile) -> None:
        self.sites = sites
        self.counts: Counter[str] = Counter()
        self.unknown_exporters: Counter[str] = Counter()
        self._last_parse_error: str | None = None

    def handle(self, line: bytes | str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        self.counts["lines"] += 1
        try:
            rec = parse_line(line)
        except FlowParseError as exc:
            self.counts["malformed"] += 1
            self._last_parse_error = str(exc)
            return None, None
        exp = self.sites.exporters.get(rec.exporter)
        if exp is None:
            self.counts["unknown_exporter"] += 1
            key = str(rec.exporter)
            if key in self.unknown_exporters or len(self.unknown_exporters) < _UNKNOWN_EXPORTERS_TRACKED:
                self.unknown_exporters[key] += 1
            return None, None
        in_i = exp.interfaces.get(rec.in_if)
        out_i = exp.interfaces.get(rec.out_if)
        common = {
            "ts_start": _ts_text(rec.start_ns),
            "ts_end": _ts_text(rec.end_ns),
            "exporter": _ip_text(rec.exporter),
            "site": exp.site,
            "appliance": exp.appliance,
            "src_ip": _ip_text(rec.src_ip),
            "dst_ip": _ip_text(rec.dst_ip),
            "proto": rec.proto,
            "src_port": rec.src_port,
            "dst_port": rec.dst_port,
            "dscp": rec.ip_tos >> 2,
            "bytes": rec.bytes,
            "packets": rec.packets,
            "in_if": rec.in_if,
            "out_if": rec.out_if,
            "in_if_name": in_i.name if in_i else "",
            "out_if_name": out_i.name if out_i else "",
            "in_transport": in_i.transport if in_i else "",
            "out_transport": out_i.transport if out_i else "",
        }
        flow = {
            **common,
            "received_at": _ts_text(rec.time_received_ns),
            "observation_domain_id": rec.observation_domain_id,
            "flow_type": rec.flow_type,
            "ecn": rec.ip_tos & 0x3,
            "sampling_rate": rec.sampling_rate,
        }
        self.counts["accepted"] += 1
        probe = common if self._is_probe(rec) else None
        if probe is not None:
            self.counts["probe_flows"] += 1
        return flow, probe

    def _is_probe(self, rec: GoflowRecord) -> bool:
        ports = self.sites.config.probe_ports
        return rec.proto == UDP and (rec.dst_port in ports or rec.src_port in ports)

    def take_stats(self) -> tuple[dict[str, int], dict[str, int], str | None]:
        counts, unknown, err = dict(self.counts), dict(self.unknown_exporters), self._last_parse_error
        self.counts.clear()
        self.unknown_exporters.clear()
        self._last_parse_error = None
        return counts, unknown, err


class LineReader:
    """Reads lines from a binary stream on a thread into a bounded queue."""

    def __init__(self, stream: IO[bytes], q: queue.Queue[bytes | None], on_drop: Callable[[], None]) -> None:
        self._stream, self._q, self._on_drop = stream, q, on_drop
        self.thread = threading.Thread(target=self._run, name="flow-reader", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        for line in self._stream:
            try:
                self._q.put_nowait(line)
            except queue.Full:
                self._on_drop()
        with contextlib.suppress(queue.Full):
            self._q.put(None, timeout=5)  # end of stream


def goflow2_argv(settings: FlowSettings) -> list[str]:
    """Fixed argument list for the goflow2 child (flags as in goflow2 v2.2.7)."""
    if settings.flows_goflow2_bin is None:
        raise ValueError("flows_goflow2_bin is not set")
    argv = [
        str(settings.flows_goflow2_bin),
        f"-listen={settings.flows_goflow2_listen}",
        "-format=json",
        "-transport=file",  # empty -transport.file = stdout
    ]
    if settings.flows_goflow2_mapping is not None:
        argv.append(f"-mapping={settings.flows_goflow2_mapping}")
    return argv


async def run(settings: FlowSettings, transport: Transport | None = None, stdin: IO[bytes] | None = None) -> int:
    sites = SitesFile(settings.flows_sites_file)
    log.info("sites: %d exporters, probe ports %s", len(sites.exporters), sites.config.probe_ports)
    if transport is None:
        transport = HttpTransport(
            base_url=settings.clickhouse_url,
            database=settings.clickhouse_database,
            user=settings.clickhouse_user,
            password=settings.clickhouse_password.get_secret_value(),
            timeout_s=settings.clickhouse_timeout_s,
        )
    writers = {
        table: SampleWriter(
            transport,
            batch_max=settings.flows_batch_max,
            flush_interval_s=settings.flows_flush_interval_s,
            buffer_max=settings.flows_buffer_max,
            table=table,
            token_fn=content_token,
        )
        for table in (FLOWS_TABLE, PROBE_FLOWS_TABLE)
    }
    consumer = FlowConsumer(sites)
    lines: queue.Queue[bytes | None] = queue.Queue(maxsize=settings.flows_queue_max)
    dropped = 0

    def on_drop() -> None:
        nonlocal dropped
        dropped += 1

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, stop.set)

    child: subprocess.Popen[bytes] | None = None
    if settings.flows_goflow2_bin is not None:
        argv = goflow2_argv(settings)
        log.info("starting goflow2: %s", " ".join(argv))
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stdin=subprocess.DEVNULL)  # noqa: S603 - fixed argv, no shell
        assert child.stdout is not None
        LineReader(child.stdout, lines, on_drop).start()
    else:
        LineReader(stdin or sys.stdin.buffer, lines, on_drop).start()

    writer_tasks = [asyncio.create_task(w.run(stop)) for w in writers.values()]
    last_stats = last_reload = time.monotonic()
    eof = False
    try:
        while not stop.is_set() and not eof:
            batch: list[bytes] = []
            try:
                item = await asyncio.to_thread(lines.get, True, 0.2)
                while True:
                    if item is None:
                        eof = True
                        break
                    batch.append(item)
                    if len(batch) >= 10_000:
                        break
                    item = lines.get_nowait()
            except queue.Empty:
                pass
            flows: list[dict[str, Any]] = []
            probes: list[dict[str, Any]] = []
            for line in batch:
                flow, probe = consumer.handle(line)
                if flow is not None:
                    flows.append(flow)
                if probe is not None:
                    probes.append(probe)
            writers[FLOWS_TABLE].enqueue(flows)
            writers[PROBE_FLOWS_TABLE].enqueue(probes)

            now = time.monotonic()
            if now - last_reload >= 30:
                last_reload = now
                sites.maybe_reload()
            if now - last_stats >= settings.flows_stats_interval_s:
                last_stats = now
                _log_stats(consumer, writers, dropped)
                dropped = 0
            if child is not None and child.poll() is not None:
                log.error("goflow2 exited with status %s; stopping so the service manager restarts us",
                          child.returncode)
                stop.set()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=5)
        stop.set()
        await asyncio.gather(*writer_tasks, return_exceptions=True)
        for w in writers.values():
            await w.flush_once()
        _log_stats(consumer, writers, dropped)
    return 1 if child is not None and child.returncode not in (None, 0, -signal.SIGTERM) else 0


def _log_stats(consumer: FlowConsumer, writers: dict[str, SampleWriter], dropped: int) -> None:
    counts, unknown, err = consumer.take_stats()
    log.info(
        "flows: %d lines, %d accepted, %d probe, %d malformed, %d unknown exporter, %d dropped (reader queue full); "
        "writer flows=%s probe_flows=%s",
        counts.get("lines", 0), counts.get("accepted", 0), counts.get("probe_flows", 0),
        counts.get("malformed", 0), counts.get("unknown_exporter", 0), dropped,
        {k: writers[FLOWS_TABLE].status()[k] for k in ("depth", "inserted", "dropped")},
        {k: writers[PROBE_FLOWS_TABLE].status()[k] for k in ("depth", "inserted", "dropped")},
    )
    if unknown:
        top = ", ".join(f"{ip} ({n})" for ip, n in sorted(unknown.items(), key=lambda kv: -kv[1])[:5])
        log.warning("flow records from exporters not in sites.yaml were dropped: %s", top)
    if err:
        log.warning("malformed goflow2 lines, last error: %s", err)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                        stream=sys.stderr)
    try:
        settings = FlowSettings()
    except ValidationError as exc:
        log.error("invalid configuration: %s", exc)
        sys.exit(2)
    logging.getLogger().setLevel(settings.log_level)
    # One line per ClickHouse insert would flood the journal; failures are logged by the writer.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        code = asyncio.run(run(settings))
    except (RuntimeError, ValueError, OSError) as exc:
        log.error("cannot run: %s", exc)
        sys.exit(2)
    sys.exit(code)


if __name__ == "__main__":
    main()
