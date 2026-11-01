"""Settings for ``buffmon-flows`` (environment, prefix ``BUFFMON_``).

Kept separate from the ingest service's settings: the flow consumer runs as its
own process and needs no dashboard credentials.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class FlowSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BUFFMON_", extra="ignore")

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    clickhouse_url: str = "http://127.0.0.1:8123"
    clickhouse_user: str = "default"
    clickhouse_password: SecretStr = SecretStr("")
    clickhouse_database: str = "buffmon"
    clickhouse_timeout_s: float = Field(default=10.0, gt=0, le=120)

    # Exporter allowlist + site/interface map.
    flows_sites_file: Path = Path("/etc/buffmon/sites.yaml")
    # goflow2 binary and arguments. buffmon-flows runs it as a child process and
    # reads its stdout; with no binary set, it reads goflow2 JSON from stdin.
    flows_goflow2_bin: Path | None = None
    flows_goflow2_listen: str = "netflow://0.0.0.0:2055"
    flows_goflow2_mapping: Path | None = None

    flows_batch_max: int = Field(default=10_000, ge=1, le=200_000)
    flows_flush_interval_s: float = Field(default=1.0, gt=0, le=60)
    flows_buffer_max: int = Field(default=500_000, ge=1000)
    # Lines read but not yet parsed; beyond this the reader drops (and counts).
    flows_queue_max: int = Field(default=200_000, ge=1000)
    flows_stats_interval_s: float = Field(default=60.0, gt=0)
