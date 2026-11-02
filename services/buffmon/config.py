"""Runtime settings. Everything comes from environment variables (prefix BUFFMON_).

Secrets (ClickHouse password, UI token hash, session secret) are only ever read
from the environment or from files referenced by the environment, never from a
checked-in config file.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)

_SERVICES_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BUFFMON_", extra="ignore")

    # --- HTTP server -------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- ClickHouse --------------------------------------------------------
    clickhouse_url: str = "http://127.0.0.1:8123"
    clickhouse_user: str = "default"
    clickhouse_password: SecretStr = SecretStr("")
    clickhouse_database: str = "buffmon"
    clickhouse_timeout_s: float = Field(default=10.0, gt=0, le=120)
    clickhouse_enabled: bool = True

    # --- Insert pipeline ---------------------------------------------------
    insert_batch_max: int = Field(default=5000, ge=1, le=100_000)
    insert_flush_interval_s: float = Field(default=1.0, gt=0, le=60)
    insert_buffer_max: int = Field(default=200_000, ge=1000)
    insert_retry_max_s: float = Field(default=30.0, gt=0)

    # --- Ingest contract (docs/PROBE-RECORD.md) ----------------------------
    probe_tokens_file: Path | None = None
    probe_tokens_reload_s: float = Field(default=5.0, gt=0)
    max_body_bytes: int = 4 * 1024 * 1024
    max_records: int = 5000
    ts_skew_ms: int = 24 * 3600 * 1000
    dedup_ttl_s: float = 900.0
    dedup_max_keys: int = 2_000_000

    # --- RFC 9946 speed tests (P3.3) -------------------------------------
    # YAML policy; unset = speed tests disabled. See deploy/speedtest-policy.example.yaml.
    speedtest_policy: Path | None = None
    # Must match the probes' [jobs] poll_s (used to tell a probe is still checking in).
    speedtest_poll_s: float = Field(default=15.0, ge=5, le=3600)

    # --- Live hub ----------------------------------------------------------
    thresholds_file: Path = _SERVICES_DIR / "thresholds.yaml"
    live_retention_s: int = Field(default=900, ge=60)
    live_session_expiry_s: int = Field(default=3600, ge=60)
    no_data_after_s: float = Field(default=10.0, gt=0)
    live_push_interval_s: float = Field(default=1.0, gt=0)

    # --- Dashboard auth ----------------------------------------------------
    ui_auth: Literal["enabled", "disabled"] = "enabled"
    ui_token_sha256: str | None = None
    session_secret: SecretStr | None = None
    session_ttl_s: int = Field(default=12 * 3600, ge=300)
    cookie_secure: bool = True
    login_max_failures_per_min: int = Field(default=10, ge=1)

    @model_validator(mode="after")
    def _check_ui_auth(self) -> Self:
        if self.ui_auth == "enabled":
            if not self.ui_token_sha256 or len(self.ui_token_sha256) != 64:
                raise ValueError(
                    "BUFFMON_UI_TOKEN_SHA256 must be the 64-char sha256 hex of the UI token "
                    "(mint one with: buffmon-mint-token ui), or set BUFFMON_UI_AUTH=disabled for local dev"
                )
            if self.session_secret is None or len(self.session_secret.get_secret_value()) < 32:
                raise ValueError("BUFFMON_SESSION_SECRET must be at least 32 characters")
        return self
