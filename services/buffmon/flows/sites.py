"""Exporter → site / appliance / interface map (``sites.yaml``).

It is also the exporter allowlist: flow records from an exporter that is not
listed are counted and dropped, because anyone who can reach the collector's
UDP port can otherwise inject flows (and fake probe paths).
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

log = logging.getLogger(__name__)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class InterfaceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(default="", max_length=64)
    # Customer's label for the underlay this interface carries, e.g. INET / MPLS / LTE.
    transport: str = Field(default="", max_length=32)


class ExporterInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    site: str = Field(min_length=1, max_length=64)
    appliance: str = Field(min_length=1, max_length=64)
    # Keyed by the ifIndex the exporter puts in ingressInterface / egressInterface.
    interfaces: dict[int, InterfaceInfo] = {}


class SitesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    # UDP ports that identify probe traffic (STAMP reflectors). Flows to or from
    # these ports are also written to probe_flows for path validation.
    probe_ports: list[int] = [862]
    exporters: dict[str, ExporterInfo]

    @field_validator("probe_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if not v or any(not 1 <= p <= 65535 for p in v):
            raise ValueError("probe_ports must be a non-empty list of 1-65535")
        return v

    @model_validator(mode="after")
    def _exporter_keys_are_ips(self) -> Self:
        seen: set[IPAddress] = set()
        for key in self.exporters:
            try:
                ip = ipaddress.ip_address(key)
            except ValueError as exc:
                raise ValueError(f"exporter key {key!r} is not an IP address") from exc
            if ip in seen:
                raise ValueError(f"exporter {key!r} is listed twice")
            seen.add(ip)
        return self

    def by_ip(self) -> dict[IPAddress, ExporterInfo]:
        return {ipaddress.ip_address(k): v for k, v in self.exporters.items()}


def load_sites(path: Path) -> SitesConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"cannot read sites file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuntimeError(f"sites file {path} is not valid YAML: {exc}") from exc
    return SitesConfig.model_validate(raw)


class SitesFile:
    """``sites.yaml`` with hot reload; an invalid edit is logged and ignored."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.config = load_sites(path)
        self.exporters = self.config.by_ip()
        self._mtime_ns = path.stat().st_mtime_ns

    def maybe_reload(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError as exc:
            log.warning("sites file %s unreadable, keeping current map: %s", self.path, exc)
            return False
        if mtime == self._mtime_ns:
            return False
        self._mtime_ns = mtime
        try:
            cfg = load_sites(self.path)
        except (RuntimeError, ValueError) as exc:
            log.error("sites file %s rejected, keeping current map: %s", self.path, exc)
            return False
        self.config, self.exporters = cfg, cfg.by_ip()
        log.info("reloaded sites from %s (%d exporters)", self.path, len(self.exporters))
        return True
