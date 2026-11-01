"""``python -m buffmon`` / ``buffmon-ingest``: run the ingest service."""

from __future__ import annotations

import logging
import sys

import uvicorn
from pydantic import ValidationError

from .app import create_app
from .config import Settings

log = logging.getLogger("buffmon")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        settings = Settings()
    except ValidationError as exc:
        log.error("invalid configuration: %s", exc)
        sys.exit(2)
    logging.getLogger().setLevel(settings.log_level)
    try:
        app = create_app(settings)
    except RuntimeError as exc:
        log.error("cannot start: %s", exc)
        sys.exit(2)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        proxy_headers=False,
        server_header=False,
        ws_max_size=64 * 1024,
    )


if __name__ == "__main__":
    main()
