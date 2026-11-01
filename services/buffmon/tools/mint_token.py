"""Mint credentials.

    buffmon-mint-token probe --probe-id sjc-br01-p1 [--tokens-file /etc/buffmon/probe-tokens.json]
    buffmon-mint-token ui

``probe`` prints the bearer token once (give it to the probe via systemd
LoadCredential or an env var) and the JSON entry for the server's tokens file.
With --tokens-file the entry is merged into that file atomically (mode 0600).

``ui`` prints a dashboard login token plus the two environment variables the
server needs (the sha256 of that token and a session-signing secret).

Secrets go to stdout exactly once; nothing is logged.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

from buffmon.auth import TOKEN_PREFIX, hash_token

log = logging.getLogger("buffmon.mint")
_PROBE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def new_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def merge_into(path: Path, probe_id: str, digest: str, replace: bool) -> None:
    current: dict[str, str] = {}
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"{path} must contain a JSON object")
        current = {str(k): str(v) for k, v in loaded.items()}
    if probe_id in current and not replace:
        raise ValueError(f"{probe_id} already has a token in {path}; pass --replace to rotate it")
    current[probe_id] = digest
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tokens.", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2, sort_keys=True)
            f.write("\n")
        Path(tmp).replace(path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    parser = argparse.ArgumentParser(prog="buffmon-mint-token", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe", help="mint a probe ingest token")
    p.add_argument("--probe-id", required=True)
    p.add_argument("--tokens-file", type=Path, help="merge the hash into this server tokens file")
    p.add_argument("--replace", action="store_true", help="rotate an existing probe's token")
    sub.add_parser("ui", help="mint a dashboard login token and session secret")
    args = parser.parse_args(argv)

    if args.cmd == "probe":
        if not _PROBE_ID.match(args.probe_id):
            log.error("probe-id must match [A-Za-z0-9._-]{1,64}")
            return 2
        token = new_token()
        digest = hash_token(token)
        if args.tokens_file:
            try:
                merge_into(args.tokens_file, args.probe_id, digest, args.replace)
            except (OSError, ValueError) as exc:
                log.error("cannot update %s: %s", args.tokens_file, exc)
                return 1
            log.info("added %s to %s", args.probe_id, args.tokens_file)
        print(f"probe token (shown once, give it to the probe): {token}")
        print(f"tokens-file entry: {json.dumps({args.probe_id: digest})}")
        return 0

    token = new_token()
    print(f"dashboard login token (shown once): {token}")
    print(f"BUFFMON_UI_TOKEN_SHA256={hash_token(token)}")
    print(f"BUFFMON_SESSION_SECRET={secrets.token_urlsafe(48)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
