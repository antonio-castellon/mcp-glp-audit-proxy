"""Hash-chained log of offline verify, export, manifest, report, and review runs.

These commands read the live audit log and never append to it. The customer
keeps this run log with the archive package. Exports made through the running
gateway (glp_export_audit) stay in the live audit trail.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .canonical import GENESIS, canonicalize, seal, sha256_hex

RUN_LOG_VERSION = "1"


def utc_z(moment: datetime | None = None) -> str:
    value = moment or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def read_only_bytes(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    return b"".join(chunks)


def input_record(path: Path) -> dict[str, str]:
    return {"name": path.name, "sha256": file_sha256(path)}


def build_run(
    *,
    tool: str,
    started_at: str,
    inputs: list[dict[str, str]],
    head: dict[str, Any] | None,
    arguments: dict[str, Any],
    exit_code: int,
) -> dict[str, Any]:
    return {
        "arguments": arguments,
        "exit_code": exit_code,
        "finished_at": utc_z(),
        "head": head,
        "host": _ascii(socket.gethostname() or "unknown"),
        "inputs": inputs,
        "os_user": _ascii(getpass.getuser() or "unknown"),
        "product_version": __version__,
        "started_at": started_at,
        "tool": tool,
    }


def append_run_log(path: Path, block: dict[str, Any]) -> None:
    """Append one sealed line. The previous line's entry_hash is the link."""
    previous = GENESIS
    if path.is_file() and path.stat().st_size:
        last = path.read_bytes().splitlines()[-1]
        loaded = json.loads(last.decode("utf-8"))
        if isinstance(loaded, dict) and isinstance(loaded.get("entry_hash"), str):
            previous = loaded["entry_hash"]
    sealed = seal({"run": block, "run_log_version": RUN_LOG_VERSION}, previous)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="ascii") as handle:
        handle.write(json.dumps(sealed, ensure_ascii=True, sort_keys=True) + "\n")


def verify_run_log(path: Path) -> tuple[bool, list[str]]:
    if not path.is_file():
        return False, [f"missing run log: {path}"]
    raw = read_only_bytes(path)
    if not raw:
        return False, ["run log is empty"]
    errors: list[str] = []
    previous = GENESIS
    lines = raw.splitlines()
    for index, line in enumerate(lines, start=1):
        if not line:
            errors.append(f"line {index} is blank")
            break
        try:
            loaded = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            errors.append(f"line {index} is not JSON: {exc}")
            break
        if not isinstance(loaded, dict):
            errors.append(f"line {index} is not an object")
            break
        digest = loaded.get("entry_hash")
        body = dict(loaded)
        body.pop("entry_hash", None)
        if sha256_hex(canonicalize(body)) != digest:
            errors.append(f"line {index} entry_hash mismatch")
            break
        if loaded.get("prev_hash") != previous:
            errors.append(f"line {index} does not link to the previous line")
            break
        if not isinstance(digest, str):
            errors.append(f"line {index} has no entry_hash")
            break
        previous = digest
    return (not errors), errors


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy verify-run-log")
    parser.add_argument("run_log", type=Path)
    args = parser.parse_args(argv)
    ok, errors = verify_run_log(args.run_log)
    if not ok:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"run log ok file={args.run_log}", file=sys.stderr)
    return 0


def attach_json(document: dict[str, Any], block: dict[str, Any]) -> dict[str, Any]:
    document["run"] = block
    return document


def dumps(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def _ascii(value: str) -> str:
    return value.encode("ascii", "backslashreplace").decode("ascii")
