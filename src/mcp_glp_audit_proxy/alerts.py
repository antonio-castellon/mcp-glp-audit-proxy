"""Critical alert when the audit chain is no longer intact.

The alert names where and when the anomaly was detected. It does not copy
record bodies, tokens, or other payload fields.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .anchor import read_head
from .chain import VerifyReport
from .permissions import tighten_path

_LOG = logging.getLogger("mcp_glp_audit_proxy.alert")


def alert_path(log: Path) -> Path:
    return log.with_name(log.name + ".alert.json")


def write_critical_alert(
    log: Path,
    report: VerifyReport,
    *,
    command: tuple[str, ...] = (),
) -> Path:
    """Write ``<log>.alert.json`` and emit one CRITICAL line. Optional argv hook."""
    head = _head_values(log)
    detected = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    payload = {
        "detected_at": detected,
        "first_bad_line": report.first_bad_line,
        "first_bad_seq": report.first_bad_seq,
        "first_bad_timestamp": report.first_bad_timestamp,
        "head": head,
        "host": socket.gethostname(),
        "kind": report.kind,
        "last_good_seq": report.last_good_seq,
        "last_good_timestamp": report.last_good_timestamp,
        "log_path": str(log),
        "version": __version__,
    }
    path = alert_path(log)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    tighten_path(path)
    if os.name == "nt":
        from .channels.winacl import protect_owner_file

        protect_owner_file(path)
    _LOG.critical(
        "audit chain integrity failure kind=%s line=%s seq=%s last_good_seq=%s last_good_timestamp=%s",
        report.kind,
        report.first_bad_line,
        report.first_bad_seq,
        report.last_good_seq,
        report.last_good_timestamp,
    )
    if command:
        subprocess.run([*command, str(path)], shell=False, check=False)  # noqa: S603
    return path


def _head_values(log: Path) -> dict[str, Any] | None:
    try:
        head = read_head(log)
    except Exception:
        return None
    if head is None:
        return None
    return {"entry_hash": head.entry_hash, "seq": head.seq}
