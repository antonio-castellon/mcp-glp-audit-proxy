"""Sidecar head for the JSONL log.

``<log>.head`` stores the latest ``seq`` and ``entry_hash`` after each fsynced
line. It is written to a temp file in the same directory, fsynced, then
renamed into place.

A crash between the log fsync and this rename may leave the head one record
behind. That lag is accepted when the extra record itself verifies. The next
append, and startup, advance the head. Any other disagreement (missing head,
shorter log, hash mismatch, lag of more than one) is a store error.

Someone who can edit both files can move them together. A copy of the head
kept outside this machine (ticket, email, LIMS) is the local control. Signed
checkpoints and WORM storage are Pro.
"""

from __future__ import annotations

import errno
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from .canonical import canonicalize
from .chain import VerifyReport, verify_file
from .errors import AuditStoreError
from .permissions import ensure_private_dir, open_flags, open_private, tighten_fd

_LOG = logging.getLogger("mcp_glp_audit_proxy.technical")


@dataclass
class Head:
    seq: int
    entry_hash: str


@dataclass
class AnchorStatus:
    ok: bool
    errors: list[str]
    lag: int


def head_path(log: Path) -> Path:
    return log.with_name(log.name + ".head")


def read_head(log: Path) -> Head | None:
    path = head_path(log)
    if not path.exists():
        return None
    try:
        raw = _read_private(path)
        parsed = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditStoreError(f"audit head unreadable: {exc}") from exc
    if not isinstance(parsed, dict):
        raise AuditStoreError("audit head is not an object")
    seq = parsed.get("seq")
    entry_hash = parsed.get("entry_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise AuditStoreError("audit head seq is invalid")
    if not isinstance(entry_hash, str) or len(entry_hash) != 64:
        raise AuditStoreError("audit head entry_hash is invalid")
    return Head(seq=seq, entry_hash=entry_hash)


def write_head(log: Path, seq: int, entry_hash: str) -> None:
    """Atomic replace. Raises OSError if the head cannot be made durable."""
    target = head_path(log)
    temporary = target.with_name(target.name + ".tmp")
    payload = canonicalize({"entry_hash": entry_hash, "seq": seq}) + b"\n"
    ensure_private_dir(target.parent)
    fd = os.open(temporary, open_flags(os.O_WRONLY | os.O_CREAT | os.O_TRUNC), 0o600)
    try:
        if os.name == "nt":
            tighten_fd(fd, str(temporary), warn=True)
        else:
            os.fchmod(fd, 0o600)
        view = payload
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write on audit head")
            view = view[written:]
        os.fsync(fd)
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    os.close(fd)
    os.replace(temporary, target)
    _sync_directory(target.parent)


def _sync_directory(path: Path) -> None:
    """Fsync the directory after the rename. Windows often cannot open it."""
    try:
        directory = os.open(path, os.O_RDONLY)
    except OSError as exc:
        if os.name != "nt":
            raise
        _LOG.warning("could not open %s to fsync the audit head: %s", path, exc)
        return
    try:
        try:
            os.fsync(directory)
        except OSError as exc:
            if os.name != "nt":
                raise
            _LOG.warning("could not fsync %s: %s", path, exc)
    finally:
        os.close(directory)


def assess(report: VerifyReport, head: Head | None) -> AnchorStatus:
    """Compare a verified log with its sidecar. The log must already be intact."""
    if not report.ok:
        return AnchorStatus(False, list(report.errors), 0)
    entries = report.entries
    if not entries:
        if head is None:
            return AnchorStatus(True, [], 0)
        return AnchorStatus(False, ["audit head present but log is empty"], 0)
    if head is None:
        return AnchorStatus(False, ["audit head missing for a non-empty log"], 0)
    last = entries[-1]
    if head.seq == last.get("seq") and head.entry_hash == last.get("entry_hash"):
        return AnchorStatus(True, [], 0)
    if len(entries) >= 2:
        previous = entries[-2]
        if head.seq == previous.get("seq") and head.entry_hash == previous.get("entry_hash"):
            return AnchorStatus(True, [], 1)
    return AnchorStatus(
        False,
        [f"audit head disagrees with log: head seq={head.seq} log seq={last.get('seq')}"],
        0,
    )


def verify_anchored(path: Path) -> VerifyReport:
    """Chain verify plus the sidecar. A one-record lag stays ok."""
    report = verify_file(path)
    if not report.ok:
        return report
    try:
        head = read_head(path)
    except AuditStoreError as exc:
        return _failed(report, [str(exc)], "head_mismatch")
    status = assess(report, head)
    if not status.ok:
        kind = "head_missing" if any("missing" in error for error in status.errors) else "head_mismatch"
        return _failed(report, status.errors, kind)
    report.anchor_lag = status.lag
    return report


def _read_private(path: Path) -> str:
    fd = open_private(path, os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8")


def _failed(report: VerifyReport, errors: list[str], kind: str) -> VerifyReport:
    failed = VerifyReport(
        ok=False,
        entries=report.entries,
        errors=errors,
        head_hash=report.head_hash,
        anchor_lag=0,
        first_bad_line=report.first_bad_line if report.first_bad_line is not None else len(report.entries) or None,
        first_bad_seq=report.first_bad_seq if report.first_bad_seq is not None else (
            report.entries[-1].get("seq") if report.entries else None
        ),
        last_good_seq=report.last_good_seq if report.last_good_seq is not None else (
            report.entries[-1].get("seq") if report.ok and report.entries else report.last_good_seq
        ),
        last_good_timestamp=report.last_good_timestamp if report.last_good_timestamp is not None else (
            report.entries[-1].get("timestamp") if report.ok and report.entries else report.last_good_timestamp
        ),
        first_bad_timestamp=report.first_bad_timestamp,
        kind=report.kind or kind,
        gaps=list(report.gaps),
    )
    if report.ok and failed.last_good_seq is None and report.entries:
        failed.last_good_seq = report.entries[-1].get("seq")
        failed.last_good_timestamp = report.entries[-1].get("timestamp")
    return failed
