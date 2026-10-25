"""Close an audit segment and check the links between segment files.

Erasure is not done inside a live chain. The customer archives the old file
and starts a new one whose first record names the previous head, or records
that the previous chain is broken.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .anchor import verify_anchored
from .canonical import GENESIS
from .config import Settings
from .errors import ConfigurationError
from .records import build_event
from .storage.jsonl import JsonlAuditStore


def close_segment(
    settings: Settings,
    *,
    reason: str,
    ticket: str,
    approved_by: str,
    previous: Path | None = None,
    output: Path | None = None,
) -> Path:
    """Write a new log whose first record is ``audit/segment_start``. Offline.

    Closing a segment for erasure or disposal needs test-facility management
    approval, and sponsor approval when the customer SOP says so. This command
    records the reason and the approver. It does not delete the old file.
    """
    if not reason.strip() or not ticket.strip() or not approved_by.strip():
        raise ConfigurationError("segment close requires a reason, a ticket, and an approver")
    source = previous or settings.audit_path
    destination = output or source.with_name(source.name + ".next.jsonl")
    if destination.exists() and destination.stat().st_size > 0:
        raise ConfigurationError(f"segment output already exists: {destination}")
    report = verify_anchored(source) if source.exists() else None
    if report is not None and report.ok and report.entries:
        previous_hash: Any = report.head_hash
        previous_seq: Any = report.entries[-1].get("seq")
        verify_report = None
    elif report is not None and report.ok:
        previous_hash = GENESIS
        previous_seq = 0
        verify_report = None
    else:
        previous_hash = "broken"
        previous_seq = None if report is None else report.last_good_seq
        verify_report = None if report is None else {
            "errors": list(report.errors),
            "first_bad_line": report.first_bad_line,
            "first_bad_seq": report.first_bad_seq,
            "first_bad_timestamp": report.first_bad_timestamp,
            "kind": report.kind,
            "last_good_seq": report.last_good_seq,
            "last_good_timestamp": report.last_good_timestamp,
        }
    arguments: dict[str, Any] = {
        "operator": settings.principal.id,
        "previous_head_hash": previous_hash,
        "previous_last_seq": previous_seq,
        "previous_path": str(source),
        "approved_by": approved_by,
        "reason": reason,
        "ticket": ticket,
    }
    if verify_report is not None:
        arguments["verify_report"] = verify_report
    store = JsonlAuditStore(destination, checkpoint_every=0)
    store.append_event(
        build_event(
            method="audit/segment_start",
            record_class="config",
            status="ok",
            server="proxy",
            principal=settings.principal.as_dict(),
            client={"id": "segment", "name": "segment", "version": None, "model_id": None},
            protocol_version=None,
            session_id=None,
            tool=None,
            arguments=arguments,
            result={"segment": "started"},
            reason=reason,
        )
    )
    return destination


def verify_segments(paths: list[Path]) -> tuple[bool, list[str]]:
    """Check each file and whether each segment_start names the previous head.

    A previous file whose chain is broken is reported. The link is accepted
    when the new segment records previous_head_hash as ``broken``.
    """
    notes: list[str] = []
    ok = True
    reports = []
    for path in paths:
        report = verify_anchored(path)
        reports.append(report)
        if report.ok:
            notes.append(f"{path}: chain ok entries={report.count} head={report.head_hash}")
        else:
            ok = False
            notes.append(f"{path}: chain broken kind={report.kind}")
            notes.extend(f"{path}: {error}" for error in report.errors)
    for index in range(1, len(paths)):
        current = reports[index]
        previous = reports[index - 1]
        start = current.entries[0] if current.entries else None
        if not isinstance(start, dict) or start.get("method") != "audit/segment_start":
            ok = False
            notes.append(f"{paths[index]}: first record is not audit/segment_start")
            continue
        linked = (start.get("arguments") or {}).get("previous_head_hash")
        if previous.ok:
            if linked != previous.head_hash:
                ok = False
                notes.append(
                    f"{paths[index]}: segment link {linked} does not match previous head {previous.head_hash}"
                )
            else:
                notes.append(f"{paths[index]}: segment link matches previous head")
        else:
            notes.append(
                f"{paths[index - 1]}: previous segment is broken ({previous.kind}); "
                f"link records {linked}"
            )
            if linked != "broken":
                ok = False
                notes.append(f"{paths[index]}: broken previous segment was not recorded as broken")
    return ok, notes
