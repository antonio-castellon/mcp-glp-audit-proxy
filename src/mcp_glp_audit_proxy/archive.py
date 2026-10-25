"""Archive manifest: an index of the log package, and a later check against it.

The command reads the package and writes only the requested output file.
It does not rewrite the log or the head sidecar.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .alerts import alert_path
from .anchor import assess, head_path
from .chain import VerifyReport, verify_bytes
from .runlog import append_run_log, build_run, input_record, utc_z
from .segments import verify_segments

MANIFEST_VERSION = "1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy archive-manifest")
    parser.add_argument("audit_file", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--segments", nargs="+", type=Path, default=None)
    parser.add_argument("--format", choices=("json", "md"), default="json")
    parser.add_argument("--run-log", type=Path, default=None)
    args = parser.parse_args(argv)
    started = utc_z()
    inputs = [args.audit_file, *(args.segments or [])]
    try:
        document = build_manifest(args.audit_file, segments=args.segments)
    except ArchiveError as exc:
        print(str(exc), file=sys.stderr)
        _record_archive_run(args, started, inputs, None, 1)
        return 1
    head = _head_of(_log_order(args.audit_file, args.segments)[-1])
    block = build_run(
        tool="archive-manifest",
        started_at=started,
        inputs=[input_record(path) for path in inputs if path.is_file()],
        head=head,
        arguments={"format": args.format},
        exit_code=0,
    )
    document["run"] = block
    text = render_markdown(document) if args.format == "md" else dumps(document)
    if any(ord(char) > 127 for char in text):
        print("manifest is not ASCII", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="ascii")
    if args.run_log is not None:
        append_run_log(args.run_log, block)
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


def transfer_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy archive-transfer")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--from", dest="sender", required=True)
    parser.add_argument("--to", dest="recipient", required=True)
    parser.add_argument("--by", required=True)
    parser.add_argument("--method", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    for label, value in (
        ("--from", args.sender),
        ("--to", args.recipient),
        ("--by", args.by),
        ("--method", args.method),
    ):
        if not str(value).strip():
            print(f"{label} is empty", file=sys.stderr)
            return 2
    if not args.manifest.is_file():
        print(f"missing manifest: {args.manifest}", file=sys.stderr)
        return 2
    raw = _read_only(args.manifest)
    record = {
        "at": _now(),
        "by": args.by,
        "from": args.sender,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "method": args.method,
        "to": args.recipient,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(dumps(record), encoding="ascii")
    if _read_only(args.manifest) != raw:
        print("manifest changed while writing the transfer record", file=sys.stderr)
        return 2
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


class ArchiveError(Exception):
    """The package cannot be indexed or does not match its manifest."""


def build_manifest(audit_file: Path, *, segments: list[Path] | None = None) -> dict[str, Any]:
    """Verify the package, then describe it. Raises before any output is written."""
    logs = _log_order(audit_file, segments)
    for log in logs:
        if not log.is_file():
            raise ArchiveError(f"missing log file: {log}")
        head = head_path(log)
        if not head.is_file():
            raise ArchiveError(f"missing head file: {head}")
    notes: list[str] = []
    if len(logs) > 1:
        ok, notes = verify_segments(logs)
        if not ok:
            raise ArchiveError("segment link check failed: " + "; ".join(notes))
    described: list[dict[str, Any]] = []
    reports: list[VerifyReport] = []
    for log in logs:
        data = _read_only(log)
        report = verify_bytes(data)
        head_bytes = _read_only(head_path(log))
        head = _parse_head(head_bytes, head_path(log))
        status = assess(report, head)
        if not report.ok or not status.ok:
            detail = "; ".join(report.errors or status.errors)
            raise ArchiveError(f"{log}: chain not intact ({detail})")
        reports.append(report)
        described.append(_describe(log, data, report, "log"))
        described.append(_describe(head_path(log), head_bytes, None, "head"))
    alert = alert_path(logs[-1])
    if alert.is_file():
        described.append(_describe(alert, _read_only(alert), None, "alert"))
    last = reports[-1].entries[-1] if reports and reports[-1].entries else None
    end = "audit/shutdown" if isinstance(last, dict) and last.get("method") == "audit/shutdown" else "open/unclean end"
    links = []
    for index in range(1, len(logs)):
        start = reports[index].entries[0] if reports[index].entries else {}
        arguments = start.get("arguments") if isinstance(start, dict) else None
        arguments = arguments if isinstance(arguments, dict) else {}
        links.append(
            {
                "approved_by": arguments.get("approved_by"),
                "file": logs[index].name,
                "previous_segment_final_entry_hash": arguments.get("previous_head_hash"),
                "reason": arguments.get("reason"),
                "ticket": arguments.get("ticket"),
            }
        )
    return {
        "archivist_received_at": "",
        "archivist_received_by": "",
        "created_at": _now(),
        "created_by": _user(),
        "end": end,
        "files": described,
        "manifest_version": MANIFEST_VERSION,
        "product_version": __version__,
        "segment_links": links,
        "segment_notes": notes,
    }


def verify_manifest(
    audit_file: Path,
    manifest_path: Path,
    *,
    report_out: Path | None = None,
    segments: list[Path] | None = None,
    received_by: str | None = None,
) -> int:
    """Check a copied package against its manifest. Writes nothing in the log directory."""
    errors: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    manifest_hash = ""
    try:
        raw = _read_only(manifest_path)
        manifest_hash = hashlib.sha256(raw).hexdigest()
        loaded = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append({"file": str(manifest_path), "message": f"manifest unreadable: {exc}", "seq": None})
        loaded = None
    if isinstance(loaded, dict):
        base = audit_file.parent
        listed = loaded.get("files")
        if not isinstance(listed, list):
            errors.append({"file": str(manifest_path), "message": "manifest files is not a list", "seq": None})
            listed = []
        names: set[str] = set()
        for item in listed:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                errors.append({"file": str(manifest_path), "message": "manifest file entry is invalid", "seq": None})
                continue
            name = item["name"]
            names.add(name)
            path = base / name
            _check_file(path, item, checks, errors)
        for extra in sorted(base.glob("*.jsonl")):
            if extra.name not in names:
                errors.append(
                    {
                        "file": extra.name,
                        "message": f"extra segment is not in the manifest: {extra.name}",
                        "seq": None,
                    }
                )
        if segments:
            ok, notes = verify_segments(list(segments))
            checks.append({"check": "segments", "file": "", "pass": ok})
            if not ok:
                for note in notes:
                    errors.append({"file": str(audit_file), "message": note, "seq": None})
    document = {
        "checked_at": _now(),
        "checked_by": _user(),
        "checks": checks,
        "errors": errors,
        "manifest_sha256": manifest_hash,
        "ok": not errors,
    }
    if received_by and not errors:
        document["receipt"] = {
            "manifest_sha256": manifest_hash,
            "received_at": _now(),
            "received_by": received_by,
            "result": "complete and unaltered",
        }
    if report_out is not None:
        report_out.parent.mkdir(parents=True, exist_ok=True)
        report_out.write_text(dumps(document), encoding="ascii")
    if errors:
        for error in errors:
            print(f"{error['file']}: {error['message']}", file=sys.stderr)
        return 1
    print(
        f"manifest ok files={len(checks)} manifest_sha256={manifest_hash}",
        file=sys.stderr,
    )
    return 0


def dumps(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def render_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Archive manifest",
        "",
        f"manifest_version: {document['manifest_version']}",
        f"created_at: {document['created_at']}",
        f"created_by: {document['created_by']}",
        f"product_version: {document['product_version']}",
        f"end: {document['end']}",
        f"archivist_received_by: {document['archivist_received_by']}",
        f"archivist_received_at: {document['archivist_received_at']}",
        "",
        "| name | size | sha256 | records | first_seq | last_seq | schemas |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in document["files"]:
        schemas = ",".join(item["schema_versions"])
        lines.append(
            f"| {item['name']} | {item['size']} | {item['sha256']} | {item['record_count']} | "
            f"{item['first_seq']} | {item['last_seq']} | {schemas} |"
        )
    lines.append("")
    lines.append("| file | previous_segment_final_entry_hash | reason | approved_by |")
    lines.append("| --- | --- | --- | --- |")
    for link in document["segment_links"]:
        lines.append(
            f"| {link['file']} | {link['previous_segment_final_entry_hash']} | "
            f"{link['reason']} | {link['approved_by']} |"
        )
    lines.append("")
    if document.get("run"):
        lines.extend(["## Run", "", dumps(document["run"]), ""])
    return "\n".join(lines)


def _record_archive_run(args: Any, started: str, inputs: list[Path], head: dict[str, Any] | None, code: int) -> None:
    if args.run_log is None:
        return
    block = build_run(
        tool="archive-manifest",
        started_at=started,
        inputs=[input_record(path) for path in inputs if path.is_file()],
        head=head,
        arguments={"format": args.format},
        exit_code=code,
    )
    append_run_log(args.run_log, block)


def _head_of(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    report = verify_bytes(_read_only(path))
    if not report.ok or not report.entries:
        return None
    last = report.entries[-1]
    if not last.get("entry_hash"):
        return None
    return {"entry_hash": last.get("entry_hash"), "seq": last.get("seq")}


def _log_order(audit_file: Path, segments: list[Path] | None) -> list[Path]:
    if not segments:
        return [audit_file]
    ordered = [path for path in segments]
    if audit_file.resolve() not in {path.resolve() for path in ordered}:
        ordered.append(audit_file)
    return ordered


def _read_only(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
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


def _parse_head(data: bytes, path: Path) -> Any:
    from .anchor import Head

    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"missing or unreadable head file: {path} ({exc})") from exc
    if not isinstance(parsed, dict):
        raise ArchiveError(f"head file is not an object: {path}")
    seq = parsed.get("seq")
    entry_hash = parsed.get("entry_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or not isinstance(entry_hash, str):
        raise ArchiveError(f"head file is invalid: {path}")
    return Head(seq=seq, entry_hash=entry_hash)


def _describe(path: Path, data: bytes, report: VerifyReport | None, role: str) -> dict[str, Any]:
    if report is None or not report.entries:
        first_seq = None
        last_seq = None
        first_ts = None
        last_ts = None
        count = None
        versions: list[str] = []
    else:
        first_seq = report.entries[0].get("seq")
        last_seq = report.entries[-1].get("seq")
        first_ts = report.entries[0].get("timestamp")
        last_ts = report.entries[-1].get("timestamp")
        count = len(report.entries)
        versions = sorted({str(entry.get("schema_version")) for entry in report.entries})
    return {
        "first_seq": first_seq,
        "first_timestamp": first_ts,
        "last_seq": last_seq,
        "last_timestamp": last_ts,
        "name": path.name,
        "record_count": count,
        "role": role,
        "schema_versions": versions,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def _check_file(
    path: Path,
    item: dict[str, Any],
    checks: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> None:
    name = str(item["name"])
    if not path.is_file():
        errors.append({"file": name, "message": f"missing file: {name}", "seq": item.get("first_seq")})
        checks.append({"check": "exists", "file": name, "pass": False})
        return
    try:
        data = _read_only(path)
    except OSError as exc:
        errors.append({"file": name, "message": f"unreadable file: {name} ({exc})", "seq": item.get("first_seq")})
        checks.append({"check": "exists", "file": name, "pass": False})
        return
    digest = hashlib.sha256(data).hexdigest()
    size_ok = len(data) == item.get("size")
    hash_ok = digest == item.get("sha256")
    checks.append({"check": "size", "file": name, "pass": size_ok})
    checks.append({"check": "sha256", "file": name, "pass": hash_ok})
    if not size_ok:
        errors.append({"file": name, "message": f"size mismatch for {name}", "seq": item.get("first_seq")})
    if not hash_ok:
        errors.append({"file": name, "message": f"sha256 mismatch for {name}", "seq": item.get("first_seq")})
    if item.get("role") != "log":
        return
    report = verify_bytes(data)
    count_ok = report.ok and len(report.entries) == item.get("record_count")
    first = report.entries[0].get("seq") if report.entries else None
    last = report.entries[-1].get("seq") if report.entries else None
    seq_ok = first == item.get("first_seq") and last == item.get("last_seq")
    checks.append({"check": "record_count", "file": name, "pass": count_ok})
    checks.append({"check": "seq", "file": name, "pass": seq_ok})
    if not report.ok:
        errors.append(
            {
                "file": name,
                "message": f"chain not intact: {'; '.join(report.errors)}",
                "seq": report.first_bad_seq,
            }
        )
    elif not count_ok or not seq_ok:
        errors.append(
            {
                "file": name,
                "message": f"count or seq mismatch for {name}",
                "seq": last,
            }
        )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _user() -> str:
    return getpass.getuser().encode("ascii", "replace").decode("ascii")
