"""Review-by-exception report and a flat CSV copy of the selected records.

The command reads the log and writes only --out. It does not copy bodies.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any

from .anchor import Head, assess
from .chain import verify_bytes
from .runlog import attach_json, build_run, dumps, input_record, read_only_bytes, utc_z

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSV_HEADER = (
    "seq",
    "timestamp",
    "record_class",
    "transport",
    "flow",
    "identity_id",
    "role",
    "method",
    "route_or_tool",
    "status",
    "policy_action",
    "reason",
    "body_sha256",
    "entry_hash",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy review")
    parser.add_argument("audit_file", type=Path)
    parser.add_argument("--since", default=None)
    parser.add_argument("--until", default=None)
    parser.add_argument("--format", choices=("json", "md", "csv"), default="json")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--run-log", type=Path, default=None)
    args = parser.parse_args(argv)
    started = utc_z()
    before = _snapshot(args.audit_file)
    try:
        document, code = build_review(args.audit_file, since=args.since, until=args.until)
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    head = document.pop("_head", None)
    block = build_run(
        tool="review",
        started_at=started,
        inputs=[input_record(args.audit_file)],
        head=head,
        arguments={"format": args.format, "since": args.since, "until": args.until},
        exit_code=code,
    )
    attach_json(document, block)
    text = _render(document, args.format)
    if any(ord(char) > 127 for char in text):
        print("review output is not ASCII", file=sys.stderr)
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="ascii")
    if args.run_log is not None:
        from .runlog import append_run_log

        append_run_log(args.run_log, block)
    after = _snapshot(args.audit_file)
    if before != after:
        print("review changed an input file", file=sys.stderr)
        return 2
    print(f"wrote {args.out}", file=sys.stderr)
    return code


def build_review(
    audit_file: Path,
    *,
    since: str | None = None,
    until: str | None = None,
) -> tuple[dict[str, Any], int]:
    data = read_only_bytes(audit_file)
    report = verify_bytes(data)
    if report.ok:
        status = assess(report, _read_head(audit_file))
        if not status.ok:
            report.ok = False
            report.errors.extend(status.errors)
            report.kind = report.kind or "head_mismatch"
            if report.first_bad_line is None:
                report.first_bad_line = len(report.entries) or None
    selected = [entry for entry in report.entries if _in_period(entry, since, until)]
    denied = []
    failures = []
    writes = []
    approvals = []
    consumed = []
    changes = []
    clocks = []
    segments = []
    previous_stamp: str | None = None
    for entry in report.entries:
        stamp = str(entry.get("timestamp") or "")
        if previous_stamp and stamp and stamp < previous_stamp and _in_period(entry, since, until):
            clocks.append(_item(entry, note="timestamp earlier than the previous record"))
        previous_stamp = stamp or previous_stamp
        if not _in_period(entry, since, until):
            continue
        if _clock_not_ok(entry):
            clocks.append(_item(entry, note="startup clock status is not ok"))
        if entry.get("method") == "audit/segment_start":
            segments.append(_item(entry))
        arguments = entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {}
        changed = arguments.get("config_changed")
        if entry.get("method") == "audit/startup" and isinstance(changed, list) and changed:
            item = _item(entry)
            item["config_changed"] = changed
            changes.append(item)
        if _is_approval(entry):
            approvals.append(_item(entry))
        if isinstance(entry.get("approval"), dict):
            consumed.append(_item(entry))
        if _is_auth_failure(entry):
            failures.append(_item(entry))
            continue
        if _is_policy_deny(entry):
            denied.append(_item(entry))
        if _write_without_reason(entry):
            writes.append(_item(entry))
    counts: dict[tuple[str, str], int] = {}
    for item in failures:
        key = (str(item.get("address") or ""), str(item.get("identity") or ""))
        counts[key] = counts.get(key, 0) + 1
    header = "chain integrity ok"
    if not report.ok:
        header = f"chain integrity FAILED at line {report.first_bad_line}"
    last = report.entries[-1] if report.entries else None
    head = None
    if report.ok and isinstance(last, dict) and last.get("entry_hash"):
        head = {"entry_hash": last.get("entry_hash"), "seq": last.get("seq")}
    document = {
        "_head": head,
        "alerts": _alerts(audit_file),
        "approvals": approvals,
        "authentication_failures": {
            "counts": [
                {"address": address, "count": count, "identity": identity}
                for (address, identity), count in sorted(counts.items())
            ],
            "items": failures,
        },
        "clock_anomalies": clocks,
        "configuration_changes": changes,
        "consumed_approvals": consumed,
        "denied": denied,
        "gaps": list(report.gaps),
        "header": header,
        "record_count": len(selected),
        "records": [_csv_row(entry) for entry in selected],
        "segment_boundaries": segments,
        "writes_without_reason": writes,
    }
    return document, (0 if report.ok else 1)


def _render(document: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        public = {key: value for key, value in document.items() if key != "records"}
        return dumps(public)
    if fmt == "csv":
        return _csv(document)
    return _markdown(document)


def _csv(document: dict[str, Any]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_HEADER)
    for row in document["records"]:
        writer.writerow(row)
    body = buffer.getvalue()
    return body + "\n# run\n" + dumps(document["run"])


def _markdown(document: dict[str, Any]) -> str:
    lines = ["# Audit review", "", document["header"], ""]
    sections = (
        ("Denied calls", document["denied"]),
        ("Authentication failures", document["authentication_failures"]["items"]),
        ("Writes without a reason", document["writes_without_reason"]),
        ("Approvals", document["approvals"]),
        ("Consumed approvals", document["consumed_approvals"]),
        ("Configuration changes", document["configuration_changes"]),
        ("Clock anomalies", document["clock_anomalies"]),
        ("Segment boundaries", document["segment_boundaries"]),
    )
    for title, items in sections:
        lines.append(f"## {title}")
        lines.append("")
        if not items:
            lines.append("None.")
        for item in items:
            lines.append(
                f"- seq {item.get('seq')} {item.get('timestamp')} {item.get('identity')} "
                f"{item.get('method')} {item.get('route')} {item.get('status')} {item.get('reason')}"
            )
        lines.append("")
    lines.append("## Gaps")
    lines.append("")
    if document["gaps"]:
        for gap in document["gaps"]:
            lines.append(f"- {gap}")
    else:
        lines.append("None.")
    lines.append("")
    lines.append("## Alert files")
    lines.append("")
    if document["alerts"]:
        for alert in document["alerts"]:
            lines.append(f"- {alert.get('name')} {alert.get('severity')} {alert.get('kind')}")
    else:
        lines.append("None.")
    lines.append("")
    lines.extend(["## Run", "", dumps(document["run"])])
    return "\n".join(lines)


def _csv_row(entry: dict[str, Any]) -> list[Any]:
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    principal = entry.get("principal") if isinstance(entry.get("principal"), dict) else {}
    decision = entry.get("policy_decision") if isinstance(entry.get("policy_decision"), dict) else {}
    body_hash = http.get("body_sha256") or entry.get("arguments_sha256") or ""
    return [
        entry.get("seq"),
        entry.get("timestamp") or "",
        entry.get("record_class") or "",
        entry.get("transport") or "",
        entry.get("flow") or "",
        principal.get("id") or "",
        principal.get("role") or "",
        http.get("method") or entry.get("method") or "",
        http.get("route") or entry.get("tool") or "",
        entry.get("status") or "",
        decision.get("action") or "",
        entry.get("reason") or "",
        body_hash or "",
        entry.get("entry_hash") or "",
    ]


def _item(entry: dict[str, Any], note: str | None = None) -> dict[str, Any]:
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    principal = entry.get("principal") if isinstance(entry.get("principal"), dict) else {}
    arguments = entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {}
    reason = entry.get("reason") or ""
    if not reason and isinstance(entry.get("error"), dict):
        reason = str(entry["error"].get("message") or "")
    if note:
        reason = note
    return {
        "address": arguments.get("client_address") or "",
        "identity": principal.get("id") or "",
        "method": http.get("method") or entry.get("method") or "",
        "reason": str(reason)[:120],
        "route": http.get("route") or entry.get("tool") or "",
        "seq": entry.get("seq"),
        "status": http.get("status") if http.get("status") is not None else entry.get("status"),
        "timestamp": entry.get("timestamp"),
    }


def _is_auth_failure(entry: dict[str, Any]) -> bool:
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    if http.get("status") == 401:
        return True
    rule = _rule(entry)
    return rule.startswith("identity:")


def _is_policy_deny(entry: dict[str, Any]) -> bool:
    decision = entry.get("policy_decision") if isinstance(entry.get("policy_decision"), dict) else {}
    return decision.get("action") == "deny" and not _is_auth_failure(entry)


def _write_without_reason(entry: dict[str, Any]) -> bool:
    if entry.get("reason"):
        return False
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    method = str(http.get("method") or entry.get("method") or "")
    if method in _WRITE_METHODS or _rule(entry) == "write:reason-missing":
        return True
    return False


def _is_approval(entry: dict[str, Any]) -> bool:
    return entry.get("method") == "glp_approve" or entry.get("tool") == "glp_approve"


def _clock_not_ok(entry: dict[str, Any]) -> bool:
    if entry.get("method") != "audit/startup":
        return False
    arguments = entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {}
    clock = arguments.get("clock")
    if not isinstance(clock, dict):
        return False
    return clock.get("ntp_synchronized") is not True


def _rule(entry: dict[str, Any]) -> str:
    decision = entry.get("policy_decision") if isinstance(entry.get("policy_decision"), dict) else {}
    return str(decision.get("rule") or "")


def _in_period(entry: dict[str, Any], since: str | None, until: str | None) -> bool:
    stamp = str(entry.get("timestamp") or "")
    if since and stamp < since:
        return False
    if until and stamp > until:
        return False
    return True


def _alerts(audit_file: Path) -> list[dict[str, Any]]:
    found = []
    for path in sorted(audit_file.parent.glob(audit_file.name + "*.json")):
        if not path.name.endswith(".alert.json") and not path.name.endswith(".warning.json"):
            continue
        item: dict[str, Any] = {"name": path.name}
        try:
            loaded = json.loads(read_only_bytes(path).decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            loaded = None
        if isinstance(loaded, dict):
            item["kind"] = loaded.get("kind")
            item["severity"] = loaded.get("severity") or "critical"
        found.append(item)
    return found


def _read_head(audit_file: Path) -> Head | None:
    path = audit_file.with_name(audit_file.name + ".head")
    if not path.is_file():
        return None
    try:
        parsed = json.loads(read_only_bytes(path).decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    seq = parsed.get("seq")
    digest = parsed.get("entry_hash")
    if isinstance(seq, bool) or not isinstance(seq, int) or not isinstance(digest, str):
        return None
    return Head(seq=seq, entry_hash=digest)


def _snapshot(path: Path) -> dict[str, tuple[int, bytes]]:
    found = {}
    for item in (path, path.with_name(path.name + ".head")):
        if item.is_file():
            stat = item.stat()
            found[item.name] = (stat.st_mtime_ns, item.read_bytes())
    return found
