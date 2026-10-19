"""Verify the hash chain and optionally write a searchable JSON export.

Exit status is 0 when the chain is intact and 1 when it is not.
A broken chain is not exported.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .anchor import verify_anchored
from .records import format_timestamp, utc_now
from .reporters.json_export import dumps_document, export_document, filter_entries
from .reporters.text_export import format_entry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy-verify")
    parser.add_argument("audit_file", type=Path)
    parser.add_argument("--json-export", type=Path, default=None)
    parser.add_argument("--record-class", default=None)
    parser.add_argument("--tool", default=None)
    parser.add_argument("--status", default=None)
    parser.add_argument("--principal", default=None)
    parser.add_argument("--method", default=None)
    parser.add_argument("--server", default=None)
    parser.add_argument("--since", default=None)
    parser.add_argument("--until", default=None)
    parser.add_argument(
        "--print-head",
        action="store_true",
        help="Print seq and entry_hash of the log tip. Copy that line outside this machine.",
    )
    args = parser.parse_args(argv)

    report = verify_anchored(args.audit_file)
    filters = {
        "method": args.method,
        "principal_id": args.principal,
        "record_class": args.record_class,
        "server": args.server,
        "since": args.since,
        "status": args.status,
        "tool": args.tool,
        "until": args.until,
    }
    # Integrity is always the full file. Filters only affect what is printed.
    selected = filter_entries(report.entries, **filters) if report.ok else []
    if report.ok:
        for entry in selected:
            print(format_entry(entry))
        seq = report.entries[-1]["seq"] if report.entries else 0
        if report.anchor_lag:
            print(
                "head lags by 1 verified record; startup will advance it",
                file=sys.stderr,
            )
        print(
            f"chain ok entries={report.count} shown={len(selected)} head={report.head_hash} seq={seq}",
            file=sys.stderr,
        )
        if args.print_head:
            tip = report.head_hash
            print(f"seq={seq} entry_hash={tip}")
    else:
        print("chain invalid", file=sys.stderr)
        for error in report.errors:
            print(error, file=sys.stderr)
        return 1

    if args.json_export is not None:
        document = export_document(
            selected,
            full_chain=report.entries,
            chain_valid=True,
            filters=filters,
            exported_at=format_timestamp(utc_now()),
        )
        args.json_export.parent.mkdir(parents=True, exist_ok=True)
        args.json_export.write_text(dumps_document(document), encoding="utf-8")
        print(f"wrote {args.json_export}", file=sys.stderr)
    return 0
