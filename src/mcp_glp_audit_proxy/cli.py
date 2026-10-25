"""Verify the hash chain and optionally write a searchable JSON export.

Exit status is 0 when the chain is intact and 1 when it is not.
A broken chain is not exported.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from .anchor import verify_anchored
from .segments import verify_segments
from .checkpoints import check_log
from .features import FeatureSet
from .records import format_timestamp, utc_now
from .reporters.json_export import dumps_document, export_document, filter_entries
from .reporters.text_export import format_entry


_HEAD_LINE = re.compile(r"seq=(\d+) entry_hash=([0-9a-f]{64})")
_HEAD_PAIR = re.compile(r"(\d+):([0-9a-f]{64})")


def _parse_head(text: str) -> tuple[int, str]:
    stripped = text.strip()
    matched = _HEAD_PAIR.fullmatch(stripped) or _HEAD_LINE.fullmatch(stripped)
    if matched is None:
        raise ValueError("expected head must be <seq>:<64 lowercase hex> or a --print-head line")
    return int(matched.group(1)), matched.group(2)


def _expected_head(inline: tuple[int, str] | None, path: Path | None) -> tuple[int, str] | None:
    if inline is None and path is None:
        return None
    from_file: tuple[int, str] | None = None
    if path is not None:
        if not path.is_file():
            raise ValueError(f"expected head file is missing: {path}")
        try:
            from_file = _parse_head(path.read_text(encoding="utf-8"))
        except UnicodeError as exc:
            raise ValueError("expected head file is not utf-8") from exc
    if inline is not None and from_file is not None and inline != from_file:
        raise ValueError("expected head values do not match")
    return inline if inline is not None else from_file


def _features_for_pubkey(licence: Path | None, client_id: str | None) -> FeatureSet | None:
    """Load a licence only when a path was given. Otherwise the caller passes None."""
    path = licence
    if path is None:
        env_path = os.environ.get("GLP_LICENCE_PATH", "").strip()
        path = Path(env_path) if env_path else None
    if path is None:
        return None
    chosen = (client_id or "").strip() or os.environ.get("GLP_CLIENT_ID", "").strip() or None
    return FeatureSet.load(path, client_id=chosen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy-verify")
    parser.add_argument("audit_file", nargs="?", type=Path)
    parser.add_argument(
        "--segments",
        nargs="+",
        type=Path,
        default=None,
        help="Check these log files in order, including each audit/segment_start link.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=None,
        help="Check this archive manifest against the log directory. Read-only.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=None,
        help="Write the dated manifest check report here. Requires --manifest.",
    )
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
    parser.add_argument(
        "--expect-head",
        default=None,
        help="Fail when the chain tip is not <seq>:<64 lowercase hex>.",
    )
    parser.add_argument(
        "--expect-head-file",
        type=Path,
        default=None,
        help="File with <seq>:<hash> or one --print-head line. The chain tip must match.",
    )
    parser.add_argument(
        "--pubkey",
        type=Path,
        default=None,
        help="Pinned public key file, passed to the licensed signer plugin.",
    )
    parser.add_argument(
        "--licence",
        type=Path,
        default=None,
        help="Licence file. Used only with --pubkey. GLP_LICENCE_PATH is the fallback.",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="Customer id for the licence fingerprint. GLP_CLIENT_ID is the fallback.",
    )
    args = parser.parse_args(argv)
    if args.report_out is not None and args.manifest is None:
        print("--report-out requires --manifest", file=sys.stderr)
        return 2
    if args.manifest is not None:
        if args.audit_file is None:
            print("an audit file is required with --manifest", file=sys.stderr)
            return 2
        from .archive import verify_manifest

        return verify_manifest(
            args.audit_file,
            args.manifest,
            report_out=args.report_out,
            segments=list(args.segments) if args.segments else None,
        )
    if args.segments:
        ok, notes = verify_segments(list(args.segments))
        for note in notes:
            print(note, file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1
    if args.audit_file is None:
        print("an audit file or --segments is required", file=sys.stderr)
        return 2
    try:
        inline = _parse_head(args.expect_head) if args.expect_head is not None else None
        expected = _expected_head(inline, args.expect_head_file)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    public_key: bytes | None = None
    if args.pubkey is not None:
        if not args.pubkey.is_file():
            print(f"public key file is missing: {args.pubkey}", file=sys.stderr)
            return 2
        try:
            public_key = args.pubkey.read_bytes()
        except OSError as exc:
            print(f"public key file is unreadable: {exc}", file=sys.stderr)
            return 2
        if not public_key:
            print("public key file is empty", file=sys.stderr)
            return 2

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
    if not report.ok:
        print("chain invalid", file=sys.stderr)
        for error in report.errors:
            print(error, file=sys.stderr)
        return 1

    seq = report.entries[-1]["seq"] if report.entries else 0
    if expected is not None and (int(seq), report.head_hash) != expected:
        print(
            f"chain tip seq={seq} entry_hash={report.head_hash} "
            f"does not match expected seq={expected[0]} entry_hash={expected[1]}",
            file=sys.stderr,
        )
        return 1

    if public_key is not None:
        try:
            features = _features_for_pubkey(args.licence, args.client_id)
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        problems = check_log(report.entries, public_key, features)
        if problems:
            print("checkpoint signature invalid", file=sys.stderr)
            for problem in problems:
                print(problem, file=sys.stderr)
            return 1

    selected = filter_entries(report.entries, **filters)
    for entry in selected:
        print(format_entry(entry))
    for gap in report.gaps:
        print(gap, file=sys.stderr)
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
        print(f"seq={seq} entry_hash={report.head_hash}")

    if args.json_export is not None:
        document = export_document(
            selected,
            full_chain=report.entries,
            chain_valid=True,
            filters=filters,
            exported_at=format_timestamp(utc_now()),
            gaps=list(report.gaps),
        )
        args.json_export.parent.mkdir(parents=True, exist_ok=True)
        args.json_export.write_text(dumps_document(document), encoding="utf-8")
        print(f"wrote {args.json_export}", file=sys.stderr)
    return 0
