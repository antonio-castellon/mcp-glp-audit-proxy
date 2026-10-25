"""Verify an append-only JSONL hash chain. Never repairs it."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import ACCEPTED_SCHEMA_VERSIONS, CANON, GENESIS, HASH_ALGO, canonicalize
from .permissions import tighten_path


@dataclass
class VerifyReport:
    ok: bool
    entries: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    head_hash: str = GENESIS
    anchor_lag: int = 0
    first_bad_line: int | None = None
    first_bad_seq: int | None = None
    last_good_seq: int | None = None
    last_good_timestamp: str | None = None
    first_bad_timestamp: str | None = None
    kind: str | None = None
    gaps: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.entries)


def verify_bytes(data: bytes) -> VerifyReport:
    if data == b"":
        return VerifyReport(ok=True, head_hash=GENESIS)
    errors: list[str] = []
    entries: list[dict[str, Any]] = []
    truncated = not data.endswith(b"\n")
    if truncated:
        errors.append("file does not end with a newline")
        chunks = data.split(b"\n")
    else:
        chunks = data.split(b"\n")[:-1]

    prev = GENESIS
    last_good_seq: int | None = None
    last_good_timestamp: str | None = None
    first_bad_line: int | None = None
    first_bad_seq: int | None = None
    first_bad_timestamp: str | None = None
    first_bad_message = ""
    for index, line in enumerate(chunks, start=1):
        before = len(errors)
        parsed: dict[str, Any] | None = None
        if line == b"":
            errors.append(f"line {index}: blank line")
        else:
            try:
                loaded = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                errors.append(f"line {index}: not utf-8 json ({exc})")
                prev = ""
            else:
                if not isinstance(loaded, dict):
                    errors.append(f"line {index}: entry is not an object")
                    prev = ""
                else:
                    parsed = loaded
                    try:
                        canonical = canonicalize(parsed)
                    except Exception as exc:  # rfc8785 raises CanonicalizationError
                        errors.append(f"line {index}: cannot canonicalize ({exc})")
                        prev = ""
                    else:
                        if canonical != line:
                            errors.append(f"line {index}: not {CANON} canonical JSON")
                        body = dict(parsed)
                        claimed = body.pop("entry_hash", None)
                        try:
                            expect = hashlib_hex(body)
                        except Exception as exc:
                            errors.append(f"line {index}: hash input rejected ({exc})")
                            prev = ""
                        else:
                            if claimed != expect:
                                errors.append(f"line {index}: entry_hash mismatch")
                            if parsed.get("prev_hash") != prev:
                                errors.append(f"line {index}: prev_hash mismatch")
                            expect_seq = 1 if not entries else int(entries[-1]["seq"]) + 1
                            if parsed.get("seq") != expect_seq:
                                errors.append(
                                    f"line {index}: seq {parsed.get('seq')!r} expected {expect_seq}"
                                )
                            if parsed.get("hash_algo") != HASH_ALGO:
                                errors.append(
                                    f"line {index}: unsupported hash_algo {parsed.get('hash_algo')!r}"
                                )
                            if parsed.get("canonicalization") != CANON:
                                errors.append(
                                    f"line {index}: unsupported canonicalization "
                                    f"{parsed.get('canonicalization')!r}"
                                )
                            if parsed.get("schema_version") not in ACCEPTED_SCHEMA_VERSIONS:
                                errors.append(
                                    f"line {index}: unsupported schema_version "
                                    f"{parsed.get('schema_version')!r}"
                                )
                            prev = claimed if isinstance(claimed, str) else ""
                            entries.append(parsed)
        if len(errors) == before and parsed is not None:
            if isinstance(parsed.get("seq"), int) and not isinstance(parsed.get("seq"), bool):
                last_good_seq = parsed["seq"]
            if isinstance(parsed.get("timestamp"), str):
                last_good_timestamp = parsed["timestamp"]
        elif first_bad_line is None:
            first_bad_line = index
            first_bad_message = errors[-1]
            if parsed is not None and isinstance(parsed.get("timestamp"), str):
                first_bad_timestamp = parsed["timestamp"]
            seq = parsed.get("seq") if parsed is not None else None
            if isinstance(seq, int) and not isinstance(seq, bool):
                first_bad_seq = seq
            else:
                first_bad_seq = 1 if last_good_seq is None else last_good_seq + 1

    if entries and isinstance(entries[-1].get("entry_hash"), str):
        head = entries[-1]["entry_hash"]
    else:
        head = GENESIS
    kind = _kind(first_bad_message, truncated, first_bad_line, len(chunks), errors)
    if kind == "truncated" and first_bad_line is None:
        first_bad_line = len(chunks) or 1
        first_bad_seq = 1 if last_good_seq is None else last_good_seq + 1
    report = VerifyReport(
        ok=not errors,
        entries=entries,
        errors=errors,
        head_hash=head,
        first_bad_line=first_bad_line,
        first_bad_seq=first_bad_seq,
        last_good_seq=last_good_seq,
        last_good_timestamp=last_good_timestamp,
        first_bad_timestamp=first_bad_timestamp,
        kind=kind,
    )
    report.gaps = shutdown_gaps(entries)
    return report


def shutdown_gaps(entries: list[dict[str, Any]]) -> list[str]:
    """Warn when a startup has no later shutdown. A warning is not a chain error.

    Old logs that never wrote audit/shutdown are reported the same way.
    """
    if not entries:
        return []
    gaps: list[str] = []
    open_line: int | None = None
    saw_shutdown = False
    for index, entry in enumerate(entries, start=1):
        method = entry.get("method")
        if method == "audit/shutdown":
            open_line = None
            saw_shutdown = True
        elif method == "audit/startup":
            if open_line is not None:
                gaps.append(_gap(open_line, index))
            open_line = index
    if open_line is not None and open_line != len(entries):
        gaps.append(_gap(open_line, len(entries)))
    elif open_line is not None and not gaps:
        gaps.append(_gap(open_line, len(entries)))
    elif not saw_shutdown and open_line is None:
        gaps.append(_gap(1, len(entries)))
    return gaps


def hashlib_hex(body: dict[str, Any]) -> str:
    from .canonical import sha256_hex

    return sha256_hex(canonicalize(body))


def verify_file(path: Path) -> VerifyReport:
    if not path.exists():
        return VerifyReport(ok=True, head_hash=GENESIS)
    tighten_path(path)
    return verify_bytes(path.read_bytes())


def integrity_text(report: VerifyReport) -> str:
    """One sentence naming where the chain stopped verifying."""
    return (
        f"audit chain integrity failure at line {report.first_bad_line} "
        f"(seq {report.first_bad_seq}): {report.kind}; "
        f"last good record seq {report.last_good_seq} at {report.last_good_timestamp}; "
        f"first bad record at {report.first_bad_timestamp}"
    )


def _gap(start: int, end: int) -> str:
    return f"gap: no audit/shutdown between line {start} and line {end} (unclean stop or crash)"


def _kind(
    message: str,
    truncated: bool,
    first_bad_line: int | None,
    line_count: int,
    errors: list[str],
) -> str | None:
    if not errors:
        return None
    if truncated and (first_bad_line is None or first_bad_line == line_count):
        return "truncated"
    if "prev_hash" in message or " seq " in f" {message}" or "blank line" in message:
        return "missing"
    if "newline" in message:
        return "truncated"
    return "edited"
