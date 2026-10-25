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

    @property
    def count(self) -> int:
        return len(self.entries)


def verify_bytes(data: bytes) -> VerifyReport:
    if data == b"":
        return VerifyReport(ok=True, head_hash=GENESIS)
    errors: list[str] = []
    entries: list[dict[str, Any]] = []
    if not data.endswith(b"\n"):
        errors.append("file does not end with a newline")
        # Still inspect complete lines so the report says where it broke.
        chunks = data.split(b"\n")
    else:
        chunks = data.split(b"\n")[:-1]

    prev = GENESIS
    for index, line in enumerate(chunks, start=1):
        if line == b"":
            errors.append(f"line {index}: blank line")
            continue
        try:
            parsed = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            errors.append(f"line {index}: not utf-8 json ({exc})")
            prev = ""
            continue
        if not isinstance(parsed, dict):
            errors.append(f"line {index}: entry is not an object")
            prev = ""
            continue
        try:
            canonical = canonicalize(parsed)
        except Exception as exc:  # rfc8785 raises CanonicalizationError
            errors.append(f"line {index}: cannot canonicalize ({exc})")
            prev = ""
            continue
        if canonical != line:
            errors.append(f"line {index}: not {CANON} canonical JSON")
        body = dict(parsed)
        claimed = body.pop("entry_hash", None)
        try:
            expect = hashlib_hex(body)
        except Exception as exc:
            errors.append(f"line {index}: hash input rejected ({exc})")
            prev = ""
            continue
        if claimed != expect:
            errors.append(f"line {index}: entry_hash mismatch")
        if parsed.get("prev_hash") != prev:
            errors.append(f"line {index}: prev_hash mismatch")
        expect_seq = 1 if not entries else int(entries[-1]["seq"]) + 1
        if parsed.get("seq") != expect_seq:
            errors.append(f"line {index}: seq {parsed.get('seq')!r} expected {expect_seq}")
        if parsed.get("hash_algo") != HASH_ALGO:
            errors.append(f"line {index}: unsupported hash_algo {parsed.get('hash_algo')!r}")
        if parsed.get("canonicalization") != CANON:
            errors.append(
                f"line {index}: unsupported canonicalization {parsed.get('canonicalization')!r}"
            )
        if parsed.get("schema_version") not in ACCEPTED_SCHEMA_VERSIONS:
            errors.append(
                f"line {index}: unsupported schema_version {parsed.get('schema_version')!r}"
            )
        prev = claimed if isinstance(claimed, str) else ""
        entries.append(parsed)

    if entries and isinstance(entries[-1].get("entry_hash"), str):
        head = entries[-1]["entry_hash"]
    else:
        head = GENESIS
    return VerifyReport(ok=not errors, entries=entries, errors=errors, head_hash=head)


def hashlib_hex(body: dict[str, Any]) -> str:
    from .canonical import sha256_hex

    return sha256_hex(canonicalize(body))


def verify_file(path: Path) -> VerifyReport:
    if not path.exists():
        return VerifyReport(ok=True, head_hash=GENESIS)
    tighten_path(path)
    return verify_bytes(path.read_bytes())
