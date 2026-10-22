"""Tamper detection: the chain fails closed on edit, deletion, reorder and gaps."""

from __future__ import annotations

from pathlib import Path

from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore


def _fill(path: Path) -> None:
    store = JsonlAuditStore(path, checkpoint_every=0)
    for index in range(3):
        store.append_event(
            build_event(
                method="tools/call",
                record_class="access",
                status="ok",
                server="excel",
                principal=SYSTEM_PRINCIPAL,
                client={"id": "proxy", "name": "proxy", "version": "0.2.0", "model_id": None},
                protocol_version="2025-11-25",
                session_id=None,
                tool=f"excel__read_{index}",
                arguments={"n": index},
                result={"n": index},
            )
        )


def test_valid_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    report = verify_file(path)
    assert report.ok
    assert report.count == 3
    assert [entry["seq"] for entry in report.entries] == [1, 2, 3]


def test_jsonl_file_uses_lf_newlines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    raw = path.read_bytes()
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")


def test_modified_payload_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    text = path.read_bytes().replace(b"excel__read_1", b"excel__read_9", 1)
    path.write_bytes(text)
    report = verify_file(path)
    assert not report.ok
    assert any("entry_hash" in error or "canonical" in error for error in report.errors)


def test_whitespace_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    path.write_bytes(path.read_bytes().replace(b"{", b"{ ", 1))
    report = verify_file(path)
    assert not report.ok
    assert any("canonical" in error for error in report.errors)


def test_deleted_line_is_a_gap(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join([lines[0], lines[2]]))
    report = verify_file(path)
    assert not report.ok
    assert any("prev_hash" in error or "seq" in error for error in report.errors)


def test_reordered_lines_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join([lines[1], lines[0], lines[2]]))
    report = verify_file(path)
    assert not report.ok


def test_unknown_hash_algo_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path)
    path.write_bytes(path.read_bytes().replace(b"sha-256", b"sha-999", 1))
    report = verify_file(path)
    assert not report.ok
    assert any("hash_algo" in error or "entry_hash" in error or "canonical" in error for error in report.errors)
