"""Archive manifest and a later read-only check against it."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

from mcp_glp_audit_proxy.archive import main as archive_main
from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.reporters.json_export import export_document
from mcp_glp_audit_proxy.segments_cli import main as segment_main
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

from conftest import assemble


def _config(directory: Path, audit: Path) -> Path:
    path = directory / "config.json"
    path.write_text(
        json.dumps(
            {
                "principal": {"id": "admin-1", "name": "Dan Admin", "role": "admin"},
                "audit": {"path": str(audit), "fail_closed": True},
            }
        ),
        encoding="utf-8",
    )
    return path


def _stamp(path: Path) -> dict[str, tuple[int, int]]:
    found = {}
    for item in path.iterdir():
        if item.is_file():
            stat = item.stat()
            found[item.name] = (stat.st_mtime_ns, stat.st_size)
    return found


def test_manifest_lists_segments_head_and_hashes(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    proxy = stack["proxies"]["operator"]
    proxy.shutdown("eof")
    nxt = tmp_path / "segment-b.jsonl"
    assert (
        segment_main(
            [
                "close",
                "--config",
                str(_config(tmp_path, audit)),
                "--reason",
                "archive",
                "--ticket",
                "T-9",
                "--approved-by",
                "Archivist",
                "--output",
                str(nxt),
            ]
        )
        == 0
    )
    out = tmp_path / "manifest.json"
    before = _stamp(tmp_path)
    assert archive_main([str(audit), "--segments", str(audit), str(nxt), "--out", str(out)]) == 0
    after = _stamp(tmp_path)
    for name, (mtime, size) in before.items():
        if name == "manifest.json":
            continue
        assert after[name] == (mtime, size)
        assert (tmp_path / name).read_bytes()
    text = out.read_text(encoding="ascii")
    text.encode("ascii")
    again = tmp_path / "manifest-2.json"
    assert archive_main([str(audit), "--segments", str(audit), str(nxt), "--out", str(again)]) == 0
    first = json.loads(text)
    second = json.loads(again.read_text(encoding="ascii"))
    first.pop("created_at")
    second.pop("created_at")
    first.pop("created_by")
    second.pop("created_by")
    assert first == second
    names = {item["name"] for item in first["files"]}
    assert audit.name in names
    assert audit.name + ".head" in names
    assert nxt.name in names
    assert nxt.name + ".head" in names
    for item in first["files"]:
        raw = (tmp_path / item["name"]).read_bytes()
        assert item["size"] == len(raw)
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()
        if item["role"] == "log":
            report = verify_file(tmp_path / item["name"])
            assert item["record_count"] == report.count
            assert item["first_seq"] == report.entries[0]["seq"]
            assert item["last_seq"] == report.entries[-1]["seq"]
    assert first["end"] == "open/unclean end"
    assert first["segment_links"][0]["approved_by"] == "Archivist"
    assert first["archivist_received_by"] == ""
    assert first["archivist_received_at"] == ""

    clean = tmp_path / "clean.jsonl"
    store = JsonlAuditStore(clean, checkpoint_every=0)
    store.append_event(
        build_event(
            method="audit/shutdown",
            record_class="config",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy"},
            protocol_version=None,
            session_id=None,
            arguments={"audit_enabled": False, "cause": "eof"},
            result={"auditing": "stopped"},
            reason="audit trail stopped (eof)",
        )
    )
    clean_out = tmp_path / "clean-manifest.json"
    assert archive_main([str(clean), "--out", str(clean_out)]) == 0
    assert json.loads(clean_out.read_text(encoding="ascii"))["end"] == "audit/shutdown"


def test_tampered_log_writes_nothing(tmp_path: Path, capsys) -> None:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    raw = audit.read_bytes()
    audit.write_bytes(raw.replace(b"audit/startup", b"audit/startuP", 1))
    out = tmp_path / "manifest.json"
    assert archive_main([str(audit), "--out", str(out)]) == 1
    assert not out.exists()
    capsys.readouterr()


def test_missing_head_names_the_file(tmp_path: Path, capsys) -> None:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    head = Path(str(audit) + ".head")
    head.unlink()
    out = tmp_path / "manifest.json"
    assert archive_main([str(audit), "--out", str(out)]) == 1
    assert not out.exists()
    assert head.name in capsys.readouterr().err


def test_verify_manifest_on_read_only_copy(tmp_path: Path, capsys) -> None:
    stack = assemble(tmp_path / "src")
    audit = stack["path"] / "audit.jsonl"
    stack["proxies"]["operator"].shutdown("eof")
    manifest = tmp_path / "src" / "manifest.json"
    assert archive_main([str(audit), "--out", str(manifest)]) == 0
    copied = tmp_path / "copy"
    shutil.copytree(tmp_path / "src", copied)
    copied_log = copied / audit.name
    names = sorted(item.name for item in copied.iterdir())
    if os.name != "nt":
        for item in copied.iterdir():
            item.chmod(0o444)
        copied.chmod(0o555)
    report = tmp_path / "report.json"
    assert verify_main([str(copied_log), "--manifest", str(copied / "manifest.json"), "--report-out", str(report)]) == 0
    assert sorted(item.name for item in copied.iterdir()) == names
    body = json.loads(report.read_text(encoding="ascii"))
    assert body["checked_at"]
    assert body["manifest_sha256"]
    assert body["checks"]
    assert all(item["pass"] for item in body["checks"])
    report.read_text(encoding="ascii").encode("ascii")
    capsys.readouterr()

    if os.name != "nt":
        copied.chmod(0o755)
        for item in copied.iterdir():
            item.chmod(0o644)
    (copied / "segment-b.jsonl").write_text("{}\n", encoding="utf-8")
    # A listed file is removed below; an unlisted jsonl is an extra segment.
    assert verify_main([str(copied_log), "--manifest", str(copied / "manifest.json")]) == 1
    assert "segment-b.jsonl" in capsys.readouterr().err

    (copied / "segment-b.jsonl").unlink()
    listed = next(item["name"] for item in json.loads((copied / "manifest.json").read_text())["files"] if item["role"] == "log")
    (copied / listed).unlink()
    assert verify_main([str(copied_log), "--manifest", str(copied / "manifest.json")]) == 1
    assert listed in capsys.readouterr().err


def test_extra_record_fails_the_manifest(tmp_path: Path, capsys) -> None:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    manifest = tmp_path / "manifest.json"
    assert archive_main([str(audit), "--out", str(manifest)]) == 0
    store = JsonlAuditStore(audit, checkpoint_every=0)
    store.append_event(
        build_event(
            method="audit/startup",
            record_class="config",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy"},
            protocol_version=None,
            session_id=None,
        )
    )
    assert verify_main([str(audit), "--manifest", str(manifest)]) == 1
    err = capsys.readouterr().err
    assert "mismatch" in err


def test_mixed_schema_chain_stays_verifiable(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path, checkpoint_every=0)
    legacy = build_event(
        method="tools/call",
        record_class="access",
        status="ok",
        server="excel",
        principal=SYSTEM_PRINCIPAL,
        client={"id": "host", "name": "host", "version": "0.4.0"},
        protocol_version="2025-11-25",
        session_id=None,
        tool="excel__read_cell",
        arguments={"patient": "kept"},
        result={"content": [{"type": "text", "text": "value"}]},
    )
    legacy["schema_version"] = "1.2.0"
    legacy.pop("arguments_sha256")
    legacy.pop("result_sha256")
    store.append_event(legacy)
    current = build_event(
        method="tools/call",
        record_class="access",
        status="ok",
        server="excel",
        principal=SYSTEM_PRINCIPAL,
        client={"id": "host", "name": "host", "version": "0.4.0"},
        protocol_version="2025-11-25",
        session_id=None,
        tool="excel__read_cell",
        arguments=None,
        result=None,
        arguments_sha256="a" * 64,
        result_sha256="b" * 64,
    )
    store.append_event(current)
    report = verify_file(path)
    assert report.ok, report.errors
    document = export_document(
        report.entries,
        full_chain=report.entries,
        chain_valid=True,
        filters={},
        exported_at="2026-10-25T00:00:00.000000+00:00",
    )
    dumped = json.dumps(document)
    assert '"schema_version": "1.2.0"' in dumped or "1.2.0" in dumped
    assert "1.3.0" in dumped
    assert document["entries"][0]["arguments"]["patient"] == "kept"
    assert document["entries"][1]["arguments"] is None
    manifest = tmp_path / "manifest.json"
    assert archive_main([str(path), "--out", str(manifest)]) == 0
    versions = json.loads(manifest.read_text(encoding="ascii"))["files"][0]["schema_versions"]
    assert versions == ["1.2.0", "1.3.0"]
