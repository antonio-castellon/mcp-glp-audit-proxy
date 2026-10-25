"""Chain-of-custody transfer and receipt for an archive manifest."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from mcp_glp_audit_proxy.archive import main as archive_main
from mcp_glp_audit_proxy.archive import transfer_main
from mcp_glp_audit_proxy.cli import main as verify_main

from conftest import assemble


def _package(tmp_path: Path) -> tuple[Path, Path]:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    stack["proxies"]["operator"].shutdown("eof")
    manifest = tmp_path / "manifest.json"
    assert archive_main([str(audit), "--out", str(manifest)]) == 0
    return audit, manifest


def test_transfer_record_has_the_manifest_hash(tmp_path: Path) -> None:
    _audit, manifest = _package(tmp_path)
    before = manifest.read_bytes()
    out = tmp_path / "transfer.json"
    assert (
        transfer_main(
            [
                str(manifest),
                "--from",
                "Gateway host",
                "--to",
                "Archivist",
                "--by",
                "Ada",
                "--method",
                "copy",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    record = json.loads(out.read_text(encoding="ascii"))
    assert record["manifest_sha256"] == hashlib.sha256(before).hexdigest()
    assert record["from"] == "Gateway host"
    assert record["to"] == "Archivist"
    assert manifest.read_bytes() == before


def test_receipt_on_an_intact_copy(tmp_path: Path) -> None:
    audit, manifest = _package(tmp_path)
    before = manifest.read_bytes()
    report = tmp_path / "outside" / "report.json"
    assert (
        verify_main(
            [
                str(audit),
                "--manifest",
                str(manifest),
                "--received-by",
                "Archivist",
                "--report-out",
                str(report),
            ]
        )
        == 0
    )
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["receipt"]["result"] == "complete and unaltered"
    assert document["receipt"]["received_by"] == "Archivist"
    assert document["receipt"]["manifest_sha256"] == hashlib.sha256(before).hexdigest()
    assert manifest.read_bytes() == before


def test_changed_byte_has_no_receipt(tmp_path: Path) -> None:
    audit, manifest = _package(tmp_path)
    copied = tmp_path / "copy"
    copied.mkdir()
    shutil.copy(audit, copied / audit.name)
    shutil.copy(audit.with_name(audit.name + ".head"), copied / (audit.name + ".head"))
    shutil.copy(manifest, copied / manifest.name)
    target = copied / audit.name
    raw = bytearray(target.read_bytes())
    raw[-4] = raw[-4] ^ 0x01
    target.write_bytes(bytes(raw))
    before = (copied / manifest.name).read_bytes()
    report = tmp_path / "report.json"
    code = verify_main(
        [
            str(copied / audit.name),
            "--manifest",
            str(copied / manifest.name),
            "--received-by",
            "Archivist",
            "--report-out",
            str(report),
        ]
    )
    assert code != 0
    document = json.loads(report.read_text(encoding="utf-8"))
    assert "receipt" not in document
    assert document["errors"]
    assert audit.name in document["errors"][0]["file"] or "mismatch" in document["errors"][0]["message"]
    assert (copied / manifest.name).read_bytes() == before


def test_manifest_file_is_unchanged_by_verify(tmp_path: Path) -> None:
    audit, manifest = _package(tmp_path)
    before = manifest.read_bytes()
    assert verify_main([str(audit), "--manifest", str(manifest), "--received-by", "Archivist"]) == 0
    assert transfer_main(
        [str(manifest), "--from", "A", "--to", "B", "--by", "C", "--method", "hand", "--out", str(tmp_path / "t.json")]
    ) == 0
    assert manifest.read_bytes() == before
