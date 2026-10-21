"""Hash chain construction and RFC 8785 vectors."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from mcp_glp_audit_proxy.canonical import GENESIS, HASH_ALGO, canonicalize, seal, sha256_hex
from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "audit-record.schema.json").read_text(encoding="utf-8"))
VECTORS = json.loads((ROOT / "schema" / "jcs-test-vectors.json").read_text(encoding="utf-8"))


def test_rfc8785_vectors_match_pinned_implementation() -> None:
    for vector in VECTORS:
        raw = canonicalize(vector["input"])
        assert raw.decode("utf-8") == vector["canonical"]
        assert sha256_hex(raw) == vector["sha256"]


def test_chain_links_and_matches_schema(tmp_path: Path) -> None:
    from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

    store = JsonlAuditStore(tmp_path / "audit.jsonl", checkpoint_every=0)
    first = store.append_event(
        build_event(
            method="audit/startup",
            record_class="config",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy", "name": "mcp-glp-audit-proxy", "version": "0.2.0", "model_id": None},
            protocol_version=None,
            session_id=None,
            reason="startup",
        )
    )
    second = store.append_event(
        build_event(
            method="tools/call",
            record_class="gxp_data",
            status="ok",
            server="excel",
            principal={"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
            client={"id": "cursor", "name": "cursor", "version": "1", "model_id": None},
            protocol_version="2025-11-25",
            session_id="host-sess",
            tool="excel__write_cell",
            arguments={"cell": "A1", "value": 1},
            result={"content": [{"type": "text", "text": "saved"}]},
            reason="record the reading",
        )
    )
    assert first["seq"] == 1
    assert first["prev_hash"] == GENESIS
    assert first["hash_algo"] == HASH_ALGO
    assert second["seq"] == 2
    assert second["prev_hash"] == first["entry_hash"]
    report = verify_file(tmp_path / "audit.jsonl")
    assert report.ok, report.errors
    assert report.count == 2
    for entry in report.entries:
        jsonschema.validate(entry, SCHEMA)
    # A checkpoint is itself a chain entry and carries an unsigned signature.
    checked = JsonlAuditStore(tmp_path / "checkpoints.jsonl", checkpoint_every=1)
    checked.append_event(
        build_event(
            method="tools/call",
            record_class="access",
            status="ok",
            server="excel",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy", "name": "proxy", "version": "0.2.0", "model_id": None},
            protocol_version=None,
            session_id=None,
            tool="excel__read_cell",
            arguments={},
            result={"ok": True},
        )
    )
    chained = verify_file(tmp_path / "checkpoints.jsonl")
    assert chained.ok, chained.errors
    checkpoints = [entry for entry in chained.entries if entry["method"] == "audit/checkpoint"]
    assert checkpoints
    signature = checkpoints[0]["result"]["signature"]
    assert signature["signed"] is False
    assert signature["algorithm"] is None
    assert checkpoints[0]["reason"] == "unsigned checkpoint (Community); signing is a Pro plugin"
    jsonschema.validate(checkpoints[0], SCHEMA)
    # Re-sealing the stored body reproduces entry_hash.
    body = dict(second)
    claimed = body.pop("entry_hash")
    assert seal(body, body["prev_hash"])["entry_hash"] == claimed
    mode = (tmp_path / "audit.jsonl").stat().st_mode
    assert mode & 0o077 == 0
