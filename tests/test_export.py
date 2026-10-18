"""Search, JSON export, QA role, and the verify CLI."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from mcp_glp_audit_proxy.cli import main as verify_main

from conftest import call_tool

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "audit-record.schema.json").read_text(encoding="utf-8"))


def test_entries_match_the_published_schema(build) -> None:
    stack = build()
    call_tool(stack["proxies"]["operator"], "excel__read_cell", {"cell": "A1"})
    for entry in stack["store"].read_entries():
        jsonschema.validate(entry, SCHEMA)


def test_qa_can_search_and_export_operator_cannot(build) -> None:
    stack = build()
    operator = stack["proxies"]["operator"]
    qa = stack["proxies"]["qa"]
    call_tool(operator, "excel__read_cell", {"cell": "A1"})
    call_tool(
        operator,
        "excel__write_cell",
        {"cell": "A1", "value": 9},
        {"io.github.antonio-castellon/reason": "record the reading"},
        request_id=11,
    )

    refused = call_tool(operator, "glp_search_audit", {}, request_id=12)
    assert refused["result"]["isError"] is True
    refused_export = call_tool(operator, "glp_export_audit", {"path": "out.json"}, request_id=13)
    assert refused_export["result"]["isError"] is True

    found = call_tool(qa, "glp_search_audit", {"tool": "excel__write_cell", "status": "ok"}, request_id=14)
    assert found["result"]["structuredContent"]["count"] == 1
    assert found["result"]["structuredContent"]["entries"][0]["record_class"] == "gxp_data"

    exported = call_tool(qa, "glp_export_audit", {"path": "trail.json"}, request_id=15)
    document = exported["result"]["structuredContent"]
    assert document["complete"] is True
    assert document["manifest"]["signer"] == "unsigned"
    assert document["manifest"]["full_chain_count"] == document["manifest"]["exported_count"]
    on_disk = json.loads((stack["path"] / "exports" / "trail.json").read_text(encoding="utf-8"))
    assert on_disk["chain_valid"] is True
    assert on_disk["manifest"]["full_head_hash"]

    filtered = call_tool(
        qa,
        "glp_export_audit",
        {"path": "writes.json", "tool": "excel__write_cell"},
        request_id=16,
    )
    assert filtered["result"]["structuredContent"]["complete"] is False

    logged = [entry for entry in stack["store"].read_entries() if entry.get("tool") == "glp_export_audit"]
    assert logged[-1]["record_class"] == "access"
    assert logged[-1]["result"]["count"] >= 1
    assert "arguments" not in json.dumps(logged[-1]["result"])


def test_export_path_cannot_escape(build) -> None:
    stack = build()
    qa = stack["proxies"]["qa"]
    response = call_tool(qa, "glp_export_audit", {"path": "../outside.json"}, request_id=20)
    assert "error" in response
    assert response["error"]["data"]["reason"] == "fail_closed"
    assert not (stack["path"] / "outside.json").exists()


def test_verify_cli_exports_only_a_valid_chain(build, capsys) -> None:
    stack = build()
    call_tool(stack["proxies"]["operator"], "excel__read_cell", {"cell": "B2"})
    audit = stack["store"].path
    destination = stack["path"] / "exports" / "cli.json"
    assert verify_main([str(audit), "--json-export", str(destination), "--status", "ok"]) == 0
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["chain_valid"] is True
    assert document["complete"] is False
    assert all(entry["status"] == "ok" for entry in document["entries"])

    raw = audit.read_bytes()
    # Flip a payload byte inside the first line without touching the newline.
    audit.write_bytes(raw.replace(b"audit/startup", b"audit/startux", 1))
    broken = stack["path"] / "exports" / "broken.json"
    assert verify_main([str(audit), "--json-export", str(broken)]) == 1
    assert not broken.exists()
    captured = capsys.readouterr()
    assert "chain invalid" in captured.err
