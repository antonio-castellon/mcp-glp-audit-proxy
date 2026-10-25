"""Shutdown records and gap warnings. A gap is not a chain error."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

from conftest import assemble


def _append(path: Path, method: str) -> None:
    store = JsonlAuditStore(path, checkpoint_every=0)
    store.append_event(
        build_event(
            method=method,
            record_class="config",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy", "name": "proxy", "version": "0"},
            protocol_version=None,
            session_id=None,
            arguments={"audit_enabled": method != "audit/shutdown", "cause": "test"},
            result={"auditing": "stopped" if method == "audit/shutdown" else "enabled"},
            reason="test",
        )
    )


def test_shutdown_is_written_once(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]
    assert proxy.shutdown("eof") is not None
    assert proxy.shutdown("eof") is None
    methods = [entry["method"] for entry in proxy.store.read_entries()]
    assert methods.count("audit/shutdown") == 1


def test_gap_warning_between_two_startups(tmp_path: Path, capsys) -> None:
    path = tmp_path / "audit.jsonl"
    _append(path, "audit/startup")
    _append(path, "audit/startup")
    assert verify_main([str(path)]) == 0
    err = capsys.readouterr().err
    assert "gap: no audit/shutdown between line 1 and line 2" in err
    assert "chain ok" in err


def test_clean_start_stop_pairs_have_no_gap(tmp_path: Path, capsys) -> None:
    path = tmp_path / "audit.jsonl"
    for method in ("audit/startup", "audit/shutdown", "audit/startup", "audit/shutdown"):
        _append(path, method)
    assert verify_main([str(path)]) == 0
    err = capsys.readouterr().err
    assert "gap:" not in err
    report = verify_file(path)
    assert report.gaps == []


def test_json_export_contains_gaps(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _append(path, "audit/startup")
    exported = tmp_path / "out.json"
    assert verify_main([str(path), "--json-export", str(exported)]) == 0
    document = json.loads(exported.read_text(encoding="utf-8"))
    assert document["gaps"]
    assert "gap:" in document["gaps"][0]
