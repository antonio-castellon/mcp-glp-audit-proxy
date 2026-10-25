"""body_mode applies to MCP tool arguments and results."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_glp_audit_proxy.bodyutil import prepare_value
from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.config import load_settings

from conftest import assemble, call_tool


def _last_tool(proxy, name: str) -> dict:
    found = None
    for entry in proxy.store.read_entries():
        if entry.get("tool") == name and entry.get("method") == "tools/call":
            found = entry
    assert found is not None
    return found


def test_hash_only_stores_hashes_not_payloads(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]
    proxy.settings.body_mode = "hash_only"
    arguments = {"patient": "X"}
    call_tool(proxy, "excel__read_cell", arguments)
    record = _last_tool(proxy, "excel__read_cell")
    expected = prepare_value(arguments, mode="hash_only", redact_paths=())
    result = {
        "content": [{"type": "text", "text": "value:"}],
        "isError": False,
    }
    assert record["arguments"] is None
    assert record["arguments_sha256"] == expected["sha256"]
    assert record["result"] is None
    assert record["result_sha256"] == prepare_value(result, mode="hash_only", redact_paths=())["sha256"]
    assert verify_file(stack["path"] / "audit.jsonl").ok
    startup = proxy.store.read_entries()[0]
    assert startup["method"] == "audit/startup"
    assert startup["arguments"]["audit_enabled"] is True


def test_redacted_and_full_modes(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]
    arguments = {"patient": "X", "keep": "yes"}
    proxy.settings.body_mode = "redacted"
    proxy.settings.redact_paths = ("$.patient",)
    call_tool(proxy, "excel__read_cell", arguments, request_id=11)
    redacted = _last_tool(proxy, "excel__read_cell")
    assert redacted["arguments"]["patient"] == "***"
    assert redacted["arguments"]["keep"] == "yes"
    assert redacted["result"]["content"][0]["text"] == "value:"

    proxy.settings.body_mode = "full"
    proxy.settings.redact_paths = ()
    call_tool(proxy, "excel__read_cell", arguments, request_id=12)
    full = [entry for entry in proxy.store.read_entries() if entry.get("tool") == "excel__read_cell"][-1]
    assert full["arguments"] == arguments
    assert full["result"]["isError"] is False
    assert verify_file(stack["path"] / "audit.jsonl").ok


def test_denied_and_pending_follow_body_mode(tmp_path: Path) -> None:
    denied_stack = assemble(tmp_path / "deny", allow=[])
    denied = denied_stack["proxies"]["operator"]
    denied.settings.body_mode = "hash_only"
    call_tool(denied, "excel__read_cell", {"patient": "X"})
    record = _last_tool(denied, "excel__read_cell")
    assert record["status"] == "denied"
    assert record["arguments"] is None
    assert record["result"] is None
    assert record["arguments_sha256"]
    assert record["result_sha256"] == prepare_value(None, mode="hash_only", redact_paths=())["sha256"]

    pending_stack = assemble(tmp_path / "pending", require_approval=True, write_tools=["excel__write_cell"])
    pending = pending_stack["proxies"]["operator"]
    pending.settings.body_mode = "hash_only"
    response = call_tool(
        pending,
        "excel__write_cell",
        {"patient": "X", "value": 1},
        meta={"io.github.antonio-castellon/reason": "record"},
        request_id=21,
    )
    assert response["result"]["isError"] is True
    stored = _last_tool(pending, "excel__write_cell")
    assert stored["status"] == "pending_approval"
    assert stored["arguments"] is None
    assert stored["result"] is None
    assert stored["result_sha256"]


def test_search_and_export_still_work(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    operator = stack["proxies"]["operator"]
    operator.settings.body_mode = "hash_only"
    call_tool(operator, "excel__read_cell", {"patient": "X"})
    found = call_tool(
        stack["proxies"]["qa"],
        "glp_search_audit",
        {"tool": "excel__read_cell"},
        request_id=30,
    )
    assert found["result"]["isError"] is False
    exported = call_tool(
        stack["proxies"]["qa"],
        "glp_export_audit",
        {"path": "out.json", "tool": "excel__read_cell"},
        request_id=31,
    )
    assert exported["result"]["isError"] is False
    assert verify_file(stack["path"] / "audit.jsonl").ok


def test_missing_body_mode_defaults_to_hash_only(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
                "audit": {"path": "audit.jsonl", "fail_closed": True},
            }
        ),
        encoding="utf-8",
    )
    loaded = load_settings(config)
    assert loaded.body_mode == "hash_only"
