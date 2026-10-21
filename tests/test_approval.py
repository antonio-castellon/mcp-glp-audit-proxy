"""Human approval before write tools. Labelled approval, not an e-signature."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from mcp_glp_audit_proxy.approvals import load_approvals
from mcp_glp_audit_proxy.canonical import SCHEMA_VERSION
from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.records import build_event

from conftest import call_tool

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "audit-record.schema.json").read_text(encoding="utf-8"))

REASON = {"io.github.antonio-castellon/reason": "enter the weighed value"}


def _pending_id(response: dict) -> str:
    text = response["result"]["content"][0]["text"]
    assert "not an electronic signature" in text
    marker = "approval_id="
    start = text.index(marker) + len(marker)
    return text[start:].split()[0]


def test_write_is_held_until_a_different_approver_accepts(build) -> None:
    stack = build(require_approval=True)
    operator = stack["proxies"]["operator"]
    approver = stack["proxies"]["approver"]
    held = call_tool(operator, "excel__write_cell", {"cell": "A1", "value": 2}, REASON)
    assert held["result"]["isError"] is True
    assert stack["fake"].calls == []
    approval_id = _pending_id(held)
    pending = [entry for entry in stack["store"].read_entries() if entry["status"] == "pending_approval"]
    assert pending[-1]["approval"]["label"] == "approval"
    assert pending[-1]["record_class"] == "gxp_data"

    decision = call_tool(
        approver,
        "glp_approve",
        {"approval_id": approval_id, "meaning": "approved"},
        request_id=11,
    )
    assert decision["result"]["isError"] is False
    assert "not an electronic signature" in decision["result"]["content"][0]["text"]

    done = call_tool(
        operator,
        "excel__write_cell",
        {"cell": "A1", "value": 2},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert done["result"]["structuredContent"]["saved"] is True
    assert any(item["method"] == "tools/call" for item in stack["fake"].calls)
    consumed = [
        entry
        for entry in stack["store"].read_entries()
        if entry.get("tool") == "excel__write_cell" and entry["status"] == "ok"
    ][-1]
    assert consumed["approval"]["status"] == "consumed"
    assert consumed["approval"]["label"] == "approval"
    assert consumed["approval"]["approver_name"] == "Ben Reviewer"

    again = call_tool(
        operator,
        "excel__write_cell",
        {"cell": "A1", "value": 2},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=13,
    )
    assert again["result"]["isError"] is True


def test_reviewed_and_rejected_do_not_authorise(build) -> None:
    stack = build(require_approval=True)
    operator = stack["proxies"]["operator"]
    approver = stack["proxies"]["approver"]
    held = call_tool(operator, "excel__write_cell", {"value": 1}, REASON)
    approval_id = _pending_id(held)
    call_tool(
        approver,
        "glp_approve",
        {"approval_id": approval_id, "meaning": "reviewed"},
        request_id=11,
    )
    reviewed = [entry for entry in stack["store"].read_entries() if entry["method"] == "glp_approve"][-1]
    assert reviewed["status"] == "reviewed"
    assert reviewed["approval"]["status"] == "reviewed"
    assert reviewed["approval"]["meaning"] == "reviewed"
    assert reviewed["schema_version"] == SCHEMA_VERSION == "1.1.0"
    jsonschema.validate(reviewed, SCHEMA)
    approved = call_tool(
        stack["proxies"]["qa"],
        "glp_search_audit",
        {"status": "approved", "tool": "glp_approve"},
        request_id=19,
    )
    assert approved["result"]["structuredContent"]["count"] == 0
    found = call_tool(
        stack["proxies"]["qa"],
        "glp_search_audit",
        {"status": "reviewed", "tool": "glp_approve"},
        request_id=20,
    )
    assert found["result"]["structuredContent"]["count"] == 1
    refused = call_tool(
        operator,
        "excel__write_cell",
        {"value": 1},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert refused["result"]["isError"] is True
    assert "meaning" in refused["result"]["content"][0]["text"]
    assert stack["fake"].calls == []

    held_again = call_tool(operator, "excel__write_cell", {"value": 2}, REASON, request_id=13)
    rejected_id = _pending_id(held_again)
    call_tool(
        approver,
        "glp_approve",
        {"approval_id": rejected_id, "meaning": "rejected"},
        request_id=14,
    )
    rejected = [entry for entry in stack["store"].read_entries() if entry["method"] == "glp_approve"][-1]
    assert rejected["status"] == "rejected"
    assert rejected["approval"]["status"] == "rejected"
    jsonschema.validate(rejected, SCHEMA)


def test_legacy_reviewed_approval_still_verifies_and_does_not_authorise(build) -> None:
    """Schema 1.0.0 stored meaning=reviewed as status approved. Do not rewrite it."""
    stack = build(require_approval=True)
    store = stack["store"]
    approval_id = "legacy-approval"
    expires = "2026-10-18T13:00:00.000000+00:00"
    client = {"id": "test", "name": "test", "version": "0", "model_id": None}
    pending = build_event(
        method="tools/call",
        record_class="gxp_data",
        status="pending_approval",
        server="excel",
        principal={"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
        client=client,
        protocol_version=None,
        session_id=None,
        tool="excel__write_cell",
        arguments={"value": 1},
        result={"approval_id": approval_id},
        policy_action="require_approval",
        policy_rule="write:approval",
        reason="enter the weighed value",
        approval={
            "approval_id": approval_id,
            "approver_id": None,
            "approver_name": None,
            "args_hash": "ab" * 32,
            "decided_at": None,
            "expires_at": expires,
            "label": "approval",
            "meaning": None,
            "status": "pending",
            "tool": "excel__write_cell",
        },
    )
    pending["schema_version"] = "1.0.0"
    decision = build_event(
        method="glp_approve",
        record_class="gxp_data",
        status="approved",
        server="proxy",
        principal={"id": "approver-1", "name": "Ben Reviewer", "role": "approver"},
        client=client,
        protocol_version=None,
        session_id=None,
        tool="glp_approve",
        arguments={"approval_id": approval_id, "meaning": "reviewed"},
        result={"tool": "excel__write_cell", "label": "approval"},
        policy_action="allow",
        policy_rule="approval",
        reason="reviewed",
        approval={
            "approval_id": approval_id,
            "approver_id": "approver-1",
            "approver_name": "Ben Reviewer",
            "args_hash": "ab" * 32,
            "decided_at": "2026-10-18T12:05:00.000000+00:00",
            "expires_at": expires,
            "label": "approval",
            "meaning": "reviewed",
            "status": "approved",
            "tool": "excel__write_cell",
        },
    )
    decision["schema_version"] = "1.0.0"
    store.append_event(pending)
    store.append_event(decision)
    report = verify_file(store.path)
    assert report.ok, report.errors
    assert report.entries[0]["schema_version"] == "1.1.0"
    on_disk = [entry for entry in report.entries if entry["method"] == "glp_approve"][-1]
    assert on_disk["schema_version"] == "1.0.0"
    assert on_disk["status"] == "approved"
    assert on_disk["approval"]["status"] == "approved"
    assert on_disk["approval"]["meaning"] == "reviewed"
    jsonschema.validate(on_disk, SCHEMA)
    record = load_approvals(report.entries)[approval_id]
    assert record.status == "reviewed"
    assert record.meaning == "reviewed"
    refused = call_tool(
        stack["proxies"]["operator"],
        "excel__write_cell",
        {"value": 1},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert refused["result"]["isError"] is True
    assert "meaning" in refused["result"]["content"][0]["text"]
    assert stack["fake"].calls == []


def test_operator_cannot_approve_and_cannot_self_approve(build) -> None:
    stack = build(require_approval=True)
    operator = stack["proxies"]["operator"]
    held = call_tool(operator, "excel__write_cell", {"value": 1}, REASON)
    approval_id = _pending_id(held)
    denied = call_tool(
        operator,
        "glp_approve",
        {"approval_id": approval_id, "meaning": "approved"},
        request_id=11,
    )
    assert denied["result"]["isError"] is True
    # Same human id, even with the approver role, cannot clear their own request.
    stack["proxies"]["approver"].settings.principal.id = "operator-1"
    self_approved = call_tool(
        stack["proxies"]["approver"],
        "glp_approve",
        {"approval_id": approval_id, "meaning": "approved"},
        request_id=12,
    )
    assert self_approved["result"]["isError"] is True
    assert stack["fake"].calls == []


def test_changed_arguments_do_not_match_the_approval(build) -> None:
    stack = build(require_approval=True)
    operator = stack["proxies"]["operator"]
    held = call_tool(operator, "excel__write_cell", {"value": 1}, REASON)
    approval_id = _pending_id(held)
    call_tool(
        stack["proxies"]["approver"],
        "glp_approve",
        {"approval_id": approval_id, "meaning": "approved"},
        request_id=11,
    )
    swapped = call_tool(
        operator,
        "excel__write_cell",
        {"value": 999},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert swapped["result"]["isError"] is True
    assert stack["fake"].calls == []


def test_expired_approval_is_refused(build) -> None:
    stack = build(require_approval=True)
    operator = stack["proxies"]["operator"]
    held = call_tool(operator, "excel__write_cell", {"value": 1}, REASON)
    approval_id = _pending_id(held)
    call_tool(
        stack["proxies"]["approver"],
        "glp_approve",
        {"approval_id": approval_id, "meaning": "approved"},
        request_id=11,
    )
    stack["clock"].advance(3601)
    late = call_tool(
        operator,
        "excel__write_cell",
        {"value": 1},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert late["result"]["isError"] is True
    assert stack["fake"].calls == []
