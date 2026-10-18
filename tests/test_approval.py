"""Human approval before write tools. Labelled approval, not an e-signature."""

from __future__ import annotations

from conftest import call_tool

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
    refused = call_tool(
        operator,
        "excel__write_cell",
        {"value": 1},
        {**REASON, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert refused["result"]["isError"] is True
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
